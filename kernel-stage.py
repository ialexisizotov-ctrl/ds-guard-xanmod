#!/usr/bin/env python3
"""Stage an exact kernel alongside the current one. No reboot or boot selection."""
import argparse, fcntl, hashlib, json, os, platform, re, shutil, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
STATE=Path('/var/lib/ds-guard-safe/kernel')

def cleanup():
 p=STATE/'temporary.json'
 if not p.exists():return
 d=json.loads(p.read_text());unit=d['unit']
 assert re.fullmatch(r'ds-guard-kprep@[A-Za-z0-9._+~\\-]+\.service',unit)
 mask=Path('/run/systemd/system')/unit
 if mask.is_symlink() and os.readlink(mask)=='/dev/null':mask.unlink()
 noauto=Path('/etc/dkms/no-autoinstall')
 if d['noauto_created'] and noauto.is_file() and noauto.read_text()=='Temporary ds-guard exact-kernel staging\n':noauto.unlink()
 run(['systemctl','daemon-reload']);p.unlink()

def run(a,timeout=60,check=True):
 p=subprocess.run(a,capture_output=True,text=True,timeout=timeout,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_SUSPEND':'1'})
 if check and p.returncode:raise RuntimeError(a[0]+' failed: '+p.stderr[-1500:])
 return p.stdout.strip()

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
 ap=argparse.ArgumentParser();ap.add_argument('kernel');ap.add_argument('directory',type=Path);a=ap.parse_args()
 catalog=json.loads((ROOT/'kernels.json').read_text());m=catalog[a.kernel]
 assert os.geteuid()==0 and platform.machine()=='x86_64'
 osd=dict(l.split('=',1) for l in Path('/etc/os-release').read_text().splitlines() if '=' in l)
 assert osd['ID'].strip('"')=='ubuntu' and osd['VERSION_ID'].strip('"')=='24.04','Kernel packages require Ubuntu 24.04'
 assert not run(['dpkg','--audit']), 'Existing package errors require review'
 assert Path('/boot/grub/grub.cfg').is_file() and Path('/boot/grub/grubenv').is_file(),'GRUB required'
 assert shutil.disk_usage('/boot').free>150*1024**2 and shutil.disk_usage('/').free>4*1024**3,'Insufficient disk space'
 cfg=Path('/boot/config-'+platform.release()).read_text()
 lock=Path('/sys/kernel/security/lockdown')
 assert 'CONFIG_MODULE_SIG_FORCE=y' not in cfg
 assert not lock.exists() or not re.search(r'\[(integrity|confidentiality)\]',lock.read_text()),'Trusted signing is required'
 flags=set(re.search(r'^flags\s*:\s*(.*)$',Path('/proc/cpuinfo').read_text(),re.M)[1].split())
 required={'cx16','lahf_lm','popcnt','pni','sse4_1','sse4_2','ssse3'}
 if m['cpu_level']=='x86-64-v3':required|={'avx','avx2','bmi1','bmi2','f16c','fma','movbe','xsave'}
 assert required<=flags,'CPU lacks the selected kernel instruction set'
 if shutil.which('dkms'):
  assert all(l.startswith('ndpi/') for l in run(['dkms','status']).splitlines()),'Other DKMS drivers need an explicit migration review'
 for kind in ['image','headers']:
  p=a.directory/m[kind];assert p.is_file() and not p.is_symlink() and sha(p)==m[kind+'_sha256'],'Package checksum mismatch'
  meta=run(['dpkg-deb','-f',str(p),'Package','Architecture'])
  assert 'linux-'+kind+'-'+a.kernel in meta and 'amd64' in meta,'Package identity mismatch'
 bundle=ROOT/'assets'/a.kernel;manifest=json.loads((bundle/'manifest.json').read_text())
 assert manifest['kernel']==a.kernel and sha(bundle/'xt_ndpi.ko')==manifest['sha256']['xt_ndpi.ko']
 assert run(['modinfo','-F','vermagic',str(bundle/'xt_ndpi.ko')]).split()[0]==a.kernel
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (STATE/'lock').open('w') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  before=run(['grub-editenv','/boot/grub/grubenv','list'])
  # A newly installed image must not silently become the next default boot.
  assert re.search(r'^saved_entry=.+$',before,re.M) and 'set default="${saved_entry}"' in Path('/boot/grub/grub.cfg').read_text(),'Pin a verified fallback with GRUB_DEFAULT=saved before staging'
  target_unit='ds-guard-kprep@'+run(['systemd-escape',a.kernel])+'.service'
  state=run(['systemctl','show',target_unit,'-p','ActiveState','--value'],check=False)
  assert state not in ('active','activating','deactivating'),'A kernel helper is already running'
  mask=Path('/run/systemd/system')/target_unit
  assert not mask.exists() and not mask.is_symlink(),'Existing kernel helper override requires review'
  noauto=Path('/etc/dkms/no-autoinstall');created=False
  assert not (STATE/'temporary.json').exists(),'An earlier staging job requires cleanup first'
  (STATE/'temporary.json').write_text(json.dumps({'unit':target_unit,'noauto_created':Path('/etc/dkms').is_dir() and not noauto.exists()}))
  try:
   mask.symlink_to('/dev/null');run(['systemctl','daemon-reload'])
   if Path('/etc/dkms').is_dir() and not noauto.exists():
    with noauto.open('x') as n:n.write('Temporary ds-guard exact-kernel staging\n')
    created=True
   log=STATE/(a.kernel+'.dpkg.log')
   with log.open('w') as out:
    subprocess.run(['dpkg','-i',str(a.directory/m['image']),str(a.directory/m['headers'])],check=True,stdout=out,stderr=subprocess.STDOUT,timeout=900,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_SUSPEND':'1'})
   dest=Path('/lib/modules')/a.kernel/'updates/dkms';dest.mkdir(parents=True,exist_ok=True)
   existing=list(dest.glob('xt_ndpi.ko*'))
   assert not existing or existing==[dest/'xt_ndpi.ko'] and sha(existing[0])==manifest['sha256']['xt_ndpi.ko'],'Different candidate module already exists'
   shutil.copyfile(bundle/'xt_ndpi.ko',dest/'xt_ndpi.ko');(dest/'xt_ndpi.ko').chmod(0o644)
   run(['depmod','-a',a.kernel],timeout=90)
   assert run(['modinfo','-k',a.kernel,'-n','xt_ndpi'])==str(dest/'xt_ndpi.ko')
   for line in Path('/proc/modules').read_text().splitlines():
    name=line.split()[0]
    if name=='xt_ndpi':continue
    run(['modinfo','-k',a.kernel,name],check=True)
   assert Path('/boot/vmlinuz-'+a.kernel).stat().st_size>1024**2
   assert Path('/boot/initrd.img-'+a.kernel).stat().st_size>1024**2
   assert 'CONFIG_LIVEPATCH=y' in Path('/boot/config-'+a.kernel).read_text()
   assert before==run(['grub-editenv','/boot/grub/grubenv','list']),'Boot environment changed unexpectedly'
   result={'candidate':a.kernel,'running_kernel':platform.release(),'module_sha256':sha(dest/'xt_ndpi.ko'),'boot_environment_preserved':True,'rebooted':False,'accepted':False}
   (STATE/(a.kernel+'.staged.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result))
  finally:
   cleanup()

if __name__=='__main__':
 if sys.argv[1:]==['--cleanup']:cleanup()
 else:main()
