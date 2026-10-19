#!/usr/bin/env python3
"""Install one locally verified, exact ABI bundle. Never force-load a module."""
import hashlib,json,os,platform,shutil,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parent
kernel=platform.release()
bundle=root/'assets'/kernel
if not bundle.exists():sys.exit(2)
m=json.loads((bundle/'manifest.json').read_text())
osd=dict(l.split('=',1) for l in Path('/etc/os-release').read_text().splitlines() if '=' in l)
if m['kernel']!=kernel or m['os_id']!=osd['ID'].strip('"') or m['os_version']!=osd['VERSION_ID'].strip('"') or m['arch']!=platform.machine():
 raise SystemExit('Prebuilt ABI/OS identity mismatch')
for name in ['xt_ndpi.ko','libxt_ndpi.so']:
 p=bundle/name
 if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=m['sha256'][name]:raise SystemExit('Prebuilt checksum mismatch')
vermagic=subprocess.check_output(['modinfo','-F','vermagic',str(bundle/'xt_ndpi.ko')],text=True).strip()
if vermagic.split()[0]!=kernel or vermagic!=m['vermagic']:raise SystemExit('Module ABI mismatch')
found=list(Path('/lib/modules',kernel).rglob('xt_ndpi.ko*'))
dest=Path('/lib/modules',kernel,'updates/dkms');dest.mkdir(parents=True,exist_ok=True)
if any(p.parent!=dest for p in found):raise SystemExit('An unowned module path requires review')
for p in found:p.unlink()
shutil.copyfile(bundle/'xt_ndpi.ko',dest/'xt_ndpi.ko');(dest/'xt_ndpi.ko').chmod(0o644)
xtdir=Path('/usr/lib/x86_64-linux-gnu/xtables')
if not xtdir.is_dir():raise SystemExit('Unknown xtables plugin directory')
shutil.copyfile(bundle/'libxt_ndpi.so',xtdir/'libxt_ndpi.so');(xtdir/'libxt_ndpi.so').chmod(0o644)
subprocess.run(['depmod','-a',kernel],check=True,timeout=90)
resolved=Path(subprocess.check_output(['modinfo','-n','xt_ndpi'],text=True).strip())
if resolved!=dest/'xt_ndpi.ko' or hashlib.sha256(resolved.read_bytes()).hexdigest()!=m['sha256']['xt_ndpi.ko']:
 raise SystemExit('Module resolver verification failed')
print('Exact kernel bundle staged; no module was loaded or unloaded.')
