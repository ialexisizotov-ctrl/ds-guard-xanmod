#!/usr/bin/env python3
"""Pure fixtures for the known legacy hold; no host service or module action."""
import hashlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import legacy_upgrade as legacy

KERNEL='7.0.12-x64v2-dsg1-xanmod1'
BOOT='22222222-2222-2222-2222-222222222222'
OLD_BOOT='11111111-1111-1111-1111-111111111111'
TXN=legacy.STATE/'transactions/33333333-3333-3333-3333-333333333333'
KNOWN_FAULT='[100] BUG: KFENCE: out-of-bounds read in memcpy_orig+0x16/0x130\n[101] realloc_wrapper+0x69/0xb0 [xt_ndpi]\n[102] ndpi_search_tls_memory+0x8e/0x100 [xt_ndpi]\n'
RULES='''*filter
-A OUTPUT -o eth0 -j DS_DOMAINS
-A FORWARD -o eth0 -j DS_DOMAINS
-A OUTPUT -o eth0 -p udp -m conntrack --ctstate NEW -j NFQUEUE --queue-balance 0:1 --queue-bypass
-A DS_DOM_A_D -m string --hex-string "|016100|" --algo kmp -j DROP
COMMIT
'''

class LegacyUpgradeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='dsg-legacy-test-');self.base=Path(self.temp.name);self.fs=self.base/'system';self.fs.mkdir();self.root=self.base/'release'
  self.patches=[patch.object(legacy,'SYSTEM_ROOT',self.fs),patch.object(legacy,'ROOT_UID',os.getuid()),patch.object(legacy.platform,'release',return_value=KERNEL),patch.object(legacy.platform,'machine',return_value='x86_64'),patch.object(legacy,'command',side_effect=self.command),patch.object(legacy.module_identity,'build_note',return_value=b'note'),patch.object(legacy.module_identity,'loaded_matches',side_effect=self.loaded_matches)]
  for p in self.patches:p.start()
  self.disk='/lib/modules/'+KERNEL+'/updates/dkms/xt_ndpi.ko';self.dmesg='';self.logrc=0;self.rules=RULES;self.loaded_ok=False;self.loaded_disk=True;self.calls=[];self.reload_failure=False
  self.write('/etc/os-release','ID=ubuntu\nVERSION_ID="24.04"\n')
  self.write('/proc/sys/kernel/random/boot_id',BOOT+'\n')
  self.write('/proc/net/netfilter/nfnetlink_queue','0 0 0\n1 0 0\n')
  self.write('/sys/module/xt_ndpi/notes/.note.gnu.build-id',b'old-note')
  self.write('/etc/systemd/system/ds-guard.service',legacy.GUARD_UNIT)
  self.write('/etc/systemd/system/ds-guard-apply.service',legacy.APPLY_UNIT)
  self.write('/usr/local/sbin/ds-guard-ndpi-lib.sh','#!/bin/bash\nVERSION=1.7.11\n')
  self.write(legacy.MARKER,legacy.MARKER_TEXT,0o600)
  for p in legacy.HOLD_PATHS:self.write(p,legacy.HOLD_TEXT)
  self.write(self.disk,b'old-module')
  self.write('/usr/lib/x86_64-linux-gnu/xtables/libxt_ndpi.so',b'old-plugin')
  self.write(legacy.STATE/'installed.json',json.dumps({'kernel':KERNEL,'sha256':hashlib.sha256(b'old-module').hexdigest()}),0o600)
  self.bundle=self.root/'assets'/KERNEL;self.bundle.mkdir(parents=True)
  for name,data in [('xt_ndpi.ko',b'new-module'),('libxt_ndpi.so',b'new-plugin')]:
   (self.bundle/name).write_bytes(data);(self.bundle/name).chmod(0o644)
  self.manifest={'kernel':KERNEL,'os_id':'ubuntu','os_version':'24.04','arch':'x86_64','vermagic':KERNEL+' SMP preempt mod_unload','sha256':{n:hashlib.sha256((self.bundle/n).read_bytes()).hexdigest() for n in ['xt_ndpi.ko','libxt_ndpi.so']}}
  (self.bundle/'manifest.json').write_text(json.dumps(self.manifest));(self.bundle/'manifest.json').chmod(0o644)

 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.temp.cleanup()

 def write(self,p,data,mode=0o644):
  f=legacy.path(p);f.parent.mkdir(parents=True,exist_ok=True)
  f.write_bytes(data if isinstance(data,bytes) else data.encode());f.chmod(mode);return f

 def loaded_matches(self,p):return self.loaded_ok if Path(p)==self.bundle/'xt_ndpi.ko' else self.loaded_disk

 def command(self,args,check=True):
  self.calls.append(args)
  if args==['dmesg']:return self.logrc,self.dmesg
  if args==['iptables-save']:return 0,self.rules
  if args[:3]==['modinfo','-F','vermagic']:return 0,self.manifest['vermagic']
  if args==['modinfo','-n','xt_ndpi']:return 0,self.disk
  if args[0]=='systemctl':
   if args[1]=='show':return 0,'inactive'
   if args[1]=='is-enabled':return 1,'disabled'
   if args[1]=='is-active':return 0,'active'
   if args[1]=='daemon-reload':
    if self.reload_failure and check:self.reload_failure=False;raise RuntimeError('fixture daemon-reload failure')
    return 0,''
  raise AssertionError('Unexpected command: '+repr(args))

 def make_candidate_live(self):
  self.loaded_ok=True;self.loaded_disk=True
  self.write(self.disk,b'new-module');self.write('/usr/lib/x86_64-linux-gnu/xtables/libxt_ndpi.so',b'new-plugin')
  self.write('/sys/kernel/livepatch/xt_ndpi/enabled','1\n');self.write('/sys/kernel/livepatch/xt_ndpi/transition','0\n')

 def baseline(self):self.write(legacy.STATE/'lifecycle/before.json',json.dumps({'baseline_kind':'legacy-upgrade'}),0o600)

 def resume(self):
  self.baseline()
  self.write(legacy.STATE/'pending.json',json.dumps({'kernel':KERNEL,'sha256':self.manifest['sha256']['xt_ndpi.ko'],'module':self.disk,'staged_boot_id':OLD_BOOT,'transaction':str(TXN)}),0o600)
  self.write(TXN/'committed','Module staged; running module retained. Reboot required before activation.\n',0o600)

 def rollback_backup(self):
  self.write(legacy.STATE/'current.json',json.dumps({'transaction':str(TXN)}),0o600)
  self.write(TXN/'before.json',json.dumps({'files':{str(p):{} for p in legacy.HOLD_PATHS}}),0o600)
  for p in legacy.HOLD_PATHS:self.write(TXN/'files'/str(p).lstrip('/'),legacy.HOLD_TEXT)

 def test_known_old_loaded_requires_stage_and_reboot(self):
  result=legacy.check_legacy(self.root)
  self.assertTrue(result['requires_stage']);self.assertTrue(result['requires_reboot']);self.assertTrue(result['two_layers_present']);self.assertFalse(result['has_faults'])

 def test_root_private_unit_mode_from_old_installer_is_supported(self):
  for name in ('ds-guard.service','ds-guard-apply.service'):
   legacy.path('/etc/systemd/system/'+name).chmod(0o600)
  self.assertTrue(legacy.check_legacy(self.root)['requires_reboot'])
  legacy.path('/etc/systemd/system/ds-guard.service').chmod(0o666)
  with self.assertRaisesRegex(RuntimeError,'права'):legacy.check_legacy(self.root)

 def test_known_allocator_fault_is_disk_stage_only(self):
  self.dmesg=KNOWN_FAULT;result=legacy.check_legacy(self.root)
  self.assertTrue(result['has_faults']);self.assertTrue(result['known_allocator_faults']);self.assertTrue(result['requires_reboot'])

 def test_other_kernel_fault_refuses(self):
  self.dmesg=KNOWN_FAULT+'[103] WARNING: CPU: 0\n'
  with self.assertRaisesRegex(RuntimeError,'Ошибки ядра'):legacy.check_legacy(self.root)

 def test_known_header_without_allocator_stack_refuses(self):
  self.dmesg=KNOWN_FAULT.replace('realloc_wrapper','foreign_allocator')
  with self.assertRaisesRegex(RuntimeError,'Ошибки ядра'):legacy.check_legacy(self.root)

 def test_dirty_candidate_loaded_refuses_even_stage(self):
  self.make_candidate_live();self.dmesg=KNOWN_FAULT
  with self.assertRaisesRegex(RuntimeError,'Ошибки ядра'):legacy.check_legacy(self.root)

 def test_unreadable_kernel_log_refuses(self):
  self.logrc=1
  with self.assertRaisesRegex(RuntimeError,'Журнал ядра недоступен'):legacy.check_legacy(self.root)

 def test_changed_hold_refuses(self):
  self.write(legacy.HOLD_PATHS[0],legacy.HOLD_TEXT+'# foreign change\n')
  with self.assertRaisesRegex(RuntimeError,'Содержимое'):legacy.check_legacy(self.root)

 def test_marker_symlink_refuses(self):
  marker=legacy.path(legacy.MARKER);foreign=self.base/'foreign';foreign.write_text(legacy.MARKER_TEXT);marker.unlink();marker.symlink_to(foreign)
  with self.assertRaisesRegex(RuntimeError,'обычный файл'):legacy.check_legacy(self.root)

 def test_2x_refuses(self):
  self.write('/etc/systemd/system/ssh.service.d/zz-ds-guard.conf','unknown\n')
  with self.assertRaisesRegex(RuntimeError,'2.x'):legacy.check_legacy(self.root)

 def test_ndpi_runtime_rule_refuses(self):
  self.rules+='-A OUTPUT -m ndpi --proto bittorrent -j DROP\n'
  with self.assertRaisesRegex(RuntimeError,'остались правила nDPI'):legacy.check_legacy(self.root)

 def test_initial_missing_layers_refuses(self):
  self.rules='*filter\nCOMMIT\n'
  with self.assertRaisesRegex(RuntimeError,'DNS и NFQUEUE'):legacy.check_legacy(self.root)

 def test_verified_resume_can_report_missing_runtime_layers(self):
  self.resume();self.make_candidate_live();self.rules='*filter\nCOMMIT\n'
  result=legacy.check_legacy(self.root,allow_lifecycle=True,resumed=True)
  self.assertFalse(result['two_layers_present']);self.assertFalse(result['boot_filter_acceptance']);self.assertFalse(result['requires_reboot']);self.assertFalse(result['requires_stage'])

 def test_same_boot_resume_refuses(self):
  self.resume();p=legacy.path(legacy.STATE/'pending.json');d=json.loads(p.read_text());d['staged_boot_id']=BOOT;p.write_text(json.dumps(d))
  with self.assertRaisesRegex(RuntimeError,'новую загрузку'):legacy.check_legacy(self.root,allow_lifecycle=True,resumed=True)

 def test_resume_without_legacy_baseline_refuses(self):
  with self.assertRaisesRegex(RuntimeError,'Без исходного журнала'):legacy.check_legacy(self.root,allow_lifecycle=True,resumed=True)

 def test_release_requires_transaction_backup(self):
  self.make_candidate_live();self.baseline()
  with self.assertRaises(RuntimeError):legacy.release_hold(self.root)
  self.assertTrue(all(legacy.path(p).exists() for p in legacy.HOLD_PATHS))

 def test_release_only_exact90_preserves_marker_and95(self):
  self.make_candidate_live();self.baseline();self.rollback_backup()
  own95=self.write('/etc/systemd/system/ds-guard.service.d/95-safe-disabled.conf','another hold\n')
  result=legacy.release_hold(self.root)
  self.assertTrue(result['hold_released']);self.assertFalse(result['activation_accepted']);self.assertFalse(any(legacy.path(p).exists() for p in legacy.HOLD_PATHS))
  self.assertEqual(legacy.path(legacy.MARKER).read_text(),legacy.MARKER_TEXT);self.assertEqual(own95.read_text(),'another hold\n')

 def test_daemon_reload_failure_restores_both_holds(self):
  self.make_candidate_live();self.baseline();self.rollback_backup();self.reload_failure=True
  with self.assertRaisesRegex(RuntimeError,'fixture daemon'):legacy.release_hold(self.root)
  self.assertTrue(all(legacy.path(p).read_text()==legacy.HOLD_TEXT for p in legacy.HOLD_PATHS))

 def test_second_unlink_failure_restores_first_hold(self):
  self.make_candidate_live();self.baseline();self.rollback_backup();real_unlink=Path.unlink;second=legacy.path(legacy.HOLD_PATHS[1])
  def unlink(p,*args,**kwargs):
   if p==second:raise OSError('fixture second unlink failure')
   return real_unlink(p,*args,**kwargs)
  with patch.object(Path,'unlink',autospec=True,side_effect=unlink):
   with self.assertRaisesRegex(OSError,'second unlink'):legacy.release_hold(self.root)
  self.assertTrue(all(legacy.path(p).read_text()==legacy.HOLD_TEXT for p in legacy.HOLD_PATHS))

if __name__=='__main__':unittest.main()
