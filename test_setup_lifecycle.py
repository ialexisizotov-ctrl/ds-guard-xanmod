import unittest,importlib.util,tempfile,json,os
from unittest.mock import patch
import lifecycle
from pathlib import Path
from setup_ru import choose_kernel,cpu_flags,V2,V3,Refusal
from network_tuning import desired_values
from lifecycle import conflicts,changed_files
spec=importlib.util.spec_from_file_location('kernel_stage',Path(__file__).with_name('kernel-stage.py'))
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)

CAT={'7.0.12-v2':{'cpu_level':'x86-64-v2'},'7.2.9-v3':{'cpu_level':'x86-64-v3'},
 '6.8.0-147':{'cpu_level':'x86-64','kind':'ubuntu','os_version':'24.04'},
 '6.8.0-87':{'cpu_level':'x86-64','kind':'ubuntu','os_version':'22.04'}}

class Selection(unittest.TestCase):
 def test_active_unsupported_console_driver_selects_ubuntu(self):
  cat={k:{**m,**({'unsupported_loaded_modules':['vga16fb','vgastate']} if 'v2' in k or 'v3' in k else {})} for k,m in CAT.items()}
  self.assertEqual(choose_kernel(cat,'ubuntu','24.04',V3,'6.8.0','prefer-xanmod',{'vga16fb'})[0],'6.8.0-147')
  with self.assertRaises(Refusal):choose_kernel(cat,'ubuntu','24.04',V3,'6.8.0','xanmod',{'vgastate'})
 def test_cpu_intersection_and_fallback(self):
  flags=cpu_flags('flags : '+' '.join(V3)+'\nflags : '+' '.join(V2)+'\n')
  self.assertEqual(choose_kernel(CAT,'ubuntu','24.04',flags,'6.8.0','prefer-xanmod')[0],'7.0.12-v2')
  self.assertEqual(choose_kernel(CAT,'ubuntu','24.04',V3,'6.8.0','prefer-xanmod')[0],'7.2.9-v3')
  with self.assertRaises(Refusal):choose_kernel(CAT,'ubuntu','24.04',V3,'7.3.1','prefer-xanmod')
  self.assertEqual(choose_kernel(CAT,'ubuntu','24.04',set(),'6.8.0','prefer-xanmod')[0],'6.8.0-147')
  with self.assertRaises(Refusal):choose_kernel(CAT,'ubuntu','24.04',set(),'6.8.0-148-generic','prefer-xanmod')
 def test_os_and_explicit_policy(self):
  self.assertEqual(choose_kernel(CAT,'ubuntu','22.04',V3,'6.8.0','prefer-xanmod')[0],'6.8.0-87')
  with self.assertRaises(Refusal):choose_kernel(CAT,'ubuntu','22.04',V3,'old','xanmod')
  with self.assertRaises(Refusal):choose_kernel(CAT,'debian','13',V3,'old','prefer-xanmod')
  self.assertEqual(choose_kernel(CAT,'ubuntu','24.04',set(),'custom','keep')[0],'custom')

class RestoreOwnership(unittest.TestCase):
 def test_manual_change_never_overwritten(self):
  before={'old':'original','foreign':'before'};after={'old':'ours','new':'ours','foreign':'before'}
  self.assertEqual(conflicts(before,after,{'old':'original','new':'ours','foreign':'manual'}),[])
  self.assertEqual(conflicts(before,after,{'old':'manual','new':'ours'}),['old'])
  self.assertEqual(conflicts(before,after,{'old':'ours','new':'manual'}),['new'])
 def test_missing_new_file_is_already_restored(self):
  self.assertEqual(conflicts({}, {'new':'ours'},{}),[])
  self.assertEqual(changed_files({'empty':None},{'empty':None}),set())
  self.assertEqual(lifecycle.affected_module_kernels(['/etc/sysctl.d/profile.conf','/usr/local/lib/ds-guard-safe/assets/7.2/xt_ndpi.ko']),set())
  self.assertEqual(lifecycle.affected_module_kernels(['/lib/modules/6.8.0-147-generic/updates/dkms/xt_ndpi.ko']),{'6.8.0-147-generic'})
 def test_file_owner_drift_refused(self):
  b={'files':{},'values':{},'packages':{},'iptables':''}
  a={'files':{'/owned':'ours'},'file_owners':{'/owned':[0,0]},'values':{},'packages':{},'iptables':''}
  now={**a,'file_owners':{'/owned':[1,1]}}
  with self.assertRaisesRegex(RuntimeError,'владелец'):lifecycle.verify_no_conflict(b,a,now)
 def test_kernel_only_disable_does_not_touch_unrelated_services_or_files(self):
  b={'files':{},'file_owners':{},'values':{},'packages':{},'iptables':'','manual':[],'units':{},'ownership_schema':1,'owned_packages':{}};a=dict(b)
  with tempfile.TemporaryDirectory() as d, patch.object(lifecycle,'STATE',Path(d)),patch.object(lifecycle,'read_records',return_value=(b,a)),patch.object(lifecycle,'snapshot',return_value=a),patch.object(lifecycle,'run') as run,patch.object(lifecycle,'restore_file') as restore:
   self.assertEqual(lifecycle.disable(),0)
   run.assert_not_called();restore.assert_not_called()
 @unittest.skipUnless(os.geteuid()==0,'ownership restoration needs an isolated root test')
 def test_file_content_mode_and_group_restored(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);state=root/'state';state.mkdir();target=root/'config'
   target.write_text('original');target.chmod(0o640);os.chown(target,0,12345)
   item=lifecycle.stamp(target)
   backup=state/'files'/str(target).lstrip('/');backup.parent.mkdir(parents=True);backup.write_text('original')
   (state/'before.json').write_text(json.dumps({'file_owners':{str(target):[0,12345]}}))
   target.write_text('changed');target.chmod(0o600);os.chown(target,0,0)
   with patch.object(lifecycle,'STATE',state):lifecycle.restore_file(str(target),item)
   self.assertEqual(target.read_text(),'original');self.assertEqual(target.stat().st_mode&0o777,0o640);self.assertEqual(target.stat().st_gid,12345)

class BootFallback(unittest.TestCase):
 def test_stable_existing_fallback(self):
  env='saved_entry=gnulinux-advanced-abcd>gnulinux-6.8.0-147-generic-advanced-abcd'
  config="submenu 'gnulinux-advanced-abcd'\nmenuentry 'gnulinux-6.8.0-147-generic-advanced-abcd'"
  self.assertEqual(stage.fallback_kernel(env,config),'6.8.0-147-generic')
  with self.assertRaises(AssertionError):stage.fallback_kernel(env+'\nnext_entry=1',config)
  with self.assertRaises(AssertionError):stage.fallback_kernel(env,'')
  with self.assertRaises(AssertionError):stage.fallback_kernel('saved_entry=0',config)
  with self.assertRaises(AssertionError):stage.fallback_kernel(env.replace('saved_entry=gnulinux-advanced-abcd','saved_entry=gnulinux-advanced-bbbb'),config+"\nsubmenu 'gnulinux-advanced-bbbb'")

class TuningCapacity(unittest.TestCase):
 def test_higher_limits_and_triplets_preserved(self):
  current={'net.core.rmem_max':'134217728','net.core.wmem_max':'268435456','net.core.netdev_max_backlog':'40000','net.core.somaxconn':'32768','net.ipv4.tcp_max_syn_backlog':'16384','net.netfilter.nf_conntrack_max':'2097152','net.ipv4.tcp_mtu_probing':'2','net.ipv4.tcp_fastopen':'1024','net.ipv4.tcp_rmem':'8192 262144 134217728','net.ipv4.tcp_wmem':'8192 262144 268435456'}
  for ram in (2048,4096,8192):
   d=desired_values(current,ram)
   for k in current:
    if k=='net.ipv4.tcp_fastopen':self.assertEqual(int(d[k]),1027)
    elif k.endswith(('tcp_rmem','tcp_wmem')):self.assertEqual(d[k],current[k])
    else:self.assertEqual(d[k],current[k])

if __name__=='__main__':unittest.main()
