#!/usr/bin/env python3
"""Recovery ownership fixtures: temporary files, no system commands or sysctls."""
import base64
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import network_tuning as tuning


class RecoveryOwnershipTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='ds-guard-recovery-test-')
  self.base=Path(self.temp.name)
  self.base_patch=patch.object(tuning,'BASE',self.base);self.base_patch.start()
  self.old=self.base/'11111111-1111-1111-1111-111111111111';self.old.mkdir()
  self.new=self.base/'22222222-2222-2222-2222-222222222222';self.new.mkdir()
  self.process_patch=patch.object(tuning.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='inactive\n'))
  self.process=self.process_patch.start()

 def tearDown(self):
  self.process_patch.stop();self.base_patch.stop();self.temp.cleanup()

 def pending(self,p):
  (self.base/'pending.json').write_text(json.dumps({'transaction':str(p)}))

 def assert_no_worker_stop(self):
  self.assertNotIn(['systemctl','stop','ds-guard-safe-tune.service'],[c.args[0] for c in self.process.call_args_list])

 def prepare_rollback(self,p,boot_id=None):
  target=self.base/'owned.conf';target.write_text('tuned\n')
  data={'boot_id':boot_id or Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'values':{'test.capacity':'4096'},
        'operation_id':'fixture-operation',
        'files':{str(target):{'data':base64.b64encode(b'original\n').decode(),'mode':0o640,'uid':os.getuid(),'gid':os.getgid()}}}
  (p/'before.json').write_text(json.dumps(data));self.pending(p)
  return target

 def test_delayed_rolled_back_timer_preserves_next_worker_and_pending(self):
  (self.old/'rolled-back.json').write_text('{}');self.pending(self.new)
  tuning.recover(self.old)
  self.assert_no_worker_stop()
  self.assertEqual(tuning.pending_transaction(),str(self.new))
  self.process.assert_called_once_with(['systemctl','stop','ds-guard-tuning-rollback-'+self.old.name+'.timer'],capture_output=True,timeout=35)

 def test_delayed_accepted_timer_preserves_next_worker_and_pending(self):
  (self.old/'accepted.json').write_text('{}');self.pending(self.new)
  tuning.recover(self.old)
  self.assert_no_worker_stop();self.assertEqual(tuning.pending_transaction(),str(self.new))

 def test_nonterminal_foreign_timer_refuses_without_stopping_worker(self):
  self.pending(self.new)
  with self.assertRaisesRegex(RuntimeError,'не совпадает'):tuning.recover(self.old)
  self.process.assert_not_called();self.assertEqual(tuning.pending_transaction(),str(self.new))

 def test_recover_current_without_pending_does_not_stop_worker(self):
  tuning.recover();self.process.assert_not_called()

 def test_current_timeout_restores_and_cancels_its_timer(self):
  target=self.prepare_rollback(self.new);values={'test.capacity':'8192'}
  def fake_sysctl(args,timeout=30):
   self.assertEqual(args[0],'sysctl')
   if args[1]=='-w':
    key,value=args[2].split('=',1);values[key]=value;return args[2]
   self.assertEqual(args[1],'-n');return values[args[2]]
  with patch.object(tuning,'run',side_effect=fake_sysctl):tuning.recover()
  self.assertEqual(values,{'test.capacity':'4096'})
  self.assertEqual(target.read_text(),'original\n');self.assertEqual(target.stat().st_mode&0o777,0o640)
  self.assertTrue((self.new/'rolled-back.json').exists());self.assertIsNone(tuning.pending_transaction())
  receipt=json.loads((self.new/'rolled-back.json').read_text())
  self.assertEqual(receipt['values'],values);self.assertEqual(receipt['operation_id'],'fixture-operation')
  self.assertEqual([c.args[0] for c in self.process.call_args_list],[
   ['systemctl','stop','ds-guard-safe-tune.service'],
   ['systemctl','stop','ds-guard-tuning-rollback-'+self.new.name+'.timer']])

 def test_reboot_refusal_preserves_pending_and_files(self):
  target=self.prepare_rollback(self.new,'different-boot')
  with patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'После перезагрузки'):tuning.recover()
   commands.assert_not_called()
  self.assertEqual(target.read_text(),'tuned\n');self.assertEqual(tuning.pending_transaction(),str(self.new))

 def test_rollback_symlink_refuses_before_any_sysctl_or_foreign_file_write(self):
  target=self.prepare_rollback(self.new);foreign=self.base/'foreign.conf';foreign.write_text('foreign\n')
  target.unlink();target.symlink_to(foreign)
  with patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'символическая ссылка'):tuning.rollback(self.new)
   commands.assert_not_called()
  self.assertEqual(foreign.read_text(),'foreign\n');self.assertTrue(target.is_symlink())
  self.assertFalse((self.new/'rolled-back.json').exists())

 def test_rollback_missing_owner_refuses_before_any_sysctl(self):
  target=self.prepare_rollback(self.new)
  before=json.loads((self.new/'before.json').read_text());del before['files'][str(target)]['uid']
  (self.new/'before.json').write_text(json.dumps(before))
  with patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'нет владельца'):tuning.rollback(self.new)
   commands.assert_not_called()
  self.assertEqual(target.read_text(),'tuned\n')

 def launch_fixture(self,unit):
  real_path=Path
  def redirect(value,*args):
   if str(value)=='/etc/systemd/system/ds-guard-safe-tune-recover.service':return unit
   return real_path(value,*args)
  return patch.object(tuning,'Path',side_effect=redirect)

 def test_launch_symlink_unit_refuses_before_copy_or_foreign_file_write(self):
  foreign=self.base/'foreign.service';foreign.write_text('foreign\n')
  unit=self.base/'recovery.service';unit.symlink_to(foreign)
  with self.launch_fixture(unit),patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'символическая ссылка'):tuning.prepare_launch()
   commands.assert_not_called()
  self.assertEqual(foreign.read_text(),'foreign\n');self.assertFalse((self.base/'network_tuning.py').exists())

 def test_launch_foreign_regular_unit_refuses_before_copy(self):
  unit=self.base/'recovery.service';unit.write_text('foreign\n')
  with self.launch_fixture(unit),patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'не принадлежит'):tuning.prepare_launch()
   commands.assert_not_called()
  self.assertEqual(unit.read_text(),'foreign\n');self.assertFalse((self.base/'network_tuning.py').exists())

 def test_launch_symlink_helper_refuses_before_foreign_file_write(self):
  foreign=self.base/'foreign.py';foreign.write_text('foreign\n')
  (self.base/'network_tuning.py').symlink_to(foreign);unit=self.base/'recovery.service'
  with self.launch_fixture(unit),patch.object(tuning,'run') as commands:
   with self.assertRaisesRegex(RuntimeError,'символическая ссылка'):tuning.prepare_launch()
   commands.assert_not_called()
  self.assertEqual(foreign.read_text(),'foreign\n');self.assertFalse(unit.exists())
  self.assertFalse((self.new/'rolled-back.json').exists())

 def test_stop_failure_does_not_attempt_rollback_or_clear_pending(self):
  target=self.prepare_rollback(self.new)
  self.process.return_value=subprocess.CompletedProcess([],1)
  with patch.object(tuning,'rollback') as rollback:
   with self.assertRaisesRegex(RuntimeError,'Не удалось остановить'):tuning.recover()
   rollback.assert_not_called()
  self.assertEqual(target.read_text(),'tuned\n');self.assertEqual(tuning.pending_transaction(),str(self.new))

 def test_recovery_holds_state_handoff_until_rollback_finishes(self):
  self.pending(self.old)
  stopped=threading.Event();allow_restore=threading.Event();launch_checked=threading.Event();errors=[]
  def fake_process(args,**kwargs):
   if args==['systemctl','stop','ds-guard-safe-tune.service']:
    stopped.set()
    if not allow_restore.wait(5):raise AssertionError('test synchronization timeout')
   return subprocess.CompletedProcess(args,0)
  def fake_rollback(p):
   (p/'rolled-back.json').write_text('{}')
  def recover():
   try:tuning.recover(self.old)
   except BaseException as e:errors.append(e)
  def launch():
   try:
    with tuning.state_lock():launch_checked.set()
   except BaseException as e:errors.append(e)
  self.process.side_effect=fake_process
  with patch.object(tuning,'rollback',side_effect=fake_rollback):
   worker=threading.Thread(target=recover);worker.start()
   try:
    self.assertTrue(stopped.wait(5));next_launch=threading.Thread(target=launch);next_launch.start()
    self.assertFalse(launch_checked.wait(0.05))
   finally:allow_restore.set()
   worker.join(5);next_launch.join(5)
  self.assertFalse(worker.is_alive());self.assertFalse(next_launch.is_alive());self.assertEqual(errors,[])
  self.assertTrue(launch_checked.is_set());self.assertIsNone(tuning.pending_transaction())


if __name__=='__main__':unittest.main()
