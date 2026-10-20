import contextlib,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import suricata_retry as s

class RetryOrigin(unittest.TestCase):
 def setUp(self):
  self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
  self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=Path.home())))
  self.state=self.root/'state';self.txn=self.state/'transactions/12345678-1234-1234-1234-123456789abc'
  self.txn.mkdir(parents=True,mode=0o700)
  self.yaml=self.root/'suricata.yaml';self.yaml.write_bytes(b'pristine package configuration\n');self.yaml.chmod(0o644)
  self.stack.enter_context(patch.object(s,'STATE',self.state));self.stack.enter_context(patch.object(s,'YAML',self.yaml))
  self.saved=self.txn/'files'/self.yaml.relative_to('/');self.saved.parent.mkdir(parents=True);self.saved.write_bytes(self.yaml.read_bytes());self.saved.chmod(0o644)
  self.before={'suricata_initial_package_status':'','units':{'suricata.service':{'active':'inactive','enabled':'not-found'}},'files':{str(self.yaml):{'symlink':False,'new_package_default':True}}}
  self.write(self.state/'current.json',{'transaction':str(self.txn)})
  self.write(self.txn/'before.json',self.before)
  self.write(self.txn/'rolled-back',{'files_restored_verified':True,'foreign_firewall_preserved':True,'previously_active_services_restored':True})
  self.write(self.txn/'suricata-start-guard.json',{'schema':1,'transaction':str(self.txn),'dropin':s.HOLD,'initial_package_status':'','initial_unit':self.before['units']['suricata.service']})
  self.active='inactive';self.enabled='disabled';self.dropins='';self.package='installed';self.commands=[]
 def write(self,p,v):p.write_text(json.dumps(v));p.chmod(0o600)
 def execute(self,args):
  self.commands.append(args)
  if args[0]=='dpkg-query':return 0,self.package
  return 0,'ActiveState='+self.active+'\nUnitFileState='+self.enabled+'\nDropInPaths='+self.dropins+'\nFragmentPath=/usr/lib/systemd/system/suricata.service'
 def test_proven_pristine_rollback_accepted_read_only(self):
  self.assertIsNotNone(s.proof(self.execute));self.assertEqual({x[0] for x in self.commands},{'dpkg-query','systemctl'})
  self.assertTrue(all(x[1]=='show' for x in self.commands if x[0]=='systemctl'))
 def test_changed_config_not_adopted(self):
  self.yaml.write_bytes(b'operator customization');self.assertIsNone(s.proof(self.execute))
 def test_active_enabled_or_custom_unit_not_adopted(self):
  for key,value in [('active','active'),('enabled','enabled'),('dropins','/etc/custom.conf')]:
   with self.subTest(key=key):
    old=getattr(self,key);setattr(self,key,value);self.assertIsNone(s.proof(self.execute));setattr(self,key,old)
 def test_incomplete_rollback_not_adopted(self):
  (self.txn/'rolled-back').unlink();self.assertIsNone(s.proof(self.execute))
 def test_missing_origin_receipt_not_adopted(self):
  (self.txn/'suricata-start-guard.json').unlink();self.assertIsNone(s.proof(self.execute))
 def test_foreign_initial_install_not_adopted(self):
  self.before['suricata_initial_package_status']='installed';self.write(self.txn/'before.json',self.before)
  self.assertIsNone(s.proof(self.execute))
 def test_symlink_and_writable_evidence_not_adopted(self):
  self.saved.chmod(0o666);self.assertIsNone(s.proof(self.execute));self.saved.chmod(0o644)
  self.saved.unlink();self.saved.symlink_to(self.yaml);self.assertIsNone(s.proof(self.execute))
 def test_second_completed_rollback_retains_original_proof(self):
  nxt=self.state/'transactions/22222222-2222-2222-2222-222222222222';nxt.mkdir(mode=0o700)
  self.write(nxt/'rolled-back',json.loads((self.txn/'rolled-back').read_text()))
  self.write(nxt/'before.json',{'suricata_initial_package_status':'installed'})
  self.write(self.state/'current.json',{'transaction':str(nxt)})
  self.assertEqual(s.proof(self.execute)['transaction'],str(self.txn))

if __name__=='__main__':unittest.main()
