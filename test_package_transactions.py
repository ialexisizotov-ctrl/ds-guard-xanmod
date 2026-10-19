import json
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
import package_transactions as ledger

class PackageTransactions(unittest.TestCase):
    def setUp(self):
        mocked=patch.object(ledger,'check_archives',return_value=[])
        mocked.start();self.addCleanup(mocked.stop)
    def test_foreign_concurrent_install_is_not_claimed(self):
        log='2026-10-19 12:00:00 install owned:amd64 <none> 1.0\n'
        after={'owned:amd64':('owned','1.0'),'foreign:amd64':('foreign','2.0')}
        self.assertEqual(ledger.logged_installs(log,{},after),{'owned':'1.0'})

    def test_existing_upgrade_and_unfinished_package_not_claimed(self):
        log='2026-10-19 12:00:00 upgrade existing:amd64 1.0 2.0\n2026-10-19 12:00:00 install unfinished:amd64 <none> 1.0\n'
        self.assertEqual(ledger.logged_installs(log,{'existing:amd64':('existing','1.0')},{'existing:amd64':('existing','2.0')}),{})

    def test_multiarch_binary_identity(self):
        log='2026-10-19 12:00:00 install library:arm64 <none> 1.0\n'
        self.assertEqual(ledger.logged_installs(log,{}, {'library:arm64':('library:arm64','1.0')}),{'library:arm64':'1.0'})

    def test_changed_version_refused(self):
        with self.assertRaises(RuntimeError):
            ledger.logged_installs('2026-10-19 12:00:00 install owned:amd64 <none> 1.0',{}, {'owned:amd64':('owned','2.0')})

    def test_scoped_log_arguments(self):
        self.assertEqual(ledger.with_private_log(['dpkg','-i','/tmp/a.deb'],Path('/private/log')),['dpkg','--log=/private/log','-i','/tmp/a.deb'])
        self.assertIn('Dpkg::Options::=--log=/private/log',ledger.with_private_log(['apt-get','-y','install','a'],Path('/private/log')))
        for command in [['apt-get','remove','a'],['dpkg','-i','--log=/else','a'],['bash','install']]:
            with self.assertRaises(RuntimeError):ledger.with_private_log(command,Path('/private/log'))

    def fixture(self, root):
        pending=root/'lifecycle/pending.json';pending.parent.mkdir()
        operation=str(uuid.uuid4());pending.write_text(json.dumps({'operation_id':operation}))
        return operation

    def test_failed_child_still_records_successful_owned_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);operation=self.fixture(root)
            def child(command,**kwargs):
                log=Path(command[1].split('=',1)[1])
                log.write_text('2026-10-19 12:00:00 install owned:all <none> 1.0\n')
                return subprocess.CompletedProcess(command,1)
            with patch.object(ledger,'STATE',root),patch.object(ledger,'package_state',side_effect=[{}, {'owned:all':('owned','1.0'),'foreign:all':('foreign','9')}]),patch.object(ledger.subprocess,'run',side_effect=child):
                self.assertEqual(ledger.execute(['dpkg','-i','fixture.deb']),1)
            receipt=json.loads(next((root/'lifecycle/package-receipts').glob('*.json')).read_text())
            self.assertEqual(receipt,{'schema':1,'operation_id':operation,'completed':True,'returncode':1,'installed':{'owned':'1.0'}})

    def test_timeout_remains_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            with patch.object(ledger,'STATE',root),patch.object(ledger,'package_state',return_value={}),patch.object(ledger.subprocess,'run',side_effect=subprocess.TimeoutExpired('dpkg',1)):
                with self.assertRaises(subprocess.TimeoutExpired):ledger.execute(['dpkg','-i','fixture.deb'])
            receipt=json.loads(next((root/'lifecycle/package-receipts').glob('*.json')).read_text())
            self.assertFalse(receipt['completed'])

    def test_direct_install_has_separate_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(ledger,'STATE',root),patch.object(ledger,'package_state',return_value={}),patch.object(ledger.subprocess,'run',return_value=subprocess.CompletedProcess([],0)):
                self.assertEqual(ledger.execute(['dpkg','-i','fixture.deb']),0)
            receipt=json.loads(next((root/'package-transactions').glob('*.json')).read_text())
            self.assertIsNone(receipt['operation_id'])
            self.assertFalse((root/'lifecycle').exists())

    def test_shell_timeout_reaches_controller_as_timeout(self):
        import controller
        with tempfile.TemporaryDirectory() as directory:
            transaction=Path(directory)
            (transaction/'package-timeout').write_text('')
            with patch.object(controller.subprocess,'run',return_value=subprocess.CompletedProcess([],1)):
                with self.assertRaises(subprocess.TimeoutExpired):controller.driver('apply',transaction)

if __name__=='__main__':unittest.main()
