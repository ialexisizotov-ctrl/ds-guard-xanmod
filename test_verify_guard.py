"""Real flock/process regression: readers wait for a rule-generation writer."""
from contextlib import redirect_stderr
import fcntl,io,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
import domain_rotation as rotation
import verify_guard as guard

class VerifyGuard(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.lock=self.root/'apply.lock'; self.lock.touch(mode=0o600)
        p=mock.patch.object(rotation,'APPLY_LOCK',self.lock);p.start();self.addCleanup(p.stop)

    def test_verifier_holds_same_lock_in_child(self):
        def child(args,**kwargs):
            self.assertEqual(args[-2:],[ 'verify-locked',str(self.root)])
            fd=os.open(self.lock,os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            return subprocess.CompletedProcess(args,0)
        with mock.patch.object(guard.subprocess,'run',side_effect=child):
            self.assertEqual(guard.verify(self.root),0)

    def test_waits_for_in_progress_writer_then_checks_committed_generation(self):
        writer = '''import fcntl,pathlib,sys,time
p=pathlib.Path(sys.argv[1]);f=open(p/'apply.lock','r+')
fcntl.flock(f,fcntl.LOCK_EX)
(p/'generation').write_text('incomplete')
print('locked',flush=True)
time.sleep(.3)
(p/'generation').write_text('complete')
'''
        real_run=subprocess.run
        p=subprocess.Popen([sys.executable,'-c',writer,str(self.root)],stdout=subprocess.PIPE,text=True)
        self.addCleanup(lambda:p.poll() is None and p.kill())
        self.assertEqual(p.stdout.readline().strip(),'locked')
        self.assertEqual((self.root/'generation').read_text(),'incomplete')
        reader='import pathlib,sys;sys.exit(0 if pathlib.Path(sys.argv[1]).read_text()=="complete" else 1)'
        def child(args,**kwargs):
            return real_run([sys.executable,'-c',reader,str(self.root/'generation')],**kwargs)
        with mock.patch.object(guard.subprocess,'run',side_effect=child):
            self.assertEqual(guard.verify(self.root),0)
        self.assertEqual(p.wait(timeout=3),0);p.stdout.close()

    def test_real_verifier_failure_is_not_retried_or_ignored(self):
        with mock.patch.object(guard.subprocess,'run',return_value=subprocess.CompletedProcess([],1)) as run, redirect_stderr(io.StringIO()) as log:
            self.assertEqual(guard.verify(self.root),1)
            run.assert_called_once()
            self.assertIn('install.log',log.getvalue())

    def test_timeout_releases_lock(self):
        with mock.patch.object(guard.subprocess,'run',side_effect=subprocess.TimeoutExpired('verify',120)):
            with self.assertRaises(subprocess.TimeoutExpired):guard.verify(self.root)
        with self.lock.open('r+') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_unsafe_lock_is_rejected_before_verification(self):
        self.lock.chmod(0o666)
        with mock.patch.object(guard.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):guard.verify(self.root)
            run.assert_not_called()

    def test_both_driver_acceptance_paths_use_guard(self):
        text=(Path(__file__).parent/'driver.sh').read_text()
        self.assertEqual(text.count('python3 "$DS_SAFE_ROOT/verify_guard.py" "$DS_TXN"'),2)

if __name__=='__main__':unittest.main()
