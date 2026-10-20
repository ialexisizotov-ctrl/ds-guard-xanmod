import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lifecycle
import transaction as tr


@unittest.skipUnless(os.geteuid() == 0, 'Secure root-owned guard fixtures require root')
class SuricataInitialGuard(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='dsg-suri-test-', dir='/run'))
        self.root = Path(self.temp)
        self.txn = self.root / 'transaction'
        self.txn.mkdir(mode=0o700)
        self.hold = self.root / 'system/suricata.service.d/97-safe-initial-install.conf'
        self.yaml = self.root / 'config/suricata.yaml'
        self.nfqueue = self.hold.with_name('nfqueue.conf')
        for key, value in [('SURICATA_HOLD', self.hold), ('SURICATA_YAML', self.yaml),
                           ('SURICATA_NFQUEUE', self.nfqueue)]:
            self.stack.enter_context(patch.object(tr, key, value))
        self.b = {'files': {}, 'units': {'suricata.service': {'active': 'inactive', 'enabled': 'not-found'}},
                  'suricata_initial_package_status': ''}
        self.write_before()
        self.package = ''
        self.active = 'inactive'
        self.enabled = 'not-found'
        self.commands = []
        self.failure = None
        self.stack.enter_context(patch.object(tr, 'suricata_package_status', side_effect=lambda: self.package))
        self.stack.enter_context(patch.object(tr, 'run', side_effect=self.execute))

    def write_before(self):
        (self.txn / 'before.json').write_text(json.dumps(self.b))
        (self.txn / 'before.json').chmod(0o600)

    def execute(self, args, check=True, **kwargs):
        self.commands.append(args)
        if args == self.failure:
            if check:
                raise RuntimeError('injected command failure')
            return ''
        if args[:2] == ['systemctl', 'is-active']:
            return self.active
        if args[:2] == ['systemctl', 'is-enabled']:
            return self.enabled
        if args == ['systemctl', 'stop', 'suricata.service']:
            self.active = 'inactive'
        return ''

    def arm(self):
        self.assertTrue(tr.arm_suricata_guard(self.txn))
        self.assertEqual(self.hold.read_text(), '[Unit]\nConditionPathExists=' +
                         str(self.txn / 'suricata-start-approved') + '\n')
        self.assertFalse((self.txn / 'suricata-start-approved').exists())

    def prepare_config(self):
        self.yaml.parent.mkdir(parents=True, exist_ok=True)
        self.yaml.write_text('%YAML 1.1\n---\n')
        self.yaml.chmod(0o600)
        self.nfqueue.write_text(tr.SURICATA_NFQUEUE_TEXT)
        self.nfqueue.chmod(0o644)
        self.b['files'][str(self.yaml)] = {'new_package_default': True, 'symlink': False}
        self.write_before()

    def test_arm_durable_owned_receipt_and_dropin_repeat(self):
        with patch.object(tr.os, 'fsync', wraps=os.fsync) as sync:
            self.arm()
            self.assertGreaterEqual(sync.call_count, 8)
        self.assertEqual(self.hold.stat().st_mode & 0o777, 0o644)
        receipt = self.txn / 'suricata-start-guard.json'
        self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
        identity = (receipt.stat().st_ino, self.hold.stat().st_ino)
        self.package = 'installed'
        self.arm()
        self.assertEqual(identity, (receipt.stat().st_ino, self.hold.stat().st_ino))
        self.assertFalse(any('start' in args or 'enable' in args for args in self.commands))

    def test_installed_suricata_keeps_prior_behavior(self):
        for active in ['active', 'inactive']:
            with self.subTest(active=active):
                self.b['suricata_initial_package_status'] = 'installed'
                self.b['units']['suricata.service'] = {'active': active, 'enabled': 'enabled'}
                self.write_before()
                self.assertFalse(tr.arm_suricata_guard(self.txn))
                self.assertFalse(tr.release_suricata_guard(self.txn))
                self.assertFalse(self.hold.exists())
                self.assertEqual(self.commands, [])

    def test_nonabsence_and_package_race_refuse_before_hold(self):
        for initial, current in [('config-files', ''), (None, ''), ('', 'installed')]:
            with self.subTest(initial=initial, current=current):
                self.b['suricata_initial_package_status'] = initial
                self.write_before()
                self.package = current
                with self.assertRaises(RuntimeError):
                    tr.arm_suricata_guard(self.txn)
                self.assertFalse(self.hold.exists())

    def test_foreign_original_unit_refuses(self):
        self.b['units']['suricata.service'] = {'active': 'inactive', 'enabled': 'disabled'}
        self.write_before()
        with self.assertRaisesRegex(RuntimeError, 'Прежняя служба'):
            tr.arm_suricata_guard(self.txn)
        self.assertFalse(self.hold.exists())
        self.assertFalse((self.txn / 'suricata-start-guard.json').exists())
        self.assertEqual(tr.restore_suricata_guard(self.txn, self.b), set())

    def test_foreign_original_yaml_refuses_without_poisoning_rollback(self):
        self.b['files'][str(self.yaml)] = {'symlink': False}
        self.write_before()
        with self.assertRaisesRegex(RuntimeError, 'Прежние файлы'):
            tr.arm_suricata_guard(self.txn)
        self.assertFalse(self.hold.exists())
        self.assertFalse((self.txn / 'suricata-start-guard.json').exists())
        self.assertEqual(tr.restore_suricata_guard(self.txn, self.b), set())

    def test_current_active_refuses_without_poisoning_rollback(self):
        self.active = 'active'
        with self.assertRaisesRegex(RuntimeError, 'уже запущена'):
            tr.arm_suricata_guard(self.txn)
        self.assertFalse(self.hold.exists())
        self.assertFalse((self.txn / 'suricata-start-guard.json').exists())
        self.assertEqual(tr.restore_suricata_guard(self.txn, self.b), set())

    def test_foreign_hold_and_parent_symlink_preserved(self):
        self.hold.parent.mkdir(parents=True)
        self.hold.write_text('foreign\n')
        with self.assertRaises(RuntimeError):
            tr.arm_suricata_guard(self.txn)
        self.assertEqual(self.hold.read_text(), 'foreign\n')
        self.hold.unlink()
        self.hold.parent.rmdir()
        target = self.root / 'foreign'
        target.mkdir()
        self.hold.parent.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'ссылкой'):
            tr.arm_suricata_guard(self.txn)
        self.assertEqual(list(target.iterdir()), [])

    def test_reload_failure_leaves_durable_guard(self):
        self.failure = ['systemctl', 'daemon-reload']
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            tr.arm_suricata_guard(self.txn)
        self.assertTrue(self.hold.exists())
        self.assertTrue((self.txn / 'suricata-start-guard.json').exists())

    def test_fsync_failure_cannot_report_armed(self):
        with patch.object(tr, '_suri_sync_directory', side_effect=OSError('injected fsync')):
            with self.assertRaises(OSError):
                tr.arm_suricata_guard(self.txn)
        self.assertNotIn(['systemctl', 'daemon-reload'], self.commands)

    def test_release_requires_default_exact_nfqueue_and_syntax_pass(self):
        self.arm()
        with self.assertRaisesRegex(RuntimeError, 'исходная пакетная'):
            tr.release_suricata_guard(self.txn)
        self.prepare_config()
        self.nfqueue.write_text(tr.SURICATA_NFQUEUE_TEXT + '# foreign\n')
        with self.assertRaisesRegex(RuntimeError, 'NFQUEUE'):
            tr.release_suricata_guard(self.txn)
        self.nfqueue.write_text(tr.SURICATA_NFQUEUE_TEXT)
        self.failure = ['/usr/bin/suricata', '-T', '-c', str(self.yaml)]
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            tr.release_suricata_guard(self.txn)
        self.assertTrue(self.hold.exists())
        self.failure = None
        self.assertTrue(tr.release_suricata_guard(self.txn))
        self.assertFalse(self.hold.exists())
        self.assertEqual(self.commands[-2:], [
            ['/usr/bin/suricata', '-T', '-c', str(self.yaml)], ['systemctl', 'daemon-reload']])

    def test_foreign_changed_hold_owner_and_approval_refuse(self):
        self.arm()
        self.prepare_config()
        original = self.hold.read_bytes()
        self.hold.write_bytes(original + b'# foreign\n')
        with self.assertRaises(RuntimeError):
            tr.release_suricata_guard(self.txn)
        self.hold.write_bytes(original)
        self.hold.chmod(0o666)
        with self.assertRaises(RuntimeError):
            tr.release_suricata_guard(self.txn)
        self.hold.chmod(0o644)
        os.chown(self.hold, 65534, 65534)
        with self.assertRaises(RuntimeError):
            tr.release_suricata_guard(self.txn)
        os.chown(self.hold, 0, 0)
        (self.txn / 'suricata-start-approved').touch()
        with self.assertRaisesRegex(RuntimeError, 'Неожиданное разрешение'):
            tr.release_suricata_guard(self.txn)
        self.assertTrue(self.hold.exists())

    def test_rollback_rearms_before_stop_then_cleanup_only_if_disabled(self):
        self.arm()
        self.prepare_config()
        tr.release_suricata_guard(self.txn)
        self.commands.clear()
        self.active = 'active'
        self.enabled = 'enabled'
        original_run = self.execute
        def checked(args, *rest, **kwargs):
            if args == ['systemctl', 'stop', 'suricata.service']:
                self.assertTrue(self.hold.exists())
            return original_run(args, *rest, **kwargs)
        with patch.object(tr, 'run', side_effect=checked):
            self.assertEqual(tr.restore_suricata_guard(self.txn, self.b), {str(self.hold)})
        self.assertEqual(self.commands[:2], [
            ['systemctl', 'daemon-reload'], ['systemctl', 'stop', 'suricata.service']])
        with self.assertRaisesRegex(RuntimeError, 'ещё может'):
            tr.cleanup_suricata_guard(self.txn, self.b)
        self.assertTrue(self.hold.exists())
        self.enabled = 'disabled'
        tr.cleanup_suricata_guard(self.txn, self.b)
        self.assertFalse(self.hold.exists())
        tr.cleanup_suricata_guard(self.txn, self.b)

    def test_partial_install_preserves_yaml_and_hold(self):
        self.arm()
        self.yaml.parent.mkdir(parents=True)
        self.yaml.write_text('unverified partial-package default\n')
        with self.assertRaisesRegex(RuntimeError, 'прервана до сохранения'):
            tr.restore_suricata_guard(self.txn, self.b)
        self.assertEqual(self.yaml.read_text(), 'unverified partial-package default\n')
        self.assertTrue(self.hold.exists())
        self.assertEqual(self.active, 'inactive')

    def test_pre_dpkg_stop_not_found_allows_checked_cleanup(self):
        self.arm()
        self.failure = ['systemctl', 'stop', 'suricata.service']
        self.active = 'unknown'
        self.assertEqual(tr.restore_suricata_guard(self.txn, self.b), {str(self.hold)})
        tr.cleanup_suricata_guard(self.txn, self.b)
        self.assertFalse(self.hold.exists())

    def test_failed_stop_running_service_retains_guard(self):
        self.arm()
        self.failure = ['systemctl', 'stop', 'suricata.service']
        self.active = 'active'
        with self.assertRaisesRegex(RuntimeError, 'не остановлена'):
            tr.restore_suricata_guard(self.txn, self.b)
        self.assertTrue(self.hold.exists())

    def test_whole_rollback_refuses_partial_before_firewall_or_files(self):
        self.arm()
        self.yaml.parent.mkdir(parents=True)
        self.yaml.write_text('partial')
        self.commands.clear()
        with patch.object(tr, 'restore_quarantine_first', return_value=set()):
            with self.assertRaisesRegex(RuntimeError, 'прервана до сохранения'):
                tr.rollback(self.txn)
        self.assertTrue(self.hold.exists())
        self.assertFalse((self.txn / 'rolled-back').exists())
        self.assertFalse(any(args[0].startswith('iptables') for args in self.commands))

    def test_guard_is_in_transaction_and_lifecycle_file_scope(self):
        self.arm()
        self.assertIn(str(self.hold), tr.owned_paths('isolated-test'))
        self.assertIn('/etc/systemd/system/suricata.service.d/97-safe-initial-install.conf', lifecycle.EXACT)


class SetupIntegration(unittest.TestCase):
    def test_shell_exact_nfqueue_and_release_order(self):
        base = Path(__file__).parent
        shell = (base / 'suricata-setup.sh').read_text()
        body = shell.split("<<'OVR'\n", 1)[1].split('\nOVR\n', 1)[0] + '\n'
        self.assertEqual(body, tr.SURICATA_NFQUEUE_TEXT)
        self.assertLess(shell.index('suricata -T'), shell.index('suricata-release'))
        self.assertLess(shell.index('suricata-release'), shell.index('systemctl enable'))
        self.assertIn('suricata-release "$DS_TXN" >>"$LOG" 2>&1 || return 1', shell)
        overrides = (base / 'safe-overrides.sh').read_text()
        self.assertLess(overrides.index('suricata-arm'), overrides.index('apt_install suricata'))
        self.assertIn('. "$DS_SAFE_ROOT/suricata-setup.sh"', overrides)
        subprocess.run(['bash', '-n', str(base / 'suricata-setup.sh')], check=True)


if __name__ == '__main__':
    unittest.main()
