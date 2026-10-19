"""Legacy upgrades preserve the current installation without claiming its past."""
import copy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lifecycle


class LegacyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / 'lifecycle'
        self.state.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(lifecycle, 'STATE', self.state))
        self.baseline = {
            'files': {}, 'file_owners': {}, 'packages': {'suricata': '7.0', 'old-kernel': '1'},
            'ownership_schema': 1, 'owned_packages': {}, 'manual': ['suricata'],
            'units': {}, 'values': {'net.ipv4.tcp_fin_timeout': '45'}, 'iptables': '',
            'kernel': 'old-kernel', 'module_state': {'xt_ndpi': True},
            'conntrack_hashsize': None, 'time': 1,
        }

    def initial_state(self, legacy=True):
        original_exists = Path.exists
        original_rglob = Path.rglob

        def exists(path):
            if str(path) == '/etc/systemd/system/ds-guard.service':
                return legacy
            if str(path) == '/var/lib/ds-guard-safe/installed.json':
                return False
            return original_exists(path)

        def rglob(path, pattern):
            if str(path) == '/etc':
                return iter(())
            return original_rglob(path, pattern)

        self.stack.enter_context(patch.object(Path, 'exists', new=exists))
        self.stack.enter_context(patch.object(Path, 'rglob', new=rglob))
        snapshot = self.stack.enter_context(patch.object(
            lifecycle, 'snapshot', side_effect=lambda: copy.deepcopy(self.baseline)))
        return snapshot

    def write_records(self, legacy=True):
        record = copy.deepcopy(self.baseline)
        record['baseline_kind'] = 'legacy-upgrade' if legacy else 'fresh'
        for name in ('before.json', 'after.json'):
            (self.state / name).write_text(json.dumps(record))
        return record

    def bytes_of_state(self):
        return {str(p.relative_to(self.state)): p.read_bytes()
                for p in self.state.rglob('*') if p.is_file()}

    def test_legacy_without_explicit_flag_still_refused(self):
        snapshot = self.initial_state()
        with self.assertRaisesRegex(RuntimeError, 'прежняя установка'):
            lifecycle.begin()
        snapshot.assert_not_called()
        self.assertFalse((self.state / 'before.json').exists())
        self.assertFalse((self.state / 'pending.json').exists())

    def test_upgrade_baseline_is_explicit_and_old_packages_are_not_owned(self):
        self.initial_state()
        # Even a caller-supplied snapshot must not invent ownership of old packages.
        self.baseline['owned_packages'] = {'suricata': '7.0'}
        lifecycle.begin(legacy_upgrade=True)
        before = json.loads((self.state / 'before.json').read_text())
        self.assertEqual(before['baseline_kind'], 'legacy-upgrade')
        self.assertEqual(before['packages'], self.baseline['packages'])
        self.assertEqual(before['owned_packages'], {})
        self.assertEqual(before['values'], self.baseline['values'])
        pending = json.loads((self.state / 'pending.json').read_text())
        self.assertEqual(pending['packages_before'], before['packages'])
        self.assertEqual(lifecycle.package_ownership(before['packages']), {})

    def test_fresh_baseline_is_not_mislabelled_when_flag_is_present(self):
        self.initial_state(legacy=False)
        lifecycle.begin(legacy_upgrade=True)
        self.assertEqual(json.loads((self.state / 'before.json').read_text())['baseline_kind'], 'fresh')

    def test_old_library_content_is_copied_before_any_replacement(self):
        self.initial_state()
        old = self.root / 'old-library.py'
        old.write_bytes(b'old library, preserved exactly\n')
        item = {'sha256': hashlib.sha256(old.read_bytes()).hexdigest(), 'mode': old.stat().st_mode & 0o777}
        self.baseline['files'][str(old)] = item
        self.baseline['file_owners'][str(old)] = [old.stat().st_uid, old.stat().st_gid]
        lifecycle.begin(legacy_upgrade=True)
        saved = self.state / 'files' / str(old).lstrip('/')
        self.assertEqual(saved.read_bytes(), old.read_bytes())
        self.assertIn('/usr/local/lib/ds-guard-safe', lifecycle.TREES)
        old.write_bytes(b'new library\n')
        self.assertEqual(saved.read_bytes(), b'old library, preserved exactly\n')

    def test_legacy_remove_and_plan_refuse_before_commands_or_mutations(self):
        self.write_records()
        before = self.bytes_of_state()
        with patch.object(lifecycle, 'run') as run, patch.object(lifecycle, 'snapshot') as snapshot:
            for plan in (False, True):
                with self.assertRaisesRegex(RuntimeError, 'исходное состояние до первой установки неизвестно'):
                    lifecycle.remove(plan)
            with self.assertRaises(RuntimeError):
                lifecycle.removal_plan()
            run.assert_not_called()
            snapshot.assert_not_called()
        self.assertEqual(before, self.bytes_of_state())

    def test_legacy_disable_refuses_before_commands_or_mutations(self):
        self.write_records()
        before = self.bytes_of_state()
        with patch.object(lifecycle, 'run') as run, patch.object(lifecycle, 'snapshot') as snapshot:
            with self.assertRaisesRegex(RuntimeError, 'отключение прежней установки пока не поддерживается'):
                lifecycle.disable()
            run.assert_not_called()
            snapshot.assert_not_called()
        self.assertEqual(before, self.bytes_of_state())

    def test_repeat_keeps_immutable_upgrade_baseline_without_claiming_admin_package(self):
        before = self.write_records()
        initial_bytes = (self.state / 'before.json').read_bytes()
        current = copy.deepcopy(before)
        current['packages']['admin-package'] = '9'
        current['module_state']['xt_ndpi'] = False
        with patch.object(lifecycle, 'snapshot', return_value=current):
            lifecycle.begin()
        self.assertEqual((self.state / 'before.json').read_bytes(), initial_bytes)
        self.assertEqual(lifecycle.package_ownership(current['packages']), {})

    def test_both_existing_memory_hold_dropins_are_recorded(self):
        for unit in ('ds-guard', 'ds-guard-apply'):
            self.assertIn('/etc/systemd/system/' + unit + '.service.d/90-codex-ndpi-memory-hold.conf', lifecycle.EXACT)


if __name__ == '__main__':
    unittest.main()
