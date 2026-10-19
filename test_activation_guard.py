"""Isolated filesystem/boot fixtures; no host service or reboot operations."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import activation_guard as guard
import lifecycle
import legacy_upgrade
import transaction

BOOT = '11111111-1111-1111-1111-111111111111'
NEXT_BOOT = '22222222-2222-2222-2222-222222222222'
TXN = guard.STATE / 'transactions/33333333-3333-3333-3333-333333333333'
EVIDENCE = {'local_layers': 3, 'nfqueue_listeners': [0, 1], 'new_kernel_errors': 0,
            'foreign_firewall_preserved': True, 'strict_https': True,
            'operator_application_check': False}


class ActivationBootFence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(guard, 'SYSTEM_ROOT', self.root))
        self.stack.enter_context(patch.object(guard, 'ROOT_UID', os.getuid()))
        self.reload = self.stack.enter_context(patch.object(guard, 'reload_units'))
        self.write('/proc/sys/kernel/random/boot_id', BOOT)
        self.write(TXN / 'before.json', json.dumps({'boot_id': BOOT}), 0o600)
        self.write(guard.HELPER, '# installed helper fixture\n')
        for p in guard.OLD_HOLDS:
            self.write(p, guard.OLD_BODY)

    def write(self, name, text, mode=0o644):
        p = guard.path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        p.chmod(mode)
        return p

    def commit(self):
        self.write(TXN / 'acceptance.json', json.dumps(EVIDENCE), 0o600)
        self.write(TXN / 'committed', guard.ACCEPTED, 0o600)

    def test_current_activation_boot_allowed_next_boot_denied_without_commit(self):
        guard.arm(TXN)
        self.assertTrue(guard.permits_start())
        for old in guard.OLD_HOLDS:
            guard.path(old).unlink()
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        self.assertFalse(guard.permits_start())
        self.assertTrue(all(guard.path(p).read_text() == guard.BODY for p in guard.DROPINS))

    def test_real_legacy_release_installs_fence_before_withdrawing_quarantine(self):
        self.write(TXN / 'before.json', json.dumps({'boot_id': BOOT, 'files': {str(p): {} for p in guard.OLD_HOLDS}}), 0o600)
        for p in guard.OLD_HOLDS:
            self.write(TXN / 'files' / str(p).lstrip('/'), guard.OLD_BODY)
        self.write('/sys/kernel/livepatch/xt_ndpi/enabled', '1')
        self.write('/sys/kernel/livepatch/xt_ndpi/transition', '0')
        info = {'has_faults': False, 'loaded_candidate': True, 'requires_stage': False}

        def reload(args, check=True):
            self.assertEqual(args, ['systemctl', 'daemon-reload'])
            self.assertTrue(guard.path(guard.MARKER).exists())
            self.assertTrue(all(guard.path(p).exists() for p in guard.DROPINS))
            self.assertFalse(any(guard.path(p).exists() for p in guard.OLD_HOLDS))
            return 0, ''

        with patch.object(legacy_upgrade, 'SYSTEM_ROOT', self.root), patch.object(legacy_upgrade, 'ROOT_UID', os.getuid()),\
             patch.object(legacy_upgrade, 'check_legacy', return_value=info), patch.object(legacy_upgrade, 'command', side_effect=reload):
            legacy_upgrade.release_hold(txn=TXN)
        self.assertTrue(guard.permits_start())
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        self.assertFalse(guard.permits_start())

    def test_unrelated_conditions_are_not_reset_or_overwritten(self):
        foreign = guard.DROPINS[0].with_name('95-admin-condition.conf')
        original = '[Service]\nExecCondition=/usr/local/bin/admin-health\n'
        self.write(foreign, original)
        guard.arm(TXN)
        self.assertEqual(guard.path(foreign).read_text(), original)
        self.assertNotIn('ExecCondition=\n', guard.BODY)
        self.assertTrue(all(guard.path(p).exists() for p in guard.OLD_HOLDS))

    def test_foreign_file_in_own_dropin_slot_refuses_before_marker(self):
        self.write(guard.DROPINS[1], '[Service]\nExecCondition=/bin/false\n')
        with self.assertRaisesRegex(RuntimeError, 'изменён вне'):
            guard.arm(TXN)
        self.assertFalse(guard.path(guard.MARKER).exists())
        self.reload.assert_not_called()

    def test_missing_helper_refuses_before_marker(self):
        guard.path(guard.HELPER).unlink()
        with self.assertRaisesRegex(RuntimeError, 'обычный файл'):
            guard.arm(TXN)
        self.assertFalse(guard.path(guard.MARKER).exists())

    def test_failed_second_dropin_leaves_original_holds_and_durable_marker(self):
        original = guard.atomic_write

        def write(p, text, mode):
            if p == guard.path(guard.DROPINS[1]):
                raise OSError('fixture interrupted second fence write')
            return original(p, text, mode)

        with patch.object(guard, 'atomic_write', side_effect=write):
            with self.assertRaisesRegex(OSError, 'second fence'):
                guard.arm(TXN)
        self.assertTrue(all(guard.path(p).read_text() == guard.OLD_BODY for p in guard.OLD_HOLDS))
        self.assertTrue(guard.path(guard.MARKER).exists())
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        self.assertFalse(guard.permits_start())

    def test_reload_failure_cannot_remove_original_holds(self):
        self.reload.side_effect = RuntimeError('fixture reload failure')
        with self.assertRaisesRegex(RuntimeError, 'reload'):
            guard.arm(TXN)
        self.assertTrue(all(guard.path(p).exists() for p in guard.OLD_HOLDS))

    def test_existing_incomplete_other_transaction_not_replaced(self):
        guard.arm(TXN)
        original = guard.path(guard.MARKER).read_bytes()
        other = guard.STATE / 'transactions/44444444-4444-4444-4444-444444444444'
        self.write(other / 'before.json', json.dumps({'boot_id': BOOT}), 0o600)
        with self.assertRaisesRegex(RuntimeError, 'Предыдущая активация'):
            guard.arm(other)
        self.assertEqual(guard.path(guard.MARKER).read_bytes(), original)

    def test_unaccepted_marker_cannot_be_cleared(self):
        guard.arm(TXN)
        with self.assertRaisesRegex(RuntimeError, 'приёмка не подтверждена'):
            guard.complete(TXN)
        self.assertTrue(guard.path(guard.MARKER).exists())

    def test_staged_commit_never_counts_as_accepted_activation(self):
        guard.arm(TXN)
        self.write(TXN / 'committed', 'Module staged; running module retained. Reboot required before activation.\n', 0o600)
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        with self.assertRaisesRegex(RuntimeError, 'изменён вне'):
            guard.permits_start()

    def test_commit_without_acceptance_does_not_allow_next_boot(self):
        guard.arm(TXN)
        self.write(TXN / 'committed', guard.ACCEPTED, 0o600)
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        with self.assertRaisesRegex(RuntimeError, 'обычный файл'):
            guard.permits_start()

    def test_crash_after_accepted_commit_before_marker_cleanup_is_safe_to_boot(self):
        guard.arm(TXN)
        self.commit()
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        self.assertTrue(guard.permits_start())

    def test_complete_flushes_acceptance_and_commit_before_removing_marker(self):
        guard.arm(TXN)
        self.commit()
        calls = []
        durable = guard.durable_file
        unlink = Path.unlink

        def flush(p):
            calls.append(p)
            durable(p)

        def remove(p, *args, **kwargs):
            if p == guard.path(guard.MARKER):
                self.assertEqual(calls, [guard.path(TXN / 'acceptance.json'), guard.path(TXN / 'committed')])
            return unlink(p, *args, **kwargs)

        with patch.object(guard, 'durable_file', side_effect=flush), patch.object(Path, 'unlink', new=remove):
            guard.complete(TXN)
        self.assertFalse(guard.path(guard.MARKER).exists())
        self.assertTrue(all(guard.path(p).exists() for p in guard.DROPINS))
        self.write('/proc/sys/kernel/random/boot_id', NEXT_BOOT)
        self.assertTrue(guard.permits_start())

    def test_sync_failure_keeps_marker(self):
        guard.arm(TXN)
        self.commit()
        with patch.object(guard, 'durable_file', side_effect=OSError('fixture sync failure')):
            with self.assertRaisesRegex(OSError, 'sync failure'):
                guard.complete(TXN)
        self.assertTrue(guard.path(guard.MARKER).exists())

    def test_marker_symlink_and_modified_boot_provenance_fail_closed(self):
        guard.arm(TXN)
        p = guard.path(guard.MARKER)
        data = json.loads(p.read_text())
        data['boot_id'] = NEXT_BOOT
        p.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, 'не совпала'):
            guard.permits_start()
        other = self.root / 'foreign'
        other.write_text(json.dumps(data))
        p.unlink()
        p.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError, 'обычный файл'):
            guard.permits_start()

    def test_missing_marker_beneath_replaced_state_directory_is_not_accepted(self):
        state = guard.path(guard.STATE)
        moved = state.with_name('saved-state')
        state.rename(moved)
        foreign = self.root / 'foreign-state'
        foreign.mkdir()
        state.symlink_to(foreign, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'Каталог'):
            guard.permits_start()

    def test_all_durable_fence_objects_are_in_both_rollback_scopes(self):
        names = {str(p) for p in (*guard.DROPINS, guard.MARKER)}
        self.assertTrue(names <= set(lifecycle.EXACT))
        self.assertIn(str(guard.HELPER.parent), lifecycle.TREES)
        with patch.object(Path, 'is_file', new=lambda p: str(p) in names), patch.object(Path, 'is_symlink', return_value=False), patch.object(transaction.glob, 'glob', return_value=[]):
            self.assertTrue(names <= set(transaction.owned_paths('fixture-kernel')))


if __name__ == '__main__':
    unittest.main()
