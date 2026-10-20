import copy
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import boot_trial as bt


UUID = '11111111-2222-4333-8444-555555555555'
OLD = '7.0.14-x64v3-xanmod1'
NEW = '7.2.9-x64v3-dsg1-xanmod1'
SUB = 'gnulinux-advanced-'+UUID
ENTRY_OLD = SUB+'>gnulinux-'+OLD+'-advanced-'+UUID
ENTRY_NEW = SUB+'>gnulinux-'+NEW+'-advanced-'+UUID
CONFIG = '\n'.join([
    'set default="${saved_entry}"', 'set default="${next_entry}"',
    'set next_entry=', 'save_env next_entry', 'set boot_once=true',
    "submenu 'Advanced options for Ubuntu' $menuentry_id_option '"+SUB+"' {",
    "  menuentry 'Ubuntu, with Linux "+OLD+"' $menuentry_id_option 'gnulinux-"+OLD+"-advanced-"+UUID+"' {",
    '  }',
    "  menuentry 'Ubuntu, with Linux "+NEW+"' $menuentry_id_option 'gnulinux-"+NEW+"-advanced-"+UUID+"' {",
    '  }', '}'])


def state(status='armed'):
    return {'schema': 1, 'status': status, 'target': NEW, 'fallback': OLD,
            'origin_boot_id': 'origin', 'saved_entry': ENTRY_OLD,
            'target_entry': ENTRY_NEW, 'grub_sha256': 'cfg',
            'grub_environment': {'saved_entry': ENTRY_OLD},
            'owned_files': {}, 'owned_links': {}, 'resume_args': ['--mode', 'full'],
            'baseline': {'fixture': True}, 'recovery_attempts': 0}


class GrubTests(unittest.TestCase):
    def setUp(self):
        probe = patch.object(bt, 'environment_backend',
                             return_value={'filesystem': 'ext2', 'abstraction': ''})
        probe.start()
        self.addCleanup(probe.stop)

    def test_exact_stable_ids(self):
        entries = bt.grub_entries(CONFIG)
        self.assertEqual(entries['gnulinux-'+NEW+'-advanced-'+UUID],
                         {'kernel': NEW, 'submenu': SUB})

    def test_duplicate_entry_refused(self):
        line = "menuentry 'duplicate' $menuentry_id_option 'gnulinux-"+NEW+"-advanced-"+UUID+"' {"
        with self.assertRaises(bt.Refusal):
            bt.grub_entries(CONFIG+'\n'+line)

    def test_duplicate_submenu_refused(self):
        with self.assertRaises(bt.Refusal):
            bt.grub_entries(CONFIG+"\nsubmenu 'duplicate' $menuentry_id_option '"+SUB+"' {")

    def test_entry_without_submenu_refused(self):
        with self.assertRaises(bt.Refusal):
            bt.grub_entries("\n".join(x for x in CONFIG.splitlines() if not x.startswith('submenu ')))

    def test_multiple_ids_refused(self):
        with self.assertRaises(bt.Refusal):
            bt.grub_entries(CONFIG+"\nmenuentry 'bad' 'gnulinux-a' 'gnulinux-b' {")

    def test_plan_preserves_default(self):
        with patch.object(bt, 'checked_file', side_effect=lambda p: CONFIG.encode() if p == bt.CFG else b'x'*(1024*1024+1)), \
             patch.object(bt, 'run') as run, patch.object(bt, 'kernel', return_value=OLD), \
             patch.object(bt, 'environment', return_value={'saved_entry': ENTRY_OLD}):
            plan = bt.boot_plan(NEW)
        self.assertEqual(plan['target_entry'], ENTRY_NEW)
        self.assertEqual(plan['saved_entry'], ENTRY_OLD)
        run.assert_called_once_with(['grub-script-check', str(bt.CFG)])

    def test_existing_next_entry_refused(self):
        with patch.object(bt, 'checked_file', return_value=CONFIG.encode()), \
             patch.object(bt, 'run'), patch.object(bt, 'environment', return_value={'saved_entry': ENTRY_OLD, 'next_entry': 'foreign'}):
            with self.assertRaises(bt.Refusal):
                bt.boot_plan(NEW)

    def test_pending_saved_default_restore_refused(self):
        with patch.object(bt, 'checked_file', return_value=CONFIG.encode()), \
             patch.object(bt, 'run'), patch.object(bt, 'environment', return_value={'saved_entry': ENTRY_OLD, 'prev_saved_entry': 'foreign'}):
            with self.assertRaises(bt.Refusal):
                bt.boot_plan(NEW)

    def test_fallback_must_be_running_kernel(self):
        with patch.object(bt, 'checked_file', return_value=CONFIG.encode()), patch.object(bt, 'run'), \
             patch.object(bt, 'environment', return_value={'saved_entry': ENTRY_OLD}), \
             patch.object(bt, 'kernel', return_value='foreign'):
            with self.assertRaises(bt.Refusal):
                bt.boot_plan(NEW)

    def test_non_saved_grub_refused(self):
        with patch.object(bt, 'checked_file', return_value=CONFIG.replace('set default="${saved_entry}"', '').encode()), patch.object(bt, 'run'):
            with self.assertRaises(bt.Refusal):
                bt.boot_plan(NEW)

    def test_no_grub_eval(self):
        with patch.object(bt, 'run') as run:
            bt.grub_entries(CONFIG+"\n# $(touch /should-not-execute)")
        run.assert_not_called()

    def test_kernel_id_in_wrong_submenu_refused(self):
        foreign = 'gnulinux-advanced-11111111-1111-1111-1111-111111111111'
        with self.assertRaises(bt.Refusal):
            bt.grub_entries(CONFIG.replace("'"+SUB+"'", "'"+foreign+"'"))

    def test_kernel_outside_submenu_refused(self):
        line = "menuentry 'outside' $menuentry_id_option 'gnulinux-extra-advanced-"+UUID+"' {\n}"
        with self.assertRaises(bt.Refusal):
            bt.grub_entries(CONFIG+'\n'+line)


class GrubEnvironmentBackendTests(unittest.TestCase):
    def test_plain_ext_backend_accepted(self):
        with patch.object(bt, 'run', side_effect=['ext2', '']) as run:
            self.assertEqual(bt.environment_backend(),
                             {'filesystem': 'ext2', 'abstraction': ''})
        self.assertEqual(run.call_args_list,
                         [unittest.mock.call(['grub-probe', '--target=fs', str(bt.ENV)]),
                          unittest.mock.call(['grub-probe', '--target=abstraction', str(bt.ENV)])])

    def test_btrfs_refused(self):
        with patch.object(bt, 'run', side_effect=['btrfs', '']):
            with self.assertRaisesRegex(bt.Refusal, 'консоль хостера'):
                bt.environment_backend()

    def test_unverified_fat_refused(self):
        with patch.object(bt, 'run', side_effect=['fat', '']):
            with self.assertRaises(bt.Refusal):
                bt.environment_backend()

    def test_lvm_raid_and_cryptodisk_refused(self):
        for abstraction in ['lvm', 'diskfilter', 'cryptodisk', 'lvm diskfilter']:
            with self.subTest(abstraction=abstraction):
                with patch.object(bt, 'run', side_effect=['ext2', abstraction]):
                    with self.assertRaises(bt.Refusal):
                        bt.environment_backend()

    def test_missing_probe_safe_refusal(self):
        with patch.object(bt, 'run', side_effect=FileNotFoundError('grub-probe')):
            with self.assertRaisesRegex(bt.Refusal, 'Не удалось подтвердить'):
                bt.environment_backend()

    def test_failed_probe_safe_refusal(self):
        with patch.object(bt, 'run', side_effect=bt.Refusal('not mounted')):
            with self.assertRaisesRegex(bt.Refusal, 'Не удалось подтвердить'):
                bt.environment_backend()

    def test_prepare_backend_failure_precedes_all_mutations(self):
        with patch.object(bt, 'locked', return_value=nullcontext()), \
             patch.object(bt, 'read_state', return_value=None), \
             patch.object(bt, 'checked_file', return_value=CONFIG.encode()), \
             patch.object(bt, 'run'), \
             patch.object(bt, 'environment_backend', side_effect=bt.Refusal('unsupported backend')), \
             patch.object(bt, 'save') as save, patch.object(bt, 'atomic') as atomic:
            with self.assertRaises(bt.Refusal):
                bt.prepare(NEW, ['--mode', 'full'])
        save.assert_not_called()
        atomic.assert_not_called()


class StateTests(unittest.TestCase):
    def setUp(self):
        self.d = state()
        self.calls = []
        self.boot = 'new'
        self.running = NEW
        self.env = {'saved_entry': ENTRY_OLD}
        self.patches = [
            patch.object(bt, 'locked', side_effect=lambda: nullcontext()),
            patch.object(bt, 'read_state', side_effect=lambda: copy.deepcopy(self.d)),
            patch.object(bt, 'save', side_effect=self.save),
            patch.object(bt, 'boot_id', side_effect=lambda: self.boot),
            patch.object(bt, 'kernel', side_effect=lambda: self.running),
            patch.object(bt, 'environment', side_effect=lambda: dict(self.env)),
            patch.object(bt, 'verify_owned'),
            patch.object(bt, 'cleanup'),
            patch.object(bt, 'health_failures', return_value=[]),
            patch.object(bt, 'run', side_effect=self.fake_run),
        ]
        self.mocks = [p.start() for p in self.patches]
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])

    def save(self, value):
        self.d = copy.deepcopy(value)
        self.calls.append(('save', self.d['status'], self.d.get('recovery_attempts')))
        return value

    def fake_run(self, argv, **kw):
        self.calls.append(('run', list(argv)))
        if argv[0] == 'grub-reboot':
            self.env['next_entry'] = argv[1]
        if argv[:1] == ['grub-set-default']:
            self.env['saved_entry'] = argv[1]
        if argv[:1] == ['grub-editenv'] and 'unset' in argv:
            self.env.pop('next_entry', None)
        return ''

    def test_no_state(self):
        self.d = None
        self.assertEqual(bt.inspect(), {'status': 'none'})

    def test_same_boot_not_resume(self):
        self.boot = 'origin'
        self.assertFalse(bt.resume_ready())
        self.assertFalse(bt.inspect()['can_resume'])
        self.assertEqual(self.calls, [])

    def test_target_guard_stops_timer(self):
        self.assertTrue(bt.resume_ready())
        self.assertEqual(self.d['status'], 'boot-healthy')
        self.assertIn(('run', ['systemctl', 'stop', bt.TIMER]), self.calls)
        self.assertEqual(bt.inspect()['phase'], 'boot_verified')

    def test_guard_foreign_saved_default_refuses(self):
        self.env['saved_entry'] = 'admin'
        self.assertEqual(bt.post_boot_guard(), 78)
        self.assertEqual(self.d['status'], 'drift-refused')
        self.assertFalse(any(c == ('run', ['systemctl', 'reboot']) for c in self.calls))

    def test_unconsumed_next_entry_refuses(self):
        self.env['next_entry'] = ENTRY_NEW
        self.assertEqual(bt.post_boot_guard(), 78)
        self.assertEqual(self.d['status'], 'drift-refused')

    def test_wrong_kernel_refuses(self):
        self.running = 'foreign'
        self.assertEqual(bt.post_boot_guard(), 78)

    def test_fallback_observed_cleans_without_reboot(self):
        self.running = OLD
        self.assertEqual(bt.post_boot_guard(), 0)
        self.assertEqual(self.d['status'], 'fallback-observed')
        bt.cleanup.assert_not_called()
        self.assertNotIn(('run', ['systemctl', 'reboot']), self.calls)

    def test_fallback_after_recovery_cleans(self):
        self.d.update(status='recovery-requested', recovery_attempts=1)
        self.running = OLD
        self.assertEqual(bt.post_boot_guard(), 0)
        self.assertEqual(self.d['status'], 'fallback-observed')
        bt.cleanup.assert_not_called()
        self.assertIn(('run', ['systemctl', 'stop', bt.TIMER]), self.calls)

    def test_recovery_attempt_durable_before_reboot(self):
        bt.health_failures.return_value = ['SSH отсутствует']
        self.assertEqual(bt.recover(), 20)
        self.assertLess(self.calls.index(('save', 'recovery-requested', 1)),
                        self.calls.index(('run', ['systemctl', 'reboot'])))
        self.assertEqual(self.d['recovery_attempts'], 1)

    def test_failed_recovery_reboot_does_not_loop(self):
        bt.health_failures.return_value = ['SSH отсутствует']
        original = self.fake_run
        def fail(argv, **kw):
            if argv == ['systemctl', 'reboot']:
                self.calls.append(('run', list(argv)))
                raise bt.Refusal('reboot failed')
            return original(argv, **kw)
        bt.run.side_effect = fail
        self.assertEqual(bt.recover(), 1)
        self.assertEqual(self.d['status'], 'reboot-failed')
        self.assertEqual(bt.recover(), 0)
        self.assertEqual(self.calls.count(('run', ['systemctl', 'reboot'])), 1)
        self.assertEqual(bt.post_boot_guard(), 1)

    def test_recovery_refuses_admin_next_boot(self):
        self.env['next_entry'] = 'admin'
        bt.health_failures.return_value = ['bad']
        self.assertEqual(bt.recover(), 78)
        self.assertNotIn(('run', ['systemctl', 'reboot']), self.calls)

    def test_recovery_same_boot_no_action(self):
        self.boot = 'origin'
        self.assertEqual(bt.recover(), 0)
        self.assertEqual(self.calls, [])

    def test_recovery_old_kernel_no_action(self):
        self.running = OLD
        self.assertEqual(bt.recover(), 0)
        self.assertEqual(self.calls, [])

    def test_recovery_health_now_good_no_reboot(self):
        self.assertEqual(bt.recover(), 0)
        self.assertEqual(self.d['status'], 'boot-healthy')
        self.assertNotIn(('run', ['systemctl', 'reboot']), self.calls)

    def test_completed_does_not_promote(self):
        self.d['status'] = 'boot-healthy'
        bt.complete(confirmed=True)
        self.assertEqual(self.d['status'], 'completed')
        self.assertEqual(self.env['saved_entry'], ENTRY_OLD)
        self.assertFalse(any(x[0] == 'run' and x[1][0] == 'grub-set-default' for x in self.calls))
        bt.cleanup.assert_called_once_with(unittest.mock.ANY)

    def test_confirm_requires_explicit_choice(self):
        self.d['status'] = 'boot-healthy'
        with self.assertRaises(bt.Refusal):
            bt.confirm()
        self.assertEqual(self.calls, [])

    def test_confirm_and_undo_only_own_default(self):
        self.d['status'] = 'boot-healthy'
        bt.confirm(confirmed=True)
        self.assertEqual(self.env['saved_entry'], ENTRY_NEW)
        self.assertEqual(self.d['status'], 'confirmed')
        bt.undo_promotion()
        self.assertEqual(self.env['saved_entry'], ENTRY_OLD)
        self.assertEqual(self.d['status'], 'default-restored')

    def test_undo_foreign_default_refuses(self):
        self.d['status'] = 'confirmed'
        self.env['saved_entry'] = 'admin'
        with self.assertRaises(bt.Refusal):
            bt.cancel()
        self.assertEqual(self.calls, [])

    def test_undo_recreates_protection_before_default_change(self):
        self.d.update(status='confirmed', finalizer_present=True)
        self.env['saved_entry'] = ENTRY_NEW
        with patch.object(bt, 'restore_finalizer_guard', side_effect=lambda d: self.calls.append(('protect-finalizer',))):
            bt.cancel()
        self.assertLess(self.calls.index(('save', 'restoring-default', 0)),
                        self.calls.index(('protect-finalizer',)))
        self.assertLess(self.calls.index(('protect-finalizer',)),
                        self.calls.index(('run', ['grub-set-default', ENTRY_OLD])))

    def test_cancel_removes_only_own_next_entry(self):
        self.env['next_entry'] = ENTRY_NEW
        bt.cancel()
        self.assertNotIn('next_entry', self.env)
        self.assertEqual(self.env['saved_entry'], ENTRY_OLD)
        self.assertEqual(self.d['status'], 'cancelled')

    def test_arm_requires_explicit_choice(self):
        with self.assertRaises(bt.Refusal):
            bt.arm()
        self.assertEqual(self.calls, [])

    def test_arm_durable_before_selection(self):
        self.d['status'] = 'prepared'
        self.boot = 'origin'
        self.running = OLD
        with patch.object(bt, 'boot_plan', return_value=copy.deepcopy(self.d)):
            bt.arm(confirmation_already_given=True)
        self.assertEqual(self.d['status'], 'armed')
        self.assertLess(self.calls.index(('save', 'arming', 0)),
                        self.calls.index(('run', ['grub-reboot', ENTRY_NEW])))
        self.assertEqual(self.env['saved_entry'], ENTRY_OLD)

    def test_arm_other_boot_refuses(self):
        self.d['status'] = 'prepared'
        with self.assertRaises(bt.Refusal):
            bt.arm(confirmation_already_given=True)
        self.assertEqual(self.calls, [])

    def test_arm_config_drift_refuses(self):
        self.d['status'] = 'prepared'
        self.boot = 'origin'
        self.running = OLD
        plan = dict(self.d, grub_sha256='different')
        with patch.object(bt, 'boot_plan', return_value=plan):
            with self.assertRaises(bt.Refusal):
                bt.arm(confirmation_already_given=True)
        self.assertEqual(self.calls, [])

    def test_prepare_conflicts_existing_pending(self):
        with self.assertRaises(bt.Refusal):
            bt.prepare(NEW, ['--mode', 'full'])
        self.assertEqual(self.calls, [])

    def test_reboot_command_failed_cancels_one_shot(self):
        self.boot = 'origin'
        self.env['next_entry'] = ENTRY_NEW
        bt.record_reboot_failure('failed')
        self.assertEqual(self.d['status'], 'prepared')
        self.assertNotIn('next_entry', self.env)
        self.assertEqual(self.env['saved_entry'], ENTRY_OLD)

    def test_old_finalize_is_conditionally_blocked(self):
        files = bt.unit_files()
        body = files[str(bt.FINALIZE_DROPIN)].decode()
        self.assertIn('ConditionPathExists=!'+str(bt.MARKER), body)
        self.assertNotIn('ExecStart=', body)
        self.assertIn('OnBootSec=180', files[str(bt.UNIT_DIR/bt.TIMER)].decode())
        self.assertIn('OnUnitInactiveSec=20', files[str(bt.UNIT_DIR/bt.TIMER)].decode())
        self.assertNotIn('setup', '\n'.join(x.decode() for x in files.values()))


class CleanupTests(unittest.TestCase):
    def fixture(self, root):
        paths = [root/'marker', root/'dropin', root/'helper']
        for p in paths:
            p.write_bytes(b'owned')
            p.chmod(0o600)
        d = state('completed')
        d.update(finalizer_present=True, owned_files={str(p): bt.digest(b'owned') for p in paths})
        return d, paths

    def test_cancel_cleanup_retains_finalizer_protection(self):
        with tempfile.TemporaryDirectory() as temp:
            d, (marker, dropin, helper) = self.fixture(Path(temp))
            with patch.object(bt, 'MARKER', marker), patch.object(bt, 'FINALIZE_DROPIN', dropin), patch.object(bt, 'run'):
                bt.cleanup(d)
            self.assertTrue(marker.is_file())
            self.assertTrue(dropin.is_file())
            self.assertFalse(helper.exists())
            self.assertTrue(d['retained_finalizer_guard'])

    def test_confirm_cleanup_removes_owned_protection(self):
        with tempfile.TemporaryDirectory() as temp:
            d, paths = self.fixture(Path(temp))
            with patch.object(bt, 'MARKER', paths[0]), patch.object(bt, 'FINALIZE_DROPIN', paths[1]), patch.object(bt, 'run'):
                bt.cleanup(d, retain_finalizer=False)
            self.assertFalse(any(p.exists() for p in paths))
            self.assertFalse(d['retained_finalizer_guard'])

    def test_admin_modified_owned_file_preserved_no_partial_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            d, paths = self.fixture(Path(temp))
            paths[-1].write_bytes(b'admin changes')
            with patch.object(bt, 'MARKER', paths[0]), patch.object(bt, 'FINALIZE_DROPIN', paths[1]), patch.object(bt, 'run') as run:
                with self.assertRaises(bt.Refusal):
                    bt.cleanup(d, retain_finalizer=False)
            self.assertTrue(all(p.exists() for p in paths))
            run.assert_not_called()

    def test_cleanup_after_remove_refuses_running_target(self):
        d = state('completed')
        with patch.object(bt, 'locked', return_value=nullcontext()), \
             patch.object(bt, 'read_state', return_value=d), \
             patch.object(bt, 'kernel', return_value=NEW), patch.object(bt, 'cleanup') as cleanup:
            with self.assertRaises(bt.Refusal):
                bt.cleanup_after_remove()
        cleanup.assert_not_called()

    def test_recreate_guard_uses_exact_recorded_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            marker, dropin = Path(temp)/'marker', Path(temp)/'dropin'
            d = state('restoring-default')
            d['finalizer_present'] = True
            with patch.object(bt, 'MARKER', marker), patch.object(bt, 'FINALIZE_DROPIN', dropin):
                bodies = {str(marker): b'ds-guard-wizard one-shot trial\n',
                          str(dropin): bt.unit_files()[str(dropin)]}
                d['owned_files'] = {p: bt.digest(v) for p, v in bodies.items()}
                with patch.object(bt, 'atomic', side_effect=lambda p, data, mode=0o600: p.write_bytes(data)), patch.object(bt, 'run'):
                    bt.restore_finalizer_guard(d)
                self.assertTrue(all(Path(p).read_bytes() == body for p, body in bodies.items()))
                self.assertTrue(d['retained_finalizer_guard'])


if __name__ == '__main__':
    unittest.main()
