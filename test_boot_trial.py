import copy
import json
import tempfile
import unittest
from contextlib import nullcontext, ExitStack
from pathlib import Path
from unittest.mock import patch

import boot_trial as bt


class InitialFallbackTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=Path.home())))
        for name, path in {
            'CFG': self.root/'boot/grub/grub.cfg',
            'ENV': self.root/'boot/grub/grubenv',
            'FALLBACK': self.root/'state/fallback.json',
            'DEFAULTS': self.root/'etc/grub',
            'DEFAULTS_DIR': self.root/'etc/grub.d',
            'FALLBACK_DROPIN': self.root/'etc/grub.d/zzzz-ds-guard-fallback.cfg',
            'BOOT_DIR': self.root/'boot',
        }.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            self.stack.enter_context(patch.object(bt, name, path))
        bt.DEFAULTS_DIR.mkdir(exist_ok=True)
        self.original = CONFIG.replace('set default="${saved_entry}"', 'set default="0"').encode()
        bt.CFG.write_bytes(self.original)
        bt.ENV.write_bytes(b'fixture')
        bt.DEFAULTS.write_text('GRUB_DEFAULT=0\n')
        for prefix in ('vmlinuz-', 'initrd.img-'):
            (bt.BOOT_DIR/(prefix+OLD)).write_bytes(b'x'*(1024*1024+1))
        self.env = {'foreign_marker': 'preserve'}
        self.commands = []
        self.stack.enter_context(patch.object(bt, 'kernel', return_value=OLD))
        self.stack.enter_context(patch.object(bt, 'boot_id', return_value='origin'))
        self.stack.enter_context(patch.object(bt, 'fallback_lock', side_effect=nullcontext))
        self.stack.enter_context(patch.object(bt, 'environment_backend', return_value={'filesystem':'ext2','abstraction':''}))
        self.stack.enter_context(patch.object(bt, 'environment', side_effect=lambda: dict(self.env)))
        self.stack.enter_context(patch.object(bt, 'run', side_effect=self.command))

    def command(self, argv, **kwargs):
        self.commands.append(argv)
        if argv[0] == 'grub-mkconfig':
            data = CONFIG.encode() if bt.FALLBACK_DROPIN.exists() else self.original
            Path(argv[-1]).write_bytes(data)
        elif argv[0] == 'grub-editenv':
            if argv[2] == 'set':
                k, v = argv[3].split('=',1)
                self.env[k] = v
            elif argv[2] == 'unset':
                self.env.pop(argv[3],None)
        elif argv[0] != 'grub-script-check':
            raise AssertionError('Unexpected command: '+str(argv))
        return ''

    def test_initial_numeric_default_is_pinned_before_packages(self):
        result = bt.ensure_fallback()
        self.assertEqual(result['entry'],ENTRY_OLD)
        self.assertEqual(self.env,{'foreign_marker':'preserve','saved_entry':ENTRY_OLD})
        self.assertEqual(bt.CFG.read_bytes(),CONFIG.encode())
        self.assertEqual(bt.DEFAULTS.read_text(),'GRUB_DEFAULT=0\n')
        self.assertEqual(bt.fallback_record()['status'],'ready')
        self.assertFalse(any(a[0] in ('dpkg','apt-get','systemctl') for a in self.commands))

    def test_repeat_is_readonly_and_keeps_first_baseline(self):
        bt.ensure_fallback()
        original_record = bt.FALLBACK.read_bytes()
        self.commands.clear()
        self.assertEqual(bt.ensure_fallback()['status'],'already-pinned')
        self.assertEqual(bt.FALLBACK.read_bytes(),original_record)
        self.assertEqual(self.commands,[['grub-script-check',str(bt.CFG)]])

    def test_existing_saved_default_is_not_adopted(self):
        bt.CFG.write_bytes(CONFIG.encode())
        self.env['saved_entry'] = ENTRY_OLD
        self.assertEqual(bt.ensure_fallback()['status'],'already-pinned')
        self.assertFalse(bt.FALLBACK.exists())
        self.assertFalse(bt.FALLBACK_DROPIN.exists())

    def test_foreign_saved_entry_is_refused(self):
        self.env['saved_entry'] = ENTRY_NEW
        with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.CFG.read_bytes(),self.original)
        self.assertFalse(bt.FALLBACK.exists())

    def test_pending_boot_entries_are_refused(self):
        for key in ('next_entry','prev_saved_entry'):
            with self.subTest(key=key):
                self.env[key] = ENTRY_NEW
                with self.assertRaises(bt.Refusal): bt.ensure_fallback()
                self.env.pop(key)
        self.assertFalse(bt.FALLBACK.exists())

    def test_unknown_default_is_not_overwritten(self):
        bt.CFG.write_bytes(self.original.replace(b'set default="0"',b'set default="foreign"'))
        with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertFalse(bt.FALLBACK.exists())

    def test_absent_running_initramfs_is_refused_before_write(self):
        (bt.BOOT_DIR/('initrd.img-'+OLD)).unlink()
        with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertFalse(bt.FALLBACK.exists())

    def test_foreign_dropin_not_overwritten(self):
        bt.FALLBACK_DROPIN.write_text('foreign')
        with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.FALLBACK_DROPIN.read_text(),'foreign')

    def test_failed_generation_restores_original_state(self):
        with patch.object(bt,'generate_grub',side_effect=bt.Refusal('fixture failure')):
            with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.CFG.read_bytes(),self.original)
        self.assertEqual(self.env,{'foreign_marker':'preserve'})
        self.assertFalse(bt.FALLBACK_DROPIN.exists())
        self.assertEqual(bt.fallback_record()['status'],'restored')

    def test_failed_saved_entry_write_rolls_back(self):
        def fail(argv,**kw):
            if argv[0]=='grub-editenv' and argv[2]=='set':
                raise bt.Refusal('write failed')
            return self.command(argv,**kw)
        with patch.object(bt,'run',side_effect=fail):
            with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.CFG.read_bytes(),self.original)
        self.assertFalse(bt.FALLBACK_DROPIN.exists())
        self.assertNotIn('saved_entry',self.env)

    def test_interrupted_commit_recovers_before_retry(self):
        bt.ensure_fallback()
        d=bt.fallback_record();d['status']='committing';bt.save_fallback(d)
        bt.ensure_fallback()
        self.assertEqual(bt.fallback_record()['status'],'ready')
        self.assertEqual(bt.fallback_record()['original_environment'],{'foreign_marker':'preserve'})

    def test_concurrent_menu_edit_is_preserved(self):
        def changed():
            bt.CFG.write_bytes(b'foreign menu')
            return CONFIG.encode()
        with patch.object(bt,'generate_grub',side_effect=changed):
            with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.CFG.read_bytes(),b'foreign menu')

    def test_generated_menu_must_honor_saved_default(self):
        with patch.object(bt,'generate_grub',return_value=self.original):
            with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        self.assertEqual(bt.CFG.read_bytes(),self.original)

    def test_removal_restores_original_config_and_preserves_foreign_metadata(self):
        bt.ensure_fallback()
        self.env['added_later']='retain'
        bt.restore_fallback()
        self.assertEqual(bt.CFG.read_bytes(),self.original)
        self.assertEqual(self.env,{'foreign_marker':'preserve','added_later':'retain'})
        self.assertFalse(bt.FALLBACK_DROPIN.exists())
        self.assertEqual(bt.fallback_record()['status'],'restored')
        self.commands.clear()
        bt.restore_fallback()
        self.assertEqual(self.commands,[])

    def test_removal_refuses_foreign_default_changes(self):
        bt.ensure_fallback()
        bt.DEFAULTS.write_text('GRUB_DEFAULT=foreign\n')
        with self.assertRaises(bt.Refusal): bt.restore_fallback()
        self.assertTrue(bt.FALLBACK_DROPIN.exists())

    def test_removal_refuses_foreign_saved_entry(self):
        bt.ensure_fallback()
        self.env['saved_entry']=ENTRY_NEW
        with self.assertRaises(bt.Refusal): bt.restore_fallback()
        self.assertEqual(self.env['saved_entry'],ENTRY_NEW)

    def test_removal_requires_original_kernel(self):
        bt.ensure_fallback()
        with patch.object(bt,'kernel',return_value=NEW):
            with self.assertRaises(bt.Refusal): bt.restore_fallback()
        self.assertTrue(bt.FALLBACK_DROPIN.exists())

    def test_modified_owned_dropin_refuses_repeat_and_remove(self):
        bt.ensure_fallback();bt.FALLBACK_DROPIN.write_text('foreign edit')
        with self.assertRaises(bt.Refusal): bt.ensure_fallback()
        with self.assertRaises(bt.Refusal): bt.restore_fallback()
        self.assertEqual(bt.FALLBACK_DROPIN.read_text(),'foreign edit')


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

    def test_confirm_accepts_only_removal_of_empty_transient_keys(self):
        self.d['status'] = 'boot-healthy'
        self.env.update(next_entry='', prev_saved_entry='', boot_success='1', recordfail='0')
        original = self.fake_run

        def realistic_grub(argv, **kw):
            result = original(argv, **kw)
            if argv[0] == 'grub-set-default':
                self.env.pop('next_entry', None)
                self.env.pop('prev_saved_entry', None)
            return result

        bt.run.side_effect = realistic_grub
        bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirmed')
        self.assertEqual(self.env, {'saved_entry': ENTRY_NEW, 'boot_success': '1', 'recordfail': '0'})
        self.assertEqual(self.d['confirmation_environment_before']['next_entry'], '')
        self.assertNotIn('next_entry', self.d['confirmation_environment_after'])

    def test_confirm_refuses_nonempty_transient_before_write(self):
        for transient in ('next_entry', 'prev_saved_entry'):
            with self.subTest(transient=transient):
                self.d['status'] = 'boot-healthy'
                self.env = {'saved_entry': ENTRY_OLD, transient: 'foreign'}
                self.calls = []
                with self.assertRaises(bt.Refusal):
                    bt.confirm(confirmed=True)
                self.assertEqual(self.calls, [])

    def test_confirm_refuses_unrelated_metadata_change(self):
        self.d['status'] = 'boot-healthy'
        self.env['boot_success'] = '1'
        original = self.fake_run

        def changed_grub(argv, **kw):
            result = original(argv, **kw)
            if argv[0] == 'grub-set-default':
                self.env['boot_success'] = '0'
            return result

        bt.run.side_effect = changed_grub
        with self.assertRaisesRegex(bt.Refusal, 'не подтверждено'):
            bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirming')
        bt.cleanup.assert_not_called()

    def test_confirm_refuses_added_nonempty_next_after_command(self):
        self.d['status'] = 'boot-healthy'
        original = self.fake_run

        def changed_grub(argv, **kw):
            result = original(argv, **kw)
            if argv[0] == 'grub-set-default':
                self.env['next_entry'] = 'foreign'
            return result

        bt.run.side_effect = changed_grub
        with self.assertRaises(bt.Refusal):
            bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirming')
        bt.cleanup.assert_not_called()

    def test_confirm_resume_owned_target_without_second_grub_write(self):
        self.d['status'] = 'confirming'
        self.env['saved_entry'] = ENTRY_NEW
        bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirmed')
        bt.verify_owned.assert_called_once()
        bt.health_failures.assert_called_once()
        self.assertNotIn(('run', ['grub-set-default', ENTRY_NEW]), self.calls)
        bt.cleanup.assert_called_once_with(unittest.mock.ANY, retain_finalizer=False)

    def test_confirm_resume_old_default_finishes_owned_write(self):
        self.d['status'] = 'confirming'
        bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirmed')
        self.assertIn(('run', ['grub-set-default', ENTRY_NEW]), self.calls)

    def test_confirm_resume_recorded_empty_removal_accepted(self):
        self.d.update(status='confirming', confirmation_environment_before={
            'saved_entry': ENTRY_OLD, 'next_entry': '', 'boot_success': '1'})
        self.env = {'saved_entry': ENTRY_NEW, 'boot_success': '1'}
        bt.confirm(confirmed=True)
        self.assertEqual(self.d['status'], 'confirmed')

    def test_confirm_resume_recorded_metadata_drift_refuses(self):
        self.d.update(status='confirming', confirmation_environment_before={
            'saved_entry': ENTRY_OLD, 'next_entry': '', 'boot_success': '1'})
        self.env = {'saved_entry': ENTRY_NEW, 'boot_success': '0'}
        with self.assertRaisesRegex(bt.Refusal, 'Метаданные GRUB'):
            bt.confirm(confirmed=True)
        self.assertEqual(self.calls, [])

    def test_confirm_resume_foreign_default_refuses(self):
        self.d['status'] = 'confirming'
        self.env['saved_entry'] = 'foreign'
        with self.assertRaises(bt.Refusal):
            bt.confirm(confirmed=True)
        self.assertEqual(self.calls, [])

    def test_confirm_requires_unchanged_verified_boot(self):
        self.d.update(status='confirming', checked_boot_id='another')
        self.env['saved_entry'] = ENTRY_NEW
        with self.assertRaisesRegex(bt.Refusal, 'другая загрузка'):
            bt.confirm(confirmed=True)
        self.assertEqual(self.calls, [])

    def test_confirm_resume_owned_file_drift_refuses_before_write(self):
        self.d['status'] = 'confirming'
        bt.verify_owned.side_effect = bt.Refusal('owned file changed')
        with self.assertRaises(bt.Refusal):
            bt.confirm(confirmed=True)
        self.assertEqual(self.calls, [])

    def test_confirm_resume_current_ssh_failure_refuses_before_write(self):
        self.d['status'] = 'confirming'
        bt.health_failures.return_value = ['служба SSH не работает']
        with self.assertRaisesRegex(bt.Refusal, 'проверки SSH'):
            bt.confirm(confirmed=True)
        self.assertEqual(self.calls, [])

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
