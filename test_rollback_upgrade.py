"""Local mock-only regression tests; never run a host rollback."""
import copy
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import lifecycle as lc
import rollback_upgrade as ru


def text_of(model):
    lines = ['*filter']
    for chain in model:
        lines.append(':' + chain + (' ACCEPT' if chain in ('INPUT', 'OUTPUT', 'FORWARD') else ' -') + ' [0:0]')
    for chain, rules in model.items():
        lines += [shlex.join(['-A', chain, *p]) for p in rules]
    return '\n'.join(lines + ['COMMIT'])


class UpgradeRollback(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / 'lifecycle'
        self.state.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(lc, 'STATE', self.state))
        real_is_symlink = Path.is_symlink
        self.stack.enter_context(patch.object(
            Path, 'is_symlink', new=lambda p: False if str(p).startswith('/root/codex-dsguard-20261019') else real_is_symlink(p)))
        old = {'INPUT': [['-p', 'tcp', '--dport', '22', '-j', 'ACCEPT']],
               'OUTPUT': [['-o', 'eth0', '-j', 'DS_DOMAINS']],
               'FORWARD': [], 'DS_DOMAINS': [['-j', 'DS_DOM_A']],
               'DS_DOM_A': [['-m', 'string', '--string', 'old', '-j', 'DROP']]}
        units = {u: {'active': 'inactive', 'enabled': 'disabled'} for u in ru.GUARDS}
        units['ds-guard-apply.service']['enabled'] = 'static'
        units['suricata.service'] = {'active': 'active', 'enabled': 'enabled'}
        self.b = {'baseline_kind': 'legacy-upgrade', 'ownership_schema': 1, 'owned_packages': {},
                  'packages': {'suricata': '7', 'old-kernel': '1'}, 'manual': ['suricata'],
                  'files': {}, 'file_owners': {}, 'existing_etc_paths': [], 'units': units,
                  'values': {'net.netfilter.nf_conntrack_acct': '0', 'net.ipv4.tcp_fin_timeout': '45'},
                  'iptables': text_of(old), 'kernel': 'old-kernel',
                  'module_state': {'xt_ndpi': True}, 'loaded_module_note_hex': 'aabb',
                  'conntrack_hashsize': None}
        for name, text, mode in [(ru.MARKER, ru.MARKER_TEXT, 0o600),
                                  *[(h, ru.HOLD_TEXT, 0o644) for h in ru.HOLDS],
                                  ('/etc/ds-guard/example', 'original', 0o640),
                                  ('/usr/local/lib/ds-guard-safe/old.py', 'old helper', 0o644)]:
            p = ru.backup(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
            p.chmod(mode)
            self.b['files'][name] = lc.stamp(p)
            self.b['file_owners'][name] = [0, 12345 if name.endswith('example') else 0]
        self.a = copy.deepcopy(self.b)
        self.a['owned_packages'] = {'new-package': '1'}
        self.a['packages']['new-package'] = '1'
        for name in ru.HOLDS:
            self.a['files'][name] = None
            self.a['file_owners'].pop(name)
        for name in ('/etc/ds-guard/example', '/usr/local/lib/ds-guard-safe/old.py'):
            self.a['files'][name] = {'sha256': 'replacement', 'mode': 0o644}
            self.a['file_owners'][name] = [0, 0]
        new = copy.deepcopy(old)
        new['OUTPUT'].append(['-o', 'eth0', '-m', 'ndpi', '--proto', 'bittorrent', '-j', 'DROP'])
        new['DS_DOM_A'][0][-3] = 'new'
        self.a['iptables'] = text_of(new)
        self.a['values']['net.netfilter.nf_conntrack_acct'] = '1'
        self.a['units']['ds-guard.service'] = {'active': 'active', 'enabled': 'enabled'}
        self.a['units']['ds-guard.timer'] = {'active': 'active', 'enabled': 'enabled'}
        self.now = copy.deepcopy(self.a)
        self.model = ru.firewall(self.now['iptables'])
        self.model['OUTPUT'].append(['-p', 'tcp', '--dport', '444', '-j', 'ACCEPT'])
        self.now['packages']['admin-package'] = '9'
        self.commands, self.restores = [], []
        self.lock_depth = 0
        self.lock_events = []
        self.interrupt_after_iptables = False
        self.simulation = 'Purg new-package [1]'
        self.stack.enter_context(patch.object(lc, 'read_records', side_effect=lambda: (copy.deepcopy(self.b), copy.deepcopy(self.a))))
        self.stack.enter_context(patch.object(lc, 'snapshot', side_effect=self.snapshot))
        self.stack.enter_context(patch.object(lc, 'apply_lock', side_effect=self.apply_lock))
        self.stack.enter_context(patch.object(lc, 'packages', side_effect=lambda: dict(self.now['packages'])))
        self.stack.enter_context(patch.object(lc, 'units', side_effect=lambda: copy.deepcopy(self.now['units'])))
        self.stack.enter_context(patch.object(lc, 'run', side_effect=self.command))
        self.stack.enter_context(patch.object(ru, 'restore_file', side_effect=self.restore))
        self.stack.enter_context(patch.object(ru, 'verify_files', side_effect=self.verify))
        self.reboot = self.stack.enter_context(patch.object(ru, 'runtime_reboot_needed', return_value=False))

    def snapshot(self):
        self.lock_events.append(('snapshot', self.lock_depth))
        d = copy.deepcopy(self.now)
        d['iptables'] = text_of(self.model)
        return d

    @contextmanager
    def apply_lock(self):
        self.lock_depth += 1
        try:
            yield
        finally:
            self.lock_depth -= 1

    def restore(self, name, item, baseline):
        self.restores.append(name)
        self.now['files'][name] = copy.deepcopy(item)
        if item is None:
            self.now['file_owners'].pop(name, None)
        else:
            self.now['file_owners'][name] = baseline['file_owners'][name]
        if name == ru.rotation.GENERATION:
            self.now['generation_text'] = ru.backup(name).read_text() if item else None

    def verify(self, b, names):
        for n in names:
            if self.now['files'].get(n) != b['files'].get(n) or b['files'].get(n) is not None and self.now['file_owners'].get(n) != b['file_owners'].get(n):
                raise RuntimeError('Файл не восстановлен: ' + n)

    def command(self, args, check=True, timeout=60):
        self.commands.append(args)
        self.lock_events.append((tuple(args), self.lock_depth))
        if args == ['iptables-save']:
            return text_of(self.model)
        if args[:3] == ['iptables', '-w', '5']:
            op, c, *tail = args[3:]
            if op == '-D':
                self.assertEqual(len(tail), 1, 'Removal must use a checked live rule number')
                self.model[c].pop(int(tail[0]) - 1)
            elif op == '-F':
                self.model[c].clear()
            elif op == '-N':
                self.model[c] = []
            elif op == '-X':
                self.model.pop(c)
            elif op == '-A':
                self.model[c].append(tail)
            elif op == '-I':
                self.model[c].insert(int(tail[0]) - 1, tail[1:])
            else:
                raise AssertionError(args)
            if self.interrupt_after_iptables:
                self.interrupt_after_iptables = False
                raise KeyboardInterrupt()
            return ''
        if args == ['dpkg', '--audit']:
            return ''
        if args[0] == 'dpkg-query':
            return 'installed' if args[-1] in self.now['packages'] else 'not-installed'
        if args[:2] == ['apt-get', '-s']:
            return self.simulation
        if args[:2] == ['apt-get', '-y']:
            for p in args[args.index('purge') + 1:]:
                self.now['packages'].pop(p)
            return ''
        if args[0] == 'grub-editenv':
            return ''
        if args[0] == 'sysctl':
            if args[1] == '-w':
                k, v = args[2].split('=', 1)
                self.now['values'][k] = v
                return args[2]
            return self.now['values'].get(args[2], '')
        if args[0] == 'systemctl':
            if args[1] == 'daemon-reload':
                return ''
            if args[1] == 'is-active':
                return self.now['units'][args[2]]['active']
            for u in args[2:]:
                if args[1] in ('stop', 'restart'):
                    self.now['units'][u]['active'] = 'inactive' if args[1] == 'stop' else 'active'
                elif args[1] in ('enable', 'disable'):
                    self.now['units'][u]['enabled'] = 'enabled' if args[1] == 'enable' else 'disabled'
                else:
                    raise AssertionError(args)
            return ''
        raise AssertionError(args)

    def test_scoped_rollback_retains_old_and_admin_packages_foreign_rules_and_owners(self):
        foreign = ru.foreign_rules(text_of(self.model))
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertEqual(self.now['packages'], {**self.b['packages'], 'admin-package': '9'})
        self.assertEqual(ru.foreign_rules(text_of(self.model)), foreign)
        self.assertEqual(self.now['file_owners']['/etc/ds-guard/example'], [0, 12345])
        self.assertEqual(self.restores[:3], [ru.MARKER, *ru.HOLDS])
        self.assertTrue(self.restores[-1].startswith(ru.LIBRARIES))
        self.assertFalse((self.state / 'removed.json').exists())
        self.assertTrue((self.state / 'rollback-upgrade-completed.json').exists())
        self.assertFalse(any(c[0] in ('rmmod', 'modprobe', 'iptables-restore') for c in self.commands))

    def test_repeat_verifies_without_restart_or_writes(self):
        ru._rollback_upgrade()
        self.commands.clear()
        self.restores.clear()
        receipt = (self.state / 'rollback-upgrade-completed.json').read_bytes()
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertEqual(self.restores, [])
        self.assertFalse(any(c[0] in ('systemctl', 'iptables') or c[:2] == ['apt-get', '-y'] for c in self.commands))
        self.assertEqual(receipt, (self.state / 'rollback-upgrade-completed.json').read_bytes())

    def test_completed_plan_still_rejects_known_file_reintroduced(self):
        ru._rollback_upgrade()
        self.now['files']['/etc/ds-guard/example'] = self.a['files']['/etc/ds-guard/example']
        self.commands.clear()
        self.restores.clear()
        with self.assertRaisesRegex(RuntimeError, 'Файл не восстановлен'):
            ru._rollback_upgrade(plan=True)
        self.assertEqual(self.restores, [])

    def test_already_original_firewall_has_no_steps(self):
        self.model = ru.firewall(self.b['iptables'])
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertFalse(any(c[0] == 'iptables' for c in self.commands))

    def test_interrupt_after_kernel_rule_change_resumes_without_duplicate_delete(self):
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertEqual(ru.owned_scope(self.model), ru.owned_scope(ru.firewall(self.b['iptables'])))

    def test_ndpi_hooks_use_reverse_positions_and_preserve_interleaved_foreign(self):
        self.model['OUTPUT'].insert(1, ['-p', 'tcp', '--dport', '555', '-j', 'ACCEPT'])
        # This is the sealed state for this independent case, not tolerated drift.
        self.a['iptables'] = text_of(self.model)
        foreign = ru.foreign_rules(text_of(self.model))
        self.assertEqual(ru._rollback_upgrade(), 0)
        deletes = [c[3:] for c in self.commands if c[:4] == ['iptables', '-w', '5', '-D']]
        self.assertEqual(deletes, [['-D', 'OUTPUT', '3'], ['-D', 'OUTPUT', '1']])
        self.assertEqual(ru.foreign_rules(text_of(self.model)), foreign)

    def test_stale_numeric_delete_cannot_remove_a_foreign_rule(self):
        baseline = ru.firewall(self.b['iptables'])
        data = ru.firewall_journal(self.b, self.a, self.snapshot(), baseline)
        self.model['OUTPUT'].insert(0, ['-p', 'tcp', '--dport', '555', '-j', 'ACCEPT'])
        with self.assertRaisesRegex(RuntimeError, 'изменение собственных правил'):
            ru.restore_firewall(data)
        self.assertFalse(any(c[0] == 'iptables' for c in self.commands))

    def test_modified_recorded_index_is_refused_even_with_valid_current_scope(self):
        baseline = ru.firewall(self.b['iptables'])
        data = ru.firewall_journal(self.b, self.a, self.snapshot(), baseline)
        # Position 3 is a foreign rule; position 1 is another managed hook.
        for index in ('3', '1'):
            with self.subTest(index=index):
                forged = copy.deepcopy(data)
                forged['steps'][0]['args'][-1] = index
                with self.assertRaisesRegex(RuntimeError, 'вне разрешённой области'):
                    ru.restore_firewall(forged)
        self.assertFalse(any(c[0] == 'iptables' for c in self.commands))

    def test_plan_has_no_mutations_or_journal(self):
        self.assertEqual(ru._rollback_upgrade(plan=True), 0)
        self.assertEqual(self.restores, [])
        self.assertFalse(list(self.state.glob('rollback-upgrade*')))

    def test_loaded_module_difference_returns_reboot_without_unload(self):
        self.reboot.return_value = True
        self.assertEqual(ru._rollback_upgrade(), 20)
        self.assertTrue(json.loads((self.state / 'rollback-upgrade-completed.json').read_text())['loaded_module_requires_reboot'])

    def test_active_baseline_refused_before_commands(self):
        self.b['units']['ds-guard.timer']['active'] = 'active'
        with self.assertRaisesRegex(RuntimeError, 'активной'):
            ru._rollback_upgrade()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.restores, [])

    def test_unknown_hold_or_bad_backup_refused(self):
        ru.backup(ru.HOLDS[0]).write_text('not the known hold')
        with self.assertRaisesRegex(RuntimeError, 'резервная копия'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_baseline_ndpi_rules_refused(self):
        self.b['iptables'] = self.a['iptables']
        with self.assertRaisesRegex(RuntimeError, 'старый nDPI'):
            ru._rollback_upgrade()
        self.assertEqual(self.commands, [])

    def test_missing_original_loaded_identity_refused(self):
        self.b.pop('loaded_module_note_hex')
        with self.assertRaisesRegex(RuntimeError, 'идентичность'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_file_drift_refused_before_mutations(self):
        self.now['files']['/etc/ds-guard/example']['sha256'] = 'administrator edit'
        with self.assertRaisesRegex(RuntimeError, 'изменены файлы'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_parent_directory_symlink_refused_before_mutations(self):
        parent = Path(ru.HOLDS[0]).parent
        real = Path.is_symlink
        with patch.object(Path, 'is_symlink', new=lambda p: p == parent or real(p)):
            with self.assertRaisesRegex(RuntimeError, 'каталог заменён ссылкой'):
                ru._rollback_upgrade()
        self.assertEqual(self.restores, [])
        self.assertEqual(self.commands, [])

    def test_foreign_dependency_removal_refused_before_mutations(self):
        self.simulation += '\nRemv admin-package [9]'
        with self.assertRaisesRegex(RuntimeError, 'посторонние пакеты'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_original_package_change_refused_before_mutations(self):
        self.now['packages']['suricata'] = '8'
        with self.assertRaisesRegex(RuntimeError, 'Прежний пакет'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_unrecognized_reference_to_owned_chain_refused(self):
        self.model['INPUT'].append(['-p', 'tcp', '-j', 'DS_DOM_A'])
        with self.assertRaisesRegex(RuntimeError, 'Чужое правило'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_owned_running_kernel_requires_reboot_before_mutations(self):
        p = 'linux-image-old-kernel'
        self.a['owned_packages'][p] = '1'
        self.a['packages'][p] = self.now['packages'][p] = '1'
        self.assertEqual(ru._rollback_upgrade(), 20)
        self.assertEqual(self.restores, [])

    def test_nonactive_new_kernel_refused_by_narrow_same_kernel_path(self):
        p = 'linux-image-new-kernel'
        self.a['owned_packages'][p] = '1'
        self.a['packages'][p] = self.now['packages'][p] = '1'
        with self.assertRaisesRegex(RuntimeError, 'пакеты ядра'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_foreign_insert_before_managed_hook_is_not_silently_reordered(self):
        self.model['OUTPUT'].insert(0, ['-p', 'tcp', '--dport', '123', '-j', 'DROP'])
        with self.assertRaisesRegex(RuntimeError, 'положение'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def configure_rotation(self):
        """The legacy and sealed generation are equal; only the timer flips it."""
        generation = ru.rotation.GENERATION
        text = 'ACTIVE=DS_DOM_A\nDNS_RULES=1\nHOST_RULES=1\nPOLICY_SHA=' + 'a' * 64 + '\n'
        for name in (*ru.rotation.INPUTS, generation):
            content = text if name == generation else name
            p = ru.backup(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            p.chmod(0o600 if name == generation else 0o644)
            for record in (self.b, self.a, self.now):
                record['files'][name] = lc.stamp(p)
                record['file_owners'][name] = [0, 0]
        model = {
            'INPUT': [['-p', 'tcp', '--dport', '22', '-j', 'ACCEPT']],
            'OUTPUT': [['-o', 'eth0', '-j', 'DS_DOMAINS'], ['-d', '192.0.2.1/32', '-j', 'ACCEPT']],
            'FORWARD': [['-o', 'eth0', '-j', 'DS_DOMAINS']],
            'DS_DOMAINS': [['-j', 'DS_DOM_A']],
            'DS_DOM_A': [['-p', 'udp', '--dport', '53', '-j', 'DS_DOM_A_D'],
                         ['-p', 'tcp', '--dport', '443', '-j', 'DS_DOM_A_W']],
            'DS_DOM_A_D': [['-m', 'string', '--string', 'example.test', '--algo', 'kmp', '-j', 'DROP']],
            'DS_DOM_A_W': [['-m', 'connbytes', '--connbytes', '33:', '--connbytes-mode', 'packets', '--connbytes-dir', 'original', '-j', 'RETURN']]}
        self.b['iptables'] = text_of(model)
        model['DS_DOM_A_W'].append(['-m', 'ndpi', '--proto', 'all', '--host', 'example.test', '-j', 'DROP'])
        self.a['iptables'] = text_of(model)
        self.model = ru.firewall(self.a['iptables'].replace('DS_DOM_A', 'DS_DOM_B'))
        rotated = text.replace('DS_DOM_A', 'DS_DOM_B')
        self.now['generation_text'] = rotated
        self.now['files'][generation] = {'sha256': hashlib.sha256(rotated.encode()).hexdigest(), 'mode': 0o600}
        self.assertNotIn(generation, lc.changed_owned(self.b, self.a))
        # Old persisted lifecycle records predate raw generation_text capture.
        self.assertNotIn('generation_text', self.a)
        self.assertTrue(ru.rotation.prove_bank_rotation(self.a, self.snapshot()))

    def test_rotation_restores_equal_before_after_generation_and_original_identity(self):
        self.configure_rotation()
        original = copy.deepcopy([self.b, self.a])
        foreign = ru.foreign_rules(text_of(self.model))
        self.assertEqual(ru._rollback_upgrade(), 0)
        generation = ru.rotation.GENERATION
        self.assertIn(generation, self.restores)
        self.assertEqual(self.now['files'][generation], self.b['files'][generation])
        self.assertEqual(ru.foreign_rules(text_of(self.model)), foreign)
        self.assertEqual([self.b, self.a], original)
        for name in ('progress', 'firewall', 'completed'):
            receipt = json.loads((self.state / ('rollback-upgrade-' + name + '.json')).read_text())
            self.assertEqual(receipt['records_sha256'], ru.digest(original))
            self.assertEqual(receipt['extra_restore_paths'], [generation])
            self.assertTrue(ru.rotation.prove_bank_rotation(self.a, receipt['rotation_observed']))
        self.commands.clear()
        self.restores.clear()
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertFalse(self.restores)
        self.assertFalse(any(c[0] in ('systemctl', 'iptables') or c[:2] == ['apt-get', '-y'] for c in self.commands))

    def test_rotation_missing_original_generation_backup_refuses_before_mutation(self):
        self.configure_rotation()
        ru.backup(ru.rotation.GENERATION).write_text('not the original')
        with self.assertRaisesRegex(RuntimeError, 'резервной копии'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])
        self.assertFalse(list(self.state.glob('rollback-upgrade*')))

    def test_rotation_interrupt_after_exact_firewall_step_resumes(self):
        self.configure_rotation()
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        receipt = json.loads((self.state / 'rollback-upgrade-firewall.json').read_text())
        self.assertEqual(receipt['next'], 0)
        self.assertEqual(ru.owned_scope(self.model), receipt['steps'][0]['after'])
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertEqual(ru.owned_scope(self.model), ru.owned_scope(ru.firewall(self.b['iptables'])))
        self.assertEqual(self.now['files'][ru.rotation.GENERATION], self.b['files'][ru.rotation.GENERATION])

    def test_rotation_interrupt_after_generation_restore_resumes_from_saved_proof(self):
        self.configure_rotation()
        armed = [True]

        def restore_then_interrupt(name, item, baseline):
            self.restore(name, item, baseline)
            if name == ru.rotation.GENERATION and armed[0]:
                armed[0] = False
                raise KeyboardInterrupt()

        with patch.object(ru, 'restore_file', side_effect=restore_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                ru._rollback_upgrade()
        self.assertFalse(ru.rotation.prove_bank_rotation(self.a, self.snapshot()))
        self.assertEqual(ru._rollback_upgrade(), 0)
        self.assertEqual(self.now['files'][ru.rotation.GENERATION], self.b['files'][ru.rotation.GENERATION])

    def test_rotation_saved_firewall_resume_does_not_accept_another_equivalent_bank(self):
        self.configure_rotation()
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        # A whole bank is equivalent policy, but is neither exact interrupted
        # step precondition nor postcondition; no normalization on resume.
        self.model = ru.firewall(self.a['iptables'])
        self.restores.clear()
        with self.assertRaisesRegex(RuntimeError, 'последнего подтверждённого шага'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_rotation_completed_repeat_refuses_rotated_generation_reintroduced(self):
        self.configure_rotation()
        observed = copy.deepcopy(self.now['files'][ru.rotation.GENERATION])
        ru._rollback_upgrade()
        self.now['files'][ru.rotation.GENERATION] = observed
        self.restores.clear()
        with self.assertRaisesRegex(RuntimeError, 'Файл не восстановлен'):
            ru._rollback_upgrade(plan=True)
        self.assertEqual(self.restores, [])

    def test_rotation_critical_input_changed_after_interruption_is_not_adopted(self):
        self.configure_rotation()
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        self.now['files'][ru.rotation.INPUTS[0]] = {'sha256': 'administrator-edit', 'mode': 0o644}
        self.restores.clear()
        with self.assertRaisesRegex(RuntimeError, 'Критический файл'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_rotation_changed_generation_owner_is_refused(self):
        self.configure_rotation()
        self.now['file_owners'][ru.rotation.GENERATION] = [1000, 0]
        with self.assertRaisesRegex(RuntimeError, 'вне подтверждённой ротации'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_rotation_saved_proof_tampering_refuses_before_mutation(self):
        self.configure_rotation()
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        path = self.state / 'rollback-upgrade-progress.json'
        receipt = json.loads(path.read_text())
        receipt['rotation_observed']['generation_text'] += 'UNKNOWN=yes\n'
        path.write_text(json.dumps(receipt))
        self.restores.clear()
        with self.assertRaisesRegex(RuntimeError, 'сохранённое происхождение'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_rotation_extra_path_and_original_journal_identity_are_not_widened(self):
        self.configure_rotation()
        self.interrupt_after_iptables = True
        with self.assertRaises(KeyboardInterrupt):
            ru._rollback_upgrade()
        path = self.state / 'rollback-upgrade-progress.json'
        original = json.loads(path.read_text())
        for field, value, message in (
                ('extra_restore_paths', [ru.rotation.GENERATION, '/etc/foreign'], 'область возврата'),
                ('records_sha256', 'other-installation', 'другой установке')):
            with self.subTest(field=field):
                receipt = {**original, field: value}
                path.write_text(json.dumps(receipt))
                self.restores.clear()
                with self.assertRaisesRegex(RuntimeError, message):
                    ru._rollback_upgrade()
                self.assertEqual(self.restores, [])

    def test_rotation_foreign_hook_position_drift_is_not_normalized(self):
        self.configure_rotation()
        self.model['OUTPUT'].insert(0, ['-p', 'tcp', '--dport', '123', '-j', 'DROP'])
        with self.assertRaisesRegex(RuntimeError, 'вне подтверждённой ротации'):
            ru._rollback_upgrade()
        self.assertEqual(self.restores, [])

    def test_rotation_capture_to_stop_is_locked_without_long_restore_under_lock(self):
        self.configure_rotation()
        self.lock_events.clear()
        self.assertEqual(ru._rollback_upgrade(), 0)
        snapshots = [depth for event, depth in self.lock_events if event == 'snapshot']
        self.assertEqual(snapshots, [0, 1])
        stop = ('systemctl', 'stop', *ru.GUARDS)
        self.assertIn((stop, 1), self.lock_events)
        reloads = [depth for event, depth in self.lock_events if event == ('systemctl', 'daemon-reload')]
        self.assertEqual(reloads, [1, 0])
        for event, depth in self.lock_events:
            if isinstance(event, tuple) and (event[0] == 'iptables' or event[:2] in (('apt-get', '-s'), ('apt-get', '-y'))):
                self.assertEqual(depth, 0, event)
        self.assertEqual(self.lock_depth, 0)


class AtomicRestore(unittest.TestCase):
    def test_actual_symlink_parent_is_not_written(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            original = root / 'foreign'
            original.mkdir()
            target = original / 'file'
            target.write_text('foreign data')
            link = root / 'link'
            link.symlink_to(original, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'каталог заменён ссылкой'):
                ru.restore_file(str(link / 'file'), None, {})
            self.assertEqual(target.read_text(), 'foreign data')

    def test_atomic_file_restore_preserves_mode_owner_and_never_unlinks_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / 'target'
            target.write_text('new')
            state = root / 'lifecycle'
            stored = state / 'files' / str(target).lstrip('/')
            stored.parent.mkdir(parents=True)
            stored.write_text('old')
            stored.chmod(0o640)
            b = {'file_owners': {str(target): [os.getuid(), os.getgid()]}}
            item = lc.stamp(stored)
            original_unlink = Path.unlink

            def unlink(p, *args, **kwargs):
                self.assertNotEqual(p, target)
                return original_unlink(p, *args, **kwargs)

            with patch.object(lc, 'STATE', state), patch.object(Path, 'unlink', new=unlink):
                ru.restore_file(str(target), item, b)
            self.assertEqual(target.read_text(), 'old')
            self.assertEqual(lc.stamp(target), item)
            self.assertEqual([target.stat().st_uid, target.stat().st_gid], b['file_owners'][str(target)])


if __name__ == '__main__':
    unittest.main()
