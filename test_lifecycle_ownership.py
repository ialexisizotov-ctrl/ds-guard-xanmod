"""Regression tests for package provenance and interrupted disable recovery.

All mutations are confined to TemporaryDirectory; system commands are mocked.
"""
import json
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lifecycle


OPERATION = '12345678-1234-1234-1234-123456789abc'


def record(packages, owned=None, values=None):
    return {'files': {}, 'file_owners': {}, 'packages': packages,
            'ownership_schema': 1, 'owned_packages': owned or {},
            'values': values or {}, 'iptables': '', 'units': {},
            'manual': [], 'module_state': {}, 'conntrack_hashsize': None,
            'kernel': 'test-kernel', 'time': 1}


class LifecycleOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / 'lifecycle'
        self.state.mkdir()
        self.state_patch = patch.object(lifecycle, 'STATE', self.state)
        self.state_patch.start()
        self.addCleanup(self.state_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, value):
        target = self.state / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value))

    def journal(self):
        before = record({'base': '1'})
        after = record({'base': '1', 'guard-dependency': '2'},
                       {'guard-dependency': '2'})
        self.write('before.json', before)
        self.write('after.json', after)
        return before, after

    def pending(self, packages):
        self.write('pending.json', {'operation_id': OPERATION,
                                   'packages_before': packages})

    def receipt(self, installed, completed=True, returncode=0,
                operation_id=OPERATION):
        self.write('package-receipts/receipt.json',
                   {'schema': 1, 'operation_id': operation_id,
                    'completed': completed, 'returncode': returncode,
                    'installed': installed})

    def test_foreign_packages_before_and_during_repeat_are_not_owned(self):
        _, after = self.journal()
        prior = {**after['packages'], 'admin-between-runs': '3'}
        self.pending(prior)
        current = {**prior, 'guard-new': '4', 'admin-during-run': '5'}
        self.receipt({'guard-new': '4'})
        self.assertEqual(lifecycle.package_ownership(current),
                         {'guard-dependency': '2', 'guard-new': '4'})

    def test_failed_command_keeps_proven_partial_install(self):
        _, after = self.journal()
        self.pending(after['packages'])
        self.receipt({'guard-new': '4'}, returncode=17)
        self.assertEqual(lifecycle.package_ownership(
            {**after['packages'], 'guard-new': '4'}),
            {'guard-dependency': '2', 'guard-new': '4'})

    def test_incomplete_receipt_preserves_journal_for_review(self):
        _, after = self.journal()
        self.pending(after['packages'])
        self.receipt({'guard-new': '4'}, completed=False)
        original = (self.state / 'after.json').read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'не завершена'):
            lifecycle.package_ownership({**after['packages'], 'guard-new': '4'})
        self.assertEqual((self.state / 'after.json').read_bytes(), original)
        self.assertTrue((self.state / 'pending.json').exists())

    def test_receipt_cannot_claim_a_preexisting_package(self):
        _, after = self.journal()
        self.pending(after['packages'])
        self.receipt({'base': '1'})
        with self.assertRaisesRegex(RuntimeError, 'ранее существовавший'):
            lifecycle.package_ownership(after['packages'])

    def test_receipt_version_drift_is_refused(self):
        _, after = self.journal()
        self.pending(after['packages'])
        self.receipt({'guard-new': '4'})
        with self.assertRaisesRegex(RuntimeError, 'версия изменилась'):
            lifecycle.package_ownership({**after['packages'], 'guard-new': '5'})

    def test_other_operation_receipt_cannot_claim_packages(self):
        _, after = self.journal()
        self.pending(after['packages'])
        self.receipt({'unrelated': '4'}, operation_id='different-operation')
        self.assertEqual(lifecycle.package_ownership(
            {**after['packages'], 'unrelated': '4'}), after['owned_packages'])

    def test_legacy_package_difference_is_not_adopted(self):
        before, after = self.journal()
        del after['ownership_schema']
        del after['owned_packages']
        self.write('after.json', after)
        with self.assertRaisesRegex(RuntimeError, 'нет доказанного происхождения'):
            lifecycle.read_records()
        self.assertEqual(json.loads((self.state / 'before.json').read_text()),
                         before)

    def test_disable_then_remove_preserves_later_admin_package(self):
        before, after = self.journal()
        current = {**after['packages'], 'admin-database': '9'}
        commands = []

        def run(args, *unused, **kwargs):
            commands.append(args)
            if args[:3] == ['apt-get', '-s', 'purge']:
                return '\n'.join('Purg ' + p + ' [2]' for p in args[3:])
            return ''

        original_read = Path.read_text

        def read_text(path, *args, **kwargs):
            if str(path) == '/sys/module/nf_conntrack/parameters/hashsize':
                return '65536\n'
            return original_read(path, *args, **kwargs)

        with patch.object(lifecycle, 'packages', return_value=current), \
             patch.object(lifecycle, 'paths', return_value=[]), \
             patch.object(lifecycle, 'values', return_value={}), \
             patch.object(lifecycle, 'units', return_value={}), \
             patch.object(lifecycle, 'run', side_effect=run), \
             patch.object(Path, 'read_text', new=read_text):
            self.assertEqual(lifecycle.disable(), 0)
            saved = json.loads((self.state / 'after.json').read_text())
            self.assertIn('admin-database', saved['packages'])
            self.assertEqual(saved['owned_packages'], {'guard-dependency': '2'})
            self.assertEqual(lifecycle.removal_plan()[3], ['guard-dependency'])
        conffile_queries = [a for a in commands if a[:3] ==
                            ['dpkg-query', '-W', '-f=${Conffiles}']]
        self.assertTrue(conffile_queries)
        self.assertTrue(all(a[-1] == 'guard-dependency' for a in conffile_queries))
        self.assertEqual(json.loads((self.state / 'before.json').read_text()),
                         before)

    def test_interrupted_disable_retries_restoration_before_success(self):
        key = 'net.ipv4.tcp_fin_timeout'
        before = record({'base': '1'}, values={key: '30'})
        after = record({'base': '1'}, values={key: '15'})
        self.write('before.json', before)
        self.write('after.json', after)
        original = (self.state / 'after.json').read_bytes()
        restore_calls = []

        def fail_once(args, *unused, **kwargs):
            restore_calls.append(args)
            if len(restore_calls) == 1:
                raise RuntimeError('injected sysctl failure')
            return ''

        with patch.object(lifecycle, 'snapshot', return_value=after), \
             patch.object(lifecycle, 'run', side_effect=fail_once):
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                lifecycle.disable()
            self.assertTrue((self.state / 'disabled').exists())
            self.assertFalse((self.state / 'disabled-complete.json').exists())
            self.assertEqual((self.state / 'after.json').read_bytes(), original)
            with self.assertRaisesRegex(RuntimeError, 'Отключение не завершено'):
                lifecycle.enable_prepare()
            self.assertEqual(lifecycle.disable(), 0)
            self.assertTrue((self.state / 'disabled-complete.json').exists())
            self.assertEqual(restore_calls, [['sysctl', '-w', key + '=30']] * 2)
            self.assertEqual(lifecycle.disable(), 0)
            self.assertEqual(len(restore_calls), 2)

    def test_disable_does_not_adopt_foreign_files_values_or_manual_marks(self):
        before = record({'base': '1'}, values={'untouched': '1', 'owned': '2'})
        before['files'] = {'/owned': 'original', '/foreign': 'original'}
        after = record({'base': '1'}, values={'untouched': '1', 'owned': '3'})
        after['files'] = {'/owned': 'installer', '/foreign': 'original'}
        current = record({'base': '1'}, values={'untouched': '9', 'owned': '2'})
        current['files'] = {'/owned': 'original', '/foreign': 'admin-change',
                            '/new-foreign': 'admin-created'}
        current['manual'] = ['base']
        projected = lifecycle.preserved_disable_snapshot(before, after, current, False)
        self.assertEqual(projected['files'], before['files'])
        self.assertEqual(projected['values'], before['values'])
        self.assertEqual(projected['manual'], [])
        self.assertNotIn('/new-foreign', lifecycle.changed_owned(before, projected))

    def test_repeat_refuses_unowned_file_or_value_drift_before_mutation(self):
        before, after = self.journal()
        before['files'] = after['files'] = {'/foreign': 'original'}
        current = {**after, 'files': {'/foreign': 'admin-change'}}
        with self.assertRaisesRegex(RuntimeError, 'вне области установки'):
            lifecycle.verify_repeat_baseline(before, after, current)
        before['values'] = after['values'] = {'untouched': '1'}
        current = {**after, 'values': {'untouched': '9'}}
        with self.assertRaisesRegex(RuntimeError, 'сетевой параметр вне области'):
            lifecycle.verify_repeat_baseline(before, after, current)

    def test_repeat_records_current_metadata_without_claiming_foreign_package(self):
        _, after = self.journal()
        current = {**after, 'packages': {**after['packages'], 'admin': '9'},
                   'manual': ['admin']}
        with patch.object(lifecycle, 'snapshot', return_value=current):
            lifecycle.begin()
        pending = json.loads((self.state / 'pending.json').read_text())
        self.assertEqual(pending['packages_before'], current['packages'])
        self.assertEqual(pending['metadata_before']['manual'], ['admin'])
        self.assertEqual(len(pending['operation_id']), 36)
        self.assertEqual(lifecycle.package_ownership(current['packages']),
                         {'guard-dependency': '2'})

    def drifted_journal(self):
        before = record({'base': '1', 'old-kernel': '1'})
        after = record({'base': '2', 'new-kernel': '2', 'guard-dependency': '2'},
                       {'guard-dependency': '2'})
        current = record({'base': '3', 'new-kernel': '2', 'admin': '9',
                          'guard-dependency': '2'}, {'guard-dependency': '2'})
        self.write('before.json', before)
        self.write('after.json', after)
        return before, after, current

    def test_repeat_and_seal_preserve_unowned_upgrade_add_remove_and_original_bytes(self):
        before, after, current = self.drifted_journal()
        original = (self.state / 'before.json').read_bytes()
        current['manual'] = ['admin']
        with patch.object(lifecycle, 'snapshot', return_value=current), \
                patch.object(lifecycle, 'run', return_value='') as run:
            lifecycle.begin()
            pending = json.loads((self.state / 'pending.json').read_text())
            self.assertEqual(pending['packages_before'], current['packages'])
            self.assertEqual(lifecycle.package_ownership(current['packages']), {'guard-dependency': '2'})
            lifecycle.seal(0)
            self.assertFalse((self.state / 'pending.json').exists())
            saved = json.loads((self.state / 'after.json').read_text())
            self.assertEqual(saved['packages'], current['packages'])
            self.assertEqual(saved['owned_packages'], {'guard-dependency': '2'})
            self.assertEqual(saved['manual'], after['manual'])
            lifecycle.verify_repeat_baseline(before, saved, current)
            self.assertFalse(any(c.args[0][0] in ('apt-get', 'dpkg', 'apt-mark') for c in run.call_args_list))
        self.assertEqual((self.state / 'before.json').read_bytes(), original)

    def test_removal_plan_excludes_unowned_upgrades_new_and_removed_kernels(self):
        _, _, current = self.drifted_journal()
        original = (self.state / 'before.json').read_bytes()
        commands = []

        def run(args, *unused, **kwargs):
            commands.append(args)
            if args[:3] == ['apt-get', '-s', 'purge']:
                return 'Purg guard-dependency [2]'
            return ''

        with patch.object(lifecycle, 'snapshot', return_value=current), \
                patch.object(lifecycle, 'run', side_effect=run):
            plan = lifecycle.removal_plan()
        self.assertEqual(plan[3], ['guard-dependency'])
        self.assertEqual(plan[4:], ([], []))
        self.assertEqual([c for c in commands if c[0] == 'apt-get'],
                         [['apt-get', '-s', 'purge', 'guard-dependency']])
        self.assertEqual((self.state / 'before.json').read_bytes(), original)

    def test_repeat_and_remove_refuse_owned_version_drift_and_baseline_collision(self):
        for kind in ('saved-version', 'live-version', 'baseline-collision'):
            with self.subTest(kind=kind):
                before, after, current = self.drifted_journal()
                if kind == 'saved-version':
                    after['packages']['guard-dependency'] = '9'
                elif kind == 'live-version':
                    current['packages']['guard-dependency'] = '9'
                else:
                    after['owned_packages']['base'] = '2'
                self.write('after.json', after)
                original = (self.state / 'before.json').read_bytes()
                with patch.object(lifecycle, 'snapshot', return_value=current), \
                        patch.object(lifecycle, 'run', return_value='') as run:
                    with self.assertRaises(RuntimeError):
                        lifecycle.begin()
                    self.assertFalse((self.state / 'pending.json').exists())
                    with self.assertRaises(RuntimeError):
                        lifecycle.removal_plan()
                    self.assertFalse(any(c.args[0][0] == 'apt-get' for c in run.call_args_list))
                self.assertEqual((self.state / 'before.json').read_bytes(), original)

    def test_absent_owned_package_allows_removal_resume_without_new_ownership(self):
        before, after, current = self.drifted_journal()
        del current['packages']['guard-dependency']
        untouched = copy.deepcopy([before, after, current])
        lifecycle.verify_no_conflict(before, after, current)
        with patch.object(lifecycle, 'snapshot', return_value=current), \
                patch.object(lifecycle, 'run', return_value='') as run:
            self.assertEqual(lifecycle.removal_plan()[3], [])
            self.assertFalse(any(c.args[0][0] == 'apt-get' for c in run.call_args_list))
        self.assertEqual([before, after, current], untouched)

    def test_unowned_package_drift_does_not_relax_other_repeat_conflicts(self):
        before, after, current = self.drifted_journal()
        for kind in ('file', 'value', 'firewall'):
            b, a, now = copy.deepcopy([before, after, current])
            with self.subTest(kind=kind):
                if kind == 'file':
                    b['files'] = a['files'] = {'/foreign': 'original'}
                    now['files'] = {'/foreign': 'changed'}
                elif kind == 'value':
                    b['values'] = a['values'] = {'foreign': '1'}
                    now['values'] = {'foreign': '2'}
                else:
                    now['iptables'] = '*filter\n:DS_DOMAINS - [0:0]\nCOMMIT\n'
                with self.assertRaises(RuntimeError):
                    lifecycle.verify_repeat_baseline(b, a, now)

    def test_new_module_default_is_observed_without_claiming_ownership(self):
        before, after = self.journal()
        current = {**after, 'values': {'new-module-default': '9'}}
        lifecycle.verify_repeat_baseline(before, after, current)
        operation = {'operation_id': OPERATION,
                     'metadata_before': {'values': current['values']}}
        self.assertEqual(lifecycle.sealed_values(operation, after['values'],
                                                 current['values']), {})

    def tuning_receipt(self, before, after, restored=False):
        self.write('../tuning/test/before.json',
                   {'operation_id': OPERATION, 'started': 1,
                    'values': before, 'requested_values': after})
        self.write('../tuning/test/' + ('rolled-back.json' if restored else 'accepted.json'),
                   {'operation_id': OPERATION, 'values': before if restored else after})

    def test_seal_values_requires_matching_worker_provenance(self):
        operation = {'operation_id': OPERATION,
                     'metadata_before': {'values': {'owned': '1', 'foreign': '5'}}}
        self.tuning_receipt({'owned': '1'}, {'owned': '2'})
        self.assertEqual(lifecycle.sealed_values(
            operation, {'owned': '1', 'foreign': '5'},
            {'owned': '2', 'foreign': '5', 'new-module-default': '9'}),
            {'owned': '2', 'foreign': '5'})
        with self.assertRaisesRegex(RuntimeError, 'не имеет подтверждённого происхождения'):
            lifecycle.sealed_values(operation, {'owned': '1', 'foreign': '5'},
                                    {'owned': '2', 'foreign': '9'})

    def test_rollback_receipt_keeps_original_values(self):
        operation = {'operation_id': OPERATION,
                     'metadata_before': {'values': {'owned': '1'}}}
        self.tuning_receipt({'owned': '1'}, {'owned': '2'}, restored=True)
        self.assertEqual(lifecycle.sealed_values(operation, {'owned': '1'},
                                                 {'owned': '1'}), {'owned': '1'})

    def test_value_change_between_begin_and_worker_is_not_adopted(self):
        operation = {'operation_id': OPERATION,
                     'metadata_before': {'values': {'owned': '1'}}}
        self.tuning_receipt({'owned': '9'}, {'owned': '2'})
        with self.assertRaisesRegex(RuntimeError, 'вне подтверждённой операции'):
            lifecycle.sealed_values(operation, {'owned': '1'}, {'owned': '2'})


if __name__ == '__main__':
    unittest.main()
