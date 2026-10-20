import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import boot_baseline as m
import lifecycle


class BootBaselineTests(unittest.TestCase):
    def fixture(self):
        b = {'baseline_kind': 'fresh', 'kernel': 'old',
             'values': {'net.core.wmem_max': '212992'}, 'files': {}, 'packages': {}}
        a = {**copy.deepcopy(b),
             'files': {'/usr/local/lib/ds-guard-safe-kernel/setup.py': {'sha256': 'abc'}},
             'file_owners': {'/usr/local/lib/ds-guard-safe-kernel/setup.py': [0, 0]},
             'owned_packages': {'linux-image-new': '1', 'linux-headers-new': '1'}}
        c = {**copy.deepcopy(a), 'kernel': 'new',
             'values': {'net.core.wmem_max': '4194304'}, 'packages': dict(a['owned_packages']),
             'module_state': {'xt_ndpi': False}}
        trial = {'schema': 1, 'status': 'boot-healthy', 'target': 'new',
                 'fallback': 'old', 'origin_boot_id': 'boot-old',
                 'checked_boot_id': 'boot-new', 'health_errors': [],
                 'owned_files': {}, 'owned_links': {}}
        stage = {'candidate': 'new', 'running_kernel': 'old', 'boot_environment_preserved': True}
        return b, a, c, trial, stage

    def test_new_boot_defaults_pass(self):
        m.validate(*self.fixture(), 'boot-new')

    def test_unsafe_states_stop(self):
        cases = [
            (0, 'baseline_kind', 'legacy-upgrade'),
            (1, 'values', {'net.core.wmem_max': '123'}),
            (2, 'kernel', 'old'),
            (2, 'module_state', {'xt_ndpi': True}),
            (3, 'status', 'armed'),
            (3, 'origin_boot_id', 'boot-new'),
            (3, 'checked_boot_id', 'other'),
            (3, 'health_errors', ['network']),
            (4, 'boot_environment_preserved', False),
            (1, 'owned_packages', {'suricata': '1'}),
            (2, 'packages', {'linux-image-new': '2', 'linux-headers-new': '1'}),
        ]
        for index, key, value in cases:
            with self.subTest(index=index, key=key):
                f = list(self.fixture())
                f[index][key] = value
                with self.assertRaises(RuntimeError):
                    m.validate(*f, 'boot-new')

    def test_foreign_file_and_owner_stop(self):
        for kind in ('file', 'owner', 'preexisting', 'guard'):
            with self.subTest(kind=kind):
                b, a, c, t, s = self.fixture()
                if kind == 'file': c['files']['/foreign'] = {'sha256': 'x'}
                if kind == 'owner': c['file_owners']['/foreign'] = [0, 0]
                if kind == 'preexisting': b['files']['/usr/local/lib/ds-guard-safe-kernel/setup.py'] = {'sha256': 'old'}
                if kind == 'guard':
                    a['files']['/etc/systemd/system/ds-guard.service'] = {'sha256': 'x'}
                    c['files'] = dict(a['files'])
                with self.assertRaises(RuntimeError): m.validate(b, a, c, t, s, 'boot-new')

    def test_capture_overlay_is_immutable_and_repeat_drift_still_stops(self):
        b, a, c, trial, stage = self.fixture()
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)/'lifecycle'
            state.mkdir()
            (state.parent/'kernel').mkdir()
            for name, d in [('before.json', b), ('after.json', a), ('last-operation.json', {'exit_code': 20})]:
                (state/name).write_text(json.dumps(d))
            original = (state/'before.json').read_bytes()
            trial_path = state.parent/'trial.json'
            trial_path.write_text(json.dumps(trial))
            (state.parent/'kernel/new.staged.json').write_text(json.dumps(stage))
            boot = state.parent/'boot'
            boot.write_text('boot-new')
            with patch.object(m, 'TRIAL', trial_path), patch.object(m, 'BOOT_ID', boot):
                self.assertTrue(m.capture(state,b,a,c,lambda *x: None,lifecycle.save))
                self.assertFalse(m.capture(state,b,a,c,lambda *x: None,lifecycle.save))
            bb, aa = m.effective(state,b,a,'new')
            self.assertEqual(bb['values'], c['values'])
            self.assertEqual(aa['values'], c['values'])
            self.assertEqual((state/'before.json').read_bytes(), original)
            # Existing repeat baseline logic must still reject later foreign drift.
            changed = copy.deepcopy(c)
            changed['values']['net.core.wmem_max'] = '123'
            with patch.object(lifecycle, 'verify_no_conflict'), patch.object(lifecycle, 'prove_bank_rotation', return_value=False):
                with self.assertRaisesRegex(RuntimeError, 'сетевой параметр'):
                    lifecycle.verify_repeat_baseline(bb,aa,changed)
            # Once tuned, an actual after snapshot is never replaced by defaults.
            aa['values'] = {'net.core.wmem_max': '16777216'}
            (state/'after.json').write_text(json.dumps(aa))
            b2, a2 = m.effective(state,b,aa,'new')
            self.assertEqual(b2['values'], c['values'])
            self.assertEqual(a2['values'], aa['values'])
            b3, _ = m.effective(state,b,aa,'old')
            self.assertEqual(b3['values'], b['values'])
            with self.assertRaises(RuntimeError): m.effective(state,b,aa,'unknown')
            (state/'before.json').write_text(json.dumps({**b, 'time':1}))
            with self.assertRaises(RuntimeError): m.effective(state,b,aa,'new')


if __name__ == '__main__':
    unittest.main()
