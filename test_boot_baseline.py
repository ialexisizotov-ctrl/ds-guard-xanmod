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
            (state/'package-receipts').mkdir()
            (state/'package-receipts/one.json').write_text(json.dumps({
                'schema': 1, 'completed': True, 'returncode': 0,
                'operation_id': '00000000-0000-0000-0000-000000000001',
                'installed': a['owned_packages']}))
            for name, d in [('before.json', b), ('after.json', a), ('last-operation.json', {'exit_code': 20})]:
                (state/name).write_text(json.dumps(d))
            original = (state/'before.json').read_bytes()
            trial_path = state.parent/'trial.json'
            trial_path.write_text(json.dumps(trial))
            (state.parent/'kernel/new.staged.json').write_text(json.dumps(stage))
            boot = state.parent/'boot'
            boot.write_text('boot-new')
            scope = {p: {'version': '1', 'architecture': 'amd64'} for p in a['owned_packages']}
            with patch.object(m, 'TRIAL', trial_path), patch.object(m, 'BOOT_ID', boot), patch.object(m, 'kernel_package_scope', return_value=scope):
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

    def ubuntu_fixture(self, target='6.8.0-147-generic'):
        b, a, c, t, s = self.fixture()
        catalog = json.loads(Path(m.__file__).with_name('kernels.json').read_text())
        scope = m.catalog_packages(target, catalog)
        a['owned_packages'] = {p: v['version'] for p, v in scope.items()}
        c['packages'] = dict(a['owned_packages'])
        c['kernel'] = t['target'] = s['candidate'] = target
        return b, a, c, t, s, scope

    def test_full_ubuntu_catalogs_and_xanmod_pass(self):
        catalog = json.loads(Path(m.__file__).with_name('kernels.json').read_text())
        for target in catalog:
            with self.subTest(target=target):
                b,a,c,t,s,scope = self.ubuntu_fixture(target)
                m.validate(b,a,c,t,s,'boot-new',scope)

    def test_preinstalled_subset_with_required_regdb_passes(self):
        b,a,c,t,s,scope = self.ubuntu_fixture()
        extras = 'linux-modules-extra-'+c['kernel']
        b['packages'] = {p:v for p,v in c['packages'].items() if p != extras}
        a['owned_packages'] = {extras:c['packages'][extras], 'wireless-regdb':'2026.05.30-0ubuntu1~24.04.1'}
        c['packages'].update(a['owned_packages'])
        scope['wireless-regdb'] = {'version':None,'architecture':'all'}
        m.validate(b,a,c,t,s,'boot-new',scope)
        c['packages']['unrelated-admin-tool'] = '9'
        m.validate(b,a,c,t,s,'boot-new',scope)

    def test_fully_preinstalled_kernel_has_no_owned_packages(self):
        b,a,c,t,s,scope = self.ubuntu_fixture()
        b['packages'] = dict(c['packages']);a['owned_packages'] = {}
        m.validate(b,a,c,t,s,'boot-new',scope)

    def test_unrelated_owned_package_wrong_version_architecture_and_missing_stop(self):
        for case in ('foreign','other_kernel','wrong_version','wrong_arch','missing','preexisting','duplicate'):
            with self.subTest(case=case):
                b,a,c,t,s,scope = self.ubuntu_fixture();p='linux-image-'+c['kernel']
                if case=='foreign':a['owned_packages']['suricata']='1';c['packages']['suricata']='1'
                if case=='other_kernel':a['owned_packages']['linux-image-other']='1';c['packages']['linux-image-other']='1'
                if case=='wrong_version':a['owned_packages'][p]=c['packages'][p]='999'
                if case=='wrong_arch':a['owned_packages'][p+':arm64']=a['owned_packages'].pop(p)
                if case=='missing':del c['packages'][p]
                if case=='preexisting':b['packages'][p]=a['owned_packages'][p]
                if case=='duplicate':a['owned_packages'][p+':amd64']=a['owned_packages'][p]
                with self.assertRaises(RuntimeError):m.validate(b,a,c,t,s,'boot-new',scope)

    def test_receipted_dependency_version_change_stops(self):
        b,a,c,t,s,scope=self.ubuntu_fixture()
        scope['wireless-regdb']={'version':None,'architecture':'all'}
        a['owned_packages']['wireless-regdb']='1';c['packages']['wireless-regdb']='2'
        with self.assertRaises(RuntimeError):m.validate(b,a,c,t,s,'boot-new',scope)

    def test_exact_ubuntu_parent_dependency_required(self):
        target='6.8.0-147-generic';parent='linux-modules-extra-'+target
        from subprocess import CompletedProcess
        for dep, expected in [('wireless-regdb',True),('linux-modules-'+target+', wireless-regdb',True),
                              ('wireless-regdb-other',False),('wireless-regdb | other',False),('',False)]:
            with self.subTest(dep=dep), patch.object(m.subprocess,'run',return_value=CompletedProcess([],0,parent+'\tamd64\tinstalled\t6.8.0-147.147\t'+dep+'\n','')):
                self.assertEqual('wireless-regdb' in m.kernel_package_scope(target),expected)
        with patch.object(m.subprocess,'run',return_value=CompletedProcess([],0,parent+'\tamd64\tinstalled\t999\twireless-regdb\n','')):
            with self.assertRaises(RuntimeError):m.kernel_package_scope(target)

    def test_catalog_cannot_be_empty_or_unknown(self):
        for catalog in ({},{'new':{'packages':[]}}, {'new':{'image':'bad','headers':'bad'}}):
            with self.assertRaises(RuntimeError):m.catalog_packages('new',catalog)

    def test_private_receipts_required_and_exact(self):
        owned={'linux-modules-extra-test':'1','wireless-regdb':'2'}
        good={'schema':1,'completed':True,'returncode':0,'operation_id':'00000000-0000-0000-0000-000000000001','installed':owned}
        with tempfile.TemporaryDirectory() as td:
            state=Path(td);receipts=state/'package-receipts';receipts.mkdir();f=receipts/'one.json'
            with self.assertRaises(RuntimeError):m.verify_kernel_receipts(state,owned)
            f.write_text(json.dumps(good));m.verify_kernel_receipts(state,owned)
            for key,value in [('schema',0),('completed',False),('returncode',1),('operation_id','bad'),('installed',{})]:
                with self.subTest(key=key):
                    f.write_text(json.dumps({**good,key:value}))
                    with self.assertRaises(RuntimeError):m.verify_kernel_receipts(state,owned)
            f.write_text(json.dumps(good));(receipts/'two.json').write_text(json.dumps(good))
            with self.assertRaises(RuntimeError):m.verify_kernel_receipts(state,owned)


if __name__ == '__main__':
    unittest.main()
