import contextlib
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ubuntu_apt as apt


class UbuntuApt(unittest.TestCase):
    def test_optional_dependencies_disabled_in_plan_and_execution_scope(self):
        with self.scenario() as (root, receipts, update, install):
            options = apt.apt_options(root)
            opts = dict(options[i+1].split('=', 1) for i, x in enumerate(options) if x == '-o')
            self.assertEqual(opts['APT::Install-Recommends'], 'false')
            self.assertEqual(opts['APT::Install-Suggests'], 'false')
            with patch.object(apt, 'resolve_packages', return_value=(['suricata'], {'fallback_used':False})) as plan:
                self.assertEqual(apt.install(['suricata'], '/fixture'), 0)
            self.assertEqual(plan.call_args.args[1], options)
            argv = install.call_args.args[0]
            self.assertEqual(argv[1:1+len(options)], options)

    def test_only_official_supported_sources_with_explicit_keyring(self):
        for suite in ['jammy', 'noble']:
            text = apt.sources(suite)
            self.assertEqual(len(text.splitlines()), 3)
            self.assertEqual(text.count('signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg'), 3)
            self.assertIn(suite+'-security main universe', text)
            self.assertIn(suite+'-updates main universe', text)
            self.assertNotIn('trusted=', text)
            self.assertNotIn('packagecloud', text)
        with self.assertRaises(RuntimeError):
            apt.sources('noble;evil')

    def test_options_do_not_replace_real_status_pins_or_holds(self):
        args = apt.apt_options(Path('/var/tmp/unique'))
        opts = dict(args[i+1].split('=', 1) for i, x in enumerate(args) if x == '-o')
        self.assertEqual(opts['Dir::Etc::sourceparts'], '/var/tmp/unique/sources.parts')
        self.assertEqual(opts['Dir::State::lists'], '/var/tmp/unique/lists')
        self.assertEqual(opts['Dir::Cache::pkgcache'], '')
        self.assertEqual(opts['Dir::Cache::srcpkgcache'], '')
        self.assertNotIn('Dir::State', opts)
        self.assertNotIn('Dir::State::status', opts)
        self.assertNotIn('Dir::Etc::preferences', opts)
        self.assertNotIn('Dir::Etc::preferencesparts', opts)
        self.assertNotIn('APT::Default-Release', opts)
        self.assertEqual(opts['APT::Ignore-Hold'], 'false')
        self.assertEqual(opts['APT::Get::allow-change-held-packages'], 'false')
        self.assertEqual(opts['APT::Sandbox::User'], '_apt')
        for key in ['Acquire::AllowInsecureRepositories', 'Acquire::AllowWeakRepositories',
                    'Acquire::AllowDowngradeToInsecureRepositories', 'APT::Get::AllowUnauthenticated']:
            self.assertEqual(opts[key], 'false')
        for key in ['Acquire::Check-Valid-Until', 'Acquire::Check-Date',
                    'Acquire::https::archive.ubuntu.com::Verify-Peer',
                    'Acquire::https::security.ubuntu.com::Verify-Host']:
            self.assertEqual(opts[key], 'true')
        self.assertEqual(opts['APT::Update::Error-Mode'], 'any')

    def test_only_update_hooks_are_cleared(self):
        self.assertEqual(apt.CLEAR_UPDATE_HOOKS.splitlines(), [
            '#clear APT::Update::Pre-Invoke;', '#clear APT::Update::Post-Invoke;',
            '#clear APT::Update::Post-Invoke-Success;'])
        self.assertNotIn('DPkg', apt.CLEAR_UPDATE_HOOKS)

    def test_foreign_distribution_or_suite_refused_before_commands(self):
        for info in [{'ID':'debian','VERSION_ID':'24.04','VERSION_CODENAME':'noble'},
                     {'ID':'ubuntu','VERSION_ID':'24.04','VERSION_CODENAME':'jammy'},
                     {'ID':'ubuntu','VERSION_ID':'26.04','VERSION_CODENAME':'resolute'}]:
            with patch.object(apt.platform, 'freedesktop_os_release', return_value=info), patch.object(apt, 'checked') as command:
                with self.assertRaises(RuntimeError):
                    apt.environment()
                command.assert_not_called()

    def test_foreign_architecture_and_unfinished_dpkg_refused(self):
        info = {'ID':'ubuntu','VERSION_ID':'24.04','VERSION_CODENAME':'noble'}
        for outputs in [['arm64'], ['amd64', 'unfinished']]:
            with patch.object(apt.platform, 'freedesktop_os_release', return_value=info), patch.object(apt, 'checked', side_effect=outputs):
                with self.assertRaises(RuntimeError):
                    apt.environment()

    def test_missing_and_installed_packages(self):
        replies = [subprocess.CompletedProcess([],0,'amd64\tinstalled\t1.0\n'),
                   subprocess.CompletedProcess([],1,''),
                   subprocess.CompletedProcess([],0,'all\tconfig-files\t2.0\n')]
        with patch.object(apt.subprocess, 'run', side_effect=replies):
            self.assertEqual(apt.missing_packages(['existing','absent','oldconfig']), ['absent','oldconfig'])

    def test_installed_version_or_architecture_is_never_replaced(self):
        for request, reply in [('existing=2.0','amd64\tinstalled\t1.0\n'),
                               ('existing','i386\tinstalled\t1.0\n'),
                               ('existing','amd64\thalf-configured\t1.0\n')]:
            with patch.object(apt.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,reply)):
                with self.assertRaises(RuntimeError):
                    apt.missing_packages([request])

    def test_package_arguments_cannot_be_flags_paths_or_release_switches(self):
        for name in ['--allow-unauthenticated','/tmp/evil.deb','package/noble','package;echo','one two','a:arm64']:
            with patch.object(apt.subprocess, 'run') as command:
                with self.assertRaises(RuntimeError):
                    apt.missing_packages([name])
                command.assert_not_called()

    @contextlib.contextmanager
    def scenario(self, update_rc=0, update_text='', install_rc=0, install_error=None, update_error=None, post_missing=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); workspace=root/'scope'; workspace.mkdir()
            (workspace/'lists').mkdir(); (workspace/'sources.list').write_text('official fixture')
            keyring=root/'ubuntu-keyring.gpg'; keyring.write_bytes(b'fixture')
            receipts=root/'receipts'; receipts.mkdir()
            def update(command, **kwargs):
                kwargs['stdout'].write(update_text)
                if update_error:
                    raise update_error
                return subprocess.CompletedProcess(command, update_rc)
            def install(command, **kwargs):
                kwargs['stdout'].write('install fixture\n')
                if install_error:
                    raise install_error
                return install_rc
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(apt,'operation_directory',return_value=receipts))
                stack.enter_context(patch.object(apt,'environment',return_value=('noble',100,65534)))
                stack.enter_context(patch.object(apt,'missing_packages',side_effect=[['suricata'], ['suricata'] if post_missing else []]))
                stack.enter_context(patch.object(apt,'make_scope',return_value=workspace))
                stack.enter_context(patch.object(apt,'sandbox_access'))
                stack.enter_context(patch.object(apt,'resolve_packages',return_value=(['suricata'], {'fallback_used': False})))
                stack.enter_context(patch.object(apt,'KEYRING',keyring))
                update_call=stack.enter_context(patch.object(apt.subprocess,'run',side_effect=update))
                install_call=stack.enter_context(patch.object(apt.ledger,'execute',side_effect=install))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                yield workspace, receipts, update_call, install_call

    def test_update_and_install_share_private_scope_and_ledger(self):
        with self.scenario() as (root, receipts, update, install):
            self.assertEqual(apt.install(['suricata'], '/fixture'),0)
            options=apt.apt_options(root)
            self.assertEqual(update.call_args.args[0], ['apt-get',*options,'update'])
            self.assertEqual(install.call_args.args[0], ['apt-get',*options,'-y','--no-remove','--no-upgrade','install','suricata'])
            self.assertEqual(install.call_args.kwargs['timeout'],600)
            record=json.loads(next(receipts.glob('*.json')).read_text())
            self.assertTrue(record['completed'])
            self.assertEqual(record['returncode'],0)
            self.assertEqual(set(record['logs']),{'update.log','install.log'})
            self.assertFalse(root.exists())

    def test_any_official_update_error_prevents_install(self):
        for reason in ['bad signature','expired Release','TLS verification failed','offline']:
            with self.subTest(reason=reason), self.scenario(update_rc=100, update_text=reason) as (root, receipts, update, install):
                with self.assertRaises(RuntimeError):apt.install(['suricata'],'/fixture')
                install.assert_not_called()
                record=json.loads(next(receipts.glob('*.json')).read_text())
                self.assertFalse(record['completed'])
                self.assertEqual(record['phase'],'failed')
                self.assertIn('update.log',record['logs'])

    def test_sandbox_fallback_prevents_install(self):
        with self.scenario(update_text='W: Download is performed unsandboxed as root') as (_,_,_,install):
            with self.assertRaises(RuntimeError):apt.install(['suricata'],'/fixture')
            install.assert_not_called()

    def test_install_failure_retains_ledger_returncode(self):
        with self.scenario(install_rc=100) as (_, receipts, _, _):
            self.assertEqual(apt.install(['suricata'],'/fixture'),100)
            record=json.loads(next(receipts.glob('*.json')).read_text())
            self.assertTrue(record['completed'])
            self.assertEqual(record['returncode'],100)

    def test_install_timeout_retains_workspace_and_does_not_claim_completion(self):
        with self.scenario(install_error=subprocess.TimeoutExpired('apt-get',600)) as (root,receipts,_,_):
            with self.assertRaises(subprocess.TimeoutExpired):apt.install(['suricata'],'/fixture')
            record=json.loads(next(receipts.glob('*.json')).read_text())
            self.assertFalse(record['completed'])
            self.assertEqual(record['phase'],'timeout')
            self.assertTrue(record['workspace_retained'])
            self.assertTrue(root.exists())
            self.assertTrue(Path(record['logs']['install.log']['path']).is_file())

    def test_update_timeout_never_starts_install_and_retains_partial_log(self):
        with self.scenario(update_error=subprocess.TimeoutExpired('apt-get',300)) as (root,receipts,_,install):
            with self.assertRaises(subprocess.TimeoutExpired):apt.install(['suricata'],'/fixture')
            install.assert_not_called()
            record=json.loads(next(receipts.glob('*.json')).read_text())
            self.assertFalse(record['completed'])
            self.assertEqual(record['phase'],'timeout')
            self.assertTrue(root.exists())
            self.assertTrue(Path(record['logs']['update.log']['path']).is_file())

    def test_success_returncode_without_installed_dependency_is_refused(self):
        with self.scenario(post_missing=True) as (_,receipts,_,_):
            with self.assertRaises(RuntimeError):apt.install(['suricata'],'/fixture')
            record=json.loads(next(receipts.glob('*.json')).read_text())
            self.assertFalse(record['completed'])
            self.assertEqual(record['phase'],'failed')

    def test_existing_packages_need_no_apt_or_keyring_bootstrap(self):
        with patch.object(apt,'missing_packages',return_value=[]), patch.object(apt,'environment') as env, patch.object(apt,'operation_directory') as directory:
            self.assertEqual(apt.install(['existing'],''),0)
            env.assert_not_called(); directory.assert_not_called()

    @unittest.skipUnless(os.geteuid()==0 and Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg').is_file(), 'requires local Ubuntu root sandbox identity')
    def test_actual_apt_uid_traverses_scope_with_restrictive_installer_umask(self):
        account=pwd.getpwnam('_apt'); old=os.umask(0o077)
        try:root=apt.make_scope('noble',account.pw_uid,account.pw_gid)
        finally:os.umask(old)
        try:
            for name in ['','lists','cache','cache/archives']:
                self.assertEqual((root/name).stat().st_mode & 0o777,0o755)
            apt.sandbox_access(root,account.pw_uid,account.pw_gid)
            self.assertEqual((root/'lists/partial').stat().st_uid,account.pw_uid)
            self.assertEqual((root/'cache/archives/partial').stat().st_mode & 0o777,0o700)
        finally:shutil.rmtree(root)

    def test_shell_timeout_marker_and_no_global_update(self):
        text=Path(__file__).with_name('safe-overrides.sh').read_text()
        wrapper=text.split('apt_install(){',1)[1].split('\n}',1)[0]
        self.assertIn('ubuntu_apt.py',wrapper)
        self.assertIn('"${DS_TXN:-}"',wrapper)
        self.assertIn('"$rc" = 124',wrapper)
        self.assertIn('"$DS_TXN/package-timeout"',wrapper)
        self.assertNotIn('apt-get',wrapper)


class CompatibleDependencies(unittest.TestCase):
    BEFORE = {'fixture-core': [{'architecture': 'amd64', 'version': '1.0',
                               'source': 'fixture-source', 'source_version': '1.0'}]}
    INITIAL = {
        'fixture-core': {'name': 'fixture-core', 'version': '2.0', 'prior': '1.0'},
        'fixture-lib': {'name': 'fixture-lib', 'version': '2.0', 'prior': None},
        'fixture-app': {'name': 'fixture-app', 'version': '1.0', 'prior': None},
    }
    FINAL = {
        'fixture-lib': {'name': 'fixture-lib', 'version': '1.0', 'prior': None},
        'fixture-app': {'name': 'fixture-app', 'version': '1.0', 'prior': None},
    }
    RECORDS = (
        'Package: fixture-app\nVersion: 1.0\nArchitecture: amd64\n\n'
        'Package: fixture-lib\nVersion: 2.0\nArchitecture: amd64\nSource: fixture-source (2.0)\n\n'
        'Package: fixture-lib\nVersion: 1.0\nArchitecture: amd64\nSource: fixture-source (1.0)\n\n')
    POLICY = 'fixture-lib:\n  Installed: (none)\n  Candidate: 2.0\n  Version table:\n     2.0 500\n        500 https://example.invalid noble/main amd64 Packages\n     1.0 500\n        500 https://example.invalid noble/main amd64 Packages\n'

    @contextlib.contextmanager
    def fixture(self, before=None, after=None, initial=None, final=None, records=None, policy=None):
        before = self.BEFORE if before is None else before
        after = before if after is None else after
        with patch.object(apt, 'installed_packages', side_effect=[before, after]), \
                patch.object(apt, 'simulation', side_effect=[
                    self.INITIAL if initial is None else initial,
                    self.FINAL if final is None else final]) as simulate, \
                patch.object(apt, 'checked', side_effect=[
                    self.RECORDS if records is None else records,
                    self.POLICY if policy is None else policy]) as query:
            yield simulate, query

    def test_one_fallback_only_new_same_source_versions_no_installed_arguments(self):
        with self.fixture() as (simulate, query):
            arguments, proof = apt.resolve_packages(Path('/scope'), ['-o', 'fixture=value'], ['fixture-app'])
            self.assertEqual(arguments, ['fixture-app', 'fixture-lib=1.0'])
            self.assertTrue(proof['fallback_used'])
            self.assertEqual(proof['passes'], 2)
            self.assertEqual(simulate.call_count, 2)
            self.assertEqual(simulate.call_args.args[2], arguments)
            self.assertEqual(query.call_args.args[0], ['apt-cache', '-o', 'fixture=value', 'policy', 'fixture-lib'])
            self.assertNotIn('fixture-core', ' '.join(arguments))

    def test_no_changes_needs_no_fallback_or_metadata_queries(self):
        with self.fixture(initial=self.FINAL) as (simulate, query):
            arguments, proof = apt.resolve_packages(Path('/scope'), [], ['fixture-app'])
            self.assertEqual(arguments, ['fixture-app'])
            self.assertFalse(proof['fallback_used'])
            self.assertEqual(simulate.call_count, 1)
            query.assert_not_called()

    def test_priority_prohibition_or_stronger_host_pin_refuses(self):
        for policy in [self.POLICY.replace('1.0 500', '1.0 -1'),
                       self.POLICY.replace('1.0 500', '1.0 0'),
                       self.POLICY.replace('2.0 500', '2.0 1001')]:
            with self.subTest(policy=policy), self.fixture(policy=policy) as (simulate, _):
                with self.assertRaisesRegex(RuntimeError, 'Политика APT'):
                    apt.resolve_packages(Path('/scope'), [], ['fixture-app'])
                self.assertEqual(simulate.call_count, 1)

    def test_source_version_unavailable_refuses_without_second_solver(self):
        records = self.RECORDS.split('Package: fixture-lib\nVersion: 1.0', 1)[0]
        with self.fixture(records=records) as (simulate, _):
            with self.assertRaisesRegex(RuntimeError, 'недоступна'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-app'])
            self.assertEqual(simulate.call_count, 1)

    def test_different_installed_sibling_source_versions_refuse(self):
        before = {**self.BEFORE, 'fixture-other': [
            {'architecture': 'amd64', 'version': '1.5',
             'source': 'fixture-source', 'source_version': '1.5'}]}
        with self.fixture(before=before):
            with self.assertRaisesRegex(RuntimeError, 'Неоднозначная исходная версия'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-app'])

    def test_unknown_installed_change_or_foreign_architecture_refuses(self):
        for before in [{}, {'fixture-core': [{**self.BEFORE['fixture-core'][0], 'architecture': 'i386'}]}]:
            with self.subTest(before=before), self.fixture(before=before):
                with self.assertRaisesRegex(RuntimeError, 'Неоднозначный прежний пакет'):
                    apt.resolve_packages(Path('/scope'), [], ['fixture-app'])

    def test_explicit_requested_version_is_not_silently_replaced(self):
        with self.fixture():
            with self.assertRaisesRegex(RuntimeError, 'Запрошенная версия'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-lib=2.0'])

    def test_matching_explicit_request_and_architecture_preserved(self):
        with self.fixture():
            arguments, _ = apt.resolve_packages(Path('/scope'), [], ['fixture-lib:amd64=1.0'])
            self.assertEqual(arguments, ['fixture-lib:amd64=1.0'])

    def test_failed_final_plan_never_repeats_or_relaxes_gate(self):
        with self.fixture(final=self.INITIAL) as (simulate, _):
            with self.assertRaisesRegex(RuntimeError, 'всё ещё меняет'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-app'])
            self.assertEqual(simulate.call_count, 2)

    def test_concurrent_package_state_change_refuses(self):
        with self.fixture(after={}):
            with self.assertRaisesRegex(RuntimeError, 'состояние изменилось'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-app'])

    def test_duplicate_metadata_from_two_pockets_is_not_ambiguous(self):
        with self.fixture(records=self.RECORDS + self.RECORDS):
            arguments, _ = apt.resolve_packages(Path('/scope'), [], ['fixture-app'])
            self.assertEqual(arguments, ['fixture-app', 'fixture-lib=1.0'])

    def test_ambiguous_same_source_binary_versions_refuse(self):
        extra = 'Package: fixture-lib\nVersion: 1.0+b1\nArchitecture: amd64\nSource: fixture-source (1.0)\n\n'
        with self.fixture(records=self.RECORDS + extra):
            with self.assertRaisesRegex(RuntimeError, 'неоднозначна'):
                apt.resolve_packages(Path('/scope'), [], ['fixture-app'])

    def test_simulation_removal_unknown_format_or_nonzero_refuses(self):
        for text, rc in [('Remv fixture-core [1.0]\n', 0),
                         ('Inst fixture-core malformed\n', 0),
                         ('broken dependencies\n', 100)]:
            with self.subTest(text=text), tempfile.TemporaryDirectory() as temporary:
                def command(args, **kwargs):
                    kwargs['stdout'].write(text)
                    self.assertIn('--simulate', args)
                    self.assertIn('--no-remove', args)
                    return subprocess.CompletedProcess(args, rc)
                with patch.object(apt.subprocess, 'run', side_effect=command):
                    with self.assertRaises(RuntimeError):
                        apt.simulation(Path(temporary), [], ['fixture-app'], 'test')
                self.assertEqual((Path(temporary)/'resolve-test.log').read_text(), text)

    def test_realistic_simulation_and_policy_output_parsed(self):
        text = ('Inst libevent-core-2.1-7t64 [2.1.12-stable-9ubuntu2] '
                '(2.1.12-stable-9ubuntu2.2 Ubuntu:24.04/noble-updates [amd64])\n'
                'Inst suricata (1:7.0.3-1build3 Ubuntu:24.04/noble [amd64])\n')
        with tempfile.TemporaryDirectory() as temporary:
            def command(args, **kwargs):
                kwargs['stdout'].write(text)
                return subprocess.CompletedProcess(args, 0)
            with patch.object(apt.subprocess, 'run', side_effect=command):
                plan = apt.simulation(Path(temporary), [], ['suricata'], 'test')
        self.assertEqual(plan['libevent-core-2.1-7t64']['prior'], '2.1.12-stable-9ubuntu2')
        self.assertIsNone(plan['suricata']['prior'])
        policy = 'suricata:\n  Installed: 1:7.0.3-1build3\n  Candidate: 1:7.0.3-1build3\n  Version table:\n *** 1:7.0.3-1build3 500\n        500 https://archive.ubuntu.com/ubuntu noble/universe amd64 Packages\n        100 /var/lib/dpkg/status\n'
        self.assertEqual(apt.policy_priorities(policy), {'suricata': {'1:7.0.3-1build3': 500}})

    def test_resolver_failure_or_timeout_never_starts_ledger(self):
        for error in [RuntimeError('incompatible'), subprocess.TimeoutExpired('apt-get', 120)]:
            with self.subTest(error=type(error).__name__), UbuntuApt().scenario() as (root, receipts, _, install):
                with patch.object(apt, 'resolve_packages', side_effect=error):
                    with self.assertRaises(type(error)):
                        apt.install(['suricata'], '/fixture')
                install.assert_not_called()
                receipt = json.loads(next(receipts.glob('*.json')).read_text())
                self.assertFalse(receipt['completed'])
                self.assertEqual(receipt['phase'], 'timeout' if isinstance(error, subprocess.TimeoutExpired) else 'failed')


if __name__ == '__main__':unittest.main()
