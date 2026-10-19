import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import package_install_gate as gate


class PackageInstallGateTests(unittest.TestCase):
    def test_new_package_passes(self):
        with patch.object(gate, 'archive_identity', return_value=('new-package', 'amd64', '2.0')), \
                patch.object(gate, 'installed_identity', return_value=None):
            self.assertEqual(gate.check_archives(['/cache/new.deb']), ['new-package:amd64'])

    def test_dependency_upgrade_refused(self):
        with patch.object(gate, 'archive_identity', return_value=('existing-library', 'amd64', '2.0')), \
                patch.object(gate, 'installed_identity', return_value='1.0'):
            with self.assertRaisesRegex(RuntimeError, 'ранее установленный пакет'):
                gate.check_archives(['/cache/dependency.deb'])

    def test_dependency_downgrade_refused(self):
        with patch.object(gate, 'archive_identity', return_value=('existing-library', 'amd64', '1.0')), \
                patch.object(gate, 'installed_identity', return_value='2.0'):
            with self.assertRaises(RuntimeError):
                gate.check_archives(['/cache/dependency.deb'])

    def test_existing_same_version_reinstall_refused(self):
        with patch.object(gate, 'archive_identity', return_value=('existing-library', 'amd64', '1.0')), \
                patch.object(gate, 'installed_identity', return_value='1.0'):
            with self.assertRaises(RuntimeError):
                gate.check_archives(['/cache/dependency.deb'])

    def test_existing_other_architecture_cannot_be_replaced(self):
        completed = subprocess.CompletedProcess([], 0, 'installed\t1.0\n', '')
        with patch.object(gate.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(gate.installed_identity('same-name', 'amd64'), '1.0')
            self.assertEqual(run.call_args.args[0][-1], 'same-name')

    def test_partial_package_state_refused(self):
        completed = subprocess.CompletedProcess([], 0, 'unpacked\t1.0\n', '')
        with patch.object(gate.subprocess, 'run', return_value=completed):
            with self.assertRaisesRegex(RuntimeError, 'незавершённом'):
                gate.installed_identity('some-package', 'amd64')

    def test_query_error_is_not_absence(self):
        completed = subprocess.CompletedProcess([], 2, '', 'database unavailable')
        with patch.object(gate.subprocess, 'run', return_value=completed):
            with self.assertRaises(RuntimeError):
                gate.installed_identity('some-package', 'amd64')

    def test_multiple_archive_versions_refused(self):
        with patch.object(gate, 'archive_identity', side_effect=[('new-package', 'all', '1'), ('new-package', 'all', '2')]), \
                patch.object(gate, 'installed_identity', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Две версии'):
                gate.check_archives(['/cache/one.deb', '/cache/two.deb'])

    def test_protocol_one_paths_preserve_spaces(self):
        self.assertEqual(gate.hook_paths(io.StringIO('/cache/a b.deb\n\n/cache/c.deb\n')),
                         ['/cache/a b.deb', '/cache/c.deb'])

    def test_protocol_version_mismatch_refused(self):
        with self.assertRaises(RuntimeError):
            gate.hook_paths(io.StringIO('VERSION 2\n'))

    def test_options_are_invocation_only_and_quote_path(self):
        options = gate.apt_gate_options('/tmp/path with spaces/gate.py')
        self.assertEqual(options[::2], ['-o', '-o', '-o'])
        self.assertIn("'/tmp/path with spaces/gate.py'", options[1])
        self.assertTrue(options[3].endswith('::Version=1'))
        self.assertTrue(options[5].endswith('::InfoFD=0'))


if __name__ == '__main__':
    unittest.main()
