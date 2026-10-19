"""Read-only APT commands cannot regenerate the shared cache; no real APT runs."""
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import lifecycle


CACHE_OPTIONS = ['-o', 'Dir::Cache::pkgcache=', '-o', 'Dir::Cache::srcpkgcache=']
RENAME_ERROR = ('E: Problem renaming the file /var/cache/apt/pkgcache.bin.GLHj5Z '
                'to /var/cache/apt/pkgcache.bin - rename (2: No such file or directory)\n'
                'E: The package cache file is corrupted\n')


class ReadOnlyAptTests(unittest.TestCase):
    def test_snapshot_avoids_the_observed_shared_cache_rename_failure(self):
        calls = []

        def apt(argv, **kwargs):
            calls.append(argv)
            if argv[0] == 'apt-mark':
                if argv[1:5] != CACHE_OPTIONS:
                    return subprocess.CompletedProcess(argv, 100, '', RENAME_ERROR)
                self.assertEqual(argv[5:], ['showmanual'])
                return subprocess.CompletedProcess(argv, 0, 'original\nadmin-package\n', '')
            self.assertEqual(argv, ['iptables-save'])
            return subprocess.CompletedProcess(argv, 0, '*filter\nCOMMIT\n', '')

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(lifecycle, 'STATE', Path(directory)), \
                patch.object(lifecycle, 'packages', return_value={'original': '1'}), \
                patch.object(lifecycle, 'package_ownership', return_value={}), \
                patch.object(lifecycle, 'paths', return_value=[]), \
                patch.object(lifecycle, 'units', return_value={}), \
                patch.object(lifecycle, 'values', return_value={}), \
                patch.object(Path, 'exists', return_value=False), \
                patch.object(Path, 'is_file', return_value=False), \
                patch.object(lifecycle.subprocess, 'run', side_effect=apt):
            result = lifecycle.snapshot()
        self.assertEqual(result['manual'], ['original', 'admin-package'])
        self.assertEqual(len(calls), 2)

    def test_readonly_marks_and_simulation_aliases_disable_both_disk_caches(self):
        commands = [['apt-mark', action] for action in (
            'showmanual', 'showauto', 'showhold', 'showinstall', 'showremove', 'showpurge')]
        commands += [['apt-get', alias, 'purge', 'own-package'] for alias in (
            '-s', '--simulate', '--just-print', '--dry-run', '--recon', '--no-act')]
        for original in commands:
            with self.subTest(command=original), patch.object(
                    lifecycle.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(original, 0, 'result\n', '')) as run:
                argument = list(original)
                self.assertEqual(lifecycle.run(argument), 'result')
                self.assertEqual(argument, original)
                self.assertEqual(run.call_args.args[0], [original[0], *CACHE_OPTIONS, *original[1:]])

    def test_readonly_error_is_not_retried_or_suppressed(self):
        with patch.object(lifecycle.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 100, '', RENAME_ERROR)) as run:
            with self.assertRaisesRegex(RuntimeError, 'Problem renaming'):
                lifecycle.run(['apt-mark', 'showmanual'])
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][1:5], CACHE_OPTIONS)

    def test_real_mutations_and_dpkg_queries_are_unchanged(self):
        commands = [
            ['apt-mark', 'manual', 'existing'], ['apt-mark', 'auto', 'existing'],
            ['apt-mark', 'hold', 'existing'], ['apt-mark', 'unhold', 'existing'],
            ['apt-get', '-y', 'install', 'own-package'],
            ['apt-get', '-y', '-o', 'APT::Get::AutomaticRemove=false', 'purge', 'own-package'],
            ['dpkg', '-i', '/tmp/own-package.deb'], ['dpkg-query', '-W'],
        ]
        for original in commands:
            with self.subTest(command=original), patch.object(
                    lifecycle.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(original, 0, '', '')) as run:
                lifecycle.run(original)
                self.assertEqual(run.call_args.args[0], original)


if __name__ == '__main__':
    unittest.main()
