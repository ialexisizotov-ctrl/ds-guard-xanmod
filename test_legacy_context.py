import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import legacy_context
import preflight
import lifecycle
import json

class LegacyEntryGate(unittest.TestCase):
    def test_normal_install_keeps_the_strict_preflight(self):
        with patch.object(legacy_context,'context',return_value=None), patch.object(preflight,'collect',return_value={'compatible':True}) as collect:
            result=legacy_context.preflight(Path('/candidate'))
        collect.assert_called_once_with(stage_only=False)
        self.assertIsNone(result['legacy_upgrade'])

    def test_verified_old_loaded_module_is_disk_staging_only(self):
        state={'requires_reboot':True,'loaded_candidate':False}
        with patch.object(legacy_context,'context',return_value=state),patch.object(preflight,'collect',return_value={'compatible':True}) as collect:
            result=legacy_context.preflight(Path('/candidate'))
        collect.assert_called_once_with(stage_only=True)
        self.assertEqual(result['legacy_upgrade'],state)

    def test_new_loaded_module_never_gets_kernel_fault_exception(self):
        with patch.object(legacy_context,'context',return_value={'requires_reboot':False}),patch.object(preflight,'collect',return_value={'compatible':False}) as collect:
            self.assertFalse(legacy_context.preflight(Path('/candidate'))['compatible'])
        collect.assert_called_once_with(stage_only=False)

    def test_failed_legacy_validation_cannot_become_normal_install(self):
        with patch.object(legacy_context,'context',side_effect=RuntimeError('hold changed')),patch.object(preflight,'collect') as collect:
            with self.assertRaisesRegex(RuntimeError,'hold changed'):legacy_context.preflight(Path('/candidate'))
        collect.assert_not_called()

    def test_direct_legacy_worker_without_setup_journal_is_refused(self):
        with tempfile.TemporaryDirectory() as d,patch.object(legacy_context,'STATE',Path(d)),patch.object(legacy_context,'context',return_value={'requires_reboot':True}),patch.object(preflight,'collect') as collect:
            with self.assertRaisesRegex(RuntimeError,'setup.sh'):legacy_context.preflight(Path('/candidate'),require_journal=True)
        collect.assert_not_called()

    def test_cold_resume_accepts_only_disappeared_legacy_rules(self):
        rule='-A OUTPUT -o eth0 -j DS_DOMAINS'
        wrap=lambda rules:'*filter\n:OUTPUT ACCEPT [0:0]\n:DS_DOMAINS - [0:0]\n'+rules+'\nCOMMIT'
        b={'files':{},'values':{},'packages':{},'iptables':wrap(rule),'baseline_kind':'legacy-upgrade'}
        a=dict(b);current={**a,'iptables':wrap('')}
        with self.assertRaises(RuntimeError):lifecycle.verify_no_conflict(b,a,current)
        lifecycle.verify_no_conflict(b,a,current,legacy_cold_boot=True)
        for rules in [rule+'\n'+rule,'-A OUTPUT -o eth1 -j DS_DOMAINS','-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP']:
            with self.assertRaises(RuntimeError):lifecycle.verify_no_conflict(b,a,{**current,'iptables':wrap(rules)},legacy_cold_boot=True)
        with self.assertRaises(RuntimeError):lifecycle.verify_no_conflict({**b,'baseline_kind':'fresh'},a,current,legacy_cold_boot=True)

    def test_partial_rollback_blocks_new_update_before_snapshot(self):
        with tempfile.TemporaryDirectory() as d,patch.object(lifecycle,'STATE',Path(d)),patch.object(lifecycle,'snapshot') as snapshot:
            (Path(d)/'rollback-upgrade-progress.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError,'Откат обновления не завершён'):lifecycle.begin(legacy_upgrade=True)
        snapshot.assert_not_called()

if __name__=='__main__':unittest.main()
