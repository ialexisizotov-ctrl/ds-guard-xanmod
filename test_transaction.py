import unittest,tempfile
from pathlib import Path
from unittest.mock import patch
import transaction
from transaction import foreign_rules,managed_hook,validate_managed_scope

class Ownership(unittest.TestCase):
    def test_exact_forms_only(self):
        self.assertTrue(managed_hook('-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP'))
        self.assertFalse(managed_hook('-A INPUT -o eth0 -m ndpi --proto bittorrent -j DROP'))
        self.assertFalse(managed_hook('-A OUTPUT -o eth0 -m ndpi --proto skype -j DROP'))
        self.assertFalse(managed_hook('-A OUTPUT -o eth0 -p udp -j NFQUEUE --queue-num 7'))
    def test_foreign_order_and_drop_policy_preserved(self):
        base='*filter\n:INPUT DROP [1:2]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\n'
        after=base+'-A OUTPUT -o eth0 -j DS_DOMAINS\n:DS_DOMAINS - [0:0]\n-A DS_DOMAINS -j DS_DOM_A\n'
        self.assertEqual(foreign_rules(base),foreign_rules(after))
        self.assertNotEqual(foreign_rules(base),foreign_rules(after.replace(':INPUT DROP',':INPUT ACCEPT')))
        self.assertNotEqual(foreign_rules(base),foreign_rules(after.replace('--dport 22','--dport 23')))
    def test_empty_accept_table_is_inert(self):
        self.assertEqual(foreign_rules(''),foreign_rules('*filter\n:OUTPUT ACCEPT [0:0]\n'))
    def test_foreign_chain_ownership_is_not_adopted(self):
        for text in ['*mangle\n:DS_DOM_A - [0:0]\n','*filter\n-A INPUT -j DS_DOMAINS\n','*raw\n-A OUTPUT -o eth0 -j DS_DOMAINS\n']:
            with self.assertRaises(RuntimeError):validate_managed_scope(text)
        validate_managed_scope('*filter\n:DS_DOM_A - [0:0]\n-A OUTPUT -o eth0 -j DS_DOMAINS\n-A DS_DOMAINS -j DS_DOM_A\n')
    def test_quarantine_is_back_before_daemon_reload_and_rule_restore(self):
        body='[Unit]\nConditionPathExists=!/root/codex-dsguard-20261019/ndpi-memory-safety-hold\n'
        names=['/etc/systemd/system/'+u+'.d/90-codex-ndpi-memory-hold.conf' for u in ['ds-guard.service','ds-guard-apply.service']]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'system';txn=Path(d)/'transaction'
            for name in names:
                backup=txn/'files'/name.lstrip('/');backup.parent.mkdir(parents=True,exist_ok=True);backup.write_text(body);backup.chmod(0o644)
            def reload(args):
                self.assertEqual(args,['systemctl','daemon-reload'])
                for name in names:self.assertEqual((root/name.lstrip('/')).read_text(),body)
            with patch.object(transaction,'run',side_effect=reload) as run:
                transaction.restore_quarantine_first(txn,{'files':dict.fromkeys(names)},root=root)
                run.assert_called_once()
    def test_hook_removal_uses_verified_positions_and_preserves_foreign_order(self):
        foreign='-A OUTPUT -p tcp --dport 22 -j ACCEPT'
        rules=[foreign,'-A OUTPUT -o eth0 -j DS_DOMAINS','-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP']
        removed=[]
        def execute(args):
            if args==['iptables-save']:return '*filter\n'+ '\n'.join(rules)+'\nCOMMIT\n'
            if args==['iptables','-w','5','-S','OUTPUT']:return '\n'.join(rules)
            self.assertEqual(args[:5],['iptables','-w','5','-D','OUTPUT'])
            self.assertTrue(args[5].isdigit());removed.append(int(args[5]));rules.pop(int(args[5])-1);return ''
        transaction.detach_managed_hooks(execute)
        self.assertEqual(rules,[foreign]);self.assertEqual(removed,[3,2])
    def test_hook_position_drift_refuses_before_deletion(self):
        hook='-A OUTPUT -o eth0 -j DS_DOMAINS'
        calls=[]
        def execute(args):
            calls.append(args)
            if args==['iptables-save']:return '*filter\n'+hook+'\nCOMMIT\n'
            return '-A OUTPUT -p tcp --dport 22 -j ACCEPT\n'+hook
        with self.assertRaisesRegex(RuntimeError,'изменились'):transaction.detach_managed_hooks(execute)
        self.assertFalse(any('-D' in call for call in calls))

if __name__=='__main__':unittest.main()
