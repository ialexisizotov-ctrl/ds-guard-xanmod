import copy,json,os,shlex,subprocess,unittest,tempfile
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
            synced=[];fsync=os.fsync
            def sync(fd):
                synced.append(fd);return fsync(fd)
            def reload(args):
                self.assertEqual(args,['systemctl','daemon-reload'])
                for name in names:self.assertEqual((root/name.lstrip('/')).read_text(),body)
                self.assertEqual(len(synced),4)
            with patch.object(transaction,'run',side_effect=reload) as run,patch.object(transaction.os,'fsync',side_effect=sync):
                restored=transaction.restore_quarantine_first(txn,{'files':dict.fromkeys(names)},root=root)
                self.assertEqual(restored,set(names))
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


class RollbackFirewallFailures(unittest.TestCase):
    """Inject real subprocess return codes through transaction.run itself."""
    def setUp(self):
        self.original={'OUTPUT':[['-p','tcp','--dport','22','-j','ACCEPT'],['-o','eth0','-j','DS_DOMAINS']],
                       'DS_DOMAINS':[['-j','DS_DOM_A']],
                       'DS_DOM_A':[['-m','string','--string','baseline','-j','DROP']]}
        self.model=copy.deepcopy(self.original)
        self.model['DS_DOM_A'].append(['-m','ndpi','--proto','bittorrent','-j','DROP'])
        self.before={'files':{},'kernel':'mock-kernel','iptables':self.serialize(self.original),'units':{},'acct':'0'}
        self.commands=[];self.failure=None;self.silent_flush=False

    @staticmethod
    def serialize(model):
        lines=['*filter']
        for chain in model:lines.append(':'+chain+(' ACCEPT' if chain=='OUTPUT' else ' -')+' [0:0]')
        for chain,rules in model.items():lines.extend(shlex.join(['-A',chain,*rule]) for rule in rules)
        return '\n'.join(lines+['COMMIT'])

    def process(self,args,**kwargs):
        self.commands.append(args);out='';rc=0
        if args==['iptables-save']:out=self.serialize(self.model)
        elif args[:3]==['iptables','-w','5']:
            op,chain,*tail=args[3:]
            if self.failure==(op,chain):rc=4
            elif op=='-S':out='\n'.join(shlex.join(['-A',chain,*rule]) for rule in self.model[chain])
            elif op=='-D':self.model[chain].pop(int(tail[0])-1)
            elif op=='-N':
                if chain in self.model:rc=1
                else:self.model[chain]=[]
            elif op=='-F':
                if not (self.silent_flush and chain=='DS_DOM_A'):self.model[chain].clear()
            elif op=='-A':self.model[chain].append(tail)
            elif op=='-I':self.model[chain].insert(int(tail[0])-1,tail[1:])
            elif op=='-X':self.model.pop(chain)
            else:raise AssertionError(args)
        elif args==['sysctl','-n','net.netfilter.nf_conntrack_acct']:out='0'
        elif args[0] not in ('systemctl','sysctl','depmod'):raise AssertionError(args)
        return subprocess.CompletedProcess(args,rc,out,'simulated xtables failure' if rc else '')

    def invoke(self):
        with patch.object(Path,'exists',return_value=False),patch.object(Path,'read_text',return_value=json.dumps(self.before)),\
             patch.object(transaction,'owned_paths',return_value=[]),patch.object(transaction,'restore_quarantine_first'),\
             patch.object(transaction.subprocess,'run',side_effect=self.process),patch.object(transaction,'save') as receipt:
            self.receipt=receipt
            transaction.rollback(Path('/isolated-mock/transaction'))

    def test_failed_flush_does_not_claim_rollback(self):
        self.failure=('-F','DS_DOM_A')
        with self.assertRaisesRegex(RuntimeError,'iptables failed: 4'):self.invoke()
        self.receipt.assert_not_called()
        self.assertFalse(any(args[:4]==['iptables','-w','5','-A'] for args in self.commands))

    def test_failed_missing_chain_creation_does_not_claim_rollback(self):
        self.failure=('-N','DS_DOM_A_D')
        with self.assertRaisesRegex(RuntimeError,'iptables failed: 4'):self.invoke()
        self.receipt.assert_not_called()

    def test_failed_extra_chain_deletion_does_not_claim_rollback(self):
        self.failure=('-X','DS_DOM_A_D')
        with self.assertRaisesRegex(RuntimeError,'iptables failed: 4'):self.invoke()
        self.receipt.assert_not_called()

    def test_successful_command_without_restoration_refuses_before_traffic_reconnect(self):
        self.silent_flush=True
        with self.assertRaisesRegex(RuntimeError,'не совпали с исходным'):self.invoke()
        self.receipt.assert_not_called()
        self.assertIn(['-m','ndpi','--proto','bittorrent','-j','DROP'],self.model['DS_DOM_A'])
        self.assertFalse(any(args[:4]==['iptables','-w','5','-I'] for args in self.commands))
        self.assertFalse(transaction.managed_state(self.serialize(self.model))['hooks'])

    def test_exact_scoped_recovery_preserves_foreign_and_skips_existing_chain_creation(self):
        self.invoke()
        self.assertEqual(transaction.managed_state(self.serialize(self.model)),transaction.managed_state(self.before['iptables']))
        self.assertEqual(transaction.foreign_rules(self.serialize(self.model)),transaction.foreign_rules(self.before['iptables']))
        creates={args[4] for args in self.commands if args[:4]==['iptables','-w','5','-N']}
        self.assertEqual(creates,transaction.CHAINS-set(self.original))
        self.receipt.assert_called_once()

if __name__=='__main__':unittest.main()
