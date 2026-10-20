import copy
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import domain_rotation as dr
import lifecycle as lc


def firewall(bank='A'):
    b='DS_DOM_'+bank
    return '\n'.join(['*filter', ':OUTPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]',
        ':DS_DOMAINS - [0:0]', ':'+b+' - [0:0]', ':'+b+'_D - [0:0]', ':'+b+'_W - [0:0]',
        '-A OUTPUT -o eth0 -j DS_DOMAINS', '-A OUTPUT -d 192.0.2.1/32 -j ACCEPT',
        '-A FORWARD -o eth0 -j DS_DOMAINS', '-A DS_DOMAINS -j '+b,
        '-A '+b+' -p udp --dport 53 -j '+b+'_D', '-A '+b+' -p tcp --dport 443 -j '+b+'_W',
        '-A '+b+'_D -m string --string example.test --algo kmp -j DROP',
        '-A '+b+'_W -m connbytes --connbytes 33: --connbytes-mode packets --connbytes-dir original -j RETURN',
        '-A '+b+'_W -m ndpi --proto all --host example.test -j DROP', 'COMMIT'])


def record(bank='A'):
    text='ACTIVE=DS_DOM_'+bank+'\nDNS_RULES=1\nHOST_RULES=1\nPOLICY_SHA='+'a'*64+'\n'
    files={p:{'sha256':hashlib.sha256(p.encode()).hexdigest(),'mode':0o644} for p in dr.INPUTS}
    files[dr.GENERATION]={'sha256':hashlib.sha256(text.encode()).hexdigest(),'mode':0o600}
    return {'files':files,'file_owners':{p:[0,0] for p in files},'generation_text':text,
            'iptables':firewall(bank),'values':{},'packages':{},'baseline_kind':'legacy-upgrade',
            'ownership_schema':1,'owned_packages':{}}


class RotationProof(unittest.TestCase):
    def test_exact_bank_swap_and_old_record_without_generation_text(self):
        a=record();now=record('B');a.pop('generation_text')
        self.assertTrue(dr.prove_bank_rotation(a,now))
        self.assertTrue(dr.prove_bank_rotation(a,dr.proof_material(now)))
        self.assertFalse(dr.prove_bank_rotation(now,now))

    def test_repeat_allows_only_generation_outside_delta_without_rebasing(self):
        b=record();a=copy.deepcopy(b);now=record('B')
        saved=copy.deepcopy([b,a,now]);lc.verify_repeat_baseline(b,a,now)
        self.assertEqual([b,a,now],saved)
        now['files']['/etc/ds-guard/admin.txt']={'sha256':'b'*64,'mode':0o644}
        with self.assertRaises(RuntimeError):lc.verify_repeat_baseline(b,a,now)

    def test_fresh_owned_generation_change_accepted_only_with_proof(self):
        b=record();a=record();b['files'][dr.GENERATION]=None;b['file_owners'].pop(dr.GENERATION)
        lc.verify_no_conflict(b,a,record('B'))
        now=record('B');now['generation_text']+='BAD=1\n'
        with self.assertRaises(RuntimeError):lc.verify_no_conflict(b,a,now)

    def test_generation_text_stamp_owner_mode_and_four_fields_are_strict(self):
        for kind in ('hash','owner','mode','extra','duplicate','count','policy','active','missing'):
            with self.subTest(kind=kind):
                now=record('B')
                if kind=='hash':now['files'][dr.GENERATION]['sha256']='f'*64
                elif kind=='owner':now['file_owners'][dr.GENERATION]=[1,0]
                elif kind=='mode':now['files'][dr.GENERATION]['mode']=0o644
                elif kind=='missing':now.pop('generation_text')
                else:
                    replacements={'extra':now['generation_text']+'X=1\n',
                        'duplicate':now['generation_text']+'ACTIVE=DS_DOM_B\n',
                        'count':now['generation_text'].replace('DNS_RULES=1','DNS_RULES=2'),
                        'policy':now['generation_text'].replace('a'*64,'b'*64),
                        'active':now['generation_text'].replace('ACTIVE=DS_DOM_B','ACTIVE=DS_DOM_A')}
                    now['generation_text']=replacements[kind]
                    now['files'][dr.GENERATION]['sha256']=hashlib.sha256(now['generation_text'].encode()).hexdigest()
                self.assertFalse(dr.prove_bank_rotation(record(),now))

    def test_each_critical_input_hash_mode_owner_is_immutable(self):
        for name in dr.INPUTS:
            for field in ('hash','mode','owner'):
                with self.subTest(name=name,field=field):
                    now=record('B')
                    if field=='hash':now['files'][name]['sha256']='f'*64
                    elif field=='mode':now['files'][name]['mode']=0o600
                    else:now['file_owners'][name]=[1,0]
                    self.assertFalse(dr.prove_bank_rotation(record(),now))

    def test_dns_rule_target_order_hooks_policies_and_other_bank_are_not_whitelisted(self):
        variants=[lambda t:t.replace('example.test','changed.test'),
            lambda t:t.replace('-j DROP','-j ACCEPT'),
            lambda t:t.replace('-A OUTPUT -o eth0 -j DS_DOMAINS\n-A OUTPUT -d 192.0.2.1/32 -j ACCEPT',
                               '-A OUTPUT -d 192.0.2.1/32 -j ACCEPT\n-A OUTPUT -o eth0 -j DS_DOMAINS'),
            lambda t:t.replace(':DS_DOM_B -',':DS_DOM_B ACCEPT'),
            lambda t:t.replace('COMMIT',':DS_DOM_A - [0:0]\nCOMMIT'),
            lambda t:t.replace('-A DS_DOMAINS -j DS_DOM_B','-A DS_DOMAINS -j DS_DOM_B\n-A DS_DOMAINS -j DS_DOM_B'),
            lambda t:t.replace('192.0.2.1','192.0.2.2')]
        for change in variants:
            with self.subTest(change=change):
                now=record('B');now['iptables']=change(now['iptables'])
                self.assertFalse(dr.prove_bank_rotation(record(),now))
        now=record('B');lines=now['iptables'].splitlines();i=next(i for i,v in enumerate(lines) if v.startswith('-A DS_DOM_B_W '));lines[i],lines[i+1]=lines[i+1],lines[i];now['iptables']='\n'.join(lines)
        self.assertFalse(dr.prove_bank_rotation(record(),now))

    def test_only_target_tokens_are_normalized(self):
        a=record();now=record('B')
        a['iptables']=a['iptables'].replace('--host example.test','--host DS_DOM_A')
        now['iptables']=now['iptables'].replace('--host example.test','--host DS_DOM_B')
        self.assertFalse(dr.prove_bank_rotation(a,now))

    def test_global_chain_output_order_is_inert_but_tables_are_checked(self):
        a=record();now=copy.deepcopy(a);lines=now['iptables'].splitlines()
        headers=[l for l in lines if l.startswith(':')];body=[l for l in lines if l.startswith('-A ')]
        now['iptables']='\n'.join(['*filter',*reversed(headers),*sorted(body,key=lambda l:l.split()[1],reverse=True),'COMMIT'])
        lc.verify_no_conflict(a,a,now)
        now['iptables']=now['iptables'].replace('*filter','*nat')
        with self.assertRaises(RuntimeError):lc.verify_no_conflict(a,a,now)

    def test_reference_or_actual_dual_bank_and_foreign_reference_are_rejected(self):
        for where in ('reference','actual'):
            a=record();now=record('B');target=a if where=='reference' else now
            target['iptables']=target['iptables'].replace('COMMIT',':DS_DOM_'+('B' if where=='reference' else 'A')+' - [0:0]\nCOMMIT')
            self.assertFalse(dr.prove_bank_rotation(a,now))
        now=record('B');now['iptables']=now['iptables'].replace('COMMIT','-A OUTPUT -j DS_DOM_B\nCOMMIT')
        with self.assertRaises(RuntimeError):dr.prove_bank_rotation(record(),now)


class ColdSubset(unittest.TestCase):
    def test_empty_owned_state_with_exact_foreign_is_allowed_only_for_explicit_legacy(self):
        a=record();now=copy.deepcopy(a)
        now['iptables']='*filter\n:OUTPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n-A OUTPUT -d 192.0.2.1/32 -j ACCEPT\nCOMMIT'
        lc.verify_no_conflict(a,a,now,legacy_cold_boot=True)
        with self.assertRaises(RuntimeError):lc.verify_no_conflict(a,a,now)
        with self.assertRaises(RuntimeError):lc.verify_no_conflict({**a,'baseline_kind':'fresh'},a,now,legacy_cold_boot=True)
        now['iptables']=now['iptables'].replace('192.0.2.1','192.0.2.2')
        with self.assertRaises(RuntimeError):lc.verify_no_conflict(a,a,now,legacy_cold_boot=True)

    def test_removed_hook_positions_account_only_for_removed_owned_hooks(self):
        expected='*filter\n:OUTPUT ACCEPT [0:0]\n:DS_DOMAINS - [0:0]\n-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP\n-A OUTPUT -d 192.0.2.1/32 -j ACCEPT\n-A OUTPUT -o eth0 -j DS_DOMAINS\nCOMMIT'
        current=expected.replace('-A OUTPUT -o eth0 -m ndpi --proto bittorrent -j DROP\n','')
        self.assertTrue(dr.cold_subset(expected,current))
        shifted=current.replace('-A OUTPUT -d 192.0.2.1/32 -j ACCEPT\n-A OUTPUT -o eth0 -j DS_DOMAINS','-A OUTPUT -o eth0 -j DS_DOMAINS\n-A OUTPUT -d 192.0.2.1/32 -j ACCEPT')
        self.assertFalse(dr.cold_subset(expected,shifted))
        self.assertFalse(dr.cold_subset(expected,expected))

    def test_cold_subset_rejects_new_rules_chain_policy_and_ndpi(self):
        expected=firewall()
        for current in (expected,expected.replace('example.test','other.test'),expected.replace(':DS_DOM_A -',':DS_DOM_A ACCEPT')):
            self.assertFalse(dr.cold_subset(expected,current))


@unittest.skipUnless(os.geteuid()==0, 'root ownership checks require local root test process')
class ApplyLock(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/run');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.path=self.root/'apply.lock'
        self.patcher=patch.object(dr,'APPLY_LOCK',self.path);self.patcher.start();self.addCleanup(self.patcher.stop)
        self.guards=patch.object(dr,'GUARD_FILES',(self.root/'guard',));self.guards.start();self.addCleanup(self.guards.stop)

    def test_fresh_no_guard_does_not_create_lock(self):
        with dr.apply_lock():self.assertFalse(self.path.exists())
        self.assertFalse(self.path.exists())

    def test_existing_lock_is_untruncated_reentrant_and_noninheritable(self):
        self.path.write_bytes(b'preserve')
        with patch.object(dr.os,'open',wraps=os.open) as opened:
            with dr.apply_lock():
                with dr.apply_lock():pass
                self.assertEqual(opened.call_count,1)
                self.assertTrue(opened.call_args.args[1]&os.O_CLOEXEC)
                self.assertFalse(opened.call_args.args[1]&os.O_TRUNC)
        self.assertEqual(self.path.read_bytes(),b'preserve')

    def test_snapshot_reads_generation_and_firewall_under_lock_but_apt_after_release(self):
        self.path.touch();generation=self.root/'domain-generation.env'
        generation.write_text(record()['generation_text']);generation.chmod(0o600)
        calls=[]
        def run(args,*unused,**kwargs):
            calls.append(args)
            if args==['iptables-save']:
                self.assertTrue(getattr(dr._local,'held',False))
                return firewall()
            if args==['apt-mark','showmanual']:
                self.assertFalse(getattr(dr._local,'held',False))
                return ''
            self.fail('unexpected command '+str(args))
        with patch.object(lc,'STATE',self.root/'state'),patch.object(lc,'GENERATION',str(generation)), \
             patch.object(lc,'packages',return_value={}),patch.object(lc,'package_ownership',return_value={}), \
             patch.object(lc,'paths',return_value=[str(generation)]),patch.object(lc,'units',return_value={}), \
             patch.object(lc,'values',return_value={}),patch.object(lc,'run',side_effect=run):
            snapshot=lc.snapshot()
        self.assertEqual(snapshot['generation_text'],generation.read_text())
        self.assertEqual(snapshot['files'][str(generation)]['sha256'],hashlib.sha256(generation.read_bytes()).hexdigest())
        self.assertEqual(calls,[['iptables-save'],['apt-mark','showmanual']])

    def test_missing_lock_with_existing_guard_is_created_without_truncation(self):
        (self.root/'guard').touch()
        with dr.apply_lock():self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        self.assertTrue(self.path.exists())

    def test_wait_is_bounded_and_no_lock_body_runs_on_timeout(self):
        self.path.touch();fd=os.open(self.path,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            with self.assertRaisesRegex(RuntimeError,'дождаться'):
                with dr.apply_lock(timeout=0):self.fail('entered busy lock')
        finally:os.close(fd)

    def test_symlink_and_writable_lock_are_refused(self):
        target=self.root/'target';target.write_bytes(b'keep');self.path.symlink_to(target)
        with self.assertRaises(OSError):
            with dr.apply_lock():self.fail('entered symlink')
        self.path.unlink();self.path.touch();self.path.chmod(0o666)
        with self.assertRaises(RuntimeError):
            with dr.apply_lock():self.fail('entered writable lock')
        self.assertEqual(target.read_bytes(),b'keep')


class ControllerCapture(unittest.TestCase):
    def exercise(self, fail_begin):
        import controller
        import legacy_context
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root=Path(temporary);state=root/'state';base=root/'transactions'
            held=False;events=[]
            @contextmanager
            def lock():
                nonlocal held
                self.assertFalse(held);held=True;events.append('acquire')
                try:yield
                finally:held=False;events.append('release')
            def begin(txn):
                self.assertTrue(held);events.append('capture')
                if fail_begin:raise RuntimeError('capture failed')
                txn.mkdir()
                return {'loaded':True,'boot_id':'lab'}
            def outside(*args,**kwargs):
                self.assertFalse(held);events.append('outside')
                return '/nonexecuted/lab-module'
            stack.enter_context(patch.object(controller,'STATE',state))
            stack.enter_context(patch.object(controller,'BASE',base))
            stack.enter_context(patch.object(controller,'apply_lock',side_effect=lock))
            stack.enter_context(patch.object(controller,'begin',side_effect=begin))
            stack.enter_context(patch.object(controller,'save',side_effect=outside))
            stack.enter_context(patch.object(controller,'run',side_effect=outside))
            stack.enter_context(patch.object(controller,'driver',side_effect=outside))
            stack.enter_context(patch.object(controller,'digest',return_value='unused'))
            stack.enter_context(patch.object(controller,'loaded_matches',return_value=False))
            stack.enter_context(patch.object(controller.shutil,'copy2',side_effect=outside))
            stack.enter_context(patch.object(legacy_context,'preflight',return_value={
                'compatible':True,'legacy_upgrade':{'requires_reboot':True},'kernel':'lab','stage_only':True}))
            if fail_begin:
                with self.assertRaisesRegex(RuntimeError,'capture failed'):controller.execute()
                self.assertEqual(events,['acquire','capture','release'])
            else:
                self.assertEqual(controller.execute(),20)
                self.assertEqual(events[:3],['acquire','capture','release'])
                self.assertTrue(events[3:]);self.assertTrue(all(e=='outside' for e in events[3:]))
            self.assertFalse(held)

    def test_capture_is_locked_but_driver_and_systemd_are_outside(self):
        self.exercise(False)

    def test_begin_exception_releases_lock_before_propagation(self):
        self.exercise(True)


if __name__=='__main__':unittest.main()
