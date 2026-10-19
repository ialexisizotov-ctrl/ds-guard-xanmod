#!/usr/bin/env python3
import argparse, fcntl, hashlib, json, os, re, shutil, subprocess, sys, time, uuid
from pathlib import Path
import preflight
from transaction import BASE, begin, run, save, rollback, foreign_rules

ROOT=Path('/usr/local/lib/ds-guard-safe')
STATE=Path('/var/lib/ds-guard-safe')

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def driver(phase,txn):
    with (txn/'driver.log').open('a') as log:
        p=subprocess.run(['bash',str(ROOT/'driver.sh'),phase,str(txn)],stdout=log,stderr=subprocess.STDOUT,
            timeout=1800,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_SUSPEND':'1'})
        if p.returncode:raise RuntimeError('Driver '+phase+' failed; see '+str(txn/'driver.log'))

def runtime_check(txn,before):
    driver('verify',txn)
    if run(['sysctl','-n','net.netfilter.nf_conntrack_acct'])!='1':raise RuntimeError('Conntrack accounting unavailable')
    queues=Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()
    if not {0,1} <= {int(l.split()[0]) for l in queues}:raise RuntimeError('NFQUEUE listeners missing')
    livepatch=Path('/sys/kernel/livepatch/xt_ndpi')
    if not livepatch.is_dir() or (livepatch/'enabled').read_text().strip()!='1' or (livepatch/'transition').read_text().strip()!='0':
        raise RuntimeError('nDPI livepatch has not completed its safe transition')
    dm=run(['dmesg']);base=before['kernel_log'].splitlines();old=set(base)
    bad=[l for l in dm.splitlines() if l not in old and re.search(r'UBSAN:|BUG:|Oops:|Kernel panic|WARNING: CPU|Out of memory|Killed process',l)]
    if bad:raise RuntimeError('New kernel diagnostic; see transaction evidence')
    # Preserve the exact order of every unrelated firewall rule.
    if foreign_rules(before['iptables'])!=foreign_rules(run(['iptables-save'])):raise RuntimeError('Unrelated firewall state changed; review required')
    if before['rules']!=run(['ip','-j','rule']):raise RuntimeError('Routing policy changed')
    def routes(s):
        return sorted(json.dumps({k:v for k,v in r.items() if k not in ('expires','flags')},sort_keys=True) for r in json.loads(s))
    if routes(before['routes'])!=routes(run(['ip','-j','route','show','table','all'])):raise RuntimeError('Network routes changed')
    now_listeners=set(run(['ss','-Hlnpt']).splitlines())
    if not set(before['tcp_listeners'].splitlines())<=now_listeners:raise RuntimeError('A pre-existing TCP listener changed')
    if before['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise RuntimeError('Unexpected reboot during transaction')
    # Strict TLS and a small real response. Additional application acceptance
    # is supplied by the operator through --health-command.
    run(['curl','--noproxy','*','--fail','--silent','--show-error','--max-time','15','https://www.google.com/generate_204'])
    return {'local_layers':3,'nfqueue_listeners':[0,1],'new_kernel_errors':0,'foreign_firewall_preserved':True,'strict_https':True}

def execute(health_command=None):
    result=preflight.collect()
    if not result['compatible']:print(json.dumps(result,indent=2));return 78
    STATE.mkdir(mode=0o700,exist_ok=True);BASE.mkdir(mode=0o700,exist_ok=True)
    pending=STATE/'pending.json'
    if pending.exists():
        p=json.loads(pending.read_text())
        if p['staged_boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            print('REBOOT_REQUIRED: the staged module has not yet been loaded by a new boot.');return 20
    with (STATE/'install.lock').open('w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Another installation is running')
        txn=BASE/str(uuid.uuid4());before=begin(txn)
        save(STATE/'current.json',{'transaction':str(txn)})
        shutil.copy2(ROOT/'transaction.py',txn/'transaction.py')
        safety='ds-guard-safe-rollback-'+txn.name
        run(['systemd-run','--unit='+safety,'--on-active=35m','/usr/bin/python3',str(txn/'transaction.py'),'rollback',str(txn)])
        print('Transaction: '+str(txn),flush=True)
        settled=False
        try:
            driver('prepare',txn)
            module=run(['modinfo','-n','xt_ndpi']);sha=digest(module)
            old=txn/'files'/before['module_before'].lstrip('/') if before['module_before'] else None
            if before['loaded']:driver('plugin-check',txn)
            if before['loaded'] and (not old or not old.is_file() or digest(old)!=sha):
                # No unloading of a livepatch module; a planned reboot is required.
                save(STATE/'pending.json',{'kernel':result['kernel'],'module':module,'sha256':sha,'staged_boot_id':before['boot_id'],'transaction':str(txn)})
                (txn/'committed').write_text('Module staged; running module retained. Reboot required before activation.\n')
                print('REBOOT_REQUIRED: module prepared; current traffic and loaded module retained. Run installer after planned reboot.',flush=True)
                settled=True
                return 20
            driver('load',txn)
            if before['acct'] not in ('0','1'):
                before['acct']=run(['sysctl','-n','net.netfilter.nf_conntrack_acct'])
                save(txn/'before.json',before)
            driver('apply',txn)
            time.sleep(3)
            evidence=runtime_check(txn,before)
            if health_command:
                subprocess.run(['/bin/bash','-c',health_command],check=True,timeout=120)
                evidence['operator_application_check']=True
            else:evidence['operator_application_check']=False
            save(txn/'acceptance.json',evidence)
            save(STATE/'installed.json',{'kernel':result['kernel'],'module':module,'sha256':sha,'transaction':str(txn),'time':time.time()})
            (txn/'committed').write_text('Local acceptance passed\n')
            (STATE/'pending.json').unlink(missing_ok=True)
            print('SUCCESS: 3/3 local layers verified. Transaction '+str(txn),flush=True)
            settled=True
            return 0
        except BaseException:
            rollback(txn)
            settled=True
            raise
        finally:
            # Leave the independent recovery timer armed if rollback itself fails.
            if settled:run(['systemctl','stop',safety+'.timer'],False)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--check',action='store_true');ap.add_argument('--health-command');args=ap.parse_args()
    if args.check:
        r=preflight.collect();print(json.dumps(r,indent=2));sys.exit(0 if r['compatible'] else 78)
    try:sys.exit(execute(args.health_command))
    except Exception as e:print('FAILED: '+str(e),file=sys.stderr);sys.exit(1)
