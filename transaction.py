#!/usr/bin/env python3
"""Scoped, local transaction records. Never restore a global firewall snapshot."""
import collections, fcntl, glob, hashlib, json, os, re, shlex, shutil, subprocess, sys, time
from pathlib import Path

BASE=Path('/var/lib/ds-guard-safe/transactions')
CHAINS={'DS_DOMAINS','DS_DOM_A','DS_DOM_B','DS_DOM_A_D','DS_DOM_A_W','DS_DOM_B_D','DS_DOM_B_W'}
UNITS=['ds-guard.timer','ds-guard.service','ds-guard-apply.service','suricata.service']

def run(args, check=True, timeout=40, **kw):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,**kw)
    if check and p.returncode: raise RuntimeError(args[0]+' failed: '+str(p.returncode))
    return p.stdout.strip()

def managed_hook(line):
    p=shlex.split(line)
    if len(p)<6 or p[0]!='-A' or p[1] not in ['OUTPUT','FORWARD','DOCKER-USER'] or p[2]!='-o': return False
    tail=p[4:]
    return tail in [['-j','DS_DOMAINS'],['-m','ndpi','--proto','bittorrent','-j','DROP'],
      ['-p','udp','-m','conntrack','--ctstate','NEW','-j','NFQUEUE','--queue-balance','0:1','--queue-bypass']]

def foreign_rules(text):
    out=[]; table=''
    for line in text.splitlines():
        if line.startswith('*'): table=line
        if line.startswith('-A ') and not managed_hook(line) and shlex.split(line)[1] not in CHAINS: out.append(table+' '+line)
        elif line.startswith(':') and line.split()[0][1:] not in CHAINS:
            # Creating an otherwise empty built-in ACCEPT table is inert.
            # DROP or user-chain policies still participate in comparison.
            if line.split()[1]!='ACCEPT':out.append(table+' '+re.sub(r'\[\d+:\d+\]','[COUNTERS]',line))
    return out

def validate_managed_scope(text):
    table=''
    for line in text.splitlines():
        if line.startswith('*'):table=line[1:]
        if line.startswith(':') and line.split()[0][1:] in CHAINS and table!='filter':raise RuntimeError('Имя цепочки ds-guard занято в другой таблице firewall')
        if not line.startswith('-A '):continue
        tokens=shlex.split(line)
        if (tokens[1] in CHAINS or managed_hook(line)) and table!='filter':raise RuntimeError('Правило ds-guard находится вне таблицы filter')
        target=next((tokens[i+1] for i,t in enumerate(tokens[:-1]) if t in ('-j','-g')),None)
        if target in CHAINS and tokens[1] not in CHAINS and not managed_hook(line):raise RuntimeError('Чужое правило использует цепочки ds-guard; автоматическая замена остановлена')

def detach_managed_hooks(execute=run):
    current=execute(['iptables-save']);validate_managed_scope(current)
    foreign=foreign_rules(current);positions=collections.defaultdict(int);removals=[];table=''
    for line in current.splitlines():
        if line.startswith('*'):table=line[1:]
        if table!='filter' or not line.startswith('-A '):continue
        chain=shlex.split(line)[1];positions[chain]+=1
        if managed_hook(line):removals.append((chain,positions[chain],line))
    # nDPI rule serialization is not always equality-preserving for -D rule.
    # Delete by position only after an exact immediate readback of that rule.
    for chain,index,line in reversed(removals):
        live=[l for l in execute(['iptables','-w','5','-S',chain]).splitlines() if l.startswith('-A ')]
        if len(live)<index or live[index-1]!=line:raise RuntimeError('Правила firewall изменились перед снятием собственного подключения')
        execute(['iptables','-w','5','-D',chain,str(index)])
        if foreign_rules(execute(['iptables-save']))!=foreign:raise RuntimeError('Изменились чужие правила firewall при снятии собственного подключения')
    return current

def save(path, value):
    temp=path.with_suffix('.next');temp.write_text(json.dumps(value,indent=2));temp.chmod(0o600);temp.replace(path)

def owned_paths(kernel):
    paths=['/etc/suricata/suricata.yaml','/etc/suricata/rules/ds-p2p.rules',
      '/etc/systemd/system/suricata.service.d/nfqueue.conf','/etc/modprobe.d/xt_ndpi.conf',
      '/etc/modules-load.d/xt_ndpi.conf','/etc/sysctl.d/99-ds-guard-conntrack.conf']
    paths += ['/etc/ds-guard/'+n for n in ['domains.txt','domain-labels.txt','domain-generation.env','domain-patterns.txt','conntrack-owner.env']]
    paths += ['/usr/local/sbin/ds-guard-'+n+'.sh' for n in ['ndpi-lib','ensure','apply','kprep']]
    paths += ['/etc/systemd/system/'+n for n in ['ds-guard.service','ds-guard-apply.service','ds-guard.timer','ds-guard-kprep@.service']]
    paths += ['/etc/systemd/system/'+n+'.d/90-codex-ndpi-memory-hold.conf' for n in ['ds-guard.service','ds-guard-apply.service']]
    paths += ['/etc/kernel/'+n+'/zz-ds-guard' for n in ['postinst.d','header_postinst.d','postrm.d']]
    for pattern in ['/usr/lib/*/xtables/libxt_ndpi.so','/lib/modules/'+kernel+'/updates/dkms/xt_ndpi.ko*']:
        paths.extend(glob.glob(pattern))
    return sorted(set(p for p in paths if Path(p).is_file() or Path(p).is_symlink()))

def begin(txn):
    txn.mkdir(parents=True,mode=0o700);(txn/'files').mkdir(mode=0o700)
    kernel=os.uname().release
    manifest={}
    for name in owned_paths(kernel):
        p=Path(name);dest=txn/'files'/p.relative_to('/');dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(p,dest,follow_symlinks=False);manifest[name]={'symlink':p.is_symlink()}
    states={u:{'active':run(['systemctl','is-active',u],False),'enabled':run(['systemctl','is-enabled',u],False)} for u in UNITS}
    ipt=run(['iptables-save'])
    data={'kernel':kernel,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
      'files':manifest,'units':states,'iptables':ipt,'routes':run(['ip','-j','route','show','table','all']),
      'rules':run(['ip','-j','rule']), 'acct':run(['sysctl','-n','net.netfilter.nf_conntrack_acct'],False),
      'failed_units':run(['systemctl','--failed','--no-legend','--plain']),
      'tcp_listeners':run(['ss','-Hlnpt']),
      'kernel_log':run(['dmesg']), 'loaded':Path('/sys/module/xt_ndpi').exists(),
      'module_before':run(['modinfo','-n','xt_ndpi'],False),
      'started':time.time(),'phase':'prepared'}
    pending=Path('/var/lib/ds-guard-safe/lifecycle/pending.json')
    if pending.is_symlink():raise RuntimeError('Журнал операции является ссылкой')
    operation_id=json.loads(pending.read_text()).get('operation_id') if pending.exists() else None
    if operation_id is not None and not re.fullmatch('[0-9a-f-]{36}',operation_id):raise RuntimeError('Некорректный идентификатор операции')
    data.update(operation_id=operation_id,requested_values={'net.netfilter.nf_conntrack_acct':'1'})
    save(txn/'before.json',data);return data

def valid_txn(arg):
    p=Path(arg).resolve()
    if p.parent != BASE or not re.fullmatch(r'[0-9a-f-]+',p.name): raise ValueError('Invalid transaction path')
    return p

def capture_package_default(txn):
    # A package newly installed by this transaction remains installed on rollback.
    # Keep its pristine default configuration rather than deleting that file.
    name='/etc/suricata/suricata.yaml';p=Path(name)
    b=json.loads((txn/'before.json').read_text())
    if name not in b['files'] and p.is_file() and not p.is_symlink():
        dest=txn/'files'/p.relative_to('/');dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(p,dest);b['files'][name]={'symlink':False,'new_package_default':True}
        save(txn/'before.json',b)

def rollback(txn):
    if (txn/'committed').exists() or (txn/'rolled-back').exists(): return
    b=json.loads((txn/'before.json').read_text())
    restore_quarantine_first(txn,b)
    run(['systemctl','stop','ds-guard.timer','ds-guard-apply.service','ds-guard.service'],False)
    # Remove only the exact three installer-owned base-hook forms.
    current=run(['iptables-save'])
    foreign_before_rollback=foreign_rules(current)
    detach_managed_hooks(run)
    # Rebuild only seven named installer chains. Never flush INPUT, OUTPUT,
    # FORWARD, Docker, UFW, or another nftables table.
    for c in CHAINS:
        run(['iptables','-w','5','-N',c],False);run(['iptables','-w','5','-F',c],False)
    positions=collections.defaultdict(int)
    for line in b['iptables'].splitlines():
        if not line.startswith('-A '): continue
        p=shlex.split(line);positions[p[1]]+=1
        if p[1] in CHAINS: run(['iptables','-w','5',*p])
        elif managed_hook(line): run(['iptables','-w','5','-I',p[1],str(positions[p[1]]),*p[2:]])
    old_chains={l.split()[0][1:] for l in b['iptables'].splitlines() if l.startswith(':')}
    for c in CHAINS-old_chains:run(['iptables','-w','5','-X',c],False)
    # Restore scoped configuration/module files; leave newly installed packages.
    old=set(b['files']); now=set(owned_paths(b['kernel']))
    for name in now-old:
        p=Path(name)
        if p.is_file() or p.is_symlink(): p.unlink()
    for name in old:
        p=Path(name);p.parent.mkdir(parents=True,exist_ok=True)
        if p.is_symlink():p.unlink()
        shutil.copy2(txn/'files'/p.relative_to('/'),p,follow_symlinks=False)
        backup=txn/'files'/p.relative_to('/')
        if p.is_symlink():
            if os.readlink(p)!=os.readlink(backup):raise RuntimeError('Rollback symlink verification failed')
        elif hashlib.sha256(p.read_bytes()).digest()!=hashlib.sha256(backup.read_bytes()).digest():
            raise RuntimeError('Rollback file verification failed')
    run(['depmod','-a',b['kernel']],False,timeout=90)
    if b['acct'] in ('0','1'):run(['sysctl','-w','net.netfilter.nf_conntrack_acct='+b['acct']],False)
    run(['systemctl','daemon-reload'],False)
    for unit,state in b['units'].items():
        if state['enabled']=='enabled':run(['systemctl','enable',unit],False)
        elif state['enabled'] not in ('static','indirect','generated','alias'):run(['systemctl','disable',unit],False)
        if state['active']=='active':run(['systemctl','restart',unit],False,timeout=90)
        else:run(['systemctl','stop',unit],False)
    if foreign_rules(run(['iptables-save']))!=foreign_before_rollback:
        raise RuntimeError('Foreign firewall changed during rollback; independent recovery remains armed')
    for unit,state in b['units'].items():
        if state['active']=='active' and run(['systemctl','is-active',unit],False)!='active':
            raise RuntimeError('Previously active service did not recover: '+unit)
    if b['acct'] in ('0','1') and run(['sysctl','-n','net.netfilter.nf_conntrack_acct'])!=b['acct']:
        raise RuntimeError('Conntrack accounting rollback verification failed')
    save(txn/'rolled-back',{'time':time.time(),'module_not_forcibly_unloaded':True,'global_firewall_not_restored':True,'files_restored_verified':True,'foreign_firewall_preserved':True,'previously_active_services_restored':True})

def restore_quarantine_first(txn,b,root=Path('/')):
    # Re-arm the known boot hold before any fallible firewall/file recovery.
    # A failed recovery must never leave an unaccepted service free to boot.
    names=['/etc/systemd/system/'+u+'.d/90-codex-ndpi-memory-hold.conf' for u in ['ds-guard.service','ds-guard-apply.service']]
    body='[Unit]\nConditionPathExists=!/root/codex-dsguard-20261019/ndpi-memory-safety-hold\n'
    restored=False
    for name in names:
        if name not in b['files']:continue
        backup=txn/'files'/name.lstrip('/');dest=root/name.lstrip('/')
        if backup.is_symlink() or backup.read_text()!=body:raise RuntimeError('Не подтверждена резервная копия запрета прежнего nDPI')
        if dest.is_symlink() or dest.exists() and dest.read_text()!=body:raise RuntimeError('Запрет запуска изменён вне установки; возврат остановлен')
        if not dest.exists():
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(backup,dest);os.chown(dest,backup.stat().st_uid,backup.stat().st_gid)
        if dest.read_text()!=body:raise RuntimeError('Запрет запуска не восстановлен')
        restored=True
    if restored:run(['systemctl','daemon-reload'])

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1] not in ('rollback','capture-package-default'):sys.exit(64)
    txn=valid_txn(sys.argv[2])
    if sys.argv[1]=='rollback':
        with (BASE.parent/'install.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            rollback(txn)
    else:capture_package_default(txn)
