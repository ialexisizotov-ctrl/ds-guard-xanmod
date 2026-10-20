#!/usr/bin/env python3
"""Scoped, local transaction records. Never restore a global firewall snapshot."""
import collections, fcntl, glob, hashlib, json, os, re, shlex, shutil, stat, subprocess, sys, time, uuid
from pathlib import Path

BASE=Path('/var/lib/ds-guard-safe/transactions')
CHAINS={'DS_DOMAINS','DS_DOM_A','DS_DOM_B','DS_DOM_A_D','DS_DOM_A_W','DS_DOM_B_D','DS_DOM_B_W'}
UNITS=['ds-guard.timer','ds-guard.service','ds-guard-apply.service','suricata.service']
SURICATA_HOLD=Path('/etc/systemd/system/suricata.service.d/97-safe-initial-install.conf')
SURICATA_YAML=Path('/etc/suricata/suricata.yaml')
SURICATA_NFQUEUE=Path('/etc/systemd/system/suricata.service.d/nfqueue.conf')
SURICATA_NFQUEUE_TEXT='[Service]\nType=simple\nPIDFile=\nExecStart=\nExecStart=/usr/bin/suricata -q 0 -q 1 -c /etc/suricata/suricata.yaml\nRestart=on-failure\nRestartSec=3\n'

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

def managed_state(text):
    """Canonical owned chains/rules and hook positions, excluding counters."""
    validate_managed_scope(text)
    table='';chains={};rules={};hooks={};positions=collections.defaultdict(int)
    for line in text.splitlines():
        if line.startswith('*'):table=line[1:]
        if table!='filter':continue
        if line.startswith(':'):
            name,policy=line.split()[:2];name=name[1:]
            if name in CHAINS:chains[name]=policy
        elif line.startswith('-A '):
            p=shlex.split(line);chain=p[1];positions[chain]+=1
            if chain in CHAINS:rules.setdefault(chain,[]).append(p[2:])
            elif managed_hook(line):hooks.setdefault(chain,[]).append([positions[chain],p[2:]])
    return {'chains':chains,'rules':rules,'hooks':hooks}

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
    paths += ['/etc/systemd/system/'+n+'.d/98-safe-activation.conf' for n in ['ds-guard.service','ds-guard-apply.service']]
    paths += ['/var/lib/ds-guard-safe/activation-guard.json']
    paths += [str(SURICATA_HOLD)]
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
      'started':time.time(),'phase':'prepared','suricata_initial_package_status':suricata_package_status()}
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

def suricata_package_status():
    p=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}','suricata'],capture_output=True,text=True,timeout=30)
    if p.returncode==1 and not p.stdout:return ''
    if p.returncode:raise RuntimeError('Не удалось определить исходное состояние пакета Suricata')
    return p.stdout.strip()

def _suri_parents(path):
    for parent in path.parents:
        if parent.is_symlink():raise RuntimeError('Каталог запрета Suricata является ссылкой')
        if parent.exists():
            st=parent.stat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
                raise RuntimeError('Небезопасный каталог запрета Suricata')

def _suri_file(path,mode=None):
    _suri_parents(path)
    if path.is_symlink():raise RuntimeError('Файл запрета Suricata является ссылкой')
    if not path.exists():return None
    st=path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or mode is not None and stat.S_IMODE(st.st_mode)!=mode:
        raise RuntimeError('Не подтверждены владелец или права файла Suricata')
    return path.read_bytes()

def _suri_sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def _suri_mkdir(path):
    if path.exists():
        _suri_parents(path/'entry');return
    _suri_mkdir(path.parent)
    path.mkdir(mode=0o755)
    _suri_sync_directory(path);_suri_sync_directory(path.parent)

def _suri_create(path,body,mode):
    current=_suri_file(path,mode)
    if current is not None:
        if current!=body:raise RuntimeError('Чужой файл запрета Suricata не будет заменён')
        with path.open('rb') as f:os.fsync(f.fileno())
        _suri_sync_directory(path.parent);return
    _suri_mkdir(path.parent)
    _suri_parents(path)
    temporary=path.with_name('.'+path.name+'.'+str(uuid.uuid4()))
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),mode);f.write(body);f.flush();os.fsync(f.fileno())
        # A concurrent new destination must never be silently replaced.
        os.link(temporary,path)
        temporary.unlink();_suri_sync_directory(path.parent)
    finally:temporary.unlink(missing_ok=True)

def _suri_context(txn,b):
    expected={'schema':1,'transaction':str(txn),'dropin':str(SURICATA_HOLD),
              'initial_package_status':b.get('suricata_initial_package_status'),
              'initial_unit':b['units'].get('suricata.service')}
    if expected['initial_package_status'] not in ('','not-installed'):
        raise RuntimeError('Не подтверждён журнал первичной установки Suricata')
    if str(SURICATA_HOLD) in b['files'] or str(SURICATA_YAML) in b['files'] and not b['files'][str(SURICATA_YAML)].get('new_package_default'):
        raise RuntimeError('Прежние файлы Suricata не принадлежат первичной установке')
    state=expected['initial_unit'] or {}
    if state.get('active') not in ('inactive','unknown','') or state.get('enabled') not in ('not-found',''):
        raise RuntimeError('Прежняя служба Suricata не принадлежит первичной установке')
    allow=txn/'suricata-start-approved'
    if allow.exists() or allow.is_symlink():raise RuntimeError('Неожиданное разрешение первичного запуска Suricata')
    return expected,('[Unit]\nConditionPathExists='+str(allow)+'\n').encode()

def _suri_record(txn,b):
    raw=_suri_file(txn/'suricata-start-guard.json',0o600)
    if raw is None:return None
    expected,body=_suri_context(txn,b)
    if json.loads(raw)!=expected:raise RuntimeError('Не подтверждён журнал первичной установки Suricata')
    return body

def arm_suricata_guard(txn):
    b=json.loads((txn/'before.json').read_text())
    receipt=txn/'suricata-start-guard.json'
    if not receipt.exists() and not receipt.is_symlink():
        initial=b.get('suricata_initial_package_status')
        if initial=='installed':return False
        if initial not in ('','not-installed'):raise RuntimeError('Исходное отсутствие Suricata не подтверждено')
        if suricata_package_status() not in ('','not-installed'):
            raise RuntimeError('Пакет Suricata появился после исходного снимка')
        if _suri_file(SURICATA_HOLD) is not None:raise RuntimeError('Файл запрета Suricata уже занят')
        # A refused precondition must not create a receipt that would poison
        # independent rollback of the rest of this transaction.
        data,_=_suri_context(txn,b)
        if run(['systemctl','is-active','suricata.service'],False) not in ('inactive','unknown',''):
            raise RuntimeError('Новая служба Suricata уже запущена; запрет не применён')
        _suri_create(receipt,json.dumps(data,sort_keys=True).encode(),0o600)
    body=_suri_record(txn,b)
    if run(['systemctl','is-active','suricata.service'],False) not in ('inactive','unknown',''):
        raise RuntimeError('Новая служба Suricata уже запущена; запрет не применён')
    _suri_create(SURICATA_HOLD,body,0o644)
    run(['systemctl','daemon-reload'])
    return True

def _suri_unlink(txn,b):
    body=_suri_record(txn,b)
    actual=_suri_file(SURICATA_HOLD,0o644)
    if actual is not None:
        if actual!=body:raise RuntimeError('Запрет Suricata изменён вне установки')
        SURICATA_HOLD.unlink();_suri_sync_directory(SURICATA_HOLD.parent)
    run(['systemctl','daemon-reload'])

def release_suricata_guard(txn):
    b=json.loads((txn/'before.json').read_text());body=_suri_record(txn,b)
    if body is None:return False
    if _suri_file(SURICATA_HOLD,0o644)!=body:raise RuntimeError('Запрет первичного запуска Suricata утрачен')
    if not b['files'].get(str(SURICATA_YAML),{}).get('new_package_default'):
        raise RuntimeError('Не сохранена исходная пакетная конфигурация Suricata')
    if _suri_file(SURICATA_NFQUEUE,0o644)!=SURICATA_NFQUEUE_TEXT.encode():
        raise RuntimeError('Не подтверждена подготовка Suricata для NFQUEUE')
    if _suri_file(SURICATA_YAML) is None:raise RuntimeError('Нет конфигурации Suricata')
    run(['/usr/bin/suricata','-T','-c',str(SURICATA_YAML)],timeout=90)
    _suri_unlink(txn,b)
    return True

def restore_suricata_guard(txn,b):
    body=_suri_record(txn,b)
    if body is None:return set()
    _suri_create(SURICATA_HOLD,body,0o644)
    run(['systemctl','daemon-reload'])
    # A failure before dpkg leaves no unit to stop. The readback below remains
    # mandatory, so an actually running/failed-to-stop unit cannot pass.
    run(['systemctl','stop','suricata.service'],False)
    if run(['systemctl','is-active','suricata.service'],False) not in ('inactive','unknown',''):
        raise RuntimeError('Первичная служба Suricata не остановлена')
    if str(SURICATA_YAML) not in b['files'] and (SURICATA_YAML.exists() or SURICATA_YAML.is_symlink()):
        raise RuntimeError('Пакетная установка Suricata прервана до сохранения default-конфигурации. Запрет запуска сохранён; требуется проверка пакетного состояния.')
    return {str(SURICATA_HOLD)}

def cleanup_suricata_guard(txn,b):
    if _suri_record(txn,b) is None:return
    if (run(['systemctl','is-active','suricata.service'],False) not in ('inactive','unknown','') or
            run(['systemctl','is-enabled','suricata.service'],False) not in ('disabled','not-found','')):
        raise RuntimeError('Suricata ещё может запуститься; запрет сохранён')
    _suri_unlink(txn,b)

def rollback(txn):
    if (txn/'committed').exists() or (txn/'rolled-back').exists(): return
    b=json.loads((txn/'before.json').read_text())
    quarantined=restore_quarantine_first(txn,b)
    suricata_held=restore_suricata_guard(txn,b)
    run(['systemctl','stop','ds-guard.timer','ds-guard-apply.service','ds-guard.service'],False)
    # Remove only the exact three installer-owned base-hook forms.
    current=run(['iptables-save'])
    foreign_before_rollback=foreign_rules(current)
    present_chains=set(managed_state(current)['chains'])
    original_scope=managed_state(b['iptables'])
    detach_managed_hooks(run)
    # Rebuild only seven named installer chains. Never flush INPUT, OUTPUT,
    # FORWARD, Docker, UFW, or another nftables table.
    for c in sorted(CHAINS):
        if c not in present_chains:run(['iptables','-w','5','-N',c])
        run(['iptables','-w','5','-F',c])
    for line in b['iptables'].splitlines():
        if not line.startswith('-A '): continue
        p=shlex.split(line)
        if p[1] in CHAINS: run(['iptables','-w','5',*p])
    old_chains={l.split()[0][1:] for l in b['iptables'].splitlines() if l.startswith(':')}
    for c in sorted(CHAINS-old_chains):run(['iptables','-w','5','-X',c])
    # Reconnect traffic only after all isolated chains are exactly restored.
    # A successful but ineffective flush (or concurrent writer) must not expose
    # packets to unaccepted nDPI rules before the final recovery check.
    isolated=run(['iptables-save'])
    if managed_state(isolated)!={**original_scope,'hooks':{}} or foreign_rules(isolated)!=foreign_before_rollback:
        raise RuntimeError('Изолированные цепочки не совпали с исходным состоянием; подключения ds-guard не восстановлены')
    positions=collections.defaultdict(int)
    for line in b['iptables'].splitlines():
        if not line.startswith('-A '):continue
        p=shlex.split(line);positions[p[1]]+=1
        if managed_hook(line):run(['iptables','-w','5','-I',p[1],str(positions[p[1]]),*p[2:]])
    # Restore scoped configuration/module files; leave newly installed packages.
    old=set(b['files']); now=set(owned_paths(b['kernel']))
    for name in now-old:
        if name in suricata_held:continue
        p=Path(name)
        if p.is_file() or p.is_symlink(): p.unlink()
    for name in old:
        # Do not truncate the already durable quarantine files while a new
        # activation fence is being removed by this same rollback.
        if name in quarantined:continue
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
    final_firewall=run(['iptables-save'])
    if foreign_rules(final_firewall)!=foreign_before_rollback:
        raise RuntimeError('Foreign firewall changed during rollback; independent recovery remains armed')
    if managed_state(final_firewall)!=original_scope:
        raise RuntimeError('Собственные цепочки или правила после отката не совпали с исходным состоянием; восстановление не подтверждено')
    for unit,state in b['units'].items():
        if state['active']=='active' and run(['systemctl','is-active',unit],False)!='active':
            raise RuntimeError('Previously active service did not recover: '+unit)
    if b['acct'] in ('0','1') and run(['sysctl','-n','net.netfilter.nf_conntrack_acct'])!=b['acct']:
        raise RuntimeError('Conntrack accounting rollback verification failed')
    cleanup_suricata_guard(txn,b)
    save(txn/'rolled-back',{'time':time.time(),'module_not_forcibly_unloaded':True,'global_firewall_not_restored':True,'files_restored_verified':True,'foreign_firewall_preserved':True,'previously_active_services_restored':True})

def restore_quarantine_first(txn,b,root=Path('/')):
    # Re-arm the known boot hold before any fallible firewall/file recovery.
    # A failed recovery must never leave an unaccepted service free to boot.
    names=['/etc/systemd/system/'+u+'.d/90-codex-ndpi-memory-hold.conf' for u in ['ds-guard.service','ds-guard-apply.service']]
    body='[Unit]\nConditionPathExists=!/root/codex-dsguard-20261019/ndpi-memory-safety-hold\n'
    restored=set()
    for name in names:
        if name not in b['files']:continue
        backup=txn/'files'/name.lstrip('/');dest=root/name.lstrip('/')
        if backup.is_symlink() or backup.read_text()!=body:raise RuntimeError('Не подтверждена резервная копия запрета прежнего nDPI')
        if dest.is_symlink() or dest.exists() and dest.read_text()!=body:raise RuntimeError('Запрет запуска изменён вне установки; возврат остановлен')
        if not dest.exists():
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(backup,dest);os.chown(dest,backup.stat().st_uid,backup.stat().st_gid)
        if dest.read_text()!=body:raise RuntimeError('Запрет запуска не восстановлен')
        dest.chmod(backup.stat().st_mode&0o777)
        with dest.open('rb') as f:os.fsync(f.fileno())
        fd=os.open(dest.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
        restored.add(name)
    if restored:run(['systemctl','daemon-reload'])
    return restored

if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1] not in ('rollback','capture-package-default','suricata-arm','suricata-release'):sys.exit(64)
    txn=valid_txn(sys.argv[2])
    if sys.argv[1]=='rollback':
        with (BASE.parent/'install.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            rollback(txn)
    elif sys.argv[1]=='capture-package-default':capture_package_default(txn)
    elif sys.argv[1]=='suricata-arm':arm_suricata_guard(txn)
    else:release_suricata_guard(txn)
