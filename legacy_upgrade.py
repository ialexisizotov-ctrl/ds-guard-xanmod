#!/usr/bin/env python3
"""Recognize the exact quarantined 1.7.11 installation; never reboot or unload."""
import hashlib,json,os,platform,re,shlex,subprocess,uuid
from pathlib import Path
import module_identity

ROOT=Path(__file__).resolve().parent
SYSTEM_ROOT=Path('/')
ROOT_UID=0
STATE=Path('/var/lib/ds-guard-safe')
MARKER=Path('/root/codex-dsguard-20261019/ndpi-memory-safety-hold')
MARKER_TEXT='Upstream realloc_wrapper overreads the old allocation. Keep nDPI packet rules suspended until corrected module is loaded and accepted.\n'
HOLD_PATHS=tuple(Path('/etc/systemd/system',u+'.d/90-codex-ndpi-memory-hold.conf') for u in ['ds-guard.service','ds-guard-apply.service'])
HOLD_TEXT='[Unit]\nConditionPathExists=!'+str(MARKER)+'\n'
GUARD_UNIT='''[Unit]
Description=DoubleServers VPS Guard - anti-torrent + packetsdk block
After=network-online.target suricata.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=2700
Environment=NEEDRESTART_SUSPEND=1
ExecStartPre=-/usr/local/sbin/ds-guard-ensure.sh
ExecStart=/usr/local/sbin/ds-guard-apply.sh
[Install]
WantedBy=multi-user.target
'''
APPLY_UNIT='''[Unit]
Description=DoubleServers VPS Guard - re-assert egress rules (idempotent)
After=network-online.target suricata.service ds-guard.service
[Service]
Type=oneshot
TimeoutStartSec=2700
Environment=NEEDRESTART_SUSPEND=1
ExecStartPre=-/usr/local/sbin/ds-guard-ensure.sh
ExecStart=/usr/local/sbin/ds-guard-apply.sh
'''
SUPPORTED={'6.8.0-87-generic':'22.04','6.8.0-147-generic':'24.04','7.0.12-x64v2-dsg1-xanmod1':'24.04','7.2.9-x64v3-dsg1-xanmod1':'24.04'}
FAULT=re.compile(r'BUG:|UBSAN:|Oops:|Kernel panic|WARNING: CPU|Out of memory|Killed process|KASAN:')

def path(p):return SYSTEM_ROOT/str(p).lstrip('/')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 if check and p.returncode:raise RuntimeError('Не выполнена проверка прежней установки: '+args[0])
 return p.returncode,p.stdout.strip()

def regular(p,mode=None,text=None):
 if p.is_symlink() or any(q.is_symlink() for q in p.parents) or not p.is_file():raise RuntimeError('Ожидался обычный файл прежней установки: '+str(p))
 s=p.stat()
 if s.st_uid!=ROOT_UID or mode is not None and s.st_mode&0o777!=mode:raise RuntimeError('Не подтверждены владелец или права прежнего файла: '+str(p))
 if text is not None and p.read_text()!=text:raise RuntimeError('Содержимое прежнего файла не совпадает с известной версией: '+str(p))
 return {'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode&0o777,'sha256':digest(p)}

def holds_present():return any(path(p).exists() or path(p).is_symlink() for p in HOLD_PATHS)
def is_legacy_required():
 return holds_present() or not path(STATE/'lifecycle/before.json').exists() and any(path(p).exists() or path(p).is_symlink() for p in [STATE/'installed.json',Path('/etc/systemd/system/ds-guard.service')])

def kernel_log_state(rc,log):
 if rc:raise RuntimeError('Журнал ядра недоступен; подготовка и активация запрещены')
 lines=log.splitlines();faults=[i for i,l in enumerate(lines) if FAULT.search(l)]
 known=bool(faults)
 for index,i in enumerate(faults):
  block='\n'.join(lines[i:min(i+80,faults[index+1] if index+1<len(faults) else len(lines))])
  if not re.search(r'BUG: KFENCE: out-of-bounds read in (?:__)?memcpy(?:_orig)?(?:\+|\b)',lines[i]) or not re.search(r'\brealloc_wrapper\+[^\n]*\[xt_ndpi\]',block) or not re.search(r'\bndpi_search_tls_memory\+[^\n]*\[xt_ndpi\]',block):known=False
 return {'has_faults':bool(faults),'known_allocator_faults':known,'kernel_fault_count':len(faults)}

def candidate(root,kernel):
 bundle=Path(root)/'assets'/kernel;regular(bundle/'manifest.json')
 m=json.loads((bundle/'manifest.json').read_text())
 osd=dict(l.split('=',1) for l in path('/etc/os-release').read_text().splitlines() if '=' in l)
 if kernel not in SUPPORTED or m.get('kernel')!=kernel or m.get('os_id')!='ubuntu' or m.get('os_version')!=SUPPORTED[kernel] or osd.get('ID','').strip('"')!='ubuntu' or osd.get('VERSION_ID','').strip('"')!=SUPPORTED[kernel] or m.get('arch')!='x86_64' or platform.machine()!='x86_64':raise RuntimeError('Нет точного проверенного сочетания ОС, ядра и архитектуры')
 for name in ['xt_ndpi.ko','libxt_ndpi.so']:
  regular(bundle/name)
  if digest(bundle/name)!=m['sha256'][name]:raise RuntimeError('Контрольная сумма подготовленного модуля или plugin не совпала')
 _,vermagic=command(['modinfo','-F','vermagic',str(bundle/'xt_ndpi.ko')])
 if vermagic!=m['vermagic'] or vermagic.split()[0]!=kernel:raise RuntimeError('ABI подготовленного модуля не совпал')
 return bundle,m

def verified_resume(kernel,sha,boot_id):
 before=path(STATE/'lifecycle/before.json');pending=path(STATE/'pending.json')
 regular(before,0o600);regular(pending,0o600)
 b=json.loads(before.read_text());p=json.loads(pending.read_text())
 expected='/lib/modules/'+kernel+'/updates/dkms/xt_ndpi.ko'
 if b.get('baseline_kind')!='legacy-upgrade' or p.get('kernel')!=kernel or p.get('sha256')!=sha or p.get('module')!=expected or not re.fullmatch('[0-9a-f-]{36}',p.get('staged_boot_id','')) or p['staged_boot_id']==boot_id:raise RuntimeError('Нет подтверждённого перехода на новую загрузку после подготовки модуля')
 txn=Path(p.get('transaction',''))
 if txn.parent!=STATE/'transactions' or not re.fullmatch('[0-9a-f-]{36}',txn.name):raise RuntimeError('Неверная ссылка на прежнюю операцию подготовки')
 regular(path(txn/'committed'))
 if not path(txn/'committed').read_text().startswith('Module staged; running module retained. Reboot required before activation.'):raise RuntimeError('Прежняя операция не подтверждает подготовку модуля')
 return True

def check_legacy(root=ROOT,allow_lifecycle=False,resumed=False):
 lifecycle=path(STATE/'lifecycle/before.json')
 if lifecycle.exists() or lifecycle.is_symlink():
  regular(lifecycle,0o600)
  if not allow_lifecycle or json.loads(lifecycle.read_text()).get('baseline_kind')!='legacy-upgrade':raise RuntimeError('Для этой установки уже существует другой исходный журнал')
 elif resumed:raise RuntimeError('Без исходного журнала продолжение после перезагрузки запрещено')
 for p in ['/etc/systemd/system/ssh.service.d/zz-ds-guard.conf','/etc/systemd/system/suricata.service.d/zz-ds-guard-nfqueue.conf']:
  if path(p).exists() or path(p).is_symlink():raise RuntimeError('Установка ds-guard 2.x не поддерживается этим переносом')
 for name,body in [('ds-guard.service',GUARD_UNIT),('ds-guard-apply.service',APPLY_UNIT)]:
  metadata=regular(path('/etc/systemd/system')/name,text=body)
  if metadata['mode'] not in (0o600,0o644):raise RuntimeError('Неизвестные права прежней службы: '+name)
 installed=path(STATE/'installed.json');regular(installed,0o600)
 installed_data=json.loads(installed.read_text())
 if not re.fullmatch('[0-9a-f]{64}',installed_data.get('sha256','')) or installed_data.get('kernel') not in SUPPORTED:raise RuntimeError('Метаданные прежней установки не соответствуют известному формату')
 helper=path('/usr/local/sbin/ds-guard-ndpi-lib.sh');regular(helper,0o644)
 if not re.search(r'^VERSION=(?:"|\x27)?1\.7\.11(?:"|\x27)?$',helper.read_text(),re.M):raise RuntimeError('Версия прежнего helper не равна проверенной 1.7.11')
 marker=regular(path(MARKER),0o600,MARKER_TEXT)
 holds={str(p):regular(path(p),0o644,HOLD_TEXT) for p in HOLD_PATHS}
 for u in ['ds-guard.service','ds-guard-apply.service','ds-guard.timer']:
  if command(['systemctl','show',u,'-p','ActiveState','--value'])[1]!='inactive':raise RuntimeError('Прежний процесс фильтрации не остановлен: '+u)
 if command(['systemctl','is-enabled','ds-guard.timer'],False)[1]!='disabled':raise RuntimeError('Прежний таймер не отключён')
 if command(['systemctl','is-active','suricata.service'],False)[1]!='active':raise RuntimeError('Suricata не работает')
 queues=path('/proc/net/netfilter/nfnetlink_queue')
 if not queues.exists() or not {0,1}<={int(l.split()[0]) for l in queues.read_text().splitlines()}:raise RuntimeError('Очереди Suricata 0 и 1 не обслуживаются')
 rules=command(['iptables-save'])[1]
 from transaction import validate_managed_scope
 validate_managed_scope(rules)
 tokens=[shlex.split(l) for l in rules.splitlines() if l.startswith('-A ')]
 if any(any(a=='-m' and b=='ndpi' for a,b in zip(t,t[1:])) for t in tokens):raise RuntimeError('В runtime остались правила nDPI; подготовка запрещена')
 dns=any(t[1] in ['DS_DOM_A_D','DS_DOM_B_D'] and '-m' in t and 'string' in t and t[-2:]==['-j','DROP'] for t in tokens)
 jumps={t[1] for t in tokens if '-j' in t and t[t.index('-j')+1]=='DS_DOMAINS'}
 nfq=any(t[1]=='OUTPUT' and '-j' in t and t[t.index('-j')+1]=='NFQUEUE' and '--queue-balance' in t and t[t.index('--queue-balance')+1]=='0:1' and '--queue-bypass' in t for t in tokens)
 layers=dns and nfq and 'OUTPUT' in jumps and bool(jumps&{'FORWARD','DOCKER-USER'})
 kernel=platform.release();bundle,m=candidate(root,kernel);boot_id=path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if resumed:verified_resume(kernel,m['sha256']['xt_ndpi.ko'],boot_id)
 if not layers and not resumed:raise RuntimeError('До подготовки не подтверждены сохранённые DNS и NFQUEUE правила')
 _,resolved=command(['modinfo','-n','xt_ndpi']);disk=Path(resolved)
 module_dir=Path('/lib/modules',kernel,'updates/dkms')
 if disk.parent!=module_dir or disk.name not in ('xt_ndpi.ko','xt_ndpi.ko.xz','xt_ndpi.ko.gz','xt_ndpi.ko.zst'):raise RuntimeError('Неизвестное расположение прежнего модуля')
 disk_path=path(disk)
 # /lib -> /usr/lib is a standard Ubuntu layout; only the module itself must
 # be regular. No destination is changed by this reader.
 if disk_path.is_symlink() or not disk_path.is_file() or disk_path.stat().st_uid!=ROOT_UID:raise RuntimeError('Прежний модуль не является обычным root-файлом')
 module_identity.build_note(disk_path)
 disk_ok=disk.name=='xt_ndpi.ko' and digest(disk_path)==m['sha256']['xt_ndpi.ko']
 plugin=path('/usr/lib/x86_64-linux-gnu/xtables/libxt_ndpi.so');regular(plugin)
 plugin_ok=digest(plugin)==m['sha256']['libxt_ndpi.so']
 loaded=path('/sys/module/xt_ndpi').exists()
 loaded_ok=loaded and module_identity.loaded_matches(bundle/'xt_ndpi.ko')
 loaded_disk=loaded and module_identity.loaded_matches(disk_path)
 note=path('/sys/module/xt_ndpi/notes/.note.gnu.build-id')
 if loaded and not note.is_file():raise RuntimeError('Идентичность загруженного модуля недоступна')
 faults=kernel_log_state(*command(['dmesg'],False))
 if faults['has_faults'] and not (loaded and not loaded_ok and faults['known_allocator_faults']):raise RuntimeError('Ошибки ядра не допускают даже ограниченную подготовку прежней установки')
 return {'legacy_version':'1.7.11','kernel':kernel,'boot_id':boot_id,'holds_present':True,'hold_files':holds,'marker':marker,'marker_path':str(MARKER),
         'resumed':resumed,'two_layers_present':bool(layers),'boot_filter_acceptance':False,'loaded_module':loaded,'disk_candidate':disk_ok,'plugin_candidate':plugin_ok,'loaded_candidate':loaded_ok,'loaded_disk_match':loaded_disk,
         'loaded_note_sha256':digest(note) if loaded else None,'requires_stage':not disk_ok or not plugin_ok,'requires_reboot':loaded and not loaded_ok,'module':str(disk),'module_sha256':m['sha256']['xt_ndpi.ko'],**faults}

def release_hold(root=ROOT,txn=None):
 resumed=path(STATE/'pending.json').exists()
 info=check_legacy(root,allow_lifecycle=True,resumed=resumed)
 if info['has_faults'] or not info['loaded_candidate'] or info['requires_stage']:raise RuntimeError('Запрет не снят: нужны чистая загрузка и точный исправленный модуль в памяти и на диске')
 livepatch=path('/sys/kernel/livepatch/xt_ndpi')
 if not livepatch.is_dir() or (livepatch/'enabled').read_text().strip()!='1' or (livepatch/'transition').read_text().strip()!='0':raise RuntimeError('Безопасный переход livepatch не завершён')
 if txn is None:
  current=path(STATE/'current.json');regular(current,0o600);txn=Path(json.loads(current.read_text())['transaction'])
 else:txn=Path(txn)
 if txn.parent!=STATE/'transactions' or not re.fullmatch('[0-9a-f-]{36}',txn.name):raise RuntimeError('Нет точной операции для возврата запрета')
 before=path(txn/'before.json');regular(before,0o600);files=json.loads(before.read_text())['files']
 for p in HOLD_PATHS:
  if str(p) not in files:raise RuntimeError('Запрет отсутствует в резервной копии операции')
  regular(path(txn/'files'/str(p).lstrip('/')),0o644,HOLD_TEXT)
 removed=[]
 try:
  for p in HOLD_PATHS:
   regular(path(p),0o644,HOLD_TEXT);path(p).unlink();removed.append(p)
  command(['systemctl','daemon-reload'])
 except BaseException:
  for p in removed:
   dest=path(p)
   if dest.exists() or dest.is_symlink():regular(dest,0o644,HOLD_TEXT);continue
   temp=dest.with_name(dest.name+'.restore-'+str(uuid.uuid4()))
   try:
    temp.write_text(HOLD_TEXT);os.chown(temp,info['hold_files'][str(p)]['uid'],info['hold_files'][str(p)]['gid']);temp.chmod(0o644);os.link(temp,dest)
   finally:temp.unlink(missing_ok=True)
  command(['systemctl','daemon-reload'],False)
  raise
 return {**info,'holds_present':False,'hold_released':True,'marker_retained':True,'activation_accepted':False}
