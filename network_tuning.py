#!/usr/bin/env python3
"""Scoped VPN sysctl profile; an independent timer restores an unaccepted change."""
import argparse,base64,contextlib,fcntl,json,os,re,shutil,subprocess,sys,time,uuid
from pathlib import Path

BASE=Path('/var/lib/ds-guard-safe/tuning')
MARKER='# Настройки сети ds-guard-safe\n'
FILES=[Path('/etc/sysctl.d/99-z-ds-guard-vpn.conf'),Path('/etc/modprobe.d/zz-ds-guard-vpn.conf'),Path('/etc/modules-load.d/ds-guard-vpn.conf')]
KEYS=['net.core.default_qdisc','net.ipv4.tcp_congestion_control','net.core.rmem_max','net.core.wmem_max','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.core.netdev_max_backlog','net.core.somaxconn','net.ipv4.tcp_max_syn_backlog','net.ipv4.tcp_fastopen','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_slow_start_after_idle','net.ipv4.tcp_fin_timeout','net.ipv4.tcp_tw_reuse','net.netfilter.nf_conntrack_max']

def run(a,timeout=30):
 return subprocess.check_output(a,text=True,stderr=subprocess.PIPE,timeout=timeout).strip()

def desired_values(current,ram_mib):
 """Do not reduce existing buffer/queue/conntrack capacity."""
 buf=67108864 if ram_mib>=8000 else 16777216
 ct=262144 if ram_mib<=2500 else 524288 if ram_mib<=5000 else 1048576
 d={'net.core.default_qdisc':'fq','net.ipv4.tcp_congestion_control':'bbr','net.ipv4.tcp_slow_start_after_idle':'0','net.ipv4.tcp_fin_timeout':'15','net.ipv4.tcp_tw_reuse':'1'}
 for k,n in [('net.core.rmem_max',buf),('net.core.wmem_max',buf),('net.core.netdev_max_backlog',16384),('net.core.somaxconn',16384),('net.ipv4.tcp_max_syn_backlog',8192),('net.netfilter.nf_conntrack_max',ct),('net.ipv4.tcp_mtu_probing',1)]:
  d[k]=str(max(int(current[k]),n))
 d['net.ipv4.tcp_fastopen']=str(int(current['net.ipv4.tcp_fastopen'])|3)
 for k in ['net.ipv4.tcp_rmem','net.ipv4.tcp_wmem']:
  a,b,c=map(int,current[k].split());a=max(a,4096);b=max(a,b,131072);c=max(b,c,buf)
  d[k]=f'{a} {b} {c}'
 return d

def norm(v):return ' '.join(v.split())
def save(p,d):
 q=p.with_suffix('.next');q.write_text(json.dumps(d,ensure_ascii=False,indent=2));q.chmod(0o600);q.replace(p)

def network_state():
 def canonical(args,skip=()):
  data=json.loads(run(args))
  return sorted(json.dumps({k:v for k,v in r.items() if k not in skip},sort_keys=True) for r in data)
 return {'routes':canonical(['ip','-j','route','show','table','all'],('expires','flags')),'rules':run(['ip','-j','rule']),
         'firewall':[re.sub(r'\[\d+:\d+\]','[COUNTERS]',x) for x in run(['iptables-save']).splitlines() if x and not x.startswith('#')],
         'qdisc':canonical(['tc','-j','qdisc','show'],('refcnt',)),
         'listeners':sorted({tuple(x.split()[3:5]) for x in run(['ss','-Hlnpt']).splitlines() if len(x.split())>=5})}

def valid_txn(p):
 p=Path(p).resolve()
 if p.parent!=BASE or not re.fullmatch('[0-9a-f-]+',p.name):raise RuntimeError('Недопустимый путь операции')
 return p

@contextlib.contextmanager
def state_lock():
 # Separate from the launch lock: its owner waits for systemd, whose OnFailure
 # recovery must be able to run. Serialize pending ownership before stopping a
 # worker, including the short handoff between two consecutive operations.
 with (BASE/'state.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  yield

def pending_transaction():
 pending=BASE/'pending.json'
 return json.loads(pending.read_text()).get('transaction') if pending.exists() else None

def clear_pending(p):
 # Caller holds state_lock. Never clear the next operation's recovery pointer.
 if pending_transaction()==str(p):(BASE/'pending.json').unlink()

def stop_timer(p):
 subprocess.run(['systemctl','stop','ds-guard-tuning-rollback-'+p.name+'.timer'],capture_output=True,timeout=35)

def regular_path(p):
 # Do not follow either the final symlink or an exchanged parent directory when
 # writing or restoring root-owned configuration. Missing files are allowed.
 if p.is_symlink() or any(parent.is_symlink() for parent in p.parents):raise RuntimeError('Обнаружена символическая ссылка вместо файла настройки: '+str(p))
 if p.exists() and not p.is_file():raise RuntimeError('Ожидался обычный файл настройки: '+str(p))

def lifecycle_operation_id():
 pending=Path('/var/lib/ds-guard-safe/lifecycle/pending.json')
 return json.loads(pending.read_text()).get('operation_id') if pending.exists() else None

def rollback(p,force=False):
 p=valid_txn(p)
 if (p/'rolled-back.json').exists() or (p/'accepted.json').exists() and not force:return
 d=json.loads((p/'before.json').read_text())
 if d['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise RuntimeError('После перезагрузки нужен отдельный план возврата')
 for name,item in d['files'].items():
  regular_path(Path(name))
  if item is not None and not {'uid','gid'}<=item.keys():raise RuntimeError('В прежнем журнале нет владельца файла; требуется отдельный проверенный возврат: '+name)
 for k,v in d['values'].items():run(['sysctl','-w',k+'='+v])
 for name,item in d['files'].items():
  f=Path(name)
  if item is None:
   if f.exists():f.unlink()
  else:
   f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(base64.b64decode(item['data']));os.chown(f,item['uid'],item['gid']);f.chmod(item['mode'])
 assert all(norm(run(['sysctl','-n',k]))==norm(v) for k,v in d['values'].items())
 for name,item in d['files'].items():
  f=Path(name);assert not f.exists() if item is None else f.read_bytes()==base64.b64decode(item['data'])
  if item is not None:assert (f.stat().st_mode&0o777,f.stat().st_uid,f.stat().st_gid)==(item['mode'],item['uid'],item['gid'])
 save(p/'rolled-back.json',{'time':time.time(),'runtime_and_owned_files_restored':True,'values':d['values'],'operation_id':d.get('operation_id')})
 latest=BASE/'current.json'
 if latest.exists() and json.loads(latest.read_text()).get('transaction')==str(p):
  save(latest,{'transaction':str(p),'rolled_back':True,'time':time.time()})

def execute(health_command=None):
 if os.geteuid():raise RuntimeError('Требуются права root')
 container=subprocess.run(['systemd-detect-virt','--container'],capture_output=True,text=True)
 if container.returncode==0:raise RuntimeError('Контейнер или WSL не поддерживается')
 for f in FILES:
  regular_path(f)
  if f.exists() and not f.read_text().startswith(MARKER):raise RuntimeError('Существующий файл не принадлежит установщику: '+str(f))
 for command in ['sysctl','ip','tc','ss','iptables-save','systemd-run','curl','modprobe']:
  if not shutil.which(command):raise RuntimeError('Не найдена обязательная команда: '+command)
 if re.search(r'BUG:|UBSAN:|Oops:|WARNING: CPU|Kernel panic|Out of memory',run(['dmesg'])):raise RuntimeError('В текущей загрузке есть ошибки ядра')
 BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
 with (BASE/'lock').open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  run(['modprobe','nf_conntrack']);run(['modprobe','tcp_bbr'])
  if 'bbr' not in run(['sysctl','-n','net.ipv4.tcp_available_congestion_control']).split():raise RuntimeError('BBR недоступен в этом ядре')
  current={k:norm(run(['sysctl','-n',k])) for k in KEYS}
  ram=int(re.search(r'^MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])//1024
  values=desired_values(current,ram)
  before={'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'values':current,'requested_values':values,'operation_id':lifecycle_operation_id(),'started':time.time(),'network':network_state(),
          'files':{str(f):None if not f.exists() else {'data':base64.b64encode(f.read_bytes()).decode(),'mode':f.stat().st_mode&0o777,'uid':f.stat().st_uid,'gid':f.stat().st_gid} for f in FILES}}
  p=BASE/str(uuid.uuid4());p.mkdir(mode=0o700);save(p/'before.json',before);shutil.copy2(__file__,p/'network_tuning.py')
  timer='ds-guard-tuning-rollback-'+p.name
  with state_lock():
   if pending_transaction() is not None:raise RuntimeError('Предыдущая настройка сети ещё требует восстановления')
   save(BASE/'pending.json',{'transaction':str(p)})
  run(['systemd-run','--unit='+timer,'--on-active=5m','/usr/bin/python3',str(p/'network_tuning.py'),'--recover',str(p)])
  settled=False
  try:
   live_hash=int(Path('/sys/module/nf_conntrack/parameters/hashsize').read_text())
   future_hash=max(live_hash,int(values['net.netfilter.nf_conntrack_max'])//4)
   content=[MARKER+'\n'.join(k+' = '+v for k,v in values.items())+'\n',MARKER+f'options nf_conntrack hashsize={future_hash}\n',MARKER+'nf_conntrack\n']
   for f,t in zip(FILES,content):
    f.parent.mkdir(parents=True,exist_ok=True);f.write_text(t);f.chmod(0o644)
   for k,v in values.items():run(['sysctl','-w',k+'='+v])
   assert all(norm(run(['sysctl','-n',k]))==norm(v) for k,v in values.items()),'Проверка значений sysctl не пройдена'
   after=network_state()
   for k in ['routes','rules','firewall','qdisc']:assert before['network'][k]==after[k],'Изменилось состояние сети: '+k
   assert set(map(tuple,before['network']['listeners']))<=set(map(tuple,after['listeners'])),'Исчез существующий TCP-слушатель'
   run(['curl','--noproxy','*','-fsS','--max-time','15','https://www.google.com/generate_204'],timeout=20)
   if health_command:run(['/bin/bash','-c',health_command],timeout=120)
   if re.search(r'BUG:|UBSAN:|Oops:|WARNING: CPU|Kernel panic|Out of memory',run(['dmesg'])):raise RuntimeError('После настройки обнаружена ошибка ядра')
   assert before['boot_id']==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
   result={'transaction':str(p),'values':values,'operation_id':before['operation_id'],'network_preserved':True,'strict_https':True,'operator_health_checked':bool(health_command),'hashsize_live':live_hash,'hashsize_after_reboot':future_hash,'reboot_required_for_hashsize':live_hash!=future_hash,'kernel':os.uname().release,'time':time.time()}
   save(p/'accepted.json',result);save(BASE/'current.json',result);settled=True
   print('Сетевой профиль применён и проверен. Ограничители скорости, маршруты и firewall сохранены.')
   if live_hash!=future_hash:print('Размер хеш-таблицы conntrack подготовлен для следующей отдельной перезагрузки.')
   print('Операция: '+str(p));return 0
  except subprocess.TimeoutExpired:
   # Let systemd kill the entire worker cgroup before OnFailure recovery.
   # A timed-out shell could otherwise leave a child racing the restoration.
   raise
  except BaseException:
   rollback(p);settled=True;raise
  finally:
   if settled:
    stop_timer(p)
    with state_lock():clear_pending(p)

def recover(p=None):
 # A delayed timer from an earlier operation must not stop the current worker.
 # Keep ownership stable until the old worker's cgroup is stopped and restored;
 # launch and worker completion use this same short state lock.
 with state_lock():
  pending=pending_transaction()
  if p is None:
   if pending is None:return
   p=pending
  p=valid_txn(p)
  terminal=(p/'rolled-back.json').exists() or (p/'accepted.json').exists()
  if terminal:
   stop_timer(p);clear_pending(p);return
  if pending!=str(p):raise RuntimeError('Операция восстановления не совпадает с текущей настройкой сети; работающий процесс не остановлен')
  stopped=subprocess.run(['systemctl','stop','ds-guard-safe-tune.service'],capture_output=True,timeout=35)
  if stopped.returncode:raise RuntimeError('Не удалось остановить рабочий процесс настройки сети; восстановление не начато')
  with (BASE/'lock').open('w') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX);rollback(p)
  if (p/'rolled-back.json').exists() or (p/'accepted.json').exists():
   stop_timer(p);clear_pending(p)

def launch(health_command=None):
 BASE.mkdir(parents=True,mode=0o700,exist_ok=True)
 with state_lock():args=prepare_launch(health_command)
 return subprocess.run(args).returncode

def prepare_launch(health_command=None):
 for u in ['ds-guard-safe-install','ds-guard-safe-recover','ds-guard-safe-kernel-stage','ds-guard-safe-kernel-cleanup','ds-guard-safe-tune','ds-guard-safe-tune-recover']:
  state=subprocess.run(['systemctl','show',u+'.service','-p','ActiveState','--value'],capture_output=True,text=True).stdout.strip()
  if state in ('active','activating','deactivating'):raise RuntimeError('Уже выполняется установка или восстановление')
 if (BASE/'pending.json').exists():raise RuntimeError('Сначала завершите восстановление предыдущей настройки сети')
 helper=BASE/'network_tuning.py'
 unit=Path('/etc/systemd/system/ds-guard-safe-tune-recover.service')
 unit_text='[Unit]\nDescription=Restore interrupted ds-guard network tuning\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(helper)+' --recover-current\nTimeoutStartSec=120\n'
 regular_path(helper);regular_path(unit)
 if unit.exists() and unit.read_text()!=unit_text:raise RuntimeError('Существующая служба восстановления не принадлежит установщику: '+str(unit))
 if helper.exists() and not helper.read_text().startswith('#!/usr/bin/env python3\n"""Scoped VPN sysctl profile; an independent timer restores an unaccepted change."""\n'):raise RuntimeError('Существующий файл восстановления не принадлежит установщику: '+str(helper))
 shutil.copy2(__file__,helper);unit.write_text(unit_text)
 unit.chmod(0o644);run(['systemctl','daemon-reload'])
 subprocess.run(['systemctl','reset-failed','ds-guard-safe-tune.service'],capture_output=True)
 args=['systemd-run','--unit=ds-guard-safe-tune','--wait','--collect','--property=Type=oneshot','--property=TimeoutStartSec=240','--property=TimeoutStopSec=15','--property=KillMode=control-group','--property=OnFailure=ds-guard-safe-tune-recover.service','/usr/bin/python3',str(helper),'--worker']
 if health_command:args+=['--health-command',health_command]
 return args

if __name__=='__main__':
 a=argparse.ArgumentParser(description='Настройка сети VPN с проверкой и возвратом прежних значений')
 a.add_argument('--health-command');a.add_argument('--rollback');a.add_argument('--restore-accepted',action='store_true');a.add_argument('--worker',action='store_true');a.add_argument('--recover');a.add_argument('--recover-current',action='store_true');args=a.parse_args()
 if args.recover or args.recover_current:recover(args.recover);sys.exit(0)
 if args.worker:sys.exit(execute(args.health_command))
 with Path('/run/ds-guard-safe-launch.lock').open('w') as launch_lock:
  fcntl.flock(launch_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.rollback:
   p=valid_txn(args.rollback)
   with (BASE/'lock').open('w') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX);rollback(p,args.restore_accepted)
  else:sys.exit(launch(args.health_command))
