#!/usr/bin/env python3
"""First-use journal and conflict-aware removal of this installer's changes.

The baseline is immutable across repeat runs. No guessed pre-install defaults,
no global firewall restore, no forced livepatch unload and no autoremove.
"""
import argparse,fcntl,hashlib,json,os,re,shlex,shutil,subprocess,time,uuid
from pathlib import Path
from transaction import CHAINS,UNITS,managed_hook,foreign_rules

STATE=Path('/var/lib/ds-guard-safe/lifecycle')
SYSCTLS=['net.netfilter.nf_conntrack_acct']
TREES=['/etc/ds-guard','/usr/local/lib/ds-guard-safe','/usr/local/lib/ds-guard-safe-kernel']
EXACT=['/etc/suricata/suricata.yaml','/etc/suricata/rules/ds-p2p.rules',
 '/etc/systemd/system/suricata.service.d/nfqueue.conf','/etc/modprobe.d/xt_ndpi.conf',
 '/etc/modules-load.d/xt_ndpi.conf','/etc/sysctl.d/99-ds-guard-conntrack.conf',
 '/etc/sysctl.d/99-z-ds-guard-vpn.conf','/etc/modprobe.d/zz-ds-guard-vpn.conf',
 '/etc/modules-load.d/ds-guard-vpn.conf','/usr/lib/x86_64-linux-gnu/xtables/libxt_ndpi.so',
 '/etc/systemd/system/ds-guard-safe-recover.service',
 '/etc/systemd/system/ds-guard-safe-kernel-cleanup.service',
 '/etc/systemd/system/ds-guard-safe-tune-recover.service']
EXACT += ['/usr/local/sbin/ds-guard-'+n+'.sh' for n in ['ndpi-lib','ensure','apply','kprep']]
EXACT += ['/etc/systemd/system/'+n for n in ['ds-guard.service','ds-guard-apply.service','ds-guard.timer','ds-guard-kprep@.service']]
EXACT += ['/etc/kernel/'+n+'/zz-ds-guard' for n in ['postinst.d','header_postinst.d','postrm.d']]
HOLD=Path('/etc/systemd/system/ds-guard.service.d/95-safe-disabled.conf')
APPLY_HOLD=Path('/etc/systemd/system/ds-guard-apply.service.d/95-safe-disabled.conf')
LOAD=Path('/etc/modules-load.d/xt_ndpi.conf')
HOLD_TEXT='[Unit]\nConditionPathExists=!/var/lib/ds-guard-safe/lifecycle/disabled\n'

def run(a,check=True,timeout=60):
 p=subprocess.run(a,capture_output=True,text=True,timeout=timeout,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_SUSPEND':'1'})
 if check and p.returncode:raise RuntimeError('Команда не выполнена: '+a[0]+'; '+p.stderr[-800:])
 return p.stdout.strip()

def save(p,d):
 q=p.with_suffix('.next');q.write_text(json.dumps(d,ensure_ascii=False,indent=2));q.chmod(0o600);q.replace(p)

def stamp(p):
 p=Path(p)
 if p.is_symlink():return {'link':os.readlink(p)}
 if p.is_file():return {'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':p.stat().st_mode&0o777}
 if p.exists():raise RuntimeError('Ожидался обычный файл: '+str(p))
 return None

def paths():
 names=set(EXACT+[str(HOLD),str(APPLY_HOLD)])
 for root in TREES:
  p=Path(root)
  if p.is_symlink():raise RuntimeError('Каталог установщика является ссылкой: '+root)
  if p.exists():names.update(str(f) for f in p.rglob('*') if f.is_file() or f.is_symlink())
 for p in Path('/lib/modules').glob('*/updates/dkms/xt_ndpi.ko*'):names.add(str(p))
 return sorted(names)

def packages():
 rows=run(['dpkg-query','-W','-f=${binary:Package}\t${db:Status-Status}\t${Version}\n']).splitlines()
 return {r.split('\t')[0]:r.split('\t')[2] for r in rows if len(r.split('\t'))==3 and r.split('\t')[1]=='installed'}

def units():return {u:{'active':run(['systemctl','is-active',u],False),'enabled':run(['systemctl','is-enabled',u],False)} for u in UNITS}

def values():
 from network_tuning import KEYS
 result={}
 for k in SYSCTLS+KEYS:
  v=run(['sysctl','-n',k],False)
  if v:result[k]=' '.join(v.split())
 return result

def snapshot():
 installed=packages();names=set(paths())
 if (STATE/'before.json').exists():
  initial=json.loads((STATE/'before.json').read_text())['packages']
  for pkg in set(installed)-set(initial):
   for line in run(['dpkg-query','-W','-f=${Conffiles}',pkg]).splitlines():
    fields=line.split()
    if fields and fields[0].startswith('/'):names.add(fields[0])
  if (STATE/'after.json').exists():names.update(json.loads((STATE/'after.json').read_text())['files'])
 owners={p:[Path(p).lstat().st_uid,Path(p).lstat().st_gid] for p in names if Path(p).is_file() or Path(p).is_symlink()}
 return {'files':{p:stamp(p) for p in sorted(names)},'file_owners':owners,'packages':installed,'manual':run(['apt-mark','showmanual']).splitlines(),
  'units':units(),'values':values(),'iptables':run(['iptables-save']),'kernel':os.uname().release,
  'module_state':{n:Path('/sys/module',n).exists() for n in ['xt_ndpi','tcp_bbr','nf_conntrack']},
  'conntrack_hashsize':Path('/sys/module/nf_conntrack/parameters/hashsize').read_text().strip() if Path('/sys/module/nf_conntrack/parameters/hashsize').exists() else None,'time':time.time()}

def changed_files(before,after):return {p for p in set(before)|set(after) if before.get(p)!=after.get(p)}

def changed_owned(b,a):
 return changed_files(b['files'],a['files'])|changed_files(b.get('file_owners',{}),a.get('file_owners',{}))

def affected_module_kernels(names):
 return {m[1] for n in names if (m:=re.match(r'^/(?:usr/)?lib/modules/([^/]+)/',n))}

def conflicts(original,expected,actual):
 # Changes outside the owned delta are irrelevant. An already restored file
 # is safe and allows interrupted removal to be resumed.
 return sorted(p for p in changed_files(original,expected) if actual.get(p) not in (original.get(p),expected.get(p)))

def begin():
 STATE.mkdir(parents=True,mode=0o700,exist_ok=True)
 if (STATE/'removed.json').exists():
  STATE.rename(STATE.with_name('lifecycle-archive-'+str(uuid.uuid4())))
  STATE.mkdir(mode=0o700)
 if (STATE/'pending.json').exists():raise RuntimeError('Предыдущая операция не завершена; нужен просмотр журнала перед повторным запуском')
 if not (STATE/'before.json').exists():
  # Old installs have no reliable pre-install image. Never pretend an adoption
  # snapshot could remove changes made before this installer was introduced.
  if Path('/etc/systemd/system/ds-guard.service').exists() or Path('/var/lib/ds-guard-safe/installed.json').exists():
   raise RuntimeError('Обнаружена прежняя установка без исходного журнала. Автоматическое полное удаление её изменений недоказуемо; требуется перенос проверенной резервной копии.')
  d=snapshot()
  # Metadata only: detect an unmanaged pre-existing config later claimed by a
  # newly installed dependency without copying unrelated production secrets.
  d['existing_etc_paths']=[str(p) for p in Path('/etc').rglob('*') if p.is_file() or p.is_symlink()]
  (STATE/'files').mkdir(mode=0o700)
  for name,item in d['files'].items():
   if item is None:continue
   target=STATE/'files'/name.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(name,target,follow_symlinks=False)
  save(STATE/'before.json',d);save(STATE/'after.json',d)
 save(STATE/'pending.json',{'started':time.time(),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})

def seal(rc):
 if not (STATE/'pending.json').exists():return
 deadline=time.monotonic()+200;notice=0
 while True:
  busy=[u for u in ['ds-guard-safe-install','ds-guard-safe-recover','ds-guard-safe-kernel-stage','ds-guard-safe-kernel-cleanup','ds-guard-safe-tune','ds-guard-safe-tune-recover'] if run(['systemctl','show',u+'.service','-p','ActiveState','--value'],False) in ('active','activating','deactivating')]
  if not busy:break
  if time.monotonic()>deadline:raise RuntimeError('Рабочий процесс или восстановление ещё выполняется. Исходный журнал сохранён; повторную установку не запускайте.')
  if time.monotonic()>notice:print('[ВОССТАНОВЛЕНИЕ] Ожидание завершения рабочего процесса перед записью результата.',flush=True);notice=time.monotonic()+20
  time.sleep(2)
 initial=json.loads((STATE/'before.json').read_text());loaded_path=STATE/'first-loaded-values.json'
 loaded=json.loads(loaded_path.read_text()) if loaded_path.exists() else {}
 started=initial['time']
 # These are measurements made before the first mutation, not kernel defaults
 # guessed during uninstall. The immutable original snapshot stays unchanged.
 for p in sorted(Path('/var/lib/ds-guard-safe/transactions').glob('*/before.json'),key=lambda p:p.stat().st_mtime):
  d=json.loads(p.read_text())
  if d.get('started',0)>=started and d.get('acct') in ('0','1') and 'net.netfilter.nf_conntrack_acct' not in initial['values']:
   loaded.setdefault('net.netfilter.nf_conntrack_acct',d['acct'])
 for p in sorted(Path('/var/lib/ds-guard-safe/tuning').glob('*/before.json'),key=lambda p:p.stat().st_mtime):
  if p.stat().st_mtime>=started:
   for k,v in json.loads(p.read_text())['values'].items():
    if k not in initial['values']:loaded.setdefault(k,v)
 save(loaded_path,loaded)
 save(STATE/'after.json',snapshot());save(STATE/'last-operation.json',{'exit_code':rc,'time':time.time()})
 (STATE/'pending.json').unlink()

def read_records():
 if not (STATE/'before.json').exists() or not (STATE/'after.json').exists():raise RuntimeError('Нет исходного журнала этой установки. Возврат к предполагаемым значениям запрещён.')
 if (STATE/'pending.json').exists():raise RuntimeError('Есть незавершённая операция. Сначала восстановите её по журналу.')
 b=json.loads((STATE/'before.json').read_text())
 if (STATE/'first-loaded-values.json').exists():
  for k,v in json.loads((STATE/'first-loaded-values.json').read_text()).items():b['values'].setdefault(k,v)
 return b,json.loads((STATE/'after.json').read_text())

def restore_file(name,item):
 p=Path(name)
 owner=None
 if item is not None:
  owner=json.loads((STATE/'before.json').read_text()).get('file_owners',{}).get(name)
  if owner is None:raise RuntimeError('В старом журнале не сохранён владелец файла: '+name)
 if stamp(p)==item and (item is None or [p.lstat().st_uid,p.lstat().st_gid]==owner):return
 if p.is_file() or p.is_symlink():p.unlink()
 if item is not None:
  p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STATE/'files'/name.lstrip('/'),p,follow_symlinks=False)
  os.chown(p,*owner,follow_symlinks=False)
  if not p.is_symlink():p.chmod(item['mode'])
  if [p.lstat().st_uid,p.lstat().st_gid]!=owner:raise RuntimeError('Не восстановлен владелец файла: '+name)
 if stamp(p)!=item:raise RuntimeError('Не удалось проверить восстановленный файл: '+name)

def verify_no_conflict(b,a,actual):
 bad=conflicts(b['files'],a['files'],actual['files'])
 if bad:raise RuntimeError('После установки изменены файлы. Они не будут перезаписаны: '+', '.join(bad[:8]))
 for p in changed_owned(b,a):
  if p in a.get('file_owners',{}) and actual.get('file_owners',{}).get(p) not in (a['file_owners'][p],b.get('file_owners',{}).get(p)):
   raise RuntimeError('После установки изменён владелец файла: '+p)
 for k,v in a['values'].items():
  if b['values'].get(k)!=v and actual['values'].get(k) not in (v,b['values'].get(k)):
   raise RuntimeError('Параметр изменён после установки: '+k)
 for pkg,version in b['packages'].items():
  if a['packages'].get(pkg)!=version:raise RuntimeError('Установка изменила ранее существовавший пакет; требуется отдельный возврат: '+pkg)
 def owned_rules(text):
  return [l for l in text.splitlines() if l.startswith('-A ') and (managed_hook(l) or shlex.split(l)[1] in CHAINS)]
 if owned_rules(actual['iptables']) not in (owned_rules(a['iptables']),owned_rules(b['iptables'])):
  raise RuntimeError('Собственные цепочки фильтрации изменились после установки. Нужна проверка их текущего владельца.')

def detach_rules():
 before=run(['iptables-save']);foreign=foreign_rules(before)
 for line in before.splitlines():
  if managed_hook(line):
   p=shlex.split(line);p[0]='-D';run(['iptables','-w','5',*p])
 if foreign_rules(run(['iptables-save']))!=foreign:raise RuntimeError('Изменились посторонние правила firewall')

def guard_changed(b,a):
 p='/etc/systemd/system/ds-guard.service'
 return b['files'].get(p)!=a['files'].get(p)

def runtime_reboot_needed(b):
 if 'module_state' not in b:return Path('/sys/module/xt_ndpi').exists()
 if any(not loaded and Path('/sys/module',n).exists() for n,loaded in b['module_state'].items()):return True
 p=Path('/sys/module/nf_conntrack/parameters/hashsize')
 return b.get('conntrack_hashsize') is not None and p.exists() and p.read_text().strip()!=b['conntrack_hashsize']

def disable():
 b,a=read_records();now=snapshot();verify_no_conflict(b,a,now)
 if (STATE/'disabled').exists():print('[ОТКЛЮЧЕНО] Повторное отключение не требуется.');return 0
 guard=guard_changed(b,a)
 if guard and any(managed_hook(l) for l in b['iptables'].splitlines()):raise RuntimeError('В исходном состоянии уже есть ds-guard; отключение требует отдельного плана сохранения прежней защиты')
 if guard:
  for p in [HOLD,APPLY_HOLD]:
   if p.exists() and p.read_text()!=HOLD_TEXT:raise RuntimeError('Занят файл запрета автозапуска: '+str(p))
 if guard:
  run(['systemctl','stop','ds-guard.timer','ds-guard-apply.service','ds-guard.service'],False)
  run(['systemctl','disable','ds-guard.timer','ds-guard.service'],False)
  detach_rules()
  for p in [HOLD,APPLY_HOLD]:p.parent.mkdir(parents=True,exist_ok=True);p.write_text(HOLD_TEXT);p.chmod(0o644)
 (STATE/'disabled').write_text('Фильтрация отключена владельцем\n')
 if guard:restore_file(str(LOAD),b['files'].get(str(LOAD)))
 # The NFQUEUE override belongs to ds-guard; restore a pre-existing Suricata
 # instance or stop a newly installed instance after all owned hooks are gone.
 suri='/etc/systemd/system/suricata.service.d/nfqueue.conf'
 if guard:
  restore_file(suri,b['files'].get(suri));run(['systemctl','daemon-reload'])
  if b['units']['suricata.service']['active']=='active':run(['systemctl','restart','suricata.service'])
  else:run(['systemctl','stop','suricata.service'],False);run(['systemctl','disable','suricata.service'],False)
 # Disable also suspends the network profile. Kernel selection is untouched.
 for name in ['/etc/sysctl.d/99-z-ds-guard-vpn.conf','/etc/modprobe.d/zz-ds-guard-vpn.conf','/etc/modules-load.d/ds-guard-vpn.conf','/etc/sysctl.d/99-ds-guard-conntrack.conf']:
  if name in changed_owned(b,a):restore_file(name,b['files'].get(name))
 for k,v in b['values'].items():
  if a['values'].get(k)!=v:run(['sysctl','-w',k+'='+v])
 if guard:assert not any(managed_hook(l) for l in run(['iptables-save']).splitlines())
 save(STATE/'after.json',snapshot())
 print('[ОТКЛЮЧЕНО] '+('Фильтрация и её автозапуск остановлены; исходные сетевые значения восстановлены.' if guard else 'Собственный сетевой профиль отменён. Фильтрация не входила в эту установку.')+' Для возврата ядра используйте удаление с отдельной загрузкой прежнего ядра.')
 if runtime_reboot_needed(b):print('[НУЖНА ПЕРЕЗАГРУЗКА] Для полного возврата состава загруженных модулей или размера хеш-таблицы conntrack требуется отдельная плановая перезагрузка.')
 return 0

def enable_prepare():
 # Re-enable is the normal verified install path. Merely starting services
 # would skip identity checks, health acceptance and rollback protection.
 if not (STATE/'disabled').exists():return
 b,a=read_records();verify_no_conflict(b,a,snapshot())
 for p in [HOLD,APPLY_HOLD]:
  if p.exists() and p.read_text()!=HOLD_TEXT:raise RuntimeError('Изменён запрет автозапуска: '+str(p))
 for p in [HOLD,APPLY_HOLD]:p.unlink(missing_ok=True)
 (STATE/'disabled').unlink();run(['systemctl','daemon-reload'])

def removal_plan():
 if run(['dpkg','--audit']):raise RuntimeError('Есть незавершённая операция пакетного менеджера. Сначала требуется её восстановление.')
 b,a=read_records();now=snapshot();verify_no_conflict(b,a,now)
 owned={p:v for p,v in a['packages'].items() if p not in b['packages']}
 for p,v in owned.items():
  if p in now['packages'] and now['packages'][p]!=v:raise RuntimeError('Пакет обновлён после установки: '+p)
 for path in changed_files(b['files'],a['files']):
  if path in b.get('existing_etc_paths',[]) and b['files'].get(path) is None:
   raise RuntimeError('Новый пакет использует прежний файл без резервной копии; его удаление остановлено: '+path)
 remove=sorted(set(owned)&set(now['packages']))
 kernels=sorted({p[len('linux-image-'):].split(':')[0] for p in remove if p.startswith('linux-image-')})
 active=os.uname().release
 bootenv=run(['grub-editenv','/boot/grub/grubenv','list'],False)
 blocked=[k for k in kernels if k==active or k in bootenv]
 if remove:
  sim=run(['apt-get','-s','purge',*remove],timeout=120)
  removals={m[1] for m in re.finditer(r'^(?:Remv|Purg)\s+(\S+)',sim,re.M)}
  if {p.split(':')[0] for p in removals}-{p.split(':')[0] for p in remove}:raise RuntimeError('Удаление затрагивает пакеты вне установки. Автоматическое удаление остановлено.')
 return b,a,now,remove,kernels,blocked

def remove(plan=False):
 if (STATE/'removed.json').exists():
  print('[УДАЛЕНО] Установка уже удалена. Повторное удаление не требуется.');return 0
 b,a,now,pkgs,kernels,blocked=removal_plan()
 print('Будут восстановлены изменённые установщиком файлы и параметры. Пакеты к удалению: '+(', '.join(pkgs) or 'нет'),flush=True)
 if blocked:
  print('[НУЖНА ПЕРЕЗАГРУЗКА] Сначала выберите и загрузите сохранённое прежнее ядро '+b['kernel']+', проверьте сервер и повторите удаление. Сейчас используется или выбрано для загрузки: '+', '.join(blocked));return 20
 if plan:print('[ПЛАН] Изменений не выполнено.');return 0
 guard=guard_changed(b,a);disable();b,a=read_records()
 # Keep the immutable baseline and audit evidence even after uninstall.
 if guard:
  run(['systemctl','stop','ds-guard.timer','ds-guard-apply.service','ds-guard.service'],False)
  detach_rules();foreign=foreign_rules(run(['iptables-save']))
  for chain in CHAINS:run(['iptables','-w','5','-F',chain],False)
  for chain in CHAINS:run(['iptables','-w','5','-X',chain],False)
  if foreign_rules(run(['iptables-save']))!=foreign:raise RuntimeError('Изменились чужие правила firewall')
 # Restore hooks before package removal so no ds-guard hook is invoked.
 changes=changed_owned(b,a)
 for name in sorted(changes):restore_file(name,b['files'].get(name))
 run(['systemctl','daemon-reload'])
 if pkgs:run(['apt-get','-y','-o','APT::Get::AutomaticRemove=false','purge',*pkgs],timeout=900)
 # dpkg may delete a restored package config while purging its new package.
 for name in sorted(changes):restore_file(name,b['files'].get(name))
 for k,v in b['values'].items():
  if a['values'].get(k)!=v:run(['sysctl','-w',k+'='+v])
 for kernel in affected_module_kernels(changes):
  if Path('/boot/vmlinuz-'+kernel).exists():run(['depmod','-a',kernel],timeout=90)
 run(['systemctl','daemon-reload'])
 for u,state in b['units'].items():
  if not guard:continue
  if a['units'].get(u)==state:continue
  run(['systemctl','enable' if state['enabled']=='enabled' else 'disable',u],False)
  if state['active']=='active':run(['systemctl','restart',u])
  else:run(['systemctl','stop',u],False)
 remaining=packages()
 initial_manual=set(b['manual']);after_manual=set(a['manual']);live_manual=set(run(['apt-mark','showmanual']).splitlines())
 for pkg in (initial_manual^after_manual)&set(remaining):
  if (pkg in live_manual)!=(pkg in after_manual):raise RuntimeError('После установки изменена отметка APT: '+pkg)
  run(['apt-mark','manual' if pkg in initial_manual else 'auto',pkg])
 if set(pkgs)&set(remaining):raise RuntimeError('Некоторые пакеты не удалены')
 if run(['dpkg','--audit']):raise RuntimeError('Пакетный менеджер не подтвердил завершение удаления')
 for pkg in pkgs:
  if run(['dpkg-query','-W','-f=${db:Status-Status}',pkg],False) not in ('','not-installed'):
   raise RuntimeError('Удаление пакета не завершено: '+pkg)
 for name in changes:
  if stamp(name)!=b['files'].get(name):raise RuntimeError('Файл не восстановлен: '+name)
 (STATE/'disabled').unlink(missing_ok=True)
 archive=STATE/'removed-metadata';archive.mkdir(mode=0o700,exist_ok=True)
 for name in ['installed.json','pending.json','current.json']:
  p=STATE.parent/name
  if p.exists():p.replace(archive/name)
 loaded=runtime_reboot_needed(b)
 save(STATE/'removed.json',{'time':time.time(),'packages_removed':pkgs,'files_restored':True,'loaded_module_requires_reboot':loaded})
 print('[УДАЛЕНО] Файлы и пакеты установки удалены, прежние настройки восстановлены. Журнал и резервные копии сохранены в '+str(STATE))
 if loaded:print('[НУЖНА ПЕРЕЗАГРУЗКА] Для окончательного возврата загруженных модулей/conntrack нужна отдельная плановая перезагрузка.');return 20
 return 0

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['begin','seal','disable','remove','enable-prepare']);ap.add_argument('--code',type=int,default=0);ap.add_argument('--plan',action='store_true');args=ap.parse_args()
 if os.geteuid():raise SystemExit('Требуются права root')
 with Path('/run/ds-guard-safe-lifecycle.lock').open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if args.mode=='begin':begin()
  elif args.mode=='seal':seal(args.code)
  elif args.mode=='enable-prepare':enable_prepare()
  elif args.mode=='disable':raise SystemExit(disable())
  elif args.mode=='remove':raise SystemExit(remove(args.plan))
