#!/usr/bin/env python3
"""Russian operator interface. Select only exact, catalogued kernel bundles."""
import argparse,fcntl,hashlib,json,os,platform,re,shutil,subprocess,sys,time,uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parent
STATE=Path('/var/lib/ds-guard-safe')
ASSET_BASE='https://github.com/ialexisizotov-ctrl/ds-guard-xanmod/releases/download/v1.7.11-dsg1/'
V2={'cx16','lahf_lm','popcnt','pni','sse4_1','sse4_2','ssse3'}
V3=V2|{'avx','avx2','bmi1','bmi2','f16c','fma','movbe','xsave'}

class Refusal(Exception):pass
class Parser(argparse.ArgumentParser):
 def error(self,message):
  self.print_help();raise Refusal('Недопустимые параметры запуска. Проверьте список режимов выше.')

def version_key(s):
 match=re.match(r'\d+(?:\.\d+)*',s)
 if not match:raise Refusal('Не удалось определить версию ядра: '+s)
 numbers=tuple(int(x) for x in match[0].split('.'))
 abi=re.match(r'-(\d+)(?:-|$)',s[match.end():])
 return numbers+(int(abi[1]),) if abi else numbers
def cpu_flags(text):
 sets=[set(s.split()) for s in re.findall(r'^flags\s*:\s*(.*)$',text,re.M)]
 return set.intersection(*sets) if sets else set()

def choose_kernel(catalog,os_id,os_version,flags,current,policy,loaded_modules=()):
 if os_id!='ubuntu' or os_version not in ('22.04','24.04'):raise Refusal('Для этой ОС нет проверенной сборки.')
 if policy=='keep':return current,'Сохраняется текущее ядро.'
 candidates=[]
 for k,m in catalog.items():
  if m.get('os_version','24.04')!=os_version:continue
  if set(m.get('unsupported_loaded_modules',()))&set(loaded_modules):continue
  needed=V3 if m['cpu_level']=='x86-64-v3' else V2 if m['cpu_level']=='x86-64-v2' else set()
  if needed<=flags:candidates.append(k)
 xan=[k for k in candidates if catalog[k].get('kind','xanmod')=='xanmod']
 ubuntu=[k for k in candidates if catalog[k].get('kind')=='ubuntu']
 if policy in ('prefer-xanmod','xanmod') and xan:
  selected=max(xan,key=version_key)
  if version_key(current)>version_key(selected):raise Refusal('Текущее ядро новее проверенного каталога. Автоматическое понижение версии запрещено; выберите сохранение ядра или обновите каталог после проверки новой сборки.')
  return selected,'Выбрана последняя проверенная сборка XanMod для этой ОС и процессора.'
 if policy=='xanmod':raise Refusal('Подходящей проверенной сборки XanMod для этой ОС, процессора и загруженных драйверов нет. Выберите Ubuntu или автоматический выбор.')
 if ubuntu:
  selected=max(ubuntu,key=version_key)
  if policy=='prefer-xanmod' and version_key(current)>version_key(selected):raise Refusal('Резервное Ubuntu-ядро старее работающего. Автоматическое понижение версии запрещено; требуется обновлённый проверенный каталог.')
  return selected,('XanMod недоступен для этой ОС, процессора или загруженных драйверов; выбран проверенный Ubuntu.' if policy=='prefer-xanmod' else 'Выбрано последнее проверенное Ubuntu-ядро из каталога.')
 raise Refusal('Подходящего проверенного ядра нет. Изменения не начаты.')

def command(a,timeout=25):
 p=subprocess.run(a,capture_output=True,text=True,timeout=timeout)
 return p.returncode,p.stdout.strip(),p.stderr.strip()

def system_info():
 osd=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
 return {'os_id':osd.get('ID','').strip('"'),'os_version':osd.get('VERSION_ID','').strip('"'),'kernel':platform.release(),'architecture':platform.machine(),'flags':cpu_flags(Path('/proc/cpuinfo').read_text()),'loaded_modules':{l.split()[0] for l in Path('/proc/modules').read_text().splitlines()}}

def package_specs(m):
 return m.get('packages') or [{'filename':m[k],'sha256':m[k+'_sha256'],'url':ASSET_BASE+m[k]} for k in ['image','headers']]

def result_message(rc,kind):
 if rc==0:return '[ГОТОВО] '+{'guard':'Модуль и три слоя ds-guard проверены.','kernel':'Пакеты ядра подготовлены.','tune':'Сетевые параметры применены и проверены.','disable':'Фильтрация отключена.','remove':'Удаление завершено.'}[kind]
 if rc==20:return '[НУЖНА ПЕРЕЗАГРУЗКА] Новый модуль подготовлен, но ещё не загружен. Выполните отдельную плановую перезагрузку и повторите установку.'
 if rc==75:return '[ЗАНЯТО] Уже выполняется установка или восстановление. Дождитесь её завершения.'
 if rc==78:return '[ОСТАНОВЛЕНО] Система не прошла проверку совместимости или безопасности. Подробности записаны в журнал.'
 return '[ОШИБКА] Шаг не завершён. Не считайте установку успешной; проверьте журнал и результат возврата прежних настроек.'

def run_step(args,title,log):
 print('[ВЫПОЛНЯЕТСЯ] '+title,flush=True)
 with log.open('a') as out:
  p=subprocess.Popen(args,stdout=out,stderr=subprocess.STDOUT)
  while True:
   try:return p.wait(timeout=20)
   except subprocess.TimeoutExpired:print('[ВЫПОЛНЯЕТСЯ] '+title+'; подробности: '+str(log),flush=True)

def download_kernel(kernel,m,log):
 directory=Path('/var/cache/ds-guard-safe/kernels')/kernel;directory.mkdir(mode=0o700,parents=True,exist_ok=True)
 for item in package_specs(m):
  name=item['filename']
  if Path(name).name!=name or not re.fullmatch('[A-Za-z0-9._+~%-]+',name):raise Refusal('Недопустимое имя пакета в каталоге.')
  dest=directory/name
  if dest.is_symlink():raise Refusal('В каталоге загрузок обнаружена символическая ссылка.')
  if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest()==item['sha256']:continue
  temp=dest.with_suffix(dest.suffix+'.part')
  if temp.is_symlink():raise Refusal('Недопустимый временный файл загрузки.')
  rc=run_step(['curl','--proto','=https','--proto-redir','=https','--tlsv1.2','-fLSs','--connect-timeout','15','--max-time','600',item['url'],'-o',str(temp)],'Загрузка пакета '+name,log)
  if rc or not temp.exists() or hashlib.sha256(temp.read_bytes()).hexdigest()!=item['sha256']:
   if temp.is_file():temp.unlink()
   raise Refusal('Пакет не загружен или его контрольная сумма не совпала. Установка ядра не начата.')
  temp.replace(dest)
 return directory

def status():
 info=system_info();print('Текущее ядро: '+info['kernel'])
 guard_present=Path('/etc/systemd/system/ds-guard.service').exists()
 stopped=(STATE/'lifecycle/disabled').exists() or (STATE/'lifecycle/removed.json').exists()
 if (STATE/'lifecycle/removed.json').exists():print('Установка: удалена; журнал и резервные копии сохранены.')
 elif (STATE/'lifecycle/disabled').exists():print('Установка: отключена владельцем; автоматический запуск фильтрации запрещён.')
 units={u:command(['systemctl','is-active',u])[1] for u in ['ds-guard.service','suricata.service','ds-guard.timer']}
 for u,state in units.items():print(u+': '+{'active':'работает','inactive':'не запущена','failed':'ошибка запуска','activating':'запускается','deactivating':'останавливается'}.get(state,'состояние не определено'))
 loaded=Path('/sys/module/xt_ndpi').exists();same=False
 if loaded:
  from module_identity import loaded_matches
  rc,path,_=command(['modinfo','-n','xt_ndpi'])
  if rc==0:same=loaded_matches(Path(path))
 print('Модуль nDPI: '+('загружен, совпадает с файлом на диске' if same else 'загружен, соответствие файлу не подтверждено' if loaded else 'не загружен'))
 queues=Path('/proc/net/netfilter/nfnetlink_queue')
 present={int(x.split()[0]) for x in queues.read_text().splitlines()} if queues.exists() else set()
 print('Очереди Suricata: '+('0 и 1 обслуживаются' if {0,1}<=present else 'полная готовность не подтверждена'))
 for key,label in [('net.ipv4.tcp_congestion_control','Алгоритм TCP'),('net.core.default_qdisc','Очередь для новых интерфейсов'),('net.netfilter.nf_conntrack_max','Лимит conntrack')]:
  rc,value,_=command(['sysctl','-n',key]);print(label+': '+(value if rc==0 else 'недоступно'))
 rc,dm,_=command(['dmesg']);from preflight import kernel_diagnostic_errors
 fault=kernel_diagnostic_errors(rc,dm)
 print('Ошибки ядра: '+('требуют проверки или журнал недоступен' if fault else 'не обнаружены в текущей загрузке'))
 staged=[]
 for p in (STATE/'kernel').glob('*.staged.json'):
  k=json.loads(p.read_text())['candidate']
  if k!=info['kernel'] and Path('/boot/vmlinuz-'+k).exists():staged.append(k)
 for k in staged:print('[ПОДГОТОВЛЕНО] Ядро '+k+' установлено рядом с прежним и ещё не запущено.')
 if not guard_present:print('ds-guard: в текущем состоянии не установлен; отсутствие его служб не является ошибкой установки только ядра или сети.')
 print('[НЕ ПРОВЕРЕНО] Этот просмотр состояния не проверяет реальный VPN и не заменяет приёмку трафика.')
 if fault:return 2
 if stopped:
  from lifecycle import read_records,runtime_reboot_needed
  b,_=read_records()
  if runtime_reboot_needed(b):print('[НУЖНА ПЕРЕЗАГРУЗКА] Возврат загруженных модулей/conntrack ещё не завершён.');return 20
  return 0
 if not guard_present:return 20 if staged else 0
 return 0 if same and all(x=='active' for x in units.values()) and {0,1}<=present and not fault else 2

def read_choice(prompt):
 print(prompt,end='',flush=True)
 try:
  with open('/dev/tty') as tty:return tty.readline().strip()
 except OSError:
  if sys.stdin.isatty():return input().strip()
  raise Refusal('Нет интерактивного терминала. Укажите режим через --mode; список доступен с --help.')

def menu():
 print('Установщик ds-guard и ядра\n1. Всё целиком: ядро + ds-guard + настройка сети\n2. Только XanMod\n3. Только настройка сети\n4. Только ds-guard\n5. Проверка и план без изменений\n6. Состояние системы\n7. Отключить фильтрацию и сетевой профиль\n8. Удалить изменения установщика\n9. Только ядро Ubuntu\n0. Выход')
 choice=read_choice('Выберите пункт: ')
 modes={'1':'full','2':'kernel-xanmod','3':'tune','4':'guard','5':'check','6':'status','7':'disable','8':'remove','9':'kernel-ubuntu','0':'exit'}
 if choice not in modes:raise Refusal('Неизвестный пункт меню.')
 return modes[choice]

def main(argv=None):
 ap=Parser(usage='%(prog)s [параметры]',description='Режимы: full — всё; kernel — только ядро; tune — сеть; guard — ds-guard; check — план; status — состояние; disable — отключить; remove — удалить и восстановить.',epilog='Ядра выбираются из проверенного каталога выпуска. Перезагрузка выполняется отдельным шагом. Автообновления по расписанию не создаются.')
 ap._optionals.title='Параметры';ap._positionals.title='Аргументы';ap._actions[0].help='показать справку и выйти'
 ap.add_argument('--mode',choices=['full','kernel','tune','guard','check','status','disable','remove'],help='режим; без параметра открывается меню')
 ap.add_argument('--kernel-policy',choices=['prefer-xanmod','xanmod','ubuntu','keep'],default='prefer-xanmod',help='предпочесть XanMod (по умолчанию), только XanMod, Ubuntu или текущее ядро')
 ap.add_argument('--tuning',choices=['vpn','keep'],default='vpn',help='в полном режиме применить сетевой профиль либо оставить прежние значения')
 ap.add_argument('--health-command',help='команда проверки реального приложения; ненулевой код считается отказом')
 ap.add_argument('--plan',action='store_true',help='только показать выбранное ядро и действия')
 a=ap.parse_args(argv);a.mode=a.mode or menu()
 if a.mode in ('kernel-xanmod','kernel-ubuntu'):a.kernel_policy=a.mode.split('-',1)[1];a.mode='kernel'
 if a.mode=='exit':return 0
 if a.mode=='status':return status()
 if a.mode in ('disable','remove'):
  if os.geteuid():raise Refusal('Запустите установщик с правами root.')
  import lifecycle
  with Path('/run/ds-guard-safe-lifecycle.lock').open('w') as life_lock, Path('/run/ds-guard-safe-launch.lock').open('w') as lock:
   fcntl.flock(life_lock,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   for unit in ['ds-guard-safe-install','ds-guard-safe-recover','ds-guard-safe-kernel-stage','ds-guard-safe-kernel-cleanup','ds-guard-safe-tune','ds-guard-safe-tune-recover']:
    if command(['systemctl','show',unit+'.service','-p','ActiveState','--value'])[1] in ('active','activating','deactivating'):raise Refusal('Сначала дождитесь завершения установки или восстановления.')
   if a.mode=='remove':return lifecycle.remove(a.plan)
   if a.plan:print('[ПЛАН] Остановить собственную фильтрацию, запретить её автозапуск и вернуть сетевые значения.');return 0
   return lifecycle.disable()
 info=system_info()
 if info['architecture']!='x86_64':raise Refusal('Поддерживается только архитектура amd64.')
 catalog=json.loads((ROOT/'kernels.json').read_text())
 policy='keep' if a.mode in ('guard','tune') else a.kernel_policy
 kernel,reason=choose_kernel(catalog,info['os_id'],info['os_version'],info['flags'],info['kernel'],policy,info['loaded_modules'])
 print(f"Система: Ubuntu {info['os_version']}; текущее ядро: {info['kernel']}")
 print('Выбранное ядро: '+kernel+'\n'+reason)
 print('Режим: '+{'full':'ядро, ds-guard и сетевой профиль' if a.tuning=='vpn' else 'ядро и ds-guard','kernel':'только подготовка ядра','tune':'только сетевой профиль','guard':'только ds-guard','check':'проверка без изменений'}[a.mode])
 if a.mode=='check' or a.plan:
  print('[ПЛАН] Выбор версии выполнен. Установка, изменение загрузчика, настройка сети и перезагрузка не выполнялись.');return 0
 if os.geteuid():raise Refusal('Запустите установщик с правами root.')
 if info['architecture']!='x86_64':raise Refusal('Поддерживается только архитектура amd64.')
 if command(['systemd-detect-virt','--container'])[0]==0:raise Refusal('Контейнер или WSL не поддерживается.')
 from preflight import kernel_diagnostic_errors
 rc,dm,_=command(['dmesg'])
 if kernel_diagnostic_errors(rc,dm):raise Refusal('В текущей загрузке есть ошибки ядра или журнал недоступен. Сначала требуется диагностика.')
 if a.mode in ('full','guard') and not (ROOT/'assets'/kernel/'manifest.json').exists():raise Refusal('Для выбранного ядра в комплекте нет проверенного модуля ds-guard.')
 logdir=Path('/var/log/ds-guard-safe');logdir.mkdir(mode=0o700,parents=True,exist_ok=True)
 log=logdir/('setup-'+str(uuid.uuid4())+'.log');log.touch(mode=0o600)
 print('Журнал операции: '+str(log))
 import lifecycle
 with Path('/run/ds-guard-safe-lifecycle.lock').open('w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if a.mode in ('full','guard'):lifecycle.enable_prepare()
  lifecycle.begin();rc=1
  try:
   rc=perform(a,info,catalog,kernel,log);return rc
  finally:lifecycle.seal(rc)

def perform(a,info,catalog,kernel,log):
 if a.mode in ('kernel','full') and kernel!=info['kernel']:
  if a.mode=='kernel' and Path('/etc/modules-load.d/xt_ndpi.conf').exists():raise Refusal('Уже установлен ds-guard. Для смены ядра выберите полный режим, чтобы подготовить совместимый модуль.')
  directory=download_kernel(kernel,catalog[kernel],log)
  args=['bash',str(ROOT/'kernel-stage.sh')]+(['--kernel-only'] if a.mode=='kernel' else [])+[kernel,str(directory)]
  rc=run_step(args,'Подготовка проверенного ядра рядом с прежним',log);print(result_message(rc,'kernel'))
  if rc:return rc
  print('[ПОДГОТОВЛЕНО] Новое ядро ещё не запущено. Сохранён прежний выбор загрузки. Нужны отдельная проверка GRUB, плановая загрузка выбранного ядра и повторный запуск установщика.');return 20
 if a.mode=='kernel':print('[ЗАПУЩЕНО] Выбранное проверенное ядро уже работает.');return 0
 if a.mode in ('full','guard'):
  args=['bash',str(ROOT/'install.sh')]+(['--health-command',a.health_command] if a.health_command else [])
  rc=run_step(args,'Установка и проверка ds-guard',log);print(result_message(rc,'guard'))
  if rc:return rc
 if a.mode=='tune' or a.mode=='full' and a.tuning=='vpn':
  args=[sys.executable,str(ROOT/'network_tuning.py')]+(['--health-command',a.health_command] if a.health_command else [])
  rc=run_step(args,'Настройка сети с сохранением прежних значений',log);print(result_message(rc,'tune'))
  if rc:
   if a.mode=='full':print('[ЧАСТИЧНО] ds-guard установлен, но настройка сети не принята. Результат её восстановления смотрите в журнале.')
   return rc
 print('[ГОТОВО] Все выбранные шаги завершены. Перезагрузка не выполнялась.')
 if not a.health_command:print('[НЕ ПРОВЕРЕНО] Для полной приёмки дополнительно проверьте реальный клиентский VPN-путь.')
 return 0

if __name__=='__main__':
 try:sys.exit(main())
 except Refusal as e:print('[ОСТАНОВЛЕНО] '+str(e),file=sys.stderr);sys.exit(78)
 except BlockingIOError:print('[ЗАНЯТО] Уже выполняется установка или восстановление.',file=sys.stderr);sys.exit(75)
 except RuntimeError as e:print('[ОСТАНОВЛЕНО] '+str(e),file=sys.stderr);sys.exit(78)
 except KeyboardInterrupt:print('\n[ПРЕРВАНО] Интерфейс закрыт. Проверьте журнал запущенной операции и состояние восстановления.',file=sys.stderr);sys.exit(130)
 except Exception:print('[ОШИБКА] Не удалось завершить операцию. Проверьте доступ к файлам, системным командам и журнал выше; успешная установка не подтверждена.',file=sys.stderr);sys.exit(1)
