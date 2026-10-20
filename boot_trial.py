#!/usr/bin/env python3
"""Owned, one-shot GRUB trial. Recovery requires working Linux userspace.

No kernel installer is run by the boot services. No watchdog is enabled.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
from contextlib import contextmanager

STATE = Path('/var/lib/ds-guard-wizard/boot-trial.json')
MARKER = Path('/var/lib/ds-guard-wizard/boot-trial-active')
HELPER = Path('/usr/local/lib/ds-guard-wizard/boot_trial.py')
LOCK = Path('/run/ds-guard-wizard-boot.lock')
CFG = Path('/boot/grub/grub.cfg')
ENV = Path('/boot/grub/grubenv')
UNIT_DIR = Path('/etc/systemd/system')
CHECK = 'ds-guard-wizard-boot-check.service'
RECOVERY = 'ds-guard-wizard-boot-recovery.service'
TIMER = 'ds-guard-wizard-boot-recovery.timer'
FINALIZE_DROPIN = UNIT_DIR/'xanmod-finalize.service.d/99-ds-guard-wizard-trial.conf'
TERMINAL = {'cancelled', 'completed', 'fallback-observed', 'default-restored'}
ACTIVE = {'prepared', 'arming', 'armed', 'boot-healthy', 'recovery-requested',
          'reboot-failed', 'drift-refused', 'confirming', 'restoring-default'}


class Refusal(RuntimeError):
    pass


def run(argv, check=True, timeout=30):
    p = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise Refusal('Не выполнена команда '+argv[0]+': '+p.stderr[-500:].strip())
    return p.stdout.strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Refusal('Ожидался обычный файл: '+str(path))
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise Refusal('Небезопасный владелец или права: '+str(path))
    return path.read_bytes()


def directory(path):
    path = Path(path)
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise Refusal('Каталог является ссылкой: '+str(parent))
        if parent.exists():
            st = parent.stat()
            if not parent.is_dir() or st.st_uid != 0 or st.st_mode & 0o022:
                raise Refusal('Небезопасный каталог: '+str(parent))
    path.mkdir(parents=True, mode=0o700, exist_ok=True)


def syncdir(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    path = Path(path)
    directory(path.parent)
    if path.is_symlink():
        raise Refusal('Запись через ссылку запрещена: '+str(path))
    tmp = path.with_name(path.name+'.next-'+str(os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        syncdir(path.parent)
    finally:
        if tmp.exists():
            tmp.unlink()


def save(state):
    state['updated_at'] = time.time()
    atomic(STATE, json.dumps(state, ensure_ascii=False, indent=2).encode())
    return state


def read_state():
    if not STATE.exists():
        return None
    d = json.loads(checked_file(STATE))
    if (d.get('schema') != 1 or not isinstance(d.get('target'), str)
            or not re.fullmatch(r'[A-Za-z0-9._+~-]+', d['target'])
            or not isinstance(d.get('owned_files'), dict)
            or not isinstance(d.get('resume_args'), list)
            or any(not isinstance(x, str) or '\x00' in x for x in d['resume_args'])
            or not isinstance(d.get('origin_boot_id'), str)
            or d.get('status') not in ACTIVE | TERMINAL | {'confirmed'}):
        raise Refusal('Повреждён журнал пробной загрузки.')
    return d


@contextmanager
def locked():
    if os.geteuid():
        raise Refusal('Запустите мастер с правами root.')
    fd = os.open(str(LOCK), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != 0 or os.fstat(fd).st_mode & 0o077:
            raise Refusal('Небезопасный файл блокировки мастера.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch(r'[0-9a-f-]{36}', value):
        raise Refusal('Не удалось определить текущую загрузку.')
    return value


def kernel():
    return os.uname().release


def environment():
    result = {}
    for line in run(['grub-editenv', str(ENV), 'list']).splitlines():
        if '=' not in line:
            raise Refusal('Непонятный формат окружения GRUB.')
        k, v = line.split('=', 1)
        if k in result:
            raise Refusal('Повторяющийся параметр GRUB: '+k)
        result[k] = v
    return result


def grub_entries(config):
    """Read standard generated GNU/Linux submenu/entry IDs, never eval GRUB."""
    entries = {}
    submenus = set()
    depth = 0
    active_submenu = None
    for line in config.splitlines():
        stripped = line.strip()
        try:
            words = shlex.split(stripped, comments=True, posix=True)
            lexer = shlex.shlex(stripped, posix=True, punctuation_chars='{}')
            lexer.whitespace_split = True
            structural = list(lexer)
        except ValueError as exc:
            raise Refusal('Неоднозначная строка меню GRUB.') from exc
        opens = sum(len(x) for x in structural if x and set(x) == {'{'})
        closes = sum(len(x) for x in structural if x and set(x) == {'}'})
        declaration = bool(words) and words[0] in ('submenu', 'menuentry')
        if not declaration:
            depth += opens-closes
            if depth < 0:
                raise Refusal('Несбалансированная структура меню GRUB.')
            if active_submenu and depth < active_submenu[1]:
                active_submenu = None
            continue
        ids = [w for w in words if w.startswith('gnulinux-')]
        if len(ids) != 1:
            if ids:
                raise Refusal('Несколько идентификаторов в строке GRUB.')
            depth += opens-closes
            continue
        ident = ids[0]
        if words[0] == 'submenu':
            if (not re.fullmatch(r'gnulinux-advanced-[0-9a-f-]+', ident)
                    or ident in submenus or active_submenu or depth != 0 or opens-closes != 1):
                raise Refusal('Неоднозначный раздел GRUB.')
            submenus.add(ident)
            active_submenu = (ident, depth+1)
        elif (m := re.fullmatch(r'gnulinux-(.+)-advanced-([0-9a-f-]+)', ident)):
            if (ident in entries or active_submenu != ('gnulinux-advanced-'+m[2], depth)
                    or opens-closes != 1):
                raise Refusal('Повторяющийся идентификатор ядра GRUB.')
            entries[ident] = {'kernel': m[1], 'submenu': 'gnulinux-advanced-'+m[2]}
        depth += opens-closes
    if depth != 0:
        raise Refusal('Незавершённая структура меню GRUB.')
    for entry in entries.values():
        if entry['submenu'] not in submenus:
            raise Refusal('Для ядра не найден однозначный раздел GRUB.')
    return entries


def environment_backend():
    """GRUB must be able to consume next_entry itself, before Linux boots.

    Conservatively support a plain ext filesystem only. Linux being able to
    write grubenv does not establish that GRUB's save_env can write it.
    """
    try:
        filesystem = run(['grub-probe', '--target=fs', str(ENV)])
        abstraction = run(['grub-probe', '--target=abstraction', str(ENV)])
    except (OSError, subprocess.TimeoutExpired, Refusal) as exc:
        raise Refusal('Не удалось подтвердить запись GRUB в grubenv. '
                      'Автоматическая пробная загрузка остановлена; '
                      'используйте консоль хостера для ручного выбора ядра.') from exc
    if filesystem != 'ext2' or abstraction:
        raise Refusal('Автоматическая пробная загрузка поддерживает только обычный '
                      'раздел ext2/ext3/ext4 без LVM, RAID и других промежуточных слоёв. '
                      'GRUB обнаружил файловую систему '+repr(filesystem)
                      +' и слой '+repr(abstraction)+'. Используйте консоль хостера '
                      'для ручного выбора ядра; запись одноразового выбора не выполнена.')
    return {'filesystem': filesystem, 'abstraction': abstraction}


def boot_plan(target):
    if not re.fullmatch(r'[A-Za-z0-9._+~-]+', target):
        raise Refusal('Некорректное имя ядра.')
    config = checked_file(CFG).decode()
    run(['grub-script-check', str(CFG)])
    backend = environment_backend()
    # Standard update-grub output must consume the one-shot entry before Linux.
    required = ['set default="${saved_entry}"', 'set default="${next_entry}"',
                'set next_entry=', 'save_env next_entry', 'set boot_once=true']
    if any(text not in config for text in required):
        raise Refusal('GRUB не подтверждает сохранённый выбор и одноразовую загрузку.')
    env = environment()
    if env.get('next_entry'):
        raise Refusal('Уже назначена другая одноразовая загрузка.')
    if env.get('prev_saved_entry'):
        raise Refusal('В GRUB ожидает восстановления прежний сохранённый выбор.')
    entries = grub_entries(config)
    old = env.get('saved_entry', '')
    parts = old.split('>')
    if len(parts) != 2 or parts[1] not in entries or entries[parts[1]]['submenu'] != parts[0]:
        raise Refusal('Нет однозначного сохранённого резервного ядра GRUB.')
    fallback = entries[parts[1]]['kernel']
    # Trial fallback must be this known currently working kernel.
    if fallback != kernel():
        raise Refusal('Сохранённое резервное ядро отличается от работающего. Автоматическая смена выбора остановлена.')
    matches = [ident for ident, value in entries.items()
               if value['kernel'] == target and value['submenu'] == parts[0]]
    if len(matches) != 1 or target == fallback:
        raise Refusal('Пробное ядро не найдено однозначно или уже работает.')
    for version in (target, fallback):
        for name in ('vmlinuz-', 'initrd.img-'):
            p = Path('/boot')/(name+version)
            if len(checked_file(p)) <= 1024*1024:
                raise Refusal('Образ ядра или initramfs отсутствует либо слишком мал: '+str(p))
    return {'fallback': fallback, 'saved_entry': old,
            'target_entry': parts[0]+'>'+matches[0], 'grub_sha256': digest(config.encode()),
            'grub_environment': env, 'grub_environment_backend': backend}


def capture_baseline():
    fields = os.environ.get('SSH_CONNECTION', '').split()
    if len(fields) != 4 or not fields[3].isdigit() or not 1 <= int(fields[3]) <= 65535:
        raise Refusal('Для защиты пробной загрузки нужен текущий сеанс SSH с SSH_CONNECTION.')
    client, server, port = fields[0], fields[2], int(fields[3])
    for address in (client, server):
        ipaddress.ip_address(address)
    units = [u for u in ('ssh.service', 'sshd.service')
             if run(['systemctl', 'is-active', u], check=False) == 'active']
    if not units:
        raise Refusal('Не найдена работающая служба SSH.')
    addresses = json.loads(run(['ip', '-j', 'address', 'show']))
    matches = [item for item in addresses
               if any(a.get('local') == server for a in item.get('addr_info', []))]
    if len(matches) != 1:
        raise Refusal('Не найден однозначный интерфейс текущего SSH-сеанса.')
    nic = matches[0]['ifname']
    family = '-6' if ipaddress.ip_address(server).version == 6 else '-4'
    routes = json.loads(run(['ip', family, '-j', 'route', 'show', 'default']))
    defaults = [{k: r[k] for k in ('dev', 'gateway', 'table') if k in r}
                for r in routes if r.get('dev') == nic]
    if not defaults:
        raise Refusal('На интерфейсе SSH нет проверяемого маршрута по умолчанию.')
    baseline = {'ssh_unit': units[0], 'ssh_port': port, 'server_address': server,
                'client_address': client, 'interface': nic, 'family': family,
                'default_routes': defaults}
    failures = health_failures(baseline)
    if failures:
        raise Refusal('Исходная проверка сервера не пройдена: '+'; '.join(failures))
    return baseline


def health_failures(baseline):
    errors = []
    if run(['systemctl', 'is-active', baseline['ssh_unit']], check=False) != 'active':
        errors.append('служба SSH не работает')
    listeners = run(['ss', '-H', '-ltn']).splitlines()
    port = str(baseline['ssh_port'])
    valid_local = {baseline['server_address'], '0.0.0.0', '*', '::'}
    found = False
    for line in listeners:
        fields = line.split()
        if len(fields) >= 4:
            local, _, number = fields[3].rpartition(':')
            if number == port and local.strip('[]') in valid_local:
                found = True
    if not found:
        errors.append('порт SSH не слушает ожидаемый адрес')
    addresses = json.loads(run(['ip', '-j', 'address', 'show']))
    nic = next((x for x in addresses if x.get('ifname') == baseline['interface']), None)
    if not nic or 'UP' not in nic.get('flags', []) or not any(
            x.get('local') == baseline['server_address'] for x in nic.get('addr_info', [])):
        errors.append('интерфейс или адрес SSH недоступен')
    routes = json.loads(run(['ip', baseline['family'], '-j', 'route', 'show', 'default']))
    actual = [{k: r[k] for k in ('dev', 'gateway', 'table') if k in r} for r in routes]
    if not any(r in actual for r in baseline['default_routes']):
        errors.append('исходный маршрут по умолчанию отсутствует')
    return errors


def unit_files():
    common = '[Unit]\nDescription=ds-guard owned kernel trial\n'
    check = common+'After=network-online.target ssh.service sshd.service\nWants=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(HELPER)+' guard\nTimeoutStartSec=140\n'
    recover = common+'After=local-fs.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(HELPER)+' recover\nTimeoutStartSec=40\n'
    timer = '[Unit]\nDescription=Bounded ds-guard kernel trial recovery\n[Timer]\nOnBootSec=180\nOnUnitInactiveSec=20\nAccuracySec=5\nUnit='+RECOVERY+'\n'
    return {str(UNIT_DIR/CHECK): check.encode(), str(UNIT_DIR/RECOVERY): recover.encode(),
            str(UNIT_DIR/TIMER): timer.encode(),
            str(FINALIZE_DROPIN): ('[Unit]\nConditionPathExists=!'+str(MARKER)+'\n').encode()}


def verify_owned(d):
    for filename, sha in d['owned_files'].items():
        if digest(checked_file(filename)) != sha:
            raise Refusal('Файл защиты загрузки изменён: '+filename)
    for filename, target in d.get('owned_links', {}).items():
        p = Path(filename)
        if not p.is_symlink() or os.readlink(p) != target:
            raise Refusal('Ссылка защиты загрузки изменена: '+filename)


def boot_ownership(d, allow_target_saved=False):
    env = environment()
    allowed = {d['saved_entry']}
    if allow_target_saved:
        allowed.add(d['target_entry'])
    if (env.get('saved_entry') not in allowed
            or env.get('next_entry', '') not in ('', d['target_entry'])
            or env.get('prev_saved_entry')):
        raise Refusal('Выбор GRUB изменён другим процессом; автоматическое действие остановлено.')
    return env


def prepare(target, resume_args, baseline=None):
    with locked():
        previous = read_state()
        if previous and previous['status'] not in TERMINAL:
            raise Refusal('Уже есть незавершённая или закреплённая пробная загрузка.')
        if not isinstance(resume_args, list) or any(not isinstance(x, str) or '\x00' in x for x in resume_args):
            raise Refusal('Неверные параметры продолжения.')
        plan = boot_plan(target)
        baseline = baseline or capture_baseline()
        if health_failures(baseline):
            raise Refusal('Исходное состояние SSH или сети не подтверждено.')
        files = unit_files()
        files[str(HELPER)] = Path(__file__).read_bytes()
        files[str(MARKER)] = b'ds-guard-wizard one-shot trial\n'
        links = {str(UNIT_DIR/'multi-user.target.wants'/CHECK): str(UNIT_DIR/CHECK),
                 str(UNIT_DIR/'timers.target.wants'/TIMER): str(UNIT_DIR/TIMER)}
        finalizer_present = run(['systemctl', 'show', 'xanmod-finalize.service', '-p', 'LoadState', '--value'], check=False) == 'loaded'
        if not finalizer_present:
            files.pop(str(FINALIZE_DROPIN))
        reused = {}
        if previous and previous.get('retained_finalizer_guard'):
            for filename in (str(FINALIZE_DROPIN), str(MARKER)):
                p = Path(filename)
                if (filename not in files or previous['owned_files'].get(filename) != digest(files[filename])
                        or digest(checked_file(p)) != previous['owned_files'][filename]):
                    raise Refusal('Сохранённая защита прежнего finalizer изменена.')
                reused[filename] = True
        # Unowned files are never adopted, even if their bytes happen to match.
        for p in [*(Path(x) for x in files), *(Path(x) for x in links)]:
            if (p.exists() or p.is_symlink()) and str(p) not in reused:
                raise Refusal('Путь защиты уже занят: '+str(p))
        if run(['systemctl', 'is-active', 'xanmod-finalize.service'], check=False) in ('active', 'activating', 'deactivating'):
            raise Refusal('Работает прежний xanmod-finalize; дождитесь его завершения.')
        d = {'schema': 1, 'status': 'prepared', 'target': target, 'origin_boot_id': boot_id(),
             'resume_args': resume_args, 'baseline': baseline, 'recovery_attempts': 0,
             'finalizer_present': finalizer_present, 'retained_finalizer_guard': False,
             'owned_files': {p: digest(v) for p, v in files.items()}, 'owned_links': links, **plan}
        # Durable intent precedes every owned file and link.
        if previous:
            prior = checked_file(STATE)
            archive = STATE.parent/'boot-trial-history'/('trial-'+str(time.time_ns())+'-'+digest(prior)[:12]+'.json')
            atomic(archive, prior)
        save(d)
        for name, value in files.items():
            atomic(Path(name), value, 0o644 if name.endswith(('.service', '.timer', '.conf')) else 0o600)
        for name, value in links.items():
            p = Path(name)
            directory(p.parent)
            p.symlink_to(value)
            syncdir(p.parent)
        run(['systemctl', 'daemon-reload'])
        verify_owned(d)
        return d


def arm(confirmation_already_given=False):
    if confirmation_already_given is not True:
        raise Refusal('Перезагрузка требует явного выбора в мастере.')
    with locked():
        d = read_state()
        if not d or d['status'] != 'prepared' or boot_id() != d['origin_boot_id'] or kernel() != d['fallback']:
            raise Refusal('Пробная загрузка не подготовлена в текущей загрузке.')
        verify_owned(d)
        plan = boot_plan(d['target'])
        for key in ('saved_entry', 'target_entry', 'grub_sha256'):
            if d[key] != plan[key]:
                raise Refusal('Настройки загрузки изменились после подготовки.')
        d['status'] = 'arming'
        save(d)
        run(['grub-reboot', d['target_entry']])
        env = boot_ownership(d)
        if env.get('next_entry') != d['target_entry']:
            raise Refusal('GRUB не подтвердил одноразовую загрузку.')
        d['status'] = 'armed'
        return save(d)


def cleanup(d, retain_finalizer=True):
    # Preflight all owned existing files before changing any.
    for filename, sha in d['owned_files'].items():
        p = Path(filename)
        if p.exists() or p.is_symlink():
            if digest(checked_file(p)) != sha:
                raise Refusal('Изменённый файл защиты не удалён: '+filename)
    for filename, target in d['owned_links'].items():
        p = Path(filename)
        if p.exists() or p.is_symlink():
            if not p.is_symlink() or os.readlink(p) != target:
                raise Refusal('Изменённая ссылка защиты не удалена: '+filename)
    run(['systemctl', 'stop', TIMER], check=False)
    keep = {str(FINALIZE_DROPIN), str(MARKER)} if retain_finalizer and d.get('finalizer_present') else set()
    for filename in [*d['owned_links'], *d['owned_files']]:
        if filename in keep:
            continue
        p = Path(filename)
        if p.exists() or p.is_symlink():
            p.unlink()
            syncdir(p.parent)
    run(['systemctl', 'daemon-reload'])
    d['retained_finalizer_guard'] = bool(keep)


def restore_finalizer_guard(d):
    """A later undo must re-protect the foreign finalizer before old default."""
    if not d.get('finalizer_present'):
        return
    expected = {str(MARKER): b'ds-guard-wizard one-shot trial\n',
                str(FINALIZE_DROPIN): unit_files()[str(FINALIZE_DROPIN)]}
    for filename, data in expected.items():
        p = Path(filename)
        if d['owned_files'].get(filename) != digest(data):
            raise Refusal('Нет подтверждённого содержимого защиты finalizer.')
        if p.exists() or p.is_symlink():
            if digest(checked_file(p)) != digest(data):
                raise Refusal('Прежняя защита finalizer изменена.')
    for filename, data in expected.items():
        p = Path(filename)
        if not p.exists():
            atomic(p, data, 0o600 if p == MARKER else 0o644)
    run(['systemctl', 'daemon-reload'])
    d['retained_finalizer_guard'] = True


def inspect():
    d = read_state()
    if not d:
        return {'status': 'none'}
    out = dict(d)
    out['running_kernel'] = kernel()
    out['current_kernel'] = out['running_kernel']
    out['current_boot_id'] = boot_id()
    out['boot_id_before'] = d['origin_boot_id']
    out['phase'] = {'boot-healthy': 'boot_verified', 'recovery-requested': 'recovery_requested',
                    'fallback-observed': 'recovered'}.get(d['status'], d['status'])
    out['different_boot'] = out['current_boot_id'] != d['origin_boot_id']
    out['expected_kernel_running'] = out['running_kernel'] == d['target']
    out['same_boot'] = not out['different_boot']
    out['can_resume'] = out['different_boot'] and out['expected_kernel_running'] and d['status'] in ('armed', 'boot-healthy')
    return out


status = inspect


def post_boot_guard():
    with locked():
        d = read_state()
        if not d or d['status'] not in ('armed', 'boot-healthy', 'recovery-requested', 'reboot-failed'):
            return 0
        if boot_id() == d['origin_boot_id']:
            return 0
        try:
            verify_owned(d)
            env = boot_ownership(d)
            if env.get('next_entry'):
                raise Refusal('GRUB не погасил одноразовый выбор.')
        except Refusal as exc:
            d.update(status='drift-refused', error=str(exc))
            save(d)
            return 78
        if kernel() == d['fallback']:
            d['status'] = 'fallback-observed'
            save(d)
            run(['systemctl', 'stop', TIMER], check=False)
            return 0
        if kernel() != d['target']:
            d.update(status='drift-refused', error='Загружено постороннее ядро.')
            save(d)
            return 78
        if d.get('recovery_attempts', 0):
            # A failed recovery reboot cannot create an automatic reboot loop.
            return 1
        # Timer waits for this lock; bounded below the timer deadline.
        deadline = time.monotonic()+110
        failures = ['проверка ещё не выполнена']
        while True:
            try:
                failures = health_failures(d['baseline'])
            except (Refusal, ValueError, subprocess.TimeoutExpired) as exc:
                failures = [str(exc)]
            if not failures or time.monotonic() >= deadline:
                break
            time.sleep(5)
        if failures:
            d['health_errors'] = failures
            save(d)
            return 1
        d.update(status='boot-healthy', health_errors=[], checked_boot_id=boot_id())
        save(d)
        run(['systemctl', 'stop', TIMER], check=False)
        return 0


def resume_ready():
    """Bounded verification on interactive reconnect; disarms recovery first."""
    result = post_boot_guard()
    current = inspect()
    return (result == 0 and current.get('status') == 'boot-healthy'
            and current.get('different_boot') is True
            and current.get('expected_kernel_running') is True)


def recover():
    with locked():
        d = read_state()
        if not d or d['status'] not in ('armed', 'reboot-failed') or d.get('recovery_attempts', 0):
            run(['systemctl', 'stop', TIMER], check=False)
            return 0
        if boot_id() == d['origin_boot_id'] or kernel() != d['target']:
            return 0
        try:
            verify_owned(d)
            env = boot_ownership(d)
            if env.get('next_entry'):
                raise Refusal('Одноразовый выбор GRUB не погашен.')
            failures = health_failures(d['baseline'])
            if not failures:
                d.update(status='boot-healthy', health_errors=[], checked_boot_id=boot_id())
                save(d)
                run(['systemctl', 'stop', TIMER], check=False)
                return 0
        except (Refusal, ValueError, subprocess.TimeoutExpired) as exc:
            # Ownership uncertainty is not permission to reboot.
            d.update(status='drift-refused', error=str(exc))
            save(d)
            return 78
        d.update(status='recovery-requested', recovery_attempts=1, health_errors=failures,
                 recovery_boot_id=boot_id())
        save(d)
        try:
            run(['systemctl', 'reboot'])
        except (Refusal, subprocess.TimeoutExpired) as exc:
            d.update(status='reboot-failed', error=str(exc))
            save(d)
            return 1
        return 20


def record_reboot_failure(reason='Команда перезагрузки не выполнена.'):
    with locked():
        d = read_state()
        if not d or d['status'] != 'armed' or boot_id() != d['origin_boot_id']:
            raise Refusal('Нет принадлежащей мастеру ожидающей перезагрузки.')
        env = boot_ownership(d)
        if env.get('next_entry') == d['target_entry']:
            run(['grub-editenv', str(ENV), 'unset', 'next_entry'])
        after = environment()
        if after.get('saved_entry') != d['saved_entry'] or after.get('next_entry'):
            raise Refusal('Не удалось отменить ожидающую одноразовую загрузку.')
        d.update(status='prepared', error=str(reason))
        return save(d)


def complete(confirmed=True):
    if confirmed is not True:
        raise Refusal('Завершение не подтверждено.')
    with locked():
        d = read_state()
        if not d or d['status'] != 'boot-healthy' or boot_id() == d['origin_boot_id'] or kernel() != d['target']:
            raise Refusal('Загрузка нового ядра ещё не подтверждена.')
        boot_ownership(d)
        cleanup(d)
        d['status'] = 'completed'
        return save(d)


def confirm(confirmed=False):
    """Explicit operator acceptance only. Never called by the boot services."""
    if confirmed is not True:
        raise Refusal('Закрепление нового ядра требует явного выбора.')
    with locked():
        d = read_state()
        if not d or d['status'] not in ('boot-healthy', 'completed') or boot_id() == d['origin_boot_id'] or kernel() != d['target']:
            raise Refusal('Загрузка нового ядра ещё не подтверждена.')
        env = boot_ownership(d)
        if env.get('next_entry'):
            raise Refusal('Есть незавершённый одноразовый выбор GRUB.')
        d['status'] = 'confirming'
        save(d)
        run(['grub-set-default', d['target_entry']])
        after = environment()
        if after.get('saved_entry') != d['target_entry'] or {k: v for k, v in after.items() if k != 'saved_entry'} != {k: v for k, v in env.items() if k != 'saved_entry'}:
            raise Refusal('Изменение постоянного выбора GRUB не подтверждено.')
        cleanup(d, retain_finalizer=False)
        d['status'] = 'confirmed'
        return save(d)


def cancel():
    with locked():
        d = read_state()
        if not d:
            return {'status': 'none'}
        promoted = d['status'] in ('confirmed', 'confirming', 'restoring-default')
        env = boot_ownership(d, allow_target_saved=promoted)
        if promoted:
            d['status'] = 'restoring-default'
            save(d)
            restore_finalizer_guard(d)
        if env.get('next_entry') == d['target_entry']:
            run(['grub-editenv', str(ENV), 'unset', 'next_entry'])
        if promoted and env.get('saved_entry') == d['target_entry']:
            run(['grub-set-default', d['saved_entry']])
        after = environment()
        if after.get('saved_entry') != d['saved_entry'] or after.get('next_entry'):
            raise Refusal('Возврат выбора GRUB не подтверждён.')
        cleanup(d)
        d['status'] = 'default-restored' if promoted else 'cancelled'
        return save(d)


undo_promotion = cancel


def cleanup_after_remove():
    """Release a retained finalizer guard only once its candidate is removed."""
    with locked():
        d = read_state()
        if not d:
            return {'status': 'none'}
        if kernel() == d['target'] or any((Path('/boot')/(prefix+d['target'])).exists()
                                       for prefix in ('vmlinuz-', 'initrd.img-')):
            raise Refusal('Пробное ядро ещё присутствует. Защита прежнего finalizer сохранена.')
        env = boot_ownership(d)
        if env.get('next_entry') or env.get('saved_entry') != d['saved_entry']:
            raise Refusal('Выбор загрузки ещё не возвращён.')
        cleanup(d, retain_finalizer=False)
        d['status'] = 'default-restored'
        return save(d)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['guard', 'recover', 'status'])
    args = parser.parse_args()
    if args.action == 'guard':
        return post_boot_guard()
    if args.action == 'recover':
        return recover()
    print(json.dumps(inspect(), ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Refusal, BlockingIOError) as exc:
        print('[ОСТАНОВЛЕНО] '+str(exc), flush=True)
        raise SystemExit(78)
