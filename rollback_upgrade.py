#!/usr/bin/env python3
"""Return only a verified, inactive legacy hold to its pre-upgrade state.

This is not removal of the original vendor installation.  Its journal remains
immutable; a separate resumable receipt records this scoped restoration.
"""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import time
import uuid

import lifecycle as lc
# Load this before restoring the old library: lifecycle.snapshot imports it.
import network_tuning  # noqa: F401
from transaction import CHAINS, UNITS, managed_hook, foreign_rules

MARKER = '/root/codex-dsguard-20261019/ndpi-memory-safety-hold'
MARKER_TEXT = 'Upstream realloc_wrapper overreads the old allocation. Keep nDPI packet rules suspended until corrected module is loaded and accepted.\n'
HOLDS = tuple('/etc/systemd/system/' + u + '.d/90-codex-ndpi-memory-hold.conf'
              for u in ('ds-guard.service', 'ds-guard-apply.service'))
HOLD_TEXT = '[Unit]\nConditionPathExists=!' + MARKER + '\n'
LIBRARIES = ('/usr/local/lib/ds-guard-safe/', '/usr/local/lib/ds-guard-safe-kernel/')
GUARDS = ('ds-guard.timer', 'ds-guard-apply.service', 'ds-guard.service')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def backup(name):
    return lc.STATE / 'files' / name.lstrip('/')


def validate_parents(name):
    p = Path(name)
    if not p.is_absolute() or '..' in p.parts:
        raise RuntimeError('Некорректный путь в журнале отката: ' + str(p))
    for parent in p.parents:
        if parent.is_symlink():
            # Ubuntu's usr-merge is expected for /lib/modules; arbitrary
            # symlinks in systemd drop-ins or helper trees are not ownership.
            if parent == Path('/lib') and os.readlink(parent) in ('usr/lib', '/usr/lib') and parent.resolve() == Path('/usr/lib'):
                continue
            raise RuntimeError('Родительский каталог заменён ссылкой: ' + str(parent))


def restore_file(name, item, b):
    """Atomic replacement avoids an unrecorded missing-file resume window."""
    p = Path(name)
    validate_parents(p)
    if item is None:
        if lc.stamp(p) is not None:
            p.unlink()
        return
    owner = b['file_owners'][name]
    if lc.stamp(p) == item and [p.lstat().st_uid, p.lstat().st_gid] == owner:
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    temp = p.with_name('.' + p.name + '.rollback-' + str(uuid.uuid4()))
    try:
        shutil.copy2(backup(name), temp, follow_symlinks=False)
        os.chown(temp, *owner, follow_symlinks=False)
        if not temp.is_symlink():
            temp.chmod(item['mode'])
            with temp.open('rb') as f:
                os.fsync(f.fileno())
        if lc.stamp(temp) != item or [temp.lstat().st_uid, temp.lstat().st_gid] != owner:
            raise RuntimeError('Не подтверждена подготовленная копия файла: ' + name)
        temp.replace(p)
        fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temp.unlink(missing_ok=True)


def firewall(text):
    """Parse only filter; ambiguous owned names in other tables are refused."""
    chains, table = {}, ''
    for line in text.splitlines():
        if line.startswith('*'):
            table = line[1:]
        elif line.startswith(':'):
            name, policy = line.split()[:2]
            name = name[1:]
            if name in CHAINS and (table != 'filter' or policy != '-'):
                raise RuntimeError('Неоднозначная собственная цепочка firewall: ' + name)
            if table == 'filter':
                chains[name] = []
        elif line.startswith('-A '):
            p = shlex.split(line)
            own = p[1] in CHAINS or managed_hook(line)
            if own and table != 'filter':
                raise RuntimeError('Правило ds-guard вне таблицы filter')
            if table == 'filter':
                if p[1] not in chains:
                    raise RuntimeError('Не найдена цепочка правила firewall')
                if p[1] not in CHAINS and not managed_hook(line):
                    if any(p[i + 1] in CHAINS for i, s in enumerate(p[:-1]) if s in ('-j', '-g')):
                        raise RuntimeError('Чужое правило ссылается на цепочку ds-guard; автоматический откат остановлен')
                chains[p[1]].append(p[2:])
    return chains


def owned_scope(model):
    # Include hook positions. A foreign insertion that changes their semantics
    # must be reviewed, rather than silently moving the old hooks around it.
    return {'chains': {c: model[c] for c in sorted(set(model) & CHAINS)},
            'hooks': {c: [[i + 1, p] for i, p in enumerate(rules)
                          if managed_hook(shlex.join(['-A', c, *p]))]
                      for c, rules in sorted(model.items()) if c not in CHAINS
                      and any(managed_hook(shlex.join(['-A', c, *p])) for p in rules)}}


def validate_baseline(b):
    if b.get('baseline_kind') != 'legacy-upgrade':
        raise RuntimeError('Этот откат поддерживает только журнал обновления прежней установки')
    if lc.recorded_package_ownership(b):
        raise RuntimeError('Исходный журнал ошибочно присваивает прежние пакеты')
    for name, text, mode in [(MARKER, MARKER_TEXT, 0o600), *[(h, HOLD_TEXT, 0o644) for h in HOLDS]]:
        expected = {'sha256': hashlib.sha256(text.encode()).hexdigest(), 'mode': mode}
        owner = b.get('file_owners', {}).get(name)
        if b['files'].get(name) != expected or not isinstance(owner, list) or len(owner) != 2 or owner[0] != 0:
            raise RuntimeError('Не подтверждён исходный запрет запуска старого модуля: ' + name)
        if lc.stamp(backup(name)) != expected:
            raise RuntimeError('Повреждена резервная копия запрета запуска: ' + name)
    for unit in UNITS:
        state = b['units'].get(unit, {})
        if state.get('enabled') not in ('enabled', 'disabled', 'static'):
            raise RuntimeError('Исходное состояние автозапуска не поддерживается: ' + unit)
        if state.get('active') not in ('active', 'inactive') or unit in GUARDS and state['active'] != 'inactive':
            raise RuntimeError('Откат к активной или неизвестной прежней фильтрации запрещён: ' + unit)
    if 'loaded_module_note_hex' not in b or 'xt_ndpi' not in b.get('module_state', {}):
        raise RuntimeError('Не сохранена исходная идентичность загруженного модуля')
    note = b['loaded_module_note_hex']
    if b['module_state']['xt_ndpi']:
        if not isinstance(note, str) or not re.fullmatch(r'(?:[0-9a-f]{2})+', note):
            raise RuntimeError('Не подтверждён исходный build-id загруженного модуля')
    elif note is not None:
        raise RuntimeError('Исходная идентичность модуля противоречит его состоянию')
    model = firewall(b['iptables'])
    for rules in model.values():
        if any(any(p[i:i + 2] == ['-m', 'ndpi'] for i in range(len(p) - 1)) for p in rules):
            raise RuntimeError('Исходный firewall использовал старый nDPI; автоматический возврат запрещён')
    return model


def validate_backups(b, a):
    for name in lc.changed_owned(b, a) | {MARKER, *HOLDS}:
        validate_parents(name)
        item = b['files'].get(name)
        if item is not None:
            validate_parents(backup(name))
            if name not in b.get('file_owners', {}) or lc.stamp(backup(name)) != item:
                raise RuntimeError('Нет точной резервной копии и владельца файла: ' + name)
        if name in b.get('existing_etc_paths', []) and item is None:
            raise RuntimeError('Прежний файл не был скопирован; откат не может его удалить: ' + name)
    for key in set(b['values']) | set(a['values']):
        if b['values'].get(key) != a['values'].get(key) and key not in b['values']:
            raise RuntimeError('Неизвестно исходное значение сетевого параметра: ' + key)


def package_plan(b, a, now):
    if lc.run(['dpkg', '--audit']):
        raise RuntimeError('Пакетный менеджер не завершил прежнюю операцию; откат остановлен')
    owned = lc.recorded_package_ownership(a)
    if set(owned) & set(b['packages']):
        raise RuntimeError('Журнал присваивает прежние пакеты; их удаление запрещено')
    for p, v in b['packages'].items():
        if now['packages'].get(p) != v:
            raise RuntimeError('Прежний пакет изменился или удалён: ' + p)
    remove = []
    for p, v in sorted(owned.items()):
        if p in now['packages'] and now['packages'][p] != v:
            raise RuntimeError('После обновления изменена версия собственного пакета: ' + p)
        state = lc.run(['dpkg-query', '-W', '-f=${db:Status-Status}', p], False)
        if state in ('installed', 'config-files'):
            remove.append(p)
        elif state not in ('', 'not-installed'):
            raise RuntimeError('Пакет находится в промежуточном состоянии: ' + p)
    kernels = {p[len('linux-image-'):].split(':')[0] for p in remove if p.startswith('linux-image-')}
    bootenv = lc.run(['grub-editenv', '/boot/grub/grubenv', 'list'], False) if kernels else ''
    blocked = sorted(k for k in kernels if k == now['kernel'] or k in bootenv)
    if blocked:
        return remove, blocked
    # This rollback is deliberately for an upgrade on the same kernel. Kernel
    # package maintainer hooks need a separate independently tested procedure.
    if any(p.startswith(('linux-image-', 'linux-headers-', 'linux-modules-')) for p in remove):
        raise RuntimeError('Обновление добавило пакеты ядра; нужен отдельный проверенный возврат ядра')
    if remove:
        sim = lc.run(['apt-get', '-s', 'purge', *remove], timeout=120)
        removals = {m[1] for m in re.finditer(r'^(?:Remv|Purg)\s+(\S+)', sim, re.M)}
        names = {p.split(':')[0] for p in remove}
        if any(p not in remove and (':' in p or p not in names) for p in removals) or re.search(r'^(?:Inst|Conf)\s', sim, re.M):
            raise RuntimeError('Удаление затрагивает посторонние пакеты или их установку')
        # Unqualified simulation names cannot prove which multiarch package is
        # removed when a foreign architecture with that name is also installed.
        for p in removals:
            if ':' not in p and any(q.split(':')[0] == p and q not in remove for q in now['packages']):
                raise RuntimeError('Неоднозначное удаление multiarch-пакета: ' + p)
    return remove, []


def make_firewall_steps(current, baseline):
    if owned_scope(current) == owned_scope(baseline):
        return []
    model = copy.deepcopy(current)
    steps = []

    def add(args, mutate):
        before = copy.deepcopy(owned_scope(model))
        mutate()
        steps.append({'args': args, 'before': before, 'after': copy.deepcopy(owned_scope(model))})

    for chain in sorted(model):
        # Match extensions may not reproduce their kernel byte representation
        # from iptables-save text. Delete by checked live position instead.
        for index in range(len(model[chain]) - 1, -1, -1):
            rule = model[chain][index]
            if managed_hook(shlex.join(['-A', chain, *rule])):
                add(['-D', chain, str(index + 1)], lambda c=chain, i=index: model[c].pop(i))
    for chain in sorted(set(model) & CHAINS):
        if model[chain]:
            add(['-F', chain], lambda c=chain: model[c].clear())
    for chain in sorted((set(baseline) & CHAINS) - set(model)):
        add(['-N', chain], lambda c=chain: model.__setitem__(c, []))
    for chain in sorted(set(baseline) & CHAINS):
        for rule in baseline[chain]:
            add(['-A', chain, *rule], lambda c=chain, r=rule: model[c].append(r))
    for chain in sorted((set(model) & CHAINS) - set(baseline)):
        add(['-X', chain], lambda c=chain: model.pop(c))
    for chain, rules in baseline.items():
        if chain in CHAINS:
            continue
        for index, rule in enumerate(rules):
            if managed_hook(shlex.join(['-A', chain, *rule])):
                if chain not in model or index > len(model[chain]):
                    raise RuntimeError('Невозможно сохранить исходное положение правила ds-guard')
                add(['-I', chain, str(index + 1), *rule], lambda c=chain, i=index, r=rule: model[c].insert(i, r))
    if owned_scope(model) != owned_scope(baseline):
        raise RuntimeError('Не удалось построить точный ограниченный план firewall')
    return steps


def firewall_journal(b, a, now, baseline):
    path = lc.STATE / 'rollback-upgrade-firewall.json'
    identity = digest([b, a])
    scope = owned_scope(firewall(now['iptables']))
    if path.exists():
        data = json.loads(path.read_text())
        if data.get('schema') != 1 or data.get('records_sha256') != identity:
            raise RuntimeError('Журнал отката не соответствует исходной установке')
        n, steps = data['next'], data['steps']
        if not isinstance(n, int) or not isinstance(steps, list) or not 0 <= n <= len(steps):
            raise RuntimeError('Повреждён журнал шагов отката firewall')
        allowed = [data['target']] if n == len(steps) else [steps[n]['before'], steps[n]['after']]
        if scope not in allowed:
            raise RuntimeError('Firewall отличается от последнего подтверждённого шага отката')
        return data
    if scope not in (owned_scope(firewall(a['iptables'])), owned_scope(baseline)):
        raise RuntimeError('Собственные правила или их положение изменились после обновления')
    return {'schema': 1, 'records_sha256': identity, 'next': 0,
            'target': owned_scope(baseline),
            'steps': make_firewall_steps(firewall(now['iptables']), baseline)}


def restore_firewall(data):
    path = lc.STATE / 'rollback-upgrade-firewall.json'
    initial_foreign = foreign_rules(lc.run(['iptables-save']))
    # The pending next step is durable before iptables executes. An interruption
    # after the kernel accepted it is recognized from the exact postcondition.
    lc.save(path, data)
    while data['next'] < len(data['steps']):
        step = data['steps'][data['next']]
        text = lc.run(['iptables-save'])
        live = firewall(text)
        scope = owned_scope(live)
        if foreign_rules(text) != initial_foreign:
            raise RuntimeError('Чужие правила изменились во время отката; продолжение остановлено')
        if scope != step['after']:
            if scope != step['before']:
                raise RuntimeError('Неожиданное изменение собственных правил во время отката')
            args = step['args']
            checked_delete = False
            if len(args) == 3 and args[0] == '-D' and args[2].isdigit():
                chain, index = args[1], int(args[2]) - 1
                if chain in live and 0 <= index < len(live[chain]):
                    rule = live[chain][index]
                    if managed_hook(shlex.join(['-A', chain, *rule])):
                        expected = copy.deepcopy(live)
                        expected[chain].pop(index)
                        # Revalidate both the current target and resulting
                        # owned state; never execute a stale recorded index.
                        checked_delete = owned_scope(expected) == step['after']
            safe = (len(args) >= 2 and args[0] in ('-F', '-N', '-X', '-A') and args[1] in CHAINS
                    or checked_delete
                    or len(args) >= 3 and args[0] == '-I' and args[2].isdigit()
                    and managed_hook(shlex.join(['-A', args[1], *args[3:]])))
            if not safe:
                raise RuntimeError('Журнал содержит команду вне разрешённой области firewall')
            lc.run(['iptables', '-w', '5', *step['args']])
            text = lc.run(['iptables-save'])
            if owned_scope(firewall(text)) != step['after'] or foreign_rules(text) != initial_foreign:
                raise RuntimeError('Не подтверждён ограниченный шаг восстановления firewall')
        data['next'] += 1
        lc.save(path, data)
    text = lc.run(['iptables-save'])
    if owned_scope(firewall(text)) != data['target'] or foreign_rules(text) != initial_foreign:
        raise RuntimeError('Не подтверждён итоговый firewall отката')


def runtime_reboot_needed(b):
    note_path = Path('/sys/module/xt_ndpi/notes/.note.gnu.build-id')
    note = note_path.read_bytes().hex() if note_path.is_file() else None
    return (os.uname().release != b['kernel']
            or Path('/sys/module/xt_ndpi').exists() != b['module_state']['xt_ndpi']
            or note != b['loaded_module_note_hex'] or lc.runtime_reboot_needed(b))


def verify_files(b, names):
    for name in names:
        item = b['files'].get(name)
        if lc.stamp(name) != item:
            raise RuntimeError('Файл после отката не совпал с исходным: ' + name)
        if item is not None:
            p = Path(name)
            if [p.lstat().st_uid, p.lstat().st_gid] != b['file_owners'][name]:
                raise RuntimeError('Владелец файла после отката не совпал: ' + name)


def _rollback_upgrade(plan=False):
    b, a = lc.read_records()
    baseline = validate_baseline(b)
    validate_backups(b, a)
    now = lc.snapshot()
    # Firewall uses the stronger positional, resumable checks below.
    lc.verify_no_conflict(b, a, {**now, 'iptables': a['iptables']})
    for name in (MARKER, *HOLDS):
        if now['files'].get(name) not in (b['files'][name], a['files'].get(name)):
            raise RuntimeError('Изменён прежний запрет запуска: ' + name)
        if now['files'].get(name) is not None and now['file_owners'].get(name) not in (b['file_owners'][name], a['file_owners'].get(name)):
            raise RuntimeError('Изменён владелец прежнего запрета запуска: ' + name)
    progress_path = lc.STATE / 'rollback-upgrade-progress.json'
    progress = json.loads(progress_path.read_text()) if progress_path.exists() else {}
    if progress and progress.get('records_sha256') != digest([b, a]):
        raise RuntimeError('Журнал незавершённого отката относится к другой установке')
    for u in UNITS:
        allowed = [b['units'][u], a['units'][u], {**a['units'][u], 'active': 'inactive'}]
        if progress.get('unit_restore_started') and u == 'suricata.service':
            allowed += [{**s, 'active': state} for s in (b['units'][u], a['units'][u]) for state in ('inactive', 'failed')]
        if now['units'][u] not in allowed:
            raise RuntimeError('После обновления изменено состояние службы: ' + u)
    data = firewall_journal(b, a, now, baseline)
    remove, blocked = package_plan(b, a, now)
    if blocked:
        print('[НУЖНА ПЕРЕЗАГРУЗКА] До отката загрузите сохранённое прежнее ядро ' + b['kernel'] + '. Сейчас используется или выбрано: ' + ', '.join(blocked))
        return 20
    changes = lc.changed_owned(b, a)
    complete_path = lc.STATE / 'rollback-upgrade-completed.json'
    if complete_path.exists():
        complete = json.loads(complete_path.read_text())
        if complete.get('records_sha256') != digest([b, a]) or remove or now['units'] != b['units']:
            raise RuntimeError('После завершённого отката состояние изменилось; повторное применение запрещено')
        verify_files(b, changes | {MARKER, *HOLDS})
        if any(now['values'].get(k) != v for k, v in b['values'].items() if a['values'].get(k) != v) or owned_scope(firewall(now['iptables'])) != owned_scope(baseline):
            raise RuntimeError('После завершённого отката параметры изменились')
        reboot = runtime_reboot_needed(b)
        print('[ОБНОВЛЕНИЕ УЖЕ ОТМЕНЕНО] Исходные файлы и настройки проверены; повторных изменений не выполнено.')
        if reboot:
            print('[НУЖНА ПЕРЕЗАГРУЗКА] Загруженный модуль или ядро ещё отличаются от исходных.')
        return 20 if reboot else 0
    if plan:
        print('[ПЛАН] Вернуть состояние перед обновлением с сохранением запрета старого nDPI. Пакеты к удалению: ' + (', '.join(remove) or 'нет') + '. Изменения не выполнены.')
        return 0
    progress.update(records_sha256=digest([b, a]), started=progress.get('started', time.time()))
    lc.save(progress_path, progress)
    foreign_before = foreign_rules(now['iptables'])
    for name in (MARKER, *HOLDS):
        restore_file(name, b['files'][name], b)
    lc.run(['systemctl', 'daemon-reload'])
    lc.run(['systemctl', 'stop', *GUARDS])
    if any(lc.run(['systemctl', 'is-active', u], False) != 'inactive' for u in GUARDS):
        raise RuntimeError('Прежняя фильтрация не остановлена; возврат файлов запрещён')
    restore_firewall(data)
    ordinary = sorted(n for n in changes if not n.startswith(LIBRARIES))
    libraries = sorted(n for n in changes if n.startswith(LIBRARIES))
    for name in ordinary:
        restore_file(name, b['files'].get(name), b)
    if remove:
        # Recheck dependencies immediately before purge as well as before any
        # restoration. Never accept an unplanned additional removal.
        current = {**now, 'packages': lc.packages()}
        fresh_remove, fresh_blocked = package_plan(b, a, current)
        if fresh_remove != remove or fresh_blocked:
            raise RuntimeError('План удаления пакетов изменился во время отката')
        lc.run(['apt-get', '-y', '-o', 'APT::Get::AutomaticRemove=false', 'purge', *remove], timeout=900)
        for name in ordinary:
            restore_file(name, b['files'].get(name), b)
    for key, value in b['values'].items():
        if a['values'].get(key) != value:
            lc.run(['sysctl', '-w', key + '=' + value])
            if ' '.join(lc.run(['sysctl', '-n', key]).split()) != value:
                raise RuntimeError('Не восстановлен сетевой параметр: ' + key)
    for kernel in sorted(lc.affected_module_kernels(changes)):
        if Path('/boot/vmlinuz-' + kernel).exists():
            lc.run(['depmod', '-a', kernel], timeout=90)
    lc.run(['systemctl', 'daemon-reload'])
    progress['unit_restore_started'] = True
    lc.save(progress_path, progress)
    for unit, state in b['units'].items():
        if state['enabled'] in ('enabled', 'disabled'):
            lc.run(['systemctl', 'enable' if state['enabled'] == 'enabled' else 'disable', unit])
        if unit == 'suricata.service':
            lc.run(['systemctl', 'restart' if state['active'] == 'active' else 'stop', unit], timeout=90)
    if lc.units() != b['units']:
        raise RuntimeError('Не подтверждено исходное состояние служб после отката')
    remaining = lc.packages()
    if any(remaining.get(p) != v for p, v in b['packages'].items()) or set(remove) & set(remaining) or lc.run(['dpkg', '--audit']):
        raise RuntimeError('Не подтверждено сохранение прежних и удаление новых пакетов')
    for p in remove:
        if lc.run(['dpkg-query', '-W', '-f=${db:Status-Status}', p], False) not in ('', 'not-installed'):
            raise RuntimeError('Удаление собственного пакета не завершено: ' + p)
    final_firewall = lc.run(['iptables-save'])
    if owned_scope(firewall(final_firewall)) != owned_scope(baseline) or foreign_rules(final_firewall) != foreign_before:
        raise RuntimeError('Собственные правила изменились после возврата служб')
    verify_files(b, ordinary + [MARKER, *HOLDS])
    # No child Python process or lazy imports after replacing these helpers.
    for name in libraries:
        restore_file(name, b['files'].get(name), b)
    verify_files(b, libraries)
    reboot = runtime_reboot_needed(b)
    lc.save(lc.STATE / 'rollback-upgrade-completed.json', {
        'schema': 1, 'records_sha256': digest([b, a]), 'completed_at': time.time(),
        'pre_upgrade_files_restored': True, 'original_vendor_installation_removed': False,
        'legacy_hold_restored': True, 'packages_removed': remove,
        'loaded_module_requires_reboot': reboot})
    print('[ОБНОВЛЕНИЕ ОТМЕНЕНО] Восстановлено подтверждённое состояние перед обновлением. Прежние пакеты сохранены; старый nDPI остаётся под запретом. Журнал и резервные копии сохранены.')
    if reboot:
        print('[НУЖНА ПЕРЕЗАГРУЗКА] Загруженное ядро или модуль отличаются от исходного состояния. Нужна отдельная плановая перезагрузка; принудительной выгрузки не было.')
        return 20
    return 0


def rollback_upgrade(plan=False):
    # The setup wrapper holds launch/lifecycle locks and checks worker units;
    # this also excludes an already started independent transaction recovery.
    with (lc.STATE.parent / 'install.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _rollback_upgrade(plan)
