"""First-touch runtime baseline after a verified, fresh kernel-only stage.

The pre-install snapshot is never rewritten. This is a new measured baseline,
not a claim that every changed value came from a kernel default. Existing guard
or tuning installations, same-boot drift, and foreign file changes still stop.
"""
import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

TRIAL = Path('/var/lib/ds-guard-wizard/boot-trial.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Нет проверяемого журнала перехода ядра: '+str(path))
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Небезопасные права журнала перехода ядра')
    return json.loads(path.read_text())


def effective(state, before, after, running):
    path = state/'boot-runtime-baseline.json'
    if not path.exists():
        return before, after
    d = checked_json(path)
    if (d.get('schema') != 1 or d.get('before_sha256') != digest(state/'before.json')
            or d.get('origin_kernel') != before['kernel']
            or not isinstance(d.get('values'), dict)
            or set(d['values']) != set(before['values'])
            or any(not isinstance(v, str) or not v for v in d['values'].values())):
        raise RuntimeError('Повреждён отдельный исходный снимок нового ядра')
    if running not in (d['target_kernel'], d['origin_kernel']):
        raise RuntimeError('Для этого ядра нет исходного сетевого снимка; требуется проверка перехода')
    if running == d['target_kernel']:
        before = copy.deepcopy(before)
        before['values'] = dict(d['values'])
        if digest(state/'after.json') == d['source_after_sha256']:
            after = copy.deepcopy(after)
            after['values'] = dict(d['values'])
    return before, after


def catalog_packages(target, catalog):
    """Exact package identities, not a broad linux-* prefix allowance."""
    entry = catalog.get(target)
    if not isinstance(entry, dict):
        raise RuntimeError('Выбранное ядро отсутствует в проверенном каталоге')
    items = entry.get('packages')
    if items is None:
        items = []
        for kind in ('image', 'headers'):
            filename = entry.get(kind, '')
            parts = filename.split('_')
            name = 'linux-'+kind+'-'+target
            if len(parts) != 3 or parts[0] != name or parts[2] != 'amd64.deb':
                raise RuntimeError('Некорректное имя закреплённого пакета ядра')
            items.append({'package': name, 'version': parts[1], 'architecture': 'amd64'})
    scope = {}
    for item in items:
        name, version, arch = (item.get(k) for k in ('package', 'version', 'architecture'))
        if (not isinstance(name, str) or not re.fullmatch(r'linux-[a-z0-9.+-]+', name)
                or not isinstance(version, str) or not version or arch not in ('amd64', 'all')
                or name in scope):
            raise RuntimeError('Некорректный состав закреплённого комплекта ядра')
        scope[name] = {'version': version, 'architecture': arch}
    if not {'linux-image-'+target, 'linux-headers-'+target} <= set(scope):
        raise RuntimeError('В комплекте ядра отсутствуют образ или заголовки')
    return scope


def kernel_package_scope(target):
    catalog = json.loads(Path(__file__).with_name('kernels.json').read_text())
    scope = catalog_packages(target, catalog)
    # The pinned Ubuntu modules-extra package depends on wireless-regdb. Only
    # admit that specific dependency when the installed, exact-version parent
    # declares it. Ownership still comes from the private dpkg receipts below.
    parent = 'linux-modules-extra-'+target
    if catalog[target].get('kind') == 'ubuntu' and parent in scope:
        fmt = '${Package}\t${Architecture}\t${db:Status-Status}\t${Version}\t${Depends}\n'
        p = subprocess.run(['dpkg-query', '-W', '-f='+fmt, parent],
                           capture_output=True, text=True, timeout=30, check=True)
        fields = p.stdout.rstrip('\n').split('\t')
        expected = scope[parent]
        if (len(fields) != 5 or fields[:4] != [parent, expected['architecture'],
                                              'installed', expected['version']]):
            raise RuntimeError('Не подтверждена версия пакета модулей нового ядра')
        if 'wireless-regdb' in [x.strip() for x in fields[4].split(',')]:
            scope['wireless-regdb'] = {'version': None, 'architecture': 'all'}
    return scope


def normalized_packages(packages, scope):
    result = {}
    for name, version in packages.items():
        parts = name.split(':')
        base = parts[0]
        if base not in scope:
            raise RuntimeError('В подтверждении есть пакет вне комплекта ядра: '+name)
        if (len(parts) > 2 or len(parts) == 2 and parts[1] != scope[base]['architecture']
                or base in result):
            raise RuntimeError('Неоднозначная архитектура пакета ядра: '+name)
        expected = scope[base]['version']
        if not isinstance(version, str) or not version or expected is not None and version != expected:
            raise RuntimeError('Версия пакета не совпала с закреплённым комплектом: '+name)
        result[base] = version
    return result


def verify_kernel_receipts(state, owned):
    proven = {}; operations = set()
    for path in sorted((state/'package-receipts').glob('*.json')):
        d = checked_json(path)
        if (d.get('schema') != 1 or d.get('completed') is not True or d.get('returncode') != 0
                or not isinstance(d.get('installed'), dict)
                or not isinstance(d.get('operation_id'), str)
                or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', d['operation_id'])):
            raise RuntimeError('Не завершена подтверждённая пакетная подготовка ядра')
        operations.add(d['operation_id'])
        for name, version in d['installed'].items():
            if name in proven or not isinstance(version, str) or not version:
                raise RuntimeError('Неоднозначное подтверждение пакета ядра')
            proven[name] = version
    if len(operations) > 1 or proven != owned:
        raise RuntimeError('Происхождение пакетов не совпало с журналом подготовки ядра')


def validate(before, after, current, trial, stage, boot_id, package_scope=None):
    """Pure eligibility checks; ordinary conflict checks run separately."""
    target = current['kernel']
    if (before.get('baseline_kind') != 'fresh'
            or before['kernel'] != after['kernel'] or after['kernel'] == target
            or before['values'] != after['values']
            or set(current['values']) != set(before['values'])
            or any(current.get('module_state', {}).get(k) for k in ('xt_ndpi',))
            or trial.get('schema') != 1 or trial.get('status') != 'boot-healthy'
            or trial.get('target') != target or trial.get('fallback') != after['kernel']
            or trial.get('origin_boot_id') == boot_id
            or trial.get('checked_boot_id') != boot_id
            or trial.get('health_errors') != []
            or stage.get('candidate') != target
            or stage.get('running_kernel') != after['kernel']
            or stage.get('boot_environment_preserved') is not True):
        raise RuntimeError('Переход не является первой проверенной загрузкой подготовленного ядра')
    # Only kernel staging may precede this first touch; no guard/tuning writes.
    changed = {k for k in set(before['files']) | set(after['files'])
               if before['files'].get(k) != after['files'].get(k)}
    module = '/lib/modules/'+target+'/updates/dkms/xt_ndpi.ko'
    cleanup = '/etc/systemd/system/ds-guard-safe-kernel-cleanup.service'
    if any(not (p.startswith('/usr/local/lib/ds-guard-safe-kernel/')
                or p in (module, cleanup)) for p in changed):
        raise RuntimeError('До смены ядра уже изменялась защита или сеть; автоматический перенос запрещён')
    if any(before['files'].get(p) is not None for p in changed):
        raise RuntimeError('Подготовка ядра заменила существовавшие файлы; нужен отдельный перенос')
    for name in set(after['files']) | set(current['files']):
        if after['files'].get(name) != current['files'].get(name):
            raise RuntimeError('После подготовки изменён файл: '+name)
    if after.get('file_owners') != current.get('file_owners'):
        raise RuntimeError('После подготовки изменились владельцы файлов')
    owned = after.get('owned_packages', {})
    scope = package_scope or {p: {'version': None, 'architecture': 'amd64'}
                              for p in ('linux-image-'+target, 'linux-headers-'+target)}
    normalized_packages(owned, scope)
    if set(owned) & set(before['packages']):
        raise RuntimeError('Подготовка ядра ошибочно присваивает прежний пакет')
    if package_scope is not None:
        installed = {p: v for p, v in current['packages'].items() if p.split(':')[0] in scope}
        observed = normalized_packages(installed, scope)
        required = {p for p, v in scope.items() if v['version'] is not None}
        if not required <= set(observed):
            raise RuntimeError('Установлен не весь закреплённый комплект нового ядра')
    if any(current['packages'].get(p) != v for p, v in owned.items()):
        raise RuntimeError('После подготовки изменились пакеты выбранного ядра')


def capture(state, before, after, current, verify, save):
    if ((state/'boot-runtime-baseline.json').exists()
            or before.get('baseline_kind') != 'fresh'
            or before.get('kernel') == current.get('kernel')
            or before.get('values') != after.get('values')):
        return False
    trial = checked_json(TRIAL)
    stage = checked_json(state.parent/'kernel'/(current['kernel']+'.staged.json'))
    boot_id = BOOT_ID.read_text().strip()
    scope = kernel_package_scope(current['kernel'])
    validate(before, after, current, trial, stage, boot_id, scope)
    verify_kernel_receipts(state, after.get('owned_packages', {}))
    for directory in ('transactions', 'tuning'):
        if any((state.parent/directory).glob('*/before.json')):
            raise RuntimeError('Существуют прежние операции защиты или настройки сети')
    last = checked_json(state/'last-operation.json')
    if last.get('exit_code') != 20:
        raise RuntimeError('Не подтверждено завершение подготовки ядра до перезагрузки')
    # Do not execute a persisted helper. Verify its owned files and links.
    for name, sha in trial.get('owned_files', {}).items():
        p = Path(name)
        if p.is_symlink() or not p.is_file() or digest(p) != sha:
            raise RuntimeError('Изменён файл защитной службы пробной загрузки')
    for name, target in trial.get('owned_links', {}).items():
        p = Path(name)
        if not p.is_symlink() or os.readlink(p) != target:
            raise RuntimeError('Изменена ссылка защитной службы пробной загрузки')
    # Preserve the usual foreign-file, package, and firewall conflict gates.
    proposed_before, proposed_after = copy.deepcopy(before), copy.deepcopy(after)
    proposed_before['values'] = dict(current['values'])
    proposed_after['values'] = dict(current['values'])
    verify(proposed_before, proposed_after, current)
    receipt = {'schema': 1, 'before_sha256': digest(state/'before.json'),
               'source_after_sha256': digest(state/'after.json'),
               'origin_kernel': before['kernel'], 'target_kernel': current['kernel'],
               'boot_id': boot_id, 'trial_sha256': digest(TRIAL),
               'values': dict(current['values']),
               'reason': 'measured-before-first-guard-or-network-write'}
    save(state/'boot-runtime-baseline.json', receipt)
    print('[ПЕРЕХОД ЯДРА] Сохранён исходный сетевой снимок новой загрузки. Прежний журнал сохранён; настройки пока не изменялись.', flush=True)
    return True
