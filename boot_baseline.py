"""First-touch runtime baseline after a verified, fresh kernel-only stage.

The pre-install snapshot is never rewritten. This is a new measured baseline,
not a claim that every changed value came from a kernel default. Existing guard
or tuning installations, same-boot drift, and foreign file changes still stop.
"""
import copy
import hashlib
import json
import os
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


def validate(before, after, current, trial, stage, boot_id):
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
    if not owned or any(p not in ('linux-image-'+target, 'linux-headers-'+target) for p in owned):
        raise RuntimeError('Не подтверждено происхождение только пакетов выбранного ядра')
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
    validate(before, after, current, trial, stage, boot_id)
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
