#!/usr/bin/env python3
"""Persistent boot fence while a quarantined legacy activation is unaccepted."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

SYSTEM_ROOT = Path('/')
ROOT_UID = 0
STATE = Path('/var/lib/ds-guard-safe')
MARKER = STATE / 'activation-guard.json'
HELPER = Path('/usr/local/lib/ds-guard-safe/activation_guard.py')
DROPINS = tuple(Path('/etc/systemd/system') / (u + '.d/98-safe-activation.conf')
               for u in ('ds-guard.service', 'ds-guard-apply.service'))
BODY = '[Service]\nExecCondition=/usr/bin/python3 ' + str(HELPER) + ' check\n'
OLD_HOLDS = tuple(p.with_name('90-codex-ndpi-memory-hold.conf') for p in DROPINS)
OLD_BODY = '[Unit]\nConditionPathExists=!/root/codex-dsguard-20261019/ndpi-memory-safety-hold\n'
ACCEPTED = 'Local acceptance passed\n'


def path(p):
    return SYSTEM_ROOT / str(p).lstrip('/')


def parents_safe(p):
    if any(parent.is_symlink() for parent in p.parents):
        raise RuntimeError('Каталог запрета активации заменён ссылкой: ' + str(p))


def regular(p, mode=None, text=None):
    parents_safe(p)
    if p.is_symlink() or not p.is_file():
        raise RuntimeError('Не подтверждён обычный файл запрета активации: ' + str(p))
    s = p.stat()
    if s.st_uid != ROOT_UID or mode is not None and s.st_mode & 0o777 != mode:
        raise RuntimeError('Не подтверждены права файла запрета активации: ' + str(p))
    if text is not None and p.read_text() != text:
        raise RuntimeError('Файл запрета активации изменён вне установщика: ' + str(p))


def sync_dir(p):
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def durable_file(p):
    with p.open('rb') as f:
        os.fsync(f.fileno())
    sync_dir(p.parent)


def atomic_write(p, text, mode):
    parents_safe(p)
    if p.exists() or p.is_symlink():
        regular(p)
    missing = [q for q in (p.parent, *p.parent.parents) if not q.exists()]
    p.parent.mkdir(parents=True, exist_ok=True)
    for q in reversed(missing):
        sync_dir(q.parent)
    temp = p.with_name('.' + p.name + '.' + str(uuid.uuid4()))
    try:
        with temp.open('x', encoding='utf-8') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        temp.replace(p)
        sync_dir(p.parent)
    finally:
        temp.unlink(missing_ok=True)


def transaction_path(value):
    p = Path(value)
    if p.parent != STATE / 'transactions' or not re.fullmatch('[0-9a-f-]{36}', p.name):
        raise RuntimeError('Неверная операция в запрете активации')
    return p


def boot_id():
    value = path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch('[0-9a-f-]{36}', value):
        raise RuntimeError('Не удалось подтвердить текущую загрузку')
    return value


def load_marker():
    p = path(MARKER)
    regular(p, 0o600)
    d = json.loads(p.read_text())
    if d.get('schema') != 1 or not isinstance(d.get('boot_id'), str) or not re.fullmatch('[0-9a-f-]{36}', d['boot_id']):
        raise RuntimeError('Повреждён запрет незавершённой активации')
    txn = transaction_path(d.get('transaction', ''))
    before = path(txn / 'before.json')
    regular(before, 0o600)
    if json.loads(before.read_text()).get('boot_id') != d['boot_id']:
        raise RuntimeError('Загрузка запрета не совпала с исходной операцией')
    return d, txn


def accepted(txn):
    committed, evidence = path(txn / 'committed'), path(txn / 'acceptance.json')
    if not committed.exists() and not committed.is_symlink():
        return False
    regular(committed, 0o600, ACCEPTED)
    regular(evidence, 0o600)
    d = json.loads(evidence.read_text())
    required = {'local_layers': 3, 'nfqueue_listeners': [0, 1],
                'new_kernel_errors': 0, 'foreign_firewall_preserved': True, 'strict_https': True}
    if any(d.get(k) != v for k, v in required.items()):
        raise RuntimeError('Приёмка незавершённой активации не подтверждена')
    return True


def permits_start():
    p = path(MARKER)
    parents_safe(p)
    if not p.exists() and not p.is_symlink():
        return True
    d, txn = load_marker()
    if path(txn / 'rolled-back').exists():
        return False
    return accepted(txn) or d['boot_id'] == boot_id()


def reload_units():
    subprocess.run(['systemctl', 'daemon-reload'], check=True, capture_output=True, text=True, timeout=30)


def arm(txn):
    txn = transaction_path(txn)
    current_boot = boot_id()
    before = path(txn / 'before.json')
    regular(before, 0o600)
    if json.loads(before.read_text()).get('boot_id') != current_boot:
        raise RuntimeError('Активация относится к другой загрузке')
    if path(txn / 'committed').exists() or path(txn / 'rolled-back').exists():
        raise RuntimeError('Операция активации уже завершена')
    # All validation precedes writes; the old holds still protect every step.
    for hold in OLD_HOLDS:
        regular(path(hold), 0o644, OLD_BODY)
    regular(path(HELPER), 0o644)
    for dropin in DROPINS:
        p = path(dropin)
        parents_safe(p)
        if p.exists() or p.is_symlink():
            regular(p, 0o644, BODY)
    if path(MARKER).exists() or path(MARKER).is_symlink():
        old, old_txn = load_marker()
        if old_txn != txn and not accepted(old_txn):
            raise RuntimeError('Предыдущая активация не завершена; запрет сохранён')
        if old_txn == txn and old['boot_id'] != current_boot:
            raise RuntimeError('Запрет относится к прежней загрузке')
    durable_file(path(HELPER))
    durable_file(before)
    atomic_write(path(MARKER), json.dumps({'schema': 1, 'transaction': str(txn), 'boot_id': current_boot}), 0o600)
    for dropin in DROPINS:
        atomic_write(path(dropin), BODY, 0o644)
    reload_units()


def complete(txn):
    txn = transaction_path(txn)
    d, recorded = load_marker()
    if recorded != txn or d['boot_id'] != boot_id() or not accepted(txn):
        raise RuntimeError('Запрет активации не снят: точная приёмка не подтверждена')
    for dropin in DROPINS:
        regular(path(dropin), 0o644, BODY)
    # Persist acceptance before withdrawing the boot fence. If interrupted
    # before unlink, check can independently recognize that exact acceptance.
    durable_file(path(txn / 'acceptance.json'))
    durable_file(path(txn / 'committed'))
    path(MARKER).unlink()
    sync_dir(path(MARKER).parent)


if __name__ == '__main__':
    try:
        if sys.argv[1:] != ['check']:
            raise SystemExit(64)
        if permits_start():
            raise SystemExit(0)
        print('[ЗАПУСК ЗАПРЕЩЁН] После перезагрузки обнаружена незавершённая активация ds-guard.', file=sys.stderr)
        raise SystemExit(1)
    except (RuntimeError, ValueError, OSError, KeyError, TypeError) as e:
        print('[ЗАПУСК ЗАПРЕЩЁН] ' + str(e), file=sys.stderr)
        raise SystemExit(1)
