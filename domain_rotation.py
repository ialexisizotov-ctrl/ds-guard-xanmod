"""Recognize only an unchanged policy moved between the vendor's A/B banks."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time

from transaction import managed_state, foreign_rules

GENERATION = '/etc/ds-guard/domain-generation.env'
INPUTS = tuple('/etc/ds-guard/' + name for name in
               ('domains.txt', 'domain-labels.txt', 'domain-patterns.txt'))
APPLY_LOCK = Path('/run/ds-guard/apply.lock')
GUARD_FILES = (Path('/etc/systemd/system/ds-guard.service'),
               Path('/usr/local/sbin/ds-guard-apply.sh'))
_local = threading.local()
_generation = re.compile(r'ACTIVE=(DS_DOM_[AB])\nDNS_RULES=(0|[1-9][0-9]*)\nHOST_RULES=(0|[1-9][0-9]*)\nPOLICY_SHA=([0-9a-f]{64})\n')


@contextmanager
def apply_lock(timeout=60):
    """Share the vendor flock only around local capture/stop, never a worker."""
    if getattr(_local, 'held', False):
        yield
        return
    if not APPLY_LOCK.exists() and not any(p.exists() for p in GUARD_FILES):
        yield
        return
    for parent in reversed(APPLY_LOCK.parents):
        if parent.is_symlink():
            raise RuntimeError('Каталог блокировки ds-guard является ссылкой')
        if parent.exists():
            st = parent.stat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise RuntimeError('Небезопасный каталог блокировки ds-guard')
    APPLY_LOCK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd = os.open(APPLY_LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022 or st.st_nlink != 1:
            raise RuntimeError('Небезопасный файл блокировки ds-guard')
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Не удалось дождаться завершения применения правил ds-guard')
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
        live = APPLY_LOCK.lstat()
        if (live.st_dev, live.st_ino) != (st.st_dev, st.st_ino):
            raise RuntimeError('Файл блокировки ds-guard заменён во время ожидания')
        _local.held = True
        try:
            yield
        finally:
            _local.held = False
    finally:
        os.close(fd)


def proof_material(snapshot):
    names = (GENERATION, *INPUTS)
    return copy.deepcopy({'generation_text': snapshot.get('generation_text'),
        'files': {p: snapshot.get('files', {}).get(p) for p in names},
        'file_owners': {p: snapshot.get('file_owners', {}).get(p) for p in names},
        'iptables': snapshot['iptables']})


def _bank(state):
    for bank in ('DS_DOM_A', 'DS_DOM_B'):
        names = {'DS_DOMAINS', bank, bank + '_D', bank + '_W'}
        if (set(state['chains']) == names and set(state['rules']) <= names
                and all(v == '-' for v in state['chains'].values())
                and state['rules'].get('DS_DOMAINS') == [['-j', bank]]):
            return bank
    return None


def _normalized(state, bank):
    names = {bank: 'DS_DOM_A', bank + '_D': 'DS_DOM_A_D', bank + '_W': 'DS_DOM_A_W'}
    def rule(tokens):
        result = list(tokens)
        for i, token in enumerate(tokens[:-1]):
            if token in ('-j', '-g') and tokens[i + 1] in names:
                result[i + 1] = names[tokens[i + 1]]
        return result
    return {'chains': {names.get(k, k): v for k, v in state['chains'].items()},
            'rules': {names.get(k, k): [rule(r) for r in v] for k, v in state['rules'].items()},
            'hooks': {k: [[pos, rule(r)] for pos, r in v] for k, v in state['hooks'].items()}}


def prove_bank_rotation(reference, actual):
    """No DNS updates: only exact token-position bank renaming is admitted."""
    old = reference.get('files', {}).get(GENERATION)
    new = actual.get('files', {}).get(GENERATION)
    text = actual.get('generation_text')
    if (not isinstance(old, dict) or not isinstance(new, dict)
            or set(old) != {'sha256', 'mode'} or set(new) != {'sha256', 'mode'}
            or old['mode'] != 0o600 or new['mode'] != 0o600
            or reference.get('file_owners', {}).get(GENERATION) != [0, 0]
            or actual.get('file_owners', {}).get(GENERATION) != [0, 0]
            or not isinstance(text, str) or len(text) > 256):
        return False
    match = _generation.fullmatch(text)
    if not match or hashlib.sha256(text.encode()).hexdigest() != new['sha256']:
        return False
    before = managed_state(reference['iptables'])
    current = managed_state(actual['iptables'])
    old_bank, new_bank = _bank(before), _bank(current)
    if not old_bank or not new_bank or old_bank == new_bank or match[1] != new_bank:
        return False
    expected = text.replace('ACTIVE=' + new_bank + '\n', 'ACTIVE=' + old_bank + '\n', 1)
    if hashlib.sha256(expected.encode()).hexdigest() != old['sha256']:
        return False
    for name in INPUTS:
        item = reference.get('files', {}).get(name)
        if (not isinstance(item, dict) or set(item) != {'sha256', 'mode'}
                or actual.get('files', {}).get(name) != item
                or reference.get('file_owners', {}).get(name) != [0, 0]
                or actual.get('file_owners', {}).get(name) != [0, 0]):
            return False
    return (_normalized(before, old_bank) == _normalized(current, new_bank)
            and foreign_rules(reference['iptables']) == foreign_rules(actual['iptables']))


def cold_subset(expected_text, current_text):
    """A verified cold legacy boot may lose rules, never add/change them."""
    expected, current = managed_state(expected_text), managed_state(current_text)
    if foreign_rules(expected_text) != foreign_rules(current_text):
        return False
    if any(expected['chains'].get(k) != v for k, v in current['chains'].items()):
        return False
    for chain, rules in current['rules'].items():
        if chain not in current['chains']:
            return False
        source = iter(expected['rules'].get(chain, []))
        for rule in rules:
            if any(rule[i:i+2] == ['-m', 'ndpi'] for i in range(len(rule) - 1)):
                return False
            if not any(r == rule for r in source):
                return False
    for chain, hooks in current['hooks'].items():
        prior = expected['hooks'].get(chain, [])
        j = 0
        for i, (position, rule) in enumerate(hooks):
            if any(rule[k:k+2] == ['-m', 'ndpi'] for k in range(len(rule) - 1)):
                return False
            while j < len(prior) and not (prior[j][1] == rule and position == prior[j][0] - (j - i)):
                j += 1
            if j == len(prior):
                return False
            j += 1
    return True
