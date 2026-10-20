#!/usr/bin/env python3
"""Install missing Ubuntu dependencies with private, signed official indexes.

Host package status, holds, preferences and dpkg hooks remain authoritative.
This isolates APT source/index acquisition, not package maintainer scripts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

import package_transactions as ledger

KEYRING = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
SUITES = {'22.04': 'jammy', '24.04': 'noble'}
REQUEST = re.compile(r'([a-z0-9][a-z0-9+.-]+)(?::(amd64|all))?(?:=([0-9][A-Za-z0-9.+:~_-]*))?')
ENV = {**ledger.ENV, 'LC_ALL': 'C'}
CLEAR_UPDATE_HOOKS = '''#clear APT::Update::Pre-Invoke;
#clear APT::Update::Post-Invoke;
#clear APT::Update::Post-Invoke-Success;
'''


def checked(command, timeout=60):
    return subprocess.run(command, capture_output=True, text=True, check=True,
                          timeout=timeout, env=ENV).stdout.strip()


def environment():
    info = platform.freedesktop_os_release()
    suite = SUITES.get(info.get('VERSION_ID'))
    if info.get('ID') != 'ubuntu' or not suite or info.get('VERSION_CODENAME') != suite:
        raise RuntimeError('Изолированная установка зависимостей поддерживает только Ubuntu 22.04/jammy и 24.04/noble')
    if checked(['dpkg', '--print-architecture']) != 'amd64':
        raise RuntimeError('Изолированная установка зависимостей поддерживает только архитектуру amd64')
    if checked(['dpkg', '--audit']):
        raise RuntimeError('Есть незавершённые пакетные операции; зависимости не изменены')
    for p in [KEYRING, *KEYRING.parents]:
        st = p.lstat()
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError('Небезопасный путь системного ключа архива Ubuntu')
    if not KEYRING.is_file() or not KEYRING.stat().st_size:
        raise RuntimeError('Отсутствует системный ключ архива Ubuntu')
    if checked(['dpkg-query', '-W', '-f=${db:Status-Status}', 'ubuntu-keyring']) != 'installed':
        raise RuntimeError('Пакет ubuntu-keyring не установлен; автоматический импорт ключей запрещён')
    if checked(['dpkg-query', '-S', str(KEYRING)]) != 'ubuntu-keyring: ' + str(KEYRING):
        raise RuntimeError('Системный ключ архива не принадлежит пакету ubuntu-keyring')
    account = pwd.getpwnam('_apt')
    if account.pw_uid == 0:
        raise RuntimeError('Пользователь песочницы APT не должен иметь UID 0')
    return suite, account.pw_uid, account.pw_gid


def missing_packages(requests):
    missing = []
    for value in requests:
        match = REQUEST.fullmatch(value)
        if not match:
            raise RuntimeError('Некорректное имя зависимости: ' + value)
        name, arch, version = match.groups()
        p = subprocess.run(['dpkg-query', '-W', '-f=${Architecture}\t${db:Status-Status}\t${Version}\n', name],
                           capture_output=True, text=True, timeout=30, env=ENV)
        if p.returncode == 1 and not p.stdout:
            missing.append(value)
            continue
        if p.returncode:
            raise RuntimeError('Не удалось проверить установленную зависимость: ' + name)
        installed = []
        for line in p.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) != 3:
                raise RuntimeError('Неоднозначное состояние зависимости: ' + name)
            if fields[1] in ('not-installed', 'config-files'):
                continue
            if fields[1] != 'installed':
                raise RuntimeError('Зависимость находится в незавершённом состоянии: ' + name)
            installed.append(fields)
        if not installed:
            missing.append(value)
        elif (len(installed) != 1 or installed[0][0] not in (arch or 'amd64', 'all')
              or (version and version != installed[0][2])):
            raise RuntimeError('Замена версии или архитектуры прежнего пакета запрещена: ' + name)
    return list(dict.fromkeys(missing))


def sources(suite):
    if suite not in SUITES.values():
        raise RuntimeError('Неизвестный выпуск Ubuntu')
    options = 'arch=amd64 signed-by=' + str(KEYRING) + ' check-valid-until=yes check-date=yes'
    return ''.join('deb [' + options + '] ' + uri + ' ' + pocket + ' main universe\n'
                   for uri, pocket in [
                       ('https://archive.ubuntu.com/ubuntu', suite),
                       ('https://archive.ubuntu.com/ubuntu', suite + '-updates'),
                       ('https://security.ubuntu.com/ubuntu', suite + '-security')])


def make_scope(suite, uid, gid):
    # /var/lib/ds-guard-safe is deliberately 0700. Do not put _apt downloads
    # beneath it or silently disable the APT sandbox to make that work.
    root = Path(tempfile.mkdtemp(prefix='ds-guard-ubuntu-apt-', dir='/var/tmp'))
    root.chmod(0o755)
    for name in ['sources.parts', 'lists', 'cache', 'cache/archives', 'log']:
        (root / name).mkdir(mode=0o755)
        (root / name).chmod(0o755)
    for name in ['lists/partial', 'cache/archives/partial']:
        p = root / name
        p.mkdir(mode=0o700)
        os.chown(p, uid, gid)
    (root / 'sources.list').write_text(sources(suite))
    (root / 'sources.list').chmod(0o644)
    (root / 'scope.conf').write_text(CLEAR_UPDATE_HOOKS)
    (root / 'scope.conf').chmod(0o644)
    return root


def sandbox_access(root, uid, gid):
    script = ('import os,sys; paths=sys.argv[1:]; '
              'assert all(os.access(p,os.R_OK) for p in paths[:3]); '
              'assert all(os.access(p,os.W_OK|os.X_OK) for p in paths[3:])')
    subprocess.run(['/usr/bin/python3', '-c', script, str(root/'sources.list'),
                    str(root/'scope.conf'), str(KEYRING), str(root/'lists/partial'),
                    str(root/'cache/archives/partial')], check=True, timeout=15,
                   user=uid, group=gid, extra_groups=[], env=ENV)


def apt_options(root):
    settings = {
        'Dir::Etc::sourcelist': str(root/'sources.list'),
        'Dir::Etc::sourceparts': str(root/'sources.parts'),
        'Dir::State::lists': str(root/'lists'),
        'Dir::Cache': str(root/'cache'),
        'Dir::Cache::archives': str(root/'cache/archives'),
        'Dir::Cache::pkgcache': '', 'Dir::Cache::srcpkgcache': '',
        'Dir::Log::Terminal': str(root/'log/term.log'),
        'Dir::Log::History': str(root/'log/history.log'),
        'Dir::Log::Planner': str(root/'log/eipp.log.xz'),
        'APT::Sandbox::User': '_apt', 'Debug::NoLocking': 'false',
        'APT::Update::Error-Mode': 'any',
        'Acquire::AllowInsecureRepositories': 'false',
        'Acquire::AllowWeakRepositories': 'false',
        'Acquire::AllowDowngradeToInsecureRepositories': 'false',
        'APT::Get::AllowUnauthenticated': 'false',
        'APT::Get::allow-downgrades': 'false',
        'APT::Get::allow-change-held-packages': 'false',
        'APT::Get::allow-remove-essential': 'false',
        'APT::Ignore-Hold': 'false',
        'Acquire::Check-Valid-Until': 'true', 'Acquire::Check-Date': 'true',
        'Acquire::ForceIPv4': 'true', 'Acquire::Retries': '3',
        'Acquire::http::Timeout': '25', 'Acquire::https::Timeout': '25',
        'Acquire::https::Verify-Peer': 'true', 'Acquire::https::Verify-Host': 'true',
        'DPkg::Lock::Timeout': '120',
    }
    for host in ['archive.ubuntu.com', 'security.ubuntu.com']:
        for key in ['Verify-Peer', 'Verify-Host']:
            settings['Acquire::https::' + host + '::' + key] = 'true'
    result = ['-c', str(root/'scope.conf')]
    for key, value in settings.items():
        result += ['-o', key + '=' + value]
    return result


def operation_directory(transaction):
    transaction = Path(transaction)
    if (not transaction.is_absolute() or transaction.parent != ledger.STATE/'transactions'
            or str(uuid.UUID(transaction.name)) != transaction.name):
        raise RuntimeError('Изолированной установке требуется собственная транзакция ds-guard')
    for p in [transaction, *transaction.parents]:
        if p.is_symlink():
            raise RuntimeError('Путь транзакции является ссылкой')
    st = transaction.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Небезопасные права исходной транзакции ds-guard')
    if not (transaction/'before.json').is_file():
        raise RuntimeError('Отсутствует исходный снимок транзакции ds-guard')
    directory = transaction/'ubuntu-apt'
    ledger.secure_directory(directory)
    return directory


def installed_packages():
    text = checked(['dpkg-query', '-W', '-f=${Package}\t${Architecture}\t${db:Status-Status}\t${Version}\t${source:Package}\t${source:Version}\n'])
    result = {}
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) != 6:
            raise RuntimeError('Не удалось однозначно прочитать исходные версии пакетов')
        name, arch, state, version, source, source_version = fields
        if state in ('not-installed', 'config-files'):
            continue
        if state != 'installed':
            raise RuntimeError('Есть незавершённая пакетная операция')
        result.setdefault(name, []).append({
            'architecture': arch, 'version': version,
            'source': source, 'source_version': source_version})
    return result


def simulation(root, options, packages, suffix):
    path = root/('resolve-' + suffix + '.log')
    with path.open('w') as stream:
        p = subprocess.run(['apt-get', *options, '--simulate', '--no-remove', '--no-upgrade',
                            'install', *packages], stdout=stream, stderr=subprocess.STDOUT,
                           timeout=120, env=ENV)
    text = path.read_text()
    if p.returncode:
        raise RuntimeError('APT не нашёл совместимый план зависимостей; пакеты не изменены')
    plan = {}
    for line in text.splitlines():
        if line.startswith('Remv '):
            raise RuntimeError('План APT требует удаления прежнего пакета; установка остановлена')
        if not line.startswith('Inst '):
            continue
        match = re.match(r'^Inst ([a-z0-9][a-z0-9+.-]+(?::[a-z0-9-]+)?) (?:\[([^\]]+)\] )?\((\S+)', line)
        if not match:
            raise RuntimeError('Не удалось проверить строку плана APT')
        name, prior, version = match.groups()
        base = name.split(':', 1)[0]
        if base in plan:
            raise RuntimeError('Неоднозначная архитектура в плане APT: ' + base)
        plan[base] = {'name': name, 'version': version, 'prior': prior}
    return plan


def package_records(text):
    records = []
    for block in re.split(r'\n\s*\n', text.strip()):
        fields = {}
        for line in block.splitlines():
            if not line or line[0].isspace():
                continue
            key, sep, value = line.partition(':')
            if sep:
                fields[key] = value.strip()
        if not fields:
            continue
        if not all(fields.get(key) for key in ('Package', 'Version', 'Architecture')):
            raise RuntimeError('Неполные метаданные зависимости Ubuntu')
        source = fields.get('Source', fields['Package'])
        match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]+)(?: \(([^()\s]+)\))?', source)
        if not match:
            raise RuntimeError('Неоднозначная исходная версия зависимости Ubuntu')
        fields['Source-Package'] = match[1]
        fields['Source-Version'] = match[2] or fields['Version']
        records.append(fields)
    return records


def policy_priorities(text):
    result = {}
    name = None
    for line in text.splitlines():
        header = re.fullmatch(r'([a-z0-9][a-z0-9+.-]+)(?::[a-z0-9-]+)?:', line)
        if header:
            name = header[1]
            if name in result:
                raise RuntimeError('Неоднозначная архитектура в политике APT')
            result[name] = {}
            continue
        version = re.fullmatch(r'\s+(?:\*\*\*\s+)?([0-9][A-Za-z0-9.+:~_-]*)\s+(-?\d+)\s*', line)
        if name and version:
            result[name][version[1]] = int(version[2])
    return result


def resolve_packages(root, options, missing):
    """One conservative source-cohort fallback, never a general backtracking solver."""
    before = installed_packages()
    first = simulation(root, options, missing, 'initial')
    changing = {name: item for name, item in first.items()
                if name in before or item['prior'] is not None}
    selected = {}
    if changing:
        cohorts = {}
        for name in changing:
            entries = before.get(name, [])
            if len(entries) != 1 or entries[0]['architecture'] not in ('amd64', 'all'):
                raise RuntimeError('Неоднозначный прежний пакет в плане APT: ' + name)
            entry = entries[0]
            source, version = entry['source'], entry['source_version']
            if not source or not version:
                raise RuntimeError('Нет исходной версии прежнего пакета: ' + name)
            if source in cohorts and cohorts[source] != version:
                raise RuntimeError('Прежние пакеты одного исходного проекта имеют разные версии')
            cohorts[source] = version
        # Do not infer a single source baseline when other installed siblings
        # already have a different source version.
        for entries in before.values():
            for entry in entries:
                if entry['source'] in cohorts and entry['source_version'] != cohorts[entry['source']]:
                    raise RuntimeError('Неоднозначная исходная версия установленных зависимостей')
        new_names = [name for name, item in first.items() if name not in before and item['prior'] is None]
        if not new_names:
            raise RuntimeError('Для установки требуется замена прежних пакетов')
        records = package_records(checked(['apt-cache', *options, 'show', *new_names], timeout=120))
        for name in new_names:
            available = [r for r in records if r['Package'] == name and r['Architecture'] in ('amd64', 'all')]
            current = [r for r in available if r['Version'] == first[name]['version']]
            identities = {(r['Source-Package'], r['Source-Version']) for r in current}
            if len(identities) != 1:
                raise RuntimeError('Не удалось подтвердить исходный пакет зависимости: ' + name)
            source, _ = next(iter(identities))
            if source not in cohorts:
                continue
            versions = {r['Version'] for r in available
                        if r['Source-Package'] == source and r['Source-Version'] == cohorts[source]}
            if len(versions) != 1:
                raise RuntimeError('Совместимая версия отсутствующей зависимости недоступна или неоднозначна: ' + name)
            version = versions.pop()
            if not REQUEST.fullmatch(name + '=' + version):
                raise RuntimeError('Некорректная версия зависимости')
            selected[name] = version
        if not selected:
            raise RuntimeError('Нет совместимых отсутствующих зависимостей без замены прежних пакетов')
        priorities = policy_priorities(checked(['apt-cache', *options, 'policy', *sorted(selected)], timeout=120))
        for name, version in selected.items():
            values = priorities.get(name, {})
            if version not in values or values[version] <= 0 or values[version] < max(values.values()):
                raise RuntimeError('Политика APT не разрешает выбор совместимой версии зависимости: ' + name)
        arguments = []
        for request in missing:
            name, arch, exact = REQUEST.fullmatch(request).groups()
            if name in selected:
                if exact and exact != selected[name]:
                    raise RuntimeError('Запрошенная версия несовместима с прежними зависимостями: ' + name)
                arguments.append(name + (':' + arch if arch else '') + '=' + selected.pop(name))
            else:
                arguments.append(request)
        arguments.extend(name + '=' + version for name, version in sorted(selected.items()))
        final = simulation(root, options, arguments, 'compatible')
        if any(name in before or item['prior'] is not None for name, item in final.items()):
            raise RuntimeError('Совместимый план всё ещё меняет прежний пакет; установка остановлена')
    else:
        arguments = list(missing)
    if installed_packages() != before:
        raise RuntimeError('Пакетное состояние изменилось во время проверки плана')
    return arguments, {
        'fallback_used': bool(changing), 'passes': 2 if changing else 1,
        'installed_versions_preserved': True, 'arguments': arguments,
        'installed_snapshot_sha256': hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()}


def install(requests, transaction):
    missing = missing_packages(requests)
    if not missing:
        print('[ЗАВИСИМОСТИ] Все запрошенные пакеты уже установлены; APT не запускался.')
        return 0
    directory = operation_directory(transaction)
    suite, uid, gid = environment()
    root = make_scope(suite, uid, gid)
    receipt = directory/(str(uuid.uuid4())+'.json')
    options = apt_options(root)
    data = {'schema': 1, 'completed': False, 'phase': 'preflight', 'suite': suite,
            'requested': requests, 'missing': missing, 'workspace': str(root),
            'source_sha256': hashlib.sha256((root/'sources.list').read_bytes()).hexdigest(),
            'keyring_sha256': hashlib.sha256(KEYRING.read_bytes()).hexdigest(),
            'apt_options': options, 'host_preferences_and_holds_preserved': True,
            'update_hooks_suppressed_for_this_invocation': True}
    ledger.save(receipt, data)
    retain = False
    try:
        sandbox_access(root, uid, gid)
        print('[ЗАВИСИМОСТИ] Проверяются подписанные официальные индексы Ubuntu ' + suite +
              '; сторонние источники системы не изменяются.', flush=True)
        data['phase'] = 'update'; ledger.save(receipt, data)
        log = root/'update.log'
        with log.open('w') as stream:
            result = subprocess.run(['apt-get', *options, 'update'], stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=300, env=ENV)
        text = log.read_text(); print(text, end='', flush=True)
        if 'unsandboxed as root' in text:
            raise RuntimeError('APT не использовал пользователя _apt; установка остановлена')
        data['update_returncode'] = result.returncode
        if result.returncode:
            raise RuntimeError('Не удалось проверить все официальные индексы Ubuntu; пакеты не устанавливались')
        data['verified_inrelease_sha256'] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root/'lists').glob('*InRelease')) if p.is_file()}
        data['phase'] = 'resolve'; ledger.save(receipt, data)
        arguments, data['resolver'] = resolve_packages(root, options, missing)
        if data['resolver']['fallback_used']:
            print('[ЗАВИСИМОСТИ] Найдены совместимые версии новых зависимостей; прежние пакеты сохраняются.', flush=True)
        print('[ЗАВИСИМОСТИ] Устанавливаются только отсутствующие пакеты: ' + ', '.join(missing), flush=True)
        data['phase'] = 'install'; ledger.save(receipt, data)
        log = root/'install.log'
        with log.open('w') as stream:
            rc = ledger.execute(['apt-get', *options, '-y', '--no-remove', '--no-upgrade', 'install', *arguments],
                                timeout=600, stdout=stream)
        text = log.read_text(); print(text, end='', flush=True)
        if 'unsandboxed as root' in text:
            raise RuntimeError('APT не использовал пользователя _apt; требуется проверка пакетной операции')
        if rc == 0 and missing_packages(missing):
            raise RuntimeError('APT завершился без ошибки, но запрошенные зависимости не установлены')
        data.update(completed=True, phase='completed', returncode=rc)
        ledger.save(receipt, data)
        return rc
    except subprocess.TimeoutExpired:
        retain = True
        data.update(phase='timeout', workspace_retained=True)
        ledger.save(receipt, data)
        print('[ТАЙМАУТ] Приватные файлы APT сохранены: ' + str(root), file=sys.stderr)
        raise
    except Exception as error:
        data.update(phase='failed', error=str(error))
        ledger.save(receipt, data)
        raise
    finally:
        # Preserve diagnostics even if update/install timed out or a later gate
        # failed. Logs remain root-only alongside the existing transaction.
        data['logs'] = {}
        for name in ['update.log', 'resolve-initial.log', 'resolve-compatible.log', 'install.log']:
            path = root/name
            if path.is_file():
                target = directory/(receipt.stem+'.'+name)
                shutil.copyfile(path, target)
                target.chmod(0o600)
                data['logs'][name] = {'path': str(target),
                    'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
        ledger.save(receipt, data)
        # On timeout descendants may still hold these files until the outer
        # transaction controller stops the entire worker process group.
        if not retain:
            shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser(description='Зависимости из подписанных официальных источников Ubuntu')
    parser.add_argument('--transaction', required=True)
    parser.add_argument('packages', nargs='+')
    args = parser.parse_args()
    return install(args.packages, args.transaction)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except subprocess.TimeoutExpired:
        sys.exit(124)
    except Exception as error:
        print('[ОШИБКА] Установка зависимостей остановлена: ' + str(error), file=sys.stderr)
        sys.exit(1)
