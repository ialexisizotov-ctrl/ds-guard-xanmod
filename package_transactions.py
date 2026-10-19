#!/usr/bin/env python3
"""Attribute installed packages to this child dpkg log, never a global delta."""
import argparse, json, os, re, subprocess, sys, uuid
from pathlib import Path
from package_install_gate import apt_gate_options, check_archives

STATE = Path('/var/lib/ds-guard-safe')
ENV = {**os.environ, 'LC_ALL':'C', 'DEBIAN_FRONTEND':'noninteractive', 'NEEDRESTART_SUSPEND':'1'}

def package_state():
    fmt = '${Package}\t${Architecture}\t${db:Status-Status}\t${Version}\t${binary:Package}\n'
    p = subprocess.run(['dpkg-query','-W','-f='+fmt], capture_output=True, text=True, check=True, timeout=60, env=ENV)
    result = {}
    for line in p.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) == 5 and fields[2] == 'installed':
            result[fields[0]+':'+fields[1]] = (fields[4], fields[3])
    return result

def secure_directory(path):
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise RuntimeError('Каталог пакетного журнала является ссылкой: '+str(parent))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o022:
        raise RuntimeError('Небезопасные права каталога пакетного журнала: '+str(path))

def save(path, value):
    temporary = path.with_suffix('.next')
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)

def logged_installs(text, before, after):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        # dpkg logs "date time install package:arch <none> version".
        if len(fields) != 6 or fields[2] != 'install' or fields[4] != '<none>':
            continue
        package, version = fields[3], fields[5]
        if package in before or package not in after:
            continue
        binary, actual = after[package]
        if actual != version:
            raise RuntimeError('Версия пакета отличается от собственной операции: '+binary)
        if binary in result and result[binary] != actual:
            raise RuntimeError('Неоднозначная версия установленного пакета: '+binary)
        result[binary] = actual
    return result

def with_private_log(command, log):
    if not command or command[0] not in ('apt-get','dpkg'):
        raise RuntimeError('Неизвестная пакетная команда')
    if any('--log' in argument or 'Dpkg::Options' in argument or 'DPkg::Options' in argument for argument in command):
        raise RuntimeError('Нельзя подменять отдельный пакетный журнал')
    if command[0] == 'apt-get' and 'install' in command:
        return [command[0], '-o', 'Dpkg::Options::=--log='+str(log), *apt_gate_options(), *command[1:]]
    if command[0] == 'dpkg' and '-i' in command:
        return [command[0], '--log='+str(log), *command[1:]]
    raise RuntimeError('Разрешён только шаг установки пакетов')

def execute(command, timeout=600, stdout=None):
    pending = STATE/'lifecycle/pending.json'
    operation_id = None
    if pending.is_symlink():
        raise RuntimeError('Журнал операции является ссылкой')
    if pending.exists():
        data = json.loads(pending.read_text())
        operation_id = data.get('operation_id')
        if not isinstance(operation_id, str) or str(uuid.UUID(operation_id)) != operation_id:
            raise RuntimeError('Некорректный идентификатор операции')
    directory = STATE/('lifecycle/package-receipts' if operation_id else 'package-transactions')
    secure_directory(directory)
    identifier = str(uuid.uuid4())
    receipt = directory/(identifier+'.json'); log = directory/(identifier+'.dpkg.log')
    invocation = with_private_log(command, log)
    if command[0] == 'dpkg':
        check_archives(command[command.index('-i')+1:])
    before = package_state()
    # Publish incomplete receipt before starting the package child. Timeouts
    # deliberately leave it incomplete; the parent must not guess ownership.
    data = {'schema':1,'operation_id':operation_id,'completed':False,'installed':{}}
    save(receipt, data)
    fd = os.open(log, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); os.close(fd)
    p = subprocess.run(invocation, stdout=stdout, stderr=subprocess.STDOUT, timeout=timeout, env=ENV)
    after = package_state()
    data.update(completed=True, returncode=p.returncode, installed=logged_installs(log.read_text(), before, after))
    save(receipt, data)
    return p.returncode

def main():
    parser = argparse.ArgumentParser(description='Установка пакетов с отдельным журналом происхождения')
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    return execute(command, args.timeout)

if __name__ == '__main__':
    try: sys.exit(main())
    except subprocess.TimeoutExpired:
        print('[ТАЙМАУТ] Пакетный процесс не завершён; требуется остановка всей рабочей группы перед восстановлением.', file=sys.stderr)
        sys.exit(124)
    except Exception as error:
        print('[ОШИБКА] Пакетная операция не подтверждена: '+str(error), file=sys.stderr)
        sys.exit(1)
