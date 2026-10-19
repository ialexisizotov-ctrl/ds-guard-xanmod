#!/usr/bin/env python3
"""Refuse replacement of existing packages immediately before APT invokes dpkg."""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


ENV = {**os.environ, 'LC_ALL': 'C'}
PACKAGE = re.compile(r'[a-z0-9][a-z0-9+.-]+')
ARCH = re.compile(r'[a-z0-9][a-z0-9-]*')


def apt_gate_options(script=None):
    script = Path(script or __file__).resolve()
    command = '/usr/bin/python3 ' + shlex.quote(str(script)) + ' --apt-hook'
    # APT documents protocol 1 (one archive path per line) as the default.
    # Set the version and descriptor for this exact invocation as well.
    return [
        '-o', 'DPkg::Pre-Install-Pkgs::=' + command,
        '-o', 'DPkg::Tools::Options::' + command + '::Version=1',
        '-o', 'DPkg::Tools::Options::' + command + '::InfoFD=0',
    ]


def archive_identity(path):
    path = Path(path)
    if not path.is_absolute() or not path.is_file():
        raise RuntimeError('Не найден абсолютный путь пакетного архива: ' + str(path))
    result = subprocess.run(
        ['dpkg-deb', '--show', '--showformat=${Package}\t${Architecture}\t${Version}\n', str(path)],
        capture_output=True, text=True, check=True, timeout=30, env=ENV)
    fields = result.stdout.rstrip('\n').split('\t')
    if (len(fields) != 3 or not PACKAGE.fullmatch(fields[0]) or
            not ARCH.fullmatch(fields[1]) or not fields[2] or '\n' in fields[2]):
        raise RuntimeError('Некорректные метаданные пакетного архива: ' + str(path))
    return tuple(fields)


def installed_identity(package, architecture):
    # Query every installed architecture of this name. An all -> amd64
    # transition can replace an existing package even when name:amd64 is absent.
    # Conservatively reject multiarch additions too; this installer is amd64-only.
    result = subprocess.run(
        ['dpkg-query', '--show', '--showformat=${db:Status-Status}\t${Version}\n',
         package],
        capture_output=True, text=True, timeout=30, env=ENV)
    if result.returncode == 1 and not result.stdout:
        return None
    if result.returncode:
        raise RuntimeError('Не удалось проверить текущий пакет: ' + package)
    current = []
    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 2:
            raise RuntimeError('Неоднозначное состояние текущего пакета: ' + package)
        if fields[0] in ('not-installed', 'config-files'):
            continue
        if fields[0] != 'installed':
            raise RuntimeError('Пакет находится в незавершённом состоянии: ' + package)
        current.append(fields[1])
    return ', '.join(current) if current else None


def check_archives(paths):
    seen = {}
    checked = []
    for path in paths:
        package, architecture, version = archive_identity(path)
        identity = package + ':' + architecture
        if identity in seen and seen[identity] != version:
            raise RuntimeError('Две версии одного пакета в одной операции: ' + identity)
        seen[identity] = version
        current = installed_identity(package, architecture)
        if current is not None:
            raise RuntimeError(
                'Установка затрагивает ранее установленный пакет ' + identity +
                ' (' + current + ' → ' + version + '). Обновление, откат версии и переустановка запрещены.')
        checked.append(identity)
    return checked


def hook_paths(stream):
    paths = []
    for raw in stream:
        line = raw.rstrip('\n')
        if not line:
            continue
        # Never interpret protocol-2/3 configuration or actions as archive paths.
        if not line.startswith('/') or '\r' in line or '\x00' in line:
            raise RuntimeError('Неизвестный формат APT hook; ожидался список путей архивов версии 1')
        paths.append(line)
    return paths


def main():
    parser = argparse.ArgumentParser(description='Защита исходных пакетов системы перед установкой')
    parser.add_argument('--apt-hook', action='store_true')
    parser.add_argument('archives', nargs='*')
    args = parser.parse_args()
    if args.apt_hook:
        if args.archives:
            raise RuntimeError('APT hook принимает архивы только через входной поток')
        descriptor = int(os.environ.get('APT_HOOK_INFO_FD', '0'))
        if descriptor != 0:
            raise RuntimeError('Неожиданный дескриптор APT hook')
        archives = hook_paths(sys.stdin)
    else:
        archives = args.archives
    check_archives(archives)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('[ОШИБКА] Изменение прежних пакетов остановлено: ' + str(error), file=sys.stderr)
        sys.exit(1)
