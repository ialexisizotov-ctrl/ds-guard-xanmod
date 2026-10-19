#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! test -f SHA256SUMS || ! sha256sum --strict --check SHA256SUMS >/dev/null 2>&1; then
  echo '[ОШИБКА] Контрольные суммы комплекта не совпали. Установка не начата.' >&2
  exit 78
fi
if ! command -v python3 >/dev/null; then
  echo '[ОШИБКА] Для установщика нужен Python 3.' >&2; exit 78
fi
exec python3 "$(pwd)/setup_ru.py" "$@"
