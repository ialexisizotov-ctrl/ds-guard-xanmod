#!/usr/bin/env bash
# A release builder replaces these two literals after all acceptance gates.
set -euo pipefail
umask 077
echo '[КАНДИДАТ] Предварительный выпуск; production-приёмка ещё не завершена.'
release='v1.7.11-dsg2-rc8'
expected='ea218418327f0f15fcc53a2d406bece30da500049566a3ff89c789422f87b5a1'
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo '[ОСТАНОВЛЕНО] Принятого релиза пока нет. Предыдущий выпуск отозван; установка не начата.'; exit 78; }
[ "$(id -u)" = 0 ] || { echo '[ОШИБКА] Запустите установщик с правами root.'; exit 77; }
work=$(mktemp -d /var/tmp/ds-guard-download.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
echo '[ЗАГРУЗКА] Скачивание закреплённого проверенного комплекта.'
if ! curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --retry 2 --connect-timeout 15 --max-time 600 \
  "https://github.com/ialexisizotov-ctrl/ds-guard-xanmod/releases/download/$release/ds-guard-safe-$release.tar.gz" -o "$work/release.tar.gz"; then
  echo '[ОШИБКА] Комплект не загружен. Изменения не начаты.'; exit 1
fi
if ! printf '%s  %s\n' "$expected" "$work/release.tar.gz" | sha256sum --check --strict - >/dev/null; then
  echo '[ОШИБКА] Контрольная сумма комплекта не совпала. Изменения не начаты.'; exit 78
fi
python3 - "$work/release.tar.gz" "$work" <<'PY'
import pathlib,sys,tarfile
archive,dest=sys.argv[1:]
with tarfile.open(archive,'r:gz') as t:
 members=t.getmembers()
 for m in members:
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()):raise SystemExit('[ОШИБКА] Недопустимый файл внутри архива.')
  if not p.parts or p.parts[0]!='ds-guard-safe':raise SystemExit('[ОШИБКА] Неверная структура архива.')
 t.extractall(dest,members=members)
PY
bash "$work/ds-guard-safe/setup.sh" "$@"
