#!/usr/bin/env bash
# A release builder replaces these two literals after all acceptance gates.
set -euo pipefail
umask 077
release='UNRELEASED'
expected='UNRELEASED'
[[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo 'No accepted release is pinned in this development snapshot'; exit 78; }
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 77; }
work=$(mktemp -d /var/tmp/ds-guard-download.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
curl --proto '=https' --tlsv1.2 --fail --show-error --location --retry 2 --connect-timeout 15 --max-time 600 \
  "https://github.com/ialexisizotov-ctrl/ds-guard-xanmod/releases/download/$release/ds-guard-safe-$release.tar.gz" -o "$work/release.tar.gz"
printf '%s  %s\n' "$expected" "$work/release.tar.gz" | sha256sum --check --strict -
python3 - "$work/release.tar.gz" "$work" <<'PY'
import pathlib,sys,tarfile
archive,dest=sys.argv[1:]
with tarfile.open(archive,'r:gz') as t:
 members=t.getmembers()
 for m in members:
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not (m.isfile() or m.isdir()):raise SystemExit('Unsafe release archive entry')
  if not p.parts or p.parts[0]!='ds-guard-safe':raise SystemExit('Unexpected release root')
 t.extractall(dest,members=members)
PY
bash "$work/ds-guard-safe/install.sh" "$@"
