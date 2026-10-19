#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
test -f SHA256SUMS || { echo 'Missing release manifest'; exit 1; }
sha256sum --strict --check SHA256SUMS >/dev/null
if [ "${1:-}" = --check ]; then exec python3 legacy_context.py; fi
python3 legacy_context.py || exit 78
exec 8>/run/ds-guard-safe-launch.lock
flock -n 8 || { echo 'Another installer is running'; exit 75; }
for unit in ds-guard-safe-install.service ds-guard-safe-recover.service; do
  state=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
  case "$state" in active|activating|deactivating) echo 'Installation or recovery is already running'; exit 75;; esac
done
install -d -m 0755 /usr/local/lib/ds-guard-safe
# Only manifest-listed regular files from this release are installed.
python3 - <<'PY'
from pathlib import Path
import shutil,hashlib
src=Path.cwd();dest=Path('/usr/local/lib/ds-guard-safe')
for line in Path('SHA256SUMS').read_text().splitlines():
 sha,name=line.split(None,1);name=name.lstrip('*')
 p=Path(name)
 if p.is_absolute() or '..' in p.parts or (src/p).is_symlink():raise SystemExit('Unsafe manifest path')
 if hashlib.sha256((src/p).read_bytes()).hexdigest()!=sha:raise SystemExit('Manifest changed')
 target=dest/p;target.parent.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(src/p,target);target.chmod(0o644)
PY
cat > /etc/systemd/system/ds-guard-safe-recover.service <<'UNIT'
[Unit]
Description=Restore only the failed ds-guard installation transaction
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/ds-guard-safe/recover.py
TimeoutStartSec=180
UNIT
chmod 0644 /etc/systemd/system/ds-guard-safe-recover.service
systemctl daemon-reload
systemctl reset-failed ds-guard-safe-install.service 2>/dev/null || true
mem=$(awk '/MemAvailable:/ {printf "%.0f", $2*512}' /proc/meminfo)
[ "$mem" -le 3221225472 ] || mem=3221225472
echo 'Starting bounded installation; logs: journalctl -u ds-guard-safe-install'
rc=0
run_id=$(cat /proc/sys/kernel/random/uuid)
systemd-run --unit=ds-guard-safe-install --wait --collect --setenv="DS_INSTALL_RUN_ID=$run_id" \
  --property=Type=oneshot --property=Nice=10 --property=CPUQuota=200% \
  --property=IOWeight=10 --property=MemoryMax="$mem" --property=MemorySwapMax=0 \
  --property=OOMPolicy=stop --property=TimeoutStartSec=2000 \
  --property=OnFailure=ds-guard-safe-recover.service \
  --property=SuccessExitStatus=20 \
  /usr/bin/python3 /usr/local/lib/ds-guard-safe/run_worker.py "$@" || rc=$?
journalctl -u ds-guard-safe-install --no-pager -n 15
if [ -f "/run/ds-guard-safe-result.$run_id.json" ]; then
  rc=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["exit_code"])' "/run/ds-guard-safe-result.$run_id.json")
fi
exit "$rc"
