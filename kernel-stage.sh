#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
sha256sum --strict --check SHA256SUMS >/dev/null
test "$(id -u)" = 0
opts=()
if [ "${1:-}" = --kernel-only ]; then opts+=(--kernel-only); shift; fi
test "$#" = 2
kernel=$1
directory=$(realpath -- "$2")
exec 8>/run/ds-guard-safe-launch.lock
flock -n 8 || exit 75
for unit in ds-guard-safe-install.service ds-guard-safe-recover.service ds-guard-safe-kernel-stage.service ds-guard-safe-kernel-cleanup.service; do
 state=$(systemctl show "$unit" -p ActiveState --value 2>/dev/null || true)
 case "$state" in active|activating|deactivating) echo 'An installation or recovery is running'; exit 75;; esac
done
# Preserve the complete checked release for staging recovery and later boot.
install -d -m 0755 /usr/local/lib/ds-guard-safe-kernel
python3 - <<'PY'
from pathlib import Path
import shutil
for line in Path('SHA256SUMS').read_text().splitlines():
 _,name=line.split(None,1);p=Path(name.lstrip('*'))
 assert not p.is_absolute() and '..' not in p.parts and p.is_file() and not p.is_symlink()
 dest=Path('/usr/local/lib/ds-guard-safe-kernel')/p;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest);dest.chmod(0o644)
shutil.copyfile('SHA256SUMS','/usr/local/lib/ds-guard-safe-kernel/SHA256SUMS')
PY
cat > /etc/systemd/system/ds-guard-safe-kernel-cleanup.service <<'UNIT'
[Unit]
Description=Remove temporary exact-kernel build suppression after the worker stops
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/ds-guard-safe-kernel/kernel-stage.py --cleanup
TimeoutStartSec=90
UNIT
systemctl daemon-reload
systemctl reset-failed ds-guard-safe-kernel-stage.service 2>/dev/null || true
systemd-run --unit=ds-guard-safe-kernel-stage --wait --collect \
 --property=Type=oneshot --property=Nice=10 --property=CPUQuota=200% \
 --property=IOWeight=10 --property=MemoryMax=2G --property=MemorySwapMax=0 \
 --property=OOMPolicy=stop --property=TimeoutStartSec=1100 \
 --property=OnFailure=ds-guard-safe-kernel-cleanup.service \
 /usr/bin/python3 /usr/local/lib/ds-guard-safe-kernel/kernel-stage.py "${opts[@]}" "$kernel" "$directory"
echo 'Kernel staged alongside existing kernels. Boot selection and running services retained.'
