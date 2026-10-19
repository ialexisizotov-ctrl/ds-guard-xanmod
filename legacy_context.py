"""Select a verified legacy transition; never a command-line bypass of gates."""
import json,re
from pathlib import Path

STATE=Path('/var/lib/ds-guard-safe')
HOLDS=[Path('/etc/systemd/system')/(u+'.d/90-codex-ndpi-memory-hold.conf') for u in ('ds-guard.service','ds-guard-apply.service')]

def context(root):
    baseline=STATE/'lifecycle/before.json'
    previous=Path('/etc/systemd/system/ds-guard.service').exists() or (STATE/'installed.json').exists()
    if not any(p.exists() or p.is_symlink() for p in HOLDS) and (baseline.exists() or not previous):return None
    pending=STATE/'pending.json'
    resumed=False
    if baseline.exists() and pending.is_file() and not pending.is_symlink():
        staged=json.loads(pending.read_text())
        resumed=staged.get('staged_boot_id')!=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    from legacy_upgrade import check_legacy
    return check_legacy(root=Path(root),allow_lifecycle=baseline.exists(),resumed=resumed)

def preflight(root,require_journal=False):
    from preflight import collect
    legacy=context(root)
    if legacy and require_journal:
        from legacy_upgrade import regular
        baseline=STATE/'lifecycle/before.json';pending=STATE/'lifecycle/pending.json'
        if not baseline.is_file() or not pending.is_file():raise RuntimeError('Для переустановки нужен журнал исходного состояния. Запустите setup.sh; прямой install.sh прежней установки запрещён.')
        regular(baseline,0o600);regular(pending,0o600)
        operation=json.loads(pending.read_text())
        if json.loads(baseline.read_text()).get('baseline_kind')!='legacy-upgrade' or not re.fullmatch('[0-9a-f-]{36}',operation.get('operation_id','')) or not isinstance(operation.get('packages_before'),dict):raise RuntimeError('Нет проверяемого исходного журнала операции переустановки; запуск остановлен')
    stage=bool(legacy and legacy['requires_reboot'])
    result=collect(stage_only=stage)
    result['legacy_upgrade']=legacy
    return result

if __name__=='__main__':
    import sys
    try:
        result=preflight(Path(__file__).resolve().parent,require_journal=True)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        sys.exit(0 if result['compatible'] else 78)
    except (RuntimeError,ValueError,OSError) as e:
        print('[ОСТАНОВЛЕНО] '+str(e),file=sys.stderr);sys.exit(78)
