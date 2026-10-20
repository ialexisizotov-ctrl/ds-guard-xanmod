"""Read a stable rule generation without racing the periodic enforcer."""
from pathlib import Path
import subprocess
import sys
from domain_rotation import apply_lock

ROOT = Path(__file__).resolve().parent

def verify(transaction):
    # Only the read-only verification child runs under the writer's lock.
    # Never hold this lock around driver apply or a systemctl start/stop.
    with apply_lock():
        result = subprocess.run(['bash', str(ROOT / 'driver.sh'),
                                 'verify-locked', str(transaction)], timeout=120)
    if result.returncode:
        print('[ОШИБКА] Проверка слоёв ds-guard не пройдена. Подробности: '
              + str(Path(transaction) / 'install.log'), file=sys.stderr)
    return result.returncode

if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('Не указан журнал транзакции')
        sys.exit(verify(sys.argv[1]))
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print('[ОШИБКА] Не удалось проверить неизменное состояние правил: '
              + str(exc), file=sys.stderr)
        sys.exit(78)
