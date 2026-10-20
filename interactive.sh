#!/usr/bin/env bash
# Public one-command entrypoint. Keep the whole bootstrap in a function so an
# interrupted curl pipe cannot execute a partially received installation body.
ds_guard_interactive_main() (
    set -euo pipefail
    umask 077
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset BASH_ENV ENV PYTHONPATH PYTHONHOME PYTHONSTARTUP
    [ "$(id -u)" = 0 ] || { echo '[ОШИБКА] Запустите с sudo bash либо от root.' >&2; exit 77; }
    for command_name in curl python3 sha256sum mktemp; do
        command -v "$command_name" >/dev/null || {
            echo "[ОШИБКА] Не найдена команда: $command_name" >&2; exit 78;
        }
    done
    work=$(mktemp -d /var/tmp/ds-guard-wizard.XXXXXXXXXX)
    trap 'rm -rf -- "$work"' EXIT
    base=https://raw.githubusercontent.com/ialexisizotov-ctrl/ds-guard-xanmod/main
    echo '[ЗАГРУЗКА] Интерактивный мастер. Проверка файлов перед запуском.'
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        --connect-timeout 15 --max-time 120 "$base/wizard.py" -o "$work/wizard.py"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        --connect-timeout 15 --max-time 120 "$base/boot_trial.py" -o "$work/boot_trial.py"
    printf '%s  %s\n' \
        d3b99a2c562ba251fa1484ecfb77e01d495fafa33dc1675f98f5afe4e5d1f6fe "$work/wizard.py" \
        ed0e3c682ed01ed325bba442bef462ba1ac841a6b0a129373f5c5f5645456ab9 "$work/boot_trial.py" |
        sha256sum --check --strict --status || {
            echo '[ОСТАНОВЛЕНО] Файлы мастера не совпали с контрольными суммами. Повторите позже; установка не начата.' >&2
            exit 78
        }
    python3 -E -s -B "$work/wizard.py" "$@"
)
ds_guard_interactive_main "$@"
