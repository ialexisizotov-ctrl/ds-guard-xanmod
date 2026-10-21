#!/usr/bin/env bash
# Public one-command entrypoint. Keep the whole bootstrap in a function so an
# interrupted curl pipe cannot execute a partially received installation body.
ds_guard_interactive_main() (
    set -euo pipefail
    umask 077
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    unset BASH_ENV ENV PYTHONPATH PYTHONHOME PYTHONSTARTUP
    [ "$(id -u)" = 0 ] || {
        echo '[ОШИБКА] Нужны права root. sudo перед curl повышает права только загрузки.' >&2
        echo '[КОМАНДА] curl -fsSL https://raw.githubusercontent.com/ialexisizotov-ctrl/ds-guard-xanmod/main/interactive.sh | sudo bash' >&2
        exit 77
    }
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
        2f597ec1b59dd35bcec8ae1ea8c032f24fae9c07ca12201d2f3d73ba9e77adfe "$work/wizard.py" \
        12c70eb400148071e02388a6cf344931c2f2cbd3ed0dbeec86e3d14e30abfb5c "$work/boot_trial.py" |
        sha256sum --check --strict --status || {
            echo '[ОСТАНОВЛЕНО] Файлы мастера не совпали с контрольными суммами. Повторите позже; установка не начата.' >&2
            exit 78
        }
    python3 -E -s -B "$work/wizard.py" "$@"
)
ds_guard_interactive_main "$@"
