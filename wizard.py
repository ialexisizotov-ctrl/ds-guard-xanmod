#!/usr/bin/env python3
"""Interactive, separately journalled boot workflow around the immutable rc4."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
import boot_trial as boot

VERSION = '1.0.0-rc11'
RELEASE = 'v1.7.11-dsg2-rc9'
ARCHIVE_SHA = '6d3eb76b7bb545ab31ff19f9148be77095cc6ef4a7888067e2b9b6601f2b841d'
ARCHIVE_BYTES = 71116763
MANIFEST_SHA = 'f0b2f40007a0beebcc9bfb93ff0e3d59c8dba8ca5f6fc14030596fd0f32aae51'
PAYLOAD_FILES = 94
ARCHIVE_MEMBERS = 95
URL = ("https://github.com/ialexisizotov-ctrl/ds-guard-xanmod/releases/download/"
       + RELEASE + "/ds-guard-safe-" + RELEASE + ".tar.gz")
CACHE = Path("/var/cache/ds-guard-wizard")
STATE = Path("/var/lib/ds-guard-wizard")
RC3_STATE = Path("/var/lib/ds-guard-safe")
ACTIVE = {"active", "activating", "deactivating"}


class Refusal(RuntimeError):
    pass


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(ok, message):
    if not ok:
        raise Refusal(message)


def secure_dir(path):
    path = Path(path)
    for part in reversed([path, *path.parents][:-1]):
        if part.exists() or part.is_symlink():
            s = part.lstat()
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                    "Небезопасный владелец, права или ссылка каталога: " + str(part))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def secure_file(path):
    path = Path(path)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
            "Небезопасный файл: " + str(path))
    return path


def save_receipt(name, data):
    secure_dir(STATE / "receipts")
    path = STATE / "receipts" / name
    require(re.fullmatch(r"[a-zA-Z0-9._-]+", name), "Недопустимое имя записи.")
    require(not path.exists() and not path.is_symlink(), "Запись уже существует.")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, ensure_ascii=False, indent=2)
        out.flush()
        os.fsync(out.fileno())
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def ask(text, choices, default=None, noninteractive=None):
    try:
        # A PTY is not seekable; Python's buffered r+ requires seekability.
        # Separate streams work both for SSH and curl | bash invocation.
        with open("/dev/tty", "r", encoding="utf-8") as tty_in, \
                open("/dev/tty", "w", encoding="utf-8") as tty_out:
            tty_out.write(text)
            tty_out.flush()
            line = tty_in.readline()
            require(bool(line), "Терминал закрыт. Действие не выбрано.")
            answer = line.strip()
    except OSError:
        if noninteractive is not None:
            print("[ОЖИДАНИЕ] Нет интерактивного терминала; перезагрузка не выполняется.")
            return noninteractive
        raise Refusal("Нужен интерактивный SSH-терминал. Для просмотра используйте --status.")
    answer = answer or default
    require(answer in choices, "Неизвестный пункт. Никакое действие не выбрано.")
    return answer


def run(command, **kwargs):
    return subprocess.run(command, check=False, **kwargs)


def verify_bundle(directory):
    directory = Path(directory)
    secure_dir(directory)
    manifest = secure_file(directory / "SHA256SUMS")
    require(sha(manifest) == MANIFEST_SHA, "Изменён manifest закреплённого комплекта.")
    names = set()
    for line in manifest.read_text().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        require(m is not None, "Повреждён manifest.")
        digest, name = m.groups()
        p = PurePosixPath(name)
        require(name not in names and not p.is_absolute() and
                all(part not in (".", "..", "") for part in name.split("/"))
                and "\\" not in name, "Недопустимый путь manifest.")
        names.add(name)
        for parent in (directory / name).parents:
            if parent == directory:
                break
            require(not parent.is_symlink(), "Ссылка внутри комплекта.")
        file = secure_file(directory / name)
        require(sha(file) == digest, "Контрольная сумма не совпала: " + name)
    require(len(names) == PAYLOAD_FILES, "Неожиданный состав комплекта.")
    all_paths = list(directory.rglob("*"))
    require(not any(p.is_symlink() for p in all_paths), "Ссылка внутри комплекта.")
    actual = {str(p.relative_to(directory)).replace(os.sep, "/") for p in all_paths if p.is_file()}
    require(actual == names | {"SHA256SUMS"}, "В комплекте найдены посторонние файлы.")
    return directory


def extract_bundle(archive, destination):
    destination = secure_dir(destination)
    root = destination / "ds-guard-safe"
    require(not root.exists() and not root.is_symlink(),
            "Каталог распаковки уже занят. Запись не начата.")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) == ARCHIVE_MEMBERS, "Неожиданный состав архива.")
        names = set()
        total = 0
        for item in members:
            p = PurePosixPath(item.name)
            require(item.isfile() and not p.is_absolute() and
                    p.parts[0] == "ds-guard-safe" and
                    ".." not in p.parts and "\\" not in item.name and
                    item.name not in names, "Недопустимый объект архива.")
            names.add(item.name)
            total += item.size
        require(total < 256 * 1024**2, "Слишком большой архив.")
        # Paths and all entry types have been validated before any extraction.
        for item in members:
            target = Path(destination) / item.name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = source.extractfile(item)
            require(stream is not None, "Не удалось прочитать архив.")
            with target.open("xb") as out, stream:
                shutil.copyfileobj(stream, out)
            target.chmod(0o600)
    return verify_bundle(Path(destination) / "ds-guard-safe")


def bundle():
    require(re.fullmatch(r"[0-9a-f]{64}", ARCHIVE_SHA) is not None and
            re.fullmatch(r"[0-9a-f]{64}", MANIFEST_SHA) is not None and
            PAYLOAD_FILES > 0 and ARCHIVE_MEMBERS == PAYLOAD_FILES + 1,
            "Сборка мастера ещё не опубликована: закреплённый комплект отсутствует.")
    secure_dir(CACHE)
    directory = CACHE / RELEASE
    if directory.exists() or directory.is_symlink():
        return verify_bundle(directory)
    print("[ЗАГРУЗКА] Закреплённый комплект " + RELEASE +
          "; версия ядра и модуля не подменяется.")
    with tempfile.TemporaryDirectory(prefix="fetch-", dir=CACHE) as temp:
        archive = Path(temp) / "release.tar.gz"
        result = run(["curl", "--proto", "=https", "--proto-redir", "=https",
                      "--tlsv1.2", "-fsSL", "--connect-timeout", "15",
                      "--max-time", "600", "--max-filesize", str(ARCHIVE_BYTES),
                      "--retry", "2", URL, "-o", str(archive)])
        require(result.returncode == 0 and archive.is_file(),
                "Комплект не скачан. Установка не начата.")
        require(archive.stat().st_size == ARCHIVE_BYTES,
                "Размер архива не совпал с закреплённым выпуском. Установка не начата.")
        require(sha(archive) == ARCHIVE_SHA, "Контрольная сумма архива не совпала.")
        extracted = extract_bundle(archive, temp)
        extracted.rename(directory)
    return verify_bundle(directory)


def selection():
    print("""
Установка ds-guard — интерактивный мастер
  1. Всё: проверенное ядро, ds-guard и сетевые параметры
  2. Только проверенное ядро XanMod
  3. Только сетевые параметры
  4. Только ds-guard на текущем ядре
  5. Проверка и план без установки
  6. Состояние системы
  7. Отключить изменения управляемой установки
  8. Удалить изменения управляемой установки
  9. Отменить обновление прежней установки
 10. Только проверенное ядро Ubuntu
 11. ds-guard и сетевые параметры на текущем ядре, без смены ядра
  0. Выход
""")
    choice = ask("Выберите пункт [1]: ", set(map(str, range(12))), "1")
    return {
        "1": ["--mode", "full"], "2": ["--mode", "kernel", "--kernel-policy", "xanmod"],
        "3": ["--mode", "tune"], "4": ["--mode", "guard"],
        "5": ["--mode", "check"], "6": ["--mode", "status"],
        "7": ["--mode", "disable"], "8": ["--mode", "remove"],
        "9": ["--mode", "rollback-upgrade"],
        "10": ["--mode", "kernel", "--kernel-policy", "ubuntu"], "0": None,
        "11": ["--mode", "full", "--kernel-policy", "keep"],
    }[choice]


def setup(directory, args):
    verify_bundle(directory)
    env = {k: v for k, v in os.environ.items()
           if k not in ("BASH_ENV", "ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    rc = run(["bash", str(directory / "setup.sh"), *args], env=env).returncode
    save_receipt("setup-" + str(time.time_ns()) + ".json",
                 {"schema": 1, "wizard": VERSION, "release": RELEASE,
                  "manifest_sha256": MANIFEST_SHA, "args": args, "returncode": rc,
                  "kernel": platform.release(), "time": time.time(),
                  "public_client_acceptance": False})
    return rc


def stage_signatures():
    result = {}
    for path in (RC3_STATE / "kernel").glob("*.staged.json"):
        s = secure_file(path).stat()
        result[path.name] = (s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    return result


def proven_stage(directory, args, before_kernel, stages_before=None):
    """Only kernel-stage20 is eligible; other rc3 code20 reasons stay distinct."""
    mode = args[args.index("--mode") + 1]
    if mode not in ("full", "kernel"):
        return None
    require(not (RC3_STATE / "lifecycle/pending.json").exists(),
            "Журнал rc3 не завершён. Пробная загрузка не разрешена.")
    sys.path.insert(0, str(directory))
    try:
        import setup_ru
        info = setup_ru.system_info()
        policy = args[args.index("--kernel-policy") + 1] if "--kernel-policy" in args else "prefer-xanmod"
        catalog = json.loads((directory / "kernels.json").read_text())
        target, _ = setup_ru.choose_kernel(catalog, info["os_id"], info["os_version"],
                                           info["flags"], info["kernel"], policy,
                                           info["loaded_modules"])
    finally:
        sys.path.remove(str(directory))
    if target == before_kernel:
        return None
    path = RC3_STATE / "kernel" / (target + ".staged.json")
    if not path.exists():
        return None
    if stages_before is not None:
        current_signature = stage_signatures().get(path.name)
        if current_signature == stages_before.get(path.name):
            # rc3 rewrites the stage receipt on every successful kernel-stage.
            # An older receipt cannot turn a different reason for code20 into
            # authorization to switch kernels.
            return None
    stage = json.loads(secure_file(path).read_text())
    require(stage.get("candidate") == target and stage.get("running_kernel") == before_kernel
            and stage.get("boot_environment_preserved") is True
            and stage.get("kernel_only") is (mode == "kernel"),
            "Подготовка нового ядра не соответствует этому запуску.")
    for suffix in ("vmlinuz-", "initrd.img-"):
        image = secure_file(Path("/boot") / (suffix + target))
        require(image.stat().st_size > 1024**2, "Образ ядра или initramfs неполон.")
    result = run(["dpkg", "--audit"], capture_output=True, text=True, timeout=30)
    require(result.returncode == 0 and not result.stdout.strip(),
            "Пакетная система требует проверки.")
    if mode == "full":
        manifest = json.loads((directory / "assets" / target / "manifest.json").read_text())
        result = run(["modinfo", "-k", target, "-n", "xt_ndpi"],
                     capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, "Не найден модуль для подготовленного ядра.")
        module = secure_file(Path(result.stdout.strip()))
        expected = manifest["sha256"]["xt_ndpi.ko"]
        require(sha(module) == expected == stage.get("module_sha256"),
                "Подготовленный модуль не совпадает с проверенной сборкой.")
    return target


def resume_args(args):
    result = list(args)
    if "--kernel-policy" in result:
        result[result.index("--kernel-policy") + 1] = "keep"
    else:
        result += ["--kernel-policy", "keep"]
    return result


def show_trial(trial):
    print("[ПРОБНАЯ ЗАГРУЗКА] Новое ядро: " + trial["target"])
    print("[ВОЗВРАТ] Прежнее ядро остаётся вариантом загрузки по умолчанию.")
    print("[ЗАЩИТА] Если система загрузится, но пропадут проверяемые сеть/SSH, "
          "защитная служба запросит один возвратный перезапуск.")
    print("[ГРАНИЦА ЗАЩИТЫ] При зависании до systemd нужен watchdog хостера "
          "или перезапуск через его панель. Один grub-reboot такого перезапуска не делает.")
    watchdogs = sorted(Path("/sys/class/watchdog").glob("watchdog[0-9]*"))
    if not watchdogs:
        print("[WATCHDOG] Внутри ОС устройство watchdog не обнаружено. "
              "Наличие независимого сброса у хостера здесь не подтверждается.")
    else:
        for device in watchdogs:
            details = []
            for key in ("identity", "state", "timeout"):
                try:
                    details.append(key + "=" + (device / key).read_text().strip()[:120])
                except OSError:
                    pass
            print("[WATCHDOG] Найден " + device.name + ": " + ", ".join(details) +
                  ". Реальный сброс не проверялся; настройки не изменены.")
    print("[ПРОДОЛЖЕНИЕ] После подключения по SSH запустите ту же одну команду: "
          "мастер сам продолжит выбранную установку.")


def offer_reboot(trial):
    show_trial(trial)
    choice = ask("\n1. Перезагрузить сейчас (доступ к консоли/сбросу хостера есть)\n"
                 "2. Отложить (обычный reboot загрузит прежнее ядро)\n"
                 "0. Отменить пробную загрузку\nВыберите [2]: ",
                 {"0", "1", "2"}, "2", noninteractive="2")
    if choice == "0":
        boot.cancel()
        print("[ОТМЕНЕНО] Разовая загрузка отменена; пакеты сохранены.")
        return 0
    if choice == "2":
        print("[ОТЛОЖЕНО] Новое ядро не назначено для загрузки. Обычный reboot "
              "оставит прежнее ядро. Для продолжения запустите эту же команду "
              "и выберите перезагрузку в мастере.")
        return 20
    boot.arm(confirmation_already_given=True)
    print("[ПЕРЕЗАГРУЗКА] Выбор проверен. SSH сейчас отключится.", flush=True)
    result = run(["systemctl", "reboot"], timeout=30)
    if result.returncode:
        # Retain a truthful journal; don't pretend reboot happened or erase an
        # already armed trial while a concurrent shutdown might be in progress.
        raise Refusal("Команда перезагрузки не принята. Пробный выбор сохранён; "
                      "повторите мастер для просмотра или отмены.")
    return 20


def finish_trial():
    print("[ПРОВЕРЕНО] Выбранные шаги завершены. Реальный клиентский VPN-путь "
          "нужно проверить отдельно.")
    choice = ask("Сделать успешно проверенное новое ядро основным? "
                 "Введите «да», если ваше SSH-подключение и нужные сервисы работают "
                 "(Enter — оставить прежнее ядро по умолчанию): ",
                 {"да", "нет"}, "нет", noninteractive="нет")
    if choice == "да":
        boot.confirm(confirmed=True)
        print("[ГОТОВО] Новое ядро выбрано основным. Прежнее ядро сохранено для возврата.")
    else:
        boot.complete()
        print("[ГОТОВО] Текущая установка завершена. При следующей перезагрузке "
              "выберется прежнее ядро; сменить выбор можно через этот мастер.")
    return 0


def display_status(trial):
    labels = {
        "none": "пробная загрузка не назначена",
        "prepared": "подготовлено; ожидается выбор перезагрузки",
        "arming": "назначение разовой загрузки не завершено; нужна проверка",
        "armed": "разовая загрузка назначена",
        "boot-healthy": "ядро запущено, сеть и SSH проверены",
        "recovery-requested": "запрошен один возвратный перезапуск",
        "fallback-observed": "сервер вернулся на прежнее ядро",
        "reboot-failed": "команда возвратного перезапуска не выполнена",
        "drift-refused": "обнаружено изменение состояния; автоматические действия остановлены",
        "confirming": "закрепление ядра не завершено; нужна проверка",
        "restoring-default": "возврат основного ядра не завершён; нужна проверка",
        "completed": "проверка завершена; прежнее ядро остаётся основным",
        "confirmed": "новое ядро закреплено",
        "cancelled": "пробная загрузка отменена",
        "default-restored": "прежнее ядро снова выбрано основным",
    }
    phase = trial.get("status", "none")
    print("Пробная загрузка: " + labels.get(phase, "неизвестное состояние"))
    for name, label in (("running_kernel", "Сейчас работает"), ("target", "Новое ядро"),
                        ("fallback", "Прежнее ядро")):
        if name in trial:
            print(label + ": " + trial[name])
    if trial.get("retained_finalizer_guard"):
        print("Защита: сохранён запрет старому XanMod-finalizer автоматически "
              "выбирать непринятое ядро.")
    if trial.get("health_errors"):
        print("Причины отказа: " + "; ".join(trial["health_errors"]))
    if trial.get("error"):
        print("Последняя ошибка: " + trial["error"])


def recovery_menu(trial, requested_mode=None):
    """Review or close an attempt; never arm, resume setup, or request reboot."""
    def fallback_running(current):
        return (current.get("running_kernel") == current.get("fallback") and
                current.get("current_boot_id") != current.get("origin_boot_id") and
                current.get("status") != "armed")

    display_status(trial)
    print("[ОСТАНОВЛЕНО] Эта попытка не будет автоматически повторена. "
          "Установка и перезагрузка из этого меню не запускаются.")
    if trial["status"] in ("armed", "recovery-requested"):
        print("[ПРИМЕЧАНИЕ] Закрытие попытки отменяет сохранённый разовый выбор ядра. "
              "Перезапуск, уже принятый системой, может завершиться.")
    while True:
        close_label = ("Закрыть попытку и открыть основное меню"
                       if fallback_running(trial) and requested_mode is None
                       else "Закрыть попытку и завершить мастер")
        choice = ask("\n1. Показать текущее состояние\n"
                     "2. " + close_label + "\n"
                     "0. Выход без изменений\nВыберите [0]: ",
                     {"0", "1", "2"}, "0", noninteractive="0")
        if choice == "0":
            print("[ВЫХОД] Попытка сохранена. Новая пробная загрузка не назначена.")
            return 0
        current = boot.inspect()
        display_status(current)
        if choice == "1":
            continue
        eligible = current.get("status") in (
            "fallback-observed", "recovery-requested", "reboot-failed")
        eligible = eligible or (
            current.get("status") == "armed" and
            current.get("current_boot_id") == current.get("origin_boot_id"))
        require(eligible and current.get("target") == trial.get("target") and
                current.get("origin_boot_id") == trial.get("origin_boot_id"),
                "Состояние попытки изменилось. Закрытие остановлено; "
                "проверьте показанную диагностику.")
        cancelled = boot.cancel()
        require(cancelled.get("status") == "cancelled",
                "Закрытие попытки не подтверждено; установка не продолжена.")
        print("[ЗАКРЫТО] Попытка завершена. Прежний выбор загрузки восстановлен; "
              "повторная загрузка нового ядра не назначена.")
        if requested_mode is not None:
            print("[ВЫХОД] Переданный --mode не выполнен. Запустите ту же команду "
                  "без --mode, чтобы явно выбрать действие в основном меню.")
            return 0
        if not fallback_running(current):
            print("[ВЫХОД] Возвратная загрузка прежнего ядра ещё не подтверждена. "
                  "Новая установка не запускается: ранее принятый перезапуск "
                  "может ещё выполняться. Проверьте состояние после подключения.")
            return 0
        return None


def confirming_menu(trial):
    """Finish only an explicitly accepted interrupted confirmation; never setup."""
    identity = ("target", "fallback", "origin_boot_id", "current_boot_id",
                "saved_entry", "target_entry", "baseline")

    def checked_current():
        current = boot.inspect()
        require(current.get("status") == "confirming"
                and all(current.get(key) == trial.get(key) for key in identity),
                "Состояние закрепления изменилось; действие остановлено.")
        require(current.get("current_boot_id")
                and current["current_boot_id"] != current.get("origin_boot_id")
                and current.get("running_kernel") == current.get("target")
                and isinstance(current.get("baseline"), dict),
                "Продолжение закрепления требует того же проверяемого нового ядра.")
        failures = boot.health_failures(current["baseline"])
        if failures:
            print("[ПРОВЕРКА] " + "; ".join(failures))
        require(not failures, "Текущие SSH и сеть не прошли проверку; закрепление остановлено.")
        return current

    current = checked_current()
    display_status(current)
    print("[ПРОВЕРКА] Текущие SSH и сеть доступны. Постоянный выбор GRUB мог уже "
          "измениться; помощник проверит сохранённый журнал перед завершением.")
    choice = ask("1. Завершить закрепление проверенного ядра\n"
                 "0. Выйти без изменений\nВыберите [0]: ",
                 {"0", "1"}, "0", noninteractive="0")
    if choice == "0":
        return 0
    checked_current()
    result = boot.confirm(confirmed=True)
    require(result.get("status") == "confirmed",
            "Помощник не подтвердил завершение закрепления.")
    print("[ГОТОВО] Закрепление завершено. Новое ядро основное; прежнее сохранено.")
    return 0


def handle_trial(directory, requested_mode=None):
    trial = boot.inspect()
    if not trial or trial.get("status") == "none":
        return None
    phase = trial["status"]
    if phase in ("cancelled", "confirmed", "default-restored"):
        return None
    if phase == "completed":
        if trial.get("current_kernel") == trial["target"]:
            print("[СОХРАНЕНО] Новое ядро работает, но основным оставлено прежнее.")
            choice = ask("1. Сделать проверенное ядро основным\n2. Открыть меню\n"
                         "Выберите [2]: ", {"1", "2"}, "2", noninteractive="2")
            if choice == "1":
                boot.confirm(confirmed=True)
                print("[ГОТОВО] Новое ядро закреплено. Прежнее сохранено.")
                return 0
        return None
    if phase in ("recovery-requested", "fallback-observed", "reboot-failed"):
        return recovery_menu(trial, requested_mode)
    if phase == "confirming":
        return confirming_menu(trial)
    if phase in ("drift-refused", "restoring-default", "arming"):
        display_status(trial)
        raise Refusal("Состояние пробной загрузки неоднозначно. Установка, "
                      "автоматический повтор и закрытие из меню остановлены; "
                      "сначала нужна проверка показанной диагностики.")
    if phase == "prepared":
        require(trial.get("running_kernel") == trial.get("fallback"),
                "Отложенная загрузка ожидает прежнее рабочее ядро; сейчас запущено другое.")
        if trial.get("current_boot_id") != trial["origin_boot_id"]:
            print("[ПРОДОЛЖЕНИЕ] После отсрочки сервер перезапущен на прежнем ядре. "
                  "Пробная загрузка ещё не назначалась. Пакеты уже подготовлены; "
                  "перед выбранной перезагрузкой повторно проверю GRUB, сеть и SSH.")
        return offer_reboot(trial)
    if trial.get("current_boot_id") == trial["origin_boot_id"]:
        if phase == "armed":
            return recovery_menu(trial, requested_mode)
        require(phase == "prepared",
                "Разовая загрузка уже назначалась. Повторный перезапуск автоматически "
                "не запускается: используйте --status или --cancel-boot.")
        return offer_reboot(trial)
    require(trial.get("running_kernel") == trial["target"],
            "Сервер загрузился в другое ядро. Повторная пробная загрузка "
            "автоматически не назначается; используйте --status.")
    require(boot.resume_ready(), "Проверки после загрузки не завершены; установка не продолжена.")
    print("[ПРОДОЛЖЕНИЕ] Новое ядро запущено; продолжаю сохранённый режим.")
    rc = setup(directory, trial["resume_args"])
    if rc == 0:
        return finish_trial()
    print("[НЕ ЗАВЕРШЕНО] Установщик вернул код " + str(rc) +
          ". Основным остаётся прежнее ядро. Автоматический перезапуск не назначен.")
    return rc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Интерактивный мастер ds-guard")
    parser.add_argument("--mode", choices=["full", "kernel", "guard", "tune",
                                          "check", "status", "disable", "remove",
                                          "rollback-upgrade"])
    parser.add_argument("--kernel-policy", choices=["prefer-xanmod", "xanmod", "ubuntu", "keep"],
                        default="prefer-xanmod")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--cancel-boot", action="store_true")
    options = parser.parse_args(argv)
    require(os.geteuid() == 0, "Запустите мастер с правами root.")
    secure_dir(STATE)
    lock_path = STATE / "wizard.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        require(os.fstat(lock.fileno()).st_uid == 0 and
                not os.fstat(lock.fileno()).st_mode & 0o077, "Небезопасная блокировка.")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if options.status or options.mode == "status":
            display_status(boot.inspect())
            if options.mode == "status":
                return setup(bundle(), ["--mode", "status"])
            return 0
        if options.cancel_boot:
            boot.cancel()
            print("[ОТМЕНЕНО] Собственные изменения выбора загрузки отменены.")
            display_status(boot.inspect())
            return 0
        directory = bundle()
        if options.mode == "check":
            return setup(directory, ["--mode", "check", "--kernel-policy", options.kernel_policy])
        trial = boot.inspect()
        if options.mode and trial.get("status") not in (
                "none", "cancelled", "confirmed", "completed", "default-restored"):
            previous_args = trial.get("resume_args", [])
            previous_mode = (previous_args[previous_args.index("--mode") + 1]
                             if "--mode" in previous_args else None)
            require(options.mode == previous_mode,
                    "Есть сохранённая пробная загрузка для другого режима. "
                    "Запустите мастер без --mode, чтобы открыть меню управления "
                    "попыткой. Выбранный режим не подменяется.")
        result = handle_trial(directory, requested_mode=options.mode)
        if result is not None:
            return result
        args = (["--mode", options.mode, "--kernel-policy", options.kernel_policy]
                if options.mode else selection())
        if args is None:
            return 0
        mode = args[args.index("--mode") + 1]
        if mode in ("status", "check"):
            # A status query can return 20 merely because an older invocation
            # staged a kernel. Preserve that result without treating this
            # read-only menu choice as a new install or boot-stage operation.
            if mode == "status":
                display_status(boot.inspect())
            return setup(directory, args)
        trial = boot.inspect()
        if mode in ("remove", "rollback-upgrade") and trial and trial.get("status") == "confirmed":
            boot.cancel()
            print("[ВОЗВРАТ] Восстановлен прежний основной пункт загрузки. "
                  "Работающее ядро установщик не удалит.")
        before_kernel = platform.release()
        stages_before = stage_signatures()
        if prepare_install_fallback(directory, args) is False:
            return 0
        rc = setup(directory, args)
        if rc == 0 and mode == "remove":
            boot.cleanup_after_remove()
            boot.restore_fallback()
        if rc != 20:
            return rc
        target = proven_stage(directory, args, before_kernel, stages_before)
        if target is None:
            print("[ОТДЕЛЬНАЯ ПЕРЕЗАГРУЗКА] Этот код 20 не подтверждает подготовку "
                  "другого ядра. Выбор GRUB не изменён; следуйте сообщению rc3 выше.")
            return 20
        trial = boot.prepare(target, resume_args(args), boot.capture_baseline())
        return offer_reboot(trial)


def current_kernel_readiness(directory):
    """Exact bundle + real read-only gates; no compile-as-acceptance shortcut."""
    code = (
        "import json,sys;from pathlib import Path;"
        "sys.path.insert(0,sys.argv[1]);import preflight;"
        "r=preflight.collect();p=Path(sys.argv[1])/'assets'/r['kernel']/'manifest.json';"
        "r['prebuilt_present']=p.is_file();"
        "print(json.dumps(r))"
    )
    result = run([sys.executable, "-E", "-s", "-B", "-c", code, str(directory)],
                 capture_output=True, text=True, timeout=120)
    require(result.returncode == 0,
            "Не удалось проверить совместимость текущего ядра. Изменения не начаты.")
    result = json.loads(result.stdout)
    require(result.get("kernel") == platform.release() and
            isinstance(result.get("errors"), list) and
            isinstance(result.get("compatible"), bool) and
            isinstance(result.get("prebuilt_present"), bool),
            "Получен неполный результат проверки текущего ядра.")
    return result


def offer_current_kernel(directory, args, reason):
    print("[СМЕНА ЯДРА НЕДОСТУПНА] " + str(reason), flush=True)
    mode = args[args.index("--mode") + 1]
    if mode != "full":
        raise Refusal("Выбран режим установки только ядра. Он не заменяется установкой "
                      "ds-guard. Чтобы сохранить ядро, выберите пункт 11 главного меню.")
    readiness = current_kernel_readiness(directory)
    if not readiness["compatible"] or not readiness["prebuilt_present"] or readiness["errors"]:
        details = readiness["errors"] or ["Для текущего ядра нет проверенного модуля в комплекте."]
        raise Refusal("Текущее ядро " + readiness["kernel"] +
                      " пока нельзя использовать для ds-guard: " + "; ".join(details) +
                      " Ядро, загрузчик и фильтрация не изменены.")
    print("[ТЕКУЩЕЕ ЯДРО ПРОВЕРЕНО] " + readiness["kernel"] +
          ". Для него есть совместимый комплект ds-guard.", flush=True)
    choice = ask("\n1. Использовать текущее ядро: ds-guard и выбранные сетевые настройки\n"
                 "0. Выйти без установки\nВыберите [0]: ",
                 {"0", "1"}, "0", noninteractive="unavailable")
    if choice == "unavailable":
        raise Refusal("Без терминала выбор ядра не меняется автоматически. "
                      "Для явного запуска на текущем ядре укажите "
                      "--mode full --kernel-policy keep. Установка не начата.")
    if choice == "0":
        print("[ВЫХОД] Установка не начата. Для явного запуска без смены ядра "
              "используйте --mode full --kernel-policy keep.")
        return False
    args[:] = resume_args(args)
    print("[ЯДРО СОХРАНЕНО] Продолжаю выбранную установку на текущем ядре. "
          "Смена загрузки и перезагрузка не требуются.", flush=True)
    return True


def prepare_install_fallback(directory, args):
    mode = args[args.index("--mode") + 1]
    if mode not in ("full", "kernel"):
        return
    policy = args[args.index("--kernel-policy") + 1] if "--kernel-policy" in args else "prefer-xanmod"
    if policy == "keep":
        return
    # Reuse the immutable core's exact read-only selection, including legacy
    # upgrade deferral, rather than maintaining a second kernel-selection policy.
    code = (
        "import json,sys;sys.path.insert(0,sys.argv[1]);import setup_ru as s\n"
        "from legacy_context import context\n"
        "i=s.system_info();p=sys.argv[3]\n"
        "p='keep' if sys.argv[2]=='full' and context(s.ROOT) else p\n"
        "try:\n"
        " k,r=s.choose_kernel(json.loads((s.ROOT/'kernels.json').read_text()),"
        "i['os_id'],i['os_version'],i['flags'],i['kernel'],p,i['loaded_modules'])\n"
        "except s.Refusal as error:\n"
        " print(json.dumps({'current':i['kernel'],'selection_error':str(error)}))\n"
        "else:\n"
        " print(json.dumps({'current':i['kernel'],'selected':k}))\n"
    )
    result = run([sys.executable, "-E", "-s", "-B", "-c", code, str(directory), mode, policy],
                 capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, "Не удалось проверить выбор ядра до подготовки загрузчика. " +
            result.stderr[-600:].strip())
    selected = json.loads(result.stdout)
    if "selection_error" in selected:
        return offer_current_kernel(directory, args, selected["selection_error"])
    if selected["selected"] == selected["current"]:
        return
    # Probe before ensure_fallback: the latter may write a journal/GRUB files.
    # Only the typed storage refusal permits a fallback offer. Corruption,
    # command failures and partial mutations must still stop the operation.
    try:
        boot.environment_backend()
    except boot.UnsupportedStorage as error:
        return offer_current_kernel(directory, args, error)
    print("[ПОДГОТОВКА ВОЗВРАТА] Проверка и закрепление работающего ядра до установки нового.", flush=True)
    fallback = boot.ensure_fallback()
    print("[ВОЗВРАТ ПОДГОТОВЛЕН] Резервное ядро: " + fallback["fallback"] +
          ". Исходные настройки сохранены. Перезагрузка не выполнялась.", flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BlockingIOError:
        print("[ЗАНЯТО] Уже работает другой экземпляр мастера.", file=sys.stderr)
        sys.exit(75)
    except KeyboardInterrupt:
        print("\n[ПРЕРВАНО] Повторите ту же команду для просмотра сохранённого этапа.",
              file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("[ОСТАНОВЛЕНО] " + str(error), file=sys.stderr)
        sys.exit(78)
