#!/usr/bin/env python3
"""Local unit tests only: all command/boot side effects are mocked.

Run in Linux as root to exercise the root-owned file guards. Temporary fixtures
are inside the root home, not the world-writable /tmp parent.
"""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

import wizard as w

REAL_ASK = w.ask


class LocalCase(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(
            tempfile.TemporaryDirectory(prefix="wizard-test-", dir=Path.home()))
        self.root = Path(self.temp)
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.stack.enter_context(redirect_stderr(io.StringIO()))
        # Any unanticipated external command must fail, never execute.
        self.commands = self.stack.enter_context(mock.patch.object(
            subprocess, "run", side_effect=AssertionError("Unmocked subprocess")))
        self.stack.enter_context(mock.patch.object(w, "STATE", self.root / "state"))
        self.stack.enter_context(mock.patch.object(w, "CACHE", self.root / "cache"))
        self.stack.enter_context(mock.patch.object(w, "RC3_STATE", self.root / "rc3"))
        self.stack.enter_context(mock.patch.object(w, "PAYLOAD_FILES", 75))
        self.stack.enter_context(mock.patch.object(w, "ARCHIVE_MEMBERS", 76))
        self.stack.enter_context(mock.patch.object(w, "ARCHIVE_SHA", "1" * 64))
        self.stack.enter_context(mock.patch.object(w, "MANIFEST_SHA", "2" * 64))

    def patch(self, target, name, **kwargs):
        return self.stack.enter_context(mock.patch.object(target, name, **kwargs))

    def payloads(self):
        files = {f"dir/file{i:02}.txt": f"payload{i}\n".encode() for i in range(75)}
        manifest = "".join(
            hashlib.sha256(data).hexdigest() + "  " + name + "\n"
            for name, data in files.items()).encode()
        return files, manifest

    def bundle_fixture(self):
        directory = self.root / "bundle"
        files, manifest = self.payloads()
        for name, data in {**files, "SHA256SUMS": manifest}.items():
            p = directory / name
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            p.write_bytes(data)
            p.chmod(0o600)
        self.patch(w, "MANIFEST_SHA", new=hashlib.sha256(manifest).hexdigest())
        return directory

    def manifest_change(self, directory, text):
        p = directory / "SHA256SUMS"
        p.write_text(text)
        self.patch(w, "MANIFEST_SHA", new=w.sha(p))

    def archive_fixture(self, alter=None):
        files, manifest = self.payloads()
        entries = [("ds-guard-safe/" + k, v, tarfile.REGTYPE)
                   for k, v in {**files, "SHA256SUMS": manifest}.items()]
        if alter:
            entries = alter(entries)
        path = self.root / "bundle.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data)
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    info.linkname = "/etc/passwd"
                    info.size = 0
                tar.addfile(info, io.BytesIO(data))
        self.patch(w, "MANIFEST_SHA", new=hashlib.sha256(manifest).hexdigest())
        return path

    def stage_fixture(self, mode="kernel", **updates):
        bundle = self.root / "fixture"
        bundle.mkdir()
        (bundle / "kernels.json").write_text("{}")
        target = "7.2.9-test"
        before = "7.0.14-old"
        stage = {
            "candidate": target, "running_kernel": before,
            "boot_environment_preserved": True, "kernel_only": mode == "kernel",
        }
        stage.update(updates)
        p = w.RC3_STATE / "kernel" / (target + ".staged.json")
        p.parent.mkdir(parents=True, mode=0o700)
        p.write_text(json.dumps(stage))
        p.chmod(0o600)
        module = types.SimpleNamespace(
            system_info=mock.Mock(return_value={
                "os_id": "ubuntu", "os_version": "24.04", "flags": set(),
                "kernel": before, "loaded_modules": []}),
            choose_kernel=mock.Mock(return_value=(target, "test")),
        )
        self.stack.enter_context(mock.patch.dict(sys.modules, {"setup_ru": module}))
        image = self.root / "image"
        with image.open("wb") as f:
            f.truncate(2 * 1024**2)
        secure_file = w.secure_file

        def secure(path):
            return image if Path(path).parent == Path("/boot") else secure_file(path)

        self.patch(w, "secure_file", side_effect=secure)
        self.patch(w, "run", return_value=types.SimpleNamespace(returncode=0, stdout=""))
        return bundle, target, before, p, module

    def trial(self, status="armed", **updates):
        value = {
            "schema": 1, "status": status, "phase": status,
            "target": "new-kernel", "fallback": "old-kernel",
            "origin_boot_id": "old-boot", "boot_id_before": "old-boot",
            "current_boot_id": "new-boot", "current_kernel": "new-kernel",
            "running_kernel": "new-kernel", "resume_args": ["--mode", "full", "--kernel-policy", "keep"],
        }
        value.update(updates)
        return value

    def main_fixture(self, trial=None, setup_rc=0):
        self.patch(w, "bundle", return_value=self.root / "bundle")
        self.patch(w.boot, "inspect", return_value=trial or {"status": "none"})
        setup = self.patch(w, "setup", return_value=setup_rc)
        prepare = self.patch(w.boot, "prepare")
        arm = self.patch(w.boot, "arm")
        cancel = self.patch(w.boot, "cancel")
        self.patch(w.boot, "capture_baseline", return_value={"baseline": "mock"})
        self.patch(w.boot, "resume_ready", return_value=True)
        return setup, prepare, arm, cancel


class BundleTests(LocalCase):
    def test_unbuilt_template_refuses_before_downloading_or_cache_creation(self):
        self.patch(w, "ARCHIVE_SHA", new="UNRELEASED")
        command = self.patch(w, "run")
        with self.assertRaises(w.Refusal):
            w.bundle()
        command.assert_not_called()
        self.assertFalse(w.CACHE.exists())

    def test_complete_fixture_verifies(self):
        directory = self.bundle_fixture()
        self.assertEqual(w.verify_bundle(directory), directory)

    def test_modified_payload_refused(self):
        directory = self.bundle_fixture()
        (directory / "dir/file00.txt").write_text("different")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_modified_manifest_refused(self):
        directory = self.bundle_fixture()
        with (directory / "SHA256SUMS").open("a") as f:
            f.write("\n")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_file_symlink_refused(self):
        directory = self.bundle_fixture()
        p = directory / "dir/file00.txt"
        original = p.read_bytes()
        p.unlink()
        outside = self.root / "outside"
        outside.write_bytes(original)
        p.symlink_to(outside)
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_parent_symlink_refused(self):
        directory = self.bundle_fixture()
        (directory / "dir").rename(self.root / "outside")
        (directory / "dir").symlink_to(self.root / "outside", target_is_directory=True)
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_world_writable_payload_refused(self):
        directory = self.bundle_fixture()
        (directory / "dir/file00.txt").chmod(0o666)
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_world_writable_parent_refused(self):
        directory = self.bundle_fixture()
        directory.chmod(0o777)
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_extra_file_refused(self):
        directory = self.bundle_fixture()
        (directory / "unmanifested.py").write_text("print('not trusted')")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_extra_bytecode_refused(self):
        directory = self.bundle_fixture()
        cache = directory / "__pycache__"
        cache.mkdir()
        (cache / "setup_ru.cpython-312.pyc").write_bytes(b"unverified bytecode")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_unmanifested_dangling_symlink_refused(self):
        directory = self.bundle_fixture()
        (directory / "dangling").symlink_to(self.root / "missing")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_duplicate_manifest_name_refused(self):
        directory = self.bundle_fixture()
        lines = (directory / "SHA256SUMS").read_text().splitlines()
        lines[1] = lines[0]
        self.manifest_change(directory, "\n".join(lines) + "\n")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_unsafe_manifest_paths_refused(self):
        for name in ("../outside", "/root/outside", "dir/../outside", "dir//file", "dir\\file", "./file"):
            with self.subTest(name=name):
                directory = self.root / ("bad" + str(abs(hash(name))))
                directory.mkdir()
                line = "0" * 64 + "  " + name + "\n"
                self.manifest_change(directory, line)
                with self.assertRaises(w.Refusal):
                    w.verify_bundle(directory)

    def test_wrong_manifest_count_refused(self):
        directory = self.bundle_fixture()
        lines = (directory / "SHA256SUMS").read_text().splitlines()
        self.manifest_change(directory, "\n".join(lines[:-1]) + "\n")
        with self.assertRaises(w.Refusal):
            w.verify_bundle(directory)

    def test_valid_archive_extracts_and_verifies(self):
        archive = self.archive_fixture()
        destination = self.root / "unpack"
        destination.mkdir()
        result = w.extract_bundle(archive, destination)
        self.assertEqual(result, destination / "ds-guard-safe")
        self.assertEqual(len(list(result.rglob("*.*"))), 75)

    def test_malicious_archive_entries_rejected_before_writes(self):
        for name, kind in (
                ("../outside", tarfile.REGTYPE),
                ("/root/outside", tarfile.REGTYPE),
                ("ds-guard-safe/../../outside", tarfile.REGTYPE),
                ("wrong-root/file", tarfile.REGTYPE),
                ("ds-guard-safe/link", tarfile.SYMTYPE),
                ("ds-guard-safe/link", tarfile.LNKTYPE),
                ("ds-guard-safe/device", tarfile.CHRTYPE)):
            with self.subTest(name=name, kind=kind):
                archive = self.archive_fixture(lambda entries: [(name, b"", kind)] + entries[1:])
                destination = self.root / ("unpack" + str(abs(hash((name, kind)))))
                destination.mkdir()
                with self.assertRaises(w.Refusal):
                    w.extract_bundle(archive, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_archive_duplicate_rejected_before_writes(self):
        archive = self.archive_fixture(lambda e: [e[0], e[0], *e[2:]])
        destination = self.root / "unpack"
        destination.mkdir()
        with self.assertRaises(w.Refusal):
            w.extract_bundle(archive, destination)
        self.assertEqual(list(destination.iterdir()), [])

    def test_destination_symlink_cannot_write_outside(self):
        archive = self.archive_fixture()
        destination = self.root / "unpack"
        destination.mkdir()
        outside = self.root / "outside"
        outside.mkdir()
        (destination / "ds-guard-safe").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(w.Refusal):
            w.extract_bundle(archive, destination)
        self.assertEqual(list(outside.iterdir()), [])

    def test_failed_download_never_extracts(self):
        self.patch(w, "run", return_value=types.SimpleNamespace(returncode=22))
        extract = self.patch(w, "extract_bundle")
        with self.assertRaises(w.Refusal):
            w.bundle()
        extract.assert_not_called()
        self.assertFalse((w.CACHE / w.RELEASE).exists())

    def test_bad_download_hash_never_extracts(self):
        def download(command, **kwargs):
            Path(command[-1]).write_bytes(b"wrong archive")
            return types.SimpleNamespace(returncode=0)
        self.patch(w, "run", side_effect=download)
        extract = self.patch(w, "extract_bundle")
        with self.assertRaises(w.Refusal):
            w.bundle()
        extract.assert_not_called()
        self.assertFalse((w.CACHE / w.RELEASE).exists())

    def test_cached_bundle_never_downloads(self):
        directory = self.bundle_fixture()
        w.CACHE.mkdir()
        directory.rename(w.CACHE / w.RELEASE)
        command = self.patch(w, "run")
        self.assertEqual(w.bundle(), w.CACHE / w.RELEASE)
        command.assert_not_called()

    def test_receipt_is_exclusive_and_no_symlink_follow(self):
        w.save_receipt("one.json", {"value": 1})
        with self.assertRaises(w.Refusal):
            w.save_receipt("one.json", {"value": 2})
        outside = self.root / "outside"
        outside.write_text("keep")
        (w.STATE / "receipts/link.json").symlink_to(outside)
        with self.assertRaises(w.Refusal):
            w.save_receipt("link.json", {"value": 2})
        self.assertEqual(outside.read_text(), "keep")


class InputTests(LocalCase):
    def test_menu_missing_tty_does_not_select_full(self):
        self.stack.enter_context(mock.patch("builtins.open", side_effect=OSError("no tty")))
        try:
            value = w.selection()
        except w.Refusal:
            return
        self.assertIsNone(value)

    def test_menu_eof_does_not_select_full(self):
        tty = mock.MagicMock()
        tty.readline.return_value = ""
        cm = mock.MagicMock()
        cm.__enter__.return_value = tty
        self.stack.enter_context(mock.patch("builtins.open", return_value=cm))
        try:
            value = w.selection()
        except w.Refusal:
            return
        self.assertIsNone(value)

    def test_menu_exit_is_no_action(self):
        self.patch(w, "ask", return_value="0")
        self.assertIsNone(w.selection())

    def test_menu_variants(self):
        for answer, expected in (
                ("1", ["--mode", "full"]),
                ("2", ["--mode", "kernel", "--kernel-policy", "xanmod"]),
                ("4", ["--mode", "guard"]),
                ("10", ["--mode", "kernel", "--kernel-policy", "ubuntu"])):
            with self.subTest(answer=answer), mock.patch.object(w, "ask", return_value=answer):
                self.assertEqual(w.selection(), expected)

    def test_resume_pins_keep_without_mutating_original(self):
        original = ["--mode", "full", "--kernel-policy", "xanmod"]
        saved = list(original)
        self.assertEqual(w.resume_args(original), ["--mode", "full", "--kernel-policy", "keep"])
        self.assertEqual(original, saved)
        self.assertEqual(w.resume_args(["--mode", "full"]),
                         ["--mode", "full", "--kernel-policy", "keep"])


class StageTests(LocalCase):
    def test_non_kernel_code20_is_not_boot_stage(self):
        for mode in ("guard", "tune", "disable", "remove", "rollback-upgrade", "check", "status"):
            with self.subTest(mode=mode):
                self.assertIsNone(w.proven_stage(self.root / "absent", ["--mode", mode], "old"))

    def test_pending_lifecycle_refuses_before_boot(self):
        pending = w.RC3_STATE / "lifecycle/pending.json"
        pending.parent.mkdir(parents=True)
        pending.write_text("{}")
        with self.assertRaises(w.Refusal):
            w.proven_stage(self.root / "absent", ["--mode", "full"], "old")

    def test_kernel_stage_provenance_passes(self):
        directory, target, before, _, _ = self.stage_fixture()
        self.assertEqual(w.proven_stage(directory, ["--mode", "kernel"], before), target)

    def test_stage_mismatch_is_refused(self):
        for field, value in (("candidate", "wrong"), ("running_kernel", "wrong"),
                             ("boot_environment_preserved", False), ("kernel_only", False)):
            with self.subTest(field=field):
                # Each independent test fixture owns its own state directory.
                with tempfile.TemporaryDirectory(dir=self.root) as temp:
                    with mock.patch.object(w, "RC3_STATE", Path(temp) / "state"):
                        directory = self.root / "fixture"
                        if directory.exists():
                            (directory / "kernels.json").unlink()
                            directory.rmdir()
                        directory, _, before, _, _ = self.stage_fixture(**{field: value})
                        with self.assertRaises(w.Refusal):
                            w.proven_stage(directory, ["--mode", "kernel"], before)

    def test_same_kernel_does_not_reboot(self):
        directory, target, before, _, module = self.stage_fixture()
        module.choose_kernel.return_value = (before, "same")
        self.assertIsNone(w.proven_stage(directory, ["--mode", "kernel"], before))

    def test_missing_stage_does_not_reboot(self):
        directory, _, before, path, _ = self.stage_fixture()
        path.unlink()
        self.assertIsNone(w.proven_stage(directory, ["--mode", "kernel"], before))

    def test_stale_stage_does_not_authorize_new_boot(self):
        directory, _, before, _, _ = self.stage_fixture()
        signatures = w.stage_signatures()
        self.assertTrue(signatures)
        self.assertIsNone(w.proven_stage(directory, ["--mode", "kernel"], before, signatures))

    def test_rewritten_stage_same_content_is_fresh(self):
        directory, target, before, path, _ = self.stage_fixture()
        signatures = w.stage_signatures()
        data = path.read_bytes()
        path.write_bytes(data)
        # Filesystem timestamp resolution need not advance on this tiny write.
        old = signatures[path.name]
        os.utime(path, ns=(path.stat().st_atime_ns, old[2] + 1_000_000))
        self.assertEqual(w.proven_stage(directory, ["--mode", "kernel"], before, signatures), target)

    def test_new_stage_absent_from_preinstall_snapshot_is_fresh(self):
        directory, target, before, _, _ = self.stage_fixture()
        self.assertEqual(w.proven_stage(directory, ["--mode", "kernel"], before, {}), target)

    def test_stage_snapshot_rejects_symlink(self):
        directory, _, _, path, _ = self.stage_fixture()
        outside = self.root / "other-stage"
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaises(w.Refusal):
            w.stage_signatures()

    def test_dirty_package_database_refused(self):
        directory, _, before, _, _ = self.stage_fixture()
        self.patch(w, "run", return_value=types.SimpleNamespace(returncode=0, stdout="unconfigured"))
        with self.assertRaises(w.Refusal):
            w.proven_stage(directory, ["--mode", "kernel"], before)

    def full_stage(self):
        directory, target, before, path, _ = self.stage_fixture(mode="full")
        module = self.root / "xt_ndpi.ko"
        module.write_bytes(b"mock ELF module")
        module.chmod(0o600)
        digest = w.sha(module)
        asset = directory / "assets" / target
        asset.mkdir(parents=True)
        (asset / "manifest.json").write_text(json.dumps({"sha256": {"xt_ndpi.ko": digest}}))
        stage = json.loads(path.read_text())
        stage["module_sha256"] = digest
        path.write_text(json.dumps(stage))

        def command(argv, **kwargs):
            return types.SimpleNamespace(returncode=0,
                                         stdout=str(module) if argv[0] == "modinfo" else "")

        self.patch(w, "run", side_effect=command)
        return directory, target, before, path, module

    def test_full_stage_requires_exact_module(self):
        directory, target, before, _, _ = self.full_stage()
        self.assertEqual(w.proven_stage(directory, ["--mode", "full"], before), target)

    def test_full_stage_wrong_module_refused(self):
        directory, _, before, _, module = self.full_stage()
        module.write_bytes(b"modified module")
        with self.assertRaises(w.Refusal):
            w.proven_stage(directory, ["--mode", "full"], before)

    def test_full_stage_receipt_wrong_module_refused(self):
        directory, _, before, path, _ = self.full_stage()
        stage = json.loads(path.read_text())
        stage["module_sha256"] = "0" * 64
        path.write_text(json.dumps(stage))
        with self.assertRaises(w.Refusal):
            w.proven_stage(directory, ["--mode", "full"], before)


class FlowTests(LocalCase):
    def test_no_trial_is_no_resume(self):
        self.patch(w.boot, "inspect", return_value={"status": "none"})
        setup = self.patch(w, "setup")
        self.assertIsNone(w.handle_trial(self.root))
        setup.assert_not_called()

    def test_deferred_reboot_does_not_arm_or_reboot(self):
        self.patch(w, "ask", return_value="2")
        arm = self.patch(w.boot, "arm")
        command = self.patch(w, "run")
        self.assertEqual(w.offer_reboot(self.trial("prepared")), 20)
        arm.assert_not_called()
        command.assert_not_called()

    def test_cancel_reboot_cleans_owned_trial_only(self):
        self.patch(w, "ask", return_value="0")
        arm = self.patch(w.boot, "arm")
        cancel = self.patch(w.boot, "cancel")
        command = self.patch(w, "run")
        self.assertEqual(w.offer_reboot(self.trial("prepared")), 0)
        cancel.assert_called_once_with()
        arm.assert_not_called()
        command.assert_not_called()

    def test_explicit_reboot_arms_before_command(self):
        events = []
        self.patch(w, "ask", return_value="1")
        arm = self.patch(w.boot, "arm", side_effect=lambda **kw: events.append(("arm", kw)))
        command = self.patch(w, "run", side_effect=lambda argv, **kw: (
            events.append(("command", argv)), types.SimpleNamespace(returncode=0))[1])
        self.assertEqual(w.offer_reboot(self.trial("prepared")), 20)
        self.assertEqual(events[0], ("arm", {"confirmation_already_given": True}))
        self.assertEqual(events[1], ("command", ["systemctl", "reboot"]))
        self.assertEqual(command.call_count, 1)

    def test_failed_arm_cannot_reboot(self):
        self.patch(w, "ask", return_value="1")
        self.patch(w.boot, "arm", side_effect=w.boot.Refusal("drift"))
        command = self.patch(w, "run")
        with self.assertRaises(w.boot.Refusal):
            w.offer_reboot(self.trial("prepared"))
        command.assert_not_called()

    def test_failed_reboot_command_no_second_attempt(self):
        self.patch(w, "ask", return_value="1")
        self.patch(w.boot, "arm")
        command = self.patch(w, "run", return_value=types.SimpleNamespace(returncode=1))
        self.patch(w.boot, "record_reboot_failure")
        with self.assertRaises(w.Refusal):
            w.offer_reboot(self.trial("prepared"))
        self.assertEqual(command.call_count, 1)

    def test_failed_resume_health_does_not_setup(self):
        self.patch(w.boot, "inspect", return_value=self.trial())
        self.patch(w.boot, "resume_ready", return_value=False)
        setup = self.patch(w, "setup")
        with self.assertRaises(w.Refusal):
            w.handle_trial(self.root)
        setup.assert_not_called()

    def test_resume_uses_saved_mode_and_keeps_kernel(self):
        trial = self.trial()
        self.patch(w.boot, "inspect", return_value=trial)
        self.patch(w.boot, "resume_ready", return_value=True)
        setup = self.patch(w, "setup", return_value=0)
        finish = self.patch(w, "finish_trial", return_value=0)
        self.assertEqual(w.handle_trial(self.root), 0)
        setup.assert_called_once_with(self.root, trial["resume_args"])
        finish.assert_called_once_with()

    def test_failed_resume_does_not_promote_or_reboot(self):
        self.patch(w.boot, "inspect", return_value=self.trial())
        self.patch(w.boot, "resume_ready", return_value=True)
        self.patch(w, "setup", return_value=78)
        finish = self.patch(w, "finish_trial")
        command = self.patch(w, "run")
        self.assertEqual(w.handle_trial(self.root), 78)
        finish.assert_not_called()
        command.assert_not_called()

    def test_ambiguous_trial_cannot_resume(self):
        for status in ("drift-refused", "restoring-default", "arming"):
            with self.subTest(status=status):
                phase = {"recovery-requested": "recovery_requested",
                         "fallback-observed": "recovered"}.get(status, status)
                with mock.patch.object(w.boot, "inspect", return_value=self.trial(status, phase=phase)), \
                     mock.patch.object(w, "setup") as setup, \
                     mock.patch.object(w.boot, "resume_ready", return_value=True), \
                     mock.patch.object(w, "finish_trial", return_value=0):
                    with self.assertRaises(w.Refusal):
                        w.handle_trial(self.root)
                    setup.assert_not_called()

    def test_armed_same_boot_never_offers_second_reboot(self):
        self.patch(w.boot, "inspect", return_value=self.trial(
            "armed", current_boot_id="old-boot", current_kernel="old-kernel"))
        self.patch(w, "ask", return_value="0")
        offer = self.patch(w, "offer_reboot", return_value=20)
        self.assertEqual(w.handle_trial(self.root), 0)
        offer.assert_not_called()

    def test_explicit_acceptance_passed_to_boot_confirm(self):
        self.patch(w, "ask", return_value="да")
        confirm = self.patch(w.boot, "confirm")
        complete = self.patch(w.boot, "complete")
        self.assertEqual(w.finish_trial(), 0)
        confirm.assert_called_once_with(confirmed=True)
        complete.assert_not_called()

    def test_declined_promotion_keeps_fallback(self):
        self.patch(w, "ask", return_value="нет")
        confirm = self.patch(w.boot, "confirm")
        complete = self.patch(w.boot, "complete")
        self.assertEqual(w.finish_trial(), 0)
        confirm.assert_not_called()
        self.assertEqual(complete.call_count, 1)

    def test_status_flag_does_not_download_install_or_offer(self):
        setup, prepare, arm, cancel = self.main_fixture(self.trial("prepared"))
        offer = self.patch(w, "offer_reboot")
        self.assertEqual(w.main(["--status"]), 0)
        w.bundle.assert_not_called()
        setup.assert_not_called()
        prepare.assert_not_called()
        arm.assert_not_called()
        cancel.assert_not_called()
        offer.assert_not_called()

    def test_status_mode_does_not_resume_pending_trial(self):
        setup, prepare, arm, cancel = self.main_fixture(self.trial("prepared", current_boot_id="old-boot"))
        offer = self.patch(w, "offer_reboot", return_value=20)
        self.assertEqual(w.main(["--mode", "status"]), 0)
        for call in setup.call_args_list:
            self.assertIn("status", call.args[1])
            self.assertNotIn("full", call.args[1])
        prepare.assert_not_called()
        arm.assert_not_called()
        cancel.assert_not_called()
        offer.assert_not_called()

    def test_check_mode_does_not_resume_pending_trial(self):
        setup, prepare, arm, cancel = self.main_fixture(self.trial("prepared", current_boot_id="old-boot"))
        offer = self.patch(w, "offer_reboot", return_value=20)
        self.assertEqual(w.main(["--mode", "check"]), 0)
        for call in setup.call_args_list:
            self.assertIn("check", call.args[1])
        prepare.assert_not_called()
        arm.assert_not_called()
        cancel.assert_not_called()
        offer.assert_not_called()

    def test_cancel_flag_does_not_run_install(self):
        setup, prepare, arm, cancel = self.main_fixture()
        self.assertEqual(w.main(["--cancel-boot"]), 0)
        cancel.assert_called_once_with()
        setup.assert_not_called()
        prepare.assert_not_called()
        arm.assert_not_called()
        w.bundle.assert_not_called()

    def test_unproven_code20_never_prepares_grub(self):
        setup, prepare, arm, cancel = self.main_fixture(setup_rc=20)
        self.patch(w, "handle_trial", return_value=None)
        self.patch(w, "proven_stage", return_value=None)
        self.assertEqual(w.main(["--mode", "full"]), 20)
        setup.assert_called_once()
        prepare.assert_not_called()
        arm.assert_not_called()

    def test_proven_code20_prepares_once_and_offers(self):
        setup, prepare, arm, cancel = self.main_fixture(setup_rc=20)
        self.patch(w, "handle_trial", return_value=None)
        stages_before = {"old-stage.staged.json": (1, 2, 3, 4)}
        self.patch(w, "stage_signatures", return_value=stages_before)
        provenance = self.patch(w, "proven_stage", return_value="new-kernel")
        prepare.return_value = self.trial("prepared")
        offer = self.patch(w, "offer_reboot", return_value=20)
        self.assertEqual(w.main(["--mode", "full"]), 20)
        self.assertIs(provenance.call_args.args[3], stages_before)
        self.assertEqual(prepare.call_count, 1)
        self.assertEqual(prepare.call_args.args[0], "new-kernel")
        self.assertEqual(prepare.call_args.args[1], ["--mode", "full", "--kernel-policy", "keep"])
        offer.assert_called_once_with(prepare.return_value)
        arm.assert_not_called()

    def test_setup_exception_never_prepares_reboot(self):
        setup, prepare, arm, cancel = self.main_fixture()
        self.patch(w, "handle_trial", return_value=None)
        setup.side_effect = OSError("fixture failure")
        with self.assertRaises(OSError):
            w.main(["--mode", "full"])
        prepare.assert_not_called()
        arm.assert_not_called()

    def test_real_boot_no_state_shape_is_supported(self):
        with mock.patch.object(w.boot, "read_state", return_value=None):
            actual = w.boot.inspect()
        self.assertEqual(actual.get("status"), "none")
        self.patch(w.boot, "inspect", return_value=actual)
        self.assertIsNone(w.handle_trial(self.root))

    def test_explicit_conflicting_mode_never_resumes_full(self):
        for mode in ("disable", "remove", "rollback-upgrade", "tune", "guard", "kernel"):
            with self.subTest(mode=mode), \
                 mock.patch.object(w.boot, "inspect", return_value=self.trial()), \
                 mock.patch.object(w.boot, "resume_ready", return_value=True), \
                 mock.patch.object(w, "bundle", return_value=self.root / "bundle"), \
                 mock.patch.object(w, "setup", return_value=0) as setup, \
                 mock.patch.object(w, "finish_trial", return_value=0):
                try:
                    w.main(["--mode", mode])
                except w.Refusal:
                    pass
                for call in setup.call_args_list:
                    self.assertNotIn("full", call.args[1])

    def test_setup_sanitizes_shell_python_environment(self):
        self.patch(w, "verify_bundle")
        command = self.patch(w, "run", return_value=types.SimpleNamespace(returncode=20))
        receipt = self.patch(w, "save_receipt")
        poisoned = {
            "BASH_ENV": "/tmp/bad.sh", "ENV": "/tmp/env", "PYTHONPATH": "/tmp/py",
            "PYTHONHOME": "/tmp/home", "PYTHONSTARTUP": "/tmp/startup",
            "PATH": "/tmp/bad", "SSH_CONNECTION": "192.0.2.1 1234 192.0.2.2 22",
        }
        with mock.patch.dict(os.environ, poisoned):
            self.assertEqual(w.setup(self.root, ["--mode", "full"]), 20)
        env = command.call_args.kwargs["env"]
        for name in ("BASH_ENV", "ENV", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
            self.assertNotIn(name, env)
        self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(env["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(env["SSH_CONNECTION"], poisoned["SSH_CONNECTION"])
        self.assertEqual(receipt.call_args.args[1]["returncode"], 20)


class ReadOnlyMenuTests(LocalCase):
    def menu_fixture(self, choice, returncode):
        setup, prepare, arm, cancel = self.main_fixture(setup_rc=returncode)
        self.patch(w, "ask", return_value=choice)
        snapshot = self.patch(w, "stage_signatures",
                              side_effect=AssertionError("Read-only mode inspected stage provenance"))
        provenance = self.patch(w, "proven_stage")
        offer = self.patch(w, "offer_reboot")
        cleanup = self.patch(w.boot, "cleanup_after_remove")
        return setup, prepare, arm, cancel, snapshot, provenance, offer, cleanup

    def test_menu_status_code20_is_returned_without_boot_stage_message(self):
        setup, *mutations = self.menu_fixture("6", 20)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(w.main([]), 20)
        setup.assert_called_once_with(self.root / "bundle", ["--mode", "status"])
        self.assertNotIn("[ОТДЕЛЬНАЯ ПЕРЕЗАГРУЗКА]", output.getvalue())
        for operation in mutations:
            operation.assert_not_called()

    def test_menu_check_code20_is_returned_without_boot_stage_message(self):
        setup, *mutations = self.menu_fixture("5", 20)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(w.main([]), 20)
        setup.assert_called_once_with(self.root / "bundle", ["--mode", "check"])
        self.assertNotIn("[ОТДЕЛЬНАЯ ПЕРЕЗАГРУЗКА]", output.getvalue())
        for operation in mutations:
            operation.assert_not_called()

    def test_menu_status_displays_boot_status_but_does_not_change_it(self):
        setup, *mutations = self.menu_fixture("6", 0)
        display = self.patch(w, "display_status")
        self.assertEqual(w.main([]), 0)
        display.assert_called_once_with({"status": "none"})
        setup.assert_called_once_with(self.root / "bundle", ["--mode", "status"])
        for operation in mutations:
            operation.assert_not_called()

    def test_menu_status_preserves_failure_without_examining_staged_receipts(self):
        setup, *mutations = self.menu_fixture("6", 78)
        self.assertEqual(w.main([]), 78)
        setup.assert_called_once()
        for operation in mutations:
            operation.assert_not_called()

    def test_explicit_status_code20_remains_read_only_with_pending_trial(self):
        setup, prepare, arm, cancel = self.main_fixture(self.trial("armed"), setup_rc=20)
        handle = self.patch(w, "handle_trial", side_effect=AssertionError("Status resumed a trial"))
        snapshot = self.patch(w, "stage_signatures")
        provenance = self.patch(w, "proven_stage")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(w.main(["--mode", "status"]), 20)
        setup.assert_called_once_with(self.root / "bundle", ["--mode", "status"])
        self.assertNotIn("[ОТДЕЛЬНАЯ ПЕРЕЗАГРУЗКА]", output.getvalue())
        for operation in (prepare, arm, cancel, handle, snapshot, provenance):
            operation.assert_not_called()


class ConfirmingMenuTests(LocalCase):
    def fixture(self, choice="0"):
        trial = self.trial("confirming", baseline={"fixture": "baseline"},
                           saved_entry="old-entry", target_entry="new-entry")
        inspect = self.patch(w.boot, "inspect", return_value=trial)
        health = self.patch(w.boot, "health_failures", return_value=[])
        ask = self.patch(w, "ask", return_value=choice)
        confirm = self.patch(w.boot, "confirm", return_value={"status": "confirmed"})
        mutations = [self.patch(w, "setup"), self.patch(w, "run"),
                     self.patch(w.boot, "arm"), self.patch(w.boot, "prepare"),
                     self.patch(w.boot, "complete"), self.patch(w.boot, "cancel")]
        return trial, inspect, health, ask, confirm, mutations

    def test_exit_is_safe_default_without_setup_or_boot_mutations(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture()
        self.assertEqual(w.handle_trial(self.root), 0)
        self.assertEqual(ask.call_args.args[2], "0")
        self.assertEqual(ask.call_args.kwargs["noninteractive"], "0")
        health.assert_called_once_with(trial["baseline"])
        confirm.assert_not_called()
        for operation in mutations:
            operation.assert_not_called()

    def test_explicit_continue_refreshes_identity_health_then_confirms_only(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture("1")
        self.assertEqual(w.handle_trial(self.root), 0)
        self.assertEqual(inspect.call_count, 3)
        self.assertEqual(health.call_args_list,
                         [mock.call(trial["baseline"]), mock.call(trial["baseline"])])
        confirm.assert_called_once_with(confirmed=True)
        for operation in mutations:
            operation.assert_not_called()

    def test_failed_health_before_prompt_never_offers_or_confirms(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture("1")
        health.return_value = ["SSH недоступен"]
        with self.assertRaises(w.Refusal):
            w.handle_trial(self.root)
        ask.assert_not_called()
        confirm.assert_not_called()
        for operation in mutations:
            operation.assert_not_called()

    def test_wrong_kernel_or_origin_boot_refuses_before_prompt(self):
        for change in ({"running_kernel": "old-kernel"},
                       {"current_boot_id": "old-boot"}):
            with self.subTest(change=change):
                trial = self.trial("confirming", baseline={}, **change)
                with mock.patch.object(w.boot, "inspect", return_value=trial), \
                        mock.patch.object(w, "ask") as ask, \
                        mock.patch.object(w.boot, "confirm") as confirm:
                    with self.assertRaises(w.Refusal):
                        w.handle_trial(self.root)
                    ask.assert_not_called()
                    confirm.assert_not_called()

    def test_health_failure_after_choice_refuses_confirmation(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture("1")
        health.side_effect = [[], ["маршрут изменился"]]
        with self.assertRaises(w.Refusal):
            w.handle_trial(self.root)
        confirm.assert_not_called()
        for operation in mutations:
            operation.assert_not_called()

    def test_identity_drift_before_prompt_or_after_choice_refuses(self):
        for point in ("before", "after"):
            for field in ("target", "fallback", "origin_boot_id", "current_boot_id",
                          "saved_entry", "target_entry", "baseline", "status"):
                with self.subTest(point=point, field=field):
                    trial = self.trial("confirming", baseline={"fixture": "baseline"},
                                       saved_entry="old-entry", target_entry="new-entry")
                    drifted = {**trial, field: "changed"}
                    states = [trial, drifted] if point == "before" else [trial, trial, drifted]
                    with mock.patch.object(w.boot, "inspect", side_effect=states), \
                            mock.patch.object(w.boot, "health_failures", return_value=[]), \
                            mock.patch.object(w, "ask", return_value="1") as ask, \
                            mock.patch.object(w.boot, "confirm") as confirm:
                        with self.assertRaises(w.Refusal):
                            w.handle_trial(self.root)
                        confirm.assert_not_called()
                        if point == "before":
                            ask.assert_not_called()

    def test_missing_terminal_exits_without_confirmation(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture()
        # Restore the real ask after fixture mocking; only /dev/tty open fails.
        with mock.patch.object(w, "ask", new=REAL_ASK), \
                mock.patch("builtins.open", side_effect=OSError("no tty")):
            self.assertEqual(w.handle_trial(self.root), 0)
        confirm.assert_not_called()
        for operation in mutations:
            operation.assert_not_called()

    def test_requested_mode_does_not_run_after_confirmation(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture("1")
        self.patch(w, "bundle", return_value=self.root / "bundle")
        self.assertEqual(w.main(["--mode", "full"]), 0)
        confirm.assert_called_once_with(confirmed=True)
        for operation in mutations:
            operation.assert_not_called()

    def test_refused_or_unconfirmed_helper_result_does_not_claim_success(self):
        trial, inspect, health, ask, confirm, mutations = self.fixture("1")
        for outcome in ({"status": "confirming"}, w.boot.Refusal("drift")):
            with self.subTest(outcome=type(outcome).__name__):
                confirm.side_effect = outcome if isinstance(outcome, Exception) else None
                confirm.return_value = outcome
                with self.assertRaises((w.Refusal, w.boot.Refusal)):
                    w.handle_trial(self.root)
        for operation in mutations:
            operation.assert_not_called()


class RecoveryMenuTests(LocalCase):
    def recovery_fixture(self, status="fallback-observed", choices=("0",), **updates):
        trial = self.trial(status, current_boot_id="fallback-boot",
                           current_kernel="old-kernel", running_kernel="old-kernel")
        trial.update(updates)
        self.patch(w.boot, "inspect", return_value=trial)
        ask = self.patch(w, "ask", side_effect=choices)
        cancel = self.patch(w.boot, "cancel", return_value={"status": "cancelled"})
        arm = self.patch(w.boot, "arm")
        setup = self.patch(w, "setup", return_value=0)
        offer = self.patch(w, "offer_reboot")
        command = self.patch(w, "run")
        return trial, ask, cancel, arm, setup, offer, command

    def assert_no_install_or_reboot(self, arm, setup, offer, command):
        arm.assert_not_called()
        setup.assert_not_called()
        offer.assert_not_called()
        command.assert_not_called()

    def test_recovery_states_exit_is_default_and_preserves_attempt(self):
        for status in ("fallback-observed", "recovery-requested", "reboot-failed"):
            with self.subTest(status=status), ExitStack() as stack:
                trial = self.trial(status)
                stack.enter_context(mock.patch.object(w.boot, "inspect", return_value=trial))
                ask = stack.enter_context(mock.patch.object(w, "ask", return_value="0"))
                cancel = stack.enter_context(mock.patch.object(w.boot, "cancel"))
                arm = stack.enter_context(mock.patch.object(w.boot, "arm"))
                setup = stack.enter_context(mock.patch.object(w, "setup"))
                offer = stack.enter_context(mock.patch.object(w, "offer_reboot"))
                command = stack.enter_context(mock.patch.object(w, "run"))
                self.assertEqual(w.handle_trial(self.root), 0)
                self.assertEqual(ask.call_args.args[2], "0")
                self.assertEqual(ask.call_args.kwargs["noninteractive"], "0")
                cancel.assert_not_called()
                self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_status_refresh_does_not_close_or_install(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("1", "0"))
        display = self.patch(w, "display_status")
        self.assertEqual(w.handle_trial(self.root), 0)
        self.assertEqual(ask.call_count, 2)
        self.assertEqual(display.call_count, 2)
        cancel.assert_not_called()
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_close_verified_fallback_returns_to_explicit_menu(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.assertIsNone(w.handle_trial(self.root))
        cancel.assert_called_once_with()
        self.assertIn("открыть основное меню", ask.call_args.args[0])
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_close_with_explicit_mode_exits_without_running_mode(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.assertEqual(w.handle_trial(self.root, requested_mode="full"), 0)
        cancel.assert_called_once_with()
        self.assertIn("завершить мастер", ask.call_args.args[0])
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_queued_recovery_close_exits_without_new_installation(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(
            "recovery-requested", choices=("2",), current_boot_id="new-boot",
            recovery_boot_id="new-boot", running_kernel="new-kernel",
            current_kernel="new-kernel")
        self.assertEqual(w.handle_trial(self.root), 0)
        cancel.assert_called_once_with()
        self.assertIn("завершить мастер", ask.call_args.args[0])
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_failed_reboot_still_on_candidate_cannot_open_installation(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(
            "reboot-failed", choices=("2",), current_boot_id="new-boot",
            running_kernel="new-kernel", current_kernel="new-kernel")
        self.assertEqual(w.handle_trial(self.root), 0)
        cancel.assert_called_once_with()
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_same_boot_armed_allows_cancel_but_no_second_reboot(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(
            "armed", choices=("2",), current_boot_id="old-boot")
        self.assertEqual(w.handle_trial(self.root), 0)
        cancel.assert_called_once_with()
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_new_drift_before_close_refuses_without_cancel(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.patch(w.boot, "inspect", side_effect=[trial, {**trial, "status": "drift-refused"}])
        with self.assertRaises(w.Refusal):
            w.handle_trial(self.root)
        cancel.assert_not_called()
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_replaced_trial_identity_before_close_is_refused(self):
        for field, value in (("target", "different-kernel"), ("origin_boot_id", "other-boot")):
            with self.subTest(field=field), ExitStack() as stack:
                trial = self.trial("fallback-observed", running_kernel="old-kernel")
                stack.enter_context(mock.patch.object(w, "ask", return_value="2"))
                stack.enter_context(mock.patch.object(
                    w.boot, "inspect", side_effect=[trial, {**trial, field: value}]))
                cancel = stack.enter_context(mock.patch.object(w.boot, "cancel"))
                with self.assertRaises(w.Refusal):
                    w.handle_trial(self.root)
                cancel.assert_not_called()

    def test_cancel_failure_cannot_open_main_menu(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        cancel.side_effect = w.boot.Refusal("owned boot state changed")
        with self.assertRaises(w.boot.Refusal):
            w.handle_trial(self.root)
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_unconfirmed_cancel_cannot_open_main_menu(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        cancel.return_value = {"status": "none"}
        with self.assertRaises(w.Refusal):
            w.handle_trial(self.root)
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_missing_tty_recovery_menu_exits_without_changes(self):
        trial = self.trial("fallback-observed", running_kernel="old-kernel")
        self.patch(w.boot, "inspect", return_value=trial)
        cancel = self.patch(w.boot, "cancel")
        arm = self.patch(w.boot, "arm")
        setup = self.patch(w, "setup")
        self.stack.enter_context(mock.patch("builtins.open", side_effect=OSError("no tty")))
        self.assertEqual(w.handle_trial(self.root), 0)
        cancel.assert_not_called()
        arm.assert_not_called()
        setup.assert_not_called()

    def test_main_after_close_requires_new_explicit_selection(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.patch(w, "bundle", return_value=self.root / "bundle")
        events = []
        cancel.side_effect = lambda: (events.append("cancel"), {"status": "cancelled"})[1]
        selection = self.patch(w, "selection", side_effect=lambda: (
            events.append("selection"), ["--mode", "tune"])[1])
        setup.side_effect = lambda directory, args: (events.append(("setup", args)), 0)[1]
        self.assertEqual(w.main([]), 0)
        selection.assert_called_once_with()
        self.assertEqual(events, ["cancel", "selection", ("setup", ["--mode", "tune"])])
        arm.assert_not_called()
        offer.assert_not_called()
        command.assert_not_called()

    def test_main_after_close_never_reuses_explicit_full(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.patch(w, "bundle", return_value=self.root / "bundle")
        selection = self.patch(w, "selection")
        self.assertEqual(w.main(["--mode", "full"]), 0)
        cancel.assert_called_once_with()
        selection.assert_not_called()
        self.assert_no_install_or_reboot(arm, setup, offer, command)

    def test_main_conflicting_explicit_mode_refuses_before_cancel(self):
        trial, ask, cancel, arm, setup, offer, command = self.recovery_fixture(choices=("2",))
        self.patch(w, "bundle", return_value=self.root / "bundle")
        with self.assertRaises(w.Refusal):
            w.main(["--mode", "remove"])
        ask.assert_not_called()
        cancel.assert_not_called()
        self.assert_no_install_or_reboot(arm, setup, offer, command)


if __name__ == "__main__":
    unittest.main(verbosity=2)
