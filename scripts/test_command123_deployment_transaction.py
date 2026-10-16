"""Offline transaction safety tests; never need sudo or a real CAPE VM."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import os
import tempfile
import unittest
from unittest import mock

import command123_deployment_transaction as t


def sha_state(data, uid, gid, mode=0o600):
    return {"sha256": hashlib.sha256(data).hexdigest(),
            "length": len(data), "mode": mode, "uid": uid, "gid": gid}


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "transactions"
        self.config = self.base / "kvm.conf"
        self.user_id = os.getuid()
        self.group_id = os.getgid()
        self.real_fstat = os.fstat
        self.patchers = [
            mock.patch.object(t, "ROOT", self.root),
            mock.patch.object(t, "host_guard", return_value="rakshati"),
            mock.patch.object(t, "setup_root", side_effect=self.mkdir_root),
            mock.patch.object(t, "owner_dir", side_effect=self.check_owned),
            mock.patch.object(t, "allowed_file", side_effect=self.restricted),
            mock.patch.object(t.os, "geteuid", return_value=0),
            mock.patch.object(t.os, "fstat",
                              side_effect=self.mock_root_owned_ledger_fstat),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)
        self.transaction = t.begin("rakshati")["transaction_id"]

    def mock_root_owned_ledger_fstat(self, fd):
        # Exercise the actual production verification on a non-root CI
        # runner while emulating only root ownership of its test ledger.
        st = self.real_fstat(fd)
        try:
            linked = os.readlink("/proc/self/fd/" + str(fd))
        except OSError:
            linked = ""
        if (linked.endswith("/ledger.json") or
                linked.endswith("/.transaction.lock") or
                "/transactions/" in linked and
                ("/before-" in linked or "/after-" in linked)):
            return SimpleNamespace(st_mode=st.st_mode, st_nlink=st.st_nlink,
                                   st_uid=0, st_size=st.st_size)
        return st

    def mkdir_root(self):
        self.root.mkdir(mode=0o700, exist_ok=True)

    def check_owned(self, directory):
        self.assertTrue(directory.is_dir())
        self.assertFalse(directory.is_symlink())

    def restricted(self, path):
        candidate = Path(path)
        if candidate != self.config:
            raise t.TransactionBlocked("Test target is not allowlisted")
        self.assertFalse(candidate.is_symlink())
        return candidate

    def prepare(self, stage="command3"):
        return t.prepare_file(self.transaction, "rakshati", stage,
                              str(self.config))["step_id"]

    def seal(self, step):
        return t.seal_file(self.transaction, "rakshati", step)

    def test_begin_owns_unique_private_receipt(self):
        path, doc = t.load(self.transaction, "rakshati")
        self.assertEqual(doc["phase"], "active")
        self.assertFalse(doc["whole_deployment_rollback_ready"])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_prepare_before_mutation_and_seal_attest_after(self):
        self.config.write_bytes(b"initial")
        step = self.prepare()
        receipt, doc = t.load(self.transaction, "rakshati")
        self.assertEqual(doc["entries"][0]["status"], "prepared")
        self.assertEqual((receipt.parent / ("before-" + step)).read_bytes(),
                         b"initial")
        self.config.write_bytes(b"changed")
        self.seal(step)
        doc = t.load(self.transaction, "rakshati")[1]
        self.assertEqual(doc["entries"][0]["status"], "sealed")
        self.assertEqual((receipt.parent / ("after-" + step)).read_bytes(),
                         b"changed")

    def test_sealed_missing_file_repair_restores_exact_bytes(self):
        self.config.write_bytes(b"original")
        step = self.prepare()
        self.config.write_bytes(b"deployed")
        self.seal(step)
        self.config.unlink()
        plan = t.repair_plan(self.transaction, "rakshati")
        self.assertTrue(plan["can_repair"])
        self.assertEqual(plan["actions"][0]["action"], "recreate_from_sealed")
        with mock.patch.object(t, "no_live_work"), \
             mock.patch.object(t.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input",
                        return_value="REPAIR-CAPE-TRANSACTION-" +
                                     self.transaction):
            result = t.repair(self.transaction, "rakshati", True)
        self.assertEqual(result["result"], "CAPE_TRACKED_MISSING_FILES_REPAIRED")
        self.assertFalse(result["whole_deployment_repair_ready"])
        self.assertEqual(self.config.read_bytes(), b"deployed")
        self.assertEqual(t.load(self.transaction, "rakshati")[1]["phase"],
                         "active")
        self.assertTrue(t.rollback_plan(self.transaction, "rakshati")
                        ["can_rollback"])

    def test_repair_never_overwrites_foreign_drift(self):
        self.config.write_bytes(b"original")
        step = self.prepare()
        self.config.write_bytes(b"deployed")
        self.seal(step)
        self.config.write_bytes(b"user changes")
        plan = t.repair_plan(self.transaction, "rakshati")
        self.assertFalse(plan["can_repair"])
        self.assertEqual(plan["actions"][0]["action"], "BLOCKED_DRIFT")
        self.assertEqual(self.config.read_bytes(), b"user changes")

    def test_interrupted_repair_keeps_partial_receipt_and_blocks_retry(self):
        step = self.prepare()
        self.config.write_bytes(b"deployed")
        self.seal(step)
        self.config.unlink()
        with mock.patch.object(t, "no_live_work"), \
             mock.patch.object(t.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input",
                        return_value="REPAIR-CAPE-TRANSACTION-" +
                                     self.transaction), \
             mock.patch.object(t, "restore_original",
                               side_effect=OSError("injected write failure")):
            with self.assertRaisesRegex(t.TransactionBlocked,
                                        "Partial repair"):
                t.repair(self.transaction, "rakshati", True)
        state = t.load(self.transaction, "rakshati")[1]
        self.assertEqual(state["phase"], "repair_partial")
        with self.assertRaises(t.TransactionBlocked):
            t.repair_plan(self.transaction, "rakshati")
        with self.assertRaises(t.TransactionBlocked):
            t.rollback_plan(self.transaction, "rakshati")

    def test_unsealed_step_blocks_rollback(self):
        self.config.write_bytes(b"original")
        self.prepare()
        self.config.write_bytes(b"untracked")
        result = t.rollback_plan(self.transaction, "rakshati")
        self.assertFalse(result["can_rollback"])
        self.assertEqual(result["actions"][0]["action"],
                         "BLOCKED_UNOWNED_OR_INCOMPLETE")

    def test_sealed_modified_file_reverses_exact_bytes(self):
        self.config.write_bytes(b"before")
        step = self.prepare()
        self.config.write_bytes(b"after")
        self.seal(step)
        plan = t.rollback_plan(self.transaction, "rakshati")
        self.assertTrue(plan["can_rollback"])
        self.assertEqual(plan["actions"][0]["action"], "restore_before")
        with mock.patch.object(t, "no_live_work"), \
             mock.patch.object(t.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input",
                        return_value="ROLLBACK-CAPE-TRANSACTION-" +
                                     self.transaction):
            result = t.rollback(self.transaction, "rakshati", True)
        self.assertEqual(result["result"], "CAPE_TRACKED_FILE_CHANGES_ROLLED_BACK")
        self.assertEqual(self.config.read_bytes(), b"before")
        self.assertEqual(t.load(self.transaction, "rakshati")[1]["phase"],
                         "rolled_back")
        self.assertFalse(result["whole_deployment_rollback_ready"])
        with self.assertRaises(t.TransactionBlocked):
            self.prepare()

    def test_new_file_is_quarantined_not_deleted(self):
        step = self.prepare()
        self.config.write_bytes(b"new config")
        self.seal(step)
        with mock.patch.object(t, "no_live_work"), \
             mock.patch.object(t.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input",
                        return_value="ROLLBACK-CAPE-TRANSACTION-" +
                                     self.transaction):
            t.rollback(self.transaction, "rakshati", True)
        self.assertFalse(self.config.exists())
        self.assertEqual((self.root / self.transaction /
                          "quarantine" / step).read_bytes(), b"new config")

    def test_foreign_drift_refuses_changes(self):
        self.config.write_bytes(b"old")
        step = self.prepare()
        self.config.write_bytes(b"intended")
        self.seal(step)
        self.config.write_bytes(b"user changed this")
        plan = t.rollback_plan(self.transaction, "rakshati")
        self.assertFalse(plan["can_rollback"])
        self.assertEqual(plan["actions"][0]["action"], "BLOCKED_DRIFT")
        self.assertEqual(self.config.read_bytes(), b"user changed this")

    def test_backup_corruption_blocks_even_when_target_matches(self):
        self.config.write_bytes(b"before")
        step = self.prepare()
        self.config.write_bytes(b"after")
        self.seal(step)
        old = self.root / self.transaction / ("before-" + step)
        old.write_bytes(b"tampered")
        with self.assertRaises(t.TransactionBlocked):
            t.rollback_plan(self.transaction, "rakshati")

    def test_unsupported_resource_refuses_ownership_and_rollback(self):
        r = t.record_unsupported(self.transaction, "rakshati", "command1",
                                 "package", "qemu-system-x86")
        self.assertFalse(r["mutation_authorized"])
        self.assertFalse(t.rollback_plan(self.transaction, "rakshati")
                         ["can_rollback"])
        self.assertEqual(t.load(self.transaction, "rakshati")[1]
                         ["entries"][0]["status"], "UNSUPPORTED_NO_MUTATION")

    def test_concurrent_transaction_writer_is_blocked(self):
        with t.exclusive_transaction_lock(self.transaction):
            with self.assertRaises(t.TransactionBlocked):
                self.prepare()
        # Lock is released after exiting the exclusive section.
        self.config.write_bytes(b"original")
        self.prepare()

    def test_cannot_repeat_same_file_or_unknown_stage(self):
        self.config.write_bytes(b"before")
        self.prepare()
        with self.assertRaises(t.TransactionBlocked):
            self.prepare()
        with self.assertRaises(t.TransactionBlocked):
            self.prepare("untrusted-stage")

    def test_rollback_requires_direct_root_consent(self):
        with self.assertRaises(t.TransactionBlocked):
            t.rollback(self.transaction, "rakshati", False)

class ServiceRecoveryGuards(unittest.TestCase):
    def test_missing_systemd_service_is_inactive(self):
        self.assertTrue(t.service_inactive_from_systemd(
            "LoadState=not-found\nActiveState=inactive\n"))

    def test_installed_stopped_service_is_inactive(self):
        self.assertTrue(t.service_inactive_from_systemd(
            "LoadState=loaded\nActiveState=inactive\n"))

    def test_active_failed_and_masked_services_are_rejected(self):
        for raw in (
            "LoadState=loaded\nActiveState=active\n",
            "LoadState=loaded\nActiveState=failed\n",
            "LoadState=masked\nActiveState=inactive\n",
        ):
            self.assertFalse(t.service_inactive_from_systemd(raw))

    def test_ambiguous_service_response_is_rejected(self):
        for raw in (
            "", "ActiveState=inactive\n",
            "LoadState=loaded\nActiveState=inactive\nActiveState=active\n",
            "LoadState=loaded\nActiveState=inactive\nGarbage=x\n",
        ):
            with self.assertRaises(t.TransactionBlocked):
                t.service_inactive_from_systemd(raw)

    def test_no_live_work_admits_absent_units_and_no_running_guests(self):
        def run(cmd, **kwargs):
            if cmd[0] == "systemctl":
                return SimpleNamespace(returncode=0, stdout=(
                    "LoadState=not-found\nActiveState=inactive\n"))
            if cmd[0] == "virsh":
                return SimpleNamespace(returncode=0, stdout="")
            raise AssertionError("unexpected host command")
        with mock.patch.object(t.subprocess, "run", side_effect=run) as proc:
            t.no_live_work()
        self.assertEqual(proc.call_count, len(t.SERVICE_STOPS) + 1)

    def test_no_live_work_refuses_active_cape_unit(self):
        def run(cmd, **kwargs):
            if cmd[0] == "systemctl":
                return SimpleNamespace(returncode=0, stdout=(
                    "LoadState=loaded\nActiveState=active\n"))
            raise AssertionError("virsh must not run after active service")
        with mock.patch.object(t.subprocess, "run", side_effect=run):
            with self.assertRaises(t.TransactionBlocked):
                t.no_live_work()


class StandaloneGuards(unittest.TestCase):
    def test_reject_protected_hosts(self):
        with mock.patch.object(t.socket, "gethostname",
                               return_value="CSE-SSL-55"):
            with self.assertRaises(t.TransactionBlocked):
                t.host_guard("cse-ssl-55")

    def test_exact_paths_only(self):
        with self.assertRaises(t.TransactionBlocked):
            t.allowed_file(Path("/etc/passwd"))

    def test_reject_invalid_transaction_token(self):
        with self.assertRaises(t.TransactionBlocked):
            t.receipt_path("../../outside")


if __name__ == "__main__":
    unittest.main()
