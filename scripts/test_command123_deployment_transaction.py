"""Offline transaction safety tests; never need sudo or a real CAPE VM."""
from pathlib import Path
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
        self.patchers = [
            mock.patch.object(t, "ROOT", self.root),
            mock.patch.object(t, "host_guard", return_value="rakshati"),
            mock.patch.object(t, "setup_root", side_effect=self.mkdir_root),
            mock.patch.object(t, "owner_dir", side_effect=self.check_owned),
            mock.patch.object(t, "allowed_file", side_effect=self.restricted),
            mock.patch.object(t.os, "geteuid", return_value=0),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)
        self.transaction = t.begin("rakshati")["transaction_id"]

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
