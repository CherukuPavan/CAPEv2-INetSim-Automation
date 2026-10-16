"""Offline-only package rollback tests, with no real host package writes."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command123_deployment_transaction as ledger
import command123_tracked_prereqs as base
import command123_tracked_apt_rollback as rollback


ORIGINAL = {"dpkg": "1", "python3": "3.12", "git": "2"}
AFTER = {**ORIGINAL, "python3-pip": "24", "python3-wheel": "2"}
STEP = "a" * 32
TX = "b" * 32


def receipt():
    before_hash = __import__("hashlib").sha256(base.snap_bytes(ORIGINAL)).hexdigest()
    after_hash = __import__("hashlib").sha256(base.snap_bytes(AFTER)).hexdigest()
    return {"schema": 1, "phase": "active", "entries": [{
        "id": STEP, "stage": "command1", "kind": "package",
        "status": "sealed",
        "simulated": ["python3-pip", "python3-wheel"],
        "before_sha256": before_hash,
        "after_sha256": after_hash,
        "observed_change": base.delta(
            ORIGINAL, AFTER, ["python3-pip", "python3-wheel"]),
    }]}


class TrackedRollbackTests(unittest.TestCase):
    def fake_inspect(self, stack, doc, installed_inventory=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        folder = Path(td.name)
        manifest = folder / "ledger.json"
        manifest.touch()
        stack.enter_context(mock.patch.object(rollback.apt, "verify_host"))
        stack.enter_context(mock.patch.object(
            rollback.ledger, "load", return_value=(manifest, doc)))
        stack.enter_context(mock.patch.object(
            rollback, "trusted_inventory_file",
            side_effect=lambda folder, name, sha:
                dict(ORIGINAL if name.startswith("apt-before-") else AFTER)))
        stack.enter_context(mock.patch.object(
            rollback.apt, "installed",
            side_effect=(installed_inventory or [dict(AFTER)])))
        stack.enter_context(mock.patch.object(
            rollback, "simulated_remove",
            return_value=["python3-pip", "python3-wheel"]))
        return folder

    def test_apt_removal_only_attested_set(self):
        with mock.patch.object(rollback.apt, "read_command", return_value=(
                "Remv python3-pip [24]\n"
                "Remv python3-wheel [2]\n")):
            removed = rollback.simulated_remove(["python3-pip", "python3-wheel"])
        self.assertEqual(removed, ["python3-pip", "python3-wheel"])

    def test_extra_transitive_removal_blocked(self):
        with mock.patch.object(rollback.apt, "read_command", return_value=(
                "Remv python3-pip [24]\nRemv python3-wheel [2]\n"
                "Remv existing-user-program [1]\n")):
            with self.assertRaises(ledger.TransactionBlocked):
                rollback.simulated_remove(["python3-pip", "python3-wheel"])

    def test_apt_simulation_install_upgrade_blocked(self):
        for raw in ("Inst new [1] (2 repo)\n", "Purg old [1]\n",
                    "Remv python3-pip [24]\nConf user-package (1 repo)\n"):
            with mock.patch.object(rollback.apt, "read_command",
                                   return_value=raw):
                with self.assertRaises(ledger.TransactionBlocked):
                    rollback.simulated_remove(["python3-pip"])

    def test_inspect_eligible_package_state(self):
        with ExitStack() as stack:
            self.fake_inspect(stack, receipt())
            value = rollback.inspect(TX, "rakshati")
        self.assertEqual(value["packages_to_remove"],
                         ["python3-pip", "python3-wheel"])
        self.assertFalse(value["other_resource_rollback_not_included"] is False)

    def test_reject_user_added_packages_after_deployment(self):
        with ExitStack() as stack:
            self.fake_inspect(stack, receipt(),
                              installed_inventory=[{**AFTER, "user-app": "1"}])
            with self.assertRaises(ledger.TransactionBlocked):
                rollback.inspect(TX, "rakshati")

    def test_reject_unsealed_or_unknown_package_ownership(self):
        doc = receipt()
        doc["entries"][0]["status"] = "prepared"
        with ExitStack() as stack:
            self.fake_inspect(stack, doc)
            with self.assertRaises(ledger.TransactionBlocked):
                rollback.inspect(TX, "rakshati")

    def test_verified_execution_journals_before_removal(self):
        doc = receipt()
        snapshots = []
        with ExitStack() as stack:
            self.fake_inspect(stack, doc,
                              installed_inventory=[dict(AFTER), dict(AFTER),
                                                   dict(ORIGINAL)])
            stack.enter_context(mock.patch.object(
                rollback.ledger, "host_guard", return_value="rakshati"))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "no_live_work"))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "exclusive_transaction_lock",
                return_value=nullcontext()))
            stack.enter_context(mock.patch.object(rollback.os, "geteuid",
                                                 return_value=0))
            stack.enter_context(mock.patch.object(rollback.sys.stdin, "isatty",
                                                 return_value=True))
            stack.enter_context(mock.patch(
                "builtins.input",
                return_value="REMOVE-ONLY-TRACKED-CAPE-BASE-APT-" + TX))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "atomic_receipt",
                side_effect=lambda path, value:
                    snapshots.append(deepcopy(value))))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "private_copy"))
            apt_run = stack.enter_context(mock.patch.object(
                rollback.subprocess, "run",
                return_value=SimpleNamespace(returncode=0)))
            result = rollback.rollback(TX, "rakshati")
        self.assertEqual(result["result"],
                         "CAPE_BASE_APT_ADDITIONS_REVERTED_VERIFIED")
        self.assertEqual(snapshots[0]["entries"][0]["status"], "rollback_partial")
        self.assertEqual(snapshots[-1]["entries"][0]["status"],
                         "rollback_verified")
        self.assertEqual(apt_run.call_count, 1)
        self.assertIn("--no-auto-remove", apt_run.call_args.args[0])
        self.assertNotIn("purge", apt_run.call_args.args[0])
        self.assertNotIn("autoremove", apt_run.call_args.args[0])

    def test_failed_apt_removal_retains_partial_receipt(self):
        doc = receipt()
        snapshots = []
        with ExitStack() as stack:
            self.fake_inspect(stack, doc,
                              installed_inventory=[dict(AFTER), dict(AFTER),
                                                   dict(AFTER)])
            stack.enter_context(mock.patch.object(
                rollback.ledger, "host_guard", return_value="rakshati"))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "no_live_work"))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "exclusive_transaction_lock",
                return_value=nullcontext()))
            stack.enter_context(mock.patch.object(rollback.os, "geteuid",
                                                 return_value=0))
            stack.enter_context(mock.patch.object(rollback.sys.stdin, "isatty",
                                                 return_value=True))
            stack.enter_context(mock.patch(
                "builtins.input",
                return_value="REMOVE-ONLY-TRACKED-CAPE-BASE-APT-" + TX))
            stack.enter_context(mock.patch.object(
                rollback.ledger, "atomic_receipt",
                side_effect=lambda path, value:
                    snapshots.append(deepcopy(value))))
            stack.enter_context(mock.patch.object(rollback.ledger,
                                                 "private_copy"))
            stack.enter_context(mock.patch.object(
                rollback.subprocess, "run",
                return_value=SimpleNamespace(returncode=100)))
            with self.assertRaises(ledger.TransactionBlocked):
                rollback.rollback(TX, "rakshati")
        self.assertEqual(doc["entries"][0]["status"], "rollback_partial")
        self.assertEqual(snapshots[-1]["entries"][0]["rollback_exit_code"], 100)

    def test_file_rollback_plan_accepts_independently_reversed_apt(self):
        doc = receipt()
        doc["entries"][0]["status"] = "rollback_verified"
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
                ledger, "load", return_value=(Path(td) / "ledger", doc)):
            answer = ledger.rollback_plan(TX, "rakshati")
        self.assertTrue(answer["can_rollback"])
        self.assertEqual(answer["actions"][0]["action"], "keep")

    def test_sealed_apt_without_reversal_blocks_file_rollback(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
                ledger, "load", return_value=(Path(td) / "ledger", receipt())):
            answer = ledger.rollback_plan(TX, "rakshati")
        self.assertFalse(answer["can_rollback"])


if __name__ == "__main__":
    unittest.main()
