"""Synthetic integration of file-first and APT undo; no host mutations."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command123_deployment_transaction as t
import command123_scoped_recovery as m


TX = "e" * 32
PLAN = {"can_rollback": True, "actions": [
    {"id": "f" * 32, "action": "restore_before"},
    {"id": "a" * 32, "action": "defer_package"},
]}
APT = {"exact_dpkg_after_state_matches": True,
       "packages_to_remove": ["python3-pip", "python3-wheel"]}


def doc(file_status="sealed", package_status="sealed", unknown=False):
    result = {"phase": "active", "entries": [
        {"kind": "package", "id": "a" * 32, "status": package_status},
        {"kind": "file", "id": "f" * 32, "status": file_status},
    ]}
    if unknown:
        result["entries"].append({
            "kind": "libvirt_domain", "id": "c" * 32,
            "status": "sealed"})
    return result


class ScopedRecoveryTests(unittest.TestCase):
    def patch_stage(self, stack, document=None):
        stack.enter_context(mock.patch.object(
            m.transaction, "load",
            return_value=(Path("/untrusted/not_used"), document or doc())))
        stack.enter_context(mock.patch.object(
            m.transaction, "rollback_plan", return_value=PLAN))
        stack.enter_context(mock.patch.object(
            m.packages, "inspect", return_value=APT))

    def test_plan_tracks_exact_file_first_then_apt_order(self):
        with ExitStack() as stack:
            self.patch_stage(stack)
            result = m.owned_stage_plan("rakshati", TX)
        self.assertEqual(result["file_rollback_steps_needed"], 1)
        self.assertTrue(result["apt_rollback_needed"])
        self.assertEqual(result["apt_new_packages_to_remove"],
                         ["python3-pip", "python3-wheel"])
        self.assertFalse(result["full_three_command_rollback_verified"])

    def test_sealed_apt_reversal_is_reverified_before_finalization(self):
        with ExitStack() as stack:
            self.patch_stage(stack, doc(package_status="rollback_verified"))
            verifier = stack.enter_context(mock.patch.object(
                m.packages, "verify_reversed", return_value={
                    "preexisting_package_inventory_matches": True}))
            result = m.owned_stage_plan("rakshati", TX)
        self.assertFalse(result["apt_rollback_needed"])
        verifier.assert_called_once_with(TX, "rakshati")

    def test_later_package_drift_blocks_scoped_rollback(self):
        with ExitStack() as stack:
            self.patch_stage(stack, doc(package_status="rollback_verified"))
            stack.enter_context(mock.patch.object(
                m.packages, "verify_reversed",
                side_effect=t.TransactionBlocked("dpkg drift")))
            with self.assertRaises(t.TransactionBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_no_attested_resources_is_not_a_successful_rollback(self):
        with ExitStack() as stack:
            self.patch_stage(stack, {"phase": "active", "entries": []})
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_rejects_unknown_vm_domain_entry(self):
        with ExitStack() as stack:
            self.patch_stage(stack, doc(unknown=True))
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_rejects_partial_file_before_any_apt_reversal(self):
        with ExitStack() as stack:
            self.patch_stage(stack, doc(file_status="prepared"))
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_rejects_unverified_partial_apt(self):
        with ExitStack() as stack:
            self.patch_stage(stack, doc(package_status="rollback_partial"))
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_rejects_package_inventory_drift(self):
        with ExitStack() as stack:
            self.patch_stage(stack)
            stack.enter_context(mock.patch.object(
                m.packages, "inspect", return_value={
                    **APT, "exact_dpkg_after_state_matches": False}))
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.owned_stage_plan("rakshati", TX)

    def test_composition_requires_explicit_root_approval(self):
        with mock.patch.object(m.os, "geteuid", return_value=1000):
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.run("rakshati", TX)

    def test_no_mutation_on_operator_decline(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.os, "geteuid",
                                                  return_value=0))
            stack.enter_context(mock.patch.object(m.sys.stdin, "isatty",
                                                  return_value=True))
            stack.enter_context(mock.patch.object(m.transaction,
                                                  "host_guard"))
            stack.enter_context(mock.patch.object(m,
                "owned_stage_plan", return_value={"some": "plan"}))
            stack.enter_context(mock.patch("builtins.input",
                                           return_value="DECLINE"))
            executor = stack.enter_context(mock.patch.object(
                m.transaction, "rollback_files_first",
                side_effect=AssertionError("No undo on refusal")))
            with self.assertRaises(m.ScopedRecoveryBlocked):
                m.run("rakshati", TX)
            executor.assert_not_called()

    def test_executes_only_file_first_then_apt_then_final(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.os, "geteuid",
                                                  return_value=0))
            stack.enter_context(mock.patch.object(m.sys.stdin, "isatty",
                                                  return_value=True))
            stack.enter_context(mock.patch.object(m.transaction,
                                                  "host_guard"))
            initial = {
                "file_rollback_steps_needed": 1,
                "apt_rollback_needed": True,
                "transaction": TX,
            }
            stage = stack.enter_context(mock.patch.object(
                m, "owned_stage_plan", return_value=initial))
            stack.enter_context(mock.patch("builtins.input",
                return_value="ROLLBACK-TRACKED-CAPE-FILES-AND-BASE-APT-" + TX))
            actions = []
            stack.enter_context(mock.patch.object(
                m.transaction, "rollback_files_first",
                side_effect=lambda *a: (actions.append("file") or
                    {"transaction_still_active": True})))
            stack.enter_context(mock.patch.object(
                m.packages, "rollback",
                side_effect=lambda *a: (actions.append("apt") or
                    {"preexisting_package_inventory_restored": True})))
            stack.enter_context(mock.patch.object(
                m.transaction, "rollback_plan",
                side_effect=lambda *a: (actions.append("check") or
                    {"can_rollback": True,
                     "actions": [{"action": "keep"}]})))
            stack.enter_context(mock.patch.object(
                m.transaction, "rollback",
                side_effect=lambda *a: (actions.append("finish") or
                    {"result": "CAPE_TRACKED_FILE_CHANGES_ROLLED_BACK"})))
            result = m.run("rakshati", TX)
        self.assertEqual(actions, ["file", "apt", "check", "finish"])
        self.assertEqual(stage.call_count, 2)
        self.assertFalse(result["full_three_command_rollback_verified"])

    def test_apt_failure_halts_without_claiming_completion(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m.os, "geteuid",
                                                  return_value=0))
            stack.enter_context(mock.patch.object(m.sys.stdin, "isatty",
                                                  return_value=True))
            stack.enter_context(mock.patch.object(m.transaction,
                                                  "host_guard"))
            stack.enter_context(mock.patch.object(
                m, "owned_stage_plan", return_value={
                    "file_rollback_steps_needed": 1,
                    "apt_rollback_needed": True,
                }))
            stack.enter_context(mock.patch("builtins.input",
                return_value="ROLLBACK-TRACKED-CAPE-FILES-AND-BASE-APT-" + TX))
            stack.enter_context(mock.patch.object(
                m.transaction, "rollback_files_first",
                return_value={"transaction_still_active": True}))
            stack.enter_context(mock.patch.object(
                m.packages, "rollback",
                side_effect=t.TransactionBlocked("APT partial")))
            fin = stack.enter_context(mock.patch.object(
                m.transaction, "rollback",
                side_effect=AssertionError("Never finalize after APT failure")))
            with self.assertRaises(t.TransactionBlocked):
                m.run("rakshati", TX)
            fin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
