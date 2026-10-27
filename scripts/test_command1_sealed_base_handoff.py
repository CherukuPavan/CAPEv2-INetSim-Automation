"""Synthetic proofs of host-bound sealed APT resumption, no mutations."""
import hashlib
import unittest
from unittest import mock

import command1_sealed_base_handoff as a
import command123_deployment_transaction as tx
import command123_tracked_prereqs as apt


class SealedBaseResumeTests(unittest.TestCase):
    def setUp(self):
        self.host = "cherukupavan-virtual-machine"
        self.ident = "a" * 32
        self.step = "b" * 32
        self.before = {"dpkg": "1", "python3.10": "3.10-old"}
        self.after = {"dpkg": "1", "python3.10": "3.10-new",
                      "git": "2"}
        self.changed = apt.delta(self.before, self.after, ["git", "python3.10"])
        self.row = {
            "kind": "package", "stage": "command1", "status": "sealed",
            "id": self.step,
            "before_sha256": hashlib.sha256(apt.snap_bytes(self.before)).hexdigest(),
            "after_sha256": hashlib.sha256(apt.snap_bytes(self.after)).hexdigest(),
            "simulated": ["git", "python3.10"],
            "observed_change": self.changed,
            "preexisting_python_upgrade_versions_before":
                {"python3.10": "3.10-old"}
        }
        self.doc = {"phase": "active", "entries": [self.row]}

    def fixture(self):
        from contextlib import ExitStack
        from pathlib import Path
        from types import SimpleNamespace
        stack=ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(
            a.apt, "verify_host", return_value="22.04"))
        active=stack.enter_context(mock.patch.object(
            a.tx, "active_transaction", return_value=self.ident))
        loaded=stack.enter_context(mock.patch.object(
            a.tx, "load", return_value=(SimpleNamespace(
                parent=Path("/private/owner")), self.doc)))
        snapshots=stack.enter_context(mock.patch.object(
            a, "trusted_inventory_file", side_effect=[
                self.before, self.after]))
        current=stack.enter_context(mock.patch.object(
            a.apt, "installed", return_value=self.after))
        return active, loaded, snapshots, current

    def test_resume_existing_sealed_apt_without_mutation(self):
        active, _, _, _=self.fixture()
        with mock.patch.object(a.tx, "begin") as forbidden, \
             mock.patch.object(a.apt, "apply") as no_apt:
            outcome=a.attest(self.host)
        self.assertTrue(outcome["may_stage_pinned_cape_source_under_same_transaction"])
        self.assertFalse(outcome["apt_reinstall_required"])
        self.assertFalse(outcome["full_package_rollback_supported"])
        self.assertEqual(outcome["existing_python_upgrades"],["python3.10"])
        self.assertEqual(outcome["transaction_id"],self.ident)
        forbidden.assert_not_called()
        no_apt.assert_not_called()
        active.assert_called_once_with(self.host)

    def test_host_inventory_drift_denies_resume(self):
        _, _, _, now=self.fixture()
        now.return_value={"dpkg":"2","python3.10":"3.10-new","git":"2"}
        with self.assertRaisesRegex(tx.TransactionBlocked, "inventory changed"):
            a.attest(self.host)

    def test_partial_package_receipt_denies_resume(self):
        self.row["status"]="prepared"
        self.fixture()
        with self.assertRaisesRegex(tx.TransactionBlocked, "not sealed"):
            a.attest(self.host)

    def test_unapproved_prior_package_upgrade_denies_resume(self):
        self.row["preexisting_python_upgrade_versions_before"]={}
        self.fixture()
        with self.assertRaisesRegex(tx.TransactionBlocked, "Unrecognized"):
            a.attest(self.host)

    def test_started_cape_source_denies_duplicate_resume(self):
        self.doc["entries"].append({
            "kind":"cape_source","stage":"command1","status":"prepared"})
        self.fixture()
        with self.assertRaisesRegex(tx.TransactionBlocked,
                                    "already attempted"):
            a.attest(self.host)

    def test_no_prior_base_receipt_denies_resume(self):
        self.doc["entries"]=[]
        self.fixture()
        with self.assertRaisesRegex(tx.TransactionBlocked,"exactly one"):
            a.attest(self.host)


if __name__ == "__main__":
    unittest.main()
