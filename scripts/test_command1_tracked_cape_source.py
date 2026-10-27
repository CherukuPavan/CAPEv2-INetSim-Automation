"""Offline pinned CAPE upstream source installation acceptance tests.

Uses a temporary local Git repository; NEVER downloads or runs CAPE installer
code and NEVER changes the operator's host packages or virtual machines.
"""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import command1_tracked_cape_source as s
import command123_deployment_transaction as tx


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.origin = self.parent / "origin"
        self.origin.mkdir()
        self.run_git(self.origin, "init", "-q")
        self.run_git(self.origin, "config", "user.name", "OfflineTest")
        self.run_git(self.origin, "config", "user.email", "test@example.invalid")
        (self.origin / "README.md").write_text("Benign verified source\n")
        (self.origin / "installer").mkdir()
        (self.origin / "installer" / "do-not-execute.sh").write_text(
            "#!/bin/sh\nprintf 'NOT RUN\\n'\n")
        (self.origin / "installer" / "do-not-execute.sh").chmod(0o755)
        self.run_git(self.origin, "add", ".")
        self.run_git(self.origin, "commit", "-qm", "static fixture")
        self.revision = self.run_git(self.origin, "rev-parse", "HEAD").strip()
        self.target_root = self.parent / "installations"
        self.txid = "a" * 32
        self.doc = {"phase": "active", "entries": []}

    def run_git(self, path, *args):
        p = subprocess.run(["git", "-C", str(path), *args],
                           capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def fake_safe_root(self, *, create=False):
        if create:
            self.target_root.mkdir(mode=0o755, exist_ok=True)
        return self.target_root

    def stage(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(s, "DEST_ROOT", self.target_root))
        stack.enter_context(mock.patch.object(s, "SOURCE", str(self.origin)))
        stack.enter_context(mock.patch.object(s, "safe_root",
                                               side_effect=self.fake_safe_root))
        stack.enter_context(mock.patch.object(s.tx, "load",
            return_value=(self.parent / "ledger.json", self.doc)))
        stack.enter_context(mock.patch.object(
            s.tx, "exclusive_transaction_lock", return_value=nullcontext()))
        stack.enter_context(mock.patch.object(s.os, "geteuid", return_value=0))
        stack.enter_context(mock.patch.object(s.sys.stdin, "isatty",
                                               return_value=True))
        stack.enter_context(mock.patch("builtins.input",
            return_value="STAGE-PINNED-CAPE-SOURCE-" + self.txid))
        stages = []
        stack.enter_context(mock.patch.object(s.tx, "atomic_receipt",
            side_effect=lambda *args, **kwargs: stages.append(
                deepcopy(self.doc))))
        return stages

    def test_exact_git_tree_and_file_manifest(self):
        info = s.pristine(self.origin, self.revision)
        self.assertEqual(info["revision"], self.revision)
        self.assertEqual(info["file_count"], 2)
        self.assertTrue(info["total_bytes"] > 0)
        self.assertEqual(len(info["content_sha256"]), 64)

    def test_tampering_is_detected(self):
        (self.origin / "README.md").write_text("foreign changes")
        with self.assertRaises(s.SourceBlocked):
            s.pristine(self.origin, self.revision)

    def test_preexisting_symlink_is_not_trusted(self):
        link = self.origin / "untrusted"
        link.symlink_to("README.md")
        self.run_git(self.origin, "add", "untrusted")
        self.run_git(self.origin, "commit", "-qm", "untrusted symlink")
        modified_rev = self.run_git(self.origin, "rev-parse", "HEAD").strip()
        with self.assertRaises(s.SourceBlocked):
            s.pristine(self.origin, modified_rev)

    def test_vetted_cape_upstream_symlink_and_gitlink_are_pinned(self):
        # Actual CAPEv2 upstream 2026-10-27 metadata: exactly one benign
        # literal relative symlink and one UNPOPULATED tests/data gitlink.
        branch=self.origin / "data" / "yara" / "monitor"
        branch.mkdir(parents=True)
        (branch / "yara").symlink_to("analyzer/windows/data/yara/")
        self.run_git(self.origin,"add","data/yara/monitor/yara")
        # A Git link must point at a locally known commit in test repos.
        # Production continues to require its separately vetted upstream SHA.
        self.run_git(self.origin,"update-index","--add","--cacheinfo",
                     "160000",self.revision,"tests/data")
        self.run_git(self.origin,"commit","-qm","vetted CAPE symbolic metadata")
        # Git checkout materializes an empty placeholder for a gitlink.
        (self.origin / "tests" / "data").mkdir(parents=True)
        pinned=self.run_git(self.origin,"rev-parse","HEAD").strip()
        with mock.patch.object(s,"VETTED_CAPE_SPECIAL_REV",pinned), \
             mock.patch.object(s,"VETTED_SOURCE_GITLINKS",
                               {"tests/data":self.revision}):
            result=s.pristine(self.origin,pinned)
            self.assertEqual(result["file_count"],4)
            first=s.portable_quarantine_digest(self.origin,pinned)
            self.assertEqual(len(first),64)
            link=branch / "yara"
            link.unlink()
            link.symlink_to("../../../../etc/passwd")
            with self.assertRaises(s.SourceBlocked):
                s.tracked_hash(self.origin,pinned)
            with self.assertRaises(s.SourceBlocked):
                s.portable_quarantine_digest(self.origin,pinned)

    def test_vetted_symlink_source_quarantine_can_be_rechecked(self):
        # A vetted link must be accepted at both write and read of the
        # rollback receipt. Prior code wrote the digest with revision
        # but rechecked it without revision, permanently blocking undo.
        branch=self.origin / "data" / "yara" / "monitor"
        branch.mkdir(parents=True)
        (branch / "yara").symlink_to("analyzer/windows/data/yara/")
        self.run_git(self.origin, "add", "data/yara/monitor/yara")
        self.run_git(self.origin, "update-index", "--add", "--cacheinfo",
                     "160000", self.revision, "tests/data")
        self.run_git(self.origin, "commit", "-qm", "vetted CAPE source")
        (self.origin / "tests" / "data").mkdir(parents=True)
        revision=self.run_git(self.origin, "rev-parse", "HEAD").strip()
        self.stage()
        with mock.patch.object(s, "VETTED_CAPE_SPECIAL_REV", revision), \
             mock.patch.object(s, "VETTED_SOURCE_GITLINKS",
                               {"tests/data": self.revision}):
            s.install("rakshati", self.txid, revision)
            with mock.patch.object(s.tx, "no_live_work"), \
                 mock.patch("builtins.input", return_value=(
                     "QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid)):
                result=s.undo("rakshati", self.txid)
            self.assertEqual(result["result"],
                             "COMMAND1_OWNED_SOURCE_UNDEPLOYED_QUARANTINED")
            proof=s.undo_plan("rakshati", self.txid)
            self.assertEqual(proof["action"], "already_quarantined")

    def test_unvetted_revision_rejects_even_known_link(self):
        branch=self.origin / "data" / "yara" / "monitor"
        branch.mkdir(parents=True)
        (branch / "yara").symlink_to("analyzer/windows/data/yara/")
        self.run_git(self.origin,"add","data/yara/monitor/yara")
        self.run_git(self.origin,"commit","-qm","unapproved pinned symlink")
        pinned=self.run_git(self.origin,"rev-parse","HEAD").strip()
        with self.assertRaises(s.SourceBlocked):
            s.pristine(self.origin,pinned)

    def test_plan_is_read_only_and_pinned(self):
        stages = self.stage()
        out = s.plan("rakshati", self.txid, self.revision)
        self.assertFalse(out["host_mutated"])
        self.assertFalse(self.target_root.exists())
        self.assertEqual(stages, [])
        self.assertFalse(out["complete_three_command_install"])

    def test_unpinned_revision_is_refused_without_write(self):
        self.stage()
        with self.assertRaises(s.SourceBlocked):
            s.plan("rakshati", self.txid, "development")
        self.assertFalse(self.target_root.exists())

    def test_installer_stages_exact_commit_and_durable_intent(self):
        stages = self.stage()
        original = s.execute_git
        invocation = []
        def observed_git(*args, **kwargs):
            invocation.append((args, deepcopy(self.doc)))
            return original(*args, **kwargs)
        with mock.patch.object(s, "execute_git", side_effect=observed_git):
            result = s.install("rakshati", self.txid, self.revision)
        self.assertEqual(result["result"],
                         "COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY")
        self.assertFalse(result["production_ready"])
        self.assertEqual([x["entries"][0]["status"] for x in stages],
                         ["prepared", "sealed"])
        self.assertTrue(all(entry["entries"][0]["status"] == "prepared"
                            for _, entry in invocation[:1]))
        target = self.target_root / self.txid / "CAPEv2"
        self.assertEqual(s.pristine(target, self.revision)["revision"],
                         self.revision)
        self.assertEqual(self.doc["entries"][0]["target"], str(target))

    def test_source_checkout_is_service_readable_with_exact_provenance(self):
        self.stage()
        result = s.install("rakshati", self.txid, self.revision)
        out = self.target_root / self.txid / "CAPEv2"
        self.assertEqual(out.stat().st_mode & 0o777, 0o755)
        self.assertEqual(out.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(result["source_tree"]["revision"], self.revision)
        self.assertEqual(self.doc["entries"][0]["staging"],
                         str(self.target_root / (".cape-stage-" + self.txid)))
        self.assertFalse((self.target_root /
                         (".cape-stage-" + self.txid)).exists())

    def test_abandoned_owned_source_stage_never_silently_reused(self):
        self.stage()
        self.target_root.mkdir()
        stage = self.target_root / (".cape-stage-" + self.txid)
        stage.mkdir()
        (stage / "README.txt").write_text("foreign incomplete work")
        with self.assertRaises(s.SourceBlocked):
            s.plan("rakshati", self.txid, self.revision)
        self.assertEqual((stage / "README.txt").read_text(),
                         "foreign incomplete work")

    def test_duplicate_or_modified_source_refused(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        with self.assertRaises(s.SourceBlocked):
            s.plan("rakshati", self.txid, self.revision)

    def test_exact_owned_source_can_be_quarantined_after_vm_shutdown(self):
        captures = self.stage()
        s.install("rakshati", self.txid, self.revision)
        before = s.undo_plan("rakshati", self.txid)
        self.assertEqual(before["action"], "quarantine_owned_checkout")
        with mock.patch.object(s.tx, "no_live_work"), \
             mock.patch("builtins.input",
                return_value="QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid):
            result = s.undo("rakshati", self.txid)
        self.assertEqual(result["result"],
                         "COMMAND1_OWNED_SOURCE_UNDEPLOYED_QUARANTINED")
        target = self.target_root / self.txid / "CAPEv2"
        self.assertFalse(target.exists())
        quarantined = self.target_root / self.txid / (
            ".quarantine-" + self.doc["entries"][0]["id"])
        self.assertTrue(quarantined.is_dir())
        self.assertEqual(self.doc["entries"][0]["status"], "rollback_verified")
        self.assertEqual(s.pristine(quarantined, self.revision)["revision"],
                         self.revision)
        self.assertEqual(s.undo_plan("rakshati", self.txid)["action"],
                         "already_quarantined")

    def test_quarantine_is_verifiable_after_newly_installed_git_removed(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        with mock.patch.object(s.tx, "no_live_work"), \
             mock.patch("builtins.input",
                return_value="QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid):
            s.undo("rakshati", self.txid)
        # The final APT undo may remove git completely. The current
        # source should remain verifiable with pure Python only.
        with mock.patch.object(s, "execute_git",
                               side_effect=AssertionError(
                                   "Git unavailable after APT undo")):
            result = s.undo_plan("rakshati", self.txid)
        self.assertEqual(result["action"], "already_quarantined")

    def test_quarantined_source_tampering_fails_without_git(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        with mock.patch.object(s.tx, "no_live_work"), \
             mock.patch("builtins.input",
                return_value="QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid):
            s.undo("rakshati", self.txid)
        private = self.target_root / self.txid / (
            ".quarantine-" + self.doc["entries"][0]["id"])
        (private / "README.md").write_text("Added content after undo")
        with mock.patch.object(s, "execute_git",
                               side_effect=AssertionError("No Git expected")):
            with self.assertRaises(s.SourceBlocked):
                s.undo_plan("rakshati", self.txid)

    def test_quarantine_digest_rejects_symlink_in_git_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".git").mkdir()
            (root / "readme").write_text("safe")
            self.assertEqual(len(s.portable_quarantine_digest(root)), 64)
            (root / ".git" / "escape").symlink_to("/etc/passwd")
            with self.assertRaises(s.SourceBlocked):
                s.portable_quarantine_digest(root)

    def test_source_undo_preserves_foreign_code_modifications(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        checkout = self.target_root / self.txid / "CAPEv2"
        (checkout / "README.md").write_text("Foreign modifications")
        with self.assertRaises(s.SourceBlocked):
            s.undo_plan("rakshati", self.txid)
        self.assertTrue(checkout.exists())
        self.assertEqual(self.doc["entries"][0]["status"], "sealed")

    def test_source_undo_precheck_requires_inactive_services_guests(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        with mock.patch.object(s.tx, "no_live_work",
                               side_effect=tx.TransactionBlocked(
                                   "guest is running")), \
             mock.patch("builtins.input",
                return_value="QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid):
            with self.assertRaises(tx.TransactionBlocked):
                s.undo("rakshati", self.txid)
        self.assertEqual(self.doc["entries"][0]["status"], "sealed")

    def test_source_quarantine_interruption_is_not_marked_verified(self):
        self.stage()
        s.install("rakshati", self.txid, self.revision)
        with mock.patch.object(s.tx, "no_live_work"), \
             mock.patch("builtins.input",
                return_value="QUARANTINE-OWNED-CAPE-SOURCE-" + self.txid), \
             mock.patch.object(s.os, "rename",
                               side_effect=OSError("simulated interruption")):
            with self.assertRaisesRegex(s.SourceBlocked, "interrupted"):
                s.undo("rakshati", self.txid)
        self.assertEqual(self.doc["entries"][0]["status"],
                         "source_rollback_partial")
        with self.assertRaises(s.SourceBlocked):
            s.undo_plan("rakshati", self.txid)

    def test_operator_decline_causes_no_write(self):
        stages = self.stage()
        with mock.patch("builtins.input", return_value="NO"):
            with self.assertRaises(s.SourceBlocked):
                s.install("rakshati", self.txid, self.revision)
        self.assertEqual(stages, [])
        self.assertFalse(self.target_root.exists())

    def test_fetch_failure_remains_prepared_no_auto_retry(self):
        stages = self.stage()
        def fail_git(path, *args, **kwargs):
            if args[:1] == ("fetch",):
                raise s.SourceBlocked("fake network failure")
            return original(path, *args, **kwargs)
        original = s.execute_git
        with mock.patch.object(s, "execute_git", side_effect=fail_git):
            with self.assertRaisesRegex(s.SourceBlocked, "partial"):
                s.install("rakshati", self.txid, self.revision)
        self.assertEqual(stages[-1]["entries"][0]["status"], "prepared")
        self.assertEqual(self.doc["entries"][0]["status"], "prepared")


if __name__ == "__main__":
    unittest.main()
