"""Offline synthetic receipts and file rename tests for owned Python venv undo."""
from __future__ import annotations

from contextlib import ExitStack, nullcontext
from pathlib import Path
import os
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command1_cape_runtime_rootless_rollback as undo
import command1_cape_runtime_rootless_stage as install


class RuntimeQuarantineTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="cape-runtime-undo-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)/"runtime-root"
        self.root.mkdir(mode=0o755)
        self.txid="b"*32
        self.step="f"*32
        self.target=self.root/self.txid
        self.target.mkdir(mode=0o700)
        (self.target/"canary.txt").write_text("preserve bytes")
        self.row={
            "kind":install.RUNTIME_KIND,
            "stage":"command1",
            "status":"sealed",
            "id":self.step,
            "target":str(self.target),
            "before_present":False,
            "runtime_owner":"cape",
        }
        self.doc={"phase":"active","entries":[self.row]}
        self.qroot=self.root/".quarantine"

    def stubs(self,stack,*,true_parent=False):
        stack.enter_context(mock.patch.object(install,"ROOT",self.root))
        stack.enter_context(mock.patch.object(
            install,"stage_parent",return_value=self.root))
        stack.enter_context(mock.patch.object(
            undo.tx,"load",return_value=(self.root/"receipt.json",self.doc)))
        stack.enter_context(mock.patch.object(
            undo.pwd,"getpwnam",
            return_value=SimpleNamespace(pw_uid=os.getuid())))
        if not true_parent:
            def private_parent(*,create=False):
                if create and not self.qroot.exists():
                    self.qroot.mkdir(mode=0o700)
                return self.qroot
            stack.enter_context(mock.patch.object(
                undo,"quarantine_parent",side_effect=private_parent))

    def test_undo_plan_identifies_exact_owned_runtime(self):
        with ExitStack() as stack:
            self.stubs(stack)
            result=undo.inspect("test-host",self.txid)
        self.assertEqual(result["action"],"quarantine_owned_runtime")
        self.assertTrue(result["prior_runtime_did_not_exist"])
        self.assertTrue(result["no_delete_operation"])
        self.assertTrue(self.target.is_dir())

    def test_actual_root_scoped_rename_preserves_bytes(self):
        phases=[]
        with ExitStack() as stack:
            self.stubs(stack)
            stack.enter_context(mock.patch.object(
                undo.os,"geteuid",return_value=0))
            stack.enter_context(mock.patch.object(
                undo.sys.stdin,"isatty",return_value=True))
            stack.enter_context(mock.patch.object(
                undo.tx,"exclusive_transaction_lock",
                return_value=nullcontext()))
            stack.enter_context(mock.patch.object(undo.tx,"no_live_work"))
            stack.enter_context(mock.patch(
                "builtins.input",
                return_value="QUARANTINE-ONLY-OWNED-CAPE-PYTHON-"+self.txid))
            stack.enter_context(mock.patch.object(
                undo.tx,"atomic_receipt",side_effect=lambda p,d:phases.append(
                    d["entries"][-1]["status"])))
            stack.enter_context(mock.patch.object(undo.tx,"fsync_dir"))
            result=undo.undo("test-host",self.txid)
            self.assertEqual(result["result"],
                             "COMMAND1_OWNED_PYTHON_RUNTIME_UNDEPLOYED_QUARANTINED")
            self.assertFalse(self.target.exists())
            q=self.qroot/("owned-"+self.step)
            self.assertEqual((q/"canary.txt").read_text(),"preserve bytes")
            self.assertEqual(phases,["rollback_prepared","rollback_verified"])
            self.assertEqual(self.row["status"],"rollback_verified")
            final=undo.inspect("test-host",self.txid)
            self.assertEqual(final["action"],"already_quarantined")

    def test_declined_confirmation_never_moves_runtime(self):
        with ExitStack() as stack:
            self.stubs(stack)
            stack.enter_context(mock.patch.object(
                undo.os,"geteuid",return_value=0))
            stack.enter_context(mock.patch.object(
                undo.sys.stdin,"isatty",return_value=True))
            stack.enter_context(mock.patch.object(
                undo.tx,"exclusive_transaction_lock",
                return_value=nullcontext()))
            stack.enter_context(mock.patch.object(undo.tx,"no_live_work"))
            stack.enter_context(mock.patch("builtins.input",return_value="NO"))
            with self.assertRaisesRegex(undo.RuntimeUndoBlocked,
                                        "did not approve"):
                undo.undo("test-host",self.txid)
        self.assertTrue(self.target.is_dir())
        self.assertEqual(self.row["status"],"sealed")

    def test_failure_in_rename_retains_recovery_intent_receipt(self):
        stamps=[]
        with ExitStack() as stack:
            self.stubs(stack)
            stack.enter_context(mock.patch.object(
                undo.os,"geteuid",return_value=0))
            stack.enter_context(mock.patch.object(
                undo.sys.stdin,"isatty",return_value=True))
            stack.enter_context(mock.patch.object(
                undo.tx,"exclusive_transaction_lock",
                return_value=nullcontext()))
            stack.enter_context(mock.patch.object(undo.tx,"no_live_work"))
            stack.enter_context(mock.patch(
                "builtins.input",
                return_value="QUARANTINE-ONLY-OWNED-CAPE-PYTHON-"+self.txid))
            stack.enter_context(mock.patch.object(
                undo.tx,"atomic_receipt",side_effect=lambda p,d: stamps.append(
                    d["entries"][-1]["status"])))
            stack.enter_context(mock.patch.object(
                undo.os,"rename",side_effect=OSError("test fail")))
            with self.assertRaises(OSError):
                undo.undo("test-host",self.txid)
            self.assertEqual(stamps,["rollback_prepared"])
            with self.assertRaisesRegex(undo.RuntimeUndoBlocked,
                                        "incomplete or uncertain"):
                undo.inspect("test-host",self.txid)
        self.assertTrue(self.target.is_dir())

    def test_foreign_or_undeclared_venv_cannot_be_quarantined(self):
        self.row["target"]=str(self.root/"foreign")
        with ExitStack() as stack:
            self.stubs(stack)
            with self.assertRaisesRegex(undo.RuntimeUndoBlocked,
                                        "not originally absent"):
                undo.inspect("test-host",self.txid)
        self.assertTrue(self.target.is_dir())

    def test_unknown_runtime_owner_blocks_undo(self):
        with ExitStack() as stack:
            self.stubs(stack)
            stack.enter_context(mock.patch.object(
                undo.pwd,"getpwnam",
                return_value=SimpleNamespace(pw_uid=os.getuid()+1)))
            with self.assertRaisesRegex(undo.RuntimeUndoBlocked,
                                        "owner/permissions"):
                undo.inspect("test-host",self.txid)
        self.assertTrue(self.target.is_dir())


if __name__=="__main__":
    unittest.main()
