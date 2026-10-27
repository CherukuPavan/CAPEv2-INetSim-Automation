"""No-host-change tests for already installed Command1 base continuation."""
import unittest
from unittest import mock

import command1_resume_pinned_cape_source as unit
import command123_deployment_transaction as tx


class ResumePinnedSourceTests(unittest.TestCase):
    def test_plan_uses_sealed_base_only(self):
        with mock.patch.object(unit.sealed,"attest",return_value={
                "transaction_id":"a"*32}) as attest, \
             mock.patch.object(unit.source,"plan",return_value={
                "result":"COMMAND1_PINNED_CAPE_SOURCE_PLAN_ONLY"}) as plan, \
             mock.patch.object(unit.source,"install") as install, \
             mock.patch.object(unit.tx,"begin") as begin, \
             mock.patch.object(unit.tx,"prepare_file") as write:
            out=unit.resume("test-lab","b"*40,apply=False)
        self.assertFalse(out["new_package_transaction_created"])
        self.assertFalse(out["source_installed"])
        self.assertFalse(out["full_cape_installed"])
        attest.assert_called_once_with("test-lab")
        plan.assert_called_once_with("test-lab","a"*32,"b"*40)
        install.assert_not_called()
        begin.assert_not_called()
        write.assert_not_called()

    def test_apply_stages_source_under_original_transaction(self):
        with mock.patch.object(unit.sealed,"attest",return_value={
                "transaction_id":"a"*32}), \
             mock.patch.object(unit.source,"plan",return_value={}), \
             mock.patch.object(unit.os,"geteuid",return_value=0), \
             mock.patch.object(unit.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(unit.source,"install",return_value={
                "result":"COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY",
                "transaction":"a"*32}) as install, \
             mock.patch.object(unit.tx,"begin") as begin:
            out=unit.resume("test-lab","b"*40,apply=True)
        self.assertTrue(out["source_installed"])
        self.assertFalse(out["full_cape_installed"])
        install.assert_called_once_with("test-lab","a"*32,"b"*40)
        begin.assert_not_called()

    def test_no_active_base_blocks_source_stage(self):
        with mock.patch.object(unit.sealed,"attest",
                 side_effect=tx.TransactionBlocked("no active transaction")), \
             mock.patch.object(unit.source,"install") as install:
            with self.assertRaisesRegex(tx.TransactionBlocked,"no active"):
                unit.resume("test-lab","b"*40,apply=True)
        install.assert_not_called()

    def test_partial_source_stage_does_not_retry(self):
        with mock.patch.object(unit.sealed,"attest",return_value={
                "transaction_id":"a"*32}), \
             mock.patch.object(unit.source,"plan",return_value={}), \
             mock.patch.object(unit.os,"geteuid",return_value=0), \
             mock.patch.object(unit.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(unit.source,"install",
                 side_effect=unit.source.SourceBlocked("partial")) as install:
            with self.assertRaisesRegex(unit.source.SourceBlocked,"partial"):
                unit.resume("test-lab","b"*40,apply=True)
        install.assert_called_once()

    def test_missing_tty_blocks_mutation(self):
        with mock.patch.object(unit.sealed,"attest",return_value={
                "transaction_id":"a"*32}), \
             mock.patch.object(unit.source,"plan",return_value={}), \
             mock.patch.object(unit.os,"geteuid",return_value=0), \
             mock.patch.object(unit.sys.stdin,"isatty",return_value=False), \
             mock.patch.object(unit.source,"install") as install:
            with self.assertRaisesRegex(tx.TransactionBlocked,"terminal"):
                unit.resume("test-lab","b"*40,apply=True)
        install.assert_not_called()

    def test_unpinned_revision_blocks_early(self):
        with mock.patch.object(unit.sealed,"attest") as attest:
            with self.assertRaisesRegex(tx.TransactionBlocked,"40-hex"):
                unit.resume("test-lab","master",apply=True)
        attest.assert_not_called()


if __name__=="__main__":
    unittest.main()
