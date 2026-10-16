"""Synthetic-only Command1 transaction-before-mutation sequencing regressions."""
import unittest
from unittest import mock

import command1_tracked_prerequisite_stage as c
import command123_deployment_transaction as tx


PROPOSAL = {"result": "CAPE_BASE_APT_REVIEW_ONLY",
            "requested_missing": ["python3-pip"],
            "simulated_installations": ["python3-pip"],
            "host_modified": False}


class BaseCommand1Tests(unittest.TestCase):
    def common(self, stack):
        stack.enter_context(mock.patch.object(c.tx, "host_guard",
                                             return_value="rakshati"))
        stack.enter_context(mock.patch.object(c.os, "geteuid",
                                             return_value=0))
        stack.enter_context(mock.patch.object(c.sys.stdin, "isatty",
                                             return_value=True))
        return stack.enter_context(mock.patch.object(
            c.packages, "plan", return_value=dict(PROPOSAL)))

    def test_base_preflight_does_not_mutate(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.common(stack)
            begin = stack.enter_context(mock.patch.object(
                c.tx, "begin", side_effect=AssertionError("No mutation")))
            value = c.preflight("rakshati")
            self.assertFalse(value["new_transaction_created"])
            self.assertFalse(value["full_CAPEv2_installed"])
            begin.assert_not_called()

    def test_transaction_created_before_apt_mutation(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.common(stack)
            sequence = []
            stack.enter_context(mock.patch("builtins.input",
                return_value="BEGIN-CAPE-DEPLOYMENT-ON-RAKSHATI"))
            def start(host):
                sequence.append("begin")
                return {"transaction_id": "a" * 32}
            def install(ident, host):
                sequence.append("apt")
                self.assertEqual(ident, "a" * 32)
                return {"result": "CAPE_BASE_APT_INSTALLED_AND_PROVEN"}
            stack.enter_context(mock.patch.object(c.tx, "begin",
                                                  side_effect=start))
            stack.enter_context(mock.patch.object(c.packages, "apply",
                                                  side_effect=install))
            done = c.apply("rakshati")
            self.assertEqual(sequence, ["begin", "apt"])
            self.assertTrue(done["automatic_transaction_pointer_created"])
            self.assertFalse(done["full_CAPEv2_installed"])
            self.assertFalse(done["full_deployment_rollback_ready"])

    def test_operator_decline_does_not_create_transaction(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.common(stack)
            stack.enter_context(mock.patch("builtins.input",
                                           return_value="NO"))
            start = stack.enter_context(mock.patch.object(c.tx, "begin"))
            with self.assertRaises(tx.TransactionBlocked):
                c.apply("rakshati")
            start.assert_not_called()

    def test_changed_preflight_does_not_create_transaction(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            plan = self.common(stack)
            stack.enter_context(mock.patch("builtins.input",
                return_value="BEGIN-CAPE-DEPLOYMENT-ON-RAKSHATI"))
            plan.side_effect = [dict(PROPOSAL),
                                {**PROPOSAL, "requested_missing": ["git"]}]
            start = stack.enter_context(mock.patch.object(c.tx, "begin"))
            with self.assertRaises(tx.TransactionBlocked):
                c.apply("rakshati")
            start.assert_not_called()

    def test_apt_exception_retains_transaction_without_new_begin(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            self.common(stack)
            stack.enter_context(mock.patch("builtins.input",
                return_value="BEGIN-CAPE-DEPLOYMENT-ON-RAKSHATI"))
            start = stack.enter_context(mock.patch.object(c.tx, "begin",
                return_value={"transaction_id": "b" * 32}))
            stack.enter_context(mock.patch.object(c.packages, "apply",
                side_effect=tx.TransactionBlocked("APT partial")))
            with self.assertRaisesRegex(tx.TransactionBlocked,
                                        "Partial or unknown"):
                c.apply("rakshati")
            start.assert_called_once_with("rakshati")

    def test_no_root_no_start(self):
        with mock.patch.object(c.os, "geteuid", return_value=1000):
            with self.assertRaises(tx.TransactionBlocked):
                c.apply("rakshati")


if __name__ == "__main__":
    unittest.main()
