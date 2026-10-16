"""Protected original master and backup machines cannot host clone workflows."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import command2_portable_workflow as workflow


class ProtectedHosts(unittest.TestCase):
    def test_both_reference_and_backup_staging_hosts_refused(self):
        for host in ("CSE-SSL-55", "SSL-55", "CSE-SSL-46", "SSL-46"):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as td, \
                 mock.patch.object(workflow.socket, "gethostname",
                                   return_value=host), \
                 mock.patch.object(workflow, "SENTINEL",
                                   Path(td) / "missing"):
                with self.assertRaises(workflow.WorkflowBlocked):
                    workflow.canonical_host(host.lower())

    def test_other_approved_host_still_allowed(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(workflow.socket, "gethostname",
                               return_value="rakshati"), \
             mock.patch.object(workflow, "SENTINEL", Path(td) / "missing"):
            self.assertEqual(workflow.canonical_host("rakshati"), "rakshati")

    def test_protected_backup_cannot_bypass_with_other_approval(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(workflow.socket, "gethostname",
                               return_value="ssl-46"), \
             mock.patch.object(workflow, "SENTINEL", Path(td) / "missing"):
            with self.assertRaises(workflow.WorkflowBlocked):
                workflow.canonical_host("rakshati")


if __name__ == "__main__":
    unittest.main()
