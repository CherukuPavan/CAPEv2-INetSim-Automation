"""Protected original master/backup machines can never run clone workflows."""
import unittest
from unittest import mock

import command2_portable_workflow as workflow


class ProtectedHosts(unittest.TestCase):
    def test_both_reference_and_backup_staging_hosts_refused(self):
        for host in ("CSE-SSL-55", "SSL-55", "CSE-SSL-46", "SSL-46"):
            with self.subTest(host=host), \
                 mock.patch.object(workflow.socket, "gethostname",
                                   return_value=host), \
                 mock.patch.object(workflow.SENTINEL, "exists",
                                   return_value=False), \
                 mock.patch.object(workflow.SENTINEL, "is_symlink",
                                   return_value=False):
                with self.assertRaises(workflow.WorkflowBlocked):
                    workflow.canonical_host(host.lower())

    def test_other_approved_host_still_allowed(self):
        with mock.patch.object(workflow.socket, "gethostname",
                               return_value="rakshati"), \
             mock.patch.object(workflow.SENTINEL, "exists",
                               return_value=False), \
             mock.patch.object(workflow.SENTINEL, "is_symlink",
                               return_value=False):
            self.assertEqual(workflow.canonical_host("rakshati"), "rakshati")

    def test_protected_backup_cannot_bypass_with_other_approval(self):
        with mock.patch.object(workflow.socket, "gethostname",
                               return_value="ssl-46"), \
             mock.patch.object(workflow.SENTINEL, "exists",
                               return_value=False), \
             mock.patch.object(workflow.SENTINEL, "is_symlink",
                               return_value=False):
            with self.assertRaises(workflow.WorkflowBlocked):
                workflow.canonical_host("rakshati")


if __name__ == "__main__":
    unittest.main()
