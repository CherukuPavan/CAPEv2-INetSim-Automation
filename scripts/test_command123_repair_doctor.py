"""Offline read-only recovery doctor unit tests; no hypervisor calls."""
from pathlib import Path
from unittest import TestCase, mock
import command123_repair_doctor as m


class DoctorTests(TestCase):
    @mock.patch.object(m.socket, "gethostname", return_value="village-host")
    def test_other_host_matching_required(self, _):
        self.assertEqual(m.check_host("village-host"), "village-host")
        with self.assertRaises(m.DoctorBlocked):
            m.check_host("different-host")

    @mock.patch.object(m.socket, "gethostname", return_value="cse-ssl-55")
    def test_source_reference_host_never_target(self, _):
        with self.assertRaises(m.DoctorBlocked):
            m.check_host("cse-ssl-55")

    def test_snapshot_listing_is_not_tpm_revert_proof(self):
        def response(*argv, **_):
            command = list(argv)
            if "--all" in command:
                return "win11\nwin11_1"
            if "domstate" in command:
                return "shut off"
            if "snapshot-list" in command:
                return "cape_candidate"
            return None
        with mock.patch.object(m, "read_command", side_effect=response):
            report = m.vm_status(1)
        self.assertTrue(report["all_expected_vms_present"])
        self.assertEqual(report["expected_vm_details"]["win11_1"]
                         ["snapshot_names"], ["cape_candidate"])
        self.assertFalse(report["expected_vm_details"]["win11_1"]
                         ["running_snapshot_TPM_safe"])

    def test_missing_clones_report_without_starting_anything(self):
        def response(*argv, **_):
            command = list(argv)
            if "--all" in command:
                return "win11"
            return ""
        with mock.patch.object(m, "read_command", side_effect=response):
            result = m.vm_status(2)
        self.assertFalse(result["all_expected_vms_present"])
        self.assertFalse(result["expected_vm_details"]["win11_2"]["present"])

    @mock.patch.object(m.socket, "gethostname", return_value="village-host")
    def test_incomplete_host_is_not_claimed_ready(self, _):
        with mock.patch.object(m, "os_status",
                               return_value={"ID": "ubuntu",
                                             "VERSION_ID": "24.04"}), \
             mock.patch.object(m, "package_status", return_value={}), \
             mock.patch.object(m, "service_status", return_value={}), \
             mock.patch.object(m, "vm_status",
                               return_value={"all_expected_vms_present": False}), \
             mock.patch.object(m, "read_command", return_value=None):
            report = m.inventory("village-host", 1, Path("/not-present"))
        self.assertFalse(report["release_cleared_for_live_malware"])
        self.assertTrue(report["INetSim_deferred_by_operator"])
        self.assertIn("CAPE_TMPFS_NOT_MOUNTED", report["blockers"])
        self.assertTrue(report["no_guest_started_reverted_or_changed"])


if __name__ == "__main__":
    import unittest
    unittest.main()
