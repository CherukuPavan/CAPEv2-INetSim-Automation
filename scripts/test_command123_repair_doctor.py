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

    def test_full_libvirt_inventory_must_be_shutoff_and_stable(self):
        calls = []
        def response(*argv, **_):
            calls.append(tuple(argv))
            if "--all" in argv:
                return "win11\\nforeign-lab"
            if "domstate" in argv:
                return "running" if argv[-1] == "foreign-lab" else "shut off"
            return ""
        with mock.patch.object(m, "read_command", side_effect=response):
            report = m.vm_status(0)
        self.assertTrue(report["libvirt_inventory_stable"])
        self.assertFalse(report["all_domains_shut_off"])
        self.assertEqual(report["defined_domain_count"], 2)
        self.assertTrue(report["no_vm_lifecycle_mutation"])
        self.assertFalse(any("start" in c or "destroy" in c
                             for c in calls))

    def test_libvirt_inventory_race_and_unknown_states_fail_closed(self):
        for other in ("win11\\nnew-foreign", None):
            scans = iter(("win11", other))
            def response(*argv, **_):
                if "--all" in argv:
                    return next(scans)
                if "domstate" in argv:
                    return "shut off"
                return ""
            with mock.patch.object(m, "read_command", side_effect=response):
                report = m.vm_status(0)
            self.assertFalse(report["libvirt_inventory_stable"])
            self.assertFalse(report["all_domains_shut_off"])

    def test_native_snapshot_versions_do_not_prove_tpm_restore(self):
        good = ("Running against daemon: 12.0.0\\n"
                "Running hypervisor: QEMU 10.2.1")
        with mock.patch.object(m, "read_command", return_value=good):
            result = m.snapshot_stack_status()
        self.assertTrue(result["version_evidence_available"])
        self.assertTrue(result["versions_meet_conservative_snapshot_lab_floor"])
        self.assertFalse(result["running_windows_tpm_restore_proven"])
        with mock.patch.object(m, "read_command",
                               return_value="Running against daemon: 10.0.0\\n"
                                            "Running hypervisor: QEMU 8.2.0"):
            result = m.snapshot_stack_status()
        self.assertFalse(result["versions_meet_conservative_snapshot_lab_floor"])

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
    def test_ubuntu_26_is_recognized_without_claiming_release(self, _):
        # Official 26.04 test candidates are eligible for experiments,
        # but the read-only doctor never attests a deployed Windows guest.
        with mock.patch.object(m, "os_status",
                               return_value={"ID":"ubuntu",
                                             "VERSION_ID":"26.04"}), \
             mock.patch.object(m, "package_status", return_value={}), \
             mock.patch.object(m, "service_status", return_value={}), \
             mock.patch.object(m, "vm_status", return_value={
                "all_expected_vms_present":False,
                "all_domains_shut_off":True,
                "libvirt_inventory_stable":True}), \
             mock.patch.object(m, "snapshot_stack_status", return_value={
                "version_evidence_available":True,
                "versions_meet_conservative_snapshot_lab_floor":True}), \
             mock.patch.object(m, "read_command", return_value=None):
            result = m.inventory("village-host",0,Path("/not-present"))
        self.assertNotIn("TARGET_OS_NOT_IN_APPROVED_UBUNTU_FAMILIES",
                         result["blockers"])
        self.assertFalse(result["TPM_snapshot_two_cycle_recovery_proven"])
        self.assertFalse(result["release_cleared_for_live_malware"])

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
        self.assertIn("LIBVIRT_DOMAIN_LIVE_OR_STATE_UNKNOWN", report["blockers"])
        self.assertIn("NATIVE_RUNNING_SNAPSHOT_STACK_NOT_ADMITTED",
                      report["blockers"])


if __name__ == "__main__":
    import unittest
    unittest.main()
