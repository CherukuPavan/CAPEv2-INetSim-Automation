"""Offline-only systemd service design tests. NO systemd access."""
import hashlib
from pathlib import Path
import unittest

import command2_ssl55_guard_systemd_unit_plan as unit


class ServiceDesignTests(unittest.TestCase):
    def test_allowlisted_libvirt_backend_variants(self):
        for service in ("libvirtd.service","virtqemud.service"):
            with self.subTest(service=service):
                proposal=unit.build_unit(service)
                text=proposal["unit_text"]
                self.assertIn("Wants="+service,text)
                self.assertIn("After="+service+" network-pre.target",text)
                self.assertIn("Before=libvirt-guests.service",text)
                self.assertIn("ConditionPathExists="+unit.EXPECTED_APPROVAL,text)
                self.assertIn("ExecStart=/usr/bin/python3 -B "+
                              unit.EXPECTED_HELPER+" --mode reconcile",text)
                self.assertEqual(proposal["unit_sha256"],
                                 hashlib.sha256(text.encode()).hexdigest())
                for flag in ("actual_libvirt_service_checked_on_host",
                             "dependency_scripts_installed",
                             "operator_approval_manifest_installed",
                             "unit_installed","unit_enabled","unit_started",
                             "nftables_service_enabled",
                             "reboot_persistence_verified",
                             "safe_to_attach_win11_1_nic","host_modified"):
                    self.assertFalse(proposal[flag])

    def test_non_allowlisted_systemd_name_blocked_without_side_effect(self):
        for service in ("nftables.service","ssh.service",
                        "libvirtd.service\nExecStart=/bin/false",
                        "command2.service",""):
            with self.subTest(service=service),self.assertRaises(unit.UnitBlocked):
                unit.build_unit(service)

    def test_does_not_instruct_host_global_firewall_flush(self):
        text=unit.build_unit("libvirtd.service")["unit_text"]
        for forbidden in ("flush ruleset","/etc/nftables.conf",
                          "ExecStart=/usr/sbin/nft","iptables -F",
                          "ufw disable","virsh start",
                          "systemctl enable"):
            self.assertNotIn(forbidden,text)

    def test_python_generator_no_process_or_file_mutation(self):
        code=Path(unit.__file__).read_text()
        body=code[code.index("from __future__ import annotations"):]
        for token in ("subprocess", "os.system(", "write_text(", "os.open(",
                      "mkdir(", "shutil.copy", "nft -f"):
            self.assertNotIn(token,body)


if __name__ == "__main__":
    unittest.main()
