#!/usr/bin/env python3
"""Synthetic tests; never touch libvirt/VMs or change the host."""
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import audit_windows_vm_preflight as m


class NetworkIsolationTests(unittest.TestCase):
    def test_libvirt_nat_is_detected(self):
        self.assertEqual(m.forwarding_mode("<network><forward mode='nat'/></network>"), "nat")

    def test_absent_forward_does_not_claim_malware_safety(self):
        self.assertEqual(m.forwarding_mode("<network><name>analysis</name></network>"), "none")
        self.assertEqual(m.forwarding_mode("<network><name>analysis</name></network>"), "none")

    def test_broken_xml_is_unknown(self):
        self.assertEqual(m.forwarding_mode("<network>"), "unknown")

    def test_incorrect_root_is_unknown(self):
        self.assertEqual(m.forwarding_mode("<domain/>"), "unknown")


class HostPreflightTests(unittest.TestCase):
    def test_no_live_malware_readiness_even_when_resources_present(self):
        with patch.object(m.os, "cpu_count", return_value=32), \
             patch.object(m.shutil, "which", return_value="/usr/bin/test"), \
             patch.object(m.shutil, "disk_usage", return_value=type("DU", (), {"free": 280*1024**3})()), \
             patch.object(m, "cmd", side_effect=[
                 (0, "Running hypervisor: QEMU 9.2.2"),
                 (0, ""), (0, "<network><forward mode='nat'/></network>"),
                 (0, "active"),
             ]), \
             patch.object(m.Path, "is_dir", return_value=True), \
             patch.object(m.Path, "read_text", return_value="MemTotal: 63000000 kB\nMemAvailable: 56000000 kB"):
            result = m.get_preflight(None)
        checks = result["checks"]
        self.assertEqual(checks["logical_cpus"], 32)
        self.assertEqual(checks["defined_vm_count"], 0)
        self.assertEqual(checks["default_libvirt_forward_mode"], "nat")
        self.assertFalse(checks["default_network_safe_for_malware"])
        self.assertFalse(result["ready_for_live_malware"])
        self.assertFalse(result["changes_made"])
        self.assertEqual(result["result"], "PREFLIGHT_REVIEW_REQUIRED")

    def test_missing_swtpm_is_review_item(self):
        def tool(name):
            return None if name == "swtpm" else "/usr/bin/test"
        with patch.object(m.os, "cpu_count", return_value=4), \
             patch.object(m.shutil, "which", side_effect=tool), \
             patch.object(m.shutil, "disk_usage", side_effect=OSError()), \
             patch.object(m, "cmd", side_effect=[
                 (0, "Running hypervisor: QEMU 9.2.2"),
                 (0, ""), (0, "<network/>"), (0, "active"),
             ]), \
             patch.object(m.Path, "is_dir", return_value=False), \
             patch.object(m.Path, "read_text", return_value=""):
            result = m.get_preflight(None)
        self.assertTrue(any("swtpm missing" in item for item in result["provisioning_review_items"]))
        self.assertFalse(result["ready_for_live_malware"])


if __name__ == "__main__":
    unittest.main()
