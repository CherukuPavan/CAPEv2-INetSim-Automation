#!/usr/bin/env python3
"""Synthetic, offline regression tests. No SSL-55 modifications or network required."""
import json
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

import audit_pre_vm_stages as m


class ForwardingTests(TestCase):
    def test_nat_is_not_isolated(self):
        self.assertEqual(m.network_forward_mode("<network><forward mode='nat'/></network>"), "nat")

    def test_route_is_not_isolated(self):
        self.assertEqual(m.network_forward_mode("<network><forward mode='route'/></network>"), "route")

    def test_no_forward_is_not_full_containment(self):
        self.assertEqual(m.network_forward_mode("<network><name>lab</name></network>"), "none")

    def test_bad_xml_does_not_pass(self):
        self.assertEqual(m.network_forward_mode("<network><forward>"), "invalid-xml")


class PackageTests(TestCase):
    @patch.object(m, "run", return_value=(0, "install ok installed"))
    def test_package_installed(self, run):
        self.assertEqual(m.package_state("cpu-checker"), "installed")
        run.assert_called_once()

    @patch.object(m, "run", return_value=(1, ""))
    def test_package_missing(self, unused):
        self.assertEqual(m.package_state("cpu-checker"), "absent-or-incomplete")

    @patch.object(m, "run", return_value=(0, "LoadState=loaded\nActiveState=active\nSubState=running"))
    def test_custom_mongodb_unit(self, unused):
        status = m.service_state("mongodb.service")
        self.assertEqual(status["ActiveState"], "active")


class ServiceAccountPermissionRegressionTests(TestCase):
    def test_execute_and_probe_under_cape_not_charan(self):
        values = {
            "ImageHash": "4.3.2", "deepdiff": None,
            "binGraph": "3.3.2", "HTTPReplay": None,
            "Socks5man": None, "pyattck": "7.2.1",
        }
        python = "/home/cape/.cache/pypoetry/virtualenvs/capev2-test-py3.12/bin/python"
        mock_results = [(0, python), (0, ""), (0, json.dumps(values))]
        audit = m.Audit()
        with patch.object(m.shutil, "which", return_value="/usr/bin/sudo"), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(m, "run", side_effect=mock_results) as runner:
            audit.check_cape_venv()
        calls = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(len(calls), 3)
        for args in calls:
            self.assertEqual(args[:5], ["sudo", "-n", "-u", "cape", "-H"])
        self.assertEqual(calls[1][-3:], ["test", "-x", python])
        self.assertIn("-B", calls[2])
        found = {check: status for _, check, status, _ in audit.rows}
        self.assertEqual(found["cape virtualenv"], "PASS")
        self.assertEqual(found["Optional: ImageHash"], "PASS")
        self.assertEqual(found["Optional: deepdiff"], "PENDING")

    def test_missing_sudo_is_unknown_not_corrupt(self):
        audit = m.Audit()
        with patch.object(m.shutil, "which", return_value=None):
            audit.check_cape_venv()
        self.assertEqual(audit.rows[0][2], "UNKNOWN")

    def test_inaccessible_cape_executable_blocks(self):
        python = "/home/cape/.cache/pypoetry/virtualenvs/test/bin/python"
        audit = m.Audit()
        with patch.object(m.shutil, "which", return_value="/usr/bin/sudo"), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(m, "run", side_effect=[(0, python), (1, "")]) as runner:
            audit.check_cape_venv()
        self.assertEqual(audit.rows[0][2], "BLOCKED")
        self.assertEqual(runner.call_count, 2)

    def test_rejects_unexpected_multiline_path(self):
        audit = m.Audit()
        with patch.object(m.shutil, "which", return_value="/usr/bin/sudo"), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(m, "run", return_value=(0, "/home/cape/bin/python\nINJECTION")):
            audit.check_cape_venv()
        self.assertEqual(audit.rows[0][2], "UNKNOWN")


class ReportTests(TestCase):
    def test_keyword_redaction(self):
        audit = m.Audit()
        audit.add("10", "test", "UNKNOWN", "password=bad")
        self.assertEqual(audit.rows[0][3], "[redacted]")

    def test_nonready_gate_always_printed(self):
        audit = m.Audit()
        audit.add("03", "KVM", "PASS", "present")
        body = audit.render()
        self.assertIn("RELEASE GATE: NOT CLEARED", body)
        self.assertIn("PASS=1", body)

    def test_invalid_status_refused(self):
        with self.assertRaises(ValueError):
            m.Audit().add("11", "test", "READY", "not approved")


if __name__ == "__main__":
    main()
