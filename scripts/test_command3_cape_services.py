"""Offline-only Command3 five-service lifecycle plan and post-restart checks."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import command3_cape_services as m

ROUTING = b"""[routing]
enable_pcap = yes
route = internet
internet = virbr0
nat = yes
no_local_routing = yes
rt_table = main

[other]
secret = SHOULD_NOT_BE_IN_REPORT
"""
VALID_SYSTEMD = ("LoadState=loaded\nActiveState=active\nSubState=running\n"
                 "Result=success\nFragmentPath=/etc/systemd/system/cape.service\n")


class RestartStepTests(unittest.TestCase):
    def fake_conf(self, root, contents=ROUTING):
        directory = Path(root) / "CAPEv2" / "conf"
        directory.mkdir(parents=True)
        path = directory / "routing.conf"
        path.write_bytes(contents)
        path.chmod(0o640)
        return path

    def test_operator_service_names_and_order_preserved(self):
        self.assertEqual(m.OPERATOR_ORDER, (
            "cape.service", "cape-processor.service",
            "cape-rooter.service", "cape-web.service",
            "suricata.service"))
        self.assertEqual(m.UPSTREAM_START_ORDER[0], "cape-rooter.service")
        self.assertNotEqual(m.OPERATOR_ORDER, m.UPSTREAM_START_ORDER)

    def test_routing_values_correct_and_preserve_other_section(self):
        value = m.routing_status(ROUTING)
        self.assertEqual(value, {"route": "internet", "internet": "virbr0",
                                 "enable_pcap": "yes"})
        self.assertNotIn("SHOULD_NOT_BE_IN_REPORT", str(value))

    def test_routing_not_trusted_just_because_it_is_none(self):
        none = ROUTING.replace(b"route = internet", b"route = none")
        none = none.replace(b"internet = virbr0", b"internet = none")
        with tempfile.TemporaryDirectory() as td:
            f = self.fake_conf(td, none)
            with patch.object(m, "systemd_status",
                              side_effect=lambda name: {
                                  "unit": name, "loaded": True, "active": True,
                                  "load_state": "loaded",
                                  "active_state": "active"}):
                report = m.report(f, "plan")
            self.assertFalse(report["restart_apply_authorized"])
            self.assertFalse(report["CAPE_READY"])
            self.assertIn("deny-egress", str(report["blocking_issues"]))

    def test_plan_never_runs_restart_or_mutates_host(self):
        with tempfile.TemporaryDirectory() as td:
            f = self.fake_conf(td)
            original = f.read_bytes()
            called = []
            def fake_status(name):
                called.append(name)
                return {"unit": name, "loaded": True,
                        "active": True, "load_state": "loaded",
                        "active_state": "active", "last_result": "success"}
            with patch.object(m, "systemd_status",
                              side_effect=fake_status), \
                 patch.object(m.os, "replace",
                              side_effect=AssertionError("No write")):
                result = m.report(f, "plan")
            self.assertEqual(called, list(m.OPERATOR_ORDER))
            self.assertEqual(f.read_bytes(), original)
            self.assertFalse(result["host_modified"])
            self.assertFalse(result["restart_automated"])
            self.assertFalse(result["restart_apply_authorized"])
            self.assertFalse(result["CAPE_READY"])
            self.assertFalse(result["services_have_just_been_restarted_verified"])
            self.assertTrue(result["all_services_active_now"])
            self.assertIn("Internet", str(result["blocking_issues"])+"Internet")
            self.assertNotIn("SHOULD_NOT_BE_IN_REPORT", str(result))

    def test_verify_reports_readonly_state_does_not_imply_restart_succeeded(self):
        with tempfile.TemporaryDirectory() as td:
            f = self.fake_conf(td)
            def fake(unit):
                return {"unit": unit, "loaded": True,
                        "active": unit != "cape-rooter.service",
                        "load_state": "loaded",
                        "active_state": ("active" if unit != "cape-rooter.service"
                                         else "failed")}
            with patch.object(m, "systemd_status", side_effect=fake):
                status = m.report(f, "verify")
            self.assertEqual(status["result"], "COMMAND3_FIVE_SERVICE_READ_ONLY_STATUS")
            self.assertFalse(status["all_services_active_now"])
            self.assertFalse(status["services_have_just_been_restarted_verified"])
            self.assertTrue(any("not active" in x for x in
                                status["blocking_issues"]))

    def test_systemctl_readonly_show_exact_approved_names_no_shell(self):
        with patch.object(m.subprocess, "check_output",
                          return_value=VALID_SYSTEMD) as called:
            status = m.systemd_status("cape-rooter.service")
        self.assertTrue(status["loaded"])
        self.assertTrue(status["active"])
        args = called.call_args.args[0]
        self.assertEqual(args, [
            "systemctl", "show", "--no-pager",
            "--property=LoadState,ActiveState,SubState,Result,FragmentPath",
            "cape-rooter.service"])
        with self.assertRaisesRegex(m.ServicesBlocked, "Unapproved"):
            m.systemd_status("ssh.service")
        called.assert_called_once()

    def test_unknown_inactive_or_missing_units_do_not_claim_all_healthy(self):
        with patch.object(m.subprocess, "check_output",
                          return_value=VALID_SYSTEMD.replace(
                              "LoadState=loaded", "LoadState=not-found")):
            self.assertFalse(m.systemd_status("cape.service")["loaded"])
        with patch.object(m.subprocess, "check_output",
                          side_effect=subprocess.TimeoutExpired(
                              cmd="systemctl", timeout=8)), \
             self.assertRaisesRegex(m.ServicesBlocked, "Unable to inspect"):
            m.systemd_status("suricata.service")

    def test_duplicate_or_missing_routing_values_refused(self):
        invalid = (
            ROUTING.replace(b"route = internet\n", b""),
            ROUTING.replace(b"route = internet\n",
                            b"route = internet\nroute = none\n"),
            ROUTING.replace(b"[routing]", b"[not_routing]"),
            ROUTING.replace(b"enable_pcap = yes",
                            b"enable_pcap = invalid"),
            ROUTING + b"\n[routing]\n",
        )
        for val in invalid:
            with self.subTest(val=val[-70:]), self.assertRaises(
                    m.ServicesBlocked):
                m.routing_status(val)

    def test_unsupported_apply_mode_and_absence_of_mutating_commands(self):
        with self.assertRaisesRegex(m.ServicesBlocked,
                                    "Read-only"):
            m.report(Path("/nonexistent/path"), "apply")
        script = Path(m.__file__).read_text(encoding="utf-8")
        for denied in (
            'choices=("plan", "apply")',
            "subprocess.run(",
            "subprocess.call(",
            "os.replace(",
            "os.system(",
            "systemctl restart",
            "start-stop-daemon",
            "write_bytes(",
            "write_text(",
            "shutil.copy",
        ):
            self.assertNotIn(denied, script)


if __name__ == "__main__":
    unittest.main()
