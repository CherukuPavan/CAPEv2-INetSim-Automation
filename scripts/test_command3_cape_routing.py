"""Synthetic-only Command3 Step6 routing profile and no-apply safety tests."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import command3_cape_routing as m

BEFORE = b"""# routing unchanged comments and other settings
[routing]
# pcap on live analysis connections
enable_pcap = no

# Route default
route = none

# Optional dirty line
internet = none

nat = yes
no_local_routing = yes
rt_table = main

[default]
password = SECRET_DO_NOT_EMIT
"""

AFTER = BEFORE.replace(b"enable_pcap = no", b"enable_pcap = yes").replace(
    b"route = none", b"route = internet").replace(
    b"internet = none", b"internet = virbr0")


class RoutingReviewTests(unittest.TestCase):
    def path(self, directory, raw=BEFORE):
        root = Path(directory) / "CAPEv2" / "conf"
        root.mkdir(parents=True)
        config = root / "routing.conf"
        config.write_bytes(raw)
        config.chmod(0o640)
        return config

    def test_operator_before_to_after_three_edits_only(self):
        proposed, changes = m.proposed_diff(BEFORE)
        self.assertEqual(proposed, AFTER)
        self.assertEqual(len(changes), 3)
        self.assertEqual(
            [x["setting"] for x in changes],
            ["[routing] enable_pcap", "[routing] route", "[routing] internet"])
        self.assertEqual(m.proposed_diff(AFTER), (AFTER, []))
        self.assertIn(b"nat = yes", proposed)
        self.assertIn(b"no_local_routing = yes", proposed)
        self.assertIn(b"rt_table = main", proposed)
        self.assertIn(b"password = SECRET_DO_NOT_EMIT", proposed)

    def test_original_config_crlf_and_comments_byte_preserved(self):
        data = BEFORE.replace(b"\n", b"\r\n")
        proposed, changes = m.proposed_diff(data)
        self.assertEqual(len(changes), 3)
        self.assertEqual(proposed, AFTER.replace(b"\n", b"\r\n"))
        self.assertEqual(m.proposed_diff(proposed), (proposed, []))

    def test_duplicate_or_missing_key_rejected(self):
        cases = (
            BEFORE.replace(b"route = none\n", b""),
            BEFORE.replace(b"route = none\n",
                           b"route = none\nroute = internet\n"),
            BEFORE + b"[routing]\n",
            BEFORE.replace(b"[routing]", b"[route]"),
            BEFORE.replace(b"internet = none", b"internet = "),
            BEFORE.replace(b"enable_pcap = no", b"enable_pcap = random"),
        )
        for invalid in cases:
            with self.subTest(bad=invalid[-60:]), self.assertRaises(
                    m.RoutingBlocked):
                m.proposed_diff(invalid)

    def test_unchanged_reference_fields_must_not_be_automatically_rewritten(self):
        for name, value in (
            (b"nat = yes", b"nat = no"),
            (b"no_local_routing = yes", b"no_local_routing = no"),
            (b"rt_table = main", b"rt_table = different"),
        ):
            with self.subTest(setting=name), self.assertRaisesRegex(
                    m.RoutingBlocked, "Unchanged operator reference"):
                m.proposed_diff(BEFORE.replace(name, value))

    def test_plan_is_readonly_never_emits_confidential_untouched_entries(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.path(root)
            original = path.read_bytes()
            with patch.object(m.os, "replace",
                              side_effect=AssertionError("No config writes")), \
                 patch.object(m.os, "unlink",
                              side_effect=AssertionError("No deletions")):
                report = m.plan(path)
            self.assertEqual(report["changed_option_count"], 3)
            self.assertEqual(report["status"],
                             "BLOCKED_DIRTY_LINE_VM_BRIDGE_AND_PUBLIC_EGRESS")
            self.assertFalse(report["host_modified"])
            self.assertFalse(report["service_restarted"])
            self.assertFalse(report["CAPE_READY"])
            self.assertTrue(report["unsupported_automatic_apply"])
            self.assertTrue(
                report["nat_already_allows_internet_even_when_cape_route_none"])
            self.assertNotIn("SECRET_DO_NOT_EMIT", str(report))
            self.assertEqual(path.read_bytes(), original)

    def test_plan_after_operator_manual_change_works_without_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.path(root, AFTER)
            status = m.plan(path)
            self.assertEqual(status["changed_option_count"], 0)
            self.assertEqual(status["status"], m.NOT_DEPLOYABLE)
            self.assertFalse(status["host_modified"])
            self.assertEqual(path.read_bytes(), AFTER)

    def test_symlink_and_insecure_config_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.path(root)
            path.unlink()
            path.symlink_to("/etc/hosts")
            with self.assertRaisesRegex(m.RoutingBlocked, "Symlink"):
                m.read_conf(path)
            path.unlink()
            path.write_bytes(BEFORE)
            path.chmod(0o666)
            with self.assertRaisesRegex(m.RoutingBlocked, "permissions"):
                m.read_conf(path)

    def test_has_no_apply_or_write_or_routing_commands(self):
        script = Path(m.__file__).read_text(encoding="utf-8")
        self.assertNotIn('choices=("plan", "apply")', script)
        for command in ("subprocess.run(", "os.replace(", "os.system(",
                        "systemctl restart", "iptables -A",
                        "virsh snapshot-revert", "router_manager.py -r",
                        "write_bytes(", "write_text("):
            self.assertNotIn(command, script)


if __name__ == "__main__":
    unittest.main()
