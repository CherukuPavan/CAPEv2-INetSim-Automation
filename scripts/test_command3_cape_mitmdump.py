"""Synthetic-only Step5 mitmdump host, preserving other CAPE configuration."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import command3_cape_mitmdump as m


ORIGINAL = (b"# mitmdump network settings\n"
            b"[mitmdump]\n"
            b"# host = ignore-comment\n"
            b"host = 127.0.0.1   # original listener\n"
            b"port = 8080\n"
            b"username = SENSITIVE_PRESERVE\n\n"
            b"[other]\n"
            b"hostile = do-not-change\n")


class MitmdumpStep5Tests(unittest.TestCase):
    def cfg(self, folder, content=ORIGINAL):
        root = Path(folder) / "CAPE" / "conf"
        root.mkdir(parents=True)
        src = root / "mitmdump.conf"
        src.write_bytes(content)
        src.chmod(0o640)
        return src

    def test_exact_one_key_and_every_other_line_unchanged(self):
        output, changes = m.transform(ORIGINAL, "192.168.122.1")
        expected = ORIGINAL.replace(
            b"host = 127.0.0.1   # original listener",
            b"host = 192.168.122.1   # original listener")
        self.assertEqual(output, expected)
        self.assertEqual(changes, [{"key": "host", "target": "192.168.122.1"}])
        self.assertEqual(m.transform(output, "192.168.122.1"), (output, []))

    def test_no_hardcoded_gateway_when_target_network_differs(self):
        altered, changes = m.transform(ORIGINAL, "10.88.30.1")
        self.assertIn(b"host = 10.88.30.1", altered)
        self.assertNotIn(b"host = 192.168.122.1", altered)
        self.assertEqual(changes[0]["target"], "10.88.30.1")

    def test_preserve_windows_line_endings_and_extra_settings(self):
        raw = ORIGINAL.replace(b"\n", b"\r\n")
        output, changes = m.transform(raw, "192.168.122.1")
        self.assertEqual(len(changes), 1)
        self.assertEqual(output.replace(b"\r\n", b"").count(b"\n"), 0)
        self.assertIn(b"host = 192.168.122.1   # original listener\r\n", output)
        self.assertEqual(m.transform(output, "192.168.122.1"), (output, []))

    def test_missing_duplicate_malformed_and_commented_only_block(self):
        for invalid in (
            ORIGINAL.replace(b"host = 127.0.0.1   # original listener\n", b""),
            ORIGINAL.replace(b"host = 127.0.0.1   # original listener\n",
                             b"host = 127.0.0.1\nhost = localhost\n"),
            ORIGINAL.replace(b"host = 127.0.0.1   # original listener\n",
                             b"host = \n"),
            ORIGINAL.replace(b"host = 127.0.0.1   # original listener\n",
                             b"host = quote-this!-bad\n"),
        ):
            with self.subTest(invalid=invalid[-70:]), self.assertRaises(
                    m.MitmdumpBlocked):
                m.transform(invalid, "192.168.122.1")

    def test_private_gateway_must_be_valid_not_public_or_wildcard(self):
        for value in ("0.0.0.0", "8.8.8.8", "::1", "localhost",
                      "127.0.0.1", "192.168.122.255.1", "192.168.122.001"):
            with self.subTest(target=value), self.assertRaises(
                    m.MitmdumpBlocked):
                m.private_ipv4(value)

    def test_verified_gateway_reads_both_active_and_saved_nat(self):
        import command2_portable_master_nat_attach as nat
        net = ET.fromstring(
            '<network><name>default</name><bridge name="virbr0"/>'
            '<forward mode="nat"/></network>')
        details = {"nat_network": "default", "bridge": "virbr0",
                   "ipv4": {"subnet": "192.168.122.0/24",
                            "gateway": "192.168.122.1"},
                   "dynamic_dhcp_ranges": [("192.168.122.2", "192.168.122.254")]}
        persistent = {"ipv4": details["ipv4"],
                      "dynamic_dhcp_ranges": details["dynamic_dhcp_ranges"]}
        with patch.object(nat, "check_network_references",
                          return_value=(details, [net, net])), \
             patch.object(nat.profile.ref, "nat_details",
                          return_value=persistent):
            self.assertEqual(m.verified_gateway(), "192.168.122.1")
        with patch.object(nat, "check_network_references",
                          return_value=(details, [net, net])), \
             patch.object(nat.profile.ref, "nat_details",
                          return_value={"ipv4": {"gateway": "192.168.122.99"},
                                        "dynamic_dhcp_ranges": []}), \
             self.assertRaisesRegex(m.MitmdumpBlocked, "differ"):
            m.verified_gateway()

    def test_read_only_plan_matches_real_gateway_and_never_leaks_secret(self):
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            with patch.object(m, "verified_gateway",
                              return_value="192.168.122.1"), \
                 patch.object(m.os, "replace",
                              side_effect=AssertionError("Plan cannot modify host")):
                report = m.plan(src, "192.168.122.1")
                with self.assertRaisesRegex(m.MitmdumpBlocked, "does not match"):
                    m.plan(src, "10.23.104.1")
            self.assertEqual(report["setting"], "host")
            self.assertEqual(report["target"], "192.168.122.1")
            self.assertFalse(report["host_modified"])
            self.assertFalse(report["service_restarted"])
            self.assertFalse(report["network_isolation_verified"])
            self.assertNotIn("SENSITIVE_PRESERVE", str(report))
            self.assertEqual(src.read_bytes(), ORIGINAL)

    def test_symlinked_path_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            src.unlink()
            src.symlink_to("/etc/hosts")
            with self.assertRaisesRegex(m.MitmdumpBlocked, "Symlink"):
                m.safe_config(src)

    def test_unprivileged_and_reference_host_apply_blocked(self):
        import socket
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            with patch.object(m.os, "geteuid", return_value=1000), \
                 self.assertRaisesRegex(m.MitmdumpBlocked, "root"):
                m.apply(src, Path(td) / "backup")
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(socket, "gethostname", return_value="CSE-SSL-55"), \
                 patch.object(m, "plan", side_effect=AssertionError("No planning")), \
                 self.assertRaisesRegex(m.MitmdumpBlocked, "SSL-55"):
                m.apply(src, Path(td) / "backup")

    def test_refused_approval_leaves_file_and_no_backup(self):
        import socket
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            backup = Path(td) / "backup"
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(socket, "gethostname", return_value="new-lab"), \
                 patch.object(m, "verified_gateway", return_value="192.168.122.1"), \
                 patch("builtins.input", return_value="NO"), \
                 self.assertRaisesRegex(m.MitmdumpBlocked, "declined"):
                m.apply(src, backup)
            self.assertEqual(src.read_bytes(), ORIGINAL)
            self.assertFalse(backup.exists())

    def test_approved_apply_creates_private_original_backup_and_repeat_is_noop(self):
        import socket
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            backup = Path(td) / "backup"
            mode = stat.S_IMODE(src.stat().st_mode)
            def fake_private_backup_dir(path):
                Path(path).mkdir(mode=0o700)
                return Path(path)
            # GitHub runners lack root; keep real ownership validation intact.
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(socket, "gethostname", return_value="new-lab"), \
                 patch.object(m, "verified_gateway", return_value="192.168.122.1"), \
                 patch.object(m.guard, "safe_backup_dir",
                              side_effect=fake_private_backup_dir), \
                 patch("builtins.input", return_value=m.APPROVAL):
                result = m.apply(src, backup)
            self.assertTrue(result["applied"])
            self.assertTrue(result["backup_created"])
            self.assertFalse(result["service_restarted"])
            self.assertEqual(src.stat().st_mode & 0o777, mode)
            self.assertEqual(Path(result["backup_path"]).read_bytes(), ORIGINAL)
            self.assertEqual(Path(result["backup_path"]).stat().st_mode & 0o777,
                             0o600)
            self.assertEqual(m.transform(src.read_bytes(), "192.168.122.1")[1], [])
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(socket, "gethostname", return_value="new-lab"), \
                 patch.object(m, "verified_gateway", return_value="192.168.122.1"), \
                 patch("builtins.input",
                       side_effect=AssertionError("No prompt after correct config")):
                second = m.apply(src, backup)
            self.assertFalse(second["applied"])
            self.assertFalse(second["backup_created"])
            self.assertEqual(len(list(backup.iterdir())), 1)

    def test_concurrent_edit_or_gateway_drift_does_not_apply(self):
        import socket
        with tempfile.TemporaryDirectory() as td:
            src = self.cfg(td)
            backup = Path(td) / "backup"
            def change_during_consent(_question):
                src.write_bytes(ORIGINAL.replace(b"port = 8080", b"port = 8081"))
                return m.APPROVAL
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(socket, "gethostname", return_value="new-lab"), \
                 patch.object(m, "verified_gateway", return_value="192.168.122.1"), \
                 patch("builtins.input", side_effect=change_during_consent), \
                 self.assertRaisesRegex(m.MitmdumpBlocked, "changed"):
                m.apply(src, backup)
            self.assertIn(b"port = 8081", src.read_bytes())
            self.assertFalse(backup.exists())


if __name__ == "__main__":
    unittest.main()
