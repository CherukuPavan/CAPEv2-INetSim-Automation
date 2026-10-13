"""Offline synthetic-only Step 13.2.2 CAPE auxiliary.conf safety checks."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import command3_cape_auxiliary as a

# Actual operator correction: the reference file did not have an amsi entry.
# Only the remaining options were existing lines to modify if necessary.
REFERENCE = b"""# Modules to be enabled or not inside the VM
[auxiliary_modules]
browser = yes
curtain = no
digisig = yes
disguise = yes
evtx = no
human_windows = yes
human_linux = no
procmon = no
recentfiles = no
screenshots_windows = yes
screenshots_linux = yes
sysmon_windows = no
sysmon_linux = no
tlsdump = yes
usage = no
file_pickup = no
permissions = no
pre_script = no
during_script = no
filecollector = yes
windows_static_route = no
tracee_linux = no
sslkeylogfile = no
# Browser extension prerequisite must be configured separately.
browsermonitor = no

[another_section]
password = PRIVATE_NOT_TO_LOG
screenshots_windows = yes
"""


class AuxiliaryStep2Tests(unittest.TestCase):
    def setup_conf(self, path, data=REFERENCE):
        folder = Path(path) / "CAPE" / "conf"
        folder.mkdir(parents=True)
        f = folder / "auxiliary.conf"
        f.write_bytes(data)
        f.chmod(0o640)
        return f

    def test_amsi_absent_is_inserted_once_and_remaining_14_changed(self):
        proposed, changes = a.transform(REFERENCE)
        self.assertEqual(len(a.TARGET), 15)
        self.assertEqual(len(changes), 15)
        self.assertEqual([x for x in changes if x["action"] == "insert"],
                         [{"key": "amsi", "action": "insert", "target": "yes"}])
        self.assertEqual(proposed.count(b"amsi = yes"), 1)
        self.assertIn(b"[auxiliary_modules]\namsi = yes\nbrowser = yes", proposed)
        # Preserve every untouched option and unrelated section byte-for-byte.
        self.assertIn(b"[another_section]\npassword = PRIVATE_NOT_TO_LOG\n"
                      b"screenshots_windows = yes\n", proposed)
        for key, want in a.TARGET.items():
            self.assertIn((key + " = " + want).encode(), proposed)
        self.assertIn(b"filecollector = yes", proposed)
        self.assertIn(b"digisig = yes", proposed)
        self.assertIn(b"sysmon_linux = no", proposed)
        self.assertIn(b"tlsdump = yes", proposed)
        self.assertEqual(a.transform(proposed), (proposed, []))

    def test_existing_amsi_no_changes_in_place_not_duplicate(self):
        earlier = REFERENCE.replace(b"[auxiliary_modules]\n",
                                    b"[auxiliary_modules]\namsi = no\n")
        data, changes = a.transform(earlier)
        self.assertEqual(data.count(b"amsi = yes"), 1)
        self.assertEqual(len(changes), 15)
        self.assertEqual([x for x in changes if x["key"] == "amsi"][0]["action"],
                         "set")

    def test_existing_amsi_yes_is_not_changed(self):
        earlier = REFERENCE.replace(b"[auxiliary_modules]\n",
                                    b"[auxiliary_modules]\namsi = yes\n")
        data, changes = a.transform(earlier)
        self.assertEqual(data.count(b"amsi = yes"), 1)
        self.assertNotIn("amsi", [x["key"] for x in changes])
        self.assertEqual(len(changes), 14)

    def test_same_profile_crlf_kept_without_mixed_line_endings(self):
        earlier = REFERENCE.replace(b"\n", b"\r\n")
        data, changes = a.transform(earlier)
        self.assertEqual(len(changes), 15)
        self.assertIn(b"[auxiliary_modules]\r\namsi = yes\r\n", data)
        self.assertEqual(data.replace(b"\r\n", b"").count(b"\n"), 0)
        self.assertEqual(a.transform(data), (data, []))

    def test_duplicate_amsi_and_other_reviewed_options_refused(self):
        for new in (b"amsi = yes\namsi = no\n", b"procmon = yes\nprocmon = no\n"):
            damaged = REFERENCE.replace(
                b"[auxiliary_modules]\n", b"[auxiliary_modules]\n" + new)
            with self.subTest(new=new), self.assertRaisesRegex(
                    a.AuxiliaryBlocked, "Duplicate"):
                a.transform(damaged)

    def test_missing_non_amsi_option_is_fail_closed(self):
        damaged = REFERENCE.replace(b"browsermonitor = no\n", b"")
        with self.assertRaisesRegex(a.AuxiliaryBlocked, "browsermonitor"):
            a.transform(damaged)

    def test_wrong_or_duplicate_section_is_fail_closed(self):
        for damaged in (REFERENCE.replace(b"[auxiliary_modules]",
                                          b"[auxiliary_disabled]"),
                        REFERENCE + b"[auxiliary_modules]\n",
                        REFERENCE.replace(b"evtx = no", b"evtx = MAYBE")):
            with self.subTest(damaged=damaged[-50:]), self.assertRaises(
                    a.AuxiliaryBlocked):
                a.transform(damaged)

    def test_plan_does_not_write_or_echo_unrelated_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.setup_conf(td)
            original = path.read_bytes()
            with patch.object(a.os, "replace",
                              side_effect=AssertionError("Plan must not write")):
                result = a.plan(path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(result["target_count"], 15)
            self.assertEqual(len(result["changes"]), 15)
            self.assertFalse(result["host_modified"])
            self.assertTrue(result["requires_browser_extension_for_browsermonitor"])
            self.assertNotIn("PRIVATE_NOT_TO_LOG", str(result))

    def test_requires_root_terminal_and_explicit_approval(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.setup_conf(td)
            backup_dir = Path(td) / "backup"
            with patch.object(a.os, "geteuid", return_value=1001), \
                 self.assertRaisesRegex(a.AuxiliaryBlocked, "Root"):
                a.apply(path, backup_dir)
            with patch.object(a.os, "geteuid", return_value=0), \
                 patch.object(a.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", return_value="NO"), \
                 self.assertRaisesRegex(a.AuxiliaryBlocked, "declined"):
                a.apply(path, backup_dir)
            self.assertEqual(path.read_bytes(), REFERENCE)
            self.assertFalse(backup_dir.exists())

    def test_approved_apply_preserves_private_backup_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.setup_conf(td)
            backup_dir = Path(td) / "backup"
            mode = stat.S_IMODE(path.stat().st_mode)
            def fake_private_dir(path):
                Path(path).mkdir(mode=0o700)
                return Path(path)
            # Test runner is unprivileged: simulate backup OWNER gate, never
            # weaken guard.safe_backup_dir in real code.
            with patch.object(a.os, "geteuid", return_value=0), \
                 patch.object(a.sys.stdin, "isatty", return_value=True), \
                 patch.object(a.guard, "safe_backup_dir",
                              side_effect=fake_private_dir), \
                 patch("builtins.input", return_value=a.APPROVAL):
                result = a.apply(path, backup_dir)
            self.assertTrue(result["applied"])
            self.assertEqual(result["result"],
                             "COMMAND3_AUXILIARY_15_TARGETS_APPLIED_NOT_RESTARTED")
            self.assertFalse(result["service_restarted"])
            self.assertFalse(result["guest_module_prerequisites_verified"])
            self.assertEqual(path.stat().st_mode & 0o777, mode)
            backup = Path(result["backup_path"])
            self.assertEqual(backup.read_bytes(), REFERENCE)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(a.transform(path.read_bytes())[1], [])
            with patch.object(a.os, "geteuid", return_value=0), \
                 patch.object(a.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input",
                       side_effect=AssertionError("No second prompt")):
                second = a.apply(path, backup_dir)
            self.assertFalse(second["applied"])
            self.assertFalse(second["backup_created"])
            self.assertEqual(len(list(backup_dir.iterdir())), 1)

    def test_changed_after_operator_approval_never_modifies_host_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.setup_conf(td)
            backup_dir = Path(td) / "backup"
            def concurrent(_question):
                path.write_bytes(REFERENCE.replace(b"browser = yes",
                                                   b"browser = no"))
                return a.APPROVAL
            with patch.object(a.os, "geteuid", return_value=0), \
                 patch.object(a.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", side_effect=concurrent), \
                 self.assertRaisesRegex(a.AuxiliaryBlocked, "changed"):
                a.apply(path, backup_dir)
            self.assertFalse(backup_dir.exists())
            self.assertIn(b"browser = no", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
