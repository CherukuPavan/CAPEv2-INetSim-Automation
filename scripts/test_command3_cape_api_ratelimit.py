"""Synthetic-only Command3 CAPE API first configuration edit tests.

Does not access /opt/CAPEv2, restart services, edit networking or use SSL-55.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import command3_cape_api_ratelimit as c


class TestApiRatelimit(unittest.TestCase):
    SAMPLE = (b"# api token and unrelated config never leave this file\n"
              b"[api]\n"
              b"username = private-admin\n"
              b"ratelimit = yes\n"
              b"\n"
              b"[other]\n"
              b"ratelimit = yes\n")

    def prepare(self, tmp, content=None):
        confdir = Path(tmp) / "CAPE" / "conf"
        confdir.mkdir(parents=True)
        confdir.chmod(0o700)
        target = confdir / "api.conf"
        target.write_bytes(self.SAMPLE if content is None else content)
        target.chmod(0o640)
        return target

    def test_changes_one_selected_section_only(self):
        after, outcome = c.change(self.SAMPLE)
        self.assertEqual(outcome, "ONE_SETTING_PENDING")
        self.assertEqual(after.count(b"ratelimit = no"), 1)
        self.assertEqual(after.count(b"ratelimit = yes"), 1)
        self.assertIn(b"username = private-admin", after)
        self.assertEqual(c.change(after)[1], "NO_CHANGE_ALREADY_CONFIGURED")
        self.assertEqual(c.change(after)[0], after)

    def test_preserves_windows_line_endings_and_inline_comment(self):
        data = b"[api]\r\n  ratelimit  = YeS   # keep note\r\n[other]\r\nx = 3\r\n"
        proposed, label = c.change(data)
        self.assertEqual(label, "ONE_SETTING_PENDING")
        self.assertEqual(proposed, data.replace(b"YeS", b"no"))

    def test_refuses_ambiguous_missing_or_duplicate_live_values(self):
        for example in (
            b"[api]\n#ratelimit = yes\n",
            b"[api]\nratelimit = yes\nratelimit = no\n",
            b"[api]\nratelimit = yes\n[api]\nratelimit = no\n",
            b"[api]\nratelimit = maybe\n",
            b"[api]\nratelimit: yes\n",
            b"[other]\nratelimit = yes\n",
            b"[api]\nratelimit = True\n",
        ):
            with self.subTest(config=example), self.assertRaises(c.Command3Blocked):
                c.change(example)

    def test_read_only_plan_does_not_write_or_show_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            content = target.read_bytes()
            with patch.object(c, "write_exclusive",
                              side_effect=AssertionError("No disk changes")), \
                 patch.object(c.os, "replace",
                              side_effect=AssertionError("No overwrite")):
                result = c.plan(target)
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(result["status"], "ONE_SETTING_PENDING")
            self.assertNotIn("private-admin", str(result))
            self.assertFalse(result["host_modified"])
            self.assertFalse(result["service_restarted"])

    def test_symlink_and_unsafe_path_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            link = target.parent / "api2.conf"
            link.symlink_to(target)
            with self.assertRaisesRegex(c.Command3Blocked, "api.conf"):
                c.plan(link)
            target.unlink()
            target.symlink_to("/etc/hosts")
            with self.assertRaisesRegex(c.Command3Blocked, "Symlink"):
                c.plan(target)

    def test_explicit_root_and_tty_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            with patch.object(c.os, "geteuid", return_value=1000), \
                 self.assertRaisesRegex(c.Command3Blocked, "Root"):
                c.apply(target, Path(tmp) / "backups")

    def test_declined_approval_never_creates_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            backup = Path(tmp) / "backups"
            before = target.read_bytes()
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", return_value="NO"), \
                 self.assertRaisesRegex(c.Command3Blocked, "approve"):
                c.apply(target, backup)
            self.assertEqual(target.read_bytes(), before)
            self.assertFalse(backup.exists())

    @staticmethod
    def synthetic_backup_dir(path):
        # GitHub Actions is unprivileged. Keep the real production helper's
        # root-owned 0700 check intact and mock only its ownership admission.
        folder = Path(path)
        folder.mkdir(mode=0o700)
        return folder

    def test_approved_atomic_edit_has_private_backup_and_no_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            backup_dir = Path(tmp) / "backups"
            original = target.read_bytes()
            original_mode = stat.S_IMODE(target.stat().st_mode)
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch.object(c, "safe_backup_dir",
                              side_effect=self.synthetic_backup_dir), \
                 patch("builtins.input", return_value=c.APPROVAL):
                result = c.apply(target, backup_dir)
            self.assertEqual(result["result"],
                             "COMMAND3_API_RATELIMIT_NO_APPLIED_NOT_RESTARTED")
            self.assertFalse(result["service_restarted"])
            self.assertEqual(target.read_bytes().count(b"ratelimit = no"), 1)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), original_mode)
            backup = Path(result["backup_path"])
            self.assertEqual(backup.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(backup_dir.stat().st_mode), 0o700)
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input",
                       side_effect=AssertionError("No second approval")):
                again = c.apply(target, backup_dir)
            self.assertFalse(again["applied"])
            self.assertFalse(again["backup_created"])
            self.assertEqual(len(list(backup_dir.iterdir())), 1)

    def test_real_backup_dir_enforces_root_ownership(self):
        if os.getuid() == 0:
            self.skipTest("Test requires an unprivileged runner")
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "root-only"
            folder.mkdir(mode=0o700)
            with self.assertRaisesRegex(c.Command3Blocked, "root-owned"):
                c.safe_backup_dir(folder)

    def test_configuration_changed_after_approval_does_not_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = self.prepare(tmp)
            backups = Path(tmp) / "backups"
            def replace_before_approval(_question):
                target.write_bytes(
                    self.SAMPLE.replace(b"username = private-admin",
                                        b"username = changed-admin"))
                return c.APPROVAL
            with patch.object(c.os, "geteuid", return_value=0), \
                 patch.object(c.sys.stdin, "isatty", return_value=True), \
                 patch("builtins.input", side_effect=replace_before_approval), \
                 self.assertRaisesRegex(c.Command3Blocked, "changed"):
                c.apply(target, backups)
            self.assertFalse(backups.exists())
            self.assertIn(b"changed-admin", target.read_bytes())


if __name__ == "__main__":
    unittest.main()
