"""Synthetic preflight tests for CAPE [tmpfs] ownership startup gate."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import command3_cape_tmpfs as m

CONFIG = b"""[cuckoo]
machinery_screenshots = on
[tmpfs]
enabled = on
path = /mnt/tmpfs/
freespace = 4096
[database]
password = DO_NOT_REPORT
"""


class CapeTmpfsTests(unittest.TestCase):
    def cfg(self, td, content=CONFIG):
        folder = Path(td) / "CAPE" / "conf"
        folder.mkdir(parents=True)
        target = folder / "cuckoo.conf"
        target.write_bytes(content)
        target.chmod(0o640)
        return target

    def test_exact_expected_options_and_no_secret_readback(self):
        options = m.parse_config(CONFIG)
        self.assertEqual(options, {"enabled": True, "path": "/mnt/tmpfs",
                                   "minimum_free_mib": 4096})
        with tempfile.TemporaryDirectory() as td:
            p = self.cfg(td)
            data, digest = m.config(p)
            self.assertEqual(data, options)
            self.assertEqual(len(digest), 64)
            self.assertNotIn("DO_NOT_REPORT", str(data))
        off = CONFIG.replace(b"enabled = on", b"enabled = off")
        self.assertFalse(m.parse_config(off)["enabled"])

    def test_absent_duplicate_bad_tmpfs_configuration_refused(self):
        broken = (
            CONFIG.replace(b"[tmpfs]", b"[oldtmpfs]"),
            CONFIG + b"\n[tmpfs]\n",
            CONFIG.replace(b"path = /mnt/tmpfs/", b"path = /mnt/disks"),
            CONFIG.replace(b"enabled = on", b"enabled = maybe"),
            CONFIG.replace(b"freespace = 4096", b"freespace = nope"),
            CONFIG.replace(b"freespace = 4096", b"freespace = -1"),
            CONFIG.replace(b"enabled = on\n",
                           b"enabled = on\nenabled = off\n"),
        )
        for item in broken:
            with self.subTest(bad=item[-60:]), self.assertRaises(m.TmpfsBlocked):
                m.parse_config(item)

    def test_plan_blocks_missing_mount_instead_of_chown_underlying_disk(self):
        with tempfile.TemporaryDirectory() as td:
            config = self.cfg(td)
            missing = Path(td) / "mnt" / "tmpfs"
            missing.parent.mkdir()
            missing.mkdir()
            with patch.object(m, "EXPECTED", missing), \
                 patch.object(m, "mount_fstype", return_value=None), \
                 patch.object(m.os, "chown",
                              side_effect=AssertionError("No chown")):
                out = m.assess(config)
            self.assertFalse(out["cape_tmpfs_prerequisite_ready"])
            self.assertEqual(out["status"], "BLOCKED_UNMOUNTED")
            self.assertIn("not a mounted tmpfs", out["blocking_issues"][0])

    def test_existing_mount_wrong_owner_detected_before_service_restarts(self):
        with tempfile.TemporaryDirectory() as td:
            config = self.cfg(td, CONFIG.replace(b"freespace = 4096",
                                                 b"freespace = 0"))
            directory = Path(td) / "mnt" / "tmpfs"
            directory.parent.mkdir()
            directory.mkdir(mode=0o700)
            other = os.getuid() + 100
            with patch.object(m, "EXPECTED", directory), \
                 patch.object(m, "mount_fstype", return_value="tmpfs"), \
                 patch.object(m, "cape_ids", return_value=(other, other)):
                out = m.assess(config)
            self.assertEqual(out["status"], "BLOCKED_MOUNT_ACCESS_OR_CAPACITY")
            self.assertFalse(out["owner_is_cape"])
            self.assertFalse(out["cape_tmpfs_prerequisite_ready"])
            self.assertEqual(out["filesystem"], "tmpfs")

    def test_owner_and_free_space_both_required(self):
        with tempfile.TemporaryDirectory() as td:
            config = self.cfg(td)
            directory = Path(td) / "mnt" / "tmpfs"
            directory.parent.mkdir()
            directory.mkdir(mode=0o700)
            uid, gid = os.getuid(), os.getgid()
            with patch.object(m, "EXPECTED", directory), \
                 patch.object(m, "mount_fstype", return_value="tmpfs"), \
                 patch.object(m, "cape_ids", return_value=(uid, gid)), \
                 patch.object(m.os, "statvfs") as fake:
                fake.return_value.f_bavail = 2000
                fake.return_value.f_frsize = 1024 * 1024
                out = m.assess(config)
            self.assertTrue(out["owner_is_cape"])
            self.assertEqual(out["free_mib"], 2000)
            self.assertFalse(out["cape_tmpfs_prerequisite_ready"])
            self.assertTrue(any("space" in x for x in out["blocking_issues"]))

    def test_disabled_tmpfs_requires_no_mount_and_no_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.cfg(td, CONFIG.replace(b"enabled = on", b"enabled = off"))
            with patch.object(m, "mount_fstype",
                              side_effect=AssertionError("No mount needed")):
                out = m.assess(path)
            self.assertTrue(out["cape_tmpfs_prerequisite_ready"])
            self.assertEqual(out["status"], "DISABLED_NO_TMPFS_REQUIRED")

    def test_symlinked_mount_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self.cfg(td)
            invalid = Path(td) / "tmpfs"
            invalid.symlink_to("/etc")
            with patch.object(m, "EXPECTED", invalid), \
                 self.assertRaisesRegex(m.TmpfsBlocked, "Symlink"):
                m.assess(path)

    def test_repair_refuses_nonroot_and_protected_ssl55(self):
        with patch.object(m.os, "geteuid", return_value=1000), \
             self.assertRaisesRegex(m.TmpfsBlocked, "Root"):
            m.repair_owner(Path("/unused/conf/cuckoo.conf"))
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m.socket, "gethostname", return_value="CSE-SSL-55"), \
             patch.object(m, "assess", side_effect=AssertionError(
                 "Must not inspect/mutate protected reference")), \
             self.assertRaisesRegex(m.TmpfsBlocked, "SSL-55"):
            m.repair_owner(Path("/unused/conf/cuckoo.conf"))

    def test_repair_never_chowns_not_mounted_or_disabled_tmpfs(self):
        first = {
            "configured_tmpfs": {"enabled": True}, "filesystem": None,
            "cape_tmpfs_prerequisite_ready": False,
        }
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m.socket, "gethostname", return_value="new-host"), \
             patch.object(m, "assess", return_value=first), \
             patch.object(m.os, "fchown",
                          side_effect=AssertionError("Never chown")), \
             self.assertRaisesRegex(m.TmpfsBlocked, "missing/disabled"):
            m.repair_owner(Path("/unused/conf/cuckoo.conf"))

    def test_declined_repair_does_not_modify_tmpfs(self):
        first = {
            "configured_tmpfs": {"enabled": True}, "filesystem": "tmpfs",
            "cape_tmpfs_prerequisite_ready": False, "owner_is_cape": False,
            "owner_write_and_execute": True, "free_mib": 9000,
            "required_free_mib": 4096,
        }
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m.socket, "gethostname", return_value="new-host"), \
             patch.object(m, "assess", return_value=first), \
             patch("builtins.input", return_value="DECLINE"), \
             patch.object(m.os, "fchown",
                          side_effect=AssertionError("No mutation")), \
             self.assertRaisesRegex(m.TmpfsBlocked, "denied"):
            m.repair_owner(Path("/unused/conf/cuckoo.conf"))

    def test_refuses_owner_repair_if_capacity_is_insufficient(self):
        first = {
            "configured_tmpfs": {"enabled": True}, "filesystem": "tmpfs",
            "cape_tmpfs_prerequisite_ready": False, "owner_is_cape": False,
            "owner_write_and_execute": True, "free_mib": 500,
            "required_free_mib": 4096,
        }
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m.socket, "gethostname", return_value="new-host"), \
             patch.object(m, "assess", return_value=first), \
             self.assertRaisesRegex(m.TmpfsBlocked, "capacity"):
            m.repair_owner(Path("/unused/conf/cuckoo.conf"))


if __name__ == "__main__":
    unittest.main()
