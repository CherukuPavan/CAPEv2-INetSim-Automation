"""Synthetic-only persistent CAPE tmpfs installer admission and unit tests."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command1_cape_tmpfs_mount as m

CONFIG = {"enabled": True, "path": "/mnt/tmpfs",
          "minimum_free_mib": 4096}


class FreshHostTmpfsTests(unittest.TestCase):
    def test_uses_each_hosts_ram_and_uid_not_ssl55_literals(self):
        self.assertEqual(m.choose_size(63981, 53114, 4096), 15995)
        self.assertEqual(m.choose_size(32768, 24000, 4096), 8192)
        self.assertIn(b"uid=550", m.unit_content(550, 660, 8192))
        self.assertIn(b"gid=660", m.unit_content(550, 660, 8192))
        self.assertIn(b"size=8192M", m.unit_content(550, 660, 8192))
        self.assertNotIn(b"uid=995", m.unit_content(550, 660, 8192))
        self.assertIn(b"RequiresMountsFor=/mnt/tmpfs", m.dropin_content())
        with self.assertRaises(m.ProvisionBlocked):
            m.choose_size(8192, 6000, 4096)

    def test_never_duplicates_existing_active_fstab_mount(self):
        self.assertTrue(m.no_mount_definition(
            b"# ignored entry\nUUID=dummy /data ext4 defaults 0 2\n"))
        with self.assertRaisesRegex(m.ProvisionBlocked, "fstab entry"):
            m.no_mount_definition(b"tmpfs /mnt/tmpfs tmpfs defaults 0 0\n")
        with self.assertRaisesRegex(m.ProvisionBlocked, "Malformed"):
            m.no_mount_definition(b"incomplete active entry\n")

    def test_wrong_hostname_or_ssl55_rejected(self):
        with self.assertRaisesRegex(m.ProvisionBlocked, "Protected SSL-55"):
            m.approved_host("CSE-SSL-55", "CSE-SSL-55")
        with self.assertRaisesRegex(m.ProvisionBlocked, "unapproved"):
            m.approved_host("newhost", "otherhost")
        self.assertEqual(m.approved_host("host12.example.org", "host12"), "host12")

    def test_synthetic_plan_is_readonly_and_uses_different_uid(self):
        with tempfile.TemporaryDirectory() as td:
            fstab = Path(td) / "fstab"
            fstab.write_text("UUID=abc / ext4 defaults 0 1\n")
            install = Path(td) / "units"
            install.mkdir()
            mountroot = Path(td) / "mounts"
            mountroot.mkdir()
            unit = install / "mnt-tmpfs.mount"
            drop = install / "cape.service.d" / "90-require-tmpfs.conf"
            path = mountroot / "tmpfs"
            with patch.object(m, "FSTAB", fstab), \
                 patch.object(m, "MOUNT_UNIT", unit), \
                 patch.object(m, "SERVICE_DROPIN", drop), \
                 patch.object(m, "MOUNT_POINT", path), \
                 patch.object(m.tmpfs, "EXPECTED", path), \
                 patch.object(m.tmpfs, "config", return_value=(
                     CONFIG, "fake-config-sha")), \
                 patch.object(m.tmpfs, "cape_ids",
                              return_value=(550, 660)), \
                 patch.object(m.tmpfs, "mount_fstype", return_value=None), \
                 patch.object(m, "available_mib",
                              return_value=(32768, 24000)), \
                 patch.object(m.socket, "gethostname", return_value="newhost"):
                report = m.plan(Path("/fake/conf/cuckoo.conf"), "newhost")
            self.assertFalse(report["host_modified"])
            self.assertFalse(report["cape_service_restarted"])
            self.assertEqual(report["cape_uid"], 550)
            self.assertEqual(report["cape_gid"], 660)
            self.assertEqual(report["chosen_mount_size_mib"], 8192)
            self.assertFalse(path.exists())
            self.assertFalse(unit.exists())
            self.assertFalse(drop.exists())

    def test_apply_rejects_nonroot_before_any_preflight(self):
        with patch.object(m.os, "geteuid", return_value=1001), \
             patch.object(m, "plan",
                          side_effect=AssertionError("No host reads")), \
             self.assertRaisesRegex(m.ProvisionBlocked, "root"):
            m.apply(Path("/fake/conf/cuckoo.conf"), "newhost")

    def test_operator_refusal_does_not_touch_mount_or_units(self):
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.sys.stdin, "isatty", return_value=True), \
             patch.object(m, "plan", return_value={
                 "approved_host": "newhost"}), \
             patch("builtins.input", return_value="NO"), \
             patch.object(m, "systemctl",
                          side_effect=AssertionError("No systemctl")), \
             self.assertRaisesRegex(m.ProvisionBlocked, "refused"):
            m.apply(Path("/fake/conf/cuckoo.conf"), "newhost")

    def test_apply_writes_one_unit_and_dependency_without_restarting_cape(self):
        with tempfile.TemporaryDirectory() as td:
            install = Path(td) / "units"
            install.mkdir()
            mounts = Path(td) / "mounts"
            mounts.mkdir()
            unit = install / "mnt-tmpfs.mount"
            drop = install / "cape.service.d" / "90-require-tmpfs.conf"
            path = mounts / "tmpfs"
            report = {
                "approved_host": "newhost", "cape_uid": 500,
                "cape_gid": 600, "chosen_mount_size_mib": 8192,
            }
            called = []
            def fake_mount(*args):
                called.append(args)
            ready = {"cape_tmpfs_prerequisite_ready": True,
                     "filesystem": "tmpfs", "free_mib": 8120}
            with patch.object(m, "MOUNT_UNIT", unit), \
                 patch.object(m, "SERVICE_DROPIN", drop), \
                 patch.object(m, "MOUNT_POINT", path), \
                 patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(m, "plan", return_value=report), \
                 patch("builtins.input", return_value=m.APPROVAL), \
                 patch.object(m.subprocess, "run",
                              return_value=SimpleNamespace(stdout="inactive")), \
                 patch.object(m, "systemctl", side_effect=fake_mount), \
                 patch.object(m.tmpfs, "assess", return_value=ready):
                result = m.apply(Path("/fake/conf/cuckoo.conf"), "newhost")
            self.assertEqual(called, [
                ("daemon-reload",), ("enable", "--now", "mnt-tmpfs.mount")])
            self.assertEqual(result["result"],
                             "CAPE_PERSISTENT_TMPFS_MOUNT_CONFIGURED_NO_RESTART")
            self.assertTrue(path.is_dir())
            self.assertIn(b"size=8192M", unit.read_bytes())
            self.assertIn(b"uid=500,gid=600", unit.read_bytes())
            self.assertIn(b"RequiresMountsFor=/mnt/tmpfs", drop.read_bytes())
            self.assertEqual(stat.S_IMODE(unit.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(drop.stat().st_mode), 0o644)
            self.assertFalse(result["cape_service_restarted"])
            self.assertFalse(result["reboot_persistence_verified"])

    def test_failed_mount_leaves_explicit_partial_or_unknown_for_review(self):
        with tempfile.TemporaryDirectory() as td:
            units = Path(td) / "units"
            units.mkdir()
            mounts = Path(td) / "mounts"
            mounts.mkdir()
            unit = units / "mnt-tmpfs.mount"
            drop = units / "cape.service.d" / "90-require-tmpfs.conf"
            path = mounts / "tmpfs"
            report = {"approved_host": "newhost", "cape_uid": 500,
                      "cape_gid": 600, "chosen_mount_size_mib": 8192}
            def interrupted(*args):
                if args[0] == "enable":
                    raise OSError("simulated mount fail")
            with patch.object(m, "MOUNT_UNIT", unit), \
                 patch.object(m, "SERVICE_DROPIN", drop), \
                 patch.object(m, "MOUNT_POINT", path), \
                 patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.sys.stdin, "isatty", return_value=True), \
                 patch.object(m, "plan", return_value=report), \
                 patch("builtins.input", return_value=m.APPROVAL), \
                 patch.object(m.subprocess, "run",
                              return_value=SimpleNamespace(stdout="inactive")), \
                 patch.object(m, "systemctl", side_effect=interrupted), \
                 self.assertRaisesRegex(m.ProvisionBlocked,
                                        "PARTIAL_OR_UNKNOWN"):
                m.apply(Path("/fake/conf/cuckoo.conf"), "newhost")
            self.assertTrue(unit.exists())
            self.assertTrue(drop.exists())
            self.assertTrue(path.exists())

    def test_never_generates_restart_or_route_or_vm_commands(self):
        src = Path(m.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "systemctl restart", "snapshot-revert", "virsh start",
            "iptables -", "rm -rf", "os.system(", "shell=True",
        ):
            self.assertNotIn(forbidden, src)


if __name__ == "__main__":
    unittest.main()
