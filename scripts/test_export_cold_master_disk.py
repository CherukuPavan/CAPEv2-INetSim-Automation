#!/usr/bin/env python3
"""Offline unit tests for cold QCOW2 disk export preflight."""
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import export_cold_master_disk as exp


TOP="/lab/win11.final"
BASE="/lab/win11.base"
DOMAIN="""<domain><devices><disk type='file' device='disk'>
<driver type='qcow2'/><source file='/lab/win11.final'/>
<target dev='sda'/></disk></devices></domain>"""
COLD="""<domainsnapshot><name>cold</name><state>shutoff</state>
<memory snapshot='no'/><disks><disk name='sda' snapshot='external'>
<source file='/lab/win11.final'/></disk></disks></domainsnapshot>"""
RUNNING=COLD.replace('shutoff', 'running').replace('snapshot=\'no\'', "snapshot='external'")


class SourceTests(unittest.TestCase):
    def run_snapshot(self, snapshot):
        def virsh(*args):
            if args[0] == "domstate":
                return "shut off"
            if args[0] == "snapshot-current":
                return "cold"
            if args[0] == "dumpxml":
                return DOMAIN
            if args[0] == "snapshot-dumpxml":
                return snapshot
            raise RuntimeError("Unexpected virsh method")
        data = [{"filename": TOP, "format": "qcow2",
                 "backing-filename": BASE, "virtual-size": 64*1024**3},
                {"filename": BASE, "format": "qcow2", "virtual-size": 64*1024**3}]
        with patch.object(exp, "virsh", side_effect=virsh), \
             patch.object(exp, "cmd", return_value=json.dumps(data)), \
             patch.object(exp.guard, "check_path"):
            return exp.source_state("win11", "cold")

    def test_cold_snapshot_chain(self):
        top, names, size = self.run_snapshot(COLD)
        self.assertEqual(names, [TOP, BASE])
        self.assertEqual(size, 64*1024**3)

    def test_running_snapshot_is_refused(self):
        with self.assertRaisesRegex(exp.ExportError, "shut-off"):
            self.run_snapshot(RUNNING)

    def test_memory_snap_refused(self):
        altered = COLD.replace("snapshot='no'", "snapshot='external'")
        with self.assertRaisesRegex(exp.ExportError, "RAM"):
            self.run_snapshot(altered)

    def test_parent_mismatch_refused(self):
        altered = COLD.replace("/lab/win11.final", "/lab/not-same")
        with self.assertRaisesRegex(exp.ExportError, "differs"):
            self.run_snapshot(altered)

    def test_unsafe_vm_name(self):
        with self.assertRaisesRegex(exp.ExportError, "safe"):
            exp.source_state("win11;bad", "cold")

    def test_master_must_be_shut_off(self):
        with patch.object(exp, "virsh", return_value="running"):
            with self.assertRaisesRegex(exp.ExportError, "shut off"):
                exp.source_state("win11", "cold")


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_existing_destination_refused(self):
        path = self.root / "clone.qcow2"
        path.write_bytes(b"old")
        with self.assertRaisesRegex(exp.ExportError, "already exists"):
            exp.check_destination(path, [TOP, BASE], 1024)

    def test_relative_destination_refused(self):
        with self.assertRaisesRegex(exp.ExportError, "absolute"):
            exp.check_destination(Path("clone.qcow2"), [TOP, BASE], 1024)

    def test_symlink_destination_refused(self):
        target = self.root / "real"
        target.write_text("x")
        link = self.root / "clone.qcow2"
        link.symlink_to(target)
        with self.assertRaisesRegex(exp.ExportError, "already exists"):
            exp.check_destination(link, [TOP, BASE], 1024)

    def test_export_plan_never_uses_qemu_img_convert(self):
        with patch.object(exp.os, "geteuid", return_value=0), \
             patch.object(exp, "LOCK_PATH", self.root / "lock"), \
             patch.object(exp, "source_state", return_value=(TOP, [TOP, BASE], 1024)), \
             patch.object(exp, "fingerprint", return_value=[]), \
             patch.object(exp, "check_destination", return_value={
                 "available_bytes": 10**12,
                 "conservative_required_bytes": 10**11}), \
             patch.object(exp, "cmd") as calls:
            result = exp.export("win11", "cold", self.root / "clone.qcow2", True)
            self.assertFalse(result["executed"])
            self.assertFalse((self.root / "clone.qcow2").exists())
            self.assertFalse((self.root / "lock").exists())
            calls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
