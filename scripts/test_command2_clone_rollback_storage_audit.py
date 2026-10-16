"""Synthetic metadata admission tests; never invoke real qemu-img."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

import command2_clone_rollback_storage_audit as audit


class DiskAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "disk.qcow2"
        self.path.write_bytes(b"fixture")
        self.base = {"format": "qcow2", "virtual-size": audit.VIRTUAL_BYTES,
                     "format-specific": {"type": "qcow2", "data": {}}}

    def runner(self, data):
        return lambda *a, **kw: SimpleNamespace(
            returncode=0, stdout=json.dumps(data))

    def test_independent_disk_admitted_without_production_claim(self):
        report = audit.inspect_qcow2(self.path, self.runner(self.base))
        self.assertTrue(report["no_internal_snapshots"])
        self.assertFalse(report["deployment_ready"])
        self.assertFalse(report["tpm_restore_proven"])

    def test_internal_snapshot_or_backing_refused(self):
        cases = [
            {"snapshots": [{"id": "1"}]},
            {"backing-filename": "/another/base.qcow2"},
            {"format": "raw"},
            {"virtual-size": 1024},
            {"encrypted": True},
            {"format-specific": {"type": "qcow2", "data": {
                "data-file": "/another/data"}}},
            {"format-specific": {"type": "qcow2", "data": {
                "has-backing-file": True}}},
            {"format-specific": {"type": "qcow2", "data": {
                "corrupt": True}}},
        ]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(
                    audit.DiskAdmissionBlocked):
                audit.inspect_qcow2(
                    self.path, self.runner({**self.base, **changes}))

    def test_symlink_and_failed_qemu_img_refused(self):
        alias = self.path.parent / "alias.qcow2"
        alias.symlink_to(self.path)
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.inspect_qcow2(alias, self.runner(self.base))
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.inspect_qcow2(self.path, lambda *a, **kw: SimpleNamespace(
                returncode=1, stdout=""))


if __name__ == "__main__":
    unittest.main()
