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


    def test_foreign_overlay_depending_on_clone_is_refused(self):
        clone = self.path
        unrelated = self.path.parent / "unrelated.qcow2"
        unrelated.write_bytes(b"safe synthetic overlay")
        chain = [
            {"filename": str(unrelated), "format": "qcow2",
             "backing-filename": str(clone)},
            {"filename": str(clone), "format": "qcow2"},
        ]
        with self.assertRaisesRegex(
                audit.DiskAdmissionBlocked,
                "reference|dependencies"):
            audit.require_no_foreign_qcow2_backing_reference(
                unrelated, (clone,), self.runner(chain))

    def test_foreign_three_layer_independent_chain(self):
        overlay = self.path.parent / "other-overlay.qcow2"
        base = self.path.parent / "other-base.qcow2"
        overlay.write_bytes(b"unrelated overlay")
        base.write_bytes(b"unrelated base")
        chain = [
            {"filename": str(overlay), "format": "qcow2",
             "backing-filename": str(base)},
            {"filename": str(base), "format": "qcow2"},
        ]
        result = audit.require_no_foreign_qcow2_backing_reference(
            overlay, (self.path,), self.runner(chain))
        self.assertEqual(result["foreign_chain_layers_verified"], 2)
        self.assertTrue(result["foreign_chain_independent_of_owned_clone"])

    def test_foreign_chain_symlink_alias_to_clone_is_refused(self):
        alias = self.path.parent / "alias-target.qcow2"
        alias.symlink_to(self.path)
        overlay = self.path.parent / "overlay.qcow2"
        overlay.write_bytes(b"test overlay")
        chain = [
            {"filename": str(overlay), "backing-filename": str(alias)},
            {"filename": str(alias)},
        ]
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(
                overlay,(self.path,),self.runner(chain))

    def test_foreign_unverifiable_backing_chains_refused(self):
        overlay = self.path.parent / "foreign.qcow2"
        overlay.write_bytes(b"foreign")
        scenarios = (
            [],
            [{"filename": str(overlay), "backing-filename": str(self.path)}],
            [{"filename": "opaque://remote"}],
            [{"filename": str(self.path.parent / "missing.qcow2")}],
            [{"filename": str(overlay)}, {"filename": str(overlay)}],
            "not an array",
        )
        for chain in scenarios:
            with self.subTest(chain=chain), self.assertRaises(
                    audit.DiskAdmissionBlocked):
                audit.require_no_foreign_qcow2_backing_reference(
                    overlay, (self.path,), self.runner(chain))

    def test_foreign_image_failure_or_missing_file_refuses(self):
        overlay = self.path.parent / "foreign.qcow2"
        overlay.write_bytes(b"foreign")
        def fail(*args, **kwargs):
            return SimpleNamespace(returncode=2, stdout="")
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(
                overlay,(self.path,), fail)
        missing = self.path.parent / "missing.qcow2"
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(
                missing,(self.path,),self.runner([]))


if __name__ == "__main__":
    unittest.main()
