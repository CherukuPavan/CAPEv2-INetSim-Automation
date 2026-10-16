"""Real qemu-img tests using harmless ephemeral QCOW2 images, no VMs.

Run with: PYTHONPATH=scripts python -B -m unittest -v
          test_command2_clone_rollback_real_qemu
QEMU is used only to create benign tiny metadata-only images in tmpfs/temp.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import command2_clone_rollback_storage_audit as audit


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img is unavailable")
class RealQEMUBackingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cape-qcow2-safe-fixture-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.clone = self.root / "owned_clone.qcow2"
        self.unrelated = self.root / "other_base.qcow2"
        self.make_base(self.clone)
        self.make_base(self.unrelated)

    def run_qemu(self, *argv):
        result = subprocess.run(
            ["qemu-img", *argv], capture_output=True, text=True,
            timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def make_base(self, path):
        self.run_qemu("create", "-f", "qcow2", str(path), "8M")

    def make_overlay(self, name, backing):
        overlay = self.root / name
        self.run_qemu(
            "create", "-f", "qcow2", "-F", "qcow2",
            "-b", str(backing), str(overlay))
        return overlay

    def test_actual_qemu_metadata_blocks_foreign_overlay_on_owned_clone(self):
        overlay = self.make_overlay("dependent-overlay.qcow2", self.clone)
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(
                overlay, (self.clone,))

    def test_actual_qemu_metadata_allows_independent_foreign_overlay(self):
        overlay = self.make_overlay("independent-overlay.qcow2", self.unrelated)
        report = audit.require_no_foreign_qcow2_backing_reference(
            overlay, (self.clone,))
        self.assertEqual(report["foreign_chain_layers_verified"], 2)
        self.assertTrue(report["foreign_chain_independent_of_owned_clone"])

    def test_actual_qemu_metadata_detects_transitive_backing_reference(self):
        middle = self.make_overlay("middle.qcow2", self.clone)
        top = self.make_overlay("top.qcow2", middle)
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(top,(self.clone,))

    def test_actual_qemu_symlink_backing_to_owned_clone_refused(self):
        alias = self.root / "alias.qcow2"
        alias.symlink_to(self.clone)
        overlay = self.make_overlay("alias-dependent.qcow2", alias)
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(overlay,(self.clone,))

    def test_actual_qemu_missing_backing_fails_closed(self):
        overlay = self.make_overlay("missing-dependent.qcow2", self.unrelated)
        self.unrelated.unlink()
        with self.assertRaises(audit.DiskAdmissionBlocked):
            audit.require_no_foreign_qcow2_backing_reference(overlay,(self.clone,))


if __name__ == "__main__":
    unittest.main()
