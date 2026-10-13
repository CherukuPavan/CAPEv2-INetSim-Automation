"""Synthetic-only exact master cold export storage readiness tests."""
from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import command1_actual_master_export_capacity as m

GIB=1024**3
SOURCE={
  "virtual_size":64*GIB,
  "master_shut_off":True,
  "backing_chain":["/private/base.qcow2","/private/top.qcow2"],
  "tpm_members":["tpm2-00.permall","tpm2-00.volatilestate"],
  "source_nvram":Path("/var/lib/libvirt/qemu/nvram/win11.fd"),
}

class ExactSourceCapacityTests(unittest.TestCase):
    def test_64_gib_master_needs_94_gib_not_48_gib(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m,"safe_storage",return_value=root), \
                 patch.object(m.master,"source",return_value=SOURCE), \
                 patch.object(m.shutil,"disk_usage",return_value=SimpleNamespace(
                     free=int(48.41*GIB))), \
                 patch.object(m,"snapshot_metadata",return_value={
                     "afterfull_snapshot_metadata_available":True,
                     "running_state_in_snapshot_verified":True}):
                result=m.plan(root)
        self.assertEqual(result["virtual_disk_size_gib"],64.0)
        self.assertEqual(result["exporter_required_free_space_gib"],94.0)
        self.assertFalse(result["conservative_export_storage_sufficient"])
        self.assertAlmostEqual(result["missing_capacity_gib"],45.59,places=2)
        self.assertFalse(result["source_bundle_exported"])
        self.assertFalse(result["original_master_disk_TPM_or_snapshots_modified"])

    def test_feasible_storage_still_does_not_export_anything(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m,"safe_storage",return_value=root), \
                 patch.object(m.master,"source",return_value=SOURCE), \
                 patch.object(m.shutil,"disk_usage",return_value=SimpleNamespace(
                     free=130*GIB)), \
                 patch.object(m,"snapshot_metadata",return_value={}):
                result=m.plan(root)
        self.assertTrue(result["conservative_export_storage_sufficient"])
        self.assertFalse(result["new_host_import_ready"])

    def test_declines_nonroot_before_reading_private_master(self):
        with patch.object(m.os,"geteuid",return_value=1000), \
             patch.object(m.master,"source",
                          side_effect=AssertionError("No TPM reads")), \
             self.assertRaisesRegex(m.CapacityBlocked,"root"):
            m.plan(Path("/var/backups"))

    def test_snapshot_metadata_checks_running_and_memory_but_not_tpm_restore(self):
        xml=(
            "<domainsnapshot><name>Afterfull</name><state>running</state>"
            "<memory snapshot='internal'/></domainsnapshot>")
        with patch.object(m.master,"virsh",return_value=xml):
            result=m.snapshot_metadata()
        self.assertTrue(result["running_state_in_snapshot_verified"])
        self.assertFalse(result["restore_with_matching_swtpm_state_proven"])
        self.assertFalse(result["cold_flattened_QCOW2_preserves_afterfull_RAM"])
        with patch.object(m.master,"virsh",return_value=xml.replace(
              "<state>running</state>","<state>shutoff</state>")):
            result=m.snapshot_metadata()
        self.assertFalse(result["running_state_in_snapshot_verified"])

    def test_missing_afterfull_metadata_does_not_fake_snapshot(self):
        with patch.object(m.master,"virsh",side_effect=
                          m.master.MasterExportBlocked("missing")):
            result=m.snapshot_metadata()
        self.assertFalse(result["afterfull_snapshot_metadata_available"])
        self.assertFalse(result["running_state_in_snapshot_verified"])

    def test_trusted_storage_parent_required_for_capacity(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"backups"
            folder.mkdir()
            link=Path(td)/"link"
            link.symlink_to(folder)
            with self.assertRaisesRegex(m.CapacityBlocked,"existing"):
                m.safe_storage(link)
            if folder.stat().st_uid!=0:
                with self.assertRaisesRegex(m.CapacityBlocked,"root"):
                    m.safe_storage(folder)
            else:
                folder.chmod(0o777)
                with self.assertRaisesRegex(m.CapacityBlocked,"root"):
                    m.safe_storage(folder)

    def test_source_probe_has_no_capture_or_reset_commands(self):
        source=Path(m.__file__).read_text()
        for banned in ("snapshot-revert","snapshot-create","virsh start",
                       "qemu-img convert","systemctl restart","rclone copy",
                       "write_bytes(","write_text(","os.system(","shell=True"):
            self.assertNotIn(banned,source)

if __name__=="__main__":
    unittest.main()
