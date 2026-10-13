"""Mock-only regression of source SSL55 protected storage inventory."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import command1_ssl55_safe_space_audit as m

XML = ("<domain type='kvm'><name>win11</name><devices>"
       "<disk device='disk'><source file="
       "'/var/lib/libvirt/images/win11.1791876230'/></disk>"
       "</devices></domain>")

class SafeSpaceTests(unittest.TestCase):
    def test_real_export_gap_is_only_45_59_gib_not_94_extra(self):
        with tempfile.TemporaryDirectory() as td:
            def mounted(path):
                return {"existing_path":True,"free_gib":48.41,
                        "capacity_gib":400.0,"device_id":42}
            with patch.object(m.os, "geteuid", return_value=0), \
                 patch.object(m.socket, "gethostname",
                              return_value="CSE-SSL-55"), \
                 patch.object(m,"mounted_space",side_effect=mounted), \
                 patch.object(m,"master_disk",return_value={
                     "existing_exporter_needed_free_gib":94.0,
                     "virtual_size_gib":64.0,
                     "backing_chain_layers":3}), \
                 patch.object(m,"directory_scopes",return_value={
                     "apt_package_cache_REVIEW_ONLY":{
                         "allocated_gib":1.2}}):
                result=m.report(mount=td,home=None)
        self.assertEqual(result["missing_free_space_gib"],45.59)
        self.assertEqual(result["files_deleted"],0)
        self.assertEqual(result["bytes_deleted"],0)
        self.assertTrue(result["requires_human_review_before_any_cleanup"])
        self.assertFalse(result["candidate_cleanup_approved"])
        self.assertFalse(result["service_or_vm_modified"])
        self.assertEqual(len(result["PROTECTED_DO_NOT_DELETE"]),7)

    def test_nonroot_and_wrong_machine_denied_before_scanning(self):
        with patch.object(m.os, "geteuid",return_value=1000), \
             patch.object(m,"master_disk",
                          side_effect=AssertionError("No VM query")), \
             self.assertRaisesRegex(m.StorageAuditBlocked,"sudo"):
            m.report()
        with patch.object(m.os, "geteuid", return_value=0), \
             patch.object(m.socket,"gethostname",return_value="otherhost"), \
             patch.object(m,"master_disk",
                          side_effect=AssertionError("No master query")), \
             self.assertRaisesRegex(m.StorageAuditBlocked,"SSL-55"):
            m.report()

    def test_directory_sizes_uses_only_aggregate_du_bytes_and_no_names(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,"process",
                 return_value="5368709120\tPRIVATE_PERSONAL_PATH"):
                value=m.metadata_size(td)
            self.assertEqual(value["allocated_gib"],5.0)
            self.assertNotIn("PRIVATE_PERSONAL_PATH",str(value))
            with patch.object(m,"process",return_value=None):
                no=m.metadata_size(td)
            self.assertIsNone(no["allocated_gib"])
            self.assertIn("timed out",no["note"])

    def test_no_follow_symlink_cache_directories(self):
        with tempfile.TemporaryDirectory() as td:
            location=Path(td)/"link"
            location.symlink_to(Path(td))
            with patch.object(m,"process",
                   side_effect=AssertionError("Do not descend symlink")):
                a=m.metadata_size(location)
            self.assertFalse(a["exists_real_directory"])

    def test_real_master_metadata_from_verified_libvirt_and_qemu(self):
        calls=[]
        def command(argv,timeout=90):
            calls.append(argv)
            if "domstate" in argv:
                return "shut off"
            if "dumpxml" in argv:
                return XML
            if "qemu-img" in argv:
                return json.dumps([
                    {"virtual-size":64*m.GIB,"format":"qcow2"},
                    {"virtual-size":64*m.GIB,"format":"qcow2"},
                    {"virtual-size":64*m.GIB,"format":"qcow2"},
                ])
            raise AssertionError(argv)
        with patch.object(m,"process",side_effect=command):
            doc=m.master_disk()
        self.assertTrue(doc["master_disk_metadata_available"])
        self.assertEqual(doc["backing_chain_layers"],3)
        self.assertEqual(doc["existing_exporter_needed_free_gib"],94)
        self.assertTrue(doc["original_disk_snapshots_TPM_unmodified"])
        self.assertEqual(len(calls),3)
        self.assertNotIn("snapshot-revert",str(calls))

    def test_running_vm_never_scans_live_qcow2(self):
        with patch.object(m,"process",return_value="running") as call:
            data=m.master_disk()
        self.assertFalse(data["master_disk_metadata_available"])
        self.assertEqual(data["observed_state"],"running")
        call.assert_called_once()

    def test_unavailable_vm_metadata_keeps_gap_unknown(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.socket,"gethostname",
                              return_value="CSE-SSL-55"), \
                 patch.object(m,"master_disk",return_value={
                     "master_disk_metadata_available":False}), \
                 patch.object(m,"mounted_space",return_value={
                     "free_gib":48.41}), \
                 patch.object(m,"directory_scopes",return_value={}):
                result=m.report(mount=td)
        self.assertIsNone(result["missing_free_space_gib"])
        self.assertFalse(result["candidate_cleanup_approved"])

    def test_script_has_no_mutation_commands(self):
        script=Path(m.__file__).read_text(encoding="utf-8")
        for expr in (
            "os.unlink(", "shutil.rmtree(", "os.remove(",
            "rm -rf", "apt-get clean", "journalctl --vacuum",
            "snapshot-revert", "virsh destroy", "virsh undefine",
            "rclone delete", "os.system(", "shell=True",
            "write_bytes(", "write_text(", "subprocess.Popen(",
        ):
            self.assertNotIn(expr,script)

if __name__=="__main__":
    unittest.main()
