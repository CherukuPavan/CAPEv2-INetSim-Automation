"""Synthetic-only same-day host/source inventory tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import command123_readonly_machine_report as m

XML=(
  "<domain type='kvm'><name>win11</name>"
  "<os><nvram>/var/lib/libvirt/qemu/nvram/win11.fd</nvram></os>"
  "<devices><disk device='disk'><source file='/vm/win11.qcow2'/>"
  "</disk><tpm><backend type='emulator' version='2.0'/></tpm>"
  "</devices></domain>"
)

class MachineReportTests(unittest.TestCase):
    def test_source_known_cold_master_reports_only_sanitized_metadata(self):
        def fake(*args,**kw):
            if "domstate" in args: return {"ok":True,"stdout":"shut off\n"}
            if "snapshot-list" in args:
                return {"ok":True,"stdout":"Afterfull\n"}
            if "dumpxml" in args:
                return {"ok":True,"stdout":XML}
            if "qemu-img" in args:
                return {"ok":True,"stdout":json.dumps({
                    "virtual-size":64*m.GIB,"format":"qcow2",
                    "backing-filename":"/vm/base.qcow2"})}
            raise AssertionError(args)
        with patch.object(m,"call",side_effect=fake), \
             patch.object(m.shutil,"which",return_value="/usr/bin/qemu-img"):
            output=m.source_master()
        self.assertTrue(output["safe_for_cold_export"])
        self.assertEqual(output["virtual_disk_gib"],64)
        self.assertEqual(output["conservative_free_space_needed_gib"],94)
        self.assertTrue(output["backing_image_present"])
        self.assertEqual(output["snapshot_names"],["Afterfull"])
        self.assertFalse(output["source_vm_modified"])

    def test_live_master_and_permission_errors_are_not_export_ready(self):
        with patch.object(m,"call",return_value={
            "ok":True,"stdout":"running\n"}):
            x=m.source_master()
        self.assertFalse(x["safe_for_cold_export"])
        with patch.object(m,"call",return_value={
            "ok":False,"error":"permission denied"}):
            x=m.source_master()
        self.assertEqual(x["libvirt_master_query"],"BLOCKED_OR_MISSING")

    def test_source_and_target_reports_never_modify_host(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,"source_master",return_value={
                  "conservative_free_space_needed_gib":500}), \
                 patch.object(m,"pkg_binary_status",return_value={}), \
                 patch.object(m,"os_release",return_value={
                     "ID":"ubuntu","VERSION_ID":"24.04"}):
                a=m.run("source",td)
            self.assertFalse(a["host_modified"])
            self.assertFalse(a["physical_integration_accepted"])
            self.assertEqual(a["conservative_export_space_check"],
                             "INSUFFICIENT_LOCAL_EXPORT_SPACE_USE_APPROVED_EXTERNAL_DRIVE")
            with patch.object(m,"target",return_value={
                  "dev_kvm_present":False}), \
                 patch.object(m,"pkg_binary_status",return_value={}):
                b=m.run("target",td)
            self.assertFalse(b["Windows_VMs_started_or_reverted"])
            self.assertFalse(b["ready_to_run_fresh_host_install"])

    def test_only_absolute_existing_directory_storage_is_accepted(self):
        self.assertFalse(m.capacity(Path("relative")).get("ok"))
        self.assertFalse(m.capacity(Path("/nonexistent-8c1e47")).get("ok"))
        with tempfile.TemporaryDirectory() as td:
            a=m.capacity(Path(td))
            self.assertTrue(a["ok"])
            self.assertGreater(a["total_gib"],0)

    def test_diagnostic_does_not_read_or_output_credentials(self):
        script=Path(m.__file__).read_text(encoding="utf-8")
        for banned in ("rclone.conf", "oauth_token", "crypt_password",
                       "snapshot-revert", "virsh start", "systemctl restart",
                       "subprocess.Popen(", "shell=True", "os.system(",
                       "write_bytes(", "write_text("):
            self.assertNotIn(banned,script)


if __name__=="__main__":
    unittest.main()
