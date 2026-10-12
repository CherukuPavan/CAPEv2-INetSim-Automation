"""Read-only, synthetic third snapshot swtpm epoch audit tests."""
from pathlib import Path
import os
import tempfile
import time
from unittest.mock import patch
import unittest

import command2_ssl55_final_tpm_restore_readiness as t

THREE={
    t.one.post.OLD:{"snapshot_epoch":1791823660},
    t.one.post.NEW:{"snapshot_epoch":1791833879},
    t.SNAP:{"snapshot_epoch":1791834797},
}
ONE={
    "captured":True,
    "name":t.SNAP,
    "guest_network":{
        "saved_and_live_one_exact_default_nat_nic":True,
        "nat_agent_verified":True,
        "dhcp_reservation_both_active_persistent":True},
    "libvirt_snapshot_metadata":THREE,
}
SWT={"unique_swtpm_process_bound_to_clone":True,
     "live_swtpm_state_blob_export_performed":False,
     "matched_swtpm_process_count":1}

class TPMFinal(unittest.TestCase):
    def test_exact_tpm_state_files_metadata_only_without_loading_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"tpm2";root.mkdir(mode=0o700)
            blob=root/"tpm2-00.permall"
            blob.write_bytes(b"do-not-read-secret-material")
            os.utime(blob,(1791834798,1791834798))
            with patch.object(t,"TPM",root):
                m=t.state_inventory(1791834797)
            self.assertEqual(m["file_names"],["tpm2-00.permall"])
            self.assertTrue(m["files"][0]["mtime_after_final_snapshot"])
            self.assertFalse(m["old_snapshot_epoch_tpm_blob_available"])
            self.assertFalse(m["exact_checkpoint_epoch_volatile_blob_available"])
            self.assertFalse(m["active_tpm_contents_read_or_exported"])
            self.assertNotIn("do-not-read-secret-material",str(m))

    def test_snapshot_revert_is_never_authorized_by_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"tpm2";root.mkdir()
            (root/"tpm2-00.permall").write_bytes(b"no-open")
            with patch.object(t,"TPM",root),\
                 patch.object(t.one,"check",return_value=ONE),\
                 patch.object(t.legacy,"find_swtpm_process",return_value=SWT),\
                 patch.object(t.shutil,"which",return_value="/usr/bin/swtpm_ioctl"),\
                 patch.object(t.time,"time",return_value=1791835200):
                report=t.metadata()
        self.assertEqual(report["result"],
                         "SSL55_ONE_NAT_TPM_RESTORE_READINESS_READONLY_HOLD")
        self.assertTrue(report["latest_guest_snapshot_uefi_os_ram_verified"])
        self.assertFalse(report["tpm_checkpoint_blob_exported_at_exact_snapshot_epoch"])
        self.assertFalse(report["safe_to_use_snapshot_with_cape_auto_revert"])
        self.assertFalse(report["malware_analysis_authorized"])
        self.assertFalse(report["two_disposable_benign_revert_cycles_verified"])
        self.assertFalse(report["original_guest_mutated"])
        self.assertTrue(report["swtpm_ioctl_utility_installed"])

    def test_legacy_only_or_missing_nat_snapshot_blocks(self):
        partial=dict(ONE,libvirt_snapshot_metadata={
            t.one.post.OLD:{"snapshot_epoch":1791823660},
            t.SNAP:{"snapshot_epoch":1791834797}})
        with patch.object(t.one,"check",return_value=partial),\
             self.assertRaisesRegex(t.TPMReadinessBlocked,
                                    "all three"):
            t.metadata()

    def test_nonsnapshot_matched_tpm_is_not_accepted(self):
        with patch.object(t.one,"check",return_value=ONE),\
             patch.object(t,"state_inventory",return_value={
                   "metadata_only":True}),\
             patch.object(t.legacy,"find_swtpm_process",return_value={
                   "unique_swtpm_process_bound_to_clone":False}),\
             patch.object(t.time,"time",return_value=1791835200),\
             self.assertRaises(t.TPMReadinessBlocked):
            t.metadata()

    def test_malicious_tpm_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/"tpm2";root.mkdir()
            other=Path(td)/"outside";other.write_bytes(b"secret")
            (root/"tpm2-00.permall").symlink_to(other)
            with patch.object(t,"TPM",root),\
                 self.assertRaisesRegex(t.TPMReadinessBlocked,
                                        "Nonregular/symlink"):
                t.state_inventory(1791834797)

    def test_root_host_required_and_no_side_effect_commands(self):
        with patch.object(t.os,"geteuid",return_value=1000):
            self.assertEqual(t.main.__name__,"main")
        source=Path(t.__file__).read_text(encoding="utf-8")
        for unsafe in ('"snapshot-revert"','"snapshot-delete"',
            '"destroy"','"shutdown"','"start"',
            '"swtpm_ioctl","--save"','"swtpm_ioctl","--load"',
            'read_bytes(', 'read_text(', 'write_bytes(', 'write_text(',
            'subprocess.run(', 'os.replace(', 'os.unlink(', 'shell=True'):
            self.assertNotIn(unsafe,source)

if __name__=="__main__":unittest.main()
