"""Synthetic-only SSL55->SSL46 SSHFS golden export/crypt upload tests.

No live Windows VM, network, SSH key, Drive OAuth, TPM or filesystem
changes. Never actually mount SSHFS, run qemu-img, transfer or delete.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import json
import tempfile
import unittest
from unittest.mock import patch

import command1_ssl46_sshfs_master_stage as m

FUSE="backupuser@CSE-SSL-46:/home/backupuser/cape-private"
BASENAME="cape-master-SSL55-20261013-test"
SHA="a"*64

class LanStageTests(unittest.TestCase):
    def fixture(self,td):
        root=Path(td)/"cape-ssl46-export"
        root.mkdir(mode=0o700)
        bundle=root/BASENAME
        return root,bundle

    def filesystem(self):
        return {"mount":"/mnt/cape-ssl46-export",
                "source":FUSE,"peer":"cse-ssl-46",
                "fs_type":"fuse.sshfs",
                "root_private_0700":True,
                "free_bytes":340*1024**3}

    def fake_plan(self,root,bundle):
        return {"result":"SSL55_TO_SSL46_REMOTE_GOLDEN_EXPORT_PLAN_ONLY",
                "mount_identity":FUSE,
                "bundle_destination":str(bundle),
                "source_virtual_gib":64.0,
                "min_required_free_gib":94.0}

    def test_remote_plan_uses_340gib_storage_not_ssl55_local(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            with patch.object(m,"protected_source"), \
                 patch.object(m,"path_and_mount",return_value=self.filesystem()), \
                 patch.object(m.golden,"plan",return_value={
                     "result":"COMMAND1_ACTUAL_MASTER_EXPORT_PLAN_ONLY",
                     "master_source_disk_virtual_bytes":64*1024**3}):
                r=m.plan(root,FUSE,bundle,True)
            self.assertEqual(r["min_required_free_gib"],94.0)
            self.assertEqual(r["remote_free_gib"],340.0)
            self.assertFalse(r["will_delete_SSL46_files"])
            self.assertFalse(r["will_modify_original_win11"])
            self.assertTrue(r["remote_private_files_unencrypted_at_rest_until_cleanup"])
            self.assertFalse(r["no_Google_Drive_upload_yet"] is False)

    def test_source_only_ssl55_root_direct_tty(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"):
            m.protected_source()
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.sys.stdin,"isatty",return_value=True), \
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-46"), \
             self.assertRaisesRegex(m.LanStageBlocked,"SSL-55"):
            m.protected_source()

    def test_bundle_must_stay_under_exact_sshfs_mount_no_existing_retries(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            self.assertEqual(m.protected_paths(root,bundle),bundle)
            with self.assertRaises(m.LanStageBlocked):
                m.protected_paths(root,Path(td)/BASENAME)
            with self.assertRaises(m.LanStageBlocked):
                m.protected_paths(root,root/"win11.qcow2")
            bundle.mkdir()
            with patch.object(m,"protected_source"), \
                 patch.object(m,"path_and_mount",return_value=self.filesystem()), \
                 self.assertRaisesRegex(m.LanStageBlocked,"never overwrite"):
                m.plan(root,FUSE,bundle,True)

    def test_unapproved_sshfs_peer_string_does_not_pass_syntax(self):
        for illegal in (
            "backupuser@localhost:/home/backupuser/cape-private",
            "backupuser@CSE-SSL-55:/home/backupuser/cape-private",
            "backupuser@CSE-SSL-46:/../etc",
            "backupuser@CSE-SSL-46:relative",
            "backupuser@CSE-SSL-46:/home/b;touch",
        ):
            with self.subTest(source=illegal),tempfile.TemporaryDirectory() as td:
                root,bundle=self.fixture(td)
                if "localhost" in illegal or "CSE-SSL-55" in illegal:
                    # Valid syntax but wrong source identity.
                    pass
                with patch.object(m.subprocess,"run",
                     return_value=SimpleNamespace(
                         returncode=0,stdout=json.dumps({
                         "filesystems":[{"source":FUSE,
                         "target":str(root),"fstype":"fuse.sshfs"}]}))), \
                     patch.object(Path,"stat",autospec=True) as st:
                    st.return_value=SimpleNamespace(st_uid=0,st_mode=0o40700)
                    with self.assertRaises(m.LanStageBlocked):
                        m.path_and_mount(root,illegal)

    def test_sshfs_must_be_verified_actual_fuse_peer_not_local_disk(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            cases=[
                {"source":FUSE,"target":str(root),"fstype":"ext4"},
                {"source":"attacker@CSE-SSL-46:/other",
                 "target":str(root),"fstype":"fuse.sshfs"},
                {"source":FUSE,"target":"/mnt/different","fstype":"fuse.sshfs"},
            ]
            for row in cases:
                with self.subTest(row=row), \
                     patch.object(m.subprocess,"run",
                       return_value=SimpleNamespace(returncode=0,
                         stdout=json.dumps({"filesystems":[row]}))), \
                     self.assertRaises(m.LanStageBlocked):
                    m.path_and_mount(root,FUSE)

    def test_successful_remote_export_delegates_only_to_existing_guarded_source(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            before=self.fake_plan(root,bundle)
            after={"result":"SSL46_GOLDEN_BUNDLE_SHA256_VERIFIED_OVER_SSHFS",
                   "mount_identity":FUSE,
                   "master_proof":{"manifest_sha256":SHA}}
            steps=[]
            def delegated_capture(path):
                steps.append(("existing_cold_export",str(path)))
                return {"all_member_files_sha256_verified":True}
            with patch.object(m,"plan",side_effect=[before,before,after]), \
                 patch("builtins.input",return_value=m.APPROVAL), \
                 patch.object(m.golden,"capture",side_effect=delegated_capture):
                result=m.export(root,FUSE,bundle)
            self.assertEqual(steps,[("existing_cold_export",str(bundle))])
            self.assertEqual(result["result"],
                             "SSL55_TO_SSL46_MASTER_EXPORT_SHA256_VERIFIED")
            self.assertFalse(result["SSL46_automatic_deletion"])
            self.assertFalse(result["Google_Drive_uploaded"])

    def test_export_denied_never_starts_conversion(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            with patch.object(m,"plan",return_value=self.fake_plan(root,bundle)), \
                 patch("builtins.input",return_value="NO"), \
                 patch.object(m.golden,"capture",
                     side_effect=AssertionError("No guest copy")), \
                 self.assertRaisesRegex(m.LanStageBlocked,"declined"):
                m.export(root,FUSE,bundle)

    def test_upload_from_sshfs_uses_ssl55_root_crypt_and_complete_remote_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            checked={"result":"SSL46_GOLDEN_BUNDLE_SHA256_VERIFIED_OVER_SSHFS",
                     "master_proof":{"manifest_sha256":SHA}}
            with patch.object(m,"plan",return_value=checked), \
                 patch.object(m.drive,"apply_upload",return_value={
                     "result":"COMMAND1_PRIVATE_CRYPT_GDRIVE_UPLOAD_CHECKED",
                     "download_compare_performed":True}) as upload:
                doc=m.upload(root,FUSE,bundle,"cape_crypt",
                             Path("/root/.config/rclone/rclone.conf"))
            upload.assert_called_once_with("CSE-SSL-55",bundle,"cape_crypt",
                               Path("/root/.config/rclone/rclone.conf"))
            self.assertTrue(doc["remote_bytes_compared"])
            self.assertTrue(doc["no_SSL46_files_deleted"])

    def test_no_upload_to_raw_drive_even_when_remote_is_supported_elsewhere(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle=self.fixture(td)
            with patch.object(m,"plan",return_value={"master_proof":{
                 "manifest_sha256":SHA}}), \
                 patch.object(m.drive,"apply_upload",
                     side_effect=AssertionError("No plaintext")) ,\
                 self.assertRaisesRegex(m.LanStageBlocked,"cape_crypt"):
                m.upload(root,FUSE,bundle,"cape_drive",Path("/root/rclone.conf"))

    def test_script_contains_no_deletion_mount_restart_or_vm_mutation(self):
        src=Path(m.__file__).read_text()
        for forbidden in (
            "rm -rf","rmtree(","unlink(","os.remove(",
            "snapshot-revert","snapshot-delete","virsh destroy",
            "virsh undefine","mount -t","systemctl restart",
            "rclone delete","shell=True","os.system(",
            "write_bytes(","write_text(",
        ):
            self.assertNotIn(forbidden,src)

if __name__=="__main__":
    unittest.main()
