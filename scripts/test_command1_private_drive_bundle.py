"""Synthetic-only personal Drive crypt transfer safety / command tests.

Never authenticates Google, transfers a VM, handles real TPM data or modifies
SSL-55. Tests crypt backend admission and root-private transfer semantics.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command1_private_drive_bundle as m

RCLONE = """[mydrive]
type = drive
token = SENSITIVE_OAUTH_NOT_TO_ECHO

[mycrypt]
type = crypt
remote = mydrive:cape-private/master-backups
password = SENSITIVE_OBSCURED_PASSWORD
filename_encryption = standard
directory_name_encryption = true
no_data_encryption = false
pass_bad_blocks = false
"""
PROOF = {"result":"COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED",
         "all_member_files_sha256_verified":True,
         "capture_intent_sha256_verified":True,
         "manifest_sha256":"a"*64,"master_uuid":"some-uuid",
         "windows_volume_bytes":20*1024**3,
         "ready_to_transfer_privately":True}

class PrivateDriveTests(unittest.TestCase):
    def config(self, td, raw=RCLONE):
        src=Path(td)/"rclone.conf"
        src.write_text(raw)
        src.chmod(0o600)
        return src

    def root_owner(self, real):
        return SimpleNamespace(
            st_mode=(stat.S_IFREG | 0o600), st_uid=0, st_nlink=1,
            st_size=real.st_size)

    def test_requires_actual_crypt_wiping_plaintext_and_names_from_drive(self):
        with tempfile.TemporaryDirectory() as td:
            config=self.config(td)
            st=config.stat()
            with patch.object(m.os,"fstat",
                              return_value=self.root_owner(st)):
                info=m.read_crypt_settings(config,"mycrypt")
            self.assertEqual(info["underlying_provider"],
                             "personal_google_drive")
            self.assertTrue(info["crypt_content_and_names_enabled"])
            self.assertTrue(info["raw_drive_upload_prohibited"])
            self.assertNotIn("SENSITIVE",str(info))
            with patch.object(m.os,"fstat",
                              return_value=self.root_owner(st)), \
                 self.assertRaisesRegex(m.TransferBlocked,"CRYPT|crypt"):
                m.read_crypt_settings(config,"mydrive")

    def test_approval_is_bound_to_exact_oauth_and_crypt_configuration_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=self.config(td)
            with patch.object(m.os,"fstat",
                              return_value=self.root_owner(cfg.stat())):
                before=m.read_crypt_settings(cfg,"mycrypt")
            cfg.write_text(RCLONE.replace(
                "SENSITIVE_OAUTH_NOT_TO_ECHO",
                "DIFFERENT_OAUTH_NOT_TO_ECHO"))
            with patch.object(m.os,"fstat",
                              return_value=self.root_owner(cfg.stat())):
                after=m.read_crypt_settings(cfg,"mycrypt")
            self.assertNotEqual(before["rclone_config_sha256"],
                                after["rclone_config_sha256"])
            self.assertEqual(len(after["rclone_config_sha256"]),64)
            self.assertNotIn("OAUTH",str(before))
            self.assertNotIn("OAUTH",str(after))

    def test_blocks_config_that_disables_encryption_or_uses_team_drive(self):
        for raw in (
            RCLONE.replace("no_data_encryption = false",
                           "no_data_encryption = true"),
            RCLONE.replace("filename_encryption = standard",
                           "filename_encryption = off"),
            RCLONE.replace("directory_name_encryption = true",
                           "directory_name_encryption = false"),
            RCLONE.replace("pass_bad_blocks = false",
                           "pass_bad_blocks = true"),
            RCLONE.replace("type = drive","type = local"),
            RCLONE.replace("type = drive",
                           "type = drive\nteam_drive = someone_else"),
            RCLONE.replace("mydrive:cape-private/master-backups",
                           "mydrive:"),
            RCLONE.replace("mydrive:cape-private/master-backups",
                           "mydrive:../../personal-files"),
        ):
            with tempfile.TemporaryDirectory() as td:
                cfg=self.config(td,raw)
                with patch.object(m.os,"fstat",
                      return_value=self.root_owner(cfg.stat())), \
                     self.assertRaises(m.TransferBlocked):
                    m.read_crypt_settings(cfg,"mycrypt")

    def test_rclone_config_requires_root_0600(self):
        with tempfile.TemporaryDirectory() as td:
            config=self.config(td)
            config.chmod(0o644)
            with self.assertRaisesRegex(m.TransferBlocked,"root-owned 0600"):
                m.read_crypt_settings(config,"mycrypt")
            config.chmod(0o600)
            if config.stat().st_uid != 0:
                with self.assertRaisesRegex(m.TransferBlocked,"root-owned"):
                    m.read_crypt_settings(config,"mycrypt")

    def test_remote_names_have_no_shell_or_local_path_expressions(self):
        self.assertEqual(
            m.transfer_remote("mycrypt","cape-master-20261013_abcdef"),
            "mycrypt:cape-master-20261013_abcdef")
        for remote,bundle in (
            ("mydrive:", "cape-master-20261013_abcdef"),
            ("--config", "cape-master-20261013_abcdef"),
            ("mycrypt", "../private"),
            ("mycrypt", "cape-master-../../etc"),
            ("mycrypt", "cape-master-;rm"),
            ("", "cape-master-20261013_abcdef"),
        ):
            with self.subTest(remote=remote,bundle=bundle), \
                 self.assertRaises(m.TransferBlocked):
                m.transfer_remote(remote,bundle)

    def test_host_role_never_downloads_onto_protected_ssl55(self):
        with patch.object(m.socket,"gethostname",
                          return_value="CSE-SSL-55"), \
             self.assertRaisesRegex(m.TransferBlocked,"protected SSL-55"):
            m.verify_host("CSE-SSL-55",upload=False)
        with patch.object(m.socket,"gethostname",
                          return_value="CSE-SSL-55"):
            self.assertEqual(
                m.verify_host("CSE-SSL-55",upload=True),"cse-ssl-55")
        with patch.object(m.socket,"gethostname",return_value="target-host"), \
             self.assertRaisesRegex(m.TransferBlocked,
                                    "approved-host"):
            m.verify_host("other-host",upload=False)

    def test_upload_preflight_byte_manifest_and_private_crypt_only(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/"cape-master-20261013_abcdef"
            src.mkdir()
            with patch.object(m,"verify_host",return_value="ref"), \
                 patch.object(m,"read_crypt_settings",
                              return_value={"crypt_content_and_names_enabled":True}), \
                 patch.object(m.master,"manifest_check",
                              return_value=PROOF) as verified:
                report=m.plan_upload("ref",src,"mycrypt",
                                     Path("/root/rclone.conf"))
            self.assertEqual(report["result"],
                             "COMMAND1_PRIVATE_CRYPT_GDRIVE_UPLOAD_PLAN_ONLY")
            self.assertEqual(report["remote"],
                             "mycrypt:cape-master-20261013_abcdef")
            self.assertFalse(report["Drive_uploaded"])
            self.assertEqual(report["bundle_proof"],PROOF)
            verified.assert_called_once_with(src)

    def test_refuse_legacy_unbound_intent_manifest_for_private_transfer(self):
        with tempfile.TemporaryDirectory() as td:
            src=Path(td)/"cape-master-20261013_abcdef"
            src.mkdir()
            old=dict(PROOF)
            old["all_member_files_sha256_verified"]=False
            with patch.object(m,"verify_host",return_value="ref"), \
                 patch.object(m,"read_crypt_settings",return_value={}), \
                 patch.object(m.master,"manifest_check",return_value=old), \
                 self.assertRaisesRegex(m.TransferBlocked,
                                        "predates SHA256-bound"):
                m.plan_upload("ref",src,"mycrypt",Path("/root/cfg"))

    def test_upload_approval_runs_immutable_crypt_copy_then_full_download_check(self):
        with tempfile.TemporaryDirectory() as td:
            bundle=Path(td)/"cape-master-20261013_abcdef"
            bundle.mkdir()
            commands=[]
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"plan_upload",return_value={
                     "remote":"mycrypt:cape-master-20261013_abcdef"}), \
                 patch("builtins.input",return_value=m.APPROVE_UPLOAD), \
                 patch.object(m,"execute_rclone",
                         side_effect=lambda _conf,*a:
                             commands.append(a)):
                report=m.apply_upload("ref",bundle,"mycrypt",
                                      Path("/root/rclone.conf"))
            self.assertEqual(commands[0][:5],
                             ("copy","--immutable","--transfers","1",
                              "--checkers"))
            self.assertEqual(commands[1][:3],
                             ("check","--download","--one-way"))
            self.assertTrue(report["download_compare_performed"])
            self.assertTrue(report["encrypted_in_remote"])

    def test_declined_upload_never_calls_rclone(self):
        with tempfile.TemporaryDirectory() as td:
            bundle=Path(td)/"cape-master-20261013_abcdef"
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"plan_upload",return_value={"remote":"mycrypt:x"}), \
                 patch("builtins.input",return_value="NO"), \
                 patch.object(m,"execute_rclone",
                              side_effect=AssertionError("no upload")), \
                 self.assertRaisesRegex(m.TransferBlocked,"declined"):
                m.apply_upload("ref",bundle,"mycrypt",
                               Path("/root/rclone.conf"))

    def test_remote_size_requires_valid_nonempty_expected_inventory(self):
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(
             returncode=0,stdout='{"count":6,"bytes":123456789}')):
            self.assertEqual(m.rclone_remote_size(Path("/root/cfg"),
                                                   "mycrypt:bundle"),
                             (6,123456789))
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(
             returncode=0,stdout='{"count":0,"bytes":0}')), \
             self.assertRaisesRegex(m.TransferBlocked,"plausible"):
            m.rclone_remote_size(Path("/root/cfg"),"mycrypt:missing")

    def test_download_must_have_new_root_private_destination_and_space(self):
        with tempfile.TemporaryDirectory() as td:
            dest=Path(td)/"cape-master-20261013_abcdef"
            # CI runner does not own its temp root as UID 0.
            if dest.parent.stat().st_uid != 0:
                with self.assertRaisesRegex(m.TransferBlocked,"root-owned"):
                    m.checked_destination(dest,10000)
            dest.mkdir()
            with self.assertRaisesRegex(m.TransferBlocked,"NEW"):
                m.checked_destination(dest,10000)

    def test_download_success_uses_private_crypt_then_canonical_sha_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/"cape-master-20261013_abcdef"
            commands=[]
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"plan_download",return_value={
                      "expected_file_count":6,
                      "remote":"mycrypt:cape-master-20261013_abcdef"}), \
                 patch("builtins.input",return_value=m.APPROVE_DOWNLOAD), \
                 patch.object(m,"execute_rclone",
                              side_effect=lambda conf,*cmd:
                                  commands.append(cmd)), \
                 patch.object(m.master,"manifest_check",return_value=PROOF), \
                 patch.object(m.Path, "iterdir",
                              return_value=iter(Path(td)/("part"+str(i))
                                                for i in range(6))):
                result=m.apply_download("target",target,"mycrypt",
                                        target.name,Path("/root/rclone.conf"))
            self.assertEqual(commands[0][:5],
                             ("copy","--immutable","--transfers","1",
                              "--checkers"))
            self.assertTrue(result["master_windows_disk_and_tpm_verified"])
            self.assertFalse(result["master_VM_imported"])
            self.assertTrue(target.is_dir())

    def test_failed_download_preserves_private_partial_directory(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/"cape-master-20261013_abcdef"
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"plan_download",return_value={
                     "expected_file_count":6,"remote":"mycrypt:"+target.name}), \
                 patch("builtins.input",return_value=m.APPROVE_DOWNLOAD), \
                 patch.object(m,"execute_rclone",
                      side_effect=m.TransferBlocked("interrupted")), \
                 self.assertRaisesRegex(m.TransferBlocked,
                                       "PARTIAL_OR_UNKNOWN"):
                m.apply_download("target",target,"mycrypt",target.name,
                                 Path("/root/cfg"))
            self.assertTrue(target.is_dir())


if __name__=="__main__":
    unittest.main()
