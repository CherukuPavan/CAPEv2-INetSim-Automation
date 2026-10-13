"""Offline SSL55 exact host/deep master fingerprint safety regression."""
from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import patch
import command1_ssl55_deep_fingerprint as m

class DeepReferenceTests(unittest.TestCase):
    def test_must_be_protected_source_hostname_and_root(self):
        with patch.object(m.os,"geteuid",return_value=1000), \
             patch.object(m,"cape_revision",
                          side_effect=AssertionError("Do not inspect")) ,\
             self.assertRaisesRegex(m.FingerprintBlocked,"Root"):
            m.run(Path("/var/backups"))
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.socket,"gethostname",return_value="other-host"), \
             self.assertRaisesRegex(m.FingerprintBlocked,"restricted"):
            m.run(Path("/var/backups"))

    def test_actual_binary_path_metadata_does_not_claim_dpkg_missing_is_not_installed(self):
        with patch.object(m.shutil,"which",side_effect=lambda x:
            "/usr/local/bin/"+x if x in ("virsh","qemu-img") else None), \
             patch.object(m,"safe_readonly",return_value=None):
            rows=m.read_binary_facts()
        self.assertTrue(rows["virsh"]["discoverable_on_root_path"])
        self.assertEqual(rows["virsh"]["package_provenance"],
                         "possibly_local_build")
        self.assertFalse(rows["inetsim"]["discoverable_on_root_path"])

    def test_cape_git_probe_uses_commit_only_never_status(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"CAPE"
            folder.mkdir()
            (folder/".git").mkdir()
            calls=[]
            def git(argv,seconds=15):
                calls.append(argv)
                return "a"*40
            with patch.object(m,"CAPE",folder), \
                 patch.object(m,"safe_readonly",side_effect=git):
                repo=m.cape_revision()
            self.assertEqual(repo["git_commit_sha40"],"a"*40)
            self.assertTrue(repo["uncommitted_changes_not_assessed"])
            self.assertEqual(len(calls),1)
            self.assertNotIn("status"," ".join(calls[0]))

    def test_root_rclone_config_reports_metadata_only(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=Path(td)/"rclone.conf"
            cfg.write_text("password = VERY_SECRET_DO_NOT_ECHO")
            cfg.chmod(0o600)
            with patch.object(m,"CONFIG",cfg):
                info=m.root_crypt_config_status()
            self.assertNotIn("VERY_SECRET_DO_NOT_ECHO",str(info))
            self.assertTrue(info["root_rclone_config_exists"])
            self.assertIsNone(info["root_crypt_remote_configured"])
            if os.geteuid()!=0:
                self.assertFalse(info["config_metadata_root_0600"])

    def test_failed_master_capacity_preserves_detail_error_type_without_secrets(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"), \
             patch.object(m,"cape_revision",return_value={}), \
             patch.object(m,"read_binary_facts",return_value={}), \
             patch.object(m,"inetsim_presence",return_value={}), \
             patch.object(m,"root_crypt_config_status",return_value={}), \
             patch.object(m.capacity,"plan",
                          side_effect=RuntimeError("PRIVATE TPM PATH")):
            report=m.run(Path("/var/backups"))
        self.assertEqual(report["source_master_capacity"]["error_type"],
                         "RuntimeError")
        self.assertNotIn("PRIVATE TPM PATH",str(report))
        self.assertFalse(report["files_or_systemd_services_modified"])

    def test_actual_capacity_keeps_same_gib_values_from_source_planner(self):
        with patch.object(m.os,"geteuid",return_value=0), \
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"), \
             patch.object(m,"cape_revision",return_value={
                 "git_commit_sha40":"a"*40}), \
             patch.object(m,"read_binary_facts",return_value={
                 "virsh":{"path":"/usr/local/bin/virsh"}}), \
             patch.object(m,"inetsim_presence",return_value={
                 "inetsim_binary_discoverable":False}), \
             patch.object(m,"root_crypt_config_status",return_value={}), \
             patch.object(m.capacity,"plan",return_value={
                 "virtual_disk_size_gib":64.0,
                 "exporter_required_free_space_gib":94.0,
                 "current_available_gib":48.41,
                 "conservative_export_storage_sufficient":False}):
            report=m.run(Path("/var/backups"))
        self.assertFalse(report["source_master_capacity"][
            "conservative_export_storage_sufficient"])
        self.assertFalse(report["guest_started_or_reverted"])
        self.assertFalse(report["source_disk_or_TPM_file_contents_emitted"])

    def test_never_copies_tokens_or_restarts_source(self):
        script=Path(m.__file__).read_text()
        for banned in ("git status","rclone config show","sudo rclone config",
                       "snapshot-revert","virsh start","systemctl restart",
                       "qemu-img convert","write_bytes(","write_text(",
                       "shell=True","os.system("):
            self.assertNotIn(banned,script)

if __name__=="__main__":
    unittest.main()
