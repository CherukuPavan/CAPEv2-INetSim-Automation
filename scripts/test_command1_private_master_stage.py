"""Synthetic-only Command 1 encrypted Drive -> exact master import stage tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import command1_private_master_stage as m

PLANNED={
    "result":"COMMAND1_EXACT_DRIVE_IMPORT_STAGE_PLAN_ONLY",
    "transfer":{"result":"COMMAND1_PRIVATE_CRYPT_GDRIVE_DOWNLOAD_PLAN_ONLY"},
    "master":"win11",
    "VM_imported":False,
}
DOWNLOADED={
    "result":"COMMAND1_PRIVATE_MASTER_DOWNLOADED_SHA256_VERIFIED",
    "bundle_manifest_sha256":"a"*64,
    "all_member_files_sha256_verified":True,
}
IMPORTED={
    "from_verified_actual_master_bundle":True,
    "master_uuid":"11111111-1111-4111-8111-111111111111",
    "guest_imported_and_off":True,
}

class PrivateMasterStageTests(unittest.TestCase):
    def args(self,td):
        return SimpleNamespace(
            approved_host="other-host",
            crypt_remote="mycrypt",
            bundle_id="cape-master-20261013_abcdef",
            bundle_dir=Path(td)/"cape-master-20261013_abcdef",
            os_disk=Path(td)/"win11.qcow2",
            uefi_vars=Path(td)/"win11-VARS.fd",
            tpm_user="libvirt-qemu",
            rclone_config=Path("/root/.config/rclone/rclone.conf"),
            witness_dir=Path(td)/"witness",
        )

    def test_plan_gates_private_transfer_and_import_targets(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            with patch.object(m,"root_host",return_value="other-host"), \
                 patch.object(m.imported,"approved_target") as files, \
                 patch.object(m.drive,"plan_download",
                              return_value=PLANNED["transfer"]) as crypt:
                output=m.path_plan(args)
            self.assertEqual(files.call_count,2)
            self.assertEqual(output["result"],
                             "COMMAND1_EXACT_DRIVE_IMPORT_STAGE_PLAN_ONLY")
            self.assertFalse(output["host_modified"])
            self.assertFalse(output["final_running_snapshot_created"])
            crypt.assert_called_once_with(
                "other-host",args.bundle_dir,"mycrypt",
                args.bundle_id,args.rclone_config)

    def test_disallow_same_disk_and_uefi_and_bad_tpm_identity(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            args.uefi_vars=args.os_disk
            with patch.object(m,"root_host",return_value="other-host"), \
                 self.assertRaises(m.ExactMasterBlocked):
                m.path_plan(args)
            args=self.args(td)
            args.tpm_user=""
            with patch.object(m,"root_host",return_value="other-host"), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,"swtpm"):
                m.path_plan(args)

    def test_stage_does_not_run_without_root_and_operator_tty(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            with patch.object(m.os,"geteuid",return_value=1000), \
                 patch.object(m,"path_plan",side_effect=AssertionError(
                     "No preflight on nonroot")), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,"interactive"):
                m.stage(args)

    def test_operator_denial_stops_before_bundle_download(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"path_plan",return_value=deepcopy(PLANNED)), \
                 patch("builtins.input",return_value="NO"), \
                 patch.object(m.drive,"apply_download",
                     side_effect=AssertionError("No transfer")), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,"declined"):
                m.stage(args)
            self.assertFalse(args.bundle_dir.exists())

    def test_all_stages_have_separate_checks_before_import(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            milestones=[]
            invoked=[]
            def action(name,ret):
                invoked.append(name)
                return deepcopy(ret)
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"path_plan",return_value=deepcopy(PLANNED)), \
                 patch("builtins.input",return_value=m.APPROVAL), \
                 patch.object(m,"root_host",return_value="other-host"), \
                 patch.object(m,"secure_witness_folder",
                              return_value=args.witness_dir), \
                 patch.object(m,"save_witness",
                              side_effect=lambda path,record,**kw:
                                  milestones.append(deepcopy(record))), \
                 patch.object(m.drive,"apply_download",
                              side_effect=lambda *a: action("download",DOWNLOADED)), \
                 patch.object(m.imported,"check",
                              side_effect=lambda *a: action("import_plan",IMPORTED)), \
                 patch.object(m.imported,"apply",
                              side_effect=lambda *a: action("import_apply",IMPORTED)):
                result=m.stage(args)
            self.assertEqual(invoked,["download","import_plan","import_apply"])
            self.assertEqual(result["result"],
                             "COMMAND1_PRIVATE_DRIVE_MASTER_IMPORTED_SHUT_OFF")
            self.assertFalse(result["master_VM_running_snapshot_created"])
            self.assertFalse(result["fresh_host_CAPE_install_complete"])
            self.assertEqual(milestones[-1]["result"],result["result"])
            self.assertEqual(len(milestones[-1]["completed"]),2)

    def test_refuses_incomplete_master_bundle_proof_before_import(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            records=[]
            no_intent=dict(DOWNLOADED)
            no_intent["all_member_files_sha256_verified"]=False
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"path_plan",return_value=deepcopy(PLANNED)), \
                 patch("builtins.input",return_value=m.APPROVAL), \
                 patch.object(m,"root_host",return_value="other-host"), \
                 patch.object(m,"secure_witness_folder",
                              return_value=args.witness_dir), \
                 patch.object(m,"save_witness",
                              side_effect=lambda path,record,**kw:
                                  records.append(deepcopy(record))), \
                 patch.object(m.drive,"apply_download",return_value=no_intent), \
                 patch.object(m.imported,"apply",
                              side_effect=AssertionError("No import")), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,
                                        "PARTIAL_OR_UNKNOWN"):
                m.stage(args)
            self.assertEqual(records[-1]["result"],
                    "COMMAND1_PRIVATE_MASTER_STAGE_PARTIAL_OR_UNKNOWN")

    def test_failed_import_preserves_partial_verified_download_witness(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            milestones=[]
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"path_plan",return_value=deepcopy(PLANNED)), \
                 patch("builtins.input",return_value=m.APPROVAL), \
                 patch.object(m,"root_host",return_value="other-host"), \
                 patch.object(m,"secure_witness_folder",
                              return_value=args.witness_dir), \
                 patch.object(m,"save_witness",
                              side_effect=lambda path,record,**kw:
                                  milestones.append(deepcopy(record))), \
                 patch.object(m.drive,"apply_download",
                              return_value=DOWNLOADED), \
                 patch.object(m.imported,"check",side_effect=RuntimeError(
                     "SENSITIVE_DO_NOT_STORE")), \
                 patch.object(m.imported,"apply",
                              side_effect=AssertionError("Never import")), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,
                                        "PARTIAL_OR_UNKNOWN"):
                m.stage(args)
            failed=milestones[-1]
            self.assertEqual(failed["result"],
                             "COMMAND1_PRIVATE_MASTER_STAGE_PARTIAL_OR_UNKNOWN")
            self.assertEqual(failed["current"],"stopped_master_import")
            self.assertEqual(failed["completed"][0]["step"],
                             "private_google_drive_download")
            self.assertNotIn("SENSITIVE_DO_NOT_STORE",str(failed))

    def test_preflight_drift_blocks_before_witness_or_import(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            changed=deepcopy(PLANNED)
            changed["transfer"]["result"]="ALTERED_DRIVE_STATE"
            with patch.object(m.os,"geteuid",return_value=0), \
                 patch.object(m.sys.stdin,"isatty",return_value=True), \
                 patch.object(m,"path_plan",side_effect=[
                     deepcopy(PLANNED),changed]), \
                 patch("builtins.input",return_value=m.APPROVAL), \
                 patch.object(m,"save_witness",
                              side_effect=AssertionError("No witness")), \
                 self.assertRaisesRegex(m.ExactMasterBlocked,
                                        "changed after approval"):
                m.stage(args)

    def test_verify_only_checks_original_manifest_and_shutoff_import(self):
        with tempfile.TemporaryDirectory() as td:
            args=self.args(td)
            with patch.object(m,"root_host",return_value="other-host"), \
                 patch.object(m.golden,"manifest_check",
                              return_value={"manifest_sha256":"a"*64}), \
                 patch.object(m.imported,"check",
                              return_value=IMPORTED) as read:
                output=m.verify(args)
            self.assertEqual(output["result"],
                             "COMMAND1_PRIVATE_EXACT_MASTER_STAGED_VERIFIED_ONLY")
            self.assertFalse(output["VM_booted_or_reverted"])
            self.assertFalse(output["CAPE_final_running_snapshot_proven"])
            self.assertTrue(read.call_args.kwargs["staged"])

    def test_no_host_VM_boot_network_or_service_restarts(self):
        source=Path(m.__file__).read_text(encoding="utf-8")
        for forbidden in ("virsh start", "snapshot-revert",
                          "systemctl restart", "iptables -",
                          "shell=True", "os.system("):
            self.assertNotIn(forbidden,source)


if __name__=="__main__":
    unittest.main()
