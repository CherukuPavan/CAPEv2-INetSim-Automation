"""Synthetic CAPE benign running snapshot-revert safety tests (no libvirt)."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_benign_snapshot_revert_gate as gate
import command2_running_cape_snapshot_gate as snap

VM="win11_1"
HOST="approved-host"
UID="3c924f24-8f7b-4592-9455-32a13c3f88a7"
MAC="02:aa:bb:cc:dd:ee"
IP="192.168.240.101"


class RevertTests(unittest.TestCase):
    def test_revert_plan_requires_existing_full_memory_disk_snapshot(self):
        xml=('<domainsnapshot><name>cape_ready_win11_1</name>'
             '<memory snapshot="internal"/><disks>'
             '<disk name="vda" snapshot="internal"/></disks></domainsnapshot>')
        def virsh(*a):
            if a==("snapshot-list",VM,"--name"):return "cape_ready_win11_1"
            if a==("snapshot-dumpxml",VM,"cape_ready_win11_1"):return xml
            raise AssertionError("unexpected "+str(a))
        with patch.object(snap,"virsh",side_effect=virsh):
            self.assertTrue(gate.snapshot_check(VM,"cape_ready_win11_1"))

    def test_snapshot_revert_plan_never_runs_vm_operations(self):
        with patch.object(snap,"target_guard"),\
             patch.object(snap,"saved_xml_checks",return_value="test"),\
             patch.object(snap,"read_receipt",return_value="hash"),\
             patch.object(gate,"snapshot_check",return_value=True),\
             patch.object(snap,"virsh",side_effect=AssertionError("No revert")):
            outcome=gate.plan(VM,HOST,UID,MAC,IP,"/receipt")
        self.assertFalse(outcome["snapshot_reverted"])
        self.assertFalse(outcome["tpm_uefi_revert_verified"])

    def test_disk_only_snapshot_fails(self):
        badxml=('<domainsnapshot><name>cape_ready_win11_1</name>'
                '<memory snapshot="no"/>'
                '<disks><disk snapshot="internal"/></disks></domainsnapshot>')
        def virsh(*a):
            if a[0]=="snapshot-list":return "cape_ready_win11_1"
            return badxml
        with patch.object(snap,"virsh",side_effect=virsh):
            with self.assertRaisesRegex(gate.RevertBlocked,"INTERNAL"):
                gate.snapshot_check(VM,"cape_ready_win11_1")

    def test_reference_host_blocked_before_revert(self):
        with patch.object(snap.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(snap,"virsh",side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(snap.SnapshotBlocked,"REFERENCE_HOST_PROTECTED"):
                gate.revert_benign(VM,"cse-ssl-55",UID,MAC,IP,"/receipt")

    def test_root_or_interactive_required(self):
        with patch.object(snap,"target_guard"),\
             patch.object(gate.os,"geteuid",return_value=1000):
            with self.assertRaisesRegex(gate.RevertBlocked,"Root"):
                gate.revert_benign(VM,HOST,UID,MAC,IP,"/receipt")
        with patch.object(snap,"target_guard"),\
             patch.object(gate.os,"geteuid",return_value=0),\
             patch.object(gate.sys.stdin,"isatty",return_value=False):
            with self.assertRaisesRegex(gate.RevertBlocked,"interactive"):
                gate.revert_benign(VM,HOST,UID,MAC,IP,"/receipt")

    def test_revert_refuses_missing_prior_cold_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt=Path(tmp)/"receipt.json"
            receipt.write_text('{"authorized_benign_revert_test":true}')
            with patch.object(snap,"target_guard"),\
                 patch.object(gate.os,"geteuid",return_value=0),\
                 patch.object(gate.sys.stdin,"isatty",return_value=True),\
                 patch.object(gate,"plan",return_value={
                     "snapshot":"cape_ready_win11_1"}),\
                 patch.object(snap,"virsh",side_effect=AssertionError("No revert")):
                with self.assertRaisesRegex(gate.RevertBlocked,"cold checkpoint"):
                    gate.revert_benign(VM,HOST,UID,MAC,IP,receipt)

    def test_success_mock_revert_does_not_claim_tpm_proven(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt=Path(tmp)/"receipt.json"
            receipt.write_text('{"authorized_benign_revert_test":true,'
                               '"full_cold_checkpoint_restore_tested":true}')
            lock=Path(tmp)/"lock"
            events=[]
            def virsh(*a):
                events.append(a)
                if a[0]=="snapshot-revert":
                    self.assertEqual(a,("snapshot-revert",VM,"cape_ready_win11_1","--running"))
                    return ""
                if a[0]=="domstate":return "running"
                raise AssertionError("Unexpected virsh "+str(a))
            with patch.object(snap,"target_guard"),\
                 patch.object(gate.os,"geteuid",return_value=0),\
                 patch.object(gate.os,"fstat",return_value=type(
                     "RootLock",(),{"st_mode":0o100600,
                                    "st_uid":0,"st_nlink":1})()),\
                 patch.object(gate.sys.stdin,"isatty",return_value=True),\
                 patch.object(gate,"LOCK",lock),\
                 patch("builtins.input",return_value="REVERT-BENIGN-WIN11_1"),\
                 patch.object(gate,"plan",return_value={
                     "snapshot":"cape_ready_win11_1"}),\
                 patch.object(snap,"saved_xml_checks",return_value="OK"),\
                 patch.object(snap,"virsh",side_effect=virsh),\
                 patch.object(gate.probe,"probe_agent",return_value={
                     "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                     "version":"0.22"}):
                result=gate.revert_benign(VM,HOST,UID,MAC,IP,receipt)
            self.assertEqual(result["result"],
                "COMMAND2_BENIGN_RUNNING_SNAPSHOT_REVERT_AGENT_VERIFIED")
            self.assertFalse(result["production_complete"])
            self.assertFalse(result["swtpm_nvram_bitlocker_state_verified_by_guest"])
            self.assertEqual(len([c for c in events if c[0]=="snapshot-revert"]),1)


if __name__=="__main__":
    unittest.main()
