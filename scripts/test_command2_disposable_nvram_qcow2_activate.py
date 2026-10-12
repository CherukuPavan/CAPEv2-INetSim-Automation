"""Offline checks for isolated second-host OVMF XML transition staging."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import command2_disposable_nvram_qcow2_activate as a

HOST="second-kvm-lab"
VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
def domain(raw):
    return (f'<domain type="kvm"><name>{VM}</name><uuid>{UID}</uuid>'
            '<os><loader type="pflash">/usr/share/OVMF/OVMF_CODE.fd</loader>'
            f'<nvram format="raw">{raw}</nvram></os><devices>'
            '<disk device="disk"><source file="/tmp/win11_1.command2.qcow2"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '<interface type="network"><mac address="02:00:01:02:03:04"/>'
            '<source network="cape-analysis-isolated"/></interface>'
            '</devices></domain>')

class ConversionActivation(unittest.TestCase):
    def fixture(self,temp):
        home=Path(temp);home.chmod(0o700)
        raw=home/(VM+".command2_VARS.fd")
        raw.write_bytes(b"PRIVATE_TEST_FIRMWARE")
        raw.chmod(0o600)
        qc=Path(str(raw)+".qcow2")
        qc.write_bytes(b"SYNTHETIC_QCOW2_METADATA_TEST_ONLY")
        qc.chmod(0o600)
        return home,raw,qc

    def guarded_plan(self,temp,guest_network="cape-analysis-isolated",
                     snapshot="",has_sidecar=True):
        root,raw,qc=self.fixture(temp)
        if not has_sidecar:qc.unlink()
        seen=[]
        def mockvirsh(*args):
            seen.append(args)
            if args==("domuuid",VM):return UID
            if args==("domstate",VM):return "shut off"
            if args==("snapshot-list",VM,"--name"):return snapshot
            if args==("dumpxml","--inactive",VM):
                return domain(raw).replace("cape-analysis-isolated",guest_network)
            self.fail("Unsafe unexpected libvirt operation "+str(args))
        def cmd(*args,**kw):
            self.assertEqual(args[0],"qemu-img")
            if args[1]=="info":return json.dumps({"format":"qcow2",
                                      "virtual-size":len(raw.read_bytes())})
            if args[1]=="compare":return ""
            self.fail("Unexpected command "+str(args))
        real_stat=Path.stat
        def mockstat(item,*args,**kwargs):
            st=real_stat(item,*args,**kwargs)
            if item==root:
                fields=list(st)
                fields[4]=0
                return os.stat_result(fields)
            return st
        with patch.object(Path,"stat",mockstat),\
             patch.object(a.prep,"hostname_guard"),\
             patch.object(a.prep.cold,"inspect",return_value={
                 "manifest_sha256":"a"*64}),\
             patch.object(a,"inspect_witness",return_value="witnesssha"),\
             patch.object(a,"virsh",side_effect=mockvirsh),\
             patch.object(a,"run",side_effect=cmd):
            result=a.plan(HOST,VM,UID,root/"recovery","a"*64,
                          root/"witness.json",root)
        self.assertTrue(all(v[0]!="define" for v in seen))
        return result

    def test_only_proposed_xml_change_and_originals_untouched(self):
        with TemporaryDirectory() as td:
            out=self.guarded_plan(td)
            raw=Path(out["old_nvram_path"]); side=Path(out["new_nvram_path"])
            self.assertEqual(raw.read_bytes(),b"PRIVATE_TEST_FIRMWARE")
            self.assertTrue(side.exists())
        self.assertEqual(out["result"],"COMMAND2_DISPOSABLE_QCOW2_NVRAM_XML_PLAN_ONLY")
        self.assertFalse(out["snapshot_created"])
        self.assertFalse(out["xml_changed"])
        self.assertFalse(out["tpm_state_changed"])

    def test_missing_sidecar_or_nat_nic_blocks_transition(self):
        with TemporaryDirectory() as td, self.assertRaisesRegex(
             a.ActivateBlocked,"sidecar"):
            self.guarded_plan(td,has_sidecar=False)
        with TemporaryDirectory() as td,self.assertRaisesRegex(
             a.ActivateBlocked,"isolated NIC"):
            self.guarded_plan(td,guest_network="default")

    def test_existing_snapshot_refuses_transition(self):
        with TemporaryDirectory() as td,self.assertRaisesRegex(
              a.ActivateBlocked,"snapshot-free"):
            self.guarded_plan(td,snapshot="cape_ready_win11_1")

    def test_restore_witness_must_include_full_tpm_uefi_and_disk(self):
        good={
            "format":"COMMAND2_FULL_COLD_RESTORE_WITNESS_V1",
            "approved_host":HOST,"vm":VM,"uuid":UID,
            "recovery_manifest_sha256":"a"*64,
            "operator":"approved-operator",
            "details":"Disposable restore verified by guest TPM and agent after boot",
        }
        fields=("cold_disk_restored_on_disposable_vm",
                "cold_nvram_restored_on_disposable_vm",
                "cold_swtpm2_restored_on_disposable_vm",
                "windows_agent_verified_after_restore",
                "windows_tpm_uefi_boot_verified_after_restore",
                "master_unmodified_verified")
        good.update({k:True for k in fields})
        with patch.object(a,"read_private_json",return_value=good):
            self.assertEqual(len(a.inspect_witness(Path("/dev/null"),
                     HOST,VM,UID,"a"*64)),64)
        for field in fields:
            bad=good.copy();bad[field]=False
            with patch.object(a,"read_private_json",return_value=bad),\
                 self.assertRaisesRegex(a.ActivateBlocked,"witness incomplete"):
                a.inspect_witness(Path("/dev/null"),HOST,VM,UID,"a"*64)

    def test_apply_without_terminal_cannot_change_saved_xml(self):
        with patch.object(a.sys.stdin,"isatty",return_value=False),\
             patch.object(a.os,"geteuid",return_value=0),\
             patch.object(a,"plan",side_effect=AssertionError("Must not plan")):
            with self.assertRaisesRegex(a.ActivateBlocked,"interactive"):
                a.apply(HOST,VM,UID,Path("/n"),"a"*64,
                        Path("/n"),Path("/n"))

    def test_raw_original_not_replaced_and_no_vm_boot_commands(self):
        content=Path(a.__file__).read_text()
        for forbidden in ('"snapshot-create"', '"snapshot-revert"',
                          '"destroy"', '"start"', '"shutdown"', '"net-start"',
                          '"attach-interface"', 'os.replace('):
            self.assertNotIn(forbidden,content)
        self.assertIn('virsh("define",str(fname),"--validate")',content)
        self.assertIn("raw-nvram-before-transition.xml",content)
        self.assertIn("ACTIVATE-QCOW2-OVMF-ON-DISPOSABLE",content)

if __name__=="__main__":
    unittest.main()
