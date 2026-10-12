"""Mock-only guarded all-N UEFI RAW/QCOW2 saved-state conversion tests."""
from pathlib import Path
import json
import os
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_master_nat_ovmf_qcow2 as m

VM="win11_1"
UUID="00000000-0000-4000-8000-000000000001"
MAC="02:ca:22:00:00:01"
def row(parent,vm=VM):
    return {"libvirt_name":vm,"libvirt_uuid_candidate":UUID,
            "mac_candidate":MAC,"disk_target":str(parent/"os.qcow2"),
            "uefi_nvram_target":str(parent/"vars.fd")}
def domain(r,active=False):
    nv=str(r["uefi_nvram_target"])+(".qcow2" if active else "")
    fmt="qcow2" if active else "raw"
    return ("<domain type='kvm'><name>"+r["libvirt_name"]+"</name><uuid>"+
            r["libvirt_uuid_candidate"]+"</uuid><os>"
            "<loader type='pflash' readonly='yes'>/ovmf/code.fd</loader>"
            "<nvram format='"+fmt+"'>"+nv+"</nvram></os>"
            "<devices><disk device='disk'><source file='"+
            r["disk_target"]+"'/></disk><tpm><backend type='emulator' "
            "version='2.0'/></tpm><interface type='network'>"
            "<source network='default'/><model type='e1000e'/>"
            "<mac address='"+r["mac_candidate"]+"'/></interface>"
            "</devices></domain>")

class Firmware(unittest.TestCase):
    def test_original_raw_only_accepted_before_activation(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); r=row(p)
            raw=Path(r["uefi_nvram_target"]);raw.write_bytes(b"\0"*540672)
            orig=domain(r)
            def cmd(*args,**kwargs):
                if args[:2]==("info","--output=json"):
                    return json.dumps({"format":"raw","virtual-size":540672})
                raise AssertionError(args)
            def virsh(*args,**kwargs):
                if args[0]=="domstate":return "shut off"
                if args[0]=="snapshot-list":return ""
                if args[0]=="dumpxml":return orig
                raise AssertionError(args)
            with patch.object(m.attach,"virsh",side_effect=virsh),\
                 patch.object(m,"qemu",side_effect=cmd):
                z=m.inspect_one(r,p,False)
            self.assertEqual(z["state"],"RAW_NVRAM_NOT_CONVERTED")
            self.assertEqual(z["source_nvram_size"],540672)
            side=Path(str(raw)+".qcow2");side.write_bytes(b"unexpected")
            with patch.object(m.attach,"virsh",side_effect=virsh),\
                 patch.object(m,"qemu",side_effect=cmd),\
                 self.assertRaisesRegex(m.NatFirmwareBlocked,"never-converted"):
                m.inspect_one(r,p,False)

    def test_exact_n_guest_plan_and_safe_all_stop_requirements(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            entries=[row(root,"win11_1")]
            raw=Path(entries[0]["uefi_nvram_target"])
            raw.write_bytes(b"raw vars")
            # A different owner of this temp directory is fine in the
            # test; the REAL helper still requires privileged 0700 root.
            with patch.object(m,"private_folder",return_value=root),\
                 patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.attach.workflow,"canonical_host",return_value="other"),\
                 patch.object(m.attach,"journal_rows",return_value=entries),\
                 patch.object(m.attach,"virsh",return_value=""),\
                 patch.object(m.attach.profile,"check_master",
                              return_value={"master_left_shut_off":True}),\
                 patch.object(m,"inspect_one",return_value={"vm":VM,
                     "state":"RAW_NVRAM_NOT_CONVERTED"}):
                z=m.check("other",root/"journal",root,False)
            self.assertEqual(z["count"],1)
            self.assertFalse(z["TPM_safe_snapshot_restoration_proven"])
            self.assertTrue(z["master_shut_off_and_unmodified"])

    def test_only_offline_n_clones_own_raw_preserved_and_xml_backup(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            rows=[row(root,"win11_1"),row(root,"win11_2")]
            seed=[{"vm":r["libvirt_name"],"state":"RAW_NVRAM_NOT_CONVERTED"}
                  for r in rows]
            initial={"count":2,"guests":seed}
            saved=[{"vm":r["libvirt_name"],"state":"QCOW2_NVRAM_ACTIVE_IN_SAVED_XML"}
                  for r in rows]
            switched={"count":2,"guests":saved}
            calls=[]
            def switch(r,folder):
                calls.append(r["libvirt_name"])
                return {"vm":r["libvirt_name"]}
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                    return_value="CONVERT-2-MASTER-NAT-UEFI-QCOW2-ONLY"),\
                 patch.object(m,"LOCK",root/"lock"),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"check",side_effect=lambda h,j,e,x: switched if x else initial),\
                 patch.object(m.attach,"journal_rows",return_value=rows),\
                 patch.object(m,"copy_and_define",side_effect=switch),\
                 patch.object(m,"private_folder",return_value=root):
                z=m.apply("other",root/"journal",root)
            self.assertEqual(calls,["win11_1","win11_2"])
            self.assertEqual(z["result"],
                "COMMAND2_ALL_N_MASTER_NAT_OVMF_QCOW2_APPLIED_VERIFIED")
            self.assertFalse(z["actual_guest_boot_or_TPM_revert_verified"])

    def test_failure_mid_batch_preserves_originals_no_repeat(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);rows=[row(root,"win11_1"),row(root,"win11_2")]
            initial={"count":2,"guests":[{"vm":VM}]}
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            attempted=[]
            def fail(r,folder):
                attempted.append(r["libvirt_name"])
                raise m.NatFirmwareBlocked("QEMU filesystem rejected conversion")
            with patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                    return_value="CONVERT-2-MASTER-NAT-UEFI-QCOW2-ONLY"),\
                 patch.object(m,"LOCK",root/"lock"),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"check",return_value=initial),\
                 patch.object(m.attach,"journal_rows",return_value=rows),\
                 patch.object(m,"copy_and_define",side_effect=fail),\
                 patch.object(m,"private_folder",return_value=root),\
                 self.assertRaisesRegex(m.NatFirmwareBlocked,"MAY_BE_PARTIAL"):
                m.apply("other",root/"journal",root)
            self.assertEqual(attempted,["win11_1"])

    def test_no_guest_boot_rollback_mutator_or_sample_releases(self):
        src=Path(m.__file__).read_text()
        for wrong in ('"snapshot-create-as"','"snapshot-revert"',
             '"snapshot-delete"','"destroy"','"shutdown"',
             '"start"','"resume"','shell=True','Set-MpPreference',
             "CAPE_READY\":True"):
            self.assertNotIn(wrong,src)

if __name__=="__main__":unittest.main()
