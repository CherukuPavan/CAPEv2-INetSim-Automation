"""Mock-only guarded golden-master import; no live libvirt or real TPM."""
from pathlib import Path
import hashlib
import json
import os
import pwd
import stat
from types import SimpleNamespace
import tempfile
from unittest.mock import patch
import unittest
import xml.etree.ElementTree as ET

import command1_import_existing_master as m
import command1_export_existing_master as golden

UUID="289d89be-68ec-4c62-90e1-ea930849266f"
class Import(unittest.TestCase):
    def setup(self,td):
        root=Path(td)
        bundle=root/"cape-master-transfer";bundle.mkdir()
        disk=bundle/golden.FILES["disk"]
        disk.write_bytes(b"EXACT WIN11 CUSTOM APPS PYTHON REGISTRY IMAGE")
        vars=bundle/golden.FILES["nvram"];vars.write_bytes(b"RAW UEFI VARS")
        tpm=bundle/"tpm-tpm2-00.permall";tpm.write_bytes(b"PRIVATE TPM MASTER")
        code=root/"OVMF_CODE.fd";code.write_bytes(b"firmware")
        srcxml=(
            '<domain type="kvm"><name>win11</name><uuid>'+UUID+'</uuid>'
            '<os><loader readonly="yes">'+str(code)+'</loader>'
            '<nvram format="raw">/original/win11_VARS.fd</nvram></os>'
            '<devices><disk type="file" device="disk">'
            '<driver type="qcow2"/><source file="/original/win11.qcow2"/>'
            '</disk><interface type="network">'
            '<source network="default"/>'
            '<mac address="52:54:00:aa:bb:cc"/>'
            '<model type="e1000e"/></interface>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '</devices></domain>')
        (bundle/golden.FILES["xml"]).write_text(srcxml)
        data={"schema":"cape-command1-master-bundle-v1",
              "master":"win11","master_uuid":UUID,
              "guest_was_shut_off":True,"source_uefi_format":"raw",
              "artifacts":{"disk":{
                    "bytes":disk.stat().st_size,
                    "sha256":golden.sha(disk)},
                 "nvram":{"bytes":vars.stat().st_size,
                          "sha256":golden.sha(vars)},
                 "tpm":{"tpm2-00.permall":{
                    "bytes":tpm.stat().st_size,"sha256":golden.sha(tpm)}}}}
        (bundle/golden.MANIFEST).write_text(json.dumps(data))
        targetdisk=root/"master-disk.qcow2"
        targetvars=root/"master-vars.fd"
        tpmroot=root/"swtpm";tpmroot.mkdir()
        return root,bundle,targetdisk,targetvars,tpmroot,srcxml,disk
    def test_xml_preserves_custom_windows_master_identity_and_rewrites_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle,disk,vars,tpmroot,xml,source=self.setup(td)
            new,data=m.prepare_xml(bundle,disk,vars)
            x=ET.fromstring(new)
            self.assertEqual(x.findtext("name"),"win11")
            self.assertEqual(x.findtext("uuid"),UUID)
            self.assertEqual(
                x.find("./devices/disk/source").get("file"),str(disk))
            self.assertEqual(x.findtext("./os/nvram"),str(vars))
            self.assertEqual(x.find("./os/nvram").get("format"),"raw")
            self.assertIn("source network=\"default\"",new)
            self.assertIn("52:54:00:aa:bb:cc",new)
            self.assertNotIn("master-disk",xml)
            self.assertTrue(data["guest_was_shut_off"])

    def test_bad_ovmf_firmware_on_new_host_fails_before_any_copies(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle,disk,vars,tpmroot,xml,source=self.setup(td)
            (root/"OVMF_CODE.fd").unlink()
            with self.assertRaisesRegex(m.ImportBlocked,"OVMF CODE"):
                m.prepare_xml(bundle,disk,vars)
            self.assertFalse(disk.exists())

    def test_import_exact_golden_bytes_and_tpm_master_only(self):
        with tempfile.TemporaryDirectory() as td:
            root,bundle,disk,vars,tpmroot,xml,source=self.setup(td)
            state=[False]
            def v(*args,**kwargs):
                if args==("list","--all","--name"):
                    return "win11" if state[0] else ""
                if args[0]=="define":
                    state[0]=True
                    return "Domain win11 defined"
                if args==("domuuid","win11"):return UUID
                if args==("domstate","win11"):return "shut off"
                if args==("dumpxml","--inactive","win11"):
                    return m.prepare_xml(bundle,disk,vars)[0]
                raise AssertionError(args)
            uid=pwd.getpwuid(os.getuid()).pw_name
            with patch.object(m,"TPM_ROOT",tpmroot),\
                 patch.object(m,"LOCK",root/"lock"),\
                 patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.socket,"gethostname",return_value="lab02"),\
                 patch.object(m,"approved_target",side_effect=lambda p:Path(p)),\
                 patch.object(m.golden,"manifest_check",return_value={
                     "result":"COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED"}),\
                 patch.object(m.os,"statvfs",return_value=SimpleNamespace(
                     f_bavail=120*1024**3,f_frsize=1)),\
                 patch.object(m,"virsh",side_effect=v),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                     "IMPORT-EXACT-COLD-WIN11-MASTER-ON-NEW-HOST-ONLY")),\
                 patch.object(m.os,"chown",return_value=None),\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                     st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)),\
                 patch.object(m.golden,"run",return_value=""):
                before=m.check("lab02",bundle,disk,vars,uid)
                self.assertEqual(before["result"],
                                 "COMMAND1_EXACT_MASTER_IMPORT_PLAN_ONLY")
                out=m.apply("lab02",bundle,disk,vars,uid)
            self.assertEqual(out["result"],
                    "COMMAND1_ACTUAL_MASTER_IMPORT_STAGED_VERIFIED")
            self.assertTrue(out["guest_imported_and_off"])
            self.assertFalse(out["final_running_master_snapshot_created"])
            self.assertFalse(out["license_bitlocker_ovmf_compatibility_proven"])
            self.assertEqual(disk.read_bytes(),source.read_bytes())
            self.assertEqual(vars.read_bytes(),b"RAW UEFI VARS")
            self.assertEqual((tpmroot/UUID/"tpm2"/"tpm2-00.permall").read_bytes(),
                             b"PRIVATE TPM MASTER")

    def test_refuses_source_ssl55_and_overwrite(self):
        with patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m.os,"geteuid",return_value=0),\
             self.assertRaisesRegex(m.ImportBlocked,"NEW host"):
            m.require_host("cse-ssl-55")
        with tempfile.TemporaryDirectory() as td:
            old=Path(td)/"disk.qcow2";old.write_bytes(b"occupied")
            with self.assertRaises(m.ImportBlocked):
                m.approved_target(old)

    def test_no_windows_boot_snapshot_revert_or_cape_mutations(self):
        code=Path(m.__file__).read_text()
        for token in ('"snapshot-revert"','"snapshot-delete"',
            '"shutdown"','"destroy"','"start"','"net-update"',
            '"attach-interface"','"detach-interface"','shell=True'):
            self.assertNotIn(token,code)
if __name__=="__main__":unittest.main()
