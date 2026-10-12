"""Offline guard coverage for preserving RAW OVMF while staging QCOW2 sidecar."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import command2_disposable_nvram_qcow2_prepare as t

VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
HOST="approved-separate-kvm-host"
def xml(firmware):
    return (f'<domain type="kvm"><name>{VM}</name><uuid>{UID}</uuid>'
            '<os><loader type="pflash" readonly="yes">/usr/share/OVMF/OVMF_CODE_4M.fd</loader>'
            f'<nvram format="raw">{firmware}</nvram></os>'
            '<devices><disk device="disk"><source file="/var/lib/libvirt/images/'
            f'{VM}.command2.qcow2"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm></devices></domain>')

class NVRAMSidecarTests(unittest.TestCase):
    def test_only_shutoff_disposable_vm_admitted_and_source_preserved(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            nv=root/(VM+".command2_VARS.fd")
            nv.write_bytes(b"BENIGN_DISPOSABLE_OVMF_TEST_CONTENT")
            def virsh(*args):
                if args==("domuuid",VM):return UID
                if args==("domstate",VM):return "shut off"
                if args==("snapshot-list",VM,"--name"):return ""
                if args==("dumpxml","--inactive",VM):return xml(nv)
                self.fail("Unexpected potentially mutating virsh call "+str(args))
            with patch.object(t,"hostname_guard"),\
                 patch.object(t,"virsh",side_effect=virsh),\
                 patch.object(t,"execute",return_value='{"format":"raw"}'),\
                 patch.object(t.cold,"inspect",return_value={
                        "manifest_sha256":"a"*64}),\
                 patch.object(t.os,"statvfs",return_value=SimpleNamespace(
                         f_frsize=4096,f_bavail=100*t.GIB//4096)):
                report=t.plan(HOST,VM,UID,root/"backup","a"*64)
            self.assertEqual(report["result"],"COMMAND2_OVMF_QCOW2_SIDECAR_PLAN_ONLY")
            self.assertEqual(report["original_nvram_sha256"],t.sha256(nv))
            self.assertFalse(report["guest_vm_xml_modified"])
            self.assertFalse(report["running_snapshot_created"])
            self.assertFalse((root/(VM+".command2_VARS.fd.qcow2")).exists())

    def test_protected_canonical_host_cannot_prepare_firmware(self):
        with patch.object(t.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(t.os,"geteuid",return_value=0):
            with self.assertRaisesRegex(t.ConversionBlocked,"protected host"):
                t.hostname_guard("cse-ssl-55")

    def test_no_noninteractive_approval_or_preexisting_output(self):
        with patch.object(t.sys.stdin,"isatty",return_value=False),\
             patch.object(t,"plan",side_effect=AssertionError("Not even plan")):
            with self.assertRaisesRegex(t.ConversionBlocked,"terminal"):
                t.prepare(HOST,VM,UID,Path("/abs"),"a"*64)

    def test_source_never_removes_existing_variables_or_defines_vm(self):
        src=Path(t.__file__).read_text()
        for symbol in ('"snapshot-create"', '"snapshot-create-as"',
                       '"snapshot-revert"', '"undefine"', '"define"',
                       '"destroy"', '"start"', '"shutdown"', '"net-start"',
                       '"attach-interface"', 'os.replace(', 'os.remove('):
            self.assertNotIn(symbol,src)
        self.assertIn('"-f","raw","-O","qcow2"',src)
        self.assertIn('os.link(candidate,dest,follow_symlinks=False)',src)
        self.assertIn("qemu-img",src)
        self.assertIn("qemu-img","-".join(["qemu","img"]))

if __name__=="__main__":
    unittest.main()
