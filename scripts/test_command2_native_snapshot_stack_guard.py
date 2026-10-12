"""Synthetic admission tests for disposable-host QCOW2 OVMF snapshot trial."""
from pathlib import Path
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch
import command2_native_snapshot_stack_guard as g

VM="win11_1"
VARS="/tmp/independent/win11_1.command2_VARS.fd"
DISK="/tmp/independent/win11_1.command2.qcow2"
def versions(libvirt="10.10.0",qemu="9.1.0"):
    return ("Compiled against library: libvirt 10.10.0\n"
            "Using library: libvirt 10.10.0\n"
            "Using API: QEMU 10.10.0\n"
            "Running hypervisor: QEMU "+qemu+"\n"
            "Running against daemon: "+libvirt)
def xml(fmt="qcow2", tpm=True, varspath=VARS):
    tp='<tpm><backend type="emulator" version="2.0"/></tpm>' if tpm else ""
    return ('<domain type="kvm"><name>win11_1</name>'
            '<os><loader type="pflash" readonly="yes">/code.fd</loader>'
            f'<nvram format="{fmt}">{varspath}</nvram></os>'
            '<memory unit="MiB">4096</memory>'
            '<devices><disk device="disk" type="file">'
            f'<source file="{DISK}"/><target dev="sda"/></disk>'
            +tp+'</devices></domain>')
class NativeSnapshotStack(unittest.TestCase):
    def test_virsh_version_parsing_and_conservative_floor(self):
        out=g.parse_versions(versions())
        self.assertEqual(out["libvirt_daemon_version"],"10.10.0")
        with self.assertRaisesRegex(g.NativeBlocked,"Libvirt daemon"):
            g.parse_versions(versions(libvirt="10.9.0"))
        with self.assertRaisesRegex(g.NativeBlocked,"QEMU older"):
            g.parse_versions(versions(qemu="8.2.0"))
        with self.assertRaisesRegex(g.NativeBlocked,"Cannot read"):
            g.parse_versions("Using library: libvirt 12.0.0")

    def fake_inspect(self,fmt="qcow2",tpm=True,actual="qcow2",varspath=VARS):
        def mockcmd(*args):
            if args[0]=="virsh" and args[-2:]==("version","--daemon"):
                return versions()
            if args[0]=="virsh" and args[-2:]==("dumpxml",VM):
                return xml(fmt,tpm,varspath)
            if args[0]=="qemu-img":
                return json.dumps({"format":actual,"virtual-size":1<<20})
            self.fail("Unexpected command "+str(args))
        with patch.object(g,"command",side_effect=mockcmd),\
             patch.object(g.Path,"is_symlink",return_value=False),\
             patch.object(g.Path,"is_file",return_value=True),\
             patch.object(g.os,"statvfs",return_value=SimpleNamespace(
                 f_frsize=4096,f_bavail=100*g.GIB//4096)):
            return g.inspect(VM)

    def test_qcow2_nvram_and_swtpm_experiment_only(self):
        result=self.fake_inspect()
        self.assertEqual(result["result"],"COMMAND2_NATIVE_SNAPSHOT_EXPERIMENT_STACK_ADMITTED")
        self.assertFalse(result["real_swtpm_rollback_tested"])
        self.assertFalse(result["physical_cape_ready"])
        self.assertFalse(result["snapshot_created"])

    def test_explicit_firmware_qcow2_sidecar_is_admitted_on_other_host(self):
        result=self.fake_inspect(varspath=VARS+".qcow2")
        self.assertEqual(result["uefi_variable_store_real_format"],"qcow2")
        self.assertFalse(result["physical_cape_ready"])

    def test_raw_nvram_blocked_regardless_of_other_features(self):
        with self.assertRaisesRegex(g.NativeBlocked,"QCOW2 NVRAM"):
            self.fake_inspect(fmt="raw")

    def test_raw_on_disk_blocked_despite_xml_claim(self):
        with self.assertRaisesRegex(g.NativeBlocked,"not standalone QCOW2"):
            self.fake_inspect(actual="raw")

    def test_missing_emulator_tpm_blocked(self):
        with self.assertRaisesRegex(g.NativeBlocked,"TPM2"):
            self.fake_inspect(tpm=False)

    def test_read_only_no_capture_commands(self):
        code=Path(g.__file__).read_text()
        for action in ('"snapshot-create"', '"snapshot-create-as"',
                       '"snapshot-revert"', '"destroy"', '"shutdown"',
                       '"undefine"', '"net-start"', '"attach-interface"'):
            self.assertNotIn(action,code)

if __name__=="__main__":
    unittest.main()
