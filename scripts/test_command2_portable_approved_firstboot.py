"""Offline guard tests for the approved one-NIC Windows firstboot path.

No real VM is booted here; Windows TASK/agent and host isolation still
require physical verification on the explicitly approved lab system.
"""
import stat
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import command2_portable_approved_firstboot as a

VM="win11_1"
UUID="12345678-1234-4234-8234-000000000001"
MAC="02:bb:cc:dd:ee:01"
DISK="/private/win11_1.command2.qcow2"
VARS="/private/win11_1.command2_VARS.fd"
ISO="/private/win11_1.command2_network_approved.iso"
ROW={"libvirt_name":VM,"libvirt_uuid_candidate":UUID,"mac_candidate":MAC,
     "disk_target":DISK,"uefi_nvram_target":VARS}

def xml(*,net="cape-analysis-isolated",mac=MAC,iso=ISO,extradev=""):
    return (f'<domain type="kvm"><name>{VM}</name><uuid>{UUID}</uuid>'
            f'<memory unit="KiB">4194304</memory>'
            f'<os><nvram format="raw">{VARS}</nvram></os><devices>'
            f'<disk type="file" device="disk"><driver type="qcow2"/>'
            f'<source file="{DISK}"/></disk>'
            f'<disk type="file" device="cdrom"><source file="{iso}"/>'
            f'<readonly/></disk><tpm><backend type="emulator" version="2.0"/>'
            f'</tpm><interface type="network"><source network="{net}"/>'
            f'<mac address="{mac}"/></interface>{extradev}</devices></domain>')

class ApprovedBootTests(unittest.TestCase):
    def test_one_exact_isolated_nic_disk_firmware_tpm_iso_required(self):
        root=a.inspect_xml(xml(),VM,ROW,Path(ISO))
        self.assertEqual(root.findtext("name"),VM)
        for arg,reason in (
            ({"net":"default"},"one reviewed isolated"),
            ({"mac":"02:00:00:00:00:01"},"one reviewed isolated"),
            ({"iso":"/unapproved.iso"},"approved CAPE_CMD2"),
            ({"extradev":"<hostdev/>"},"host-connected"),
            ({"extradev":"<channel/>"},"host-connected"),
        ):
            with self.subTest(arg=arg),self.assertRaisesRegex(a.ApprovedBootBlocked,reason):
                a.inspect_xml(xml(**arg),VM,ROW,Path(ISO))

    def test_allowed_iso_names_only(self):
        with self.assertRaisesRegex(a.ApprovedBootBlocked,"Unknown"):
            a.iso_file(Path(ISO),"../../etc/passwd")

    def test_boot_requires_paused_live_device_gate_before_resume(self):
        with TemporaryDirectory() as td:
            lock=Path(td)/"lock"
            states={"clone":"shut off"}
            commands=[]
            def virsh(*args,**kwargs):
                commands.append(args)
                if args[0]=="start":
                    self.assertEqual(args[1:],(VM,"--paused"))
                    states["clone"]="paused"
                if args[0]=="resume":
                    self.assertEqual(args[1:],(VM,))
                    states["clone"]="running"
                if args[0]=="domstate":
                    return "shut off" if args[1]=="win11" else states["clone"]
                if args[0]=="dumpxml":return xml()
                return ""
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(a,"LOCK",lock),\
                 patch.object(a,"checked_plan",
                              return_value={"result":"PLAN_ONLY"}),\
                 patch.object(a.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="BOOT-ISOLATED-ONE-NIC-WIN11_1"),\
                 patch.object(a.os,"fstat",return_value=fs),\
                 patch.object(a,"virsh",side_effect=virsh),\
                 patch.object(a.workflow,"load_guest",
                              return_value=(ROW,"192.168.240.0/24",None)),\
                 patch.object(a.nic,"verify_network_live",return_value=True):
                result=a.approved_boot("otherhost",Path("/private/reservation.json"),
                                       VM,Path("/private/v2.json"))
            self.assertTrue(result["guest_running"])
            self.assertFalse(result["static_ipv4_proved"])
            self.assertLess(commands.index(("start",VM,"--paused")),
                            commands.index(("resume",VM)))

    def test_changed_live_xml_leaves_guest_paused_without_revert_or_destroy(self):
        with TemporaryDirectory() as td:
            states={"clone":"shut off"}
            commands=[]
            def virsh(*args,**kwargs):
                commands.append(args)
                if args[0]=="start":states["clone"]="paused"
                if args[0]=="domstate":
                    return "shut off" if args[1]=="win11" else states["clone"]
                if args[0]=="dumpxml":return xml(net="default")
                raise AssertionError("Unsafe VM action "+str(args))
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(a,"LOCK",Path(td)/"lock"),\
                 patch.object(a,"checked_plan",return_value={"result":"PLAN"}),\
                 patch.object(a.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="BOOT-ISOLATED-ONE-NIC-WIN11_1"),\
                 patch.object(a.os,"fstat",return_value=fs),\
                 patch.object(a,"virsh",side_effect=virsh),\
                 patch.object(a.workflow,"load_guest",
                              return_value=(ROW,"192.168.240.0/24",None)):
                with self.assertRaisesRegex(a.ApprovedBootBlocked,"isolated NIC"):
                    a.approved_boot("otherhost",Path("/private/reservation.json"),
                                    VM,Path("/private/v2.json"))
            self.assertEqual(states["clone"],"paused")
            self.assertNotIn("resume",[x[0] for x in commands])
            self.assertNotIn("destroy",[x[0] for x in commands])

    def test_no_malware_or_unreviewed_libvirt_changes(self):
        code=Path(a.__file__).read_text()
        for forbidden in ('virsh("destroy"', 'virsh("shutdown"',
                          'virsh("snapshot-revert"',
                          'virsh("snapshot-create"',
                          'virsh("attach-interface"',
                          "shell=True"):
            self.assertNotIn(forbidden,code)

if __name__=="__main__":
    unittest.main()
