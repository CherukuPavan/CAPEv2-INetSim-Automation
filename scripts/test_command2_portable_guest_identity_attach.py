"""Offline safeguards for portable shut-off zero-NIC identity ISO attachment."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command2_portable_guest_identity_attach as a
import command2_portable_guest_identity_iso as identity
import command2_windows_guest_config as guestconfig

HOST="fresh-capetarget"
VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
CIDR="192.168.241.0/24"
def row(root):
    return {
        "libvirt_name":VM,"libvirt_uuid_candidate":UID,
        "smbios_generation_id_candidate":"abcdabcd-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "windows_hostname_target":"WIN11-1",
        "guest_static_ipv4_target":"192.168.241.101",
        "mac_candidate":"02:fe:19:22:33:44",
        "disk_target":str(root/"images"/"win11_1.command2.qcow2"),
        "uefi_nvram_target":str(root/"nvram"/"win11_1.command2_VARS.fd")}
def xml(data,iso=None,nic=False):
    src="" if iso is None else '<source file="'+str(iso)+'"/>'
    interface="<interface type='network'/>" if nic else ""
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+
            '</uuid><os><nvram>'+data["uefi_nvram_target"]+
            '</nvram></os><devices>'
            '<disk type="file" device="disk"><driver type="qcow2"/>'
            '<source file="'+data["disk_target"]+'"/></disk>'
            '<disk type="file" device="cdrom">'+src+
            '<target dev="sdb"/><readonly/></disk>'+interface+
            '</devices></domain>')
class AttachTests(unittest.TestCase):
    def mkfiles(self,root):
        root=Path(root)
        (root/"images").mkdir()
        (root/"nvram").mkdir()
        entry=row(root)
        Path(entry["disk_target"]).write_bytes(b"INDEPENDENT_FAKE_DISK")
        j=root/"command2-identity-reservation.json"
        j.write_text(json.dumps({
            "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "version":1,"host":HOST,"guest_count":1,
            "host_network_modified":False,"entries":[entry]}))
        guest=guestconfig.make_guest_config(entry,CIDR)
        conf=root/"command2-guest-config-win11_1.json"
        raw=identity.render_config(guest)
        conf.write_bytes(raw)
        src=root/"win11_1.command2_identity.iso"
        src.write_bytes(b"FAKE_V1_IDENTITY_ISO_BYTES")
        return j,conf,src,entry,raw

    def run_plan(self,folder,bad_xml=None,vmstate="shut off",iso_data=None):
        journal,conf,source,row0,raw=self.mkfiles(folder)
        def mocked_virsh(*args):
            if args==("domuuid",VM):return UID
            if args==("domstate",VM):return vmstate
            if args==("dumpxml","--inactive",VM):
                return bad_xml or xml(row0)
            self.fail("Unexpected request "+str(args))
        with patch.object(identity,"host_guard"), \
             patch.object(identity,"guarded_dir",return_value=Path(folder)), \
             patch.object(identity,"read_json",side_effect=lambda p:
                        json.loads(Path(p).read_text())), \
             patch.object(a,"safe_root_file"), \
             patch.object(a,"media_contents",return_value=(
                (raw if iso_data is None else iso_data),
                a.sha(raw).encode())), \
             patch.object(a.os,"statvfs",return_value=SimpleNamespace(
                     f_bavail=100*a.GIB//4096,f_frsize=4096)), \
             patch.object(a,"virsh",side_effect=mocked_virsh):
            return a.plan(HOST,VM,journal)

    def test_expected_plan_only_preserves_vm_and_network(self):
        with TemporaryDirectory() as td:
            plan=self.run_plan(td)
        self.assertEqual(plan["result"],"COMMAND2_IDENTITY_ATTACH_PLAN_ONLY")
        self.assertEqual(plan["cdrom_target"],"sdb")
        self.assertTrue(plan["clone_zero_nic"])
        self.assertFalse(plan["iso_inserted"])
        self.assertFalse(plan["guest_network_authorized"])

    def test_wrong_config_in_iso_is_refused(self):
        with TemporaryDirectory() as td, self.assertRaisesRegex(
            a.AttachBlocked,"ISO content differs"):
            self.run_plan(td,iso_data=b'{"tampered":true}')

    def test_guest_running_refused(self):
        with TemporaryDirectory() as td,self.assertRaisesRegex(
            a.AttachBlocked,"running VM"):
            self.run_plan(td,vmstate="running")

    def test_xml_rejects_nic_and_preinserted_optical_media(self):
        entry=row(Path("/private"))
        with self.assertRaisesRegex(a.AttachBlocked,"Unexpected guest NIC"):
            a.xml_gate(xml(entry,nic=True),VM,UID,Path(entry["disk_target"]))
        with self.assertRaisesRegex(a.AttachBlocked,"empty read-only"):
            a.xml_gate(xml(entry,iso="/tmp/preexisting.iso"),VM,UID,
                       Path(entry["disk_target"]))

    def test_existing_destination_preserved(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            journal,conf,source,ent,raw=self.mkfiles(root)
            target=Path(ent["disk_target"]).parent/(VM+".command2_identity.iso")
            target.write_bytes(b"ORIGINAL")
            with patch.object(identity,"host_guard"), \
                 patch.object(identity,"guarded_dir",return_value=root), \
                 patch.object(identity,"read_json",return_value={
                     "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
                     "version":1,"host":HOST,"guest_count":1,
                     "host_network_modified":False,"entries":[ent]}), \
                 patch.object(a,"safe_root_file"), \
                 patch.object(a,"media_contents",return_value=(raw,
                     a.sha(raw).encode())), \
                 patch.object(a,"virsh",side_effect=lambda *args:
                    UID if args==("domuuid",VM) else
                    "shut off" if args==("domstate",VM) else
                    xml(ent) if args==("dumpxml","--inactive",VM) else
                    "UNEXPECTED"), \
                 patch.object(a.os,"statvfs",return_value=SimpleNamespace(
                     f_bavail=100*a.GIB//4096,f_frsize=4096)):
                with self.assertRaisesRegex(a.AttachBlocked,"artifact exists"):
                    a.plan(HOST,VM,journal)
            self.assertEqual(target.read_bytes(),b"ORIGINAL")

    def test_noninteractive_attach_refused_before_preflight(self):
        with patch.object(a.sys.stdin,"isatty",return_value=False), \
             patch.object(a,"plan",side_effect=AssertionError("Should not plan")):
            with self.assertRaisesRegex(a.AttachBlocked,"TTY"):
                a.apply(HOST,VM,Path("/fake"))

    def test_no_unapproved_vm_lifecycle_or_network_mutators(self):
        source=Path(a.__file__).read_text()
        for dangerous in ('"start",vm','"destroy",vm','"shutdown",vm',
                          '"attach-interface"','"net-start"','"net-autostart"',
                          '"snapshot-create"','"snapshot-revert"','"nft","add"'):
            self.assertNotIn(dangerous,source)

if __name__=="__main__":
    unittest.main()
