"""Offline-only safety tests for host-approved Windows optical configuration."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command2_portable_network_approval_iso as a
import command2_portable_guest_identity_iso as identity
import command2_windows_guest_config as config

HOST="fresh-cape-testhost"
VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
MAC="02:00:be:fe:12:34"
def row(root):
    root=Path(root)
    return {"libvirt_name":VM,"libvirt_uuid_candidate":UID,
            "mac_candidate":MAC,"windows_hostname_target":"WIN11-1",
            "guest_static_ipv4_target":"192.168.241.101",
            "disk_target":str(root/"images"/"win11_1.command2.qcow2"),
            "uefi_nvram_target":str(root/"nvram"/"win11_1.command2_VARS.fd")}

def xml(entry,with_nic=True,media=None):
    media=media or (Path(entry["disk_target"]).parent/
                    (VM+".command2_identity.iso"))
    nic=(f'<interface type="network"><source network="cape-analysis-isolated"/>'
         f'<mac address="{MAC}"/></interface>') if with_nic else ""
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
            '<os><nvram>'+entry["uefi_nvram_target"]+'</nvram></os>'
            '<devices><disk device="disk"><source file="'+entry["disk_target"]+
            '"/></disk><tpm><backend type="emulator" version="2.0"/></tpm>'
            '<disk device="cdrom"><source file="'+str(media)+
            '"/><target dev="sdb"/><readonly/></disk>'+nic+
            '</devices></domain>')

class ApprovalMedia(unittest.TestCase):
    def prepare(self,td):
        root=Path(td)
        (root/"images").mkdir()
        (root/"nvram").mkdir()
        ent=row(root)
        Path(ent["disk_target"]).write_bytes(b"TEST-INDEPENDENT-DISK")
        old=Path(ent["disk_target"]).parent/(VM+".command2_identity.iso")
        old.write_bytes(b"IDENTITY-ISO")
        j=root/"command2-identity-reservation.json"
        j.write_text(json.dumps({
            "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "version":1,"guest_count":1,"host":HOST,"entries":[ent]}))
        data=identity.render_config(config.make_guest_config(
            ent,"192.168.241.0/24"))
        (root/"command2-guest-config-win11_1.json").write_bytes(data)
        return j,ent,data,old

    def fake_plan(self,root,with_nic=True):
        j,ent,data,old=self.prepare(root)
        def virsh(*args):
            if args==("domuuid",VM):return UID
            if args==("domstate",VM):return "shut off"
            if args==("dumpxml","--inactive",VM):
                return xml(ent,with_nic=with_nic)
            raise AssertionError("Unexpected libvirt operation: "+str(args))
        with patch.object(identity,"host_guard"), \
             patch.object(identity,"guarded_dir",return_value=Path(root)), \
             patch.object(identity,"read_json",return_value={
                "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
                "version":1,"guest_count":1,"host":HOST,"entries":[ent]}), \
             patch.object(a.attachment,"safe_root_file"), \
             patch.object(a.nic,"read_acceptance_receipt",return_value=True), \
             patch.object(a,"trusted_cape_iso"), \
             patch.object(a,"virsh",side_effect=virsh), \
             patch.object(a.shutil,"which",return_value="/usr/bin/genisoimage"), \
             patch.object(a.os,"statvfs",return_value=SimpleNamespace(
                f_bavail=100*a.GIB//4096,f_frsize=4096)):
            return a.checked_inputs(HOST,VM,j,Path(root)/"network.receipt")

    def test_plan_does_not_authorize_or_start_windows(self):
        with TemporaryDirectory() as td:
            status=self.fake_plan(td)
        self.assertEqual(status["result"],"COMMAND2_NETWORK_APPROVAL_MEDIA_PLAN_ONLY")
        self.assertFalse(status["approved_media_created"])
        self.assertFalse(status["network_or_guest_modified"])
        self.assertFalse(status["guest_running"])
        self.assertEqual(status["cdrom_target"],"sdb")

    def test_refuses_unattached_guest_nic(self):
        with TemporaryDirectory() as td:
            with self.assertRaisesRegex(a.ApprovalBlocked,"NIC"):
                self.fake_plan(td,with_nic=False)

    def test_wrong_mac_refused(self):
        ent=row(Path("/tmp/guest-test"))
        raw=xml(ent).replace(MAC,"02:00:aa:bb:cc:dd")
        with self.assertRaisesRegex(a.ApprovalBlocked,"NIC"):
            a.network_xml(raw,VM,UID,MAC,Path(ent["disk_target"]),
                          Path(ent["disk_target"]).parent/
                          (VM+".command2_identity.iso"))

    def test_network_media_requires_existing_exact_cdrom(self):
        ent=row(Path("/tmp/guest-test"))
        raw=xml(ent).replace(".command2_identity.iso",".other.iso")
        with self.assertRaisesRegex(a.ApprovalBlocked,"Optical"):
            a.network_xml(raw,VM,UID,MAC,Path(ent["disk_target"]),
                          Path(ent["disk_target"]).parent/
                          (VM+".command2_identity.iso"))

    def test_receipt_path_failure_fails_closed(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            j,ent,data,old=self.prepare(root)
            with patch.object(identity,"host_guard"), \
                 patch.object(identity,"guarded_dir",return_value=root), \
                 patch.object(identity,"read_json",return_value={
                    "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
                    "version":1,"guest_count":1,"host":HOST,"entries":[ent]}), \
                 patch.object(a.attachment,"safe_root_file"), \
                 patch.object(a.nic,"read_acceptance_receipt",
                              side_effect=a.nic.NicBlocked("not witnessed")):
                with self.assertRaisesRegex(a.ApprovalBlocked,"acceptance"):
                    a.checked_inputs(HOST,VM,j,root/"fake-receipt")

    def test_no_interactive_tty_no_host_actions(self):
        with patch.object(a.sys.stdin,"isatty",return_value=False), \
             patch.object(a,"checked_inputs",side_effect=AssertionError("no plan")):
            with self.assertRaisesRegex(a.ApprovalBlocked,"terminal"):
                a.apply(HOST,VM,Path("/missing"),Path("/missing"))

    def test_approval_payload_matches_windows_bootstrap_contract(self):
        text=Path(a.__file__).read_text()
        for field in ("COMMAND2_HOST_NETWORK_APPROVAL_V1",
                      "guest_uuid","guest_name","guest_mac",
                      "host_ipv4_negative_egress_verified",
                      "host_ipv6_negative_egress_verified",
                      "reboot_persistence_verified",
                      "guest_l2_separation_verified"):
            self.assertIn(field,text)
        self.assertIn("network-approved.json",text)
        self.assertIn("network-approved.sha256",text)
        self.assertIn('"--update","--config"',text)
        for banned in ('"destroy"', '"start"', '"shutdown"',
                       '"attach-interface"', '"net-start"',
                       '"snapshot-create-as"', '"snapshot-revert"'):
            self.assertNotIn(banned,text)

if __name__=="__main__":
    unittest.main()
