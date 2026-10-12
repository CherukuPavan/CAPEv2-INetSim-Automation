"""Offline-only test suite for other-host Windows zero-NIC identity media."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command2_portable_guest_identity_iso as media
import command2_windows_guest_config as config

VM="win11_1"
HOST="fresh-capetarget"
UUID="12345678-1234-4234-8234-123456789abc"
CIDR="192.168.241.0/24"

def row():
    return {
        "libvirt_name":VM,
        "libvirt_uuid_candidate":UUID,
        "smbios_generation_id_candidate":"abcdabcd-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "windows_hostname_target":"WIN11-1",
        "guest_static_ipv4_target":"192.168.241.101",
        "mac_candidate":"02:fe:19:22:33:44",
        "disk_target":"/private/images/win11_1.command2.qcow2",
        "uefi_nvram_target":"/private/nvram/win11_1.command2_VARS.fd",
    }

def journal(items=None):
    if items is None:items=[row()]
    return {"format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "version":1,"host":HOST,"guest_count":len(items),
            "entries":items,"host_network_modified":False}

class IdentityMedia(unittest.TestCase):
    def paths(self,root):
        root=Path(root)
        return (root/"command2-identity-reservation.json",
                root/"command2-guest-config-win11_1.json",
                root/"win11_1.command2_identity.iso")

    def test_expected_identity_config_bytes_exact(self):
        value=config.make_guest_config(row(),CIDR)
        result=media.render_config(value)
        self.assertEqual(json.loads(result),value)
        self.assertTrue(result.endswith(b"\n"))
        self.assertIsNone(value["default_gateway"])
        self.assertFalse(value["auto_apply_network"])

    def invoke(self,alter=None):
        with TemporaryDirectory() as temp:
            j,c,d=self.paths(temp)
            j.write_text(json.dumps(journal()))
            guest=config.make_guest_config(row(),CIDR)
            if alter:alter(guest)
            c.write_bytes(media.render_config(guest))
            def check_read(path):
                return json.loads(Path(path).read_text())
            with patch.object(media,"host_guard"), \
                 patch.object(media,"guarded_dir",return_value=Path(temp)), \
                 patch.object(media,"read_json",side_effect=check_read), \
                 patch.object(media,"vm_guard"), \
                 patch.object(media.shutil,"which",return_value="/usr/bin/genisoimage"), \
                 patch.object(media.os,"statvfs",return_value=SimpleNamespace(
                         f_bavail=100*media.GIB//4096,f_frsize=4096)):
                return media.plan(host=HOST,vm=VM,journal=j,config=c,dest=d)

    def test_expected_guest_media_plan_no_disk_or_network_changes(self):
        result=self.invoke()
        self.assertEqual(result["result"],"COMMAND2_IDENTITY_OPTICAL_PLAN_ONLY")
        self.assertFalse(result["contains_host_network_approval"])
        self.assertFalse(result["iso_created"])
        self.assertFalse(result["optical_media_attached"])
        self.assertEqual(result["guest_static_ip_future_only"],"192.168.241.101")

    def test_gateway_configuration_refused(self):
        with self.assertRaises((config.GuestConfigBlocked,media.MediaBlocked)):
            self.invoke(lambda c: c.__setitem__("default_gateway","192.168.241.1"))

    def test_guest_uuid_mismatch_refused(self):
        with self.assertRaises(media.MediaBlocked):
            self.invoke(lambda c: c.__setitem__("expected_machine_uuid",
                                                "deadbeef-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))

    def test_guest_mac_mismatch_refused(self):
        with self.assertRaises(media.MediaBlocked):
            self.invoke(lambda c: c.__setitem__("nic_mac",
                                                "02:fe:19:22:33:45"))

    def test_old_or_new_media_never_overwritten(self):
        with TemporaryDirectory() as temp:
            j,c,d=self.paths(temp)
            d.write_bytes(b"EXISTING_OPTICAL_EVIDENCE")
            with patch.object(media,"host_guard"):
                with self.assertRaisesRegex(media.MediaBlocked,"replace or reuse"):
                    media.plan(host=HOST,vm=VM,journal=j,config=c,dest=d)
            self.assertEqual(d.read_bytes(),b"EXISTING_OPTICAL_EVIDENCE")

    def test_running_vm_or_duplicate_guest_nic_guard_enforced(self):
        fake_xml=('<domain><name>'+VM+'</name><uuid>'+UUID+'</uuid><devices>'
            '<disk device="disk"><source file="/private/images/win11_1.command2.qcow2"/>'
            '<driver type="qcow2"/></disk><interface type="network"/></devices></domain>')
        def call(*cmd):
            return UUID if cmd[-2:] == ("domuuid",VM) else (
                "shut off" if cmd[-2:]==("domstate",VM) else fake_xml)
        with patch.object(media,"read_cmd",side_effect=call):
            with self.assertRaisesRegex(media.MediaBlocked,"zero NICs"):
                media.vm_guard(VM,UUID)

    def test_noninteractive_media_creation_has_zero_effect(self):
        with patch.object(media.sys.stdin,"isatty",return_value=False), \
             patch.object(media,"plan",side_effect=AssertionError("Unexpected plan")):
            with self.assertRaisesRegex(media.MediaBlocked,"local terminal"):
                media.build(host=HOST,vm=VM,journal=Path("/unused"),
                            config=Path("/unused"),dest=Path("/unused"))

    def test_source_has_no_vm_power_or_network_commands(self):
        s=Path(media.__file__).read_text()
        for needle in ('"net-start"', '"attach-interface"', '"shutdown"',
                       '"destroy"', '"snapshot-create"', '"change-media"',
                       '"net-autostart"', '"start"'):
            self.assertNotIn(needle,s)

if __name__=="__main__":
    unittest.main()
