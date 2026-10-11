"""Synthetic-only tested SSL55 host preflight for no-reboot CD fix insertion."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_oneclick_fix_iso_host as h


def vmxml(vm,mode="old"):
    if vm!="win11_1":
        uid=h.MASTER_UUID if vm=="win11" else h.TRIAL_UUID
        nic='<interface type="network"/>' if vm=="win11" else ""
        return ('<domain type="kvm"><name>'+vm+'</name><uuid>'+uid+
                '</uuid><devices>'+nic+'</devices></domain>')
    return ('<domain type="kvm"><name>win11_1</name><uuid>'+h.UUID+'</uuid>'
            '<os><nvram>'+h.EXPECTED_NVRAM+'</nvram></os>'
            '<devices><interface type="network"><source network="cape-analysis-isolated"/>'
            '<mac address="'+h.MAC+'"/><model type="e1000e"/></interface>'
            '<disk type="file" device="disk"><driver type="qcow2"/>'
            '<source file="'+str(h.EXPECTED_DISK)+'"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '<disk device="cdrom"><target dev="sdb"/><source file="'+
            str(h.OLD if mode=="old" else h.NEW)+'"/></disk>'
            '</devices></domain>')


class OneclickIsoHostTests(unittest.TestCase):
    def test_original_sources_are_immutable_pinned(self):
        repo=Path(__file__).parent
        for name,want in h.SOURCES.items():
            with self.subTest(name=name):
                self.assertEqual(h.git_blob((repo/name).read_bytes()),want)

    def test_verify_host_guest_xml_detects_altered_nic_and_original(self):
        self.assertTrue(h.vm_xml(vmxml("win11_1"),"win11_1"))
        for changed in (vmxml("win11_1").replace(h.MAC,"02:00:00:00:00:01"),
                        vmxml("win11_1").replace(str(h.OLD),"/tmp/other.iso"),
                        vmxml("win11_1").replace(str(h.EXPECTED_DISK),"/tmp/other.qcow2")):
            with self.subTest(changed=changed[:50]),self.assertRaises(h.OpticalBlocked):
                h.vm_xml(changed,"win11_1")
        self.assertTrue(h.vm_xml(vmxml("win11"),"win11"))
        self.assertTrue(h.vm_xml(vmxml("win11_trial_1"),"win11_trial_1"))

    def test_wrong_reference_host_refuses_read_access_before_filesystem(self):
        with patch.object(h.os,"geteuid",return_value=0),\
             patch.object(h.socket,"gethostname",return_value="unapproved-host"):
            with self.assertRaisesRegex(h.OpticalBlocked,"protected SSL55"):
                h.preflight("/tmp/dummy")

    def test_source_integrity_rejects_modified_payload(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for name in h.SOURCES:
                (root/name).write_bytes((Path(__file__).parent/name).read_bytes())
            self.assertEqual(len(h.checked_source(root)),2)
            one=root/"command2_ssl55_win11_1_oneclick_guest_fix.ps1"
            one.write_bytes(one.read_bytes()+b"\\n#tampered")
            with self.assertRaisesRegex(h.OpticalBlocked,"checksum"):
                h.checked_source(root)

    def test_operator_declined_before_iso_create_or_change_media(self):
        with patch.object(h.sys.stdin,"isatty",return_value=True),\
             patch.object(h,"preflight",return_value={"expected":"ok"}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(h,"command",side_effect=AssertionError("no writes")):
            with self.assertRaisesRegex(h.OpticalBlocked,"declined"):
                h.apply("/tmp/dummy")

    def test_source_has_only_one_exact_libvirt_media_update_mutation(self):
        contents=Path(h.__file__).read_text(encoding="utf-8")
        for forbidden in ('"attach-interface"', '"net-start"', '"net-destroy"',
                          '"snapshot-create-as"','"shutdown"', '"destroy"',
                          '"start","win11"', '"nft","-f"',
                          '"systemctl","enable"', "flush ruleset"):
            self.assertNotIn(forbidden,contents)
        self.assertIn('virsh("change-media",VM,"sdb",str(NEW)',contents)
        self.assertIn('"--update","--live","--config"',contents)
        self.assertNotIn("--force",contents)

    def test_windows_fix_media_label_and_placeholder_for_hash(self):
        text=Path(h.__file__).read_text()
        self.assertIn('"CAPE_FIX"',text)
        self.assertIn('batch.count(b"__PS_SHA256__")==1',text)
        self.assertIn('hashlib.sha256(ps).hexdigest().upper()',text)


if __name__=="__main__":
    unittest.main()
