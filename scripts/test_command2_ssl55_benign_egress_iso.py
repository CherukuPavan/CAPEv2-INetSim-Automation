"""Offline tests for exact SSL55 benign-ISO gate; no host mutations."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_benign_egress_iso as b

def xml(*,source=None,network="cape-analysis-isolated",cdrom="sdb"):
    media=str(source or b.OLD)
    return (f'<domain><name>{b.VM}</name><uuid>{b.UUID}</uuid>'
            '<os><nvram>/var/lib/libvirt/qemu/nvram/'
            'win11_1.command2_VARS.fd</nvram></os><devices>'
            '<disk device="disk"><source file="'+b.DISK+'"/>'
            '<backingStore/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '<interface><mac address="02:0a:30:6a:3f:50"/>'
            f'<source network="{network}"/></interface>'
            '<disk type="file" device="cdrom"><source file="'+media+'"/>'
            f'<target dev="{cdrom}"/><readonly/></disk>'
            '</devices></domain>')

class IsoGuards(unittest.TestCase):
    def test_reviewed_optical_model(self):
        self.assertEqual(b.domxml(xml())["target"],"sdb")
    def test_does_not_change_system_disk(self):
        with self.assertRaisesRegex(b.Blocked,"primary"):
            b.domxml(xml().replace(b.DISK,"/tmp/other.qcow2"))
    def test_refuse_new_media_before_user_authorization(self):
        with self.assertRaisesRegex(b.Blocked,"original reviewable"):
            b.domxml(xml(source=b.NEW))
    def test_wrong_nic_refused(self):
        with self.assertRaisesRegex(b.Blocked,"NIC"):
            b.domxml(xml(network="default"))
    def test_wrong_cd_drive_refused(self):
        with self.assertRaisesRegex(b.Blocked,"Optical"):
            b.domxml(xml(cdrom="hdc"))
    def test_noninteractive_apply_no_mutation(self):
        with patch.object(b.sys.stdin,"isatty",return_value=False),\
             patch.object(b,"plan",side_effect=AssertionError("Must not plan")):
            with self.assertRaisesRegex(b.Blocked,"terminal"):
                b.apply(Path("p"),Path("c"))
    def test_declined_approval_does_not_run_media_update(self):
        with patch.object(b.sys.stdin,"isatty",return_value=True),\
             patch.object(b,"plan",return_value={"result":"PLAN"}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(b,"virsh",side_effect=AssertionError("No mutation")):
            with self.assertRaisesRegex(b.Blocked,"approve"):
                b.apply(Path("p"),Path("c"))
    def test_source_does_not_use_force_or_guest_exec(self):
        source=Path(b.__file__).read_text()
        for needle in ('virsh("destroy"', 'virsh("shutdown"',
                       'virsh("attach-interface"', 'virsh("snapshot-',
                       'virsh("net-start"', 'virsh("net-autostart"',
                       '"--force"', '"qemu-monitor-command"'):
            self.assertNotIn(needle,source)

if __name__=="__main__":
    unittest.main()
