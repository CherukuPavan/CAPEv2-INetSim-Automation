"""Offline-only synthetic tests of read-only SSL55 runtime L2 guard."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import command2_ssl55_l2_runtime_readonly as s

def xml(*,net=None,uid=None,backing=False,target="vnet1"):
    chain=('<backingStore><source file="/tmp/master.qcow2"/></backingStore>'
           if backing else '<backingStore/>')
    return (
        '<domain><name>'+s.VM+'</name><uuid>'+str(uid or s.UID)+
        '</uuid><os><nvram>'+s.VARS+'</nvram></os><devices>'+
        '<disk device="disk"><driver type="qcow2"/>'
        '<source file="'+s.DISK+'"/>'+chain+'</disk>'+
        '<tpm><backend type="emulator" version="2.0"/></tpm>'+
        '<interface type="network"><mac address="'+s.NIC_MAC+'"/>'
        '<source network="'+str(net or s.NETWORK)+'"/>'
        '<target dev="'+target+'"/></interface></devices></domain>'
    )

class RuntimeXmlTests(unittest.TestCase):
    def test_expected_live_xml_returns_tap(self):
        self.assertEqual(s.xml_check(xml(),True),"vnet1")
    def test_saved_xml_does_not_require_tap(self):
        self.assertIsNone(s.xml_check(xml(),False))
    def test_master_backing_chain_blocks(self):
        with self.assertRaisesRegex(s.Blocked,"backing"):
            s.xml_check(xml(backing=True),True)
    def test_nat_nic_blocks(self):
        with self.assertRaisesRegex(s.Blocked,"MAC/isolated"):
            s.xml_check(xml(net="default"),True)
    def test_wrong_identity_blocks(self):
        with self.assertRaisesRegex(s.Blocked,"identity"):
            s.xml_check(xml(uid="other"),True)
    def test_bad_target_blocks(self):
        with self.assertRaisesRegex(s.Blocked,"TAP"):
            s.xml_check(xml(target="eno1"),True)

class KernelL2Tests(unittest.TestCase):
    def fake_sys(self,temp,isolated="1",extra=False):
        base=Path(temp)
        br=base/s.BRIDGE
        (br/"bridge").mkdir(parents=True)
        (br/"brif").mkdir()
        tap=base/"vnet1"
        (tap/"brport").mkdir(parents=True)
        (tap/"brport"/"isolated").write_text(isolated+"\n")
        (tap/"master").symlink_to(br)
        (br/"brif"/"vnet1").symlink_to(tap)
        if extra:
            (br/"brif"/"vnet2").symlink_to(tap)
        return base
    def test_single_isolated_tap_pass(self):
        with TemporaryDirectory() as root:
            sysroot=self.fake_sys(root)
            data=s.bridge_config("vnet1",sysroot)
            self.assertEqual(data["tap_kernel_isolated_flag"],1)
            self.assertEqual(data["bridge_member_ports"],["vnet1"])
    def test_no_kernel_isolation_bit_refused(self):
        with TemporaryDirectory() as root:
            sysroot=self.fake_sys(root,isolated="0")
            with self.assertRaisesRegex(s.Blocked,"NOT enabled"):
                s.bridge_config("vnet1",sysroot)
    def test_second_bridge_member_blocks(self):
        with TemporaryDirectory() as root:
            sysroot=self.fake_sys(root,extra=True)
            with self.assertRaisesRegex(s.Blocked,"other port"):
                s.bridge_config("vnet1",sysroot)
    def test_wrong_bridge_master_refused(self):
        with TemporaryDirectory() as root:
            sysroot=self.fake_sys(root)
            (sysroot/"vnet1"/"master").unlink()
            (sysroot/"vnet1"/"master").symlink_to(sysroot/"other-bridge")
            with self.assertRaisesRegex(s.Blocked,"not enslaved"):
                s.bridge_config("vnet1",sysroot)
    def test_src_no_mutations(self):
        content=Path(s.__file__).read_text()
        for needle in ('virsh("start"', 'virsh("destroy"', 'virsh("net-start"',
                       'virsh("snapshot-create"', 'virsh("shutdown"',
                       '"nft","add"', '"nft","delete"',
                       'virsh("attach-interface"', 'virsh("change-media"'):
            self.assertNotIn(needle,content)

class NetworkShapeTests(unittest.TestCase):
    def test_active_libvirt_whitespace_fields(self):
        values=s.props("Active:         yes\nAutostart:      no\n"
                       "Bridge:         cape-lab0\nPersistent:     yes")
        self.assertEqual(values["active"],"yes")
    def test_duplicate_status_field_refused(self):
        with self.assertRaisesRegex(s.Blocked,"Duplicate"):
            s.props("Active: yes\nActive: no")
    def test_expected_network_no_forward(self):
        net=('<network><name>cape-analysis-isolated</name>'
             '<bridge name="cape-lab0"/><port isolated="yes"/>'
             '<dns enable="no"/>'
             '<ip address="192.168.240.1" netmask="255.255.255.0"/>'
             '</network>')
        def fake_vm(*args):
            if args[0]=="net-info":
                return "Active: yes\nPersistent: yes\nAutostart: no\nBridge: cape-lab0"
            return net
        with patch.object(s,"virsh",side_effect=fake_vm):
            self.assertTrue(s.network_preflight())
    def test_nat_forward_refused(self):
        net=('<network><name>cape-analysis-isolated</name>'
             '<bridge name="cape-lab0"/><port isolated="yes"/>'
             '<dns enable="no"/><forward mode="nat"/>'
             '<ip address="192.168.240.1" netmask="255.255.255.0"/>'
             '</network>')
        with patch.object(s,"virsh",side_effect=lambda *a: (
             "Active: yes\nPersistent: yes\nAutostart: no\nBridge: cape-lab0"
             if a[0]=="net-info" else net)):
            with self.assertRaisesRegex(s.Blocked,"no longer"):
                s.network_preflight()

if __name__=="__main__":
    unittest.main()
