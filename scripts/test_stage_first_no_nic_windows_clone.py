#!/usr/bin/env python3
"""Pure XML safety fixtures; never create VMs or copy Windows image."""
import unittest
import xml.etree.ElementTree as ET
import stage_first_no_nic_windows_clone as s
from test_clone_domain_xml import MASTER

U="af0ba1c2-f4c4-49a5-9111-513a9c405cae"

def fixture():
    return MASTER.replace(
        "<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>",
        "<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>"
    )

class Tests(unittest.TestCase):
    def test_zero_nic_fresh_tpm_uuid_and_disk(self):
        root=ET.fromstring(s.render(fixture(),identifier=U))
        self.assertEqual(root.findtext("name"),s.NAME)
        self.assertEqual(root.findtext("uuid"),U)
        self.assertEqual(root.findall("./devices/interface"),[])
        self.assertEqual(root.findall("./devices/redirdev"),[])
        self.assertEqual(root.findall("./devices/channel"),[])
        self.assertEqual(root.find("./devices/disk[@device='disk']/source").get("file"),
                         str(s.DISK))
        self.assertEqual(root.findtext("./os/nvram"),str(s.NVRAM))
        self.assertEqual(root.find("./devices/tpm/backend").get("type"),
                         "emulator")
        self.assertEqual(root.find("./devices/graphics").get("listen"),
                         "127.0.0.1")

    def test_reject_unsafe_guest_share(self):
        xml=fixture().replace("</devices>",
                              "<filesystem type='mount'/></devices>")
        with self.assertRaisesRegex(s.StageError,"host-connected"):
            s.render(xml,identifier=U)

    def test_reject_wrong_master_disk(self):
        xml=fixture().replace("win11.finalshutoffversion",
                              "win11.cape-bitlocker-maintenance.qcow2")
        with self.assertRaisesRegex(s.StageError,"unexpected disk"):
            s.render(xml,identifier=U)

    def test_reject_persisting_nat_network(self):
        xml=fixture().replace("network='default'","network='campus'")
        with self.assertRaisesRegex(s.StageError,"network attachment"):
            s.render(xml,identifier=U)

    def test_reject_embedded_shared_tpm_state(self):
        xml=fixture().replace(
            "<backend type='emulator' version='2.0'/>",
            "<backend type='emulator' version='2.0'><source path='/old-tpm'/></backend>"
        )
        with self.assertRaisesRegex(s.StageError,"state path"):
            s.render(xml,identifier=U)

    def test_no_implicit_source_qemu_passthrough(self):
        xml=fixture().replace("</domain>",
                 "<qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu/'>"
                 "<qemu:arg value='--device'/></qemu:commandline></domain>")
        with self.assertRaisesRegex(s.StageError,"QEMU extension"):
            s.render(xml,identifier=U)

    def test_guest_ip_not_personalized_and_no_guest_started(self):
        self.assertIn("zero-NIC",s.__doc__)
        self.assertIn("no guest IP address/hostname customization yet",
                      s.__doc__.lower())

if __name__=="__main__":
    unittest.main()
