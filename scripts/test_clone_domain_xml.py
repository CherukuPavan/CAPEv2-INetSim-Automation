#!/usr/bin/env python3
"""No libvirt required; synthetic XML regression suite."""
import unittest
import xml.etree.ElementTree as ET
import clone_domain_xml as m

MASTER="""<domain type='kvm'><name>win11</name>
<uuid>289d89be-68ec-4c62-90e1-ea930849266f</uuid>
<memory unit='KiB'>4194304</memory><vcpu>4</vcpu>
<os><type>hvm</type><nvram>/var/lib/libvirt/qemu/nvram/win11_VARS.fd</nvram></os>
<devices><disk type='file' device='disk'><driver type='qcow2'/>
<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>
<target dev='sda' bus='sata'/></disk>
<interface type='network'><mac address='52:54:00:62:a0:00'/>
<source network='default'/><model type='e1000e'/></interface>
<tpm model='tpm-tis'><backend type='emulator' version='2.0'/></tpm>
<graphics type='spice' port='5900' listen='127.0.0.1' autoport='no'/>
</devices></domain>"""

def render(xml=MASTER):
    return m.render(xml, name="win11_1",
        uuid_value="a1a1a1a1-1234-4444-8888-bbbbbbbbbbbb",
        mac="02:11:22:33:44:55",
        clone_disk="/var/lib/libvirt/images/cape/win11_1.qcow2",
        clone_nvram="/var/lib/libvirt/qemu/nvram/win11_1_VARS.fd",
        isolated_network="cape-isolated")

class Tests(unittest.TestCase):
    def test_preserves_hardware_and_replaces_identifiers(self):
        out=ET.fromstring(render())
        info=m.analyze_static(ET.tostring(out,encoding="unicode"))
        self.assertEqual(info["name"],"win11_1")
        self.assertEqual(info["mac"],"02:11:22:33:44:55")
        self.assertEqual(info["network"],"cape-isolated")
        self.assertNotIn("finalshutoffversion",info["disk"])
        self.assertIn("win11_1",info["nvram"])
        self.assertEqual(out.findtext("vcpu"),"4")
        self.assertEqual(out.find("devices/graphics").get("port"),"-1")
        self.assertEqual(out.find("devices/graphics").get("autoport"),"yes")
        self.assertEqual(out.find("devices/disk/target").get("bus"),"sata")

    def test_rejects_same_name(self):
        with self.assertRaisesRegex(m.UnsafeDefinition,"name matches"):
            m.render(MASTER,name="win11",uuid_value="a1a1a1a1-1234-4444-8888-bbbbbbbbbbbb",
                     mac="02:11:22:33:44:55",clone_disk="/var/lib/libvirt/images/clone.qcow2",
                     clone_nvram="/var/lib/libvirt/qemu/nvram/new.fd",isolated_network="cape-isolated")

    def test_rejects_host_passthrough(self):
        xml=MASTER.replace("</devices>","<hostdev mode='subsystem' type='pci'/></devices>")
        with self.assertRaisesRegex(m.UnsafeDefinition,"passthrough"):
            render(xml)

    def test_rejects_direct_nat(self):
        with self.assertRaisesRegex(m.UnsafeDefinition,"forwarding"):
            m.validate_no_forward_network("<network><forward mode='nat'/><bridge name='virbr0'/></network>")

    def test_accepts_nonforwarding_but_not_certified(self):
        m.validate_no_forward_network("<network><bridge name='virbr2'/></network>")

    def test_blocks_duplicate_master_nvram(self):
        with self.assertRaisesRegex(m.UnsafeDefinition,"alias"):
            m.render(MASTER,name="win11_1",
                     uuid_value="a1a1a1a1-1234-4444-8888-bbbbbbbbbbbb",
                     mac="02:11:22:33:44:55",
                     clone_disk="/var/lib/libvirt/images/clone.qcow2",
                     clone_nvram="/var/lib/libvirt/qemu/nvram/win11_VARS.fd",
                     isolated_network="cape-isolated")

    def test_tpm_state_source_must_not_be_shared(self):
        xml=MASTER.replace("version='2.0'/>","version='2.0'><source path='/shared/tpm'/></backend>")
        with self.assertRaises(m.UnsafeDefinition):
            render(xml)

if __name__=="__main__":
    unittest.main()
