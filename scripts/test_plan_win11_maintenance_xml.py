#!/usr/bin/env python3
"""Pure XML fixtures: guest maintenance plan never touches libvirt or TPM."""
import unittest
import xml.etree.ElementTree as ET
import plan_win11_maintenance_xml as p

OLD="/var/lib/libvirt/images/win11.finalshutoffversion"
NEW="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
DOMAIN="""<domain type='kvm'>
<name>win11</name><uuid>289d89be-68ec-4c62-90e1-ea930849266f</uuid>
<os><nvram>/var/lib/libvirt/qemu/nvram/win11_VARS.fd</nvram></os>
<devices>
<disk type='file' device='disk'><driver name='qemu' type='qcow2'/>
<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>
<target dev='sda'/></disk>
<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>
<interface type='network'><source network='default'/><mac address='52:54:00:01:02:03'/></interface>
<redirdev bus='usb' type='spicevmc'/>
<redirdev bus='usb' type='spicevmc'/>
<redirfilter><usbdev allow='no'/></redirfilter>
<channel type='spicevmc'><target type='virtio' name='com.redhat.spice.0'/></channel>
<graphics type='spice' autoport='yes' listen='127.0.0.1'/>
</devices></domain>"""

class Tests(unittest.TestCase):
    def test_spice_redirection_removed_but_firmware_tpm_retained(self):
        rendered,summary=p.plan(DOMAIN,OLD,NEW)
        root=ET.fromstring(rendered)
        self.assertEqual(summary["temporary_removals"]["redirdev"],2)
        self.assertEqual(summary["temporary_removals"]["channel"],1)
        self.assertEqual(summary["temporary_removals"]["interface"],1)
        self.assertEqual(len(root.findall("./devices/graphics")),1)
        self.assertEqual(len(root.findall("./devices/tpm")),1)
        self.assertEqual(root.find("./os/nvram").text,
                         "/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
        self.assertEqual(root.find("./devices/disk/source").get("file"),NEW)
        self.assertEqual(len(root.findall("./devices/interface")),0)
        self.assertEqual(len(root.findall("./devices/redirdev")),0)
        self.assertEqual(DOMAIN.count("<redirdev"),2)
        self.assertFalse(summary["writes_performed"])

    def test_external_usb_redirect_fails_closed(self):
        modified=DOMAIN.replace("type='spicevmc'/>",
                                "type='tcp'/>",1)
        with self.assertRaisesRegex(p.MaintenancePlanError,"USB redirection"):
            p.plan(modified,OLD,NEW)

    def test_passthrough_fails_closed(self):
        modified=DOMAIN.replace("</devices>",
            "<hostdev mode='subsystem' type='usb'/></devices>")
        with self.assertRaisesRegex(p.MaintenancePlanError,"hostdev"):
            p.plan(modified,OLD,NEW)

    def test_extra_interface_fails_closed(self):
        modified=DOMAIN.replace("</devices>",
            "<interface type='network'><source network='default'/></interface></devices>")
        with self.assertRaisesRegex(p.MaintenancePlanError,"exactly one"):
            p.plan(modified,OLD,NEW)

    def test_external_graphics_listener_fails_closed(self):
        modified=DOMAIN.replace("listen='127.0.0.1'",
                                "listen='0.0.0.0'")
        with self.assertRaisesRegex(p.MaintenancePlanError,"graphics listener"):
            p.plan(modified,OLD,NEW)

    def test_master_source_must_match(self):
        modified=DOMAIN.replace(OLD,"/tmp/different.qcow2")
        with self.assertRaisesRegex(p.MaintenancePlanError,"master disk"):
            p.plan(modified,OLD,NEW)

    def test_custom_qemu_options_fails_closed(self):
        modified=DOMAIN.replace("</domain>",
            "<qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu'/>"
            "</domain>")
        with self.assertRaisesRegex(p.MaintenancePlanError,"QEMU command"):
            p.plan(modified,OLD,NEW)

if __name__=="__main__":
    unittest.main()
