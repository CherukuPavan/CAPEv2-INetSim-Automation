#!/usr/bin/env python3
"""Offline pure XML guards for original-TPM Windows maintenance boot."""
import unittest
import xml.etree.ElementTree as ET
import start_win11_isolated_bitlocker_maintenance as b
import plan_win11_maintenance_xml as p
from test_plan_win11_maintenance_xml import DOMAIN, OLD, NEW

class Tests(unittest.TestCase):
    def setUp(self):
        self.original=ET.fromstring(DOMAIN)
        self.tpm=ET.tostring(self.original.find("./devices/tpm"))
        self.nvram=self.original.find("./os/nvram").text
        self.uid=self.original.findtext("./uuid")
        self.planned,_=p.plan(DOMAIN,OLD,NEW)

    def verify(self,xml):
        b.xml_host_safe(xml,self.uid,self.tpm,self.nvram)

    def test_sanitized_xml_passes(self):
        self.verify(self.planned)

    def test_adding_network_interface_is_blocked(self):
        root=ET.fromstring(self.planned)
        devices=root.find("devices")
        interfaces=ET.SubElement(devices,"interface",{"type":"network"})
        ET.SubElement(interfaces,"source",{"network":"default"})
        with self.assertRaisesRegex(b.MaintenanceBootError,"host-connected"):
            self.verify(ET.tostring(root,encoding="unicode"))

    def test_spice_redirdev_is_blocked(self):
        root=ET.fromstring(self.planned)
        ET.SubElement(root.find("devices"),"redirdev",
                      {"type":"spicevmc","bus":"usb"})
        with self.assertRaisesRegex(b.MaintenanceBootError,"host-connected"):
            self.verify(ET.tostring(root,encoding="unicode"))

    def test_tpm_replacement_is_blocked(self):
        root=ET.fromstring(self.planned)
        root.find("./devices/tpm/backend").set("version","1.2")
        with self.assertRaisesRegex(b.MaintenanceBootError,"TPM"):
            self.verify(ET.tostring(root,encoding="unicode"))

    def test_libvirt_live_tpm_socket_is_allowed(self):
        root=ET.fromstring(self.planned)
        ET.SubElement(root.find("./devices/tpm/backend"),"source",
                      {"type":"unix","mode":"connect",
                       "path":"/run/libvirt/qemu/swtpm-test.sock"})
        self.verify(ET.tostring(root,encoding="unicode"))

    def test_switch_back_to_original_disk_is_blocked(self):
        root=ET.fromstring(self.planned)
        root.find("./devices/disk/source").set("file",OLD)
        with self.assertRaisesRegex(b.MaintenanceBootError,"maintenance overlay"):
            self.verify(ET.tostring(root,encoding="unicode"))

    def test_nvram_mismatch_is_blocked(self):
        root=ET.fromstring(self.planned)
        root.find("./os/nvram").text="/tmp/new-firmware-vars.fd"
        with self.assertRaisesRegex(b.MaintenanceBootError,"UEFI"):
            self.verify(ET.tostring(root,encoding="unicode"))

if __name__=="__main__":
    unittest.main()
