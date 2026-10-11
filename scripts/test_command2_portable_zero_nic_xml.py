"""No-NIC portable libvirt renderer regression tests (pure XML fixtures)."""
import unittest
import uuid
import xml.etree.ElementTree as ET
from unittest.mock import patch

import command2_portable_zero_nic_xml as x


MASTER_DISK="/var/lib/libvirt/images/master_win11.qcow2"
MASTER_NV="/var/lib/libvirt/qemu/nvram/master_VARS.fd"

def source_xml(nic='<interface type="network"><source network="default"/></interface>',
               extra="", backend='type="emulator" version="2.0"'):
    return (f'<domain type="kvm"><name>win11</name>'
            f'<uuid>{uuid.UUID(int=1)}</uuid>'
            f'<os><type arch="x86_64">hvm</type>'
            f'<nvram template="/usr/share/OVMF/OVMF_VARS.fd">{MASTER_NV}</nvram></os>'
            '<devices>'
            f'<disk type="file" device="disk"><driver name="qemu" type="qcow2"/>'
            f'<source file="{MASTER_DISK}"/></disk>'
            '<disk type="file" device="cdrom"><source file="/tmp/installer.iso"/></disk>'
            '<tpm model="tpm-crb"><backend '+backend+'/></tpm>'
            '<graphics type="spice" port="5900" listen="0.0.0.0" passwd="secret">'
            '<listen type="address" address="0.0.0.0"/></graphics>'
            + nic+extra+'</devices><genid>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</genid>'
            '<seclabel type="dynamic"/></domain>')


def guest(i=1):
    return {"libvirt_name":f"win11_{i}",
            "libvirt_uuid_candidate":str(uuid.UUID(int=i+10)),
            "smbios_generation_id_candidate":str(uuid.UUID(int=i+100)),
            "windows_hostname_target":f"WIN11-{i}",
            "disk_target":f"/var/lib/libvirt/images/win11_{i}.command2.qcow2",
            "uefi_nvram_target":f"/var/lib/libvirt/qemu/nvram/win11_{i}.command2_VARS.fd",
            "nic_attached":False,
            "static_ipv4_applied":False,
            "per_vm_tpm_state_must_be_fresh":True}


def render(raw=None, item=None):
    return x.render_no_nic(raw if raw is not None else source_xml(),
                           item if item is not None else guest(),
                           expected_master_disk=MASTER_DISK,
                           expected_master_nvram=MASTER_NV)


class Tests(unittest.TestCase):
    def test_independent_domain_no_nic_and_private_graphics(self):
        xml=render()
        root=ET.fromstring(xml)
        self.assertEqual(root.findtext("name"),"win11_1")
        self.assertEqual(root.findtext("uuid"),guest()["libvirt_uuid_candidate"])
        self.assertEqual(root.findtext("genid"),guest()["smbios_generation_id_candidate"])
        self.assertEqual(root.findtext("./os/nvram"),guest()["uefi_nvram_target"])
        self.assertEqual(root.find("./devices/disk[@device='disk']/source").get("file"),
                         guest()["disk_target"])
        self.assertFalse(root.findall("./devices/interface"))
        self.assertIsNone(root.find("./devices/disk[@device='cdrom']/source"))
        graphics=root.find("./devices/graphics")
        self.assertEqual(graphics.get("listen"),"127.0.0.1")
        self.assertEqual(graphics.get("port"),"-1")
        self.assertNotIn("passwd",graphics.attrib)
        self.assertEqual(graphics.find("listen").get("address"),"127.0.0.1")
        self.assertIsNone(root.find("seclabel"))
        self.assertEqual(ET.fromstring(source_xml()).find("./devices/interface").get("type"),
                         "network")  # source fixture not mutated

    def test_bridged_source_nic_removed_instead_of_inherited(self):
        raw=source_xml(nic='<interface type="bridge"><source bridge="campus0"/></interface>')
        self.assertFalse(ET.fromstring(render(raw)).findall("./devices/interface"))

    def test_reject_direct_or_host_passthrough_network(self):
        for nic in ('<interface type="direct"/>', '<interface type="hostdev"/>'):
            with self.subTest(nic=nic), self.assertRaisesRegex(x.XMLBlocked,"passthrough"):
                render(source_xml(nic=nic))

    def test_reject_other_host_connected_devices(self):
        for device in ('hostdev','filesystem','smartcard','redirdev','channel','vsock'):
            with self.subTest(tag=device), self.assertRaisesRegex(x.XMLBlocked,"host-connected"):
                render(source_xml(extra=f'<{device}/>' ))

    def test_reject_wrong_master_disk_or_uefi(self):
        with self.assertRaisesRegex(x.XMLBlocked,"source OS disk"):
            render(source_xml().replace(MASTER_DISK,"/var/lib/libvirt/images/different.qcow2"))
        with self.assertRaisesRegex(x.XMLBlocked,"NVRAM"):
            render(source_xml().replace(MASTER_NV,"/tmp/unverified.vars"))
        with self.assertRaisesRegex(x.XMLBlocked,"master XML"):
            render(source_xml().replace("<name>win11</name>","<name>random</name>"))

    def test_reject_reused_master_or_same_disk_nvram(self):
        item=guest();item["disk_target"]=MASTER_DISK
        with self.assertRaisesRegex(x.XMLBlocked,"master paths"):
            render(item=item)
        item=guest();item["uefi_nvram_target"]=item["disk_target"]
        with self.assertRaisesRegex(x.XMLBlocked,"master paths"):
            render(item=item)

    def test_reject_explicit_tpm_source_or_encryption(self):
        raw=source_xml(backend='type="emulator" version="2.0"')
        raw=raw.replace('<backend type="emulator" version="2.0"/>',
                        '<backend type="emulator" version="2.0">'
                        '<source path="/var/lib/libvirt/swtpm/win11"/></backend>')
        with self.assertRaisesRegex(x.XMLBlocked,"TPM backend"):
            render(raw)

    def test_bad_guest_identity_and_existing_nic_refused(self):
        item=guest();item["nic_attached"]=True
        with self.assertRaisesRegex(x.XMLBlocked,"zero-NIC"):
            render(item=item)
        item=guest();item["libvirt_uuid_candidate"]="bad-id"
        with self.assertRaisesRegex(x.XMLBlocked,"UUID"):
            render(item=item)
        item=guest();item["windows_hostname_target"]="WRONG"
        with self.assertRaisesRegex(x.XMLBlocked,"Unexpected clone"):
            render(item=item)

    def test_extraneous_qemu_commandline_rejected(self):
        raw=source_xml().replace("</domain>","<qemu:commandline "
            'xmlns:qemu="http://libvirt.org/schemas/domain/qemu">'
            '<qemu:arg value="-netdev"/></qemu:commandline></domain>')
        with self.assertRaisesRegex(x.XMLBlocked,"commandline"):
            render(raw)

    def test_networkless_model_and_no_host_mutation_modules(self):
        import inspect
        text=inspect.getsource(x)
        for forbidden in ('subprocess','virsh ','sudo ','qemu-img ',
                          'libvirt.open(','os.system(','rclone '):
            self.assertNotIn(forbidden,text)


if __name__=="__main__":
    unittest.main()
