#!/usr/bin/env python3
"""Synthetic, offline-only preservation audit tests. No libvirt calls."""
import unittest
import audit_win11_bitlocker_working_overlay as pre

DOMAIN="""<domain><name>win11</name><uuid>289d89be-68ec-4c62-90e1-ea930849266f</uuid>
<os><nvram>/var/lib/libvirt/qemu/nvram/win11_VARS.fd</nvram></os>
<devices><disk type='file' device='disk'><driver type='qcow2'/>
<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>
<target dev='sda'/></disk>
<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>
<interface type='network'><source network='default'/><link state='down'/></interface>
</devices></domain>"""
SNAP="""<domainsnapshot><name>finalshutoffversion</name>
<state>shutoff</state><memory snapshot='no'/>
<disks><disk name='sda' snapshot='external'>
<source file='/var/lib/libvirt/images/win11.finalshutoffversion'/>
</disk></disks></domainsnapshot>"""


class LayoutTests(unittest.TestCase):
    def test_valid_cold_master_metadata(self):
        result=pre.xml_summary(DOMAIN,SNAP)
        self.assertEqual(result["tpm_backend"],"emulator")
        self.assertEqual(result["tpm_version"],"2.0")
        self.assertEqual(result["existing_nic_link_state"],"down")
        self.assertEqual(result["nic_source_network"],"default")
        self.assertEqual(result["target"],"sda")

    def test_running_snapshot_blocked(self):
        with self.assertRaisesRegex(pre.AuditFailure,"shut-off"):
            pre.xml_summary(DOMAIN,SNAP.replace("shutoff","running"))

    def test_saved_ram_blocked(self):
        with self.assertRaisesRegex(pre.AuditFailure,"memory"):
            pre.xml_summary(DOMAIN,SNAP.replace("snapshot='no'","snapshot='external'"))

    def test_unpaired_snapshot_disk_blocked(self):
        with self.assertRaisesRegex(pre.AuditFailure,"differs"):
            pre.xml_summary(DOMAIN,
                SNAP.replace("win11.finalshutoffversion","wrong-image"))

    def test_absent_tpm_blocked(self):
        altered=DOMAIN.replace(
            "<tpm model='tpm-crb'><backend type='emulator' version='2.0'/></tpm>","")
        with self.assertRaisesRegex(pre.AuditFailure,"TPM"):
            pre.xml_summary(altered,SNAP)

    def test_non_emulated_tpm_blocked(self):
        altered=DOMAIN.replace("type='emulator'","type='passthrough'")
        with self.assertRaisesRegex(pre.AuditFailure,"emulator"):
            pre.xml_summary(altered,SNAP)

    def test_multiple_nics_blocked(self):
        altered=DOMAIN.replace("</devices>",
            "<interface type='network'><source network='default'/></interface></devices>")
        with self.assertRaisesRegex(pre.AuditFailure,"exactly one"):
            pre.xml_summary(altered,SNAP)

    def test_invalid_uefi_nvram_blocked(self):
        with self.assertRaisesRegex(pre.AuditFailure,"NVRAM"):
            pre.xml_summary(DOMAIN.replace(
                "<nvram>/var/lib/libvirt/qemu/nvram/win11_VARS.fd</nvram>",""),SNAP)


if __name__=="__main__":
    unittest.main()
