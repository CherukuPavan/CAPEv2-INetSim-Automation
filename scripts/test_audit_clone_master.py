#!/usr/bin/env python3
"""Offline tests: never call real libvirt or touch QEMU disks."""
import unittest
import xml.etree.ElementTree as ET

import audit_clone_master as audit

DOMAIN = """<domain type='kvm'>
<name>win11</name><uuid>289d89be-68ec-4c62-90e1-ea930849266f</uuid>
<memory unit='KiB'>4194304</memory><vcpu>4</vcpu>
<os><type machine='pc-q35-8.2'>hvm</type><nvram>/tmp/nvram</nvram></os>
<devices>
<disk type='file' device='disk'><driver name='qemu' type='qcow2'/>
<source file='/var/lib/libvirt/images/win11.Afterfull'/><target dev='sda'/></disk>
<disk type='file' device='cdrom'><source file='/tmp/Win11.iso'/><target dev='sdb'/></disk>
<interface type='network'><mac address='52:54:00:62:a0:00'/>
<source network='cape-isolated'/><model type='e1000e'/></interface>
<tpm model='tpm-tis'><backend type='emulator'/></tpm>
<channel type='unix'><target name='org.qemu.guest_agent.0'/></channel>
</devices></domain>"""

SNAP = """<domainsnapshot>
<name>Afterfull</name><state>running</state><creationTime>1791583660</creationTime>
<parent><name>basicinstallwinsnapshot</name></parent>
<memory snapshot='external' file='/var/lib/libvirt/images/win11.mem'/>
<disks><disk name='sda' snapshot='external'>
<source file='/var/lib/libvirt/images/win11.Afterfull'/></disk></disks>
</domainsnapshot>"""


class VMParserTests(unittest.TestCase):
    def test_domain_extracts_disk_network_tpm(self):
        vm = audit.domain_summary(ET.fromstring(DOMAIN))
        self.assertEqual(vm["name"], "win11")
        self.assertEqual(vm["memory_kib"], 4194304)
        self.assertEqual(vm["vcpus"], 4)
        self.assertEqual(vm["disks"][0]["source_file"], "/var/lib/libvirt/images/win11.Afterfull")
        self.assertEqual(vm["interfaces"][0]["network"], "cape-isolated")
        self.assertTrue(vm["nvram_present"])
        self.assertTrue(vm["qemu_guest_agent_channel_configured"])
        self.assertEqual(vm["tpm"][0]["backend"], "emulator")

    def test_snapshot_records_memory_state_parent(self):
        snap = audit.snapshot_summary(ET.fromstring(SNAP))
        self.assertEqual(snap["name"], "Afterfull")
        self.assertEqual(snap["state"], "running")
        self.assertEqual(snap["parent"], "basicinstallwinsnapshot")
        self.assertEqual(snap["memory"]["snapshot"], "external")
        self.assertEqual(snap["disks"][0]["snapshot"], "external")

    def test_cape_parser_reads_mapping_but_never_secrets(self):
        src = """[kvm]
machines = win11,win11_1
password = confidential
[win11]
label = win11
ip = 192.0.2.11
snapshot = analysis-ready
token = confidential2
[win11_1]
label = win11_1
ip = 192.0.2.12
snapshot = analysis-ready
"""
        result = audit.cape_kvm_summary(src)
        self.assertEqual(result["sections"]["win11"]["snapshot"], "analysis-ready")
        self.assertEqual(result["sections"]["win11_1"]["ip"], "192.0.2.12")
        self.assertNotIn("password", repr(result))
        self.assertNotIn("confidential", repr(result))
        self.assertNotIn("token", repr(result))


    def test_network_nat_is_detectable(self):
        network = ET.fromstring("<network><name>default</name><forward mode='nat'/><bridge name='virbr0'/></network>")
        self.assertEqual(audit.network_summary(network)["forward_mode"], "nat")

    def test_network_no_forward(self):
        net = ET.fromstring("<network><name>cape</name><bridge name='virbr2'/></network>")
        self.assertIsNone(audit.network_summary(net)["forward_mode"])

    def test_error_xml_does_not_leak_raw_xml(self):
        warning = []
        result = audit.checked_xml({"ok": False, "stdout": "",
                  "error": "no permission", "exit_code": 1}, "VM", warning)
        self.assertIsNone(result)
        self.assertIn("no permission", warning[0])

    def test_unsafe_vm_name_rejected_before_subprocess(self):
        with self.assertRaises(ValueError):
            audit.collect("win11;touch /tmp/bad")

    def test_missing_os_memory_units(self):
        vm = audit.domain_summary(ET.fromstring("<domain><name>test</name><devices/></domain>"))
        self.assertIsNone(vm["memory_kib"])
        self.assertEqual(vm["disks"], [])
        self.assertEqual(vm["interfaces"], [])

    def test_read_only_command_is_subprocess_without_shell(self):
        class FakeProc:
            returncode = 0
            stdout = "shut off\n"
            stderr = ""
        from unittest.mock import patch
        with patch.object(audit.subprocess, "run", return_value=FakeProc()) as fake:
            x = audit.virsh("domstate", "win11")
        self.assertEqual(x["stdout"].strip(), "shut off")
        self.assertEqual(fake.call_args.args[0][:4],
            ("sudo", "-n", "virsh", "-c"))
        self.assertFalse(fake.call_args.kwargs.get("shell", False))


if __name__ == "__main__":
    unittest.main()
