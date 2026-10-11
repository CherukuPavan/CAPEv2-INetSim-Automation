"""Mock-only libvirt network audit: NEVER touches real SSL-55."""
import json
import unittest
from unittest.mock import patch

import command2_ssl55_network_readonly_audit as audit


def xml(name, identity, iface=""):
    return (f'<domain><name>{name}</name><uuid>{identity}</uuid>'
            f'<devices>{iface}</devices></domain>')


class NetworkAuditTests(unittest.TestCase):
    def test_parses_master_default_and_clone_zero_nics(self):
        v=audit.network_interfaces(xml(
            "win11",audit.VM_IDS["win11"],
            '<interface type="network"><source network="default"/>'
            '<model type="virtio"/><mac address="52:54:00:00:01:01"/>'
            '</interface>'),"win11",audit.VM_IDS["win11"])
        self.assertEqual(len(v),1)
        self.assertEqual(v[0]["source_network"],"default")
        self.assertTrue(v[0]["mac_present"])
        self.assertEqual(audit.network_interfaces(
            xml("win11_1",audit.VM_IDS["win11_1"]),
            "win11_1",audit.VM_IDS["win11_1"]),[])

    def test_refuses_mismatched_name_and_uuid(self):
        with self.assertRaisesRegex(audit.AuditBlocked,"identity"):
            audit.network_interfaces(xml("unrelated",audit.VM_IDS["win11"]),
                                     "win11",audit.VM_IDS["win11"])
        with self.assertRaisesRegex(audit.AuditBlocked,"identity"):
            audit.network_interfaces(xml("win11","broken"),
                                     "win11",audit.VM_IDS["win11"])

    def test_end_to_end_mock_inventory_without_changes(self):
        nic='<interface type="network"><source network="default"/></interface>'
        def fake_virsh(*args):
            if args[0]=="domuuid":
                return audit.VM_IDS[args[1]]
            if args[0]=="domstate":
                return "running" if args[1]=="win11_1" else "shut off"
            if args[0]=="dumpxml":
                v=args[-1]
                return xml(v,audit.VM_IDS[v],nic if v=="win11" else "")
            if args == ("net-info",audit.LAB_NETWORK):
                return "Active: no\nAutostart: no\nBridge: cape-lab0\n"
            self.fail("unreviewed command: "+str(args))
        with patch.object(audit.socket,"gethostname",return_value="CSE-SSL-55.edu"),\
             patch.object(audit,"virsh",side_effect=fake_virsh):
            out=audit.inventory()
        self.assertEqual(out["protected_domains"]["win11"]["interface_counts"]["inactive"],1)
        self.assertEqual(out["protected_domains"]["win11_1"]["interface_counts"]["live"],0)
        self.assertTrue(out["analysis_network_known_off"])
        self.assertFalse(out["win11_1_nic_attach_authorized"])
        self.assertFalse(out["host_changed"])

    def test_refuses_non_reference_host_before_any_host_command(self):
        with patch.object(audit.socket,"gethostname",return_value="new-deployment-host"),\
             patch.object(audit,"virsh",side_effect=AssertionError("Should not query libvirt")):
            with self.assertRaisesRegex(audit.AuditBlocked,"SSL-55"):
                audit.inventory()

    def test_no_write_commands_present(self):
        from pathlib import Path
        source=Path(audit.__file__).read_text(encoding="utf-8")
        for dangerous in ("net-start","net-define","attach-interface","update-device",
                          "start --", "virsh destroy","virsh define", "nft add",
                          "subprocess.Popen", "qemu-img convert", "os.system"):
            self.assertNotIn(dangerous,source)


if __name__=="__main__":
    unittest.main()
