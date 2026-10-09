#!/usr/bin/env python3
"""All synthetic: no real Windows disk or host command is accessed."""
import unittest
from unittest.mock import patch
import personalize_clone_windows as p

G="{12345678-1234-1234-1234-123456789ABC}"
PATH=(r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001"
      r"\Services\Tcpip\Parameters\Interfaces"+"\\"+G)
OLD="198.51.100.105"
NEW="198.51.100.110"

class Tests(unittest.TestCase):
    def registry(self):
        return "\n".join([
            "Windows Registry Editor Version 5.00", "", "["+PATH+"]",
            '"EnableDHCP"=dword:00000000',
            '"IPAddress"='+p.multi_literal([OLD]),
            '"SubnetMask"='+p.multi_literal(["255.255.255.0"]), "",
        ])

    def test_roundtrip_multistring(self):
        self.assertEqual(p.registry_multisz(p.multi_literal([OLD])), [OLD])

    def test_find_original_interface(self):
        guid, options = p.find_interface(self.registry(), OLD)
        self.assertEqual(guid, G)
        self.assertEqual(options["original_mask"], "255.255.255.0")

    def test_missing_ip_blocks(self):
        with self.assertRaisesRegex(p.Stop, "exactly one"):
            p.find_interface(self.registry(), "203.0.113.5")

    def test_multiple_matching_ips_blocks(self):
        text=self.registry()
        text=text.replace(p.multi_literal([OLD]), p.multi_literal([OLD,"198.51.100.106"]))
        with self.assertRaisesRegex(p.Stop, "multiple"):
            p.find_interface(text, OLD)

    def test_dhcp_enabled_blocks(self):
        with self.assertRaisesRegex(p.Stop,"DHCP-disabled"):
            p.find_interface(self.registry().replace("dword:00000000", "dword:00000001"), OLD)

    def test_multiple_interfaces_with_same_ip_blocks(self):
        another="{87654321-1234-1234-1234-123456789ABC}"
        duplicate=self.registry().replace(G,another)
        with self.assertRaisesRegex(p.Stop, "exactly one"):
            p.find_interface(self.registry()+"\n"+duplicate, OLD)

    def test_registry_patch_contains_only_required_fields(self):
        result=p.patch_contents(1,G,"WIN11-1",NEW,"255.255.255.0","198.51.100.1")
        self.assertIn(f'"IPAddress"={p.multi_literal([NEW])}',result)
        self.assertIn(r"\Control\ComputerName\ComputerName",result)
        self.assertIn('"EnableDHCP"=dword:00000000',result)
        self.assertNotIn("Defender",result)

    def test_bad_controlset(self):
        with self.assertRaises(p.Stop):
            p.parse_select('[HKEY_LOCAL_MACHINE\\SYSTEM\\Select]\n"Current"=dword:00000000')
        self.assertEqual(p.parse_select('"Current"=dword:00000002'),2)

    def test_bad_ip(self):
        with self.assertRaises(p.Stop):
            p.validate_addresses(OLD,"198.51.100.0","255.255.255.0",None)
        with self.assertRaises(p.Stop):
            p.validate_addresses(OLD,OLD,"255.255.255.0",None)

    def test_bad_hostname(self):
        with self.assertRaisesRegex(p.Stop,"hostname"):
            p.patch_contents(1,G,"WIN11_UNSAFE",NEW,"255.255.255.0",None)

    def test_plan_does_not_modify_disk(self):
        def cmd(*args, **kwargs):
            self.assertEqual(args[0],"virt-win-reg")
            if args[-1]==r"HKLM\SYSTEM\Select":
                return '"Current"=dword:00000001'
            return self.registry()
        with patch.object(p,"disk_guard"),patch.object(p,"execute",side_effect=cmd) as executor:
            result=p.prepare(__import__("pathlib").Path("/clone.qcow2"),
                             OLD,NEW,"WIN11-1","255.255.255.0",None,"plan")
        self.assertEqual(result["status"],"PLAN_ONLY")
        self.assertEqual(executor.call_count,2)

if __name__=="__main__":
    unittest.main()
