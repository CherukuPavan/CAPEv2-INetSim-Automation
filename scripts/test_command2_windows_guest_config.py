"""Offline Windows personalization config validation; no guest actions."""
from pathlib import Path
import unittest
import command2_windows_guest_config as cfg


def identity(i):
    return {"libvirt_name":f"win11_{i}",
       "windows_hostname_target":f"WIN11-{i}",
       "guest_static_ipv4_target":f"192.168.240.{100+i}",
       "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}",
       "mac_candidate":f"02:aa:bb:cc:dd:{i:02x}",
       "disk_target":f"/var/lib/libvirt/images/cape-analysis/win11_{i}.command2.qcow2",
       "uefi_nvram_target":f"/var/lib/libvirt/qemu/nvram/win11_{i}.command2_VARS.fd"}


class WindowsGuestConfigTests(unittest.TestCase):
    def test_counts_1_5_16_generate_expected_hostnames_ips(self):
        for count in (1,5,16):
            configs=[cfg.make_guest_config(identity(i),"192.168.240.0/24")
                     for i in range(1,count+1)]
            self.assertEqual(len({x["hostname"] for x in configs}),count)
            self.assertEqual(len({x["ipv4"] for x in configs}),count)
            self.assertEqual(configs[-1]["hostname"],f"WIN11-{count}")
            self.assertEqual(configs[-1]["ipv4"],f"192.168.240.{100+count}")
            self.assertTrue(all(x["default_gateway"] is None for x in configs))
            self.assertTrue(all(not x["auto_apply_network"] for x in configs))
            self.assertTrue(all(x["host_isolation_must_be_independently_verified"] for x in configs))

    def test_wrong_name_mac_and_ip_refused(self):
        for field,value in (("windows_hostname_target","WRONG"),
                            ("guest_static_ipv4_target","192.168.240.88"),
                            ("mac_candidate","01:00:5e:00:00:01"),
                            ("disk_target","/var/lib/libvirt/images/master.qcow2")):
            rec=identity(1);rec[field]=value
            with self.subTest(field=field),self.assertRaises(cfg.GuestConfigBlocked):
                cfg.make_guest_config(rec,"192.168.240.0/24")

    def test_noncanonical_guid_and_foreign_subnet_blocked(self):
        row=identity(2);row["libvirt_uuid_candidate"]="not-a-guid"
        with self.assertRaises(cfg.GuestConfigBlocked):
            cfg.make_guest_config(row,"192.168.240.0/24")
        with self.assertRaises(cfg.GuestConfigBlocked):
            cfg.make_guest_config(identity(2),"192.168.241.0/24")
        with self.assertRaises(cfg.GuestConfigBlocked):
            cfg.make_guest_config(identity(2),"8.8.8.0/24")

    def test_powershell_guest_agent_never_modifies_host(self):
        source=Path(__file__).with_name("command2_guest_personalize.ps1").read_text(encoding="utf-8")
        for mode in ('"Plan"','"Identity"','"Network"','"Verify"'):
            self.assertIn(mode,source)
        self.assertIn("HostIsolationVerified",source)
        self.assertIn("ExpectedSha256",source)
        self.assertIn("Get-CimInstance Win32_ComputerSystemProduct",source)
        self.assertIn("Rename-Computer",source)
        self.assertIn("New-NetIPAddress",source)
        self.assertIn("Restart-Computer",source)
        self.assertIn("guest NIC",source)
        self.assertNotIn("New-NetRoute",source)
        self.assertNotIn("Set-NetFirewallProfile",source)
        self.assertNotIn("Disable-NetAdapterBinding",source)
        self.assertNotIn("Set-ExecutionPolicy",source)
        self.assertNotIn("Enable-NetAdapter",source)


if __name__=="__main__":
    unittest.main()
