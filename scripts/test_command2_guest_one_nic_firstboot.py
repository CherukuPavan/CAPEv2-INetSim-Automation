"""Offline, static safety checks for generic guarded one-NIC Windows setup."""
from pathlib import Path
import unittest

SRC=Path(__file__).with_name("command2_guest_one_nic_firstboot.ps1")


class OneNicGuestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s=SRC.read_text(encoding="utf-8")

    def test_guest_identity_and_1_to_16_sequential_ipv4(self):
        for part in ("ValidateRange(1,16)","ExpectedUuid","ExpectedMac",
                     "ExpectedIPv4","Win32_ComputerSystemProduct",
                     "Get-NetAdapter -Physical","02:(?:[0-9a-f]{2}:){4}",
                     '"192.168.240."+(100+$GuestIndex)',
                     '"WIN11-"+$GuestIndex',"Wrong guest SMBIOS UUID"):
            self.assertIn(part,self.s)

    def test_block_unexpected_route_mac_second_nic_or_existing_ipv4(self):
        for part in ('DestinationPrefix "0.0.0.0/0"',
                     'DestinationPrefix "::/0"',
                     'Exactly one physical NIC required',
                     'Actual NIC MAC differs from host reservation',
                     'Unexpected existing IPv4 address',
                     'IP exists with wrong subnet prefix',
                     'no_ipv4_or_ipv6_default_gateway'):
            self.assertIn(part,self.s)

    def test_plan_and_verify_are_non_mutating(self):
        self.assertIn('if ($Mode -eq "Plan")',self.s)
        self.assertIn('if ($Mode -eq "Verify")',self.s)
        pos_apply=self.s.index("Admin\nif (-not $ApproveBenignSetup)")
        self.assertLess(self.s.index('if ($Mode -eq "Verify")'),pos_apply)
        for snippet in ("Set-NetIPInterface","New-NetIPAddress","Rename-Computer"):
            self.assertGreater(self.s.index(snippet),pos_apply)

    def test_no_windows_firewall_security_gateway_changes(self):
        for snippet in ("New-NetRoute","Remove-NetRoute",
                        "Set-NetFirewallProfile","Disable-NetAdapterBinding",
                        "Restart-Computer","Invoke-WebRequest","DownloadFile",
                        "Set-ExecutionPolicy", "Set-DnsClientServerAddress",
                        "netsh advfirewall","Disable-MpRealtimeMonitoring"):
            self.assertNotIn(snippet,self.s)
        self.assertIn("running_snapshot_verified=$false",self.s)
        self.assertIn("malware_analysis_authorized=$false",self.s)
        self.assertIn("host_egress_isolation_proved=$false",self.s)

    def test_requires_admin_and_explicit_benign_only_mutation(self):
        for snippet in ("function Admin", "ApproveBenignSetup",
                        "Get-NetIPAddress", "New-NetIPAddress",
                        "Rename-Computer", "Guest IPv4", "Windows"):
            self.assertIn(snippet,self.s)


if __name__ == "__main__":
    unittest.main()
