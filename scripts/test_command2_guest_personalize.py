"""Guardrails for unattended Command2 Windows identity/static IPv4 script.

These are static contract checks; Windows 11 OS execution is NOT proven by
GitHub-hosted Linux unit tests. PowerShell parsing is exercised by CI.
"""
from pathlib import Path
import unittest

SOURCE=Path(__file__).with_name("command2_guest_personalize.ps1")

class GuestWindowsPersonalizeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s=SOURCE.read_text(encoding="utf-8")

    def test_identity_is_no_nic_or_approved_one_nic_only_and_exact_uuid(self):
        for t in (
            'if ($Mode -eq "Identity")',
            'if ($adapters.Count -ne 0)',
            'if (-not $HostIsolationVerified -or $adapters.Count -ne 1)',
            'Identity NIC MAC differs from exact reservation',
            '$identityV4.Count -ne 0 -or $identityV6.Count -ne 0',
            'Rename-Computer',
            'Restart-Computer',
            'Win32_ComputerSystemProduct',
            'if ($actual -ne $vmid)',
        ):
            self.assertIn(t,self.s)

    def test_network_requires_one_expected_mac_and_host_isolation(self):
        for t in (
            "HostIsolationVerified",
            "CleanMac", "Get-NetAdapter -Physical",
            "Exactly one reserved isolated NIC",
            'if (-not $HostIsolationVerified)',
            "Get-NetIPAddress", "Get-NetIPInterface",
        ):
            self.assertIn(t,self.s)

    def test_static_address_not_false_pass_on_dhcp_or_prefix_mismatch(self):
        for t in (
            '$sameIPWrongPrefix.Count -ne 0',
            '$matchingIP.Count -gt 1',
            '[string]$ipif[0].Dhcp -ne "Disabled"',
            "An identical DHCP lease is NOT a static IP",
            "Set-NetIPInterface",
            "New-NetIPAddress",
            "$finalIP.Count -ne 1",
            '[string]$finalIPv4.Dhcp -ne "Disabled"',
        ):
            self.assertIn(t,self.s)

    def test_no_v4_or_v6_default_route_and_postchange_reread(self):
        for t in (
            '-DestinationPrefix "0.0.0.0/0"',
            '-DestinationPrefix "::/0"',
            "$v6Routes.Count -ne 0",
            "$finalRoutes.Count -ne 0",
            "$finalV6Routes.Count -ne 0",
            "ipv6_default_route_present=$false",
            "ipv4_default_route_present=$false",
            "Post-change static IPv4",
        ):
            self.assertIn(t,self.s)

    def test_verify_fails_closed_if_dhcp_or_static_ip_invalid(self):
        verify=self.s.split('if ($Mode -eq "Verify") {',1)[1].split(
            'if ($Mode -ne "Network")',1)[0]
        self.assertIn('if ($matchingIP.Count -ne 1',verify)
        self.assertIn('Expected unique STATIC IPv4',verify)
        self.assertIn('no_changes_made=$true',verify)

    def test_no_default_gateway_or_remote_download_action(self):
        for forbidden in (
            "New-NetRoute", "Remove-NetRoute", "Set-DnsClientServerAddress",
            "Invoke-WebRequest","Invoke-RestMethod","Disable-NetFirewallProfile",
            "Disable-WindowsOptionalFeature","Set-ExecutionPolicy",
        ):
            self.assertNotIn(forbidden,self.s)

if __name__=="__main__":
    unittest.main()
