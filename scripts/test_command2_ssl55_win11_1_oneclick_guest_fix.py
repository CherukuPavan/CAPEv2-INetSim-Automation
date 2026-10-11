"""Synthetic source checks for SSL55 safely guarded click-only guest IP migration."""
from pathlib import Path
import unittest


class SSL55Win11GuestFixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d=Path(__file__).parent
        cls.ps=(d/"command2_ssl55_win11_1_oneclick_guest_fix.ps1").read_text()
        cls.cmd=(d/"command2_ssl55_win11_1_oneclick_SETUP.cmd").read_text()

    def test_exact_pilot_identity_and_legacy_ip(self):
        for key in ("732b2256-ee99-41fa-881d-fbf5c476d960",
                    "020A306A3F50", "WIN11-1",
                    "192.168.122.125","192.168.122.1",
                    "192.168.240.101", "Win32_ComputerSystemProduct",
                    "Get-NetAdapter -Physical"):
            self.assertIn(key,self.ps)

    def test_refuse_other_ips_mac_default_routes_and_ipv6(self):
        for key in ("Exactly one NIC required",
                    "Reserved NIC MAC mismatch",
                    "Unexpected guest IPv4 or subnet prefix",
                    "Unexpected IPv6 default route",
                    "Multiple IPv4 default routes",
                    "Unexpected IPv4 default route or gateway",
                    "Unexpected non-link-local guest IPv6",
                    "Unexpected DHCP enabled",
                    "Windows hostname is not WIN11-1"):
            self.assertIn(key,self.ps)

    def test_exact_old_default_route_removed_before_exact_old_ip(self):
        route=self.ps.index("Remove-NetRoute -InterfaceIndex $state.Index")
        ip=self.ps.index("Remove-NetIPAddress -InterfaceIndex $state.Index")
        new=self.ps.index("New-NetIPAddress -InterfaceIndex $state.Index")
        self.assertLess(route,ip)
        self.assertLess(ip,new)
        self.assertIn("-NextHop $OldGateway",self.ps)
        self.assertIn("-IPAddress $OldIp",self.ps)
        self.assertIn("-IPAddress $NewIp -PrefixLength $NewPrefix",self.ps)

    def test_explicit_operator_short_approval_and_plan_mode(self):
        self.assertIn('if ($Mode -eq \'Plan\')',self.ps)
        self.assertIn("if (-not (IsAdmin))",self.ps)
        self.assertIn("Read-Host 'Type YES",self.ps)
        self.assertIn("if ($answer -cne 'YES')",self.ps)
        self.assertIn("WARNING: Changes may be partial",self.ps)
        self.assertIn("Start-Process -FilePath",self.ps)
        self.assertIn("notepad.exe",self.ps)

    def test_no_broad_route_reset_no_firewall_changes_or_downloads(self):
        for forbidden in ("Disable-NetAdapterBinding",
                          "Set-NetFirewallProfile",
                          "Set-DnsClientServerAddress",
                          "New-NetRoute", "Remove-NetIPInterface",
                          "Restart-Computer","Rename-Computer",
                          "Invoke-WebRequest","Remove-NetRoute -Confirm",
                          "Remove-NetIPAddress -Confirm",
                          "Disable-MpRealtimeMonitoring",
                          "Set-ExecutionPolicy","netsh"):
            self.assertNotIn(forbidden,self.ps)

    def test_click_launcher_auto_elevates_and_checks_sha256_before_execution(self):
        for wanted in ("Start-Process -FilePath 'powershell.exe'",
                       "-Verb RunAs", "-Wait -PassThru",
                       "Get-FileHash -LiteralPath",
                       "__PS_SHA256__","%~dp0","FIX.PS1",
                       "pause"):
            self.assertIn(wanted,self.cmd)
        self.assertNotIn("netsh",self.cmd)
        self.assertNotIn("route delete",self.cmd)

if __name__=="__main__":
    unittest.main()
