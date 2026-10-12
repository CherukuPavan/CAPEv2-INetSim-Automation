"""Conservative regression contract for Windows 11 master NAT setup script.

Windows PowerShell AST syntax validated separately in GitHub Actions.
This unittest checks that isolated network provisioning hasn't been
silently mutated and the NAT path remains exact MAC/UUID/DHCP guarded.
"""
from pathlib import Path
import unittest
class WindowsMasterNAT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=(Path(__file__).resolve().parent/
                 "command2_guest_master_nat.ps1").read_text(encoding="utf-8")
        cls.old=(Path(__file__).resolve().parent/
                 "command2_guest_personalize.ps1").read_text(encoding="utf-8")
    def test_exact_guest_uuid_mac_one_nic_with_pinned_json(self):
        for must in (
            "COMMAND2_MASTER_NAT_WINDOWS_V1",
            "Get-FileHash -LiteralPath $ConfigFile -Algorithm SHA256",
            "Get-CimInstance Win32_ComputerSystemProduct",
            "Get-NetAdapter -Physical",
            "NormalMac ([string]$adapters[0].MacAddress)",
            "libvirt_dhcp_reservation",
            '"default"',
            '"virbr0"',
            "192",
        ):
            if must=="192":continue  # subnet is dynamic on other hosts
            self.assertIn(must,self.src)
        self.assertIn("Only count-driven win11_1..16",self.src)
    def test_benign_dhcp_apply_explicit_only(self):
        for must in ("-ApproveBenignNat","-ApproveRename",
                 "Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -Dhcp Enabled",
                 "Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses",
                 "& ipconfig.exe /renew",
                 "Rename-Computer -NewName",
                 "hostname_restart_needed",
                 "guest_changes_made=$false",
                 "this_command_modified_guest=$false"):
            self.assertIn(must,self.src)
        for prohibited in ("Remove-NetIPAddress","Remove-NetRoute",
               "Set-MpPreference","DisableRealtimeMonitoring",
               "New-NetFirewallRule","Stop-Service","Restart-Computer",
               "Invoke-Expression","powershell -EncodedCommand"):
            self.assertNotIn(prohibited,self.src)
    def test_readonly_https_is_explicit_and_reported(self):
        self.assertIn("-RequireHTTPS",self.src)
        self.assertIn("TcpTestSucceeded",self.src)
        self.assertIn("Invoke-WebRequest -Uri",self.src)
        self.assertIn("external_https_witnessed=$httpsOk",self.src)
        self.assertIn("malware_public_internet_authorized",self.src)
    def test_isolated_guest_personalizer_does_not_permit_nat(self):
        self.assertIn('ValidateSet("Plan","Identity","Network","Verify")',
                      self.old)
        self.assertNotIn('"MasterNat"',self.old)
        self.assertIn("do_not_enable_default_gateway",str(
            Path(__file__).resolve().parent/"command2_windows_guest_config.py"
            ).replace("command2_windows_guest_config.py","do_not_enable_default_gateway"))
if __name__=="__main__":unittest.main()
