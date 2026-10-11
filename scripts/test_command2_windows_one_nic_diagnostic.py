"""Offline-only tests: double-click Windows CD-ROM route diagnostic."""
from pathlib import Path
import unittest


class WindowsOneNicDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder=Path(__file__).parent
        cls.ps=(folder/"command2_windows_one_nic_diagnostic.ps1").read_text()
        cls.cmd=(folder/"command2_windows_one_nic_CHECK.cmd").read_text()

    def test_capture_ipv4_and_ipv6_default_route_and_nic(self):
        for token in ("'0.0.0.0/0'","'::/0'","Get-NetAdapter -Physical",
                      "Get-NetIPAddress -AddressFamily IPv4",
                      "Get-NetIPAddress -AddressFamily IPv6",
                      "Get-NetIPInterface","Win32_ComputerSystemProduct",
                      "Start-Process","notepad.exe"):
            self.assertIn(token,self.ps)

    def test_never_weakens_guest_firewall_or_edits_ip_route(self):
        for token in ("Set-NetIPInterface","New-NetIPAddress",
                      "Remove-NetRoute","New-NetRoute","Remove-NetIPAddress",
                      "Set-NetFirewallProfile","Disable-NetAdapterBinding",
                      "Restart-Computer","Rename-Computer","Invoke-WebRequest",
                      "DownloadFile","Start-BitsTransfer"):
            self.assertNotIn(token,self.ps)
        self.assertIn("NO networking or firewall changes",self.ps)

    def test_single_double_click_launches_optical_script_and_pauses(self):
        self.assertIn('"%~dp0DIAG.PS1"',self.cmd)
        self.assertIn("powershell.exe -NoProfile",self.cmd)
        self.assertIn("pause",self.cmd)
        self.assertNotIn("route add",self.cmd)
        self.assertNotIn("netsh",self.cmd)


if __name__=="__main__":
    unittest.main()
