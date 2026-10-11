"""Static safety and interface checks for guest-startup PowerShell bootstrap.

Actual Windows SYSTEM scheduled-task execution requires host/guest pilot.
"""
from pathlib import Path
import unittest


class WindowsStartupBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=Path(__file__).with_name(
            "command2_guest_startup_autoconfig.ps1").read_text(encoding="utf-8")

    def test_install_requires_operator_approval_and_exact_guest_uuid(self):
        for s in ("ApproveInstall","ExpectedTemplateUuid",
                  "Win32_ComputerSystemProduct",
                  "GuestInit", "Register-ScheduledTask",
                  "Get-ScheduledTask", "refuse overwrite"):
            if s=="refuse overwrite":
                self.assertIn("no blind overwrite",self.text)
            else:
                self.assertIn(s,self.text)

    def test_no_nic_identity_then_approved_network_only(self):
        for s in ("Get-NetAdapter -Physical",
                  'if ($adapters.Count -eq 0)',
                  'CallPersonalizer "Identity"',
                  'CallPersonalizer "Network"',
                  "network-approved.json",
                  "network-approved.sha256",
                  "host_ipv4_negative_egress_verified",
                  "host_ipv6_negative_egress_verified",
                  "reboot_persistence_verified",
                  "guest_l2_separation_verified"):
            self.assertIn(s,self.text)

    def test_cd_media_must_be_optical_and_integrity_checked(self):
        for s in ("CAPE_CMD2","Win32_LogicalDisk","DriveType -ne 5",
                  "Get-FileHash","guest-config.json","guest-config.sha256",
                  "Get-Volume","expected_machine_uuid"):
            self.assertIn(s,self.text)

    def test_no_guest_network_weakening_or_host_commands(self):
        for s in ("Disable-NetAdapterBinding","Set-NetFirewallProfile",
                  "New-NetRoute","virsh ","nft ","Disable-WindowsOptionalFeature",
                  "Set-ExecutionPolicy -ExecutionPolicy", "Windows Defender",
                  "Invoke-WebRequest","DownloadFile","System.Net.WebClient"):
            # Safety docstring may mention no Windows changes; the commands
            # above are not needed for setting a private guest IP.
            self.assertNotIn(s,self.text)
        self.assertIn('network_changed=$false',self.text)


if __name__=="__main__":
    unittest.main()
