"""Validate read-only Windows trusted Internet witness source contract."""
from pathlib import Path
import unittest
P=Path(__file__).with_name("command2_windows_benign_internet_witness.ps1")
class Witness(unittest.TestCase):
    def test_witness_checks_dhcp_dns_gateway_tcp_https_and_exact_setup_mac(self):
        s=P.read_text(encoding="utf-8")
        for key in ("02:CA:55:11:01:01","Get-NetAdapter",
              "Get-NetIPInterface","Get-NetIPConfiguration",
              "IPv4DefaultGateway","Resolve-DnsName",
              "Test-NetConnection","Invoke-WebRequest",
              "internet_verified","modifications_made=$false",
              "malware_analysis_authorized=$false"):
            self.assertIn(key,s)
    def test_no_windows_host_mutations(self):
        s=P.read_text(encoding="utf-8")
        for forbidden in ("New-NetIPAddress","Remove-NetIPAddress",
            "Set-NetIPAddress","Set-NetRoute","New-NetRoute",
            "Remove-NetRoute","Disable-NetAdapter","Enable-NetAdapter",
            "Set-NetFirewallProfile","Clear-Tpm","Set-DnsClientServerAddress",
            "Start-Process","Invoke-Expression"):
            self.assertNotIn(forbidden,s)
if __name__=="__main__":unittest.main()
