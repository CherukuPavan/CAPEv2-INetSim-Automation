"""Offline tests of no-default-gateway read-only Windows egress v2 source."""
import re
from pathlib import Path
import unittest

FILE=Path(__file__).with_name("command2_guest_benign_egress_probe_v2.ps1")

class TestEgressProbeV2(unittest.TestCase):
    def test_versioned_output_does_not_overwrite_first_failure(self):
        source=FILE.read_text()
        self.assertIn("CAPE_Command2_GuestEgressProbe_V2.txt",source)
        self.assertIn("BENIGN_GUEST_IPV4_IPV6_EGRESS_PROBES_V2",source)

    def test_absent_gateway_is_not_queried_as_exact_cim_object(self):
        source=FILE.read_text()
        self.assertIn("Get-NetRoute -AddressFamily $family -ErrorAction Stop",source)
        self.assertIn("$_.DestinationPrefix -eq $prefix",source)
        self.assertNotIn("Get-NetRoute -AddressFamily IPv4 -DestinationPrefix",source)
        self.assertNotIn("Get-NetRoute -AddressFamily IPv6 -DestinationPrefix",source)
        self.assertIn("IPv6",source)
        self.assertIn("IPv4",source)

    def test_query_errors_are_inconclusive_not_false_negative(self):
        source=FILE.read_text()
        self.assertIn("INCONCLUSIVE_",source)
        self.assertIn("GUEST_DEFAULT_ROUTE_GUARD' 'INCONCLUSIVE",source)
        self.assertIn("$script:inconclusive=$true",source)

    def test_no_unbounded_external_connectivity(self):
        source=FILE.read_text()
        self.assertIn("WaitOne(2500,$false)",source)
        self.assertIn("[System.Net.Sockets.TcpClient]::new($ip.AddressFamily)",source)
        self.assertEqual(source.count("SOCKET_FAILED_"),2)
        self.assertEqual(source.count("CONNECTED_UNSAFE"),2)
        self.assertEqual(source.count("IP='"),4)

    def test_no_guest_network_mutations_or_downloads(self):
        source=FILE.read_text()
        for command in ("Set-Net", "New-Net", "Remove-Net", "Disable-Net",
                        "Invoke-WebRequest", "Invoke-RestMethod", "Start-BitsTransfer",
                        "Set-MpPreference", "Add-MpPreference", "netsh.exe"):
            self.assertNotIn(command+" ",source)

if __name__=="__main__":
    unittest.main()
