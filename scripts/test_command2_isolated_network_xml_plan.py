"""Pure network XML tests, never creating a libvirt network/NIC."""
import unittest
import xml.etree.ElementTree as ET
import command2_isolated_network_xml_plan as net


class IsolatedXMLTests(unittest.TestCase):
    def test_five_guest_private_bridge_xml_without_forward(self):
        out=net.plan("cape-analysis-isolated","cape-lab0",
                     "192.168.240.0/24",
                     [f"192.168.240.{101+i}" for i in range(5)])
        root=ET.fromstring(out["libvirt_network_xml"])
        self.assertIsNone(root.find("forward"))
        self.assertIsNone(root.find("route"))
        self.assertIsNone(root.find(".//dhcp"))
        self.assertEqual(root.findtext("name"),"cape-analysis-isolated")
        self.assertEqual(root.find("bridge").get("name"),"cape-lab0")
        self.assertEqual(root.find("dns").get("enable"),"no")
        self.assertEqual(root.find("port").get("isolated"),"yes")
        self.assertTrue(out["all_future_guest_tap_ports_must_be_kernel_isolated"])
        self.assertFalse(out["l2_actual_peer_packet_tested"])
        self.assertEqual(root.find("ip").get("address"),"192.168.240.1")
        for field in ("guest_ipv6_disabled_or_blocked_verified",
                      "nftables_guard_installed",
                      "nftables_guard_reboot_verified",
                      "nic_attachment_authorized",
                      "network_started",
                      "cape_host_to_guest_path_verified"):
            self.assertFalse(out[field])

    def test_refuse_wrong_name_and_bridge(self):
        with self.assertRaises(net.NetworkPlanBlocked):
            net.plan("default","cape-lab0","192.168.240.0/24")
        with self.assertRaises(net.NetworkPlanBlocked):
            net.plan("cape-analysis-isolated","virbr0","192.168.240.0/24")

    def test_refuse_public_default_or_noncanonical_subnet(self):
        for subnet in ("8.8.8.0/24","192.168.122.0/24","169.254.1.0/24",
                       "192.168.240.0/20","192.168.240.8/24"):
            with self.subTest(subnet=subnet),self.assertRaises(net.NetworkPlanBlocked):
                net.plan("cape-analysis-isolated","cape-lab0",subnet)

    def test_refuse_guest_ip_collisions_and_host_bridge_ip(self):
        for ips in (["192.168.240.101","192.168.240.101"],
                    ["192.168.240.1"],["192.168.240.255"],
                    ["10.0.0.101"]):
            with self.subTest(ips=ips),self.assertRaises(net.NetworkPlanBlocked):
                net.plan("cape-analysis-isolated","cape-lab0",
                         "192.168.240.0/24",ips)

    def test_source_has_no_write_capable_interface(self):
        from pathlib import Path
        src=Path(net.__file__).read_text()
        for word in ('virsh','net-define','net-start','nft','systemctl',
                     'subprocess.run','socket.socket','os.system'):
            # 'nftables_guard' metadata is present by design; its CLI isn't.
            if word == 'nft':
                self.assertNotIn('"nft"',src)
            else:
                self.assertNotIn(word,src)


if __name__=="__main__":
    unittest.main()
