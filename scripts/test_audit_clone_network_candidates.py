#!/usr/bin/env python3
"""Synthetic libvirt XML network classification; no real host network ops."""
import unittest
from unittest.mock import patch
import audit_clone_network_candidates as m

CANDIDATE="""<network><name>cape-isolated</name><bridge name='virbr9'/>
<ip address='192.168.212.1' netmask='255.255.255.0'/></network>"""
NAT="""<network><name>default</name><forward mode='nat'/>
<bridge name='virbr0'/><ip address='192.168.122.1' netmask='255.255.255.0'>
<dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp>
</ip></network>"""

class Tests(unittest.TestCase):
    def test_no_forward_network_still_not_isolation_proof(self):
        x=m.check_network_xml(CANDIDATE)
        self.assertTrue(x["xml_candidate_only"])
        self.assertFalse(x["host_egress_isolation_verified"])
        self.assertEqual(x["ipv4"][0]["subnet"],"192.168.212.0/24")

    def test_default_nat_blocked(self):
        x=m.check_network_xml(NAT)
        self.assertFalse(x["xml_candidate_only"])
        self.assertEqual(x["forward_mode"],"nat")
        self.assertEqual(x["ipv4"][0]["dhcp_ranges"][0]["from"],"192.168.122.2")
        self.assertIn("FORWARDING_XML_PRESENT",x["blocking_or_review_reasons"])

    def test_rejects_explicit_route_forward(self):
        xml=CANDIDATE.replace("<bridge","<forward mode='route'/><bridge")
        self.assertFalse(m.check_network_xml(xml)["xml_candidate_only"])

    def test_ipv6_needs_review(self):
        xml=CANDIDATE.replace("</network>",
              "<ip family='ipv6' address='fd00::1' prefix='64'/></network>")
        x=m.check_network_xml(xml)
        self.assertFalse(x["xml_candidate_only"])
        self.assertTrue(x["has_ipv6_xml"])

    def test_bridge_is_required(self):
        xml=CANDIDATE.replace("<bridge name='virbr9'/>","")
        self.assertIn("NO_BRIDGE",
            m.check_network_xml(xml)["blocking_or_review_reasons"])

    def test_extra_ipv4_network_blocks(self):
        xml=CANDIDATE.replace("</network>",
              "<ip address='10.0.0.1' netmask='255.255.255.0'/></network>")
        self.assertFalse(m.check_network_xml(xml)["xml_candidate_only"])

    def test_explicit_libvirt_dns_flagged(self):
        xml=CANDIDATE.replace("</network>","<dns/></network>")
        self.assertIn("LIBVIRT_DNS_CONFIG_PRESENT",
                      m.check_network_xml(xml)["blocking_or_review_reasons"])

    def test_no_libvirt_command_after_trial_check_failure(self):
        with patch.object(m,"check_guest_zero_nic",
                          side_effect=m.NetworkAuditError("NIC found")),\
             patch.object(m,"virsh") as virsh:
            with self.assertRaisesRegex(m.NetworkAuditError,"NIC found"):
                m.inventory()
            virsh.assert_not_called()

if __name__=="__main__":
    unittest.main()
