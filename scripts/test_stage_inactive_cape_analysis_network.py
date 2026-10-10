#!/usr/bin/env python3
"""Fixture-only inactive libvirt network definition tests; no host changes."""
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import stage_inactive_cape_analysis_network as m

class Tests(unittest.TestCase):
    def test_xml_has_no_forwarding_dns_dhcp_or_exposed_ports(self):
        m.validate_xml(m.network_xml())
        root=ET.fromstring(m.network_xml())
        self.assertIsNone(root.find("forward"))
        self.assertEqual(root.find("port").get("isolated"),"yes")
        self.assertEqual(root.find("dns").get("enable"),"no")
        self.assertIsNone(root.find("./ip/dhcp"))
        self.assertEqual(root.find("./bridge").get("name"),m.BRIDGE)

    def test_forwarding_network_rejected(self):
        xml=m.network_xml().replace("</network>",
                 '<forward mode="nat"/></network>')
        with self.assertRaisesRegex(m.Blocked,"forwarding"):
            m.validate_xml(xml)

    def test_nonisolated_ports_rejected(self):
        xml=m.network_xml().replace('isolated="yes"','isolated="no"')
        with self.assertRaisesRegex(m.Blocked,"port isolation"):
            m.validate_xml(xml)

    def test_dhcp_rejected(self):
        xml=m.network_xml().replace("</ip>",'<dhcp/></ip>')
        with self.assertRaisesRegex(m.Blocked,"DHCP"):
            m.validate_xml(xml)

    def test_guest_state_must_be_safe(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"virsh",return_value="running"):
            with self.assertRaisesRegex(m.Blocked,"Master not shut off"):
                m.preflight()

    def test_plan_has_no_host_mutation(self):
        with patch.object(m,"preflight",return_value={"bridge":m.BRIDGE}),\
             patch.object(m,"command") as c:
            result=m.perform("plan")
        self.assertFalse(result["definition_created"])
        c.assert_not_called()

if __name__=="__main__":
    unittest.main()
