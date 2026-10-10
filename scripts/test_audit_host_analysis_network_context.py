#!/usr/bin/env python3
"""Fixture tests only; never inspect or change real SSL-55 host routes."""
import json
import unittest
from unittest.mock import patch
import audit_host_analysis_network_context as m

class TestHostNetworkContext(unittest.TestCase):
    def test_interface_subnets_do_not_include_host_address(self):
        rows=m.summarize_addresses([
            {"ifname":"enp1s0","operstate":"UP",
             "addr_info":[{"family":"inet","local":"10.23.105.55",
                           "prefixlen":22}]}])
        self.assertEqual(rows[0]["ipv4_subnets"],["10.23.104.0/22"])
        self.assertNotIn("10.23.105.55",json.dumps(rows))

    def test_nft_rules_redacted(self):
        raw=json.dumps({"nftables":[
             {"table":{"family":"ip","name":"filter"}},
             {"chain":{"family":"ip","table":"filter","name":"FORWARD",
                       "hook":"forward","policy":"drop"}},
             {"rule":{"expr":[{"match":{"left":{"payload":{"protocol":"ip",
                     "field":"daddr"}},"op":"==","right":"192.0.2.99"}},
                     {"accept":None}]}}]})
        record=m.summarize_nft(raw)
        self.assertEqual(record["chains"][0]["policy"],"drop")
        self.assertEqual(record["action_counts"]["accept"],1)
        self.assertNotIn("192.0.2.99",json.dumps(record))

    def test_nft_broken_fails_unknown(self):
        self.assertEqual(m.summarize_nft("{")["parse"],"UNAVAILABLE")

    def test_iptables_structure_only(self):
        with patch.object(m.shutil,"which",return_value="/usr/bin/iptables"),\
             patch.object(m,"query",return_value="-P FORWARD DROP\n-A FORWARD -i bad0 -j ACCEPT\n"):
            r=m.summarize_iptables("iptables","filter")
        self.assertEqual(r["policies"]["FORWARD"],"DROP")
        self.assertEqual(r["target_counts"]["ACCEPT"],1)
        self.assertNotIn("bad0",json.dumps(r))

    def test_running_master_blocks_before_network_tools(self):
        with patch.object(m,"virsh",return_value="running"),\
             patch.object(m,"query") as query:
            with self.assertRaisesRegex(m.NetworkContextError,
                                        "Original master is not shut off"):
                m.check_untouched_guest()
            query.assert_not_called()

    def test_ip_route_structural_only(self):
        out=m.summarize_routes([
            {"dst":"10.23.104.0/22","dev":"enp1s0","gateway":"10.23.104.1"}],"v4")
        self.assertEqual(out[0]["dst"],"10.23.104.0/22")
        self.assertNotIn("10.23.104.1",json.dumps(out))

if __name__=="__main__":
    unittest.main()
