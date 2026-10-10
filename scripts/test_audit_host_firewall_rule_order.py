#!/usr/bin/env python3
"""Isolated tests; do not query the host firewall or libvirt."""
import json
import unittest
from unittest.mock import patch
import audit_host_firewall_rule_order as m

class Tests(unittest.TestCase):
    def test_ordered_iptables_targets_redact_sensitive_match(self):
        input_lines="""-P FORWARD ACCEPT
-A FORWARD -i virbr0 -s 10.23.105.55 -j DOCKER-USER
-A FORWARD -i virbr0 -o enp0s31f6 -d 192.0.2.5 -j REJECT
-A DOCKER-USER -j RETURN
"""
        x=m.parse_iptables(input_lines,"iptables","filter")
        forward=[item for item in x["ordered_chains"] if item["chain"]=="FORWARD"]
        self.assertEqual([item["position"] for item in forward],[1,2])
        self.assertEqual(forward[0]["actions"][0]["jump"],"DOCKER-USER")
        self.assertEqual(forward[1]["interfaces"][1]["oif"],"enp0s31f6")
        self.assertNotIn("192.0.2.5",json.dumps(x))
        self.assertNotIn("10.23.105.55",json.dumps(x))

    def test_nft_inet_forward_priority_drop(self):
        blob=json.dumps({"nftables":[
          {"chain":{"family":"inet","table":"cape","name":"guard",
             "hook":"forward","prio":-100,"policy":"drop"}},
          {"rule":{"family":"inet","table":"cape","chain":"guard",
             "expr":[{"accept":None},{"match":{"right":"SECRET"}}]}},
          {"chain":{"family":"ip","table":"nat","name":"prerouting",
             "hook":"prerouting","prio":-100,"policy":"accept"}}]})
        result=m.parse_nft(blob)
        self.assertEqual(result[0]["priority"],-100)
        self.assertEqual(result[0]["policy"],"drop")
        self.assertEqual(len(result),2)
        self.assertNotIn("SECRET",json.dumps(result))

    def test_no_nic_requirement_before_reading_firewall(self):
        with patch.object(m,"virsh",return_value="running"),\
             patch.object(m,"read_command") as called:
            with self.assertRaisesRegex(m.RuleAuditError,"master not shut off"):
                m.preflight()
            called.assert_not_called()

    def test_bad_nft_json_blocked(self):
        with self.assertRaisesRegex(m.RuleAuditError,"Cannot parse"):
            m.parse_nft("this is not json")

if __name__=="__main__":
    unittest.main()
