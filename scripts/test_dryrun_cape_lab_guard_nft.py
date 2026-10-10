#!/usr/bin/env python3
"""Synthetic-only tests. No nft, guest or libvirt state modifications."""
import json
import unittest
from unittest.mock import patch
import dryrun_cape_lab_guard_nft as m

class Tests(unittest.TestCase):
    def test_policy_blocks_lateral_forward_host_input_output(self):
        script=m.policy_text()
        m.validate_policy(script)
        self.assertIn('iifname "cape-lab0" drop',script)
        self.assertIn('oifname "cape-lab0" drop',script)
        self.assertIn('iifname "cape-lab0" ip daddr 192.168.240.1 ct state established,related accept',script)
        self.assertIn('oifname "cape-lab0" ip daddr 192.168.240.0/24 tcp dport 8000 accept',script)
        self.assertEqual(script.count('type filter hook '),3)
        self.assertNotIn("flush ruleset",script)
        for interface in ("enp0s31f6","wlp0s20f3","virbr0","docker0"):
            self.assertNotIn(interface,script)

    def test_missing_forward_drop_fails_closed(self):
        source=m.policy_text().replace('iifname "cape-lab0" drop','iifname "cape-lab0" accept',1)
        with self.assertRaisesRegex(m.DryRunBlocked,"Missing"):
            m.validate_policy(source)

    def test_existing_guard_name_detected(self):
        blob=json.dumps({"nftables":[
                {"metainfo":{"version":"1.1"}},
                {"table":{"family":"inet","name":m.TABLE}}]})
        self.assertIn(("inet",m.TABLE),m.nft_tables(blob))

    def test_running_master_is_blocked_before_network_queries(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"virsh",return_value="running"):
            with self.assertRaisesRegex(m.DryRunBlocked,"master"):
                m.check_guest_and_network()

    def test_guest_running_no_nic_must_be_kept(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"virsh",side_effect=["shut off","running",
                  "<domain><name>win11_trial_1</name><uuid>"+m.TRIAL_UUID+"</uuid>"
                  "<devices><interface/></devices></domain>"]):
            with self.assertRaisesRegex(m.DryRunBlocked,"NIC"):
                m.check_guest_and_network()

if __name__=="__main__":unittest.main()
