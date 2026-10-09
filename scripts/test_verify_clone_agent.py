#!/usr/bin/env python3
"""Pure offline tests for CAPE agent health response and ping behavior."""
import unittest
from unittest.mock import patch, Mock
import json

import verify_clone_agent as v

class Tests(unittest.TestCase):
    def test_valid_agent_payload(self):
        ok={"message":"CAPE Agent!","version":"0.22","is_user_admin":True,
            "features":["execute","execpy"]}
        x=v.validate_agent_payload(json.dumps(ok).encode())
        self.assertTrue(x["elevated"])
        self.assertEqual(x["version"],"0.22")

    def test_rejects_unprivileged_agent(self):
        payload=json.dumps({"message":"CAPE Agent!","is_user_admin":False,"features":["execute"]})
        with self.assertRaisesRegex(v.AgentCheckError,"administrator"):
            v.validate_agent_payload(payload.encode())

    def test_rejects_random_http_server(self):
        with self.assertRaisesRegex(v.AgentCheckError,"identify"):
            v.validate_agent_payload(b'{"message":"Other service"}')

    def test_rejects_missing_features(self):
        with self.assertRaisesRegex(v.AgentCheckError,"execute"):
            v.validate_agent_payload(b'{"message":"CAPE Agent!","is_user_admin":true,"features":[]}')

    def test_ping_args_explicit_not_shell(self):
        process=Mock(returncode=0)
        with patch.object(v.subprocess,"run",return_value=process) as run:
            v.ping_once("198.51.100.20")
        self.assertEqual(run.call_args.args[0][:3],["ping","-n","-c"])
        self.assertNotIn("shell",run.call_args.kwargs)

    def test_wait_calls_both_and_returns_status(self):
        with patch.object(v,"ping_once"),patch.object(v,"agent_once",
            return_value={"identity":"CAPE Agent!"}):
            result=v.wait_for_agent("198.51.100.20",timeout=10)
        self.assertEqual(result["ping"],"PASS")
        self.assertEqual(result["cape_curl_equivalent"],"PASS")

    def test_neighbor_mac_matches_expected_vm(self):
        from unittest.mock import Mock
        response=Mock(returncode=0,stdout="198.51.100.20 dev virbr2 lladdr 02:aa:bb:cc:dd:ee REACHABLE\\n")
        with patch.object(v.subprocess,"run",return_value=response) as checker:
            v.verify_neighbor("198.51.100.20","virbr2","02:aa:bb:cc:dd:ee")
        self.assertIn("virbr2",checker.call_args.args[0])

    def test_wrong_neighbor_mac_blocks(self):
        from unittest.mock import Mock
        response=Mock(returncode=0,stdout="198.51.100.20 dev virbr2 lladdr 02:aa:bb:cc:dd:ee REACHABLE")
        with patch.object(v.subprocess,"run",return_value=response):
            with self.assertRaisesRegex(v.AgentCheckError,"MAC"):
                v.verify_neighbor("198.51.100.20","virbr2","02:11:22:33:44:55")

    def test_healthy_clone_checks_real_bridge_mac_and_cape_agent(self):
        with patch.object(v,"ping_once") as ping, \
             patch.object(v,"verify_neighbor") as neighbor, \
             patch.object(v,"agent_once",return_value={"identity":"CAPE Agent!"}) as curl:
            info=v.wait_for_agent("198.51.100.20",timeout=10,
                 interface="virbr2",expected_mac="02:aa:bb:cc:dd:ee")
        self.assertEqual(info["neighbor_mac"],"PASS")
        ping.assert_called_once_with("198.51.100.20","virbr2")
        neighbor.assert_called_once_with("198.51.100.20","virbr2","02:aa:bb:cc:dd:ee")
        curl.assert_called_once_with("198.51.100.20",interface="virbr2")

    def test_rejects_bridge_without_mac(self):
        with self.assertRaisesRegex(v.AgentCheckError,"together"):
            v.wait_for_agent("198.51.100.20",timeout=10,interface="virbr2")

    def test_no_loopback_for_analysis_guest(self):
        with self.assertRaises(v.AgentCheckError):
            v.wait_for_agent("127.0.0.1")

if __name__=="__main__":
    unittest.main()
