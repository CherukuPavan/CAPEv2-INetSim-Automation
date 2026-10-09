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

    def test_no_loopback_for_analysis_guest(self):
        with self.assertRaises(v.AgentCheckError):
            v.wait_for_agent("127.0.0.1")

if __name__=="__main__":
    unittest.main()
