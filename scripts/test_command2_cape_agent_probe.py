"""No-network mock tests for a strict CAPE Windows agent HTTP probe."""
from contextlib import contextmanager
import json
import unittest
from unittest.mock import patch
import urllib.error
import command2_cape_agent_probe as a


class Response:
    status=200
    def __init__(self, data):
        self.data=data
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def read(self,number):
        return self.data[:number]


class Transport:
    def __init__(self, content):
        self.content=content
        self.last=None
    def open(self, request, timeout):
        self.last=(request.full_url,timeout)
        return Response(self.content)


class AgentProbeTests(unittest.TestCase):
    def test_expected_cape_json_and_exact_port(self):
        wire=Transport(json.dumps({
            "message":"CAPE Agent!","version":"0.22",
            "is_user_admin":True,"features":["execute"]}).encode())
        result=a.probe_agent("192.168.240.101",opener=wire)
        self.assertEqual(wire.last,("http://192.168.240.101:8000/",4))
        self.assertEqual(result["result"],"COMMAND2_CAPE_AGENT_READONLY_VERIFIED")
        self.assertFalse(result["samples_executed"])
        self.assertFalse(result["files_sent"])

    def test_non_rfc1918_address_never_called(self):
        class BadOpener:
            def open(self,*a,**k):raise AssertionError("Do not connect")
        for ip in ("1.1.1.1","127.0.0.1","169.254.10.3",
                   "224.0.0.1","::1","example.com"):
            with self.subTest(ip=ip),self.assertRaises(a.AgentBlocked):
                a.probe_agent(ip,opener=BadOpener())

    def test_wrong_non_cape_service_is_rejected(self):
        for reply in (
            {"message":"Other service","version":"1","is_user_admin":True},
            {"message":"CAPE Agent!","version":"0.22","is_user_admin":False},
            {"message":"CAPE Agent!","version":0.22,"is_user_admin":True},
            {"status":"ok"},
        ):
            with self.subTest(reply=reply),self.assertRaises(a.AgentBlocked):
                a.probe_agent("172.28.240.101",
                              opener=Transport(json.dumps(reply).encode()))

    def test_bounded_response_prevents_unbounded_memory(self):
        with self.assertRaisesRegex(a.AgentBlocked,"larger"):
            a.probe_agent("10.254.240.101",opener=Transport(b"x"*9000))

    def test_bad_json_rejected(self):
        with self.assertRaisesRegex(a.AgentBlocked,"not JSON"):
            a.probe_agent("10.254.240.101",opener=Transport(b"<html/>"))

    def test_no_write_actions_or_exec_endpoints(self):
        from pathlib import Path
        src=Path(a.__file__).read_text()
        self.assertIn('method="GET"',src)
        for code in ("subprocess.run","os.system(", "method=\"POST\"",
                     "virsh","/execute","/upload","/execpy"):
            self.assertNotIn(code,src)


if __name__=="__main__":
    unittest.main()
