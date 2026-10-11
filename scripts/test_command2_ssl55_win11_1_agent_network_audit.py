"""Offline synthetic-only existing win11_1 CAPE agent/route observation tests."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import command2_ssl55_win11_1_agent_network_audit as m


class MockHTTPResponse:
    def __init__(self,status=200,payload=None):
        self.status=status
        self.data=payload if payload is not None else json.dumps({
            "message":"CAPE Agent!","version":"agent-test","is_user_admin":True
        }).encode()
    def read(self,n):return self.data[:n]


class MockHTTP:
    def __init__(self,host,port,timeout,source_address,response):
        assert (host,port,timeout,source_address)==(
            m.IP,8000,4,(m.HOST_IP,0))
        self.response=response
        self.requests=[]
    def request(self,method,path,headers):
        self.requests.append((method,path,headers))
        assert (method,path)==("GET","/")
    def getresponse(self):return self.response
    def close(self):pass


class ReadOnlyAgentTests(unittest.TestCase):
    def test_parse_spaced_libvirt_network_properties(self):
        props=m.properties("Active:        yes\n"
                           "Autostart:      no\n"
                           "Bridge:    cape-lab0")
        self.assertEqual(props["active"],"yes")
        self.assertEqual(props["autostart"],"no")
        with self.assertRaisesRegex(m.CheckBlocked,"Duplicate"):
            m.properties("Active: yes\nActive: no")

    def test_exact_host_route_on_bridge_checked(self):
        good='[{"dst":"192.168.240.101","dev":"cape-lab0","prefsrc":"192.168.240.1"}]'
        with patch.object(m,"run",return_value=good):
            actual=m.check_ipv4_route()
        self.assertEqual(actual["dev"],"cape-lab0")
        for result in (
            '[{"dev":"enp0s31f6","prefsrc":"10.23.105.55"}]',
            '[{"dev":"cape-lab0","prefsrc":"192.168.240.2"}]',
            '[{"dev":"cape-lab0","prefsrc":"192.168.240.1","gateway":"10.1.1.1"}]',
            '[]','garbage'):
            with self.subTest(result=result),\
                 patch.object(m,"run",return_value=result):
                with self.assertRaises(m.CheckBlocked):
                    m.check_ipv4_route()

    def test_agent_exact_private_host_source_and_json_identity(self):
        calls=[]
        def make(*args,**kwargs):
            obj=MockHTTP(*args,**kwargs,response=MockHTTPResponse())
            calls.append(obj)
            return obj
        with patch.object(m.http.client,"HTTPConnection",side_effect=make):
            result=m.probe_agent()
        self.assertEqual(result["status"],"verified")
        self.assertTrue(result["agent_identity_verified"])
        self.assertEqual(calls[0].requests[0][:2],("GET","/"))

    def test_agent_unexpected_service_identity_never_passes(self):
        for payload in (
            b'{"message":"Not CAPE","version":"4","is_user_admin":true}',
            b'{"message":"CAPE Agent!","version":"4","is_user_admin":false}',
            b'not-json',b'{"message":"CAPE Agent!"}',
        ):
            with self.subTest(payload=payload),\
                 patch.object(m.http.client,"HTTPConnection",
                              side_effect=lambda *a,**k:
                               MockHTTP(*a,**k,response=MockHTTPResponse(payload=payload))):
                self.assertFalse(m.probe_agent()["agent_identity_verified"])

    def test_agent_absent_does_not_report_analysis_readiness(self):
        def refuse(*args,**kwargs):
            raise ConnectionRefusedError("No agent listening")
        with patch.object(m.http.client,"HTTPConnection",side_effect=refuse):
            status=m.probe_agent()
        self.assertEqual(status["status"],"unreachable_or_http_error")
        self.assertFalse(status["agent_identity_verified"])

    def test_full_audit_never_claims_external_egress_or_snapshot(self):
        with patch.object(m,"check_vm",return_value={"correct_guest_running":True}),\
             patch.object(m,"check_lab",return_value={"cape_guard_service_active_success":True}),\
             patch.object(m,"check_ipv4_route",return_value={"dev":m.BRIDGE}),\
             patch.object(m,"probe_agent",return_value={
                 "status":"verified","agent_identity_verified":True}):
            from contextlib import redirect_stdout
            import io
            out=io.StringIO()
            with redirect_stdout(out):rc=m.main()
        self.assertEqual(rc,0)
        data=json.loads(out.getvalue())
        for key in ("actual_guest_external_ipv4_negative_probe",
                    "actual_guest_external_ipv6_negative_probe",
                    "real_l2_guest_to_guest_negative_probe",
                    "full_cold_uefi_swtpm_restore_tested",
                    "running_snapshot_created",
                    "safe_for_malware_execution","host_guest_changes"):
            self.assertFalse(data[key])

    def test_unavailable_agent_keeps_report_but_nonzero_exit(self):
        with patch.object(m,"check_vm",return_value={}),\
             patch.object(m,"check_lab",return_value={}),\
             patch.object(m,"check_ipv4_route",return_value={}),\
             patch.object(m,"probe_agent",return_value={
                 "status":"unreachable_or_http_error",
                 "agent_identity_verified":False}):
            from contextlib import redirect_stdout
            import io
            output=io.StringIO()
            with redirect_stdout(output):rc=m.main()
        self.assertEqual(rc,3)
        self.assertIn("unreachable_or_http_error",output.getvalue())

    def test_source_has_no_guest_or_host_mutations(self):
        source=Path(m.__file__).read_text(encoding="utf-8")
        for dangerous in ('"attach-interface"', '"snapshot-create-as"',
                          '"net-start"','"start","win11_1"',
                          '"destroy"', '"shutdown"', '"systemctl","enable"',
                          '"nft","-f"', 'subprocess.Popen',
                          "virsh snapshot", "Set-NetFirewallProfile",
                          "New-NetIPAddress"):
            self.assertNotIn(dangerous,source)


if __name__=="__main__":
    unittest.main()
