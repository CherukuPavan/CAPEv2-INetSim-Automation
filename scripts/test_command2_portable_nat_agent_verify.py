"""Synthetic MAC-bound CAPE Agent independent Windows NAT witness tests."""
import base64
import json
import tempfile
from pathlib import Path
from urllib.parse import parse_qs
import unittest
from unittest.mock import patch

import command2_portable_nat_agent_verify as g

V="win11_1"
SHA="a"*64
BASE={"vm":V,"host":"lab02","uuid":"00000000-0000-4000-8000-000000000001",
 "mac":"02:ca:22:00:00:01","source_gateway":"192.168.122.1",
 "target_nat_ip":"192.168.122.201","json_sha256":SHA,
 "script_sha256":"b"*64,"fixed_command_sha256":"c"*64}
FIELDS={"result":"COMMAND2_WINDOWS_MASTER_NAT_READONLY_VERIFIED",
 "vm_name":V,"hostname_verified":True,"one_nic_mac_verified":True,
 "dhcp_reserved_ip_observed":True,"gateway_verified":True,"dns_verified":True,
 "external_https_witnessed":True,"sample_execution_authorized":False,
 "this_command_modified_guest":False}
def response(d):
    return {"message":"Successfully executed command","status_code":200,
            "stdout":base64.b64encode((json.dumps(d)+"\n").encode()).decode("ascii")}
class GuestNatWitness(unittest.TestCase):
    def test_exact_pinned_readonly_windows_verify_command(self):
        text=g.verify_command(SHA)
        self.assertIn("-Mode Verify -RequireHTTPS",text)
        self.assertIn("-ExpectedSha256 "+SHA,text)
        self.assertNotIn("-ApproveBenignNat",text)
        self.assertNotIn("-Mode Apply",text)
        with self.assertRaises(g.GuestVerifyBlocked):
            g.verify_command("a"*10)

    def test_agent_readonly_stdout_is_bounded_structured_complete(self):
        all_calls=[]
        def fake(*args):
            all_calls.append(args)
            return response(FIELDS)
        with patch.object(g.transport,"agent_post",side_effect=fake):
            result=g.witness("192.168.122.201","192.168.122.1",SHA,V)
        self.assertTrue(result["real_guest_https_from_nat_ipv4"])
        self.assertEqual(all_calls[0][:3],(
             "192.168.122.201","192.168.122.1","/execute"))
        data=parse_qs(all_calls[0][3].decode("ascii"))
        self.assertEqual(data["encoding"],["base64"])
        self.assertNotIn("async",data)
        self.assertNotIn("shell",data)
        for mutation in (
            {"external_https_witnessed":False},
            {"vm_name":"win11_2"},
            {"sample_execution_authorized":True},
            {"this_command_modified_guest":True},
        ):
            wrong={**FIELDS,**mutation}
            with patch.object(g.transport,"agent_post",return_value=response(wrong)),\
                 self.assertRaises(g.GuestVerifyBlocked):
                g.witness("192.168.122.201","192.168.122.1",SHA,V)

    def test_partial_or_non_json_output_cannot_be_verified(self):
        for response_data in (
            {"message":"Successfully executed command","stdout":"bad-base64"},
            {"message":"Error executing command","stdout":""},
            {"message":"Successfully executed command",
             "stdout":base64.b64encode(b"error: BitLocker recovery needed").decode()},
        ):
            with patch.object(g.transport,"agent_post",return_value=response_data),\
                 self.assertRaises(g.GuestVerifyBlocked):
                g.witness("192.168.122.201","192.168.122.1",SHA,V)

    def test_input_intent_and_receipt_must_be_exact(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            stage=root/(V+g.transport.STAGE_SUFFIX)
            stage.write_bytes(b'{"vm":"win11_1"}')
            intent=root/(V+g.transport.INTENT_SUFFIX)
            approved={"format":g.approved.INTENT_FORMAT,"vm":V,
               "host":"lab02","uuid":BASE["uuid"],"mac":BASE["mac"],
               "target_nat_ip":BASE["target_nat_ip"],
               "json_sha256":BASE["json_sha256"],
               "fixed_command_sha256":BASE["fixed_command_sha256"],
               "stage_receipt_sha256":g.hashlib.sha256(stage.read_bytes()).hexdigest(),
               "execution_started_or_unknown":True,
               "windows_guest_change_completed":False,
               "guest_hostname_dhcp_and_https_verified":False}
            intent.write_text(json.dumps(approved))
            with patch.object(g.transport,"verified_evidence_folder",return_value=root),\
                 patch.object(g.approved,"trusted_stage_json",side_effect=lambda x:
                         json.loads(x.read_text())):
                path=g.validate_intent(BASE,root)
            self.assertFalse(path.exists())
            approved["target_nat_ip"]="192.168.122.99"
            intent.write_text(json.dumps(approved))
            with patch.object(g.transport,"verified_evidence_folder",return_value=root),\
                 patch.object(g.approved,"trusted_stage_json",side_effect=lambda x:
                         json.loads(x.read_text())),\
                 self.assertRaises(g.GuestVerifyBlocked):
                g.validate_intent(BASE,root)

    def test_independent_witness_saved_only_after_double_recheck(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            target=d/(V+g.SUFFIX)
            with patch.object(g,"ready",return_value=(BASE,target)),\
                 patch.object(g,"witness",return_value={
                    "real_guest_https_from_nat_ipv4":True}):
                report=g.collect("lab02",Path("/root/j"),V,
                                 Path("/tmp/nat.iso"),d)
            self.assertTrue(report["real_guest_https_from_nat_ipv4"])
            self.assertTrue(target.exists())
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertFalse(json.loads(target.read_text())["malware_analysis_authorized"])

    def test_no_mutating_vm_guest_or_snapshot_commands(self):
        s=Path(g.__file__).read_text()
        for phrase in ('"snapshot-revert"','"snapshot-delete"','"destroy"',
           '"shutdown"','"restart"','"net-update"','Remove-NetIPAddress',
           'Restart-Computer','-Mode Apply','shell=True'):
            self.assertNotIn(phrase,s)

if __name__=="__main__":unittest.main()
