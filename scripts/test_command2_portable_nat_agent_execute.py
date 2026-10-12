"""No actual CAPE Agent/Windows calls: golden-master NAT async apply tests."""
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_nat_agent_execute as g

VM="win11_1"
UUID="00000000-0000-4000-8000-000000000001"
MAC="02:ca:22:00:00:01"
J=Path("/root/cape/command2-identity-reservation.json")
SHA="a"*64
BEFORE={"vm":VM,"uuid":UUID,"mac":MAC,"bootstrap_ip":"192.168.122.125",
 "source_gateway":"192.168.122.1","target_nat_ipv4":"192.168.122.201",
 "iso_config_sha256":SHA,"approved_script_sha256":"b"*64}
STAGE={"format":"COMMAND2_TRUSTED_WINDOWS_NAT_UPLOAD_ONLY_V1",
 "approved_host":"lab02","vm":VM,"vm_uuid":UUID,"mac":MAC,
 "bootstrap_ip":"192.168.122.125","gateway":"192.168.122.1",
 "target_ip":"192.168.122.201","json_sha256":SHA,
 "script_sha256":"b"*64,
 "remote_files":["C:/CAPE_NAT2/nat-config.json",
                 "C:/CAPE_NAT2/command2_guest_master_nat.ps1"],
 "powershell_executed":False,"windows_hostname_ipv4_verified":False}

class GuestExecute(unittest.TestCase):
    def evidence(self,td):
        d=Path(td)/"evidence"; d.mkdir(mode=0o700)
        p=d/(VM+g.transport.STAGE_SUFFIX)
        p.write_text(json.dumps(STAGE));p.chmod(0o600)
        return d

    def test_exact_hardcoded_benign_command_no_shell(self):
        expected=g.script_command(SHA)
        self.assertEqual(expected.count("powershell.exe"),1)
        self.assertIn("-File C:/CAPE_NAT2/command2_guest_master_nat.ps1",expected)
        self.assertIn("-ConfigFile C:/CAPE_NAT2/nat-config.json",expected)
        self.assertIn("-Mode Apply -ApproveBenignNat -ApproveRename",expected)
        self.assertNotIn("cmd.exe",expected)
        for wrong in ("", "x"*64,"a"*63+";"):
            with self.assertRaises(g.GuestExecuteBlocked):
                g.script_command(wrong)

    def test_prefight_binds_exact_stage_sha_mac_ip_and_no_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.evidence(td)
            with patch.object(g.transport,"verified_evidence_folder",return_value=d),\
                 patch.object(g.transport,"inspect",return_value=BEFORE),\
                 patch.object(g.transport.attach,"virsh",return_value=""):
                plan=g.authorized_stage("lab02",J,VM,Path("/root/ISO.iso"),d)
            self.assertEqual(plan["target_nat_ip"],"192.168.122.201")
            self.assertFalse(plan["guest_powershell_executed"])
            self.assertFalse(plan["guest_hostname_ipv4_https_independently_verified"])
            with patch.object(g.transport,"verified_evidence_folder",return_value=d),\
                 patch.object(g.transport,"inspect",return_value=BEFORE),\
                 patch.object(g.transport.attach,"virsh",return_value="snapshot-ready"),\
                 self.assertRaisesRegex(g.GuestExecuteBlocked,"existing snapshots"):
                g.authorized_stage("lab02",J,VM,Path("/root/ISO.iso"),d)

    def test_stage_from_other_guest_or_changed_mac_never_authorized(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.evidence(td)
            p=d/(VM+g.transport.STAGE_SUFFIX)
            p.write_text(json.dumps({**STAGE,"mac":"02:ca:22:00:00:99"}))
            with patch.object(g.transport,"verified_evidence_folder",return_value=d),\
                 patch.object(g.transport,"inspect",return_value=BEFORE),\
                 self.assertRaisesRegex(g.GuestExecuteBlocked,"does not match"):
                g.authorized_stage("lab02",J,VM,Path("/tmp/x.iso"),d)

    def test_upstream_agent_execute_posts_async_form_without_shell_flag(self):
        sent=[]
        def fake(ip,src,path,body,ctype):
            sent.append((ip,src,path,body,ctype))
            return {"message":"Successfully executed command","status_code":200}
        with patch.object(g.transport,"agent_post",side_effect=fake):
            outcome=g.request_execute("192.168.122.125","192.168.122.1",SHA)
        self.assertTrue(outcome["http_accepted_async_powerShell_request"])
        self.assertFalse(outcome["windows_dhcp_ipv4_hostname_https_verified"])
        self.assertEqual(sent[0][:3],("192.168.122.125","192.168.122.1","/execute"))
        form=parse_qs(sent[0][3].decode("ascii"))
        self.assertEqual(form["async"],["1"])
        self.assertEqual(form["command"],[g.script_command(SHA)])
        self.assertNotIn("shell",form)

    def test_exact_one_attempt_intent_durable_no_auto_retry(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.evidence(td)
            calls=[]
            def post(*x):
                calls.append(x)
                raise g.transport.TransportBlocked("connection dropped mid-request")
            with patch.object(g.transport,"verified_evidence_folder",return_value=d),\
                 patch.object(g.transport,"inspect",return_value=BEFORE),\
                 patch.object(g.transport.attach,"virsh",return_value=""),\
                 patch.object(g.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                    return_value="EXECUTE-ONLY-TRUSTED-WINDOWS-NAT-SETUP-WIN11_1"),\
                 patch.object(g.transport,"agent_post",side_effect=post),\
                 self.assertRaisesRegex(g.GuestExecuteBlocked,"MAY_HAVE_RUN"):
                g.apply("lab02",J,VM,Path("/root/ISO.iso"),d)
            self.assertEqual(len(calls),1)
            receipt=d/(VM+g.transport.INTENT_SUFFIX)
            self.assertTrue(receipt.exists())
            self.assertEqual(receipt.stat().st_mode & 0o777,0o600)
            self.assertTrue(json.loads(receipt.read_text())["no_retry_even_if_connection_lost"])
            with patch.object(g.transport,"verified_evidence_folder",return_value=d),\
                 patch.object(g.transport,"inspect",return_value=BEFORE),\
                 patch.object(g.transport.attach,"virsh",return_value=""),\
                 self.assertRaisesRegex(g.GuestExecuteBlocked,"already journaled"):
                g.authorized_stage("lab02",J,VM,Path("/root/ISO.iso"),d)

    def test_no_malware_command_revert_reboot_or_firewall(self):
        text=Path(g.__file__).read_text(encoding="utf-8")
        for key in ('"snapshot-revert"','"snapshot-delete"','"destroy"',
                    '"shutdown"','"restart"','"net-update"','shell=True',
                    'Restart-Computer','Set-MpPreference','DisableFirewall'):
            self.assertNotIn(key,text)

if __name__=="__main__":unittest.main()
