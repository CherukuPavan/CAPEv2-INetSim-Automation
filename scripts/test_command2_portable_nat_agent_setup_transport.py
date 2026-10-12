"""Offline-only guarded trusted CAPE Agent upload/identity tests.

No Windows command or malware execution, all service calls mocked.
"""
from pathlib import Path
import hashlib
import json
import os
import tempfile
from unittest.mock import patch
import unittest
import xml.etree.ElementTree as ET

import command2_portable_nat_agent_setup_transport as g

VM="win11_1"
UUID="00000000-0000-4000-8000-000000000001"
MAC="02:ca:22:00:00:01"
JOURNAL=Path("/root/cape/command2-identity-reservation.json")
CONFIG={
  "format":"COMMAND2_MASTER_NAT_WINDOWS_V1",
  "guest_name":VM,"nic_network":"default","bridge":"virbr0",
  "malware_public_internet_authorized":False,
  "expected_machine_uuid":UUID,"nic_mac":MAC,
  "ipv4":"192.168.122.201","default_gateway":"192.168.122.1"
}
ROW={"libvirt_name":VM,"libvirt_uuid_candidate":UUID,"mac_candidate":MAC}
DOMAIN=('<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+'</uuid>'
        '<devices><interface type="network"><source network="default"/>'
        '<mac address="'+MAC+'"/><model type="e1000e"/>'
        '</interface></devices></domain>')
def fake_virsh(*args,**kwargs):
    if args==("domuuid",VM):return UUID
    if args==("domstate",VM):return "running"
    if args==("domstate","win11"):return "shut off"
    if args==("list","--name"):return VM
    if args[0]=="dumpxml":return DOMAIN
    raise AssertionError(args)

class BenignTransport(unittest.TestCase):
    def test_guest_profile_is_pinned_to_json_and_exact_repo_script(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_1.master-nat.iso"
            iso.write_bytes(b"synthetic fixture")
            doc=(json.dumps(CONFIG,sort_keys=True)+"\n").encode()
            digest=hashlib.sha256(doc).hexdigest()
            script=b"#Requires -Version 5.1\n# safe benign fixture"
            def contents(_,leaf):
                return {"nat-config.json":doc,
                        "nat-config.sha256":(digest+"\n").encode(),
                        "command2_guest_master_nat.ps1":script}[leaf]
            with patch.object(g,"iso_entry",side_effect=contents),\
                 patch.object(g.media,"script_source",return_value=script):
                result=g.iso_profile(VM,iso)
            self.assertEqual(result["config_sha256"],digest)
            self.assertEqual(result["config"]["ipv4"],"192.168.122.201")
            with patch.object(g,"iso_entry",side_effect=contents),\
                 patch.object(g.media,"script_source",return_value=b"OTHER"),\
                 self.assertRaisesRegex(g.TransportBlocked,"script differs"):
                g.iso_profile(VM,iso)
            def mismatch(_,leaf):
                return b"tampered config" if leaf=="nat-config.json" else contents(_,leaf)
            with patch.object(g,"iso_entry",side_effect=mismatch),\
                 patch.object(g.media,"script_source",return_value=script),\
                 self.assertRaisesRegex(g.TransportBlocked,"pinned ISO"):
                g.iso_profile(VM,iso)

    def test_only_one_running_protected_clone_owning_exact_neighbor_mac(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_1.master-nat.iso"
            iso.write_bytes(b"mock")
            details={"config":CONFIG,
                     "config_sha256":"a"*64,"script_sha256":"b"*64}
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=[ROW]),\
                 patch.object(g.attach,"virsh",side_effect=fake_virsh),\
                 patch.object(g,"iso_profile",return_value=details),\
                 patch.object(g.attach.profile,"check_active_nat",
                   return_value={"ipv4":{
                       "subnet":"192.168.122.0/24",
                       "gateway":"192.168.122.1"}}),\
                 patch.object(g,"agent_get",return_value={
                     "ip":"192.168.122.201","agent_version":"0.23"}),\
                 patch.object(g,"mac_of_neighbor",return_value=MAC):
                report=g.inspect("lab02",JOURNAL,VM,iso)
            self.assertEqual(report["bootstrap_ip"],"192.168.122.201")
            self.assertEqual(report["uuid"],UUID)
            self.assertFalse(report["agent_powershell_upload_or_execution_done"])
            with patch.object(g.attach.workflow,"canonical_host",return_value="lab02"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.attach,"journal_rows",return_value=[ROW]),\
                 patch.object(g.attach,"virsh",side_effect=fake_virsh),\
                 patch.object(g,"iso_profile",return_value=details),\
                 patch.object(g.attach.profile,"check_active_nat",
                   return_value={"ipv4":{
                       "subnet":"192.168.122.0/24",
                       "gateway":"192.168.122.1"}}),\
                 patch.object(g,"agent_get",return_value={
                     "ip":"192.168.122.201","agent_version":"0.23"}),\
                 patch.object(g,"mac_of_neighbor",return_value="02:ca:22:00:00:ff"),\
                 self.assertRaisesRegex(g.TransportBlocked,"unique elevated"):
                g.inspect("lab02",JOURNAL,VM,iso)

    def test_store_uploads_only_exact_whitelisted_setup_files(self):
        captured=[]
        def outgoing(ip,source,path,body,ctype):
            captured.append((ip,source,path,body,ctype))
            return {"message":"Successfully stored file"}
        with patch.object(g,"agent_post",side_effect=outgoing):
            a=g.store("192.168.122.201","192.168.122.1",
                      "nat-config.json",b'{"benign":true}')
            b=g.store("192.168.122.201","192.168.122.1",
                      "command2_guest_master_nat.ps1",b"# ben")
        self.assertEqual(len(captured),2)
        self.assertTrue(all(z[2]=="/store" for z in captured))
        self.assertIn(b"C:/CAPE_NAT2/nat-config.json",captured[0][3])
        self.assertIn("multipart/form-data",captured[0][4])
        self.assertEqual(a["remote_path"],"C:/CAPE_NAT2/nat-config.json")
        self.assertEqual(b["remote_path"],
                         "C:/CAPE_NAT2/command2_guest_master_nat.ps1")
        with self.assertRaisesRegex(g.TransportBlocked,"only reviewed"):
            g.store("192.168.122.201","192.168.122.1",
                    "unreviewed.exe",b"BAD")

    def test_stage_receipt_is_root_private_no_windows_execution(self):
        with tempfile.TemporaryDirectory() as td:
            iso=Path(td)/"win11_1.master-nat.iso"
            iso.write_bytes(b"mock")
            evidence=Path(td)/"evidence"
            evidence.mkdir(mode=0o700)
            before={"vm":VM,"uuid":UUID,"mac":MAC,
                    "bootstrap_ip":"192.168.122.201",
                    "source_gateway":"192.168.122.1",
                    "target_nat_ipv4":"192.168.122.201",
                    "iso_config_sha256":"a"*64,
                    "approved_script_sha256":"b"*64}
            meta={"config_bytes":b'{"benign":true}',
                  "script_bytes":b"#Requires -Version 5.1",
                  "config_sha256":"a"*64}
            with patch.object(g.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                   "UPLOAD-ONLY-TRUSTED-NAT-WINDOWS-SETUP-WIN11_1")),\
                 patch.object(g,"inspect",return_value=before),\
                 patch.object(g,"iso_profile",return_value=meta),\
                 patch.object(g,"store",side_effect=lambda ip,src,name,data:
                     {"remote_path":"C:/CAPE_NAT2/"+name,"bytes":len(data)}),\
                 patch.object(g.os,"geteuid",return_value=0):
                result=g.stage("lab02",JOURNAL,VM,iso,evidence)
            self.assertEqual(result["result"],
                "COMMAND2_TRUSTED_GUEST_NAT_MEDIA_UPLOADED_NOT_EXECUTED")
            file=evidence/(VM+g.STAGE_SUFFIX)
            self.assertTrue(file.is_file())
            self.assertEqual(os.stat(file).st_mode & 0o777,0o600)
            self.assertFalse(json.loads(file.read_text())["powershell_executed"])
            with patch.object(g.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=(
                   "UPLOAD-ONLY-TRUSTED-NAT-WINDOWS-SETUP-WIN11_1")),\
                 patch.object(g,"inspect",return_value=before),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 self.assertRaisesRegex(g.TransportBlocked,"stage witness"):
                g.stage("lab02",JOURNAL,VM,iso,evidence)

    def test_does_not_run_windows_scripts_firewalls_snapshots_or_malware(self):
        s=Path(g.__file__).read_text()
        for item in ('"snapshot-revert"','"snapshot-delete"',
                     '"shutdown"','"destroy"','"start"',
                     '"net-update"','"attach-interface"',
                     '"execute",','os.replace(', 'shell=True'):
            self.assertNotIn(item,s)
if __name__=="__main__":unittest.main()
