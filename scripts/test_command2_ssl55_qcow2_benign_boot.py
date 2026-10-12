"""Synthetic-only SSL55 QCOW2 benign boot. NEVER powers a real VM."""
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import command2_ssl55_qcow2_benign_boot as b
VM=b.VM
UID=b.UID
XML=(
    '<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
    '<os><nvram format="qcow2">'+str(b.activation.SIDE)+'</nvram></os>'
    '<devices><disk type="file" device="disk"><driver type="qcow2"/>'
    '<source file="'+str(b.activation.ref.DISK)+'"/></disk>'
    '<interface type="network"><source network="cape-analysis-isolated"/>'
    '<mac address="02:0a:30:6a:3f:50"/></interface>'
    '<tpm><backend type="emulator" version="2.0"/></tpm>'
    '</devices></domain>'
)
def ready_plan():
    return {"result":"SSL55_WIN11_1_QCOW2_FIRST_BENIGN_BOOT_PLAN_ONLY",
            "saved_domain_xml_sha256":"a"*64}

class QCOW2FirstBoot(unittest.TestCase):
    def test_exact_disk_qcow2_firmware_tpm_mac_and_isolation(self):
        self.assertEqual(b.read_xml(XML,expected_state="shut off")["nvram"],
                         str(b.activation.SIDE))
        for bad,term in [
            (XML.replace('nvram format="qcow2"','nvram format="raw"'),"EFI"),
            (XML.replace(str(b.activation.SIDE),str(b.activation.RAW)),"EFI"),
            (XML.replace("cape-analysis-isolated","default"),"NIC"),
            (XML.replace("02:0a:30:6a:3f:50","02:00:00:00:00:aa"),"NIC"),
            (XML.replace(str(b.activation.ref.DISK),"/other/master.qcow2"),"disk"),
            (XML.replace('type="emulator"','type="passthrough"'),"TPM"),
            (XML.replace("</devices>","<hostdev/></devices>"),"host-connected"),
        ]:
            with self.subTest(term=term),self.assertRaisesRegex(b.BootBlocked,term):
                b.read_xml(bad,expected_state="shut off")

    def test_preflight_requires_activated_xml_network_and_no_running_guests(self):
        def v(*args,**kwargs):
            if args==("list","--name"):return ""
            if args==("domstate",VM):return "shut off"
            if args==("dumpxml","--inactive",VM):return XML
            if args[0]=="snapshot-list":return ""
            if args[0]=="domstate":return "shut off"
            if args[0]=="domuuid":return {
                 b.activation.ref.MASTER[0]:b.activation.ref.MASTER[1],
                 b.activation.ref.TRIAL[0]:b.activation.ref.TRIAL[1]}[args[1]]
            raise AssertionError(args)
        with patch.object(b.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.activation,"plan",return_value={
                 "backup_original_xml_sha256":b.activation.XML_SHA}),\
             patch.object(b.oldboot,"verify_guard"),\
             patch.object(b.oldboot,"network_live"),\
             patch.object(b.oldboot.boot,"domain_autostart",return_value=False),\
             patch.object(b,"virsh",side_effect=v):
            self.assertEqual(b.preflight(Path("/safe/original/xml"))["result"],
                             "SSL55_WIN11_1_QCOW2_FIRST_BENIGN_BOOT_PLAN_ONLY")

    def test_paused_start_verifies_live_graph_before_resume(self):
        with tempfile.TemporaryDirectory() as d:
            calls=[]
            states=["shut off"]
            def v(*args,**kwargs):
                calls.append(args)
                if args[:1]==("start",):
                    self.assertEqual(args,("start",VM,"--paused"))
                    states[0]="paused"
                    return ""
                if args[:1]==("resume",):
                    states[0]="running"
                    return ""
                if args[0]=="domstate":
                    return states[0] if args[1]==VM else "shut off"
                if args[0]=="dumpxml":return XML
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(b,"LOCK",Path(d)/"lock"),\
                 patch.object(b,"preflight",return_value=ready_plan()),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="BOOT-SSL55-WIN11_1-QCOW2-BENIGN"),\
                 patch.object(b.os,"fstat",return_value=fs),\
                 patch.object(b,"virsh",side_effect=v),\
                 patch.object(b.oldboot,"verify_guard"),\
                 patch.object(b.oldboot,"network_live"),\
                 patch.object(b.agent,"probe_agent",return_value={
                    "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                    "guest_ip":b.IP,"version":"0.23"}):
                result=b.first_boot(Path("/safe/original/xml"))
            self.assertEqual(states[0],"running")
            self.assertIn(("start",VM,"--paused"),calls)
            self.assertIn(("resume",VM),calls)
            self.assertLess(calls.index(("dumpxml",VM)),calls.index(("resume",VM)))
            self.assertEqual(result["result"],
                             "SSL55_WIN11_1_QCOW2_BOOT_AND_CAPE_AGENT_OK")
            self.assertFalse(result["snapshot_created"])

    def test_bad_live_graph_leaves_vm_paused(self):
        with tempfile.TemporaryDirectory() as d:
            ops=[]
            state=["shut off"]
            def v(*args,**kwargs):
                ops.append(args)
                if args[0]=="start":state[0]="paused";return ""
                if args[0]=="domstate":return state[0]
                if args[0]=="dumpxml":return XML.replace(
                    "cape-analysis-isolated","default")
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(b,"LOCK",Path(d)/"lock"),\
                 patch.object(b,"preflight",return_value=ready_plan()),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="BOOT-SSL55-WIN11_1-QCOW2-BENIGN"),\
                 patch.object(b.os,"fstat",return_value=fs),\
                 patch.object(b,"virsh",side_effect=v):
                with self.assertRaisesRegex(b.BootBlocked,"PARTIAL_VM_STATE"):
                    b.first_boot(Path("/safe/original/xml"))
            self.assertEqual(state[0],"paused")
            self.assertNotIn(("resume",VM),ops)
            self.assertNotIn(("destroy",VM),ops)

    def test_no_malware_or_force_shutdown_or_snapshot(self):
        code=Path(b.__file__).read_text(encoding="utf-8")
        for blocked in ('virsh("destroy"','virsh("shutdown"',
                        'virsh("snapshot-create"','virsh("snapshot-revert"',
                        'virsh("define"','virsh("undefine"','shell=True'):
            self.assertNotIn(blocked,code)

if __name__=="__main__":
    unittest.main()
