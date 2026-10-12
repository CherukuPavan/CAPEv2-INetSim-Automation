"""Pure regression tests for OTHER-host first ZERO-NIC identity VM boot.

No libvirt boot performed in these tests; real Windows/template acceptance is
still required. The boot phase refuses SSL55 through the shared host guard.
"""
import stat
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import command2_portable_identity_boot as b

VM="win11_1"
UID="12345678-1234-4234-8234-000000000001"
DISK="/private/win11_1.command2.qcow2"
VARS="/private/win11_1.command2_VARS.fd"
ISO="/private/win11_1.command2_identity.iso"

def row():
    return {"libvirt_name":VM,"libvirt_uuid_candidate":UID,
            "disk_target":DISK,"uefi_nvram_target":VARS}

def domain(nic="",disk=DISK,iso=ISO):
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+
            '</uuid><os><nvram format="raw">'+VARS+'</nvram></os>'
            '<devices><disk type="file" device="disk">'
            '<driver type="qcow2"/><source file="'+disk+'"/>'
            '</disk><disk type="file" device="cdrom">'
            '<source file="'+iso+'"/><readonly/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            +nic+'</devices></domain>')

def mock_plan():
    return {"identity_iso":ISO,"uuid":UID,"result":"PLAN"}

class IdentityBootTests(unittest.TestCase):
    def test_saved_identity_xml_admitted_only_with_expected_reserved_state(self):
        self.assertTrue(b.read_domain(domain(),VM,row(),Path(ISO)))
        with self.assertRaisesRegex(b.BootBlocked,"zero NIC"):
            b.read_domain(domain('<interface type="network"/>'),VM,row(),Path(ISO))
        with self.assertRaisesRegex(b.BootBlocked,"OS disk"):
            b.read_domain(domain(disk="/other/master.qcow2"),VM,row(),Path(ISO))
        with self.assertRaisesRegex(b.BootBlocked,"identity-only"):
            b.read_domain(domain(iso="/other/unknown.iso"),VM,row(),Path(ISO))
        with self.assertRaisesRegex(b.BootBlocked,"host passthrough"):
            b.read_domain(domain('<hostdev/>'),VM,row(),Path(ISO))

    def test_protected_host_refused_by_inherited_guard(self):
        with patch.object(b.workflow.socket,"gethostname",return_value="CSE-SSL-55"):
            with self.assertRaisesRegex(b.workflow.WorkflowBlocked,"Protected SSL-55"):
                b.workflow.canonical_host("cse-ssl-55")

    def test_boot_starts_paused_inspects_then_resumes_only_named_vm(self):
        with TemporaryDirectory() as td:
            lock=Path(td)/"lock"
            events=[]
            state={"vm":"shut off"}
            def cmd(*args,**kwargs):
                if args[0]=="start":
                    self.assertEqual(args[1:],(VM,"--paused"))
                    events.append("start-paused")
                    state["vm"]="paused"
                    return ""
                if args[0]=="resume":
                    self.assertEqual(args[1:],(VM,))
                    events.append("resume")
                    state["vm"]="running"
                    return ""
                if args[0]=="domstate":
                    return "shut off" if args[1]=="win11" else state["vm"]
                if args[0]=="dumpxml":
                    return domain()
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(b,"LOCK",lock),\
                 patch.object(b,"checked_plan",return_value=mock_plan()),\
                 patch.object(b,"input",return_value="BOOT-ZERO-NIC-IDENTITY-WIN11_1"),\
                 patch.object(b,"virsh",side_effect=cmd),\
                 patch.object(b.workflow.snapshotgate,"reservation_rows",
                              return_value=[row()]),\
                 patch.object(b,"read_domain",return_value=True),\
                 patch.object(b.os,"fstat",return_value=fs):
                result=b.boot("other-host",Path("/private/journal.json"),VM)
            self.assertEqual(events,["start-paused","resume"])
            self.assertTrue(result["guest_running"])
            self.assertFalse(result["windows_hostname_verified"])

    def test_failed_paused_live_validation_never_resumes_or_destroys(self):
        with TemporaryDirectory() as td:
            lock=Path(td)/"lock"
            calls=[]
            def cmd(*args,**kwargs):
                calls.append(args)
                if args[0]=="start":return ""
                if args[0]=="domstate":return "paused"
                if args[0]=="dumpxml":return domain()
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(b,"LOCK",lock),\
                 patch.object(b,"checked_plan",return_value=mock_plan()),\
                 patch.object(b,"input",return_value="BOOT-ZERO-NIC-IDENTITY-WIN11_1"),\
                 patch.object(b,"virsh",side_effect=cmd),\
                 patch.object(b.workflow.snapshotgate,"reservation_rows",
                              return_value=[row()]),\
                 patch.object(b,"read_domain",side_effect=b.BootBlocked("live XML drift")),\
                 patch.object(b.os,"fstat",return_value=fs):
                with self.assertRaisesRegex(b.BootBlocked,"live XML drift"):
                    b.boot("other-host",Path("/private/journal.json"),VM)
            self.assertNotIn("resume",[x[0] for x in calls])
            self.assertNotIn("destroy",[x[0] for x in calls])

    def test_cli_is_one_vm_with_separate_boot_consent(self):
        code=Path(b.__file__).read_text(encoding="utf-8")
        for required in ('--mode','--approved-host','--journal','--vm',
                         'BOOT-ZERO-NIC-IDENTITY-',
                         'virsh("start",vm,"--paused"',
                         'virsh("resume",vm',
                         "windows_bootstrap_task_executed_verified"):
            self.assertIn(required,code)
        for forbidden in ('virsh("destroy"', 'virsh("shutdown"',
                          'virsh("attach-interface"', 'virsh("snapshot-create'):
            self.assertNotIn(forbidden,code)

if __name__=="__main__":
    unittest.main()
