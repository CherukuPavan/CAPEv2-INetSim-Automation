"""Synthetic-only tests for existing SSL55 win11_1 benign boot; no host changes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_win11_1_benign_boot as x


NIC='<interface type="network"><source network="'+x.NETWORK+'"/><mac address="'+x.MAC+'"/><model type="e1000e"/></interface>'
XML=('<domain type="kvm"><name>'+x.VM+'</name><uuid>'+x.UUID+'</uuid>'
     '<os><nvram>'+x.NVRAM+'</nvram></os><devices><disk device="disk" '
     'type="file"><driver type="qcow2"/><source file="'+x.DISK+'"/>'
     '</disk><tpm><backend type="emulator" version="2.0"/></tpm>'
     +NIC+'</devices></domain>')
PLAN={"result":"SSL55_WIN11_1_BENIGN_BOOT_PLAN_ONLY","vm_saved_xml_sha256":"A"}


class BenignBootTests(unittest.TestCase):
    def test_exact_saved_guest_is_single_nic_independent_disk_uefi_tpm(self):
        self.assertEqual(len(x.guest_xml(XML)),64)
        with self.assertRaisesRegex(x.BootBlocked,"exactly one"):
            x.guest_xml(XML.replace(NIC,""))
        with self.assertRaisesRegex(x.BootBlocked,"Wrong guest NIC"):
            x.guest_xml(XML.replace(x.MAC,"02:00:00:00:00:01"))
        with self.assertRaisesRegex(x.BootBlocked,"disk or NVRAM"):
            x.guest_xml(XML.replace(x.DISK,"/tmp/foreign.qcow2"))

    def test_preflight_reports_not_booted_and_never_modifies_host(self):
        def v(*a):
            if a==("domuuid",x.VM):return x.UUID
            if a[0]=="domuuid":
                return x.guard.MASTER_UUID if a[1]=="win11" else x.guard.TRIAL_UUID
            if a[0]=="domstate":return "shut off"
            if a==("dumpxml","--inactive",x.VM):return XML
            if a[0]=="dumpxml":
                vm=a[-1]
                mac="<interface/>" if vm=="win11" else ""
                uid=x.guard.MASTER_UUID if vm=="win11" else x.guard.TRIAL_UUID
                return '<domain><name>'+vm+'</name><uuid>'+uid+'</uuid><devices>'+mac+'</devices></domain>'
            if a==("list","--name") or a[0]=="snapshot-list":return ""
            raise AssertionError("Unexpected host mutation/query: "+str(a))
        with patch.object(x,"verify_guard"),\
             patch.object(x,"network_live"),\
             patch.object(x,"guest_xml",return_value="exact-xml-hash"),\
             patch.object(x,"virsh",side_effect=v),\
             patch.object(x.boot,"domain_autostart",return_value=False):
            report=x.preflight()
        self.assertEqual(report["result"],"SSL55_WIN11_1_BENIGN_BOOT_PLAN_ONLY")
        self.assertFalse(report["guest_booted"])
        self.assertFalse(report["malware_analysis_authorized"])
        self.assertFalse(report["host_changes"])

    def test_running_vm_refused_before_boot(self):
        with patch.object(x,"verify_guard"),\
             patch.object(x,"network_live"),\
             patch.object(x,"virsh",side_effect=lambda *a:
                  x.UUID if a==("domuuid",x.VM) else "running"),\
             patch.object(x,"cmd",side_effect=AssertionError("no writes")):
            with self.assertRaisesRegex(x.BootBlocked,"shut-off"):
                x.preflight()

    def test_operator_refusal_makes_no_libvirt_start(self):
        with patch.object(x.os,"geteuid",return_value=0),\
             patch.object(x.sys.stdin,"isatty",return_value=True),\
             patch.object(x,"preflight",return_value=PLAN),\
             patch("builtins.input",return_value="NO"),\
             patch.object(x,"virsh",
                 side_effect=AssertionError("Must not start VM")):
            with self.assertRaisesRegex(x.BootBlocked,"declined"):
                x.boot_benign()

    def test_one_approved_vm_start_exact_and_other_guests_stay_off(self):
        calls=[]
        def fake(*args):
            calls.append(args)
            if args==("start",x.VM):return "Domain started"
            if args==("domstate",x.VM):return "running"
            if args==("domstate","win11"):return "shut off"
            if args==("domstate","win11_trial_1"):return "shut off"
            if args==("dumpxml",x.VM):return XML
            if args==("domuuid",x.VM):return x.UUID
            if args==("list","--name"):return x.VM
            raise AssertionError("Unexpected guest libvirt command "+str(args))
        with tempfile.TemporaryDirectory() as tmp:
            lock=Path(tmp)/"lock"
            meta=type("RootLock",(),{"st_mode":0o100600,
                                    "st_uid":0,"st_nlink":1})()
            with patch.object(x.os,"geteuid",return_value=0),\
                 patch.object(x.os,"fstat",return_value=meta),\
                 patch.object(x.sys.stdin,"isatty",return_value=True),\
                 patch.object(x,"preflight",return_value=PLAN),\
                 patch.object(x,"LOCK",lock),\
                 patch.object(x,"virsh",side_effect=fake),\
                 patch.object(x,"network_live"),\
                 patch.object(x.boot,"domain_autostart",return_value=False),\
                 patch("builtins.input",return_value=x.CONFIRM):
                result=x.boot_benign()
        self.assertEqual(result["result"],
                         "SSL55_WIN11_1_RUNNING_BENIGN_ONLY_NO_ANALYSIS")
        self.assertEqual(calls.count(("start",x.VM)),1)
        self.assertFalse(result["malware_execution_authorized"])
        self.assertFalse(result["running_snapshot_captured"])
        self.assertFalse(any(c[0] in ("snapshot-create-as","shutdown",
                                      "attach-interface","net-start","destroy")
                             for c in calls))

    def test_boot_partial_failure_never_blindly_restores_or_reboots(self):
        calls=[]
        with tempfile.TemporaryDirectory() as tmp:
            meta=type("RootLock",(),{"st_mode":0o100600,
                                    "st_uid":0,"st_nlink":1})()
            def guest(*a):
                calls.append(a)
                if a==("start",x.VM):return "OK"
                if a==("domstate",x.VM):return "shut off"
                raise AssertionError(a)
            with patch.object(x.os,"geteuid",return_value=0),\
                 patch.object(x.os,"fstat",return_value=meta),\
                 patch.object(x.sys.stdin,"isatty",return_value=True),\
                 patch.object(x,"preflight",return_value=PLAN),\
                 patch.object(x,"LOCK",Path(tmp)/"lock"),\
                 patch.object(x,"virsh",side_effect=guest),\
                 patch("builtins.input",return_value=x.CONFIRM):
                with self.assertRaisesRegex(x.BootBlocked,"PARTIAL"):
                    x.boot_benign()
        self.assertEqual(calls,[("start",x.VM),("domstate",x.VM)])

    def test_source_does_not_provide_undesired_guest_host_mutators(self):
        text=Path(x.__file__).read_text(encoding="utf-8")
        implementation=text[text.index("from __future__ import annotations"):]
        for forbidden in ('"attach-interface"', '"net-start"', '"nft","--file"',
                          '"snapshot-create-as"', '"destroy"', '"shutdown"',
                          '"start","win11"', '"start","win11_trial_1"',
                          '"net-define"', 'New-NetIPAddress'):
            self.assertNotIn(forbidden,implementation)


if __name__=="__main__":
    unittest.main()
