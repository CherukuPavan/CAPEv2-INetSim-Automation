#!/usr/bin/env python3
"""Synthetic fixtures for staged win11_1 no-NIC benign boot, never touch libvirt."""
import unittest
from unittest.mock import patch
from pathlib import Path
import command2_boot_first_cloned_windows as b
import stage_first_no_nic_windows_clone as stage
from test_stage_first_no_nic_windows_clone import fixture

def domain():
    return stage.render(
        fixture(),identifier=b.IDENT,name=b.NAME,disk=b.DISK,nvram=b.NVRAM)

class Tests(unittest.TestCase):
    def test_staged_clone_xml_from_real_renderer_allowed(self):
        root=b.check_xml(domain())
        self.assertEqual(root.findtext("name"),"win11_1")
        self.assertFalse(root.findall("./devices/interface"))

    def test_trial_disk_is_not_allowed_for_real_win11_1(self):
        xml=domain().replace("win11_1.command2.qcow2","win11_trial_1.qcow2")
        with self.assertRaisesRegex(b.BootBlocked,"disk path"):
            b.check_xml(xml)

    def test_guest_nat_nic_forbidden(self):
        xml=domain().replace("</devices>",
          '<interface type="network"><source network="default"/></interface></devices>')
        with self.assertRaisesRegex(b.BootBlocked,"interface"):
            b.check_xml(xml)

    def test_unexpected_tpm_socket_forbidden(self):
        xml=domain().replace(
           '<backend type="emulator" version="2.0" />',
           '<backend type="emulator" version="2.0"><source '
           'path="/run/libvirt/qemu/swtpm/7-win11-swtpm.sock" /></backend>')
        with self.assertRaisesRegex(b.BootBlocked,"socket"):
            b.check_xml(xml)

    def test_graphics_exposure_forbidden(self):
        xml=domain().replace('listen="127.0.0.1"','listen="0.0.0.0"')
        with self.assertRaisesRegex(b.BootBlocked,"loopback"):
            b.check_xml(xml)

    def test_boot_starts_paused_and_checks_before_resume(self):
        calls=[]
        def mock_virsh(*args):
            calls.append(args)
            if args==("start",b.NAME,"--paused"):return ""
            if args==("domstate",b.NAME):
                return "paused" if ("resume",b.NAME) not in calls else "running"
            if args==("dumpxml",b.NAME):return "<domain/>"
            if args==("resume",b.NAME):return ""
            raise AssertionError("Unexpected virsh: "+str(args))
        with patch.object(b,"preflight",return_value={
                 "result":"COMMAND2A_FIRST_BOOT_PREFLIGHT_PASSED"}),\\
             patch.object(b.tpm,"prepare",return_value={
                 "status":"INSTALLED"}) as apparmor,\\
             patch.object(b,"check_xml") as verify_xml,\\
             patch.object(b,"check_master_and_trial"):
            with patch.object(b,"virsh",side_effect=mock_virsh):
                report=b.boot()
        self.assertEqual(report["result"],"COMMAND2A_NEW_CLONE_BOOTED_ZERO_NICS")
        self.assertEqual(calls[0],("start",b.NAME,"--paused"))
        self.assertEqual(calls[1],("domstate",b.NAME))
        self.assertEqual(calls[2],("dumpxml",b.NAME))
        self.assertEqual(calls[3],("resume",b.NAME))
        self.assertFalse(report["malware_execution_authorized"])
        self.assertFalse(report["windows_login_verified"])
        self.assertFalse(report["windows_static_ip_assigned"])
        apparmor.assert_called_once_with(b.NAME,b.IDENT,apply=True)
        self.assertEqual(verify_xml.call_count,2)

    def test_paused_live_nic_check_blocks_before_cpu_resume(self):
        seen=[]
        def mock_virsh(*args):
            seen.append(args)
            if args==("start",b.NAME,"--paused"):return ""
            if args==("domstate",b.NAME):return "paused"
            if args==("dumpxml",b.NAME):return "<domain/>"
            raise AssertionError("Unexpected action")
        with patch.object(b,"preflight",return_value={}),\\
             patch.object(b.tpm,"prepare",return_value={"status":"INSTALLED"}),\\
             patch.object(b,"check_xml",side_effect=b.BootBlocked("NIC")),\\
             patch.object(b,"virsh",side_effect=mock_virsh):
            with self.assertRaisesRegex(b.BootBlocked,"NIC"):
                b.boot()
        self.assertNotIn(("resume",b.NAME),seen)
        self.assertNotIn(("start",b.MASTER),seen)

    def test_failed_running_check_suspends_only_exact_owned_clone(self):
        calls=[]
        def mock_virsh(*args):
            calls.append(args)
            if args==("start",b.NAME,"--paused"):return ""
            if args==("domstate",b.NAME):
                return "running" if ("resume",b.NAME) in calls else "paused"
            if args==("dumpxml",b.NAME):return "<domain/>"
            if args==("resume",b.NAME):return ""
            if args==("domuuid",b.NAME):return b.IDENT
            if args==("suspend",b.NAME):return ""
            raise AssertionError("Unexpected action: "+str(args))
        with patch.object(b,"preflight",return_value={}),\\
             patch.object(b.tpm,"prepare",return_value={"status":"INSTALLED"}),\\
             patch.object(b,"check_xml"),\\
             patch.object(b,"check_master_and_trial",
                 side_effect=[None,b.BootBlocked("poststart")]),\\
             patch.object(b,"virsh",side_effect=mock_virsh):
            with self.assertRaisesRegex(b.BootBlocked,"poststart"):
                b.boot()
        self.assertIn(("suspend",b.NAME),calls)
        self.assertNotIn(("destroy",b.NAME),calls)
        self.assertNotIn(("suspend",b.MASTER),calls)

if __name__=="__main__":unittest.main()
