#!/usr/bin/env python3
"""Synthetic gated Windows clone resume tests; never touch real guest."""
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import stage_first_no_nic_windows_clone as stage
import resume_first_no_nic_windows_clone as m
from test_clone_domain_xml import MASTER

def clone_xml():
    return stage.render(MASTER,identifier=m.UUID)

class Tests(unittest.TestCase):
    def test_offline_trial_xml_has_no_nic(self):
        m.check_trial(clone_xml())

    def test_refuses_nic_in_live_xml(self):
        xml=clone_xml().replace("</devices>",
                "<interface type='user'/></devices>")
        with self.assertRaisesRegex(m.ResumeBlocked,"interface"):
            m.check_trial(xml)

    def test_refuses_shared_original_tpm_socket(self):
        xml=clone_xml()
        root=ET.fromstring(xml)
        backend=root.find("./devices/tpm/backend")
        ET.SubElement(backend,"source",{"path":"/run/libvirt/qemu/swtpm/master-win11-swtpm.sock"})
        with self.assertRaisesRegex(m.ResumeBlocked,"swtpm"):
            m.check_trial(ET.tostring(root,encoding="unicode"))

    def test_refuses_non_paused_guest(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m,"check_master"),\
             patch.object(m,"check_firmware_and_files"),\
             patch.object(m,"virsh",side_effect=[
                 m.UUID,"running"
             ]) as virsh:
            with self.assertRaisesRegex(m.ResumeBlocked,"already be paused"):
                m.preflight()
            self.assertNotIn(("resume",m.NAME),
                             [c.args for c in virsh.call_args_list])

    def test_plan_never_resumes(self):
        with patch.object(m,"preflight",return_value={"trial_state":"PAUSED"}),\
             patch.object(m,"virsh") as virsh:
            report=m.perform("plan")
        self.assertFalse(report["guest_resumed"])
        virsh.assert_not_called()

    def test_resume_only_trial_and_recheck(self):
        replies=["","running","<domain/>"]
        with patch.object(m,"preflight",return_value={"trial_state":"PAUSED"}),\
             patch.object(m,"check_trial"),\
             patch.object(m,"check_master"),\
             patch.object(m,"virsh",side_effect=replies) as virsh:
            report=m.perform("resume")
        self.assertTrue(report["guest_resumed"])
        calls=[c.args for c in virsh.call_args_list]
        self.assertEqual(calls[0],("resume",m.NAME))
        self.assertNotIn(("resume",m.MASTER),calls)

    def test_after_resume_live_xml_violation_pauses_trial(self):
        def virsh(*args):
            if args[0]=="resume":return ""
            if args[0]=="domstate":return "running"
            if args[0]=="dumpxml":return "<domain/>"
            if args[0]=="suspend":return ""
            raise AssertionError("Unexpected libvirt call")
        with patch.object(m,"preflight",return_value={}),\
             patch.object(m,"check_trial",side_effect=m.ResumeBlocked("Unexpected NIC")),\
             patch.object(m,"virsh",side_effect=virsh) as v:
            with self.assertRaisesRegex(m.ResumeBlocked,"NIC"):
                m.perform("resume")
        calls=[c.args for c in v.call_args_list]
        self.assertIn(("suspend",m.NAME),calls)
        self.assertNotIn(("suspend",m.MASTER),calls)

if __name__=="__main__":
    unittest.main()
