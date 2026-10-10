#!/usr/bin/env python3
"""Pure mocked first trial paused-start checks, no real VM/TPM startup."""
import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch
import stage_first_no_nic_windows_clone as staging
import start_first_no_nic_windows_clone_paused as m
from test_clone_domain_xml import MASTER

def clone():
    return staging.render(MASTER,identifier=m.UUID)

class Tests(unittest.TestCase):
    def test_zero_nic_clone_xml_succeeds(self):
        root=m.check_xml(clone(),live=False)
        self.assertEqual(root.findtext("name"),m.NAME)
        self.assertFalse(root.findall("./devices/interface"))
        self.assertEqual(root.findtext("./os/nvram"),m.NVRAM)

    def test_rejects_guest_nic_before_start(self):
        xml=clone().replace("</devices>",
                            "<interface type='user'/></devices>")
        with self.assertRaisesRegex(m.PausedStartError,"interface"):
            m.check_xml(xml,live=False)

    def test_rejects_shared_tpm_socket(self):
        xml=clone().replace("<backend type=\"emulator\" version=\"2.0\" />",
                            "<backend type=\"emulator\" version=\"2.0\">"
                            "<source path='/run/libvirt/qemu/swtpm/old-win11-swtpm.sock'/>"
                            "</backend>")
        with self.assertRaises(m.PausedStartError):
            m.check_xml(xml,live=False)

    def test_rejects_forwarded_graphics(self):
        xml=clone().replace('listen="127.0.0.1"','listen="0.0.0.0"')
        with self.assertRaisesRegex(m.PausedStartError,"loopback"):
            m.check_xml(xml,live=False)

    def test_first_start_only_paused_and_never_resume(self):
        with patch.object(m,"examine",return_value={"trial_vm_offline":True}), \
             patch.object(m,"check_xml"), \
             patch.object(m,"virsh",side_effect=[
                 "", "paused", "<domain/>", "shut off"
             ]) as v:
            result=m.paused_start()
        self.assertEqual(result["result"],"TRIAL_FIRST_START_PAUSED_SAFE")
        self.assertFalse(result["guest_cpus_resumed"])
        calls=[c.args for c in v.call_args_list]
        self.assertEqual(calls[0],("start",m.NAME,"--paused"))
        self.assertNotIn(("resume",m.NAME),calls)
        self.assertNotIn(("start",m.MASTER),calls)

    def test_unsafe_live_xml_safety_stops_trial_only(self):
        def guest(*args):
            if args[0]=="start":return ""
            if args[0]=="domstate":return "paused"
            if args[0]=="dumpxml":return "<domain/>"
            if args[0]=="destroy":return ""
            raise AssertionError("Unexpected VM command")
        with patch.object(m,"examine",return_value={}), \
             patch.object(m,"check_xml",side_effect=m.PausedStartError("NIC")), \
             patch.object(m,"virsh",side_effect=guest) as v:
            with self.assertRaisesRegex(m.PausedStartError,"NIC"):
                m.paused_start()
        self.assertIn(("destroy",m.NAME),[c.args for c in v.call_args_list])
        self.assertNotIn(("destroy",m.MASTER),
                         [c.args for c in v.call_args_list])

if __name__=="__main__":
    unittest.main()
