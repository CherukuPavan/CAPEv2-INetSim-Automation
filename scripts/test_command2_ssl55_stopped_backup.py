"""Offline guards for independent STOPPED-ONLY SSL55 cold bundle."""
import unittest
from pathlib import Path
from unittest.mock import patch
import command2_ssl55_stopped_backup as c

def xml(*,chain=False,network="cape-analysis-isolated",uuid=None):
    backing=('<backingStore><source file="/tmp/master.qcow2"/></backingStore>'
             if chain else '<backingStore/>')
    return ('<domain><name>'+c.VM+'</name><uuid>'+str(uuid or c.UID)+
            '</uuid><os><nvram>'+str(c.VARS)+'</nvram></os>'
            '<devices><disk device="disk"><source file="'+str(c.DISK)+'"/>'+
            backing+'</disk><tpm><backend type="emulator" version="2.0"/></tpm>'+
            '<interface><source network="'+network+'"/></interface>'
            '</devices></domain>')

class Gate(unittest.TestCase):
    def test_required_flattened_clone_xml(self):
        root=__import__("xml.etree.ElementTree",fromlist=["fromstring"]).fromstring(xml())
        self.assertEqual(root.findtext("uuid"),c.UID)
    def test_wrong_guest_uuid_refused(self):
        with patch.object(c.os,"geteuid",return_value=0),\
             patch.object(c.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(c,"virsh") as vm:
            vm.side_effect=lambda *args: (
                "WRONG" if args[:1]==("domuuid",) else "shut off")
            with self.assertRaisesRegex(c.Stop,"clone UUID"):
                c.state()
    def test_cold_copy_is_never_allowed_with_running_guest(self):
        with patch.object(c,"plan",return_value={"vm_state":"running"}),\
             patch.object(c.sys.stdin,"isatty",return_value=True):
            with self.assertRaisesRegex(c.Stop,"already shut-off"):
                c.capture()
    def test_noninteractive_refused_before_plan(self):
        with patch.object(c.sys.stdin,"isatty",return_value=False),\
             patch.object(c,"plan",side_effect=AssertionError("Should not plan")):
            with self.assertRaisesRegex(c.Stop,"terminal"):
                c.capture()
    def test_script_has_no_vm_lifecycle_or_restore_calls(self):
        text=Path(c.__file__).read_text()
        self.assertNotIn('virsh("shutdown"',text)
        self.assertNotIn('virsh("start"',text)
        self.assertNotIn('virsh("destroy"',text)
        self.assertNotIn('virsh("snapshot-revert"',text)
    def test_checkpoint_has_exact_paths_and_reserve(self):
        self.assertEqual(c.VM,"win11_1")
        self.assertEqual(c.UID,"732b2256-ee99-41fa-881d-fbf5c476d960")
        self.assertEqual(c.GIB,1024**3)

if __name__=="__main__":
    unittest.main()
