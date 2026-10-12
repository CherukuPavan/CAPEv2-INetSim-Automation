"""Synthetic guarded post-blockpull acceptance; no host or network calls."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_post_blockpull_acceptance as s

def xml(has_backing=False):
    backing = ('<backingStore><source file="' + s.PROTECTED[0] +
               '"/></backingStore>' if has_backing else '<backingStore/>')
    return ('<domain><name>' + s.VM + '</name><uuid>' + s.UID +
            '</uuid><os><nvram>' + s.VARS + '</nvram></os><devices>' +
            '<disk device="disk"><driver type="qcow2"/>'
            '<source file="' + s.TOP + '"/><target dev="sda"/>' +
            backing + '</disk><tpm><backend type="emulator" version="2.0"/>'
            '</tpm><interface type="network">'
            '<source network="cape-analysis-isolated"/>'
            '<mac address="02:0a:30:6a:3f:50"/>'
            '</interface></devices></domain>')

class Tests(unittest.TestCase):
    def test_success_empty_chain(self):
        out=s.check_xml(xml())
        self.assertTrue(out["backing_chain_empty"])
    def test_backing_refused(self):
        with self.assertRaisesRegex(s.Blocked,"Backing"):
            s.check_xml(xml(True))
    def test_exact_guest_identity_required(self):
        with self.assertRaisesRegex(s.Blocked,"identity"):
            s.check_xml(xml().replace(s.UID,"WRONG"))
    def test_original_master_open_refused(self):
        handles={p:[] for p in (s.TOP,s.VARS)+s.PROTECTED}
        handles[s.TOP]=["23"]
        handles[s.VARS]=["16"]
        self.assertTrue(s.validate_handles(handles)["runtime_master_file_dependency_not_observed"])
        handles[s.PROTECTED[0]]=["19"]
        with self.assertRaisesRegex(s.Blocked,"still held open"):
            s.validate_handles(handles)
    def test_exact_qemu_pid(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp)
            for p,uid in (("101",s.UID),("102","other")):
                v=base/p
                v.mkdir()
                (v/"comm").write_text("qemu-system-x86\n")
                (v/"cmdline").write_bytes(
                    b"qemu-system-x86_64\0-name\0guest=win11_1,debug-threads=on"
                    b"\0-uuid\0" + uid.encode() + b"\0")
            self.assertEqual(s.exact_qemu_pid(base),101)
    def test_source_no_mutation_apis(self):
        raw=Path(s.__file__).read_text()
        for needle in ('"qemu-monitor-command"', '"snapshot-create-as"',
                       '"snapshot-revert"', '"blockpull"', '"blockcommit"',
                       '"shutdown"', '"destroy"', '"rebase"', '"convert"'):
            self.assertNotIn(needle,raw)

if __name__=="__main__":
    unittest.main()
