"""Synthetic SSL55 decision gates: never create dangerous running snapshot."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import command2_ssl55_running_snapshot_readonly as a

def domain(*,nvram_fmt=None,backing=False,tpm=True,network=a.VM):
    attr=(' format="'+nvram_fmt+'"') if nvram_fmt is not None else ""
    chain='<backingStore><source file="/tmp/master.img"/></backingStore>' if backing else '<backingStore/>'
    tp='<tpm><backend type="emulator" version="2.0"/></tpm>' if tpm else ""
    return ('<domain><name>'+a.VM+'</name><uuid>'+a.UID+
            '</uuid><os><loader type="pflash">/fake/firmware</loader>'+
            '<nvram'+attr+'>'+str(a.VARS)+'</nvram></os><devices>'+
            '<disk device="disk"><driver type="qcow2"/>'
            '<source file="'+str(a.DISK)+'"/>'+chain+'</disk>'+tp+
            '<interface><mac address="02:0a:30:6a:3f:50"/>'
            '<source network="cape-analysis-isolated"/></interface>'
            '</devices></domain>')

class ProtectedSnapshot(unittest.TestCase):
    def test_expected_domain_identifies_raw_pflash_and_swtpm(self):
        result=a.checkdomain(domain())
        self.assertEqual(result["loader_type"],"pflash")
        self.assertEqual(result["xml_nvram_format"],"raw")
        self.assertTrue(result["swtpm_emulator_2"])
    def test_nonflat_disk_refused(self):
        with self.assertRaisesRegex(a.AuditBlocked,"backing"):
            a.checkdomain(domain(backing=True))
    def test_missing_tpm_refused(self):
        with self.assertRaisesRegex(a.AuditBlocked,"TPM"):
            a.checkdomain(domain(tpm=False))
    def test_wrong_vm_identity_refused(self):
        with self.assertRaisesRegex(a.AuditBlocked,"identity"):
            a.checkdomain(domain().replace(a.UID,"00000000-0000-0000-0000-000000000000"))
    def test_safety_module_contains_no_snapshot_mutators(self):
        t=Path(a.__file__).read_text()
        for s in ('"snapshot-create-as"', '"snapshot-revert"', '"destroy"',
                  '"shutdown"', '"start"', '"define"', '"undefine"',
                  '"qemu-monitor-command"', '"setmem"', '"blockcopy"'):
            self.assertNotIn(s,t)
    def test_full_readonly_snapshot_audit_reports_incompatibility(self):
        def vs(*args):
            if args[:1]==("domuuid",):
                return {a.VM:a.UID,a.MASTER[0]:a.MASTER[1],
                        a.TRIAL[0]:a.TRIAL[1]}[args[1]]
            if args[:1]==("domstate",):
                return "running" if args[1]==a.VM else "shut off"
            if args[:1]==("dumpxml",):return domain()
            if args[:1]==("snapshot-list",):return ""
            raise AssertionError("Unexpected virsh "+str(args))
        def query(*args,**kw):
            if args[0]=="qemu-img":
                return json.dumps({"format":"qcow2" if str(a.DISK)==args[-1]
                                   else "raw",
                                   "virtual-size":68719476736})
            raise AssertionError("Unexpected read-only command "+str(args))
        with patch.object(a.os,"geteuid",return_value=0), \
             patch.object(a.socket,"gethostname",return_value="CSE-SSL-55"), \
             patch.object(a,"virsh",side_effect=vs), \
             patch.object(a,"cmd",side_effect=query), \
             patch.object(a,"fileinfo",return_value={"size_bytes":100}), \
             patch.object(a.TPM,"is_dir",return_value=True), \
             patch.object(a.TPM,"is_symlink",return_value=False), \
             patch.object(a.TPM,"iterdir",return_value=[
                Path("/tmp/tpm2-00.permall")]), \
             patch.object(a.os,"statvfs",return_value=SimpleNamespace(
                f_frsize=4096,f_bavail=64*a.GIB//4096)):
            outcome=a.perform()
        self.assertFalse(outcome["snapshot_capture_attempted"])
        self.assertFalse(outcome["running_snapshot_ready_for_cape"])
        self.assertEqual(outcome["nvram_format_on_disk"],"raw")
        self.assertIn("RAW_PFLASH_VARIABLE_STORE",outcome["native_snapshot_blockers"])
        self.assertFalse(outcome["host_guest_modified"])
    def test_undefined_snapshot_proofs_never_declared_true(self):
        text=Path(a.__file__).read_text()
        self.assertIn('"libvirt_swtpm_state_atomic_snapshot_proven":False',text)
        self.assertIn('"snapshot_revert_tested":False',text)

if __name__=="__main__":
    unittest.main()
