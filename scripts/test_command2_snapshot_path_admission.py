"""Pure synthetic Command 2 snapshot lifecycle inventory checks."""
import unittest
from unittest.mock import patch
import command2_snapshot_path_admission as s

VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
def xml(fmt="raw",hasnic=True):
    nv="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
    if fmt=="qcow2":nv+=".qcow2"
    nic=('<interface type="network"><source network="cape-analysis-isolated"/>'
         '</interface>') if hasnic else ""
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+'</uuid>'
            '<os><nvram format="'+fmt+'">'+nv+'</nvram></os>'
            '<devices><disk device="disk"><driver type="qcow2"/>'
            '<source file="/private/win11_1.command2.qcow2"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            +nic+'</devices></domain>')
class SnapshotAdmission(unittest.TestCase):
    def test_raw_ovmf_staged_vm_refuses_cape_readiness(self):
        a=s.classify_xml(VM,UUID,xml(),"running",set())
        self.assertEqual(a["phase"],"STANDALONE_RAW_OVMF_SNAPSHOT_BLOCKED")
        self.assertFalse(a["vm_snapshot_revert_proven_by_inventory"])
    def test_qcow2_zero_nic_is_not_ready(self):
        a=s.classify_xml(VM,UUID,xml("qcow2",False),"shut off",set())
        self.assertEqual(a["phase"],"ZERO_NIC_STAGE_NOT_ANALYSIS_READY")
    def test_activated_qcow2_without_snapshot_needs_running_capture(self):
        a=s.classify_xml(VM,UUID,xml("qcow2"),"running",set())
        self.assertEqual(a["phase"],"RUNNING_SNAPSHOT_NOT_YET_CAPTURED")
    def test_snapshot_presence_is_not_revert_proof(self):
        a=s.classify_xml(VM,UUID,xml("qcow2"),"shut off",
                         {"cape_ready_win11_1"})
        self.assertEqual(a["phase"],"SNAPSHOT_METADATA_AND_REAL_REVERT_EVIDENCE_REQUIRED")
        self.assertFalse(a["tpm_state_revert_proven_by_inventory"])
    def test_default_nat_nic_refused(self):
        with self.assertRaisesRegex(s.AdmissionBlocked,"non-isolated"):
            s.classify_xml(VM,UUID,xml().replace("cape-analysis-isolated","default"),
                           "running",set())
    def test_overlapping_uuids_and_missing_vm_fail(self):
        with patch.object(s,"virsh",return_value=UUID):
            with self.assertRaisesRegex(s.AdmissionBlocked,"invalid or duplicated"):
                s.inventory([(VM,UUID),(VM,UUID)])
    def test_reserved_journal_is_strictly_bound_to_host_and_count(self):
        import json
        import os
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as td:
            root=Path(td);root.chmod(0o700)
            p=root/"command2-identity-reservation.json"
            def write(entries,host="spare-kvm"):
                p.write_text(json.dumps({
                    "format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
                    "version":1,"host":host,"guest_count":len(entries),
                    "host_network_modified":False,"entries":entries}))
                p.chmod(0o600)
            entries=[{"libvirt_name":"win11_1",
                      "libvirt_uuid_candidate":UUID}]
            write(entries)
            realstat=Path.stat
            def root_owned(obj,*args,**kwargs):
                info=realstat(obj,*args,**kwargs)
                data=list(info);data[4]=0
                return os.stat_result(data)
            with patch.object(Path,"stat",root_owned):
                self.assertEqual(s.rows_from_reserved_journal(p,"spare-kvm"),
                                 [(VM,UUID)])
                with self.assertRaisesRegex(s.AdmissionBlocked,"host mismatch"):
                    s.rows_from_reserved_journal(p,"other-kvm")
                write([{"libvirt_name":"win11_2",
                        "libvirt_uuid_candidate":UUID}])
                with self.assertRaisesRegex(s.AdmissionBlocked,"ordered"):
                    s.rows_from_reserved_journal(p,"spare-kvm")

    def test_renamed_reference_cannot_use_other_host_journal(self):
        with patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s.sys,"argv",["tool","--journal","/tmp/bogus"]),\
             patch.object(s.os,"geteuid",return_value=0):
            self.assertEqual(s.main(),2)

    def test_no_vm_mutators_in_lifecycle(self):
        from pathlib import Path
        code=Path(s.__file__).read_text()
        for forbidden in ('"snapshot-create-as"', '"snapshot-revert"',
                          '"define"', '"destroy"', '"start"', '"shutdown"',
                          '"attach-interface"', '"net-start"'):
            self.assertNotIn(forbidden,code)
if __name__=="__main__":unittest.main()
