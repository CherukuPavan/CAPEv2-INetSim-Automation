"""Offline-only clone cleanup proof: no real libvirt guest or VM touched."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command2_portable_zero_nic_rollback as u
import command2_portable_zero_nic_stager as stager

HOST="rakshati"
VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
GENID="22345678-1234-4234-8234-123456789abc"


class CloneRecoveryTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.folder=Path(td.name)
        self.disk=self.folder/(VM+".command2.qcow2")
        self.nvram=self.folder/(VM+".command2_VARS.fd")
        self.disk.write_bytes(b"benign qcow2 unit fixture")
        self.nvram.write_bytes(b"benign firmware unit fixture")
        self.row={"libvirt_name":VM,"libvirt_uuid_candidate":UID,
                  "smbios_generation_id_candidate":GENID,
                  "disk_target":str(self.disk),"uefi_nvram_target":str(self.nvram)}
        self.receipt={
            "schema":1,"status":"prepared","vm":VM,"uuid":UID,
            "before":{"disk_sha256":u.sha256_file(self.disk)},
        }
        self.safe=[]
        self.original_fstat=os.fstat

    def test_unmodified_guest_bytes_can_be_quarantined_without_deletion(self):
        target=self.folder/("."+VM+".quarantine-"+UID)
        digest=u.sha256_file(self.disk)
        self.assertTrue(u.quarantine_noreplace(self.disk,target,digest))
        self.assertFalse(self.disk.exists())
        self.assertTrue(target.is_file())
        self.assertEqual(u.sha256_file(target),digest)
        self.assertEqual(target.stat().st_nlink,1)

    def test_existing_quarantine_never_overwritten(self):
        target=self.folder/("."+VM+".quarantine-"+UID)
        target.write_bytes(b"foreign valuable data")
        with self.assertRaises(u.CloneRollbackBlocked):
            u.quarantine_noreplace(self.disk,target,u.sha256_file(self.disk))
        self.assertEqual(target.read_bytes(),b"foreign valuable data")
        self.assertTrue(self.disk.exists())

    def test_source_disk_drift_prevents_any_quarantine_mutation(self):
        expected=u.sha256_file(self.disk)
        self.disk.write_bytes(b"modified after approved plan")
        target=self.folder/("."+VM+".quarantine-"+UID)
        with self.assertRaises(u.CloneRollbackBlocked):
            u.quarantine_noreplace(self.disk,target,expected)
        self.assertFalse(target.exists())
        self.assertTrue(self.disk.exists())

    def test_exact_staging_intent_and_complete_records_required(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(stager,"host_guard"))
            stack.enter_context(mock.patch.object(stager,"exact_dir",
                                                   return_value=self.folder))
            stack.enter_context(mock.patch.object(stager,"reservation_entries",
                                                   return_value=[self.row]))
            intent={
                "name":VM,"stage":"BEFORE_ANY_CLONE_FILES",
                "disk":str(self.disk),"nvram":str(self.nvram),
                "uuid":UID,"zero_nics":True,
            }
            done={
                "name":VM,"status":"SHUT_OFF_ZERO_NICS_STAGED",
                "uuid":UID,"tpm_persistent_state_created":False,
                "guest_personalized":False,"network_attached":False,
                "clean_restore_verified":False,
            }
            data=stack.enter_context(mock.patch.object(
                u,"private_json",side_effect=[intent,done]))
            self.assertEqual(u.expected(HOST,self.folder,VM),self.row)
        self.assertEqual(data.call_count,2)

    def test_foreign_staging_intent_refuses_ownership(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(stager,"host_guard"))
            stack.enter_context(mock.patch.object(stager,"exact_dir",
                                                   return_value=self.folder))
            stack.enter_context(mock.patch.object(stager,"reservation_entries",
                                                   return_value=[self.row]))
            stack.enter_context(mock.patch.object(
                u,"private_json",side_effect=[
                    {"name":VM,"stage":"PREEXISTING_VM_UNKNOWN"},{}]))
            with self.assertRaises(u.CloneRollbackBlocked):
                u.expected(HOST,self.folder,VM)

    def test_plan_refuses_snapshots_or_foreign_vm_identity(self):
        xml=(f'<domain type="kvm"><name>{VM}</name><uuid>{UID}</uuid>'
             f'<genid>{GENID}</genid>'
             f'<os><nvram>{self.nvram}</nvram></os>'
             f'<devices><disk device="disk"><source file="{self.disk}"/></disk>'
             '<tpm><backend type="emulator" version="2.0"/></tpm>'
             '</devices></domain>')
        def virsh(*args):
            if args==("domuuid",VM):return UID
            if args==("domstate",VM):return "shut off"
            if args==("list","--name"):return ""
            if args==("snapshot-list",VM,"--name"):return "old_snapshot"
            if args==("dominfo",VM):return "Managed save: no"
            if args==("dumpxml","--inactive",VM):return xml
            raise AssertionError("Unexpected virsh args")
        with mock.patch.object(stager,"virsh",side_effect=virsh):
            with self.assertRaisesRegex(u.CloneRollbackBlocked,"Snapshot"):
                u.live_admission(self.row)

    def test_plan_verifies_independent_qcow2_before_vm_undefine(self):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(u,"expected",
                                                   return_value=self.row))
            stack.enter_context(mock.patch.object(u,"live_admission",
                                                   return_value="<domain/>"))
            stack.enter_context(mock.patch.object(u,"standalone_paths",
                                        return_value=(self.disk,self.nvram)))
            stack.enter_context(mock.patch.object(
                stager,"virsh",return_value="shut off"))
            checked=stack.enter_context(mock.patch.object(
                u.disk_audit,"inspect_qcow2",return_value={
                    "no_external_backing":True,
                    "no_internal_snapshots":True,
                    "no_external_data_file":True,
                }))
            reviewed=u.plan(HOST,self.folder,VM)
        checked.assert_called_once_with(self.disk)
        self.assertTrue(
            reviewed["independent_flat_qcow2_without_snapshots"])
        self.assertEqual(reviewed["disk_sha256"],u.sha256_file(self.disk))

    def test_plan_refuses_qcow2_backing_or_internal_snapshots(self):
        for case in ("external backing chain","unexpected internal snapshot"):
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    u,"expected",return_value=self.row))
                stack.enter_context(mock.patch.object(
                    u,"live_admission",return_value="<domain/>"))
                stack.enter_context(mock.patch.object(
                    u,"standalone_paths",
                    return_value=(self.disk,self.nvram)))
                undo=stack.enter_context(mock.patch.object(
                    stager,"virsh",side_effect=AssertionError(
                        "Do not act on the clone or protected master")))
                stack.enter_context(mock.patch.object(
                    u.disk_audit,"inspect_qcow2",
                    side_effect=u.disk_audit.DiskAdmissionBlocked(case)))
                with self.assertRaisesRegex(
                        u.CloneRollbackBlocked,"independence"):
                    u.plan(HOST,self.folder,VM)
                undo.assert_not_called()
        self.assertTrue(self.disk.exists())
        self.assertTrue(self.nvram.exists())

    def test_other_vm_image_or_nvram_reference_blocks_cleanup(self):
        for kind in ("disk","nvram"):
            if kind=="disk":
                xml=(f'<domain><name>unrelated</name><devices>'
                     f'<disk device="disk"><source file="{self.disk}"/></disk>'
                     '</devices></domain>')
            else:
                xml=(f'<domain><name>unrelated</name>'
                     f'<os><nvram>{self.nvram}</nvram></os>'
                     '<devices></devices></domain>')
            def mocked_virsh(*args):
                if args==("list","--all","--name"):
                    return "win11_1\nunrelated\n"
                if args==("dumpxml","--inactive","unrelated"):
                    return xml
                raise AssertionError("Unexpected libvirt request")
            with mock.patch.object(stager,"virsh",side_effect=mocked_virsh):
                with self.subTest(kind=kind), self.assertRaisesRegex(
                        u.CloneRollbackBlocked,"Another defined VM"):
                    u.no_foreign_domain_uses_images(VM,str(self.disk),
                                                    str(self.nvram))

    def test_no_foreign_vm_storage_sharing_is_admitted(self):
        xml='<domain><name>unrelated</name><devices></devices></domain>'
        def mocked(*args):
            if args==("list","--all","--name"):
                return "win11_1\nunrelated\n"
            if args==("dumpxml","--inactive","unrelated"):
                return xml
            raise AssertionError("Unexpected query")
        with mock.patch.object(stager,"virsh",side_effect=mocked):
            self.assertIsNone(u.no_foreign_domain_uses_images(
                VM,str(self.disk),str(self.nvram)))

    def test_indirect_foreign_backing_blocks_vm_rollback(self):
        foreign=self.folder/"foreign-overlay.qcow2"
        foreign.write_bytes(b"synthetic independent VM disk")
        xml=(f'<domain><name>unrelated</name><devices>'
             f'<disk device="disk"><source file="{foreign}"/></disk>'
             '</devices></domain>')
        def fake_virsh(*args):
            if args==("list","--all","--name"):
                return VM+"\\nunrelated\\n"
            if args==("dumpxml","--inactive","unrelated"):
                return xml
            raise AssertionError("Unexpected libvirt query")
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                stager,"virsh",side_effect=fake_virsh))
            audit=stack.enter_context(mock.patch.object(
                u.disk_audit,"require_no_foreign_qcow2_backing_reference",
                side_effect=u.disk_audit.DiskAdmissionBlocked(
                    "Indirect reference to clone disk")))
            with self.assertRaisesRegex(
                    u.CloneRollbackBlocked,"backing chain"):
                u.no_foreign_domain_uses_images(VM,str(self.disk),
                                                str(self.nvram))
        audit.assert_called_once_with(str(foreign),
                                      (str(self.disk),str(self.nvram)))
        self.assertTrue(self.disk.exists())
        self.assertTrue(self.nvram.exists())

    def test_readable_unrelated_foreign_backing_is_allowed(self):
        foreign=self.folder/"foreign-base.qcow2"
        foreign.write_bytes(b"fake foreign image")
        xml=(f'<domain><name>unrelated</name><devices>'
             f'<disk device="disk"><source file="{foreign}"/></disk>'
             '</devices></domain>')
        def fake_virsh(*args):
            if args==("list","--all","--name"):
                return VM+"\\nunrelated\\n"
            if args==("dumpxml","--inactive","unrelated"):
                return xml
            raise AssertionError("Unexpected libvirt query")
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                stager,"virsh",side_effect=fake_virsh))
            audit=stack.enter_context(mock.patch.object(
                u.disk_audit,"require_no_foreign_qcow2_backing_reference",
                return_value={"foreign_chain_independent_of_owned_clone":True}))
            self.assertIsNone(u.no_foreign_domain_uses_images(
                VM,str(self.disk),str(self.nvram)))
        audit.assert_called_once()

    def test_foreign_disk_protocol_is_not_silently_ignored(self):
        xml=('<domain><name>unrelated</name><devices>'
             '<disk device="disk"><source protocol="rbd" '
             'name="pool/image"/></disk></devices></domain>')
        def fake_virsh(*args):
            if args==("list","--all","--name"):
                return VM+"\\nunrelated\\n"
            if args==("dumpxml","--inactive","unrelated"):
                return xml
            raise AssertionError("Unexpected libvirt query")
        with mock.patch.object(stager,"virsh",side_effect=fake_virsh):
            with self.assertRaisesRegex(
                    u.CloneRollbackBlocked,"opaque/unknown"):
                u.no_foreign_domain_uses_images(VM,str(self.disk),
                                                str(self.nvram))

    def test_inactive_guest_xml_with_nic_cannot_be_removed(self):
        xml=(f'<domain type="kvm"><name>{VM}</name><uuid>{UID}</uuid>'
             f'<genid>{GENID}</genid>'
             f'<os><nvram>{self.nvram}</nvram></os>'
             f'<devices><disk device="disk"><source file="{self.disk}"/></disk>'
             '<tpm><backend type="emulator" version="2.0"/></tpm>'
             '<interface type="network"/></devices></domain>')
        def virsh(*args):
            mapping={
                ("domuuid",VM):UID,("domstate",VM):"shut off",
                ("list","--name"):"",("snapshot-list",VM,"--name"):"",
                ("dominfo",VM):"Managed save: no",
                ("dumpxml","--inactive",VM):xml,
            }
            return mapping[args]
        with mock.patch.object(stager,"virsh",side_effect=virsh):
            with self.assertRaisesRegex(u.CloneRollbackBlocked,"zero-NIC"):
                u.live_admission(self.row)

    def test_durable_receipt_rejects_skipped_reverse_step(self):
        # Initial record uses root-private stager.atomic_note; following
        # updates check a full predecessor receipt and exact status advance.
        original_fstat=self.original_fstat
        def fstat(fd):
            st=original_fstat(fd)
            return SimpleNamespace(st_mode=st.st_mode,st_uid=0,
                                   st_nlink=st.st_nlink,st_size=st.st_size)
        path=self.folder/"undo.json"
        with mock.patch.object(u.os,"fstat",side_effect=fstat):
            u.record(path,self.receipt,True)
            future={**self.receipt,"status":"nvram_quarantined"}
            with self.assertRaises(u.CloneRollbackBlocked):
                u.record(path,future)
            future={**self.receipt,"status":"domain_undefined"}
            u.record(path,future)
        self.assertIn(b"domain_undefined",path.read_bytes())

    def test_full_untouched_vm_undo_preserves_both_images(self):
        qc=self.folder/("."+self.disk.name+".quarantine-"+UID)
        nv=self.folder/("."+self.nvram.name+".quarantine-"+UID)
        original_d=self.disk.read_bytes()
        original_n=self.nvram.read_bytes()
        plan={"vm":VM,"uuid":UID,"host":HOST,
              "disk":str(self.disk),"nvram":str(self.nvram),
              "disk_quarantine":str(qc),"nvram_quarantine":str(nv),
              "disk_sha256":u.sha256_file(self.disk),
              "nvram_sha256":u.sha256_file(self.nvram)}
        operations=[]
        def guest(*args):
            operations.append(args)
            if args==("undefine",VM,"--keep-nvram"):return ""
            if args==("list","--all","--name"):return ""
            raise AssertionError("Unexpected libvirt mutation")
        old_fstat=os.fstat
        def fake_root(fd):
            st=old_fstat(fd)
            return SimpleNamespace(st_mode=st.st_mode,
                    st_uid=0,st_nlink=st.st_nlink,st_size=st.st_size)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(u.os,"geteuid",return_value=0))
            stack.enter_context(mock.patch.object(u.sys.stdin,"isatty",
                                                 return_value=True))
            stack.enter_context(mock.patch.object(u,"plan",return_value=plan))
            stack.enter_context(mock.patch.object(u,"expected",
                                                 return_value=self.row))
            stack.enter_context(mock.patch.object(stager,"exact_dir",
                                                 return_value=self.folder))
            stack.enter_context(mock.patch.object(u,"standalone_paths",
                                                 return_value=(self.disk,self.nvram)))
            stack.enter_context(mock.patch.object(stager,"virsh",
                                                 side_effect=guest))
            stack.enter_context(mock.patch.object(u.os,"fstat",
                                                 side_effect=fake_root))
            recorded_steps=[]
            records=stack.enter_context(mock.patch.object(
                u,"record",side_effect=lambda path,payload,*extra:
                recorded_steps.append(payload["status"])))
            stack.enter_context(mock.patch("builtins.input",
                return_value="QUARANTINE-ONLY-UNTOUCHED-WIN11_1"))
            result=u.revert(HOST,self.folder,VM)
        self.assertEqual(result["result"],
                         "COMMAND2_UNTOUCHED_ZERO_NIC_CLONE_QUARANTINED")
        self.assertEqual(qc.read_bytes(),original_d)
        self.assertEqual(nv.read_bytes(),original_n)
        self.assertFalse(self.disk.exists())
        self.assertFalse(self.nvram.exists())
        self.assertEqual(operations[0],
                         ("undefine",VM,"--keep-nvram"))
        self.assertEqual(recorded_steps,
                         ["prepared","domain_undefined","disk_quarantined",
                          "nvram_quarantined","verified"])

    def test_undefine_failure_keeps_all_vm_storage_bytes(self):
        disk=self.disk.read_bytes()
        nvram=self.nvram.read_bytes()
        plan={"vm":VM,"uuid":UID,"host":HOST,
              "disk":str(self.disk),"nvram":str(self.nvram),
              "disk_sha256":u.sha256_file(self.disk),
              "nvram_sha256":u.sha256_file(self.nvram)}
        real_fstat=os.fstat
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(u.os,"geteuid",return_value=0))
            stack.enter_context(mock.patch.object(u.sys.stdin,"isatty",
                                                 return_value=True))
            stack.enter_context(mock.patch.object(u,"plan",return_value=plan))
            stack.enter_context(mock.patch.object(u,"expected",
                                                 return_value=self.row))
            stack.enter_context(mock.patch.object(stager,"exact_dir",
                                                 return_value=self.folder))
            stack.enter_context(mock.patch.object(u.os,"fstat",
                side_effect=lambda fd: SimpleNamespace(
                    st_mode=real_fstat(fd).st_mode,st_uid=0,
                    st_nlink=real_fstat(fd).st_nlink,
                    st_size=real_fstat(fd).st_size)))
            stack.enter_context(mock.patch.object(u,"record"))
            stack.enter_context(mock.patch.object(stager,"virsh",
                                      side_effect=OSError("VM not removable")))
            stack.enter_context(mock.patch("builtins.input",
                return_value="QUARANTINE-ONLY-UNTOUCHED-WIN11_1"))
            with self.assertRaisesRegex(
                    u.CloneRollbackBlocked,"partial/unknown"):
                u.revert(HOST,self.folder,VM)
        self.assertEqual(self.disk.read_bytes(),disk)
        self.assertEqual(self.nvram.read_bytes(),nvram)

    def test_decline_does_not_undefine_or_quarantine_vm(self):
        with mock.patch.object(u.os,"geteuid",return_value=0), \
             mock.patch.object(u.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(u,"plan",return_value={
                 "result":"safe review","vm":VM}), \
             mock.patch("builtins.input",return_value="DECLINE"), \
             mock.patch.object(stager,"virsh",
                               side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(u.CloneRollbackBlocked,"declined"):
                u.revert(HOST,self.folder,VM)


if __name__=="__main__":
    unittest.main()
