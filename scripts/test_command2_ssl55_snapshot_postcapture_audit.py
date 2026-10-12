"""Offline-only regression for real postcapture running memory/disk audit.

No libvirt calls reach host; no snapshots are created, reverted or deleted.
"""
from pathlib import Path
import hashlib
import json
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import command2_ssl55_snapshot_postcapture_audit as m

SNAPXML=('<domainsnapshot><name>'+m.SNAP+'</name><state>running</state>'
         '<memory snapshot="internal"/>'
         '<disks><disk name="sda" snapshot="internal"/></disks>'
         '<domain type="kvm"><name>'+m.VM+'</name><uuid>'+m.UUID+
         '</uuid></domain></domainsnapshot>')
class PostCapture(unittest.TestCase):
    def test_real_running_internal_snapshot_requires_matching_domain(self):
        ok=m.safe_snapshot_metadata(SNAPXML)
        self.assertEqual(ok["memory_snapshot"],"internal")
        self.assertEqual(ok["snapshot_disk_names"],["sda"])
        self.assertFalse(ok["metadata_proves_tpm_state_restoration"])
        for bad in (
            SNAPXML.replace('state>running','state>shutoff'),
            SNAPXML.replace('<memory snapshot="internal"/>',
                            '<memory snapshot="no"/>'),
            SNAPXML.replace('<disk name="sda" snapshot="internal"/>',
                            '<disk name="sda" snapshot="no"/>'),
            SNAPXML.replace('<disk name="sda" snapshot="internal"/>',
                            '<disk name="firmware" snapshot="internal"/>'),
            SNAPXML.replace(m.UUID,"wrong-uuid"),
            SNAPXML.replace(m.SNAP,"unknown-snapshot"),
        ):
            with self.subTest(bad=bad),self.assertRaises(m.PostcaptureBlocked):
                m.safe_snapshot_metadata(bad)

    def test_qcow_info_distinguishes_firmware_and_os_internal_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"disk.qcow2"
            path.write_bytes(b"not real qcow2 - mocked qemu-img")
            response={"format":"qcow2","virtual-size":2*1024**3,
                      "snapshots":[{"name":m.SNAP,"id":"1"}]}
            with patch.object(m,"command",return_value=json.dumps(response)):
                data=m.qcow_info(path)
            self.assertTrue(data["candidate_snapshot_present_in_image"])
            response["snapshots"]=[]
            with patch.object(m,"command",return_value=json.dumps(response)):
                data=m.qcow_info(path)
            self.assertFalse(data["candidate_snapshot_present_in_image"])
            response["backing-filename"]="/master.qcow2"
            with patch.object(m,"command",return_value=json.dumps(response)):
                with self.assertRaisesRegex(m.PostcaptureBlocked,
                                            "backing"):
                    m.qcow_info(path)

    def test_one_read_only_audit_checks_originals_runtime_and_tpm_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            backup=home/"original.xml"
            backup.write_bytes(b"original libvirt domain")
            orig=(m.BACKUP,m.TPM,m.transition.XML_SHA)
            m.BACKUP=backup
            m.TPM=home/"tpm"
            m.TPM.mkdir()
            (m.TPM/"tpm2-00.permall").write_bytes(b"test tpm")
            m.transition.XML_SHA=m.digest(backup.read_bytes())
            self.addCleanup(lambda:setattr(m,"BACKUP",orig[0]))
            self.addCleanup(lambda:setattr(m,"TPM",orig[1]))
            self.addCleanup(lambda:setattr(m.transition,"XML_SHA",orig[2]))
            fake_file=types.SimpleNamespace(st_uid=0,
                          st_mode=stat.S_IFREG|0o600,st_nlink=1)
            original_stat=Path.stat
            def fake_stat(path,*a,**kw):
                actual=original_stat(path,*a,**kw)
                if Path(path)==backup:return fake_file
                return actual
            def virsh(*args):
                if args==("domuuid",m.VM):return m.UUID
                if args[0]=="domuuid":
                    return dict([m.transition.ref.MASTER,
                                 m.transition.ref.TRIAL])[args[1]]
                if args[0]=="domstate":
                    return "running" if args[1]==m.VM else "shut off"
                if args==("list","--name"):return m.VM
                if args==("snapshot-list",m.VM,"--name"):return m.SNAP
                if args==("snapshot-dumpxml",m.VM,m.SNAP):return SNAPXML
                if args==("dumpxml","--inactive",m.VM):return "saved-domain"
                if args==("dumpxml",m.VM):return "live-domain"
                raise AssertionError(args)
            expected_disk={"candidate_snapshot_present_in_image":True,
                "format":"qcow2","standalone":True}
            expected_fw={"candidate_snapshot_present_in_image":False,
                "format":"qcow2","standalone":True}
            expected_graph={"critical_devices_match":True}
            fs=types.SimpleNamespace(f_bavail=14_000_000,f_frsize=4096)
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(m,"virsh",side_effect=virsh),\
                 patch.object(m,"qcow_info",side_effect=[expected_disk,expected_fw]),\
                 patch.object(m.candidate,"check_critical_live",
                              return_value=expected_graph),\
                 patch.object(m.candidate,"SAVE_SHA",
                              m.digest(b"saved-domain")),\
                 patch.object(m.prep,"sha256",return_value=m.transition.RAW_SHA),\
                 patch.object(m.prep,"verify_existing_bundle",return_value={
                      "manifest_sha256":m.transition.MANIFEST_SHA,
                      "byte_verified_member_count":3}),\
                 patch.object(m.hostguard,"verify_guard"),\
                 patch.object(m.hostguard,"network_live"),\
                 patch.object(m.agent,"probe_agent",return_value={
                     "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                     "version":"0.23"}),\
                 patch.object(m.os,"statvfs",return_value=fs),\
                 patch.object(Path,"stat",autospec=True,side_effect=fake_stat):
                result=m.assess()
            self.assertEqual(result["result"],
                "SSL55_SNAPSHOT_POSTCAPTURE_READONLY_COMPLETE")
            self.assertTrue(result["snapshot_os_disk_label_present"])
            self.assertFalse(result["snapshot_in_uefi_image"])
            self.assertFalse(result["release_for_cape_analysis"])
            self.assertFalse(result["snapshot_can_be_reverted_consistently"])
            self.assertFalse(result["host_or_guest_changed"])

    def test_no_vms_are_mutated_in_any_audit_function(self):
        source=Path(m.__file__).read_text()
        for forbidden in ('virsh("snapshot-create"', 'virsh("snapshot-revert"',
                 'virsh("snapshot-delete"', 'virsh("start"', 'virsh("shutdown"',
                 'virsh("destroy"', 'virsh("define"', 'os.unlink(',
                 'os.replace(', 'shell=True'):
            self.assertNotIn(forbidden,source)

    def test_mismatching_private_backup_or_snapshot_blocks(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m,"virsh",side_effect=lambda *a:(
                  "fake" if a[0]=="domuuid" else "running")):
            with self.assertRaisesRegex(m.PostcaptureBlocked,"clone"):
                m.assess()

if __name__=="__main__":unittest.main()
