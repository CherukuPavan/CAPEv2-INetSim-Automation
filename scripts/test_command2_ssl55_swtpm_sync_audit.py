"""Offline checks for exact SSL55 read-only swtpm snapshot sync inventory.

No swtpm control socket interaction, no power controls, no guest mutation.
"""
import json
from pathlib import Path
import stat
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import command2_ssl55_swtpm_sync_audit as m
EPOCH=1760287500
SNAPXML=('<domainsnapshot><name>'+m.SNAP+'</name><state>running</state>'
         '<creationTime>'+str(EPOCH)+'</creationTime>'
         '<memory snapshot="internal"/>'
         '<disks><disk name="sda" snapshot="internal"/>'
         '<disk name="sdb" snapshot="no"/></disks>'
         '<domain type="kvm"><name>'+m.VM+'</name><uuid>'+m.UUID+
         '</uuid></domain></domainsnapshot>')
DOMAIN=('<domain type="kvm"><name>'+m.VM+'</name><uuid>'+m.UUID+
        '</uuid><os><nvram format="qcow2">'+str(m.OVMF)+'</nvram></os>'
        '<devices><disk device="disk" type="file"><driver type="qcow2"/>'
        '<source file="'+str(m.DISK)+'"/></disk><tpm>'
        '<backend type="emulator" version="2.0"/></tpm>'
        '<interface type="network"><source network="cape-analysis-isolated"/>'
        '<mac address="02:0a:30:6a:3f:50"/></interface></devices></domain>')

class TPMHoldAudit(unittest.TestCase):
    def test_domain_and_snapshot_must_match_exact_guest_devices(self):
        self.assertTrue(m.xml_domain(DOMAIN)["identity_storage_uefi_tpm_network_match"])
        a=m.snapshot_metadata(SNAPXML)
        self.assertTrue(a["running_ram_and_exact_sda_internal_metadata"])
        self.assertEqual(a["other_disk_entries"],1)
        for bad in (
            SNAPXML.replace('name="sda" snapshot="internal"',
                            'name="sdb" snapshot="internal"'),
            SNAPXML.replace('state>running','state>shutoff'),
            SNAPXML.replace('<memory snapshot="internal"/>',
                            '<memory snapshot="no"/>'),
            SNAPXML.replace(m.UUID,"00000000-0000-0000-0000-000000000000"),
            SNAPXML.replace('<creationTime>'+str(EPOCH)+'</creationTime>',''),
        ):
            with self.subTest(bad=bad),self.assertRaises(m.AuditBlocked):
                m.snapshot_metadata(bad)
        for bad in (
            DOMAIN.replace('network="cape-analysis-isolated"','network="default"'),
            DOMAIN.replace(str(m.DISK),'/master.qcow2'),
            DOMAIN.replace(str(m.OVMF),'/malicious-var.fd'),
            DOMAIN.replace('type="emulator"','type="passthrough"'),
            DOMAIN.replace('</devices>','<hostdev/></devices>'),
        ):
            with self.subTest(bad=bad),self.assertRaises(m.AuditBlocked):
                m.xml_domain(bad)

    def test_qcow_image_requires_candidate_in_independent_disk_and_vars(self):
        with tempfile.TemporaryDirectory() as td:
            q=Path(td)/"disk.qcow2"
            q.write_bytes(b"test file, QEMU info mocked")
            state={"format":"qcow2","snapshots":[{"name":m.SNAP}]}
            with patch.object(m,"cmd",return_value=json.dumps(state)):
                self.assertTrue(m.qcow_names(q)["candidate_name_present_once"])
            state["snapshots"]=[]
            with patch.object(m,"cmd",return_value=json.dumps(state)),\
                 self.assertRaisesRegex(m.AuditBlocked,"candidate"):
                m.qcow_names(q)
            state["snapshots"]=[{"name":m.SNAP}]
            state["backing-filename"]="/master.qcow2"
            with patch.object(m,"cmd",return_value=json.dumps(state)),\
                 self.assertRaisesRegex(m.AuditBlocked,"format/backing"):
                m.qcow_names(q)

    def test_process_scopes_to_exact_tpm_directory_without_disclosure(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            unrelated=root/"8"
            unrelated.mkdir()
            (unrelated/"cmdline").write_bytes(
               b"/usr/bin/swtpm\0socket\0--tpmstate\0dir=/unrelated\0")
            matching=root/"25"
            matching.mkdir()
            (matching/"cmdline").write_bytes(
                ("/usr/bin/swtpm\0socket\0--tpmstate\0dir="+str(m.TPM)+
                 "\0--ctrl\0type=unixio,path=/run/private/token\0").encode())
            answer=m.find_swtpm_process(root)
            self.assertEqual(answer["matched_swtpm_process_count"],1)
            self.assertFalse(answer["live_swtpm_control_socket_queried"])
            self.assertNotIn("private/token",str(answer))
            (matching/"cmdline").write_bytes(b"/usr/bin/swtpm\0socket\0")
            with self.assertRaisesRegex(m.AuditBlocked,"one"):
                m.find_swtpm_process(root)

    def test_tpm_file_metadata_cannot_be_treated_as_checkpoint(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)
            (folder/"tpm2-00.permall").write_bytes(b"TEST ONLY")
            with patch.object(m,"TPM",folder):
                report=m.tpm_files(EPOCH)
            self.assertFalse(report["tpm_persistent_state_at_capture_time_verified"])
            self.assertFalse(report["files_hashed_or_copied_while_running"])
            self.assertEqual(report["files_metadata_only"][0]["name"],
                             "tpm2-00.permall")

    def test_complete_audit_is_hold_even_with_snapshot_on_both_qcow2(self):
        def fake_virsh(*args):
            if args==("domuuid",m.VM):return m.UUID
            if args[0]=="domuuid":return dict([m.MASTER,m.TRIAL])[args[1]]
            if args[0]=="domstate":
                return "running" if args[1]==m.VM else "shut off"
            if args==("list","--name"):return m.VM
            if args==("snapshot-list",m.VM,"--name"):return m.SNAP
            if args==("dumpxml","--inactive",m.VM):return DOMAIN
            if args==("dumpxml",m.VM):return DOMAIN
            if args==("snapshot-dumpxml",m.VM,m.SNAP):return SNAPXML
            raise AssertionError(args)
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m,"virsh",side_effect=fake_virsh),\
             patch.object(m,"qcow_names",return_value={
                "qcow2":True,"candidate_name_present_once":True,
                "snapshot_names":[m.SNAP]}),\
             patch.object(m,"tpm_files",return_value={
                "tpm_persistent_state_at_capture_time_verified":False}),\
             patch.object(m,"find_swtpm_process",return_value={
                "unique_swtpm_process_bound_to_clone":True}):
            result=m.assess()
        self.assertFalse(result["CAPE_READY"])
        self.assertFalse(result["snapshot_revert_authorized"])
        self.assertFalse(result["libvirt_snapshotted_swtpm_checkpoint_proven"])
        self.assertTrue(result["tpm_safe_recovery_path_not_yet_proven"])
        self.assertTrue(result["guest_running_now"])

    def test_module_has_no_guest_mutation_commands(self):
        source=Path(m.__file__).read_text()
        forbidden=(
            'virsh("snapshot-create"', 'virsh("snapshot-revert"',
            'virsh("start"', 'virsh("shutdown"', 'virsh("destroy"',
            'virsh("suspend"', 'virsh("resume"', 'virsh("define"',
            'swtpm_ioctl","--save"', 'swtpm_ioctl","--load"',
            'os.unlink(', 'os.replace(', 'shell=True')
        for word in forbidden:
            self.assertNotIn(word,source)

if __name__=="__main__":
    unittest.main()
