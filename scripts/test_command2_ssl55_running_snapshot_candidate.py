"""SSL55 running memory snapshot CANDIDATE: no real VM touched in tests."""
import hashlib
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import types
import unittest
from unittest.mock import patch
import command2_ssl55_running_snapshot_candidate as s

UID=s.UID
VM=s.VM
XML=(
    '<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
    '<os><loader readonly="yes" type="pflash">/usr/share/OVMF/X.fd</loader>'
    '<nvram format="qcow2">'+str(s.transition.SIDE)+'</nvram></os>'
    '<memory unit="KiB">4194304</memory>'
    '<devices><disk type="file" device="disk"><driver type="qcow2"/>'
    '<source file="'+str(s.transition.ref.DISK)+'"/></disk>'
    '<interface type="network"><source network="cape-analysis-isolated"/>'
    '<mac address="02:0a:30:6a:3f:50"/></interface>'
    '<tpm><backend type="emulator" version="2.0"/></tpm>'
    '</devices></domain>')
PREVIEW='<domainsnapshot><name>'+s.SNAP+'</name><state>running</state></domainsnapshot>'
SNAPXML=('<domainsnapshot><name>'+s.SNAP+'</name><state>running</state>'
         '<memory snapshot="internal"/>'
         '<disks><disk name="sda" snapshot="internal"/></disks>'
         '</domainsnapshot>')

def plan():
    return {"result":"SSL55_RUNNING_SNAPSHOT_CANDIDATE_PLAN_ONLY",
            "vm":VM,"candidate_name":s.SNAP,
            "saved_xml_sha256":s.SAVE_SHA,
            "protected_master_trial_shut_off":True,
            "verified_cold_recovery_member_count":3,
            "libvirt_daemon_version":"11.1.0",
            "qemu_hypervisor_version":"9.2.2",
            "host_policy_readback_passed":True,
            "snapshot_preview_sha256":"test-only",
            "free_gib":62.0,
            "snapshot_created":False}

class Candidate(unittest.TestCase):
    def test_exact_host_domain_and_ovmf_first_boot(self):
        self.assertTrue(s.check_critical_live(XML,XML)["critical_devices_match"])
        self.assertEqual(
            s.check_critical_live(XML,XML)["only_documented_runtime_xml_metadata"],[])
        tests=(
          XML.replace('nvram format="qcow2"','nvram format="raw"'),
          XML.replace(str(s.transition.SIDE),str(s.transition.RAW)),
          XML.replace(str(s.transition.ref.DISK),"/other/master.qcow2"),
          XML.replace('network="cape-analysis-isolated"','network="default"'),
          XML.replace('type="emulator"','type="passthrough"'),
          XML.replace('</devices>','<hostdev/></devices>'),
        )
        for changed in tests:
            with self.subTest(changed=changed),self.assertRaises(
                 s.SnapshotCandidateBlocked):
                s.check_critical_live(XML,changed)

    def test_running_libvirt_runtime_index_port_and_bridge_are_safe_metadata(self):
        # libvirt may add block-source index and network portid/bridge only
        # while the VM is running; they do NOT represent device substitution.
        live=XML.replace(
            'file="'+str(s.transition.ref.DISK)+'"',
            'file="'+str(s.transition.ref.DISK)+'" index="1"')
        live=live.replace(
            '<source network="cape-analysis-isolated"/>',
            '<source network="cape-analysis-isolated" bridge="cape-lab0" '
            'portid="3c0af211-9a41-43c9-a6a2-44c33c09f483"/>')
        answer=s.check_critical_live(XML,live)
        self.assertTrue(answer["critical_devices_match"])
        self.assertEqual(answer["only_documented_runtime_xml_metadata"],
            ["running.disk_source.index","running.nic_source.bridge",
             "running.nic_source.portid"])

    def test_running_xml_normalization_cannot_hide_unsafe_device_drift(self):
        expected='<source network="cape-analysis-isolated"/>'
        for unsafe,reason in (
           ('<source network="cape-analysis-isolated" bridge="virbr0"/>',
            "NOT exact isolated"),
           ('<source network="cape-analysis-isolated" portgroup="uplink"/>',
            "Unreviewed isolated"),
           ('<source network="cape-analysis-isolated" portid="bogus"/>',
            "port identifier invalid"),
           ('<source network="cape-analysis-isolated" '
            'portid="3c0af211-9a41-43c9-a6a2-44c33c09f483" '
            'bridge="cape-lab0" portgroup="x"/>',
            "Unreviewed isolated"),
        ):
            with self.subTest(unsafe=unsafe),self.assertRaisesRegex(
                s.SnapshotCandidateBlocked,reason):
                s.check_critical_live(XML,XML.replace(expected,unsafe))
        original='file="'+str(s.transition.ref.DISK)+'"'
        for bad in ('index="notnumber"','index="-1"',
                    'index="300"','cache="unsafe"'):
            with self.subTest(bad=bad),self.assertRaises(
                s.SnapshotCandidateBlocked):
                s.check_critical_live(XML,XML.replace(original,
                                                original+' '+bad))
        with self.assertRaisesRegex(s.SnapshotCandidateBlocked,
                                   "attributes differ"):
            s.check_critical_live(XML,XML.replace(
                '<loader readonly="yes" type="pflash">',
                '<loader readonly="no" type="pflash">'))

    def test_no_write_plan_has_all_real_safety_admissions(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            backup=root/s.transition.BACKUP_FILE
            backup.write_text("original xml")
            original_back=(s.ROOT_BACKUP,s.transition.XML_SHA,s.SAVE_SHA)
            s.ROOT_BACKUP=root
            s.transition.XML_SHA=s.sha(b"original xml")
            s.SAVE_SHA=s.sha(XML.encode())
            self.addCleanup(lambda:setattr(s,"ROOT_BACKUP",original_back[0]))
            self.addCleanup(lambda:setattr(s.transition,"XML_SHA",original_back[1]))
            self.addCleanup(lambda:setattr(s,"SAVE_SHA",original_back[2]))
            def virsh(*args,**kwargs):
                if args==("domuuid",VM):return UID
                if args[0]=="domuuid":
                    return dict([s.transition.ref.MASTER,
                                 s.transition.ref.TRIAL])[args[1]]
                if args[0]=="domstate":
                    return "running" if args[1]==VM else "shut off"
                if args==("snapshot-list",VM,"--name"):return ""
                if args==("list","--name"):return VM
                if args[0]=="dumpxml":return XML
                if args==("version","--daemon"):
                    return ("Running against daemon: 11.1.0\n"
                            "Running hypervisor: QEMU 9.2.2")
                if args[:1]==("snapshot-create-as",):
                    self.assertIn("--print-xml",args)
                    return PREVIEW
                raise AssertionError(args)
            tpm=root/"tpm"
            tpm.mkdir()
            (tpm/"tpm2-00.permall").write_bytes(b"tpm")
            old_tpm=s.transition.ref.TPM
            s.transition.ref.TPM=tpm
            self.addCleanup(lambda:setattr(s.transition.ref,"TPM",old_tpm))
            file=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,
                                        st_nlink=1)
            statfs=types.SimpleNamespace(f_bavail=20_000_000,
                                         f_frsize=4096)
            def size(path):
                return statfs
            real_stat=Path.stat
            with patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s,"virsh",side_effect=virsh),\
                 patch.object(s.prep,"sha256",return_value=s.transition.RAW_SHA),\
                 patch.object(s.prep,"verify_existing_bundle",return_value={
                     "manifest_sha256":s.transition.MANIFEST_SHA,
                     "byte_verified_member_count":3}),\
                 patch.object(s.hostguard,"verify_guard"),\
                 patch.object(s.hostguard,"network_live"),\
                 patch.object(s.agent,"probe_agent",return_value={
                     "result":"COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                     "version":"0.23"}),\
                 patch.object(s,"cmd",return_value=json.dumps({
                     "format":"qcow2"})),\
                 patch.object(s.Path,"stat",autospec=True) as fake_stat,\
                 patch.object(s.os,"statvfs",side_effect=size):
                fake_stat.side_effect=lambda path,*a,**k:(
                    file if Path(path)==backup else real_stat(path,*a,**k))
                result=s.inspect()
            self.assertEqual(result["vm_state"],"running")
            self.assertFalse(result["snapshot_created"])
            self.assertFalse(result["swtpm_consistent_restore_proven"])

    def test_capture_requires_consent_and_preserves_partial_failures(self):
        with TemporaryDirectory() as td:
            lock=Path(td)/"lock"
            state={"snapshot":False}
            ops=[]
            def virsh(*args,**kwargs):
                ops.append(args)
                if args[0]=="snapshot-create-as":
                    state["snapshot"]=True
                    raise s.SnapshotCandidateBlocked("libvirt failed after attempt")
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                                     st_uid=0,st_nlink=1)
            with patch.object(s,"LOCK",lock),\
                 patch.object(s.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=
                       "CAPTURE-SSL55-BENIGN-TPM-UNPROVEN-CANDIDATE"),\
                 patch.object(s,"inspect",return_value=plan()),\
                 patch.object(s.os,"fstat",return_value=fs),\
                 patch.object(s,"virsh",side_effect=virsh):
                with self.assertRaisesRegex(s.SnapshotCandidateBlocked,
                                            "CAPTURE_ATTEMPTED_VM_STATE"):
                    s.capture_candidate()
            self.assertTrue(state["snapshot"])
            self.assertNotIn("snapshot-revert",[a[0] for a in ops])
            self.assertNotIn("snapshot-delete",[a[0] for a in ops])

    def test_snapshot_candidate_never_declares_cape_ready(self):
        source=Path(s.__file__).read_text()
        for forbidden in ('virsh("snapshot-revert"',
                          'virsh("snapshot-delete"',
                          'virsh("destroy"',
                          'virsh("shutdown"',
                          'virsh("start"',
                          "shell=True"):
            self.assertNotIn(forbidden,source)
        self.assertEqual(s.SNAP,"cape_candidate_win11_1")
        self.assertNotEqual(s.SNAP,"cape_ready_win11_1")

if __name__=="__main__":
    unittest.main()
