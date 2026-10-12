"""Offline exact SSL55 second running candidate; no real VM operations."""
import json
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import command2_ssl55_postnat_running_snapshot as m
VM=m.VM
UID=m.dual.UID
OLD=m.OLD
NEW=m.NEW
DOMAIN=('<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
        '<os><nvram format="qcow2">'+str(m.OVMF)+'</nvram></os>'
        '<memory unit="KiB">4194304</memory><devices>'
        '<disk type="file" device="disk"><driver type="qcow2"/>'
        '<source file="'+str(m.OS_DISK)+'"/></disk>'
        '<tpm model="tpm-crb"><backend type="emulator" version="2.0"/>'
        '</tpm><interface type="network">'
        '<source network="cape-analysis-isolated"/>'
        '<mac address="02:0a:30:6a:3f:50"/><model type="e1000e"/>'
        '</interface><interface type="network">'
        '<source network="default"/><mac address="02:ca:55:11:01:02"/>'
        '<model type="e1000e"/></interface></devices></domain>')
def snap(name,epoch):
    return ('<domainsnapshot><name>'+name+'</name>'
            '<state>running</state><creationTime>'+str(epoch)+
            '</creationTime><memory snapshot="internal"/>'
            '<disks><disk name="sda" snapshot="internal"/>'
            '<disk name="sdb" snapshot="no"/></disks>'
            '<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+
            '</uuid></domain></domainsnapshot>')
DHCP=('<network><name>default</name><forward mode="nat"/>'
      '<bridge name="virbr0"/><ip address="192.168.122.1">'
      '<dhcp><range start="192.168.122.2" end="192.168.122.254"/>'
      '<host mac="02:ca:55:11:01:02" ip="192.168.122.131" '
      'name="WIN11-1"/></dhcp></ip></network>')
DUAL={"original_agent_still_reachable":True,
      "nat_agent_reachable":True,
      "nat_lease_observation":{"observed_nat_ips_for_mac":["192.168.122.131"]}}
def virsh(created=False):
    def query(*a,**kw):
        if a==("snapshot-list",VM,"--name"):
            return OLD+("\n"+NEW if created else "")
        if a==("snapshot-dumpxml",VM,OLD):return snap(OLD,1760293200)
        if a==("snapshot-dumpxml",VM,NEW):return snap(NEW,1760294300)
        if a[0]=="dumpxml":return DOMAIN
        if a[0]=="net-dumpxml":return DHCP
        raise AssertionError(a)
    return query
def qcow_reply(created=False):
    names=[OLD]+([NEW] if created else [])
    return json.dumps({"format":"qcow2","snapshots":[
        {"name":n} for n in names]})
class Capture(unittest.TestCase):
    def test_exact_ram_uefi_tpm_disk_and_persistent_dual_nic(self):
        with patch.object(m,"virsh",side_effect=virsh(False)):
            self.assertTrue(m.domain_views()["nat_is_persistent_in_guest_definition"])
            a=m.snapshot_xml(OLD)
            self.assertTrue(a["running_ram_internal"])
            self.assertTrue(a["windows_os_disk_sda_internal"])
        with patch.object(m,"virsh",side_effect=lambda *a,**k:
             DOMAIN.replace('network="default"','network="other"')
             if a[0]=="dumpxml" else virsh(False)(*a,**k)),\
             self.assertRaisesRegex(m.CaptureBlocked,"interface state"):
            m.domain_views()
        with patch.object(m,"virsh",side_effect=lambda *a,**k:
             DOMAIN.replace(str(m.OVMF),"/lost-vars.fd")
             if a[0]=="dumpxml" else virsh(False)(*a,**k)),\
             self.assertRaisesRegex(m.CaptureBlocked,"OVMF changed"):
            m.domain_views()

    def test_original_snapshot_never_confused_with_new_capture(self):
        with patch.object(m,"virsh",side_effect=virsh(False)):
            before=m.snapshot_xml(OLD)
        with patch.object(m,"virsh",side_effect=virsh(True)):
            after=m.snapshot_xml(NEW)
        self.assertGreater(after["snapshot_epoch"],before["snapshot_epoch"])
        self.assertTrue(after["running_ram_internal"])
        with patch.object(m,"virsh",side_effect=lambda *a,**k:
             snap(NEW,1760294300).replace('<state>running</state>',
                                          '<state>shutoff</state>')),\
             self.assertRaises(m.CaptureBlocked):
            m.snapshot_xml(NEW)

    def test_exact_two_image_qcow_snapshots_are_required(self):
        with tempfile.TemporaryDirectory() as td:
            disk=Path(td)/"disk.qcow2"
            vars=Path(td)/"vars.fd.qcow2"
            disk.write_bytes(b"qcow simulated")
            vars.write_bytes(b"qcow simulated")
            with patch.object(m,"OS_DISK",disk),patch.object(m,"OVMF",vars),\
                 patch.object(m,"cmd",return_value=qcow_reply(False)):
                result=m.images(NEW,False)
            self.assertTrue(result["os_disk"]["old_checkpoint_preserved"])
            self.assertFalse(result["uefi_qcow2"]["new_checkpoint_present_once"])
            with patch.object(m,"OS_DISK",disk),patch.object(m,"OVMF",vars),\
                 patch.object(m,"cmd",return_value=qcow_reply(True)):
                result=m.images(NEW,True)
            self.assertTrue(result["os_disk"]["new_checkpoint_present_once"])
            self.assertTrue(result["uefi_qcow2"]["new_checkpoint_present_once"])
            with patch.object(m,"OS_DISK",disk),patch.object(m,"OVMF",vars),\
                 patch.object(m,"cmd",return_value=json.dumps({
                     "format":"qcow2","snapshots":[{"name":NEW}]})),\
                 self.assertRaisesRegex(m.CaptureBlocked,"Original"):
                m.images(NEW,True)
            vars.unlink()
            vars.symlink_to(disk)
            with patch.object(m,"OS_DISK",disk),patch.object(m,"OVMF",vars),\
                 self.assertRaisesRegex(m.CaptureBlocked,"missing"):
                m.images(NEW,False)

    def test_full_plan_requires_free_space_agent_nic_reservation(self):
        with tempfile.TemporaryDirectory() as td:
            disk=Path(td)/"disk.qcow2";disk.write_bytes(b"stub")
            vars=Path(td)/"uefi.qcow2";vars.write_bytes(b"stub")
            tpm=Path(td)/"tpm";tpm.mkdir()
            (tpm/"tpm2-00.permall").write_bytes(b"non-secret-test")
            spec=SimpleNamespace(f_bavail=70*1024**3,f_frsize=1)
            def query(*args,**kw):
                if args and args[0]=="qemu-img":
                    return qcow_reply(False)
                raise AssertionError(args)
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(m.dual,"assess",return_value=DUAL),\
                 patch.object(m,"OS_DISK",disk),\
                 patch.object(m,"OVMF",vars),\
                 patch.object(m,"TPM",tpm),\
                 patch.object(m.os,"statvfs",return_value=spec),\
                 patch.object(m,"virsh",side_effect=virsh(False)),\
                 patch.object(m,"cmd",side_effect=query):
                report=m.preflight(False)
            self.assertFalse(report["CAPE_READY"])
            self.assertFalse(report["snapshot_for_final_one_nic_config"])
            self.assertEqual(report["snapshot_name"],NEW)
            self.assertTrue(report["pre_existing_snapshot_not_reverted_or_deleted"])
            self.assertFalse(report["swtpm_epoch_consistent_checkpoint_captured"])
            self.assertFalse(report["new_snapshot_created"])

    def test_low_disk_space_or_missing_swtpm_blocks_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m.os,"geteuid",return_value=0),\
                 patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(m.dual,"assess",return_value=DUAL),\
                 patch.object(m,"virsh",side_effect=virsh(False)),\
                 patch.object(m,"domain_views",return_value={"ok":True}),\
                 patch.object(m,"images",return_value={"os_disk":{"ok":True}}),\
                 patch.object(m,"TPM",Path(td)/"missing"),\
                 self.assertRaisesRegex(m.CaptureBlocked,"swtpm"):
                m.preflight(False)

    def test_capture_path_is_one_new_snapshot_no_revert_and_verify(self):
        with tempfile.TemporaryDirectory() as td:
            prev={"image_checkpoints":{"ok":True},
                  "network_checks":{"same":True},
                  "prior_snapshot_proof":{"snapshot_epoch":1760293200}}
            created=dict(prev,
                new_snapshot_proof={"snapshot_epoch":1760294300})
            state=[False]; calls=[]
            def v(*args,**kw):
                calls.append(args)
                if args[0]=="snapshot-create-as":
                    self.assertEqual(args,("snapshot-create-as","--domain",VM,
                                          "--name",NEW,"--atomic"))
                    state[0]=True
                    return ""
                raise AssertionError(args)
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                               st_uid=0,st_nlink=1)
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.APPROVE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"preflight",side_effect=lambda flag:
                     created if flag else prev),\
                 patch.object(m,"virsh",side_effect=v):
                out=m.capture()
            self.assertEqual(sum(x[0]=="snapshot-create-as" for x in calls),1)
            self.assertFalse(out["tpmsafe_reversion_tested"])
            self.assertTrue(out["new_snapshot_visible_in_libvirt_snapshot_list"])

    def test_capture_partial_failure_must_hold_never_delete_or_revert(self):
        with tempfile.TemporaryDirectory() as td:
            prev={"image_checkpoints":{"ok":True},
                  "network_checks":{"same":True},
                  "prior_snapshot_proof":{"snapshot_epoch":1760293200}}
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                               st_uid=0,st_nlink=1)
            called=[]
            def v(*args,**kw):
                called.append(args)
                raise m.CaptureBlocked("QEMU snapshot failed")
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.APPROVE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"preflight",return_value=prev),\
                 patch.object(m,"virsh",side_effect=v),\
                 self.assertRaisesRegex(m.CaptureBlocked,"POSSIBLE_PARTIAL"):
                m.capture()
            self.assertEqual(len(called),1)
            self.assertFalse(any(a[0] in ("snapshot-delete","snapshot-revert",
                                         "shutdown","destroy") for a in called))

if __name__=="__main__":unittest.main()
