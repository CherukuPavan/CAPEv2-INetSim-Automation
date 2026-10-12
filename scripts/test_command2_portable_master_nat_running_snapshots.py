"""Synthetic-only 1..16 cloned master NAT GUI-visible running candidates."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_master_nat_running_snapshots as m

def rows(n):
    return [{"libvirt_name":f"win11_{i}",
        "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}",
        "mac_candidate":f"02:ca:22:00:00:{i:02x}",
        "disk_target":f"/srv/clones/win11_{i}.command2.qcow2",
        "uefi_nvram_target":f"/srv/ovmf/win11_{i}.command2_VARS.fd"}
        for i in range(1,n+1)]

def snapshot_xml(vm):
    return ("<domainsnapshot><name>cape_one_nat_"+vm+
       "</name><state>running</state><memory snapshot='internal'/>"
       "<disks><disk name='sda' snapshot='internal'/></disks>"
       "<domain type='kvm'><name>"+vm+"</name><devices>"
       "<interface type='network'><source network='default'/>"
       "<model type='e1000e'/></interface></devices></domain>"
       "</domainsnapshot>")

class AllNatSnapshots(unittest.TestCase):
    def test_expected_old_state_and_verified_running_metadata(self):
        with patch.object(m.attach,"virsh",return_value=""):
            self.assertFalse(m.libvirt_snapshot("win11_1",False)
                             ["snapshot_already_exists"])
        def good(*a,**kw):
            if a[:1]==("snapshot-list",):return "cape_one_nat_win11_1"
            if a[:1]==("snapshot-dumpxml",):return snapshot_xml("win11_1")
            raise AssertionError(a)
        with patch.object(m.attach,"virsh",side_effect=good):
            out=m.libvirt_snapshot("win11_1",True)
        self.assertTrue(out["captured_running_ram"])
        self.assertEqual(out["snapshot_name"],"cape_one_nat_win11_1")
        with patch.object(m.attach,"virsh",return_value="rogue"):
            with self.assertRaises(m.NATSnapshotBlocked):
                m.libvirt_snapshot("win11_1",False)

    def test_qcow_two_real_standalone_image_tables(self):
        with tempfile.TemporaryDirectory() as td:
            disk=Path(td)/"win11_1.command2.qcow2"
            firmware=Path(td)/"win11_1.command2_VARS.fd.qcow2"
            disk.write_bytes(b"synthetic");firmware.write_bytes(b"synthetic")
            row=rows(1)[0]
            row["disk_target"]=str(disk)
            row["uefi_nvram_target"]=str(firmware)[:-6]
            domain=("<domain type='kvm'><devices>"
                "<disk device='disk'><source file='"+str(disk)+"'/></disk>"
                "</devices><os><nvram format='qcow2'>"+str(firmware)+
                "</nvram></os></domain>")
            def command(*a,**kw):
                if a[:2]==("qemu-img","info"):
                    return json.dumps({"format":"qcow2",
                      "snapshots":[{"name":"cape_one_nat_win11_1"}]})
                raise AssertionError(a)
            with patch.object(m.attach,"virsh",return_value=domain),\
                 patch.object(m.native,"command",side_effect=command):
                ret=m.images(row,True)
            self.assertEqual(len(ret),2)
            self.assertEqual(ret["Windows_OS"]["checkpoint_names"],
                             ["cape_one_nat_win11_1"])
            with patch.object(m.attach,"virsh",return_value=domain),\
                 patch.object(m.native,"command",side_effect=command),\
                 self.assertRaisesRegex(m.NATSnapshotBlocked,"Unexpected/partial"):
                m.images(row,False)

    def test_acceptance_receipt_requires_exact_root_private_witness(self):
        row=rows(1)[0]
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            receipt=root/(row["libvirt_name"]+m.RECEIPT_SUFFIX)
            doc={"format":"COMMAND2_WINDOWS_NAT_INDEPENDENT_ACCEPTANCE_V1",
                "host":"lab02","vm":"win11_1",
                "uuid":row["libvirt_uuid_candidate"],
                "mac":row["mac_candidate"],
                "target_nat_ip":"192.168.122.201",
                "CAPE_agent_through_new_nat_and_L2_mac_verified":True,
                "guest_hostname_effective":True,
                "guest_only_expected_mac":True,
                "guest_dhcp_exact_reserved_ipv4":True,
                "guest_default_nat_gateway_and_dns":True,
                "real_guest_https_from_nat_ipv4":True,
                "guest_script_ran_in_verify_readonly_mode":True,
                "running_memory_disk_uefi_snapshot_captured":False,
                "swtpm_consistent_revert_proven":False,
                "malware_analysis_authorized":False}
            receipt.write_text(json.dumps(doc))
            with patch.object(m.witness.transport,"verified_evidence_folder",
                              return_value=root),\
                 patch.object(m.witness.approved,"trusted_stage_json",
                              return_value=doc):
                h=m.attest_guest(row,"lab02",root)
                self.assertEqual(h,hashlib.sha256(receipt.read_bytes()).hexdigest())
                doc["malware_analysis_authorized"]=True
                with self.assertRaises(m.NATSnapshotBlocked):
                    m.attest_guest(row,"lab02",root)

    def test_count_driven_all_n_preflight_and_state_holds(self):
        for n in (1,3,16):
            records=rows(n)
            with tempfile.TemporaryDirectory() as td:
                journal=Path(td)/"command2-identity-reservation.json"
                journal.write_text(json.dumps(records))
                storage=Path(td)/"disk.qcow2";storage.write_bytes(b"stub")
                for r in records:r["disk_target"]=str(storage)
                proof={"result":"COMMAND2_ALL_N_MASTER_NAT_AGENTS_RUNNING_VERIFIED_READONLY",
                  "count":n,"guests":[{
                   "vm":r["libvirt_name"],"mac":r["mac_candidate"],
                   "reserved_unique_mac_ip_live_and_persistent":True,
                   "saved_live_one_master_nat_nic":True,
                   "host_gateway_route_verified":True,
                   "cape_agent":{"valid":True}} for r in records]}
                stack={"uefi_variable_store_real_format":"qcow2",
                       "swtpm2_present":True,"snapshot_created":False,
                       "guest_ram_bytes":2*1024**3}
                with patch.object(m.attach,"journal_rows",return_value=records),\
                     patch.object(m.agents,"check",return_value=proof),\
                     patch.object(m,"attest_guest",return_value="b"*64),\
                     patch.object(m.native,"inspect",return_value=stack),\
                     patch.object(m,"libvirt_snapshot",return_value={
                         "snapshot_already_exists":False}),\
                     patch.object(m,"images",return_value={"ok":True}),\
                     patch.object(m.os,"statvfs",return_value=SimpleNamespace(
                         f_bavail=150*1024**3,f_frsize=1)):
                    result=m.assess("lab02",journal,Path(td),False)
                self.assertEqual(result["count"],n)
                self.assertFalse(result["all_running_native_snapshots_created"])
                self.assertFalse(result["CAPE_READY"])
                self.assertFalse(result["swtpm_epoch_matched_backup_and_twice_benign_revert_proven"])

    def test_one_approved_snapshot_each_and_partial_error_stops(self):
        with tempfile.TemporaryDirectory() as td:
            records=rows(3)
            journal=Path(td)/"command2-identity-reservation.json"
            journal.write_text(json.dumps(records))
            baseline={"count":3,"guest_snapshots":[
               {"vm":r["libvirt_name"],"expected_name":
                "cape_one_nat_"+r["libvirt_name"]} for r in records]}
            states=[]
            def call(*a,**kw):
                if a[0]=="snapshot-list":return ""
                if a[0]=="snapshot-create-as":
                    self.assertEqual(kw,{"timeout":1800})
                    states.append(a)
                    return ""
                raise AssertionError(a)
            with patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="CAPTURE-3-MASTER-NAT-RUNNING-TPM-UNVERIFIED"),\
                 patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)),\
                 patch.object(m,"assess",side_effect=lambda *a:baseline),\
                 patch.object(m.attach,"journal_rows",return_value=records),\
                 patch.object(m.attach,"virsh",side_effect=call),\
                 patch.object(m,"libvirt_snapshot",return_value={
                     "snapshot_already_exists":True}),\
                 patch.object(m,"images",return_value={"ok":True}):
                done=m.capture("lab02",journal,Path(td))
            self.assertEqual(len(states),3)
            self.assertIn("cape_one_nat_win11_3",str(states[-1]))
            def failing(*a,**kw):
                if a[0]=="snapshot-list":return ""
                if a[0]=="snapshot-create-as":
                    raise m.NATSnapshotBlocked("libvirt refused snapshot")
                raise AssertionError(a)
            with patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",
                       return_value="CAPTURE-3-MASTER-NAT-RUNNING-TPM-UNVERIFIED"),\
                 patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)),\
                 patch.object(m,"assess",return_value=baseline),\
                 patch.object(m.attach,"journal_rows",return_value=records),\
                 patch.object(m.attach,"virsh",side_effect=failing),\
                 self.assertRaisesRegex(m.NATSnapshotBlocked,
                                        "PARTIAL_STATE_POSSIBLE"):
                m.capture("lab02",journal,Path(td))

    def test_no_revert_delete_shutdown_start_or_unsafe_auto_retry(self):
        s=Path(m.__file__).read_text()
        for bad in ('"snapshot-revert"','"snapshot-delete"','"destroy"',
                    '"shutdown"','"restart"','"start"','shell=True'):
            self.assertNotIn(bad,s)

if __name__=="__main__":unittest.main()
