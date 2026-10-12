"""Offline synthetic acceptance for N-vm running snapshot+revert gate."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import command2_running_snapshot_batch_gate as g

HOST="new-kvm-host"
def row(i):
    return {"libvirt_name":f"win11_{i}",
            "libvirt_uuid_candidate":f"12345678-1234-4234-8234-{i:012d}",
            "mac_candidate":f"02:02:03:04:05:{i:02x}",
            "guest_static_ipv4_target":f"192.168.241.{100+i}",
            "uefi_nvram_target":f"/nvram/win11_{i}.command2_VARS.fd",
            "windows_hostname_target":f"WIN11-{i}"}
def domain(r):
    return (f'<domain type="kvm"><name>{r["libvirt_name"]}</name>'
            f'<uuid>{r["libvirt_uuid_candidate"]}</uuid>'
            f'<os><nvram format="qcow2">{r["uefi_nvram_target"]}.qcow2</nvram></os>'
            '<devices><disk device="disk" type="file">'
            '<driver type="qcow2"/></disk><tpm><backend type="emulator" version="2.0"/>'
            '</tpm><interface type="network">'
            '<source network="cape-analysis-isolated"/>'
            f'<mac address="{r["mac_candidate"]}"/></interface>'
            '</devices></domain>')
def snapxml(vm, state="running", memory="internal", disk="internal"):
    return (f'<domainsnapshot><name>cape_ready_{vm}</name><state>{state}</state>'
            f'<memory snapshot="{memory}"/>'
            f'<disks><disk name="sda" snapshot="{disk}"/></disks>'
            '</domainsnapshot>')
def fake_virsh(rows, with_snap=True, memory="internal"):
    indexed={r["libvirt_name"]:r for r in rows}
    def invoke(*cmd):
        name=cmd[2] if cmd[0]=="dumpxml" and cmd[1]=="--inactive" else cmd[1]
        r=indexed[name]
        if cmd[0]=="domuuid":return r["libvirt_uuid_candidate"]
        if cmd[0]=="domstate":return "shut off"
        if cmd[0]=="dumpxml" and cmd[1]=="--inactive":return domain(r)
        if cmd[0]=="snapshot-list":
            return f"cape_ready_{name}" if with_snap else ""
        if cmd[0]=="snapshot-dumpxml":
            return snapxml(name,memory=memory)
        raise AssertionError("Unexpected read query: "+str(cmd))
    return invoke
def witness(r):
    name=r["libvirt_name"]
    data={"format":"COMMAND2_RUNNING_SNAPSHOT_REVERT_WITNESS_V1",
          "host":HOST,"vm":name,"uuid":r["libvirt_uuid_candidate"],
          "mac":r["mac_candidate"],"guest_ip":r["guest_static_ipv4_target"],
          "snapshot":"cape_ready_"+name,
          "operator":"lab-operator",
          "witness_details":"Two benign running revert cycles and TPM tests seen on dedicated disposable lab."}
    for k in g.REQUIRED_CYCLE:data[k]=True
    return data

class SnapshotBatch(unittest.TestCase):
    def test_two_vm_success_only_with_both_witnesses(self):
        rows=[row(1),row(2)]
        with TemporaryDirectory() as temp:
            root=Path(temp)
            for r in rows:
                (root/(r["libvirt_name"]+".running-snapshot-witness.json")).write_text(
                    json.dumps(witness(r)))
            with patch.object(g,"virsh",side_effect=fake_virsh(rows)), \
                 patch.object(g,"image_snapshots",return_value={
                     "os_disk_and_uefi_vars_have_named_checkpoint":True}), \
                 patch.object(g,"rootfile",side_effect=lambda p,limit=128*1024:
                       json.loads(Path(p).read_text())):
                result=g.evaluate(rows,"192.168.241.0/24",HOST,root/"journal",root)
        self.assertEqual(result["witnessed_gates_count"],2)
        self.assertTrue(result["all_vm_snapshots_and_revert_evidence_present"])
        self.assertFalse(result["production_release_authorized_by_this_script"])
        self.assertFalse(result["raw_pflash_swtpm_atomic_restore_guaranteed_by_metadata"])

    def test_missing_second_snapshot_blocks_batch_even_if_first_ok(self):
        rows=[row(1),row(2)]
        def vm(*args):
            if args==("snapshot-list","win11_2","--name"):return ""
            return fake_virsh(rows)(*args)
        with TemporaryDirectory() as temp:
            root=Path(temp)
            for r in rows:
                (root/(r["libvirt_name"]+".running-snapshot-witness.json")).write_text(
                    json.dumps(witness(r)))
            with patch.object(g,"virsh",side_effect=vm), \
                 patch.object(g,"image_snapshots",return_value={
                     "os_disk_and_uefi_vars_have_named_checkpoint":True}), \
                 patch.object(g,"rootfile",side_effect=lambda p,limit=128*1024:
                       json.loads(Path(p).read_text())):
                result=g.evaluate(rows,"192.168.241.0/24",HOST,root/"journal",root)
        self.assertFalse(result["all_vm_snapshots_and_revert_evidence_present"])
        self.assertEqual(result["witnessed_gates_count"],1)
        self.assertEqual(result["vm_results"][1]["status"],"BLOCKED")

    def test_missing_tpm_revert_evidence_refused(self):
        r=row(1)
        proof=witness(r)
        proof["post_revert_swtpm2_consistency_verified"]=False
        with patch.object(g,"rootfile",return_value=proof):
            with self.assertRaisesRegex(g.GateBlocked,"TPM/UEFI"):
                g.witness_gate("/path/witness",r["libvirt_name"],r,
                               "cape_ready_win11_1",HOST)

    def test_disk_only_snapshot_refused(self):
        r=row(1)
        with patch.object(g,"virsh",side_effect=lambda *args:
             "cape_ready_win11_1" if args[0]=="snapshot-list" else
             snapxml("win11_1",memory="no")):
            with self.assertRaisesRegex(g.GateBlocked,"BOTH"):
                g.snapshot_metadata("win11_1","cape_ready_win11_1")

    def test_real_ssl55_sda_os_plus_sdb_firmware_no_is_accepted(self):
        vm="win11_1"
        live=(f'<domainsnapshot><name>cape_ready_{vm}</name>'
              '<state>running</state><memory snapshot="internal"/>'
              '<disks><disk name="sda" snapshot="internal"/>'
              '<disk name="sdb" snapshot="no"/></disks></domainsnapshot>')
        with patch.object(g,"virsh",side_effect=lambda *argv:
             "cape_ready_win11_1" if argv[0]=="snapshot-list" else live):
            result=g.snapshot_metadata(vm,"cape_ready_"+vm)
        self.assertEqual(result["snapshot_disk_entries"],2)
        self.assertFalse(
            result["qcow2_uefi_checkpoint_independently_verified_by_metadata"])
        for unsafe in (
            live.replace('name="sdb" snapshot="no"',
                         'name="sdb" snapshot="internal"'),
            live.replace('name="sdb" snapshot="no"',
                         'name="sdc" snapshot="no"'),
            live.replace('name="sdb" snapshot="no"',
                         'name="sda" snapshot="no"'),
        ):
            with patch.object(g,"virsh",side_effect=lambda *argv:
                 "cape_ready_win11_1" if argv[0]=="snapshot-list" else unsafe),\
                 self.assertRaises(g.GateBlocked):
                g.snapshot_metadata(vm,"cape_ready_"+vm)

    def test_image_checkpoints_require_both_separate_qcow2_files(self):
        with TemporaryDirectory() as td:
            root=Path(td)
            disk=root/"win11_1.command2.qcow2"
            nvram=root/"win11_1.command2_VARS.fd.qcow2"
            disk.write_bytes(b"stub")
            nvram.write_bytes(b"stub")
            record={"disk_target":str(disk),
                    "uefi_nvram_target":str(nvram)[:-6]}
            snap="cape_ready_win11_1"
            info={"format":"qcow2","snapshots":[{"name":snap}]}
            def get_info(*argv):
                self.assertEqual(argv[:3],("qemu-img","info","--output=json"))
                return json.dumps(info)
            with patch.object(g,"run",side_effect=get_info):
                found=g.image_snapshots(record,snap)
            self.assertTrue(found["os_disk_and_uefi_vars_have_named_checkpoint"])
            self.assertFalse(found["swtpm_checkpoint_or_rollback_proven"])
            calls=[]
            def missing_firmware(*argv):
                calls.append(argv[-1])
                data=dict(info)
                if argv[-1]==str(nvram):data["snapshots"]=[]
                return json.dumps(data)
            with patch.object(g,"run",side_effect=missing_firmware),\
                 self.assertRaisesRegex(g.GateBlocked,"uefi_vars"):
                g.image_snapshots(record,snap)
            self.assertEqual(calls,[str(disk),str(nvram)])
            nvram.unlink()
            nvram.symlink_to(disk)
            with patch.object(g,"run",side_effect=get_info),\
                 self.assertRaisesRegex(g.GateBlocked,"symlinked"):
                g.image_snapshots(record,snap)

    def test_offline_snapshot_not_accepted(self):
        with patch.object(g,"virsh",side_effect=lambda *args:
             "cape_ready_win11_1" if args[0]=="snapshot-list" else
             snapxml("win11_1",state="shutoff")):
            with self.assertRaisesRegex(g.GateBlocked,"RUNNING"):
                g.snapshot_metadata("win11_1","cape_ready_win11_1")

    def test_public_or_link_local_or_default_nat_subnet_refused(self):
        r=row(1)
        for subnet in ("169.254.100.0/24","127.0.0.0/24",
                       "192.168.122.0/24","8.8.8.0/24"):
            with self.subTest(subnet=subnet),self.assertRaises(g.GateBlocked):
                g.expected_guest(r,subnet)

    def test_world_writable_witness_directory_refused(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(g.os,"geteuid",return_value=0), \
                 patch.object(g.os,"stat",wraps=g.os.stat):
                with self.assertRaisesRegex(g.GateBlocked,"Root private"):
                    g.private_evidence_folder(root)

    def test_raw_nvram_or_unactivated_qcow2_sidecar_blocks_release(self):
        r=row(1)
        for bad in (domain(r).replace('format="qcow2"','format="raw"'),
                    domain(r).replace(".command2_VARS.fd.qcow2",
                                      ".command2_VARS.fd")):
            with self.subTest(bad=bad),\
                 patch.object(g,"virsh",side_effect=lambda *args:
                     r["libvirt_uuid_candidate"] if args[0]=="domuuid" else
                     "shut off" if args[0]=="domstate" else bad):
                with self.assertRaisesRegex(g.GateBlocked,"QCOW2 OVMF"):
                    g.live_domain("win11_1",r)

    def test_running_vm_even_with_running_snapshot_not_ready_for_cape(self):
        r=row(1)
        with patch.object(g,"virsh",side_effect=lambda *args:
            r["libvirt_uuid_candidate"] if args[0]=="domuuid" else "running"):
            with self.assertRaisesRegex(g.GateBlocked,"shut-off guest"):
                g.live_domain("win11_1",r)

    def test_nonsequential_reservation_fails(self):
        rows=[row(2),row(1)]
        data={"format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
              "version":1,"host":HOST,"guest_count":2,"entries":rows,
              "host_network_modified":False}
        with patch.object(g,"rootfile",return_value=data):
            with self.assertRaisesRegex(g.GateBlocked,"sequential"):
                g.reservation_rows("/fake",HOST)

    def test_reference_host_is_immutable(self):
        with patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"), \
             patch.object(g.os,"geteuid",return_value=0):
            with self.assertRaisesRegex(g.GateBlocked,"reference host protected"):
                g.host_guard("cse-ssl-55")

    def test_no_execution_or_vm_mutators(self):
        source=Path(g.__file__).read_text()
        for marker in ('"snapshot-create-as"', '"snapshot-revert"',
                       '"start"', '"destroy"', '"shutdown"',
                       '"net-start"', '"attach-interface"', '"nft","add"'):
            self.assertNotIn(marker,source)

if __name__=="__main__":
    unittest.main()
