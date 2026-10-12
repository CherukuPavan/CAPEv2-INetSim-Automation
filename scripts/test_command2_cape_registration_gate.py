"""Offline CAPE KVM per-guest running snapshot registration gates."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import command2_cape_registration_gate as a

HOST="fresh-analysis-host"
def rows():
    return [{"libvirt_name":f"win11_{i}",
             "guest_static_ipv4_target":f"192.168.241.{100+i}"}
            for i in (1,2)]
ORIGINAL="[kvm]\nmachines = template\ninterface = cape-lab0\ndsn = qemu:///system\n\n[template]\nlabel = template\nip = 192.168.241.199\n"

class CapeRegistration(unittest.TestCase):
    def make_plan(self,folder,accepted=True):
        path=Path(folder)/"kvm.conf"
        path.write_text(ORIGINAL)
        proof={"all_vm_snapshots_and_revert_evidence_present":accepted}
        with patch.object(a.gate,"host_guard"), \
             patch.object(a.gate,"private_evidence_folder"), \
             patch.object(a.gate,"reservation_rows",return_value=rows()), \
             patch.object(a.gate,"evaluate",return_value=proof), \
             patch.object(a,"read_host_vms",return_value={
                 "win11_1","win11_2","template"}):
            out=a.plan(HOST,Path(folder)/"journal.json","192.168.241.0/24",
                       Path(folder),path)
        return out,path

    def test_each_vm_has_distinct_snapshot_before_cape_registration(self):
        with TemporaryDirectory() as temp:
            out,p=self.make_plan(temp)
            self.assertEqual(out["result"],
                    "COMMAND2_CAPE_REGISTRATION_SNAPSHOT_VERIFIED_PLAN_ONLY")
            self.assertEqual(out["vm_count"],2)
            self.assertEqual([x["snapshot"] for x in out["registered_guest_proposals"]],
                    ["cape_ready_win11_1","cape_ready_win11_2"])
            self.assertFalse(out["production_release_authorized"])
            self.assertEqual(p.read_text(),ORIGINAL)

    def test_one_missing_snapshot_witness_blocks_all_registrations(self):
        with TemporaryDirectory() as temp:
            with self.assertRaisesRegex(a.RegBlocked,"Per-VM CAPE"):
                self.make_plan(temp,accepted=False)

    def test_plan_rejects_previous_registered_vm(self):
        with TemporaryDirectory() as tmp:
            p=Path(tmp)/"kvm.conf"
            p.write_text(ORIGINAL+"[win11_1]\nlabel = win11_1\n")
            with patch.object(a.gate,"host_guard"), \
                 patch.object(a.gate,"private_evidence_folder"), \
                 patch.object(a.gate,"reservation_rows",return_value=rows()), \
                 patch.object(a.gate,"evaluate",return_value={
                     "all_vm_snapshots_and_revert_evidence_present":True}), \
                 patch.object(a,"read_host_vms",return_value={
                     "win11_1","win11_2","template"}):
                with self.assertRaisesRegex(a.reg.CapeConfigError,"already configured"):
                    a.plan(HOST,p,p,Path(tmp),p)

    def test_unapproved_snapshot_fallback_never_written(self):
        original=ORIGINAL
        out=a.reg.render_config(
            original,[{"name":"win11_1","ip":"192.168.241.101",
                       "snapshot":"cape_ready_win11_1"},
                      {"name":"win11_2","ip":"192.168.241.102",
                       "snapshot":"cape_ready_win11_2"}],
            libvirt_existing={"win11_1","win11_2","template"},
            snapshot="UNUSED_SINGLE_SNAPSHOT",interface="cape-lab0")
        self.assertNotIn("UNUSED_SINGLE_SNAPSHOT",out)
        self.assertIn("snapshot = cape_ready_win11_1",out)
        self.assertIn("snapshot = cape_ready_win11_2",out)

    def test_noninteractive_apply_refused_without_mutation(self):
        with patch.object(a.sys.stdin,"isatty",return_value=False), \
             patch.object(a.os,"geteuid",return_value=0), \
             patch.object(a,"plan",side_effect=AssertionError("Do not read plan")):
            with self.assertRaisesRegex(a.RegBlocked,"terminal"):
                a.apply(HOST,Path("/none"),"192.168.241.0/24",
                        Path("/none"),Path("/none"))

    def test_no_snapshot_vm_network_or_malware_execution_in_module(self):
        code=Path(a.__file__).read_text()
        for needle in ('"snapshot-create-as"', '"snapshot-revert"',
                       '"destroy"', '"shutdown"', '"net-start"',
                       '"attach-interface"', '"curl"'):
            self.assertNotIn(needle,code)

if __name__=="__main__":
    unittest.main()
