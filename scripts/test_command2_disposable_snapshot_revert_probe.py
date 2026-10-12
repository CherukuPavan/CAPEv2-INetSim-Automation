"""Synthetic destructive snapshot-revert gate tests: NO real VM modifications."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_disposable_snapshot_revert_probe as r

HOST="other-lab-ubuntu"
VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"
ROW={"libvirt_name":VM,"libvirt_uuid_candidate":UID,
     "mac_candidate":"02:ee:01:02:03:01",
     "guest_static_ipv4_target":"192.168.241.101",
     "uefi_nvram_target":"/private/nvram/win11_1.command2_VARS.fd"}
SUBNET="192.168.241.0/24"
SHA="a"*64
MANIFEST={"manifest_sha256":SHA}
def fake_virsh(*args,**kw):
    if args==("domuuid",VM):return UID
    if args==("domstate",VM):return "shut off"
    if args==("domstate","win11"):return "shut off"
    if args==("list","--name"):return ""
    raise AssertionError("Unexpected virsh command "+str(args))

class BenignRevert(unittest.TestCase):
    def make_plan(self,other_vm_running=False, snapshot_state="running",
                  bad_nft=False, bad_cold=False):
        def mockvirsh(*args,**kwargs):
            if args==("list","--name") and other_vm_running:return "win11_2"
            return fake_virsh(*args,**kwargs)
        with patch.object(r.flow,"canonical_host",return_value=HOST),\
             patch.object(r.os,"geteuid",return_value=0),\
             patch.object(r.flow,"load_guest",return_value=(ROW,SUBNET,None)),\
             patch.object(r.cold,"inspect",side_effect=(
                 r.cold.RecoveryBlocked("Missing cold recovery") if bad_cold
                 else None),return_value=MANIFEST),\
             patch.object(r,"virsh",side_effect=mockvirsh),\
             patch.object(r.nic,"verify_network_live",side_effect=(
                 r.nic.NicBlocked("Missing nft") if bad_nft else None),
                 return_value=True),\
             patch.object(r.batch,"live_domain",return_value={
                 "nvram_format":"qcow2","shut_off_for_cape":True}),\
             patch.object(r.batch,"snapshot_metadata",return_value={
                 "state":snapshot_state,"memory_snapshot":"internal",
                 "os_disk_snapshot":"internal"}):
            return r.plan(HOST,Path("/root/reservation.json"),VM,
                          Path("/private/fullcold"),SHA)

    def test_correct_disposable_snapshot_metadata_not_proof_of_rollback(self):
        report=self.make_plan()
        self.assertEqual(report["result"],
                         "COMMAND2_DISPOSABLE_RUNNING_REVERT_PLAN_ONLY")
        self.assertEqual(report["snapshot"],"cape_ready_win11_1")
        self.assertTrue(report["host_nft_libvirt_isolation_structure_verified"])
        self.assertFalse(report["swtpm_uefi_atomic_rollback_proven"])
        self.assertFalse(report["snapshot_reverted"])
        self.assertFalse(report["safe_for_malware"])

    def test_missing_real_isolation_structure_blocks_revert(self):
        with self.assertRaisesRegex(r.RevertBlocked,"isolation guard"):
            self.make_plan(bad_nft=True)

    def test_unverified_full_cold_backup_blocks_revert(self):
        with self.assertRaisesRegex(r.cold.RecoveryBlocked,"Missing cold"):
            self.make_plan(bad_cold=True)

    def test_any_other_running_guest_blocks_revert(self):
        with self.assertRaisesRegex(r.RevertBlocked,"Another guest running"):
            self.make_plan(other_vm_running=True)

    def test_no_running_memory_capture_refuses_revert(self):
        with self.assertRaisesRegex(r.RevertBlocked,"running memory"):
            self.make_plan(snapshot_state="shutoff")

    def test_invalid_manifest_hash_refuses_revert(self):
        with self.assertRaisesRegex(r.RevertBlocked,"manifest"):
            self.make_plan.__wrapped__() if hasattr(self.make_plan,"__wrapped__") else (
                self.invoke_wrong_hash())

    def invoke_wrong_hash(self):
        with patch.object(r.flow,"canonical_host",return_value=HOST),\
             patch.object(r.os,"geteuid",return_value=0),\
             patch.object(r.flow,"load_guest",return_value=(ROW,SUBNET,None)):
            return r.plan(HOST,Path("/root/reservation.json"),VM,
                          Path("/private/fullcold"),"unreviewed")

    def test_revert_requires_operator_tty_before_any_host_query(self):
        with patch.object(r.sys.stdin,"isatty",return_value=False),\
             patch.object(r,"plan",side_effect=AssertionError("No plan")):
            with self.assertRaisesRegex(r.RevertBlocked,"terminal"):
                r.revert_once(HOST,Path("/root/journal"),VM,
                              Path("/private/cold"),SHA)

    def test_no_force_or_shutdown_in_destructive_revert(self):
        code=Path(r.__file__).read_text()
        self.assertIn('virsh("snapshot-revert",vm,prior["snapshot"]',code)
        self.assertIn('nic.verify_network_live',code)
        for banned in ('"--force"', '"destroy"', '"shutdown"', '"undefine"',
                       '"net-autostart"', '"attach-interface"', '"start"', '"clear-tpm"'):
            self.assertNotIn(banned,code)

if __name__=="__main__":
    unittest.main()
