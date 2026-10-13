"""Offline synthetic-only final CAPE golden-NAT shutdown regressions.

Mocks libvirt, Windows, filesystem state and receipts: NEVER contacts a VM.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import stat
import unittest
from unittest.mock import patch

import command2_portable_master_nat_final_shutdown as m

HOST="lab02"

def fixture(n=3):
    rows=[{"libvirt_name":f"win11_{i}",
           "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}"}
          for i in range(1,n+1)]
    accepted={"result":"COMMAND2_MASTER_NAT_ALL_N_RUNNING_CANDIDATES_VERIFIED",
              "count":n,"all_running_native_snapshots_created":True,
              "CAPE_READY":False,
              "swtpm_epoch_matched_backup_and_twice_benign_revert_proven":False,
              "guest_snapshots":[{
                  "vm":r["libvirt_name"],
                  "uuid":r["libvirt_uuid_candidate"],
                  "expected_name":"cape_one_nat_"+r["libvirt_name"],
                  "snapshot_captured":True,
                  "swtpm_state_consistency_at_checkpoint_proved":False}
                   for r in rows]}
    return rows,accepted

class ExactFinalNat(unittest.TestCase):
    def read_only_context(self,rows,accepted,states):
        return (patch.object(m.snapshots,"assess",return_value=accepted),
                patch.object(m.snapshots.attach,"journal_rows",
                             return_value=rows),
                patch.object(m.shutdown,"inspect",side_effect=lambda h,s,v,j:{
                    "state":states[v],"uuid":next(r["libvirt_uuid_candidate"]
                    for r in rows if r["libvirt_name"]==v),
                    "capabilities":{"acpi":True,"qga_channel":False}}))

    def test_plan_requires_all_n_and_does_not_issue_shutdown(self):
        with TemporaryDirectory() as td:
            rows,accepted=fixture(3)
            j=Path(td)/"command2-identity-reservation.json"
            j.write_text("{}")
            states={r["libvirt_name"]:"running" for r in rows}
            a,b,c=self.read_only_context(rows,accepted,states)
            with a,b,c,patch.object(m.shutdown,"request_shutdown") as action:
                result=m.preflight(HOST,j,Path(td))
                action.assert_not_called()
            self.assertEqual(result["count"],3)
            self.assertFalse(result["malware_or_cape_ready"])
            self.assertFalse(result["snapshot_revert_tpm_state_proven"])

    def test_unverified_or_partial_snapshot_blocks_before_any_shutdown(self):
        with TemporaryDirectory() as td:
            rows,accepted=fixture(2)
            j=Path(td)/"command2-identity-reservation.json"
            j.write_text("{}")
            states={r["libvirt_name"]:"running" for r in rows}
            a,b,c=self.read_only_context(rows,accepted,states)
            with a,b,c,patch.object(m.shutdown,"request_shutdown") as action:
                accepted["guest_snapshots"][1]["snapshot_captured"]=False
                with self.assertRaisesRegex(m.FinalShutdownBlocked,"Unmatched"):
                    m.preflight(HOST,j,Path(td))
                action.assert_not_called()
                accepted["guest_snapshots"][1]["snapshot_captured"]=True
                accepted["CAPE_READY"]=True
                with self.assertRaisesRegex(m.FinalShutdownBlocked,"TPM-ready"):
                    m.preflight(HOST,j,Path(td))

    def test_entire_batch_gracefully_shut_off_and_snapshot_metadata_kept(self):
        with TemporaryDirectory() as td:
            rows,accepted=fixture(3)
            j=Path(td)/"command2-identity-reservation.json"
            j.write_text("{}")
            states={r["libvirt_name"]:"running" for r in rows}
            called=[]
            def run_shutdown(host,scope,vm,journal,seconds):
                self.assertEqual(scope,"portable-master-nat")
                self.assertEqual(seconds,420)
                self.assertEqual(states[vm],"running")
                states[vm]="shut off"
                called.append(vm)
                return {"result":"COMMAND2_GRACEFUL_SHUTDOWN_SHUT_OFF_CONFIRMED"}
            a,b,c=self.read_only_context(rows,accepted,states)
            with a,b,c,patch.object(m.os,"geteuid",return_value=0),\\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\\
                 patch("builtins.input",return_value=
                       "FINAL-SHUTDOWN-3-NAT-TPM-UNVERIFIED"),\\
                 patch.object(m,"LOCK",Path(td)/"unique.lock"),\\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                     st_uid=0,st_nlink=1,st_mode=stat.S_IFREG|0o600)),\\
                 patch.object(m.shutdown,"request_shutdown",
                              side_effect=run_shutdown),\\
                 patch.object(m.snapshots,"libvirt_snapshot") as metadata,\\
                 patch.object(m.snapshots,"images") as qcow:
                out=m.execute(HOST,j,Path(td),420)
            self.assertEqual(called,["win11_1","win11_2","win11_3"])
            self.assertEqual(out["result"],
                "COMMAND2_MASTER_NAT_ALL_N_SHUT_OFF_SNAPSHOTS_PRESERVED")
            self.assertTrue(out["snapshot_metadata_preserved"])
            self.assertFalse(out["CAPE_READY"])
            self.assertFalse(out["swtpm_safe_full_snapshot_revert_proven"])
            self.assertGreaterEqual(metadata.call_count,3)
            self.assertGreaterEqual(qcow.call_count,3)
            self.assertFalse((Path(td)/"unique.lock").exists())

    def test_partial_failure_halts_and_never_forces_remaining_guests(self):
        with TemporaryDirectory() as td:
            rows,accepted=fixture(3)
            j=Path(td)/"command2-identity-reservation.json"
            j.write_text("{}")
            states={r["libvirt_name"]:"running" for r in rows}
            called=[]
            def fail_second(host,scope,vm,journal,seconds):
                called.append(vm)
                if vm=="win11_2":
                    raise m.shutdown.ShutdownBlocked("Guest did not respond")
                states[vm]="shut off"
                return {"result":"COMMAND2_GRACEFUL_SHUTDOWN_SHUT_OFF_CONFIRMED"}
            a,b,c=self.read_only_context(rows,accepted,states)
            with a,b,c,patch.object(m.os,"geteuid",return_value=0),\\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\\
                 patch("builtins.input",return_value=
                       "FINAL-SHUTDOWN-3-NAT-TPM-UNVERIFIED"),\\
                 patch.object(m,"LOCK",Path(td)/"unique.lock"),\\
                 patch.object(m.os,"fstat",return_value=SimpleNamespace(
                     st_uid=0,st_nlink=1,st_mode=stat.S_IFREG|0o600)),\\
                 patch.object(m.shutdown,"request_shutdown",
                              side_effect=fail_second),\\
                 patch.object(m.snapshots,"libvirt_snapshot"),\\
                 patch.object(m.snapshots,"images"),\\
                 self.assertRaisesRegex(m.FinalShutdownBlocked,
                                        "PARTIAL_OR_UNKNOWN"):
                m.execute(HOST,j,Path(td))
            self.assertEqual(called,["win11_1","win11_2"])
            self.assertEqual(states["win11_1"],"shut off")
            self.assertEqual(states["win11_3"],"running")

    def test_read_only_and_no_forced_reset_revert_or_reboot(self):
        source=Path(m.__file__).read_text()
        for token in ('"destroy"','"reset"','"snapshot-revert"',
                      '"snapshot-delete"','"start"','shell=True'):
            self.assertNotIn(token,source)
        with patch.object(m.os,"geteuid",return_value=1000):
            with self.assertRaisesRegex(m.FinalShutdownBlocked,"Root"):
                m.execute("lab02",Path("/tmp/private.json"),
                          Path("/tmp/evidence"))

if __name__=="__main__":
    unittest.main()
