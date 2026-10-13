"""Offline synthetic regression for joined guarded Command2 N-VM sequence."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import command2_exact_master_full_sequence as s

class SequenceTests(unittest.TestCase):
    def args(self,td,n=2):
        root=Path(td)
        return SimpleNamespace(mode="plan",approved_host="other-host",
             bundle=root/"cape-master-abcd",
             disk_dir=root/"images", nvram_dir=root/"nvram",
             journal_dir=root/"journals",iso_dir=root/"iso",
             evidence_dir=root/"evidence",count=n,
             receipt_dir=root/"receipts",shutdown_timeout=360)

    def test_count_bounds_and_additional_semantics(self):
        self.assertEqual(s.vm_names(3),["win11_1","win11_2","win11_3"])
        self.assertEqual(len(s.phases(3)),2+3*4+3)
        for n in (-1,0,17,100):
            with self.assertRaises(s.SequenceBlocked):
                s.vm_names(n)
        with patch.object(s.sys.stdin,"isatty",return_value=True), \
             patch("builtins.input",return_value="2"):
            self.assertEqual(s.resolve_count(None),2)
        with patch.object(s.sys.stdin,"isatty",return_value=True), \
             patch("builtins.input",return_value="00"), \
             self.assertRaises(s.SequenceBlocked):
            s.resolve_count(None)

    def test_order_strict_sequential_windows_identities_and_final_shutdown(self):
        exact=s.phases(2)
        self.assertEqual(exact[:2],[
            ("cold_count_stage",None),("all_clone_uefi_qcow2",None)])
        self.assertEqual(exact[2:6],[
            ("boot_exact_windows","win11_1"),
            ("upload_trusted_windows_setup","win11_1"),
            ("request_benign_windows_identity","win11_1"),
            ("independently_verify_windows","win11_1")])
        self.assertEqual(exact[6:10],[
            ("boot_exact_windows","win11_2"),
            ("upload_trusted_windows_setup","win11_2"),
            ("request_benign_windows_identity","win11_2"),
            ("independently_verify_windows","win11_2")])
        self.assertEqual(exact[-3:],[
            ("all_clones_agent_health",None),
            ("capture_all_running_candidates",None),
            ("all_graceful_shutdown",None)])

    def test_exact_private_journal_guest_ip_and_media_binding(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td)
            p="/PRIVATE/code/" + s.STEPS["cold_count_stage"]
            c=s.child_args(a,2,p,"cold_count_stage")
            self.assertEqual(c[c.index("--count")+1],"2")
            vm="win11_2"
            for kind in ("upload_trusted_windows_setup",
                         "request_benign_windows_identity",
                         "independently_verify_windows"):
                cmd=s.child_args(a,2,"/PRIVATE/code/"+s.STEPS[kind],kind,vm)
                self.assertEqual(cmd[cmd.index("--vm")+1],vm)
                self.assertIn("win11_2.master-nat.iso",cmd)
                self.assertIn(str(a.journal_dir/"command2-identity-reservation.json"),cmd)
            cmd=s.child_args(a,2,"/PRIVATE/code/"+s.STEPS[
                             "all_graceful_shutdown"],"all_graceful_shutdown")
            self.assertIn("--timeout-seconds",cmd)
            self.assertEqual(cmd[-1],"360")
            with self.assertRaisesRegex(s.SequenceBlocked,"Unapproved"):
                s.child_args(a,2,p,"arbitrary-cape-analysis")

    def test_read_only_plan_delegates_to_existing_source_admission_only(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td,3)
            calls=[]
            with patch.object(s.workflow,"canonical_host",return_value="other-host"), \
                 patch.object(s.os,"geteuid",return_value=0), \
                 patch.object(s,"run_child",side_effect=lambda argv:
                              calls.append(argv) or 0):
                r=s.plan(a)
            self.assertEqual(r["additional_vm_count"],3)
            self.assertEqual(r["vm_names"],["win11_1","win11_2","win11_3"])
            self.assertEqual(r["step_count"],2+12+3)
            self.assertFalse(r["host_modified"])
            self.assertFalse(r["TPM_safe_snapshot_restore_proven"])
            self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][calls[0].index("--mode")+1],"plan")

    def test_approval_denial_never_writes_receipt_or_stage(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td)
            with patch.object(s.os,"geteuid",return_value=0), \
                 patch.object(s.sys.stdin,"isatty",return_value=True), \
                 patch.object(s.workflow,"canonical_host",return_value="other-host"), \
                 patch.object(s,"plan",return_value={
                     "result":"PLAN","additional_vm_count":2}), \
                 patch("builtins.input",return_value="NO"), \
                 patch.object(s,"witness_folder",side_effect=AssertionError("no witness")), \
                 self.assertRaisesRegex(s.SequenceBlocked,"declined"):
                s.execute(a)

    def test_exact_success_calls_child_in_strict_order_and_records_stages(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td,2)
            record=[]
            programs=[]
            fake_plan={"result":"PLAN","additional_vm_count":2}
            with patch.object(s.os,"geteuid",return_value=0), \
                 patch.object(s.sys.stdin,"isatty",return_value=True), \
                 patch.object(s.workflow,"canonical_host",return_value="other-host"), \
                 patch.object(s,"plan",return_value=fake_plan), \
                 patch("builtins.input",return_value=s.APPROVAL), \
                 patch.object(s,"witness_folder",return_value=a.receipt_dir), \
                 patch.object(s,"save_witness",
                     side_effect=lambda path,data,**kw:
                         record.append(deepcopy(data))), \
                 patch.object(s,"run_child",
                     side_effect=lambda argv: programs.append(argv) or 0):
                result=s.execute(a)
            self.assertEqual(len(programs),len(s.phases(2)))
            self.assertEqual(result["count"],2)
            self.assertEqual(result["names"],["win11_1","win11_2"])
            self.assertTrue(result["running_ram_disk_uefi_snapshot_candidates_stored"])
            self.assertFalse(result["swtpm2_snapshots_revert_proven"])
            self.assertFalse(result["CAPE_SAFE_TO_RUN_SAMPLES"])
            self.assertEqual(record[-1]["result"],
                 "COMMAND2_ALL_N_CANDIDATE_SNAPSHOTS_SHUT_OFF_TPM_UNVERIFIED")
            self.assertEqual(len(record[-1]["completed"]),len(s.phases(2)))

    def test_stops_and_persists_partial_receipt_without_retry_or_next_vm(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td,2)
            receipts=[]
            invoked=[]
            def child(argv):
                invoked.append(argv)
                if len(invoked)==4:return 2
                return 0
            with patch.object(s.os,"geteuid",return_value=0), \
                 patch.object(s.sys.stdin,"isatty",return_value=True), \
                 patch.object(s.workflow,"canonical_host",return_value="other-host"), \
                 patch.object(s,"plan",return_value={"result":"PLAN"}), \
                 patch("builtins.input",return_value=s.APPROVAL), \
                 patch.object(s,"witness_folder",return_value=a.receipt_dir), \
                 patch.object(s,"save_witness",
                      side_effect=lambda path,val,**kw:
                          receipts.append(deepcopy(val))), \
                 patch.object(s,"run_child",side_effect=child), \
                 self.assertRaisesRegex(s.SequenceBlocked,"PARTIAL_OR_UNKNOWN"):
                s.execute(a)
            self.assertEqual(len(invoked),4)
            last=receipts[-1]
            self.assertEqual(last["result"],"COMMAND2_SEQUENCE_PARTIAL_OR_UNKNOWN")
            self.assertEqual(last["failed_step"]["step"],
                             "upload_trusted_windows_setup")
            self.assertEqual(last["failed_step"]["vm"],"win11_1")
            self.assertEqual(len(last["completed"]),3)

    def test_reference_ssl55_never_stages_even_root(self):
        with tempfile.TemporaryDirectory() as td:
            a=self.args(td)
            with patch.object(s.os,"geteuid",return_value=0), \
                 patch.object(s.sys.stdin,"isatty",return_value=True), \
                 patch.object(s.workflow,"canonical_host",
                              side_effect=s.workflow.WorkflowBlocked("SSL-55")), \
                 patch.object(s,"plan",side_effect=AssertionError("no plan")), \
                 self.assertRaises(s.workflow.WorkflowBlocked):
                s.execute(a)

    def test_unapproved_programs_never_run(self):
        with self.assertRaises(s.SequenceBlocked):
            s.run_child(["/tmp/unauthorized.py","--mode","apply"])
        src=Path(s.__file__).read_text(encoding="utf-8")
        for banned in ("snapshot-revert", "virsh start", "systemctl restart",
                       "iptables -A", "shell=True", "os.system("):
            self.assertNotIn(banned,src)

if __name__=="__main__":
    unittest.main()
