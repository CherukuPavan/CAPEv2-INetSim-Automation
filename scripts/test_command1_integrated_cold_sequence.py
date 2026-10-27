"""Read-only mocked tests for combined host/source and golden cold handoff."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command1_integrated_cold_sequence as seq


class IntegratedColdTests(unittest.TestCase):
    def setUp(self):
        td=tempfile.TemporaryDirectory(prefix="cape-test-cold-")
        self.addCleanup(td.cleanup)
        self.path=Path(td.name)
        self.receipts=self.path/"receipts"
        self.receipts.mkdir()
        self.handoff=self.path/"handoff"
        self.args=SimpleNamespace(
            approved_host="lab-destination",
            cape_revision="a"*40,
            service_account_file=self.path/"restricted-sa.json",
            shared_parent_folder_id="A"*22,
            crypt_subfolder="master-backups",
            config=self.path/"crypt.conf",
            bundle_id="cape-master-SSL55-20261013-lan01",
            bundle_destination=self.path/"cape-master-SSL55-20261013-lan01",
            os_disk=self.path/"win11.qcow2",
            uefi_vars=self.path/"win11_VARS.fd",
            swtpm_user="libvirt-qemu",
            receipt_dir=self.receipts,
            handoff_receipt_dir=self.handoff,
        )
        self.plan={"result":"COMMAND1_INTEGRATED_COLD_SEQUENCE_PLAN_ONLY",
                   "host":self.args.approved_host,"host_modified":False}

    def test_partial_offline_python_profile_is_rejected_before_change(self):
        self.args.runtime_manifest=self.path/"manifest.json"
        with self.assertRaisesRegex(seq.IntegratedBlocked,
                                    "Partial CAPE runtime input"):
            seq.phases_for(self.args)
        with mock.patch.object(seq.base,"apply") as mutate:
            with self.assertRaisesRegex(seq.IntegratedBlocked,
                                        "Partial CAPE runtime input"):
                seq.execute(self.args)
        mutate.assert_not_called()

    def test_full_runtime_profile_appears_in_readonly_phase_order(self):
        for key in seq.RUNTIME_FIELDS:
            setattr(self.args,key,
                    ("a"*64 if "sha256" in key else self.path/key))
        self.assertEqual(
            seq.phases_for(self.args),
            (seq.PHASES[0],seq.RUNTIME_PHASE,seq.PHASES[1]))
        # A complete profile is routed into the existing three-phase
        # executor. Before approval or host admission it cannot mutate.
        with mock.patch.object(seq.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(seq,"preflight",return_value=self.plan), \
             mock.patch("builtins.input",return_value="DECLINED"), \
             mock.patch.object(seq.base,"apply") as mutate:
            with self.assertRaisesRegex(
                    seq.IntegratedBlocked,"Operator declined"):
                seq.execute(self.args)
        mutate.assert_not_called()

    def test_preflight_blocks_mismatched_python_abi_before_mutation(self):
        for key in seq.RUNTIME_FIELDS:
            setattr(self.args,key,("a"*64 if "sha256" in key
                                   else self.path/key))
        with mock.patch.object(seq,"admitted",return_value={
                 "service_account_email_to_share_with_as_viewer":
                 "viewer@example.invalid"}), \
             mock.patch.object(seq.base,"preflight",return_value={}), \
             mock.patch.object(seq.runtime.wheels,"plan",return_value={
                 "target_platform":"ubuntu-26.04-amd64",
                 "source_sha":self.args.cape_revision}), \
             mock.patch.object(seq.runtime,
                 "verified_runtime_release",
                 side_effect=seq.runtime.RuntimeBlocked(
                     "Reviewed CAPE native wheelhouse targets Ubuntu 26.04")) as v, \
             mock.patch.object(seq.base,"apply") as install:
            with self.assertRaisesRegex(seq.runtime.RuntimeBlocked,
                                        "Ubuntu 26.04"):
                seq.preflight(self.args)
        install.assert_not_called()
        v.assert_called_once_with("ubuntu-26.04-amd64")

    def test_admission_checks_credentials_before_base_transaction(self):
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.os,"geteuid",return_value=0))
            st.enter_context(mock.patch.object(seq.tx,"host_guard"))
            st.enter_context(mock.patch.object(seq.master,"admitted_host"))
            st.enter_context(mock.patch.object(
                seq.reader,"verify_inputs",
                side_effect=seq.reader.ReaderBlocked("No service account key")))
            with self.assertRaises(seq.reader.ReaderBlocked):
                seq.preflight(self.args)

    def test_plan_does_not_mutate_apts_or_guest(self):
        with ExitStack() as st:
            st.enter_context(mock.patch.object(
                seq, "admitted",return_value={
                    "service_account_email_to_share_with_as_viewer":
                    "private-viewer@demo.iam.gserviceaccount.com"}))
            p=st.enter_context(mock.patch.object(seq.base,"preflight",
                return_value={"result":"COMMAND1_BASE_TRANSACTION_PREFLIGHT"}))
            out=seq.preflight(self.args)
        self.assertFalse(out["guest_booted"])
        self.assertFalse(out["TPM_running_checkpoint_tested"])
        self.assertFalse(out["CAPE_ready"])
        self.assertFalse(out["host_modified"])
        p.assert_called_once_with(self.args.approved_host,self.args.cape_revision)

    def test_execution_runs_exact_order_and_never_starts_guest(self):
        writes=[]
        ordered=[]
        def write(path,record,*,first=False):
            writes.append((record["phase"],record["current"],
                           tuple(record["finished"]),first))
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",
                                                 return_value=seq.APPROVAL))
            st.enter_context(mock.patch.object(
                seq.master,"private_receipt_dir",return_value=self.receipts))
            st.enter_context(mock.patch.object(
                seq.master,"durable_receipt",side_effect=write))
            st.enter_context(mock.patch.object(
                seq.master,"inputs",return_value={"host_modified":False}))
            st.enter_context(mock.patch.object(seq.base,"apply",
                side_effect=lambda *args: (
                    ordered.append("base") or {
                        "exact_public_source_staged":True,
                        "transaction_id":"f"*32})))
            run=st.enter_context(mock.patch.object(seq.master,"execute",
                side_effect=lambda *args: (
                    ordered.append("master") or {
                        "master_imported_shut_off":True,
                        "guest_started":False})))
            result=seq.execute(self.args)
        self.assertEqual(ordered,["base","master"])
        self.assertEqual(result["master_vm_state"],"shut off")
        self.assertFalse(result["complete_command1"])
        self.assertFalse(result["TPM_coherent_running_snapshot_proven"])
        self.assertEqual(writes[0][0],"started")
        self.assertTrue(writes[0][3])
        self.assertEqual(writes[-1][2],seq.PHASES)
        self.assertEqual(writes[-1][0],"exact_cold_master_staged_only")
        child_args=run.call_args.args[0]
        self.assertEqual(child_args.receipt_dir,self.handoff)
        self.assertEqual(self.args.receipt_dir,self.receipts)

    def test_resume_existing_base_stages_source_without_new_apt(self):
        self.args.use_active_base=True
        ordered=[]
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",
                                                 return_value=seq.APPROVAL))
            st.enter_context(mock.patch.object(
                seq.master,"private_receipt_dir",return_value=self.receipts))
            st.enter_context(mock.patch.object(seq.master,"durable_receipt"))
            st.enter_context(mock.patch.object(
                seq.master,"inputs",return_value={"host_modified":False}))
            st.enter_context(mock.patch.object(seq.sealed_base,"attest",
                return_value={"transaction_id":"a"*32}))
            staged=st.enter_context(mock.patch.object(
                seq.cape_source,"install",side_effect=lambda *args:(
                    ordered.append("source") or {
                        "result":"COMMAND1_CAPE_PINNED_SOURCE_STAGED_ONLY"})))
            block=st.enter_context(mock.patch.object(
                seq.base,"apply",side_effect=AssertionError(
                    "never create a second APT transaction")))
            st.enter_context(mock.patch.object(
                seq.master,"execute",side_effect=lambda *args:(
                    ordered.append("master") or {
                        "master_imported_shut_off":True,
                        "guest_started":False})))
            out=seq.execute(self.args)
        self.assertEqual(ordered,["source","master"])
        self.assertEqual(out["tracked_transaction"],"a"*32)
        block.assert_not_called()
        staged.assert_called_once_with(
            self.args.approved_host,"a"*32,self.args.cape_revision)

    def test_resume_declined_approval_does_not_stage_source(self):
        self.args.use_active_base=True
        with mock.patch.object(seq.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(seq,"preflight",return_value=self.plan), \
             mock.patch("builtins.input",return_value="NO"), \
             mock.patch.object(seq.cape_source,"install") as stage:
            with self.assertRaises(seq.IntegratedBlocked):
                seq.execute(self.args)
        stage.assert_not_called()

    def test_optional_rootless_runtime_executes_in_middle_with_receipt(self):
        for key in seq.RUNTIME_FIELDS:
            setattr(self.args,key,("a"*64 if "sha256" in key
                                   else self.path/key))
        ordered=[]
        records=[]
        source_tx="e"*32
        def log(path,doc,**kwargs):
            records.append({
                "current":doc["current"],"phase":doc["phase"],
                "finished":list(doc["finished"]),
                "transaction_id":doc.get("transaction_id"),
                "packages":doc.get("rootless_python_runtime_packages"),
            })
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",
                                                 return_value=seq.APPROVAL))
            st.enter_context(mock.patch.object(
                seq.master,"private_receipt_dir",return_value=self.receipts))
            st.enter_context(mock.patch.object(
                seq.master,"durable_receipt",side_effect=log))
            st.enter_context(mock.patch.object(
                seq.master,"inputs",return_value={"host_modified":False}))
            st.enter_context(mock.patch.object(seq.base,"apply",
                side_effect=lambda *args:(
                    ordered.append("base") or {
                        "exact_public_source_staged":True,
                        "transaction_id":source_tx})))
            rootless=st.enter_context(mock.patch.object(seq.runtime,"apply",
                side_effect=lambda *args:(
                    ordered.append("runtime") or {
                        "result":"CAPE_ROOTLESS_OFFLINE_PY312_RUNTIME_INSTALLED",
                        "transaction":source_tx,
                        "packages":170,
                        "runtime":"/opt/cape-deployment-runtime/venv"})))
            master_exec=st.enter_context(mock.patch.object(
                seq.master,"execute",side_effect=lambda *args:(
                    ordered.append("master") or {
                        "master_imported_shut_off":True,
                        "guest_started":False})))
            result=seq.execute(self.args)
        self.assertEqual(ordered,["base","runtime","master"])
        self.assertTrue(result["rootless_cape_python_runtime_installed"])
        self.assertEqual(result["rootless_python_packages_installed"],170)
        self.assertEqual(records[-1]["finished"],list(seq.phases_for(self.args)))
        self.assertEqual(records[-1]["packages"],170)
        self.assertEqual(rootless.call_args.args[0],self.args.approved_host)
        self.assertEqual(rootless.call_args.args[1],source_tx)
        master_exec.assert_called_once()

    def test_runtime_failure_halts_before_private_master_import(self):
        for key in seq.RUNTIME_FIELDS:
            setattr(self.args,key,("b"*64 if "sha256" in key
                                   else self.path/key))
        records=[]
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",
                                                 return_value=seq.APPROVAL))
            st.enter_context(mock.patch.object(
                seq.master,"private_receipt_dir",return_value=self.receipts))
            st.enter_context(mock.patch.object(seq.master,"durable_receipt",
                side_effect=lambda path,doc,**kw:records.append(dict(doc))))
            st.enter_context(mock.patch.object(seq.base,"apply",
                return_value={"exact_public_source_staged":True,
                              "transaction_id":"e"*32}))
            st.enter_context(mock.patch.object(seq.runtime,"apply",
                side_effect=RuntimeError("synthetic rootless installer failure")))
            handoff=st.enter_context(mock.patch.object(seq.master,"execute"))
            with self.assertRaisesRegex(seq.IntegratedBlocked,"BEFORE retry"):
                seq.execute(self.args)
        handoff.assert_not_called()
        self.assertEqual(records[-1]["phase"],"PARTIAL_OR_UNKNOWN_STOP")
        self.assertEqual(records[-1]["current"],seq.RUNTIME_PHASE)
        self.assertEqual(records[-1]["finished"],[seq.PHASES[0]])
        self.assertEqual(records[-1]["transaction_id"],"e"*32)

    def test_partial_master_import_keeps_external_transaction_and_receipt(self):
        records=[]
        sequence=[]
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",
                                                 return_value=seq.APPROVAL))
            st.enter_context(mock.patch.object(
                seq.master,"private_receipt_dir",return_value=self.receipts))
            st.enter_context(mock.patch.object(
                seq.master,"durable_receipt",
                side_effect=lambda path,record,**kw: records.append(dict(record))))
            st.enter_context(mock.patch.object(seq.master,"inputs",
                                                 return_value={"host_modified":False}))
            st.enter_context(mock.patch.object(seq.base,"apply",
                return_value={"exact_public_source_staged":True,
                              "transaction_id":"f"*32}))
            st.enter_context(mock.patch.object(seq.master,"execute",
                side_effect=RuntimeError("SIMULATED_ONLY")))
            with self.assertRaisesRegex(seq.IntegratedBlocked,"BEFORE retry"):
                seq.execute(self.args)
        self.assertEqual(records[-1]["phase"],"PARTIAL_OR_UNKNOWN_STOP")
        self.assertEqual(records[-1]["current"],"private_exact_master_import")
        self.assertEqual(records[-1]["finished"],["tracked_host_and_cape_source"])
        self.assertEqual(records[-1]["transaction_id"],"f"*32)
        self.assertNotIn("service_account_private_key",str(records))
        self.assertNotIn("crypt_password",str(records))

    def test_declined_approval_causes_no_change(self):
        with ExitStack() as st:
            st.enter_context(mock.patch.object(seq.sys.stdin,"isatty",
                                                 return_value=True))
            st.enter_context(mock.patch.object(seq,"preflight",
                                                 return_value=self.plan))
            st.enter_context(mock.patch("builtins.input",return_value="no"))
            b=st.enter_context(mock.patch.object(seq.base,"apply"))
            m=st.enter_context(mock.patch.object(seq.master,"execute"))
            with self.assertRaises(seq.IntegratedBlocked):
                seq.execute(self.args)
        b.assert_not_called()
        m.assert_not_called()


if __name__=="__main__":
    unittest.main()
