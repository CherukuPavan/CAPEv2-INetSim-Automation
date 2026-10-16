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
