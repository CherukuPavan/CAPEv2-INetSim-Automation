"""Synthetic orchestration safety tests; never access Google Drive or VM."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command1_private_master_handoff_sequence as h


class PrivateHandoffTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.args = SimpleNamespace(
            approved_host="target-lab",
            service_account_file=self.root / "service.json",
            shared_parent_folder_id="A" * 20,
            crypt_subfolder="master-backups",
            config=self.root / "cape_reader.conf",
            bundle_id="cape-master-SSL55-20261013-lan01",
            bundle_destination=self.root / "master-bundle",
            os_disk=self.root / "master.qcow2",
            uefi_vars=self.root / "master_VARS.fd",
            swtpm_user="libvirt-qemu",
            receipt_dir=self.root / "receipts",
        )
        self.args.receipt_dir.mkdir()
        self.plan = {
            "result": "COMMAND1_PRIVATE_MASTER_HANDOFF_PREFLIGHT",
            "approved_host": "target-lab",
            "host_modified": False,
        }

    def test_exact_internal_steps_and_one_operator_invocation(self):
        self.assertEqual(h.STAGES, (
            "restricted_reader", "encrypted_master_download", "cold_master_import"))
        self.assertEqual(set(h.CHILD), set(h.STAGES))
        cases = {
            "restricted_reader": (
                "--mode", "setup",
                "--service-account-file", str(self.args.service_account_file),
                "--shared-parent-folder-id", "A"*20,
                "--config", str(self.args.config)),
            "encrypted_master_download": (
                "--mode", "download", "--crypt-remote", "cape_crypt",
                "--bundle-id", self.args.bundle_id,
                "--destination", str(self.args.bundle_destination)),
            "cold_master_import": (
                "--mode", "stage", "--swtpm-user", "libvirt-qemu",
                "--bundle", str(self.args.bundle_destination),
                "--os-disk", str(self.args.os_disk)),
        }
        for step, required in cases.items():
            argv = h.child_argv(self.args, step)
            self.assertEqual(argv[:2], [h.sys.executable, "-B"])
            self.assertIn("--approved-host", argv)
            self.assertIn(self.args.approved_host, argv)
            for component in required:
                self.assertIn(component, argv)
        with self.assertRaises(h.HandoffBlocked):
            h.child_argv(self.args, "unreviewed-shell-command")

    def test_preflight_fails_if_crypt_config_would_overwrite(self):
        self.args.config.write_text("unrelated user settings")
        with mock.patch.object(h.os, "geteuid", return_value=0), \
             mock.patch.object(h, "admitted_host"), \
             mock.patch.object(h.reader, "verify_inputs",
                               side_effect=h.reader.ReaderBlocked("Existing config")):
            with self.assertRaises(h.reader.ReaderBlocked):
                h.inputs(self.args)
        self.assertEqual(self.args.config.read_text(), "unrelated user settings")

    def test_executor_success_retains_final_shutoff_proof_only(self):
        receipts = []
        steps = []
        def write(target, state, *, first=False):
            receipts.append((state["phase"], state["current_stage"],
                             tuple(state["finished"]), first))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(h.sys.stdin, "isatty",
                                                  return_value=True))
            stack.enter_context(mock.patch.object(
                h, "inputs", return_value=self.plan))
            stack.enter_context(mock.patch("builtins.input",
                return_value=h.APPROVAL))
            stack.enter_context(mock.patch.object(
                h, "private_receipt_dir", return_value=self.args.receipt_dir))
            stack.enter_context(mock.patch.object(
                h, "durable_receipt", side_effect=write))
            runner = stack.enter_context(mock.patch.object(
                h, "invoke", side_effect=lambda argv:
                steps.append(Path(argv[2]).name) or 0))
            out = h.execute(self.args)
        self.assertEqual(steps, [h.CHILD[x] for x in h.STAGES])
        self.assertEqual(out["result"],
                         "COMMAND1_VERIFIED_PRIVATE_COLD_MASTER_STAGED_ONLY")
        self.assertFalse(out["complete_command1"])
        self.assertFalse(out["TPM_coherent_running_snapshot_verified"])
        self.assertFalse(out["CAPE_ready"])
        self.assertEqual(receipts[-1][0], "cold_master_staged_not_booted")
        self.assertEqual(receipts[-1][2], h.STAGES)
        self.assertTrue(receipts[0][3])

    def test_second_step_failure_keeps_partial_receipt_no_retries(self):
        states = []
        runner = mock.Mock(side_effect=[0, 2])
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(h.sys.stdin,"isatty",
                                                  return_value=True))
            stack.enter_context(mock.patch.object(h,"inputs",return_value=self.plan))
            stack.enter_context(mock.patch("builtins.input",return_value=h.APPROVAL))
            stack.enter_context(mock.patch.object(
                h,"private_receipt_dir",return_value=self.args.receipt_dir))
            stack.enter_context(mock.patch.object(
                h,"durable_receipt",
                side_effect=lambda p,d,**kw: states.append(dict(d))))
            stack.enter_context(mock.patch.object(h,"invoke",runner))
            with self.assertRaisesRegex(h.HandoffBlocked,
                                        "DO NOT blindly retry"):
                h.execute(self.args)
        self.assertEqual(runner.call_count,2)
        self.assertEqual(states[-1]["phase"],"partial_or_unknown")
        self.assertEqual(states[-1]["current_stage"],"encrypted_master_download")
        self.assertEqual(states[-1]["finished"],["restricted_reader"])
        self.assertEqual(states[-1]["last_exit_code"],2)
        self.assertNotIn("crypt_password",str(states))
        self.assertNotIn("service_account_private_key",str(states))

    def test_declined_approval_never_starts_credential_or_vm_action(self):
        with mock.patch.object(h.sys.stdin,"isatty",return_value=True), \
             mock.patch.object(h,"inputs",return_value=self.plan), \
             mock.patch("builtins.input",return_value="NO"), \
             mock.patch.object(h,"invoke") as run:
            with self.assertRaises(h.HandoffBlocked):
                h.execute(self.args)
            run.assert_not_called()

    def test_source_has_no_auto_vm_start_or_unsafe_shell(self):
        source=Path(h.__file__).read_text()
        for forbidden in (
                "virsh start", "virsh destroy", "snapshot-revert",
                "systemctl restart", "shell=True", "os.system("):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
