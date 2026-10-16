"""Synthetic benign 2-cycle VM restore tests; never launch a VM."""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command2_disposable_two_cycle_revert as m


HOST = "rakshati"
VM = "win11_1"
JOURNAL = Path("/private/journal")
COLD = Path("/private/cold")
SHA = "a" * 64
CHECKED = {
    "host": HOST, "vm": VM,
    "uuid": "12345678-1234-4234-8234-123456789abc",
    "guest_ip": "192.168.241.101",
    "subnet": "192.168.241.0/24",
    "snapshot": "cape_ready_win11_1",
    "reviewed_full_cold_recovery_manifest_sha256": SHA,
    "one_disposable_guest_shut_off": True,
    "host_nft_libvirt_isolation_structure_verified": True,
}
OK_REVERT = {
    "result": "COMMAND2_ONE_BENIGN_RUNNING_SNAPSHOT_REVERT_AGENT_REACHABLE",
    "guest_running_after_revert": True,
    "post_revert_agent_http_verified": True,
}


class TwoCycleTests(unittest.TestCase):
    def test_plan_readonly_and_does_not_certify_tpm(self):
        with mock.patch.object(m.once, "plan", return_value=CHECKED):
            result = m.plan(HOST, JOURNAL, VM, COLD, SHA)
        self.assertEqual(result["cycles_planned"], 2)
        self.assertFalse(result["TPM_UEFI_full_state_revert_proven"])
        self.assertFalse(result["safe_for_malware"])
        self.assertEqual(len(result["identity_sha256"]), 64)

    def test_isolation_failure_blocks_before_cycling(self):
        with mock.patch.object(m.once, "plan", return_value={
                **CHECKED, "host_nft_libvirt_isolation_structure_verified": False}):
            with self.assertRaises(m.TwoCycleBlocked):
                m.plan(HOST, JOURNAL, VM, COLD, SHA)

    def test_host_identity_drift_changes_fingerprint(self):
        with mock.patch.object(m.once, "plan", side_effect=[
                CHECKED, {**CHECKED, "uuid":
                    "22345678-1234-4234-8234-123456789abc"}]):
            original = m.plan(HOST, JOURNAL, VM, COLD, SHA)
            changed = m.plan(HOST, JOURNAL, VM, COLD, SHA)
        self.assertNotEqual(original["identity_sha256"],
                            changed["identity_sha256"])

    def test_graceful_shutdown_uses_only_shutdown_never_force(self):
        calls = []
        states = iter(["running", "running", "shut off"])
        def libvirt(*args):
            calls.append(args)
            if args[0] == "domstate":
                return next(states)
            return ""
        with mock.patch.object(m.once, "virsh", side_effect=libvirt), \
             mock.patch.object(m.time, "sleep"):
            self.assertTrue(m.shut_down_without_force(VM))
        self.assertEqual(calls, [
            ("domstate", VM), ("shutdown", VM),
            ("domstate", VM), ("domstate", VM)])
        self.assertFalse(any("destroy" in x for x in calls))

    def test_graceful_shutdown_timeout_fails_closed(self):
        with mock.patch.object(m.once, "virsh", return_value="running"), \
             mock.patch.object(m.time, "monotonic",
                               side_effect=[10.0, 71.0]), \
             mock.patch.object(m.time, "sleep"):
            with self.assertRaisesRegex(m.TwoCycleBlocked,
                                        "did not shut down"):
                m.shut_down_without_force(VM, timeout=60)

    def scenario(self, return_bad=False):
        stack = ExitStack()
        self.addCleanup(stack.close)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        calls, entries = [], []
        report = {"result": "COMMAND2_TWO_BENIGN_REVERT_PLAN_ONLY",
                  "identity_sha256": "b" * 64,
                  "host": HOST, "vm": VM,
                  "snapshot": "cape_ready_win11_1"}
        stack.enter_context(mock.patch.object(m.os, "geteuid",
                                               return_value=0))
        stack.enter_context(mock.patch.object(m.sys.stdin, "isatty",
                                               return_value=True))
        stack.enter_context(mock.patch.object(m, "plan",
                                               return_value=report))
        stack.enter_context(mock.patch.object(m, "witness_dir",
                                               return_value=Path(tmp.name)))
        stack.enter_context(mock.patch.object(m, "lock", return_value=45))
        stack.enter_context(mock.patch.object(m.os, "close"))
        stack.enter_context(mock.patch.object(
            m, "write_receipt",
            side_effect=lambda file, doc, initial=False:
                entries.append((initial, doc["in_progress"],
                                doc["result"], len(doc["cycles"])))))
        stack.enter_context(mock.patch(
            "builtins.input",
            return_value="TWO-BENIGN-RESTORES-WIN11_1"))
        def revert(*args):
            calls.append("revert")
            if return_bad and len([x for x in calls if x == "revert"]) == 2:
                raise m.once.RevertBlocked("Injected second revert failure")
            return OK_REVERT
        stack.enter_context(mock.patch.object(m.once, "revert_once",
                                               side_effect=revert))
        stack.enter_context(mock.patch.object(
            m, "shut_down_without_force",
            side_effect=lambda vm: calls.append("shutdown") or True))
        return calls, entries

    def test_executes_two_real_reverts_and_two_clean_shutdowns(self):
        calls, entries = self.scenario()
        report = m.run(HOST, JOURNAL, VM, COLD, SHA, Path("/fake/private"))
        self.assertEqual(calls, ["revert", "shutdown",
                                 "revert", "shutdown"])
        self.assertEqual(report["real_benign_running_revert_cycles_verified"], 2)
        self.assertTrue(report["guest_off_final"])
        self.assertFalse(report["production_ready"])
        self.assertFalse(report["TPM_UEFI_full_state_revert_proven"])
        self.assertEqual(entries[-1][2],
                         "TWO_BENIGN_REVERT_CYCLES_AGENT_ONLY_VERIFIED")

    def test_disk_marker_challenge_seeds_then_reverts_both_mutations(self):
        calls, entries = self.scenario()
        with mock.patch.object(m, "seed_marker_from_stopped_guest",
                               side_effect=lambda *a: calls.append("seed") or True) as seed, \
             mock.patch.object(m.marker, "read_marker",
                               side_effect=[False, True, False]) as reader, \
             mock.patch.object(m.marker, "create_marker",
                               side_effect=lambda *a: calls.append("mark") or True):
            result = m.run(HOST, JOURNAL, VM, COLD, SHA,
                           Path("/fake/private"), prove_disk_marker=True)
        self.assertEqual(calls, ["seed", "revert", "mark", "shutdown",
                                 "revert", "shutdown"])
        self.assertTrue(result["disk_mutation_rollback_proven"])
        self.assertFalse(result["TPM_UEFI_full_state_revert_proven"])
        seed.assert_called_once()
        self.assertEqual(reader.call_count, 3)
        self.assertEqual(entries[-1][2],
                         "TWO_BENIGN_REVERT_CYCLES_AGENT_ONLY_VERIFIED")

    def test_disk_marker_surviving_first_revert_stops_without_next_cycle(self):
        calls, entries = self.scenario()
        with mock.patch.object(m, "seed_marker_from_stopped_guest",
                               return_value=True), \
             mock.patch.object(m.marker, "read_marker", return_value=True):
            with self.assertRaises(m.TwoCycleBlocked):
                m.run(HOST, JOURNAL, VM, COLD, SHA,
                      Path("/fake/private"), prove_disk_marker=True)
        self.assertEqual(calls, ["revert"])
        self.assertEqual(entries[-1][2], "TWO_CYCLE_PARTIAL_OR_UNKNOWN")

    def test_marker_initial_boot_never_forces_guest_shutdown(self):
        states = iter(["shut off", "running"])
        def virsh(*args):
            if args[0] == "domstate":
                return next(states)
            return ""
        with mock.patch.object(m.once, "virsh", side_effect=virsh) as virsh, \
             mock.patch.object(m, "wait_agent_after_boot", return_value=True), \
             mock.patch.object(m.marker, "read_marker",
                               side_effect=[False, True]), \
             mock.patch.object(m.marker, "create_marker", return_value=True), \
             mock.patch.object(m, "shut_down_without_force", return_value=True):
            self.assertTrue(m.seed_marker_from_stopped_guest(
                VM, "192.168.241.101", "192.168.241.1"))
        self.assertIn(mock.call("start", VM), virsh.call_args_list)
        self.assertNotIn(mock.call("destroy", VM), virsh.call_args_list)

    def test_failure_on_cycle_two_keeps_one_completed_and_partial_state(self):
        calls, entries = self.scenario(return_bad=True)
        with self.assertRaisesRegex(m.TwoCycleBlocked, "Incomplete cycle"):
            m.run(HOST, JOURNAL, VM, COLD, SHA, Path("/fake/private"))
        self.assertEqual(calls, ["revert", "shutdown", "revert"])
        self.assertEqual(entries[-1][2], "TWO_CYCLE_PARTIAL_OR_UNKNOWN")
        self.assertEqual(entries[-1][3], 1)

    def test_noninteractive_refused_before_even_planning(self):
        with mock.patch.object(m.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(m.os, "geteuid", return_value=0), \
             mock.patch.object(m, "plan",
                               side_effect=AssertionError("must not plan")):
            with self.assertRaises(m.TwoCycleBlocked):
                m.run(HOST, JOURNAL, VM, COLD, SHA, Path("/fake/private"))

    def test_root_private_record_never_pretends_uefi_tpm_proof(self):
        source = Path(m.__file__).read_text()
        self.assertIn('TPM_UEFI_full_state_revert_proven": False', source)
        self.assertIn('no_auto_retry_or_guest_cleanup', source)
        self.assertNotIn('virsh("destroy"', source)
        self.assertNotIn('virsh("snapshot-create"', source)


if __name__ == "__main__":
    unittest.main()
