"""Read-only tests for all-domain quiescence, identity and state races."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

import command123_libvirt_quiescence as q

UUID1 = "289d89be-68ec-4c62-90e1-ea930849266f"
UUID2 = "11111111-2222-3333-4444-555555555555"
UUID3 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class LibvirtQuiescenceTests(TestCase):
    def test_no_domains_allows_recovery_after_three_inventories(self):
        with patch.object(q, "read_virsh", return_value="") as call:
            doc = q.no_nonshutoff_domains()
        self.assertEqual(doc["defined_domain_count"], 0)
        self.assertTrue(doc["only_shutoff_domains_observed"])
        self.assertTrue(doc["domain_uuid_verified_twice"])
        self.assertTrue(doc["domain_state_verified_twice"])
        self.assertFalse(doc["not_an_exclusive_libvirt_lock"] is False)
        self.assertEqual(call.call_count, 3)

    def test_multiple_shutoff_domains_are_repeatedly_inspected(self):
        seen = []
        def tool(*args):
            seen.append(args)
            if args == ("list", "--all", "--name"):
                return "win11_2\nwin11\n"
            if args == ("domuuid", "win11"):
                return UUID1 + "\n"
            if args == ("domuuid", "win11_2"):
                return UUID2 + "\n"
            if args[:1] == ("domstate",):
                return "shut off\n"
            raise AssertionError(args)
        with patch.object(q, "read_virsh", side_effect=tool):
            report = q.no_nonshutoff_domains()
        self.assertEqual(report["defined_domain_count"], 2)
        one = [("domuuid", "win11"), ("domstate", "win11"),
               ("domuuid", "win11_2"), ("domstate", "win11_2")]
        self.assertEqual(seen,
             [("list", "--all", "--name"), *one,
              ("list", "--all", "--name"), *one,
              ("list", "--all", "--name")])

    def test_paused_suspended_running_crashed_and_unknown_are_blocked(self):
        for state in ("paused", "pmsuspended", "running", "crashed",
                      "in shutdown", "idle", "unknown", "shut off (saved)"):
            with self.subTest(state=state):
                events = ["win11_1\n", UUID1+"\n", state+"\n"]
                with patch.object(q, "read_virsh",
                                  side_effect=events) as tool:
                    with self.assertRaisesRegex(
                            q.QuiescenceBlocked, "live, paused, suspended"):
                        q.no_nonshutoff_domains()
                self.assertEqual(tool.call_count, 3)

    def test_transient_guest_start_between_two_scans_is_blocked(self):
        events = ["win11\n", UUID1+"\n", "shut off\n",
                  "win11\n", UUID1+"\n", "running\n"]
        with patch.object(q, "read_virsh", side_effect=events):
            with self.assertRaisesRegex(
                    q.QuiescenceBlocked, "live, paused, suspended"):
                q.no_nonshutoff_domains()

    def test_same_named_guest_replaced_by_different_uuid_is_blocked(self):
        events = ["win11\n", UUID1+"\n", "shut off\n",
                  "win11\n", UUID3+"\n", "shut off\n"]
        with patch.object(q, "read_virsh", side_effect=events):
            with self.assertRaisesRegex(
                    q.QuiescenceBlocked, "identity replaced"):
                q.no_nonshutoff_domains()

    def test_new_domain_appears_between_state_scans(self):
        events = ["win11\n", UUID1+"\n", "shut off\n",
                  "win11\nwin11_1\n"]
        with patch.object(q, "read_virsh", side_effect=events):
            with self.assertRaisesRegex(
                    q.QuiescenceBlocked, "inventory drift"):
                q.no_nonshutoff_domains()

    def test_duplicate_domain_name_or_identity_is_refused(self):
        with patch.object(q, "read_virsh", return_value="win11\nwin11\n"):
            with self.assertRaisesRegex(q.QuiescenceBlocked, "duplicate"):
                q.no_nonshutoff_domains()
        events = ["win11\nwin11_2\n", UUID1+"\n", "shut off\n",
                  UUID1+"\n"]
        with patch.object(q, "read_virsh", side_effect=events):
            with self.assertRaisesRegex(
                    q.QuiescenceBlocked, "share one UUID"):
                q.no_nonshutoff_domains()

    def test_unverified_domain_uuid_is_refused_before_state(self):
        with patch.object(q, "read_virsh",
                          side_effect=["win11\n", "invalid\n"]) as call:
            with self.assertRaisesRegex(
                    q.QuiescenceBlocked, "UUID absent or invalid"):
                q.no_nonshutoff_domains()
        self.assertEqual(call.call_count, 2)

    def test_virsh_failure_and_timeout_block_recovery(self):
        with patch.object(q.subprocess, "run", return_value=SimpleNamespace(
                returncode=1, stdout="")):
            with self.assertRaisesRegex(q.QuiescenceBlocked, "inventory"):
                q.no_nonshutoff_domains()
        from subprocess import TimeoutExpired
        with patch.object(q.subprocess, "run", side_effect=TimeoutExpired(
                cmd=["virsh"], timeout=1)):
            with self.assertRaisesRegex(q.QuiescenceBlocked, "inspect"):
                q.no_nonshutoff_domains()

    def test_all_actions_are_read_only_list_domid_and_state(self):
        calls = []
        def runner(argv, **_):
            calls.append(argv)
            if "list" in argv:
                return SimpleNamespace(returncode=0, stdout="win11\n")
            if "domuuid" in argv:
                return SimpleNamespace(returncode=0, stdout=UUID1+"\n")
            return SimpleNamespace(returncode=0, stdout="shut off\n")
        with patch.object(q.subprocess, "run", side_effect=runner):
            q.no_nonshutoff_domains()
        self.assertEqual(calls, [
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
            ["virsh", "-c", "qemu:///system", "domuuid", "win11"],
            ["virsh", "-c", "qemu:///system", "domstate", "win11"],
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
            ["virsh", "-c", "qemu:///system", "domuuid", "win11"],
            ["virsh", "-c", "qemu:///system", "domstate", "win11"],
            ["virsh", "-c", "qemu:///system", "list", "--all", "--name"],
        ])
        for argv in calls:
            for forbidden in ("start", "destroy", "undefine",
                              "snapshot-revert", "domreset"):
                self.assertNotIn(forbidden, argv)


if __name__ == "__main__":
    main()
