"""Synthetic tracked APT regression: no actual package or host modifications."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command123_tracked_prereqs as a
import command123_deployment_transaction as tx


class TrackedAPTTests(unittest.TestCase):
    def test_exact_supported_lts_host_versions_for_base_apt_only(self):
        for release in ("24.04", "26.04"):
            with self.subTest(release=release), \
                 mock.patch.object(a.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(Path, "read_text", return_value=(
                     'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="'+release+'"\n')):
                self.assertEqual(a.verify_host(), release)
        for release in ("22.04", "25.10", "26.10", "99.99"):
            with self.subTest(release=release), \
                 mock.patch.object(a.platform, "machine", return_value="x86_64"), \
                 mock.patch.object(Path, "read_text", return_value=(
                     'ID=ubuntu\nVERSION_ID="'+release+'"\n')):
                with self.assertRaises(tx.TransactionBlocked):
                    a.verify_host()
        with mock.patch.object(a.platform, "machine", return_value="aarch64"), \
             mock.patch.object(Path, "read_text",
                               return_value='ID=ubuntu\nVERSION_ID=26.04\n'):
            with self.assertRaises(tx.TransactionBlocked):
                a.verify_host()

    def test_shadowed_custom_hypervisor_prevents_apt_plan(self):
        for name in ("qemu-img", "qemu-system-x86_64", "virsh", "swtpm"):
            with self.subTest(name=name):
                def pretend(binary):
                    return "/usr/local/bin/" + binary if binary == name else None
                with mock.patch.object(a.shutil, "which", side_effect=pretend):
                    with self.assertRaisesRegex(
                            tx.TransactionBlocked, "External or shadowed"):
                        a.no_shadowed_virtualization_executables()

    def test_missing_hypervisor_binaries_can_be_staged_from_signed_apt(self):
        with mock.patch.object(a.shutil, "which", return_value=None):
            observed = a.no_shadowed_virtualization_executables()
        self.assertTrue(observed)
        self.assertTrue(all(value is None for value in observed.values()))

    def test_resolute_plan_includes_official_version_gated_virt_packages(self):
        baseline = {"dpkg": "1", "git": "2"}
        fake = {"running_snapshot_stack_versions_admitted": True}
        with mock.patch.object(a, "verify_host", return_value="26.04"), \
             mock.patch.object(a, "no_shadowed_virtualization_executables"), \
             mock.patch.object(a, "installed", return_value=baseline), \
             mock.patch.object(a.hypervisor, "plan", return_value=fake) as candidates, \
             mock.patch.object(a, "simulate",
                 side_effect=lambda names, **kwargs: list(names)) as simulate:
            result=a.plan()
        self.assertTrue(result["resolute_virt26_binaries_in_scope"])
        self.assertTrue(result["qemu_libvirt_candidate_versions_admitted"])
        self.assertTrue(set(a.VIRT26) <= set(result["requested_missing"]))
        self.assertFalse(result["snapshot_stack_authorized"])
        self.assertIn("qemu-system-x86", result["requested_missing"])
        self.assertIn("rclone", result["requested_missing"])
        candidates.assert_called_once()
        simulate.assert_called_once()

    def test_resolute_plan_refuses_old_or_unavailable_hypervisor(self):
        for witness in ({"running_snapshot_stack_versions_admitted": False},
                        a.hypervisor.ReleaseBlocked("no signed policy")):
            with self.subTest(witness=repr(witness)), \
                 mock.patch.object(a, "verify_host", return_value="26.04"), \
                 mock.patch.object(a, "no_shadowed_virtualization_executables"), \
                 mock.patch.object(a, "installed") as inventory:
                with mock.patch.object(
                    a.hypervisor, "plan",
                    side_effect=witness if isinstance(witness, Exception)
                    else None, return_value=witness if isinstance(witness, dict)
                    else None):
                    with self.assertRaises(tx.TransactionBlocked):
                        a.plan()
                inventory.assert_not_called()

    def test_noble_plan_remains_exact_old_seven_base_packages(self):
        with mock.patch.object(a,"verify_host",return_value="24.04"), \
             mock.patch.object(a,"installed",return_value={"dpkg":"1"}), \
             mock.patch.object(a,"simulate",
                 side_effect=lambda names:list(names)), \
             mock.patch.object(a.hypervisor,"plan") as newer:
            result=a.plan()
        self.assertFalse(result["resolute_virt26_binaries_in_scope"])
        self.assertEqual(set(result["requested_missing"]), set(a.BASE))
        self.assertFalse(result["qemu_libvirt_candidate_versions_admitted"])
        newer.assert_not_called()

    def test_delta_attributes_all_transitive_new_packages(self):
        changed = a.delta(
            {"dpkg": "1", "python3": "3.12"},
            {"dpkg": "1", "python3": "3.12", "python3-pip": "1",
             "python3-wheel": "2"},
            ["python3-pip", "python3-wheel"])
        self.assertEqual(changed["new_packages"],
                         {"python3-pip": "1", "python3-wheel": "2"})
        self.assertEqual(changed["preexisting_changed"], {})
        self.assertEqual(changed["preexisting_removed"], {})
        self.assertEqual(changed["unplanned_additions"], [])

    def test_delta_detects_package_replacement(self):
        result = a.delta({"dpkg": "1", "git": "2"},
                         {"dpkg": "1", "git": "3", "new": "1"},
                         ["git"])
        self.assertIn("git", result["preexisting_changed"])
        self.assertEqual(result["unplanned_additions"], ["new"])

    def test_simulation_rejects_apparent_removals(self):
        with mock.patch.object(a, "read_command", return_value=(
                "Inst python3-pip (1 Ubuntu:24.04)\n"
                "Remv unattended-upgrades [1]\n")):
            with self.assertRaises(tx.TransactionBlocked):
                a.simulate(["python3-pip"])

    def test_simulation_accepts_expected_install_output(self):
        with mock.patch.object(a, "read_command", return_value=(
                "Inst python3-pip (1 Ubuntu:24.04)\n"
                "Inst python3-wheel (2 Ubuntu:24.04)\n")):
            self.assertEqual(a.simulate(["python3-pip"]),
                             ["python3-pip", "python3-wheel"])

    def test_simulation_rejects_unknown_package(self):
        with self.assertRaises(tx.TransactionBlocked):
            a.simulate(["qemu-system-x86"])

    def test_plan_rejects_apt_upgrade_of_existing_package(self):
        with mock.patch.object(a, "verify_host"), \
             mock.patch.object(a, "installed", return_value={
                 "dpkg": "1", "python3": "1", "git": "2"}), \
             mock.patch.object(a, "simulate", return_value=["git"]):
            with self.assertRaises(tx.TransactionBlocked):
                a.plan()

    def run_apply(self, before, after, proc_status=0):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        path = home / "ledger.json"
        path.write_text("{}")
        doc = {"phase": "active", "entries": []}
        saved = []
        proposal = {"result": "CAPE_BASE_APT_REVIEW_ONLY",
                    "requested_missing": ["python3-pip"],
                    "simulated_installations": ["python3-pip", "python3-wheel"],
                    "installed_package_count": len(before),
                    "baseline_inventory_sha256": __import__("hashlib").sha256(
                        a.snap_bytes(before)).hexdigest(),
                    "host_modified": False, "snapshot_stack_authorized": False}
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(a.os, "geteuid",
                                               return_value=0))
        stack.enter_context(mock.patch.object(a.sys.stdin, "isatty",
                                               return_value=True))
        stack.enter_context(mock.patch.object(tx, "host_guard",
                                               return_value="rakshati"))
        stack.enter_context(mock.patch.object(
            tx, "exclusive_transaction_lock", return_value=nullcontext()))
        stack.enter_context(mock.patch.object(tx, "load",
                                               return_value=(path, doc)))
        stack.enter_context(mock.patch.object(a, "plan", return_value=proposal))
        stack.enter_context(mock.patch.object(a, "installed",
                                               side_effect=[before, after]))
        stack.enter_context(mock.patch(
            "builtins.input",
            return_value="INSTALL-TRACKED-CAPE-BASE-PREREQUISITES"))
        def copy(folder, name, data):
            (folder / name).write_bytes(data)
        stack.enter_context(mock.patch.object(tx, "private_copy",
                                               side_effect=copy))
        stack.enter_context(mock.patch.object(tx, "atomic_receipt",
            side_effect=lambda path, data: saved.append(deepcopy(data))))
        runner = stack.enter_context(mock.patch.object(
            a.subprocess, "run",
            return_value=SimpleNamespace(returncode=proc_status)))
        return doc, saved, runner, home

    def test_success_seals_before_and_after(self):
        doc, saved, runner, home = self.run_apply(
            {"dpkg": "1"}, {"dpkg": "1", "python3-pip": "1",
                           "python3-wheel": "2"})
        result = a.apply("a" * 32, "rakshati")
        self.assertEqual(result["result"], "CAPE_BASE_APT_INSTALLED_AND_PROVEN")
        self.assertEqual(doc["entries"][0]["status"], "sealed")
        self.assertEqual(saved[0]["entries"][0]["status"], "prepared")
        self.assertEqual(saved[-1]["entries"][0]["status"], "sealed")
        self.assertTrue(list(home.glob("apt-before-*")))
        self.assertTrue(list(home.glob("apt-after-*")))
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(runner.call_args.args[0][:3],
                         ["apt-get", "install", "-y"])

    def test_partial_apt_exit_is_durable_and_blocks_retry(self):
        doc, saved, _, _ = self.run_apply(
            {"dpkg": "1"},
            {"dpkg": "1", "python3-pip": "1"}, proc_status=100)
        with self.assertRaises(tx.TransactionBlocked):
            a.apply("a" * 32, "rakshati")
        self.assertEqual(doc["entries"][0]["status"],
                         "PARTIAL_OR_UNEXPECTED_NO_AUTO_RETRY")
        self.assertEqual(saved[-1]["entries"][0]["apt_exit_code"], 100)
        with self.assertRaises(tx.TransactionBlocked):
            a.apply("a" * 32, "rakshati")

    def test_unexpected_or_upgraded_package_halts(self):
        doc, saved, _, _ = self.run_apply(
            {"dpkg": "1", "git": "1"},
            {"dpkg": "1", "git": "2", "python3-pip": "1",
             "mystery": "9"})
        with self.assertRaises(tx.TransactionBlocked):
            a.apply("a" * 32, "rakshati")
        self.assertEqual(doc["entries"][0]["status"],
                         "PARTIAL_OR_UNEXPECTED_NO_AUTO_RETRY")
        self.assertIn("git", saved[-1]["entries"][0]
                      ["observed_change"]["preexisting_changed"])

    def test_inventory_drift_after_consent_blocks_before_mutation(self):
        old = {"dpkg": "1", "git": "2"}
        changed = {"dpkg": "1", "git": "3"}
        doc, saved, runner, home = self.run_apply(old, old)
        # The plan was approved for the original state, but dpkg reports
        # same number of packages with a changed version just before apt.
        with mock.patch.object(a, "installed", return_value=changed):
            with self.assertRaises(__import__(
                    "command123_deployment_transaction"
                ).TransactionBlocked):
                a.apply("a" * 32, "rakshati")
        self.assertEqual(saved, [])
        runner.assert_not_called()

    def test_refuses_missing_interactive_root(self):
        with mock.patch.object(a.os, "geteuid", return_value=1000):
            with self.assertRaises(tx.TransactionBlocked):
                a.apply("a" * 32, "rakshati")


if __name__ == "__main__":
    unittest.main()
