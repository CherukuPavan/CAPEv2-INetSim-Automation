"""No-write release gate regressions, including Ubuntu 24.04 APT mismatch."""
import unittest
from unittest import mock
from types import SimpleNamespace

import command123_hypervisor_release_compat as g


class ReleaseSnapshotVersionsTests(unittest.TestCase):
    def test_noble_2404_candidates_block_before_install(self):
        report = g.candidate_matrix({
            "qemu-system-x86": "1:8.2.2+ds-0ubuntu1.16",
            "libvirt-daemon-system": "10.0.0-2ubuntu8.19",
        })
        self.assertEqual(
            report["result"], "COMMAND123_HYPERVISOR_RELEASE_CANDIDATES_BLOCKED")
        self.assertEqual(len(report["blockers"]), 2)
        self.assertFalse(report["running_snapshot_stack_versions_admitted"])
        self.assertFalse(report["safe_to_autoinstall_for_full_snapshot_contract"])
        self.assertFalse(report["VMs_modified"])

    def test_supported_version_is_only_a_gate_not_physical_proof(self):
        report = g.candidate_matrix({
            "qemu-system-x86": "1:9.2.3-0ubuntu1",
            "libvirt-daemon-system": "10.10.0-5ubuntu1",
        })
        self.assertTrue(report["running_snapshot_stack_versions_admitted"])
        self.assertEqual(report["result"],
                         "COMMAND123_HYPERVISOR_RELEASE_VERSIONS_OK_SOURCE_UNVERIFIED")
        self.assertFalse(report["snapshot_stack_package_provenance_approved"])
        self.assertFalse(report["safe_to_autoinstall_for_full_snapshot_contract"])
        self.assertIn("PINNED_COMPATIBLE_HYPERVISOR_SOURCE_NOT_IMPLEMENTED",
                      report["release_blockers"])
        self.assertFalse(report["cold_windows_boot_proven"])
        self.assertFalse(report["swtpm_restore_consistency_proven"])
        self.assertFalse(report["CAPE_three_commands_ready"])

    def test_versions_and_epoch(self):
        self.assertEqual(g.parse_deb_version("1:8.2.2+ds-0ubuntu1.16"),
                         (8, 2, 2))
        self.assertEqual(g.parse_deb_version("10.10.0-3"),
                         (10, 10, 0))
        with self.assertRaises(g.ReleaseBlocked):
            g.parse_deb_version("(none)")

    def test_reject_prerelease_and_upstream_downgrade_packages(self):
        # Debian ~rc is older than GA; +really can denote older upstream.
        for candidate in ("1:9.0.0~rc1-1",
                          "9.0.0+really8.2.2-1",
                          "10.10.0~rc2-1",
                          "10.10.0+really10.0.0-2"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(g.ReleaseBlocked):
                    g.parse_deb_version(candidate)
        self.assertEqual(g.parse_deb_version("1:9.1.0+ds-1ubuntu2"),
                         (9, 1, 0))

    def test_no_candidate_is_fail_closed(self):
        with self.assertRaises(g.ReleaseBlocked):
            g.policy_candidate("Installed: (none)\nCandidate: (none)\n")

    def test_policy_read_only_argv_and_timeout(self):
        mocked = SimpleNamespace(
            returncode=0,
            stdout="qemu-system-x86:\n  Installed: (none)\n"
                   "  Candidate: 1:8.2.2+ds-0ubuntu1.16\n")
        with mock.patch.object(g.subprocess, "run",
                               return_value=mocked) as run:
            actual = g.read_policy("qemu-system-x86")
        self.assertEqual(actual, "1:8.2.2+ds-0ubuntu1.16")
        self.assertEqual(run.call_args.args[0],
                         ["apt-cache", "policy", "qemu-system-x86"])
        with self.assertRaises(g.ReleaseBlocked):
            g.read_policy("unknown")

    def test_missing_package_blocks_release(self):
        with self.assertRaises(g.ReleaseBlocked):
            g.candidate_matrix({"qemu-system-x86": "9.0.0"})

    @mock.patch.object(g.platform, "machine", return_value="x86_64")
    def test_live_apt_gate_without_install(self, _):
        with mock.patch.object(
            g, "read_policy", side_effect=lambda x: {
                "qemu-system-x86": "8.2.2-0ubuntu1",
                "libvirt-daemon-system": "10.0.0-2ubuntu1",
            }[x]) as policy:
            report = g.plan()
        self.assertEqual(policy.call_count, 2)
        self.assertFalse(report["running_snapshot_stack_versions_admitted"])
        self.assertFalse(report["apt_modified"])


if __name__ == "__main__":
    unittest.main()
