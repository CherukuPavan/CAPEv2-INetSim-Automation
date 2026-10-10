#!/usr/bin/env python3
"""Static offline safety checks for the Command 2A post-restart host checkpoint.

No libvirt, nft, sudo or disk commands execute in these tests.
"""
from pathlib import Path
import re
import subprocess
import unittest

SCRIPT = Path(__file__).with_name("command2_postrestart_host_checkpoint.sh")


class CheckpointScriptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        proc = subprocess.run(["bash", "-n", str(SCRIPT)],
                              capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_only_expected_guest_and_identity_gates(self):
        s = self.script
        self.assertIn("732b2256-ee99-41fa-881d-fbf5c476d960", s)
        self.assertIn("289d89be-68ec-4c62-90e1-ea930849266f", s)
        self.assertIn("e75f6fef-347d-462f-9738-4de3df6bfa74", s)
        self.assertIn("win11_1.command2.qcow2", s)
        self.assertIn("win11_1.command2_VARS.fd", s)
        self.assertIn('v dumpxml --inactive win11_1', s)
        self.assertIn('v snapshot-list win11_1', s)
        self.assertIn('sudo -n nft list table inet cape_analysis_guard', s)

    def test_no_mutation_or_live_qcow2_probe(self):
        # No calls to mutation-capable management actions even in a command
        # that could modify the shared SSL-55 host or the guest.
        s = self.script
        for forbidden in (
            "v start ", "v shutdown ", "v destroy ", "v suspend ",
            "v resume ", "v define ", "v undefine ", "v attach-",
            "v detach-", "v snapshot-create", "v snapshot-revert",
            "v net-start", "v net-autostart", "nft add ", "nft flush ",
            "nft delete ", "qemu-img check", "qemu-img amend",
            "qemu-img rebase", "qemu-img convert", "systemctl",
            "rm -rf", "mkfs", "iptables -", "ip link set",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, s)
        self.assertRegex(s, r'(?m)^umask 077$')
        self.assertRegex(s, r'(?m)^REPORT="\$\(mktemp')

    def test_pass_does_not_claim_actual_network_containment(self):
        s = self.script
        self.assertIn("runtime egress NOT proven", s)
        self.assertIn("PENDING: Snapshots", s)
        self.assertIn('RESULT: COMMAND2A_POSTRESTART_HOST_READONLY_PASS', s)


if __name__ == "__main__":
    unittest.main()
