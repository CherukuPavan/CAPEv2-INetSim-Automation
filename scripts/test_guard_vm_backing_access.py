#!/usr/bin/env python3
"""Offline regression tests: no host virtualization or AppArmor operations."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import guard_vm_backing_access as g


BASE = "/var/lib/libvirt/images/win11.qcow2"
MIDDLE = "/var/lib/libvirt/images/win11.basicinstallwinsnapshot"
TOP = "/var/lib/libvirt/images/win11.Afterfull"
UUID = "289d89be-68ec-4c62-90e1-ea930849266f"


def chain():
    return [
        {"filename": TOP, "format": "qcow2", "backing-filename": MIDDLE},
        {"filename": MIDDLE, "format": "qcow2", "backing-filename": BASE},
        {"filename": BASE, "format": "qcow2"},
    ]


class ChainTests(unittest.TestCase):
    def test_three_layer_external_snapshot(self):
        self.assertEqual(g.validate_chain(TOP, chain()), [TOP, MIDDLE, BASE])

    def test_relative_backing_path(self):
        records = chain()
        records[0]["backing-filename"] = "win11.basicinstallwinsnapshot"
        self.assertEqual(len(g.validate_chain(TOP, records)), 3)

    def test_top_mismatch_fails_closed(self):
        with self.assertRaises(g.GuardError):
            g.validate_chain(BASE, chain())

    def test_missing_base_fails_closed(self):
        with self.assertRaises(g.GuardError):
            g.validate_chain(TOP, chain()[:-1])

    def test_cycle_fails_closed(self):
        records = chain()
        records[2]["backing-filename"] = TOP
        with self.assertRaises(g.GuardError):
            g.validate_chain(TOP, records)

    def test_non_qcow2_fails_closed(self):
        records = chain()
        records[1]["format"] = "raw"
        with self.assertRaises(g.GuardError):
            g.validate_chain(TOP, records)

    def test_unsafe_metacharacters_fails_closed(self):
        records = chain()
        records[1]["filename"] = '/tmp/file*.qcow2'
        with self.assertRaises(g.GuardError):
            g.validate_chain(TOP, records)

    def test_read_lock_only_for_backings(self):
        policy = g.policy_text([MIDDLE, BASE])
        self.assertIn('"' + BASE + '" rk,', policy)
        self.assertIn('"' + MIDDLE + '" rk,', policy)
        self.assertNotIn(TOP, policy)
        self.assertNotIn(' rw', policy)

    def test_apparmor_include_variations(self):
        for entry in (
            "  include if exists <abstractions/libvirt-qemu.d>",
            "  #include if exists <abstractions/libvirt-qemu.d>",
        ):
            self.assertIsNotNone(g.INCLUDE.search(entry))
        self.assertIsNone(g.INCLUDE.search('include <abstractions/other>'))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / ("99-cape-qcow2-" + UUID)
        self.lock = self.root / "guard.lock"
        self.policy = g.policy_text([MIDDLE, BASE])
        patches = [
            patch.object(g, "LOCKFILE", self.lock),
            patch.object(g, "RULEDIR", self.root),
            patch.object(g, "policy_path", return_value=self.target),
            patch.object(g, "discover", return_value=(UUID, [TOP, MIDDLE, BASE])),
            patch.object(g, "ensure_supported"),
            patch.object(g.os, "geteuid", return_value=0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_create_and_repeated_apply(self):
        with patch.object(g, "parse_profile") as parser:
            result = g.apply(UUID, self.policy, "win11")
            self.assertIn("Installed", result)
            self.assertEqual(self.target.read_text(), self.policy)
            self.assertIn("Already configured", g.apply(UUID, self.policy, "win11"))
            self.assertEqual(parser.call_count, 2)

    def test_refuses_existing_unknown_rule(self):
        self.target.write_text("unsafe\n")
        with self.assertRaisesRegex(g.GuardError, "different contents"):
            g.apply(UUID, self.policy, "win11")
        self.assertEqual(self.target.read_text(), "unsafe\n")

    def test_rolls_back_on_parser_failure(self):
        with patch.object(g, "parse_profile", side_effect=[g.GuardError("parse failed"), None]):
            with self.assertRaisesRegex(g.GuardError, "parse failed"):
                g.apply(UUID, self.policy, "win11")
        self.assertFalse(self.target.exists())

    def test_rejects_changed_snapshot_chain(self):
        with patch.object(g, "discover", return_value=(UUID, [MIDDLE, BASE])):
            with self.assertRaisesRegex(g.GuardError, "changed"):
                g.apply(UUID, self.policy, "win11")
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
