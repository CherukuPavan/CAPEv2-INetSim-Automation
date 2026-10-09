#!/usr/bin/env python3
"""Offline mocked working-overlay checks; no libvirt or QEMU guest actions."""
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import prepare_win11_bitlocker_working_overlay as p

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)
        self.dest=self.dir/"win11.cape-bitlocker-maintenance.qcow2"

    def test_plan_never_creates_overlay(self):
        with patch.object(p,"DEST",self.dest), \
             patch.object(p,"preflight",return_value=(("fingerprint",),213.0)), \
             patch.object(p,"cmd") as commands:
            result=p.perform("plan")
        self.assertEqual(result["status"],"PLAN_ONLY_NO_CHANGES")
        self.assertFalse(self.dest.exists())
        commands.assert_not_called()

    def test_create_new_overlay_only(self):
        def fake(*args,timeout=120):
            if args[0:2]==("qemu-img","create"):
                Path(args[-1]).write_bytes(b"QFI-test-overlay")
                return ""
            if args[0:2]==("qemu-img","info"):
                return json.dumps({"format":"qcow2",
                    "virtual-size":64*1024**3,
                    "full-backing-filename":str(p.TOP),
                    "backing-filename":str(p.TOP)})
            raise AssertionError("Unexpected external command")
        with patch.object(p,"DEST",self.dest), \
             patch.object(p,"LOCK",self.dir/"test.lock"), \
             patch.object(p,"preflight",return_value=(("fingerprint",),213.0)), \
             patch.object(p,"check_lock_permissions"), \
             patch.object(p,"snapshot_fingerprint",return_value=("fingerprint",)), \
             patch.object(p.shutil,"disk_usage",return_value=SimpleNamespace(free=5*10**11)), \
             patch.object(p,"cmd",side_effect=fake):
            result=p.perform("create")
        self.assertEqual(result["status"],"WORKING_OVERLAY_CREATED_NOT_ATTACHED")
        self.assertTrue(self.dest.exists())
        self.assertEqual(self.dest.read_bytes(),b"QFI-test-overlay")
        self.assertFalse(result["guest_started"])
        self.assertFalse(result["master_definition_modified"])

    def test_bad_backing_is_rejected_and_temporary_file_removed(self):
        def fake(*args,timeout=120):
            if args[0:2]==("qemu-img","create"):
                Path(args[-1]).write_bytes(b"QFI-test-overlay")
                return ""
            if args[0:2]==("qemu-img","info"):
                return json.dumps({"format":"qcow2","virtual-size":64*1024**3,
                                   "backing-filename":"/wrong/original.qcow2",
                                   "full-backing-filename":"/wrong/original.qcow2"})
            raise AssertionError("Unexpected command")
        with patch.object(p,"DEST",self.dest), \
             patch.object(p,"LOCK",self.dir/"test.lock"), \
             patch.object(p,"preflight",return_value=(("fingerprint",),213.0)), \
             patch.object(p,"check_lock_permissions"), \
             patch.object(p,"cmd",side_effect=fake):
            with self.assertRaisesRegex(p.Block,"backing image"):
                p.perform("create")
        self.assertFalse(self.dest.exists())
        self.assertFalse(list(self.dir.glob(".cape-working-*.qcow2")))

    def test_unrecognized_mode_blocks(self):
        with self.assertRaisesRegex(p.Block,"Unknown mode"):
            p.perform("apply")

if __name__=="__main__":
    unittest.main()
