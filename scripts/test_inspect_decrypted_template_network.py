#!/usr/bin/env python3
"""Fixture-only tests; no NBD, NTFS mount, VM startup or host writes."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import inspect_decrypted_template_network as t

class Tests(unittest.TestCase):
    def test_idle_nbd_selected_only_if_unmounted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            sys=root/"sys"; dev=root/"dev"
            sys.mkdir();dev.mkdir()
            for name in ("nbd0","nbd1"):
                (sys/name).mkdir()
                (dev/name).touch()
            (sys/"nbd0"/"pid").write_text("1234")
            self.assertEqual(t.choose_free_nbd(sys,dev),str(dev/"nbd1"))

    def test_reject_when_no_idle_nbd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            sys=root/"sys";dev=root/"dev"
            sys.mkdir();dev.mkdir()
            (sys/"nbd0").mkdir();(dev/"nbd0").touch()
            (sys/"nbd0"/"nbd0p3").mkdir()
            with self.assertRaisesRegex(t.ReadError,"No idle"):
                t.choose_free_nbd(sys,dev)

    def test_ignore_bad_device_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            sys=root/"sys";dev=root/"dev"
            sys.mkdir();dev.mkdir()
            (sys/"nbdX").mkdir();(dev/"nbdX").touch()
            with self.assertRaisesRegex(t.ReadError,"No idle"):
                t.choose_free_nbd(sys,dev)

    def test_refuse_running_windows_without_touching_image(self):
        with patch.object(t.os,"geteuid",return_value=0), \
             patch.object(t,"virsh",return_value="running"), \
             patch.object(t,"call") as commands:
            with self.assertRaisesRegex(t.ReadError,"shut off"):
                t.validate()
            commands.assert_not_called()

if __name__=="__main__":
    unittest.main()
