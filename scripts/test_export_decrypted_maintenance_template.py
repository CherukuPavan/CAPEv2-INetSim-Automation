#!/usr/bin/env python3
"""Mocked cold-template export safety tests; no Windows VM or host I/O."""
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import export_decrypted_maintenance_template as e

class Tests(unittest.TestCase):
    def test_plan_reports_read_only_and_no_master_write(self):
        details={"source":e.SOURCE,"destination":str(e.OUTPUT),
                 "source_clear_ntfs_candidate":True}
        with patch.object(e,"read_preflight",return_value=(["disk"],details)), \
             patch.object(e,"shell") as commands:
            report=e.perform("plan")
        self.assertEqual(report["mode"],"PLAN_READ_ONLY")
        self.assertFalse(report["copy_created"])
        self.assertFalse(report["master_modified"])
        commands.assert_not_called()

    def test_invalid_mode_fails_before_any_host_read(self):
        with patch.object(e,"read_preflight") as preflight:
            with self.assertRaisesRegex(e.TemplateExportError,"Unknown"):
                e.perform("unsafe")
            preflight.assert_not_called()

    def test_fail_closed_if_guest_remains_running(self):
        with patch.object(e.os,"geteuid",return_value=0), \
             patch.object(e,"virsh",return_value="running"):
            with self.assertRaisesRegex(e.TemplateExportError,"still running"):
                e.read_preflight()

    def test_export_checks_cold_preflight_before_creating_copy(self):
        with TemporaryDirectory() as tmp:
            with patch.object(e,"LOCK",Path(tmp)/"lock"), \
                 patch.object(e.os,"fstat",
                              return_value=SimpleNamespace(st_uid=0,st_mode=0o600)), \
                 patch.object(e,"read_preflight",
                              side_effect=e.TemplateExportError("Decryption not yet verified")), \
                 patch.object(e,"shell") as commands:
                with self.assertRaisesRegex(e.TemplateExportError,"Decryption not yet"):
                    e.perform("export")
                commands.assert_not_called()

if __name__=="__main__":
    unittest.main()
