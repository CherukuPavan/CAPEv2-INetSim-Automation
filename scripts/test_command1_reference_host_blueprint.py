"""Synthetic-only read-only SSL55 reproducibility blueprint tests."""
from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import command1_reference_host_blueprint as m

class BlueprintTests(unittest.TestCase):
    def test_only_readonly_allowlisted_commands_can_execute(self):
        with patch.object(m.subprocess,"run",
                          side_effect=AssertionError("Must not execute")):
            self.assertIsNone(m.query("systemctl","restart","cape.service"))
            self.assertIsNone(m.query("virsh","start","win11"))
            self.assertIsNone(m.query("rclone","config","show"))
        with patch.object(m.subprocess,"run",
                  return_value=SimpleNamespace(
                      stdout="LoadState=loaded\n",returncode=0)) as call:
            self.assertEqual(m.query("systemctl","show","--no-pager",
                           "--property=LoadState,ActiveState,UnitFileState",
                           "cape.service"), "LoadState=loaded")
            call.assert_called_once()
            self.assertFalse(call.call_args.kwargs["check"])

    def test_package_list_contains_host_dependencies_but_no_secrets(self):
        def fake(*argv):
            return "install ok installed|2.7.1" if argv[-1]=="ovmf" else None
        with patch.object(m,"query",side_effect=fake):
            result=m.packages()
        self.assertEqual(result["ovmf"],"2.7.1")
        self.assertEqual(result["swtpm"],"NOT_INSTALLED_OR_UNKNOWN")
        self.assertIn("postgresql",result)
        self.assertIn("suricata",result)
        self.assertIn("inetsim",result)

    def test_only_allowlisted_unit_states_not_environment_or_execstart(self):
        def fake(*arg):
            return ("LoadState=loaded\nActiveState=active\n"
                    "UnitFileState=enabled\n"
                    "Environment=SQL_PASSWORD_DO_NOT_REPORT\n"
                    "ExecStart=/bin/SECRET_DO_NOT_REPORT\n")
        with patch.object(m,"query",side_effect=fake):
            report=m.services()
        self.assertEqual(report["cape.service"]["ActiveState"],"active")
        self.assertNotIn("SECRET_DO_NOT_REPORT",str(report))
        self.assertNotIn("SQL_PASSWORD",str(report))
        self.assertIn("inetsim.service",report)

    def test_git_records_commit_and_boolean_dirty_without_filenames(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/"CAPEv2"
            repo.mkdir()
            def fake(*arg):
                if "rev-parse" in arg:return "a"*40
                if "status" in arg:return " M conf/cuckoo-SENSITIVE-API.conf"
                return None
            with patch.object(m,"CAPE",repo), \
                 patch.object(m,"query",side_effect=fake):
                result=m.repository()
            self.assertTrue(result["uncommitted_changes_present"])
            self.assertEqual(result["CAPE_commit_SHA40"],"a"*40)
            self.assertNotIn("SENSITIVE",str(result))

    def test_full_report_is_readonly_without_configuration_contents(self):
        base={"OS":{"ID":"ubuntu"},"arch":"x86_64","CPU_count":16,
              "memory":{"MemTotal_gib":64},"storage":{"free_gib":200},
              "exact_master":{"safe_for_cold_export":True}}
        with patch.object(m.common,"run",return_value=base), \
             patch.object(m,"packages",return_value={"ovmf":"2.7"}), \
             patch.object(m,"repository",return_value={"CAPE_checkout_present":True}), \
             patch.object(m,"services",return_value={"cape.service":{"ActiveState":"active"}}), \
             patch.object(m,"mounted_tmpfs",return_value={"exact_mnt_tmpfs":True}):
            report=m.run()
        self.assertFalse(report["host_or_service_modified"])
        self.assertFalse(report["secrets_included"])
        self.assertFalse(report["full_fresh_host_installer_proven"])
        self.assertIn("CAPE_conf_presence",report)
        source=Path(m.__file__).read_text()
        for banned in ("systemctl restart","snapshot-revert","virsh start",
                       "rclone.conf","passphrase","password =",
                       "os.system(","shell=True","write_bytes("):
            self.assertNotIn(banned,source)

if __name__=="__main__":
    unittest.main()
