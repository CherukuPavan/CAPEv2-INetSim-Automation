"""Synthetic-only tests for SSL55 read-only deployment evidence admission."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command1_reference_report_gate as gate

def baseline():
    units={k:{"LoadState":"loaded","ActiveState":"active"}
           for k in gate.REQUIRED_UNITS}
    units["inetsim.service"]={
        "LoadState":"not-found","ActiveState":"inactive"}
    return {
        "purpose":"read_only_exact_ssl55_installer_reference",
        "hostname":"CSE-SSL-55",
        "host_modified":False,
        "secrets_collected":False,
        "architecture":"x86_64",
        "os_release":{"ID":"ubuntu","VERSION_ID":"24.04"},
        "cape_configs_present":{k:True for k in gate.REQUIRED_CONF},
        "cape_git_revision":"unavailable",
        "packages":{
            **{k:"not_installed_or_unknown" for k in gate.VIRT_PACKAGES},
            "postgresql":"18+293.pgdg24.04+1",
            "mongodb-org":"8.0.32",
            "inetsim":"not_installed_or_unknown",
        },
        "services":units,
        "master":{"state":"shut off",
                  "snapshot_names":["Afterfull","other"]},
        "rclone_installed":True,
        "vm_storage_free_gib":48.41,
    }

class ReferenceEvidenceTests(unittest.TestCase):
    def test_matches_source_report_without_inventing_missing_packages(self):
        report=gate.review(baseline())
        obs=report["source"]
        self.assertTrue(obs["all_six_CAPE_conf_files_present"])
        self.assertTrue(obs["required_services_loaded_and_active"])
        self.assertTrue(obs[
            "master_win11_shut_off_with_Afterfull_named_snapshot"])
        self.assertEqual(obs["source_master_export_space_free_gib"],48.41)
        self.assertFalse(obs["virtualization_software_absent_proven"])
        self.assertIsNone(obs["source_master_virtual_size_gib"])
        self.assertFalse(report["may_begin_unattended_export_now"])
        self.assertIn("CAPE_GIT_COMMIT_NOT_IDENTIFIED",
                      report["blocking_evidence"])
        self.assertIn("INETSIM_NOT_DISCOVERED_BY_PACKAGE_OR_SYSTEMD",
                      report["blocking_evidence"])
        self.assertIn("VIRTUALIZATION_PACKAGE_PROVENANCE_UNKNOWN",
                      report["blocking_evidence"])

    def test_missing_dpkg_does_not_mean_virsh_missing(self):
        data=baseline()
        r=gate.review(data)
        self.assertFalse(r["source"]["virtualization_software_absent_proven"])
        self.assertEqual(len(r["source"][
            "virtualization_selected_dpkg_package_status"]),4)
        self.assertFalse(r["may_infer_virtualization_missing_from_dpkg"])

    def test_inetsim_present_package_still_requires_running_validation(self):
        data=baseline()
        data["packages"]["inetsim"]="1.2.3"
        report=gate.review(data)
        self.assertNotIn("INETSIM_NOT_DISCOVERED_BY_PACKAGE_OR_SYSTEMD",
                         report["blocking_evidence"])
        self.assertIn("INETSIM_OPERATION_NOT_VERIFIED",
                      report["blocking_evidence"])
        self.assertFalse(report["source"][
            "INetSim_operational_implementation_verified"])

    def test_40_hex_cape_revision_distinguishes_source_provenance(self):
        data=baseline()
        data["cape_git_revision"]="e"*40
        doc=gate.review(data)
        self.assertEqual(doc["source"]["original_CAPE_checkout_git_SHA40"],
                         "e"*40)
        self.assertNotIn("CAPE_GIT_COMMIT_NOT_IDENTIFIED",
                         doc["blocking_evidence"])

    def test_missing_cape_services_are_not_ignored(self):
        data=baseline()
        data["services"]["cape.service"]["ActiveState"]="activating"
        doc=gate.review(data)
        self.assertFalse(doc["source"][
            "required_services_loaded_and_active"])
        self.assertIn("REFERENCE_REQUIRED_SERVICE_NOT_ACTIVE",
                      doc["blocking_evidence"])

    def test_missing_snapshot_is_not_recreated_in_evidence(self):
        data=baseline()
        data["master"]["snapshot_names"]=[]
        doc=gate.review(data)
        self.assertIn("REFERENCE_MASTER_OR_AFTERFULL_NOT_ATTESTED",
                      doc["blocking_evidence"])

    def test_report_loader_rejects_symlink_and_secret_claim(self):
        with tempfile.TemporaryDirectory() as td:
            report=Path(td)/"reference.json"
            report.write_text(json.dumps(baseline()))
            doc=gate.load(report)
            self.assertEqual(doc["hostname"],"CSE-SSL-55")
            alias=Path(td)/"alias.json"
            alias.symlink_to(report)
            with self.assertRaisesRegex(gate.ReferenceBlocked,"regular"):
                gate.load(alias)
            bad=baseline()
            bad["secrets_collected"]=True
            report.write_text(json.dumps(bad))
            with self.assertRaisesRegex(gate.ReferenceBlocked,"privacy"):
                gate.load(report)

    def test_invalid_json_and_large_report_refused(self):
        with tempfile.TemporaryDirectory() as td:
            report=Path(td)/"reference.json"
            report.write_text("{unclosed")
            with self.assertRaisesRegex(gate.ReferenceBlocked,"Invalid JSON"):
                gate.load(report)
            report.write_bytes(b" "*(gate.MAX_REPORT_BYTES+1))
            with self.assertRaisesRegex(gate.ReferenceBlocked,"size"):
                gate.load(report)

    def test_does_not_output_unknown_arbitrary_user_metadata(self):
        data=baseline()
        data["OAuth_GOOGLE_SECRET_NOT_TO_PRINT"]="very-secret-value"
        result=gate.review(data)
        self.assertNotIn("very-secret-value",json.dumps(result))
        self.assertFalse(result["portable_Cape_INetSim_command1_complete"])
        self.assertFalse(result["golden_master_private_drive_uploaded"])

    def test_reject_non_reference_os_and_bogus_free_space(self):
        data=baseline()
        data["os_release"]["VERSION_ID"]="22.04"
        with self.assertRaises(gate.ReferenceBlocked):
            gate.review(data)
        data=baseline()
        data["vm_storage_free_gib"]="over a million"
        with self.assertRaises(gate.ReferenceBlocked):
            gate.review(data)

if __name__=="__main__":
    unittest.main()
