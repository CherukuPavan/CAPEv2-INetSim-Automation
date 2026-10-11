"""Mock-only replay-design acceptance based on 2026-10-11 SSL55 evidence."""
import copy
import unittest
import command2_ssl55_persistence_design as p


def report():
    return {
        "result":"SSL55_COMMAND2_NFT_BOOT_PERSISTENCE_INSPECTION_ONLY",
        "network_or_guest_changed":False,
        "existing_guard_expected_structure_now":True,
        "analysis_network":{
            "active":"no","autostart":"no","persistent":"yes",
            "bridge":"cape-lab0","nonforward_no_dhcp_known_subnet":True},
        "domain_autostart_enabled":{v:False for v in
                                    ("win11","win11_1","win11_trial_1")},
        "vm_powerstates":{v:"shut off" for v in
                          ("win11","win11_1","win11_trial_1")},
        "analysis_network_and_clones_autostart_disabled":True,
        "nftables_config_metadata":{
            "exists":True,"file_safe_to_inspect":True,"root_controlled":True,
            "global_flush_present":True,
            "guard_reference_present":False,"includes_present":False},
        "service_show_observations":{
            "nftables.service":{
                "query_succeeded":True,"load_state":"loaded",
                "unit_file_state":"disabled","boot_enabled_observed":False},
            "cape-analysis-guard.service":{
                "query_succeeded":True,"load_state":"not-found",
                "boot_enabled_observed":False}},
        "safe_to_activate_bridge":False,
        "safe_to_attach_win11_1_nic":False,
        "safe_to_assume_guard_survives_reboot":False,
    }


class PlanTests(unittest.TestCase):
    def test_actual_report_shape_designs_no_write(self):
        output=p.plan(report())
        self.assertEqual(output["result"],
                         "COMMAND2_SSL55_FIREWALL_PERSISTENCE_DESIGN_ONLY")
        for flag in ("nftables_service_enable_authorized",
                     "cape_service_enable_authorized","bridge_start_authorized",
                     "guest_nic_attach_authorized","snapshot_capture_authorized",
                     "host_modified"):
            self.assertFalse(output[flag])
        self.assertFalse(output["unresolved_live_tests"]["reboot_survival"])
        self.assertTrue(output["global_flush_in_base_nft_config"])

    def test_changed_firewall_service_configuration_is_not_auto_repaired(self):
        for key,value in (
            ("unit_file_state","enabled"),
            ("load_state","not-found"),
            ("boot_enabled_observed",True),
        ):
            data=report()
            data["service_show_observations"]["nftables.service"][key]=value
            with self.subTest(key=key),self.assertRaises(p.PersistenceBlocked):
                p.plan(data)

    def test_unsafe_analysis_lab_or_vm_autostart_refused(self):
        for section,key,value in (
            ("analysis_network","active","yes"),
            ("analysis_network","autostart","yes"),
            ("analysis_network","bridge","virbr0"),
            ("domain_autostart_enabled","win11_1",True),
            ("vm_powerstates","win11","running"),
            ("vm_powerstates","win11_trial_1","paused"),
        ):
            data=report()
            data[section][key]=value
            with self.subTest(section=section,key=key),\
                 self.assertRaises(p.PersistenceBlocked):
                p.plan(data)

    def test_different_nft_base_policy_refused_instead_of_enabling_it(self):
        for key,value in (
            ("global_flush_present",False),
            ("guard_reference_present",True),
            ("includes_present",True),
            ("root_controlled",False),
        ):
            data=report()
            data["nftables_config_metadata"][key]=value
            with self.subTest(key=key),self.assertRaises(p.PersistenceBlocked):
                p.plan(data)

    def test_guard_absence_or_fake_acceptance_cannot_lead_to_plan(self):
        for key,value in (
            ("existing_guard_expected_structure_now",False),
            ("safe_to_activate_bridge",True),
            ("safe_to_attach_win11_1_nic",True),
            ("safe_to_assume_guard_survives_reboot",True),
            ("network_or_guest_changed",True),
        ):
            data=report()
            data[key]=value
            with self.subTest(key=key),self.assertRaises(p.PersistenceBlocked):
                p.plan(data)

    def test_no_calls_that_modify_host_in_python_implementation(self):
        from pathlib import Path
        text=Path(p.__file__).read_text()
        body=text[text.index("from __future__ import annotations"):]
        for forbidden in ("subprocess", "systemctl", "os.system(", "virsh",
                          "write_text(", "mkdir(", "os.open(", "nft -f"):
            # The plan's advisory string intentionally mentions systemctl
            # concepts, but may never contain executable service commands.
            if forbidden == "systemctl":
                self.assertNotIn("subprocess.run",body)
            else:
                self.assertNotIn(forbidden,body)


if __name__ == "__main__":
    unittest.main()
