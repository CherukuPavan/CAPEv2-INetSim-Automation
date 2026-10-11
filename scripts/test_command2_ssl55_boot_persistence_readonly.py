"""Offline tests: unit enablement and protected SSL55 VM autostart readback."""
import tempfile
from pathlib import Path
from unittest.mock import patch
import unittest

import command2_ssl55_boot_persistence_readonly as b


def baseline_report():
    return {"result":"SSL55_EXISTING_COMMAND2_NFT_PERSISTENCE_AUDIT_ONLY",
            "analysis_network":{"active":"no","autostart":"no","persistent":"yes"},
            "existing_lab_firewall":{"expected_guard_shape":True},
            "protected_domains":{x:{"power_state":"shut off"}
                                 for x in ("win11","win11_1","win11_trial_1")}}


def systemd_show(load="not-found",unit=""):
    return ("\n".join((
        "LoadState="+load,"UnitFileState="+unit,
        "ActiveState=inactive","After=network.target",
        "Before=","Requires=","Wants=")))


class PersistenceAuditTests(unittest.TestCase):
    def test_missing_service_is_not_relabelled_as_unknown_or_enabled(self):
        state=b.parse_show(systemd_show(),"cape-analysis-guard.service")
        self.assertEqual(state["load_state"],"not-found")
        self.assertFalse(state["boot_enabled_observed"])
        state=b.parse_show(systemd_show("loaded","disabled"),"nftables.service")
        self.assertEqual(state["unit_file_state"],"disabled")
        self.assertFalse(state["boot_enabled_observed"])

    def test_explicit_enabled_unit_is_recorded_but_not_a_reboot_test(self):
        state=b.parse_show(systemd_show("loaded","enabled"),"nftables.service")
        self.assertTrue(state["boot_enabled_observed"])
        self.assertIn("network.target",state["deps"])

    def test_unavailable_metadata_stays_unverified(self):
        state=b.parse_show(None,"nftables.service")
        self.assertFalse(state["query_succeeded"])
        self.assertFalse(state["boot_enabled_observed"])
        with self.assertRaises(b.BootBlocked):
            b.parse_show("LoadState=loaded","nftables.service")

    def test_no_root_controlled_nft_config_does_not_claim_persistence(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"nftables.conf"
            p.write_text("flush ruleset\ntable inet cape_analysis_guard {}\n")
            report=b.nft_config_metadata(p)
            # CI fixture is non-root, so reject or record only if runner is root.
            if report["root_controlled"]:
                self.assertTrue(report["guard_reference_present"])
                self.assertTrue(report["global_flush_present"])
            else:
                self.assertFalse(report["file_safe_to_inspect"])

    def test_autostart_disable_is_parsed_unambiguously(self):
        def fake(*a):
            return "Id: 9\nAutostart: enable" if a[-1]=="win11" else "Autostart: disable"
        with patch.object(b.baseline,"virsh",side_effect=fake):
            self.assertTrue(b.domain_autostart("win11"))
            self.assertFalse(b.domain_autostart("win11_1"))

    def test_full_plan_never_approves_bridge_while_unit_state_unknown(self):
        def fake_sys(*a):
            return systemd_show("not-found","") if a[0]=="systemctl" else None
        def fake_virsh(*a):
            if a[0]=="dominfo":return "Autostart: disable"
            raise AssertionError("No unexpected libvirt command")
        with patch.object(b.baseline,"audit",return_value=baseline_report()),\
             patch.object(b.baseline,"virsh",side_effect=fake_virsh),\
             patch.object(b,"read",side_effect=fake_sys),\
             patch.object(b,"nft_config_metadata",return_value={"exists":False}):
            report=b.perform()
        self.assertTrue(report["analysis_network_and_clones_autostart_disabled"])
        self.assertFalse(report["safe_to_activate_bridge"])
        self.assertFalse(report["safe_to_attach_win11_1_nic"])
        self.assertFalse(report["safe_to_assume_guard_survives_reboot"])
        self.assertFalse(report["network_or_guest_changed"])

    def test_master_autostart_enabled_refuses_safe_fail_closed_posture(self):
        def fake_virsh(*a):
            if a[0]=="dominfo":return ("Autostart: enable"
                                      if a[1]=="win11" else "Autostart: disable")
            raise AssertionError("No unexpected libvirt command")
        with patch.object(b.baseline,"audit",return_value=baseline_report()),\
             patch.object(b.baseline,"virsh",side_effect=fake_virsh),\
             patch.object(b,"read",return_value=systemd_show("loaded","enabled")) ,\
             patch.object(b,"nft_config_metadata",return_value={"exists":False}):
            report=b.perform()
        self.assertFalse(report["analysis_network_and_clones_autostart_disabled"])
        self.assertFalse(report["safe_to_activate_bridge"])

    def test_source_performs_no_modifying_commands(self):
        code=Path(b.__file__).read_text()
        body=code[code.index("from __future__ import annotations"):]
        for needle in ('"systemctl","enable"', '"systemctl","start"',
                       '"virsh","net-start"', '"attach-interface"',
                       '"shutdown"', '"destroy"', '"nft","-f"', 'write_text('):
            self.assertNotIn(needle,body)


if __name__=="__main__":
    unittest.main()
