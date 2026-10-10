#!/usr/bin/env python3
"""Fixture-only tests. No real nftables/systemd/libvirt commands."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import audit_cape_lab_guard_persistence as a

class Tests(unittest.TestCase):
    def test_nftables_conf_reports_flush_without_leaking_config(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"nftables.conf"
            path.write_text("""#!/usr/sbin/nft -f
# vendor note sensitive=ABC123
flush ruleset
include "/etc/nftables.d/private/*"
table inet private { chain input { type filter hook input priority 0; policy accept; } }
""")
            result=a.analyze_nftables_conf(path)
        self.assertTrue(result["flush_ruleset_present"])
        self.assertEqual(result["include_directive_count"],1)
        self.assertFalse(result["safe_to_replace"])
        self.assertNotIn("ABC123",json.dumps(result))
        self.assertNotIn("private/*",json.dumps(result))

    def test_absent_conf_is_not_certified_safe(self):
        with tempfile.TemporaryDirectory() as td:
            result=a.analyze_nftables_conf(Path(td)/"absent")
        self.assertFalse(result["exists"])
        self.assertFalse(result["safe_to_replace"])

    def test_symlink_conf_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            (base/"real").write_text("flush ruleset")
            (base/"link").symlink_to(base/"real")
            result=a.analyze_nftables_conf(base/"link")
        self.assertEqual(result["inspection"],"BLOCKED_SYMLINK")

    def test_unit_metadata_filters_commands(self):
        raw="""LoadState=loaded
ActiveState=inactive
UnitFileState=enabled
ExecStart={ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf ; }
Before=network-pre.target libvirtd.service docker.service
After=local-fs.target
DropInPaths=/etc/systemd/system/nftables.service.d/local.conf
"""
        record=a.summarize_unit(raw,"nftables.service")
        self.assertTrue(record["exec_mentions_nft"])
        self.assertTrue(record["before_docker"])
        self.assertTrue(record["unit_dropins_present"])
        self.assertNotIn("local.conf",json.dumps(record))

    def test_guard_rules_have_expected_verdict_order(self):
        table={"nftables":[{"table":{"family":"inet","name":a.GUARD}}]}
        hooks={"cape_forward":"forward","cape_input":"input",
               "cape_output":"output"}
        for name,hook in hooks.items():
            table["nftables"].append({"chain":{"name":name,"family":"inet",
                "table":a.GUARD,"hook":hook,"type":"filter","prio":-50,"policy":"accept"}})
        for chain,actions in {"cape_forward":["drop","drop"],
                              "cape_input":["accept","drop"],
                              "cape_output":["accept","drop"]}.items():
            for action in actions:
                table["nftables"].append({"rule":{"family":"inet",
                  "table":a.GUARD,"chain":chain,"expr":[{action:None}]}})
        data=json.dumps(table)
        with patch.object(a,"command",return_value=data):
            self.assertTrue(a.inspect_guard()["rule_verdict_order_verified"])
        table["nftables"][-1]["rule"]["expr"]=[{"accept":None}]
        with patch.object(a,"command",return_value=json.dumps(table)):
            with self.assertRaisesRegex(a.AuditBlocked,"order"):
                a.inspect_guard()

    def test_running_master_blocks_before_guard_or_service_read(self):
        with patch.object(a,"virsh",return_value="running"),\
             patch.object(a,"command") as call:
            with self.assertRaisesRegex(a.AuditBlocked,"master"):
                a.guest_network_gate()
            call.assert_not_called()

if __name__=="__main__":
    unittest.main()
