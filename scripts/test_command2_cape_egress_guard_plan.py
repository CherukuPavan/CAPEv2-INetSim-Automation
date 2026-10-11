"""Offline nft guard policy rendering safety tests; no host operations."""
import hashlib
from pathlib import Path
import unittest

import command2_cape_egress_guard_plan as plan


class EgressGuardTests(unittest.TestCase):
    def test_conservative_bridge_only_policy_for_five_vms(self):
        report = plan.render_cape_egress_guard()
        rules = report["ruleset_text"]
        self.assertIn('iifname "cape-lab0" counter drop', rules)
        self.assertIn('iifname "cape-lab0" meta nfproto ipv6 counter drop', rules)
        self.assertIn('iifname "cape-lab0" ip daddr != 192.168.240.1 counter drop', rules)
        self.assertIn("type filter hook forward priority -150; policy accept;", rules)
        self.assertIn("type filter hook input priority -150; policy accept;", rules)
        self.assertNotIn("masquerade", rules.lower())
        self.assertNotIn("flush", rules.lower())
        self.assertNotIn("delete table", rules.lower())
        self.assertFalse(report["deployment_authorized"])
        self.assertFalse(report["attaches_nics"])
        self.assertFalse(report["changes_nftables"])
        self.assertFalse(report["ipv4_runtime_negative_egress_verified"])
        self.assertFalse(report["ipv6_runtime_negative_egress_verified"])
        self.assertFalse(report["l2_guest_segmentation_verified"])
        self.assertFalse(report["reboot_persistence_verified"])
        self.assertEqual(report["ruleset_sha256"],
                         hashlib.sha256(rules.encode()).hexdigest())

    def test_dynamic_host_ip_without_leaking_campus_config(self):
        obj=plan.render_cape_egress_guard("172.28.240.0/24")
        self.assertEqual(obj["host_bridge_ipv4"],"172.28.240.1")
        self.assertIn("172.28.240.1",obj["ruleset_text"])
        self.assertNotIn("enp0s31f6",obj["ruleset_text"])
        self.assertNotIn("10.23.105.55",obj["ruleset_text"])

    def test_malicious_injected_names_never_enter_rules(self):
        for name in ("bridge0","cape-lab0; flush ruleset", "cape-lab0\nflush"):
            with self.subTest(name=name):
                with self.assertRaises(plan.GuardPlanBlocked):
                    plan.render_cape_egress_guard(bridge=name)
        with self.assertRaises(plan.GuardPlanBlocked):
            plan.render_cape_egress_guard(table="cape_analysis_cmd2_guard;flush ruleset")

    def test_public_and_bad_subnet_rejected(self):
        for cidr in ("8.8.8.0/24","192.168.122.0/24","192.168.240.0/16",
                     "192.168.240.5/24","bad;flush","169.254.1.0/24"):
            with self.subTest(cidr=cidr):
                with self.assertRaises(plan.GuardPlanBlocked):
                    plan.render_cape_egress_guard(cidr)

    def test_module_has_no_apply_commands(self):
        code=Path(plan.__file__).read_text(encoding="utf-8")
        for needle in ("subprocess.run", "subprocess.Popen", "os.system(",
                       "os.open(", "write_text(", "nft -f",
                       "systemctl enable", "virsh net-start"):
            self.assertNotIn(needle,code)


if __name__=="__main__":
    unittest.main()
