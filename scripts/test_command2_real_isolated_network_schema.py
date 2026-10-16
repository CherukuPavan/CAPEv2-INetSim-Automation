"""Exercise generated CAPE lab XML and nftables against REAL Linux tools.

This is a non-mutating syntax/schema check on a disposable test runner.
It NEVER defines a libvirt network, applies nftables rules, boots a VM,
or certifies actual guest isolation / reboot containment.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import command2_cape_egress_guard_plan as guard
import command2_isolated_network_xml_plan as network


class RealNetworkSchemaTests(unittest.TestCase):
    def require_tool(self, program):
        if shutil.which(program) is None:
            self.skipTest(program + " unavailable")
        return program

    def check_command(self, args, *, stdin=None):
        result = subprocess.run(
            args, input=stdin, capture_output=True, text=True,
            timeout=35, check=False)
        self.assertEqual(result.returncode, 0,
                         "Command rejected generated configuration: " +
                         args[0] + " " + result.stderr[:2000])
        return result.stdout

    def test_real_libvirt_network_schema_without_defining_network(self):
        self.require_tool("virt-xml-validate")
        # The libvirt wrapper invokes xmllint; installations of
        # libvirt-clients alone do not guarantee its availability.
        self.require_tool("xmllint")
        xml = network.plan(
            "cape-analysis-isolated", "cape-lab0", "192.168.240.0/24",
            ["192.168.240.125", "192.168.240.126"]
        )["libvirt_network_xml"]
        with tempfile.TemporaryDirectory(prefix="cape-syntax-test-") as td:
            file = Path(td) / "isolated.xml"
            file.write_text(xml, encoding="utf-8")
            self.check_command(["virt-xml-validate", str(file), "network"])
        self.assertNotIn("<forward", xml)
        self.assertNotIn("<dhcp", xml)

    def test_real_nft_candidate_syntax_without_installing_rules(self):
        self.require_tool("nft")
        # 'nft --check' is non-mutating but still needs CAP_NET_ADMIN
        # to inspect current netlink state. Offline unittest CI runs as
        # non-root; the dedicated real-tool workflow runs this under sudo.
        if os.geteuid() != 0:
            probe = subprocess.run(
                ["nft", "-j", "list", "tables"], capture_output=True,
                text=True, check=False, timeout=15)
            if probe.returncode != 0:
                self.skipTest("Unprivileged CI has no nft netlink access")
        for subnet in ("192.168.240.0/24", "172.28.240.0/24",
                       "10.99.240.0/24"):
            with self.subTest(subnet=subnet):
                rules = guard.render_cape_egress_guard(subnet)["ruleset_text"]
                self.check_command(["nft", "--check", "-f", "-"], stdin=rules)
                self.assertNotIn("flush ruleset", rules)
                self.assertNotIn("masquerade", rules)
                self.assertNotIn("delete table", rules)

    def test_generated_network_and_nft_use_exact_same_bridge_and_host(self):
        subnet = "172.28.240.0/24"
        xml = network.plan("cape-analysis-isolated", "cape-lab0", subnet)
        nft = guard.render_cape_egress_guard(subnet)
        self.assertEqual(xml["bridge_ipv4"], nft["host_bridge_ipv4"])
        self.assertEqual(xml["bridge"], nft["analysis_bridge"])
        self.assertFalse(xml["network_defined_on_host"])
        self.assertFalse(nft["deployment_authorized"])


if __name__ == "__main__":
    unittest.main()
