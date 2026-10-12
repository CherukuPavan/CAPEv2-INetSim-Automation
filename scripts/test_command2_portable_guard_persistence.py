"""Offline create-only dedicated CAPE nft guard reboot unit tests."""
import ast
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_portable_guard_persistence as g
import command2_portable_workflow as workflow

HOST="other-kvm-lab"
CIDR="192.168.241.0/24"
ROOT=Path("/root/command2-identity-reservation.json")
def rows():
    return [{"libvirt_name":"win11_1","guest_static_ipv4_target":"192.168.241.101"},
            {"libvirt_name":"win11_2","guest_static_ipv4_target":"192.168.241.102"}]
class GuardReplay(unittest.TestCase):
    def test_exact_generated_guard_boot_has_pinned_hash_and_fail_closed(self):
        expected="a"*64
        src=g.boot_source(expected,"192.168.241.1")
        ast.parse(src)
        self.assertIn("SHA='"+expected+"'",src)
        self.assertIn("BRIDGE_IP='192.168.241.1'",src)
        self.assertIn("Foreign CAPE nft table present",src)
        self.assertIn('cmd("nft","--check","-f",str(POLICY))',src)
        self.assertIn('cmd("nft","-f",str(POLICY))',src)
        self.assertNotIn("flush ruleset",src)
        self.assertNotIn("delete table",src)

    def test_only_dedicated_unit_without_guest_network_autostart(self):
        self.assertIn("cape-command2-nft-guard.service",str(g.UNIT))
        self.assertIn("WantedBy=multi-user.target",g._UNIT)
        self.assertIn("ExecStart=/usr/bin/python3",g._UNIT)
        self.assertNotIn("virsh",g._UNIT)
        self.assertNotIn("net-autostart",g._UNIT)

    def test_replay_requires_exact_state_in_synthetic_preflight(self):
        with patch.object(workflow,"canonical_host",return_value=HOST),\
             patch.object(g.os,"geteuid",return_value=0),\
             patch.object(workflow.snapshotgate,"reservation_rows",return_value=rows()),\
             patch.object(workflow,"load_guest",return_value=(
                rows()[0],CIDR,None)),\
             patch.object(g,"run",side_effect=lambda *args:
                 "win11_1" if args[-2:]==("list","--name") else ""):
            with self.assertRaisesRegex(g.ServiceBlocked,"No running VM"):
                g.plan(HOST,ROOT)

    def test_noninteractive_install_never_changes_host(self):
        with patch.object(g.sys.stdin,"isatty",return_value=False),\
             patch.object(g,"plan",side_effect=AssertionError("Do not inspect system")):
            with self.assertRaisesRegex(g.ServiceBlocked,"terminal"):
                g.install(HOST,ROOT)

    def test_nftables_service_or_existing_unit_is_never_overwritten(self):
        source=Path(g.__file__).read_text()
        self.assertIn('base["UnitFileState"] in',source)
        self.assertIn('own["LoadState"]=="not-found"',source)
        self.assertIn("not f.exists() and not f.is_symlink()",source)
        self.assertIn("os.O_EXCL|os.O_NOFOLLOW",source)
        self.assertIn('"enable","cape-command2-nft-guard.service"',source)
        self.assertNotIn('"disable","nftables.service"',source)
        self.assertNotIn('"restart","libvirtd.service"',source)
        self.assertNotIn('"net-autostart"',source)

if __name__=="__main__":
    unittest.main()
