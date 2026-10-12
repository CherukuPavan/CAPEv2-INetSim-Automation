"""Other-host CAPE-only libvirt+nft staged installer synthetic tests."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import command2_portable_network_install as n
import command2_portable_workflow as workflow

HOST="other-lab-ubuntu"
CIDR="192.168.241.0/24"
VM="win11_1"
journal=Path("/root/private/command2-identity-reservation.json")
def entries():
    return [{"libvirt_name":f"win11_{i}",
             "guest_static_ipv4_target":f"192.168.241.{100+i}"}
            for i in (1,2)]
class NetworkInstall(unittest.TestCase):
    def runplan(self,existing=False,running=False,conflict=False):
        rows=entries()
        def inspected_vm(journal,host,vm):
            return next(x for x in rows if x["libvirt_name"]==vm),CIDR,None
        def guestvirsh(*args):
            if args==("list","--name"):return "unrelated-running" if running else ""
            if args==("net-list","--all","--name"):return "default"
            self.fail("Unexpected libvirt read/write "+str(args))
        def nftcheck(*args,**kw):
            self.assertEqual(args,("nft","--check","-f","-"))
            self.assertIn('iifname "cape-lab0"',kw["input_text"])
            self.assertNotIn("flush ruleset",kw["input_text"])
            return ""
        with patch.object(workflow,"canonical_host",return_value=HOST),\
             patch.object(n.os,"geteuid",return_value=0),\
             patch.object(workflow.snapshotgate,"reservation_rows",
                          return_value=rows),\
             patch.object(workflow,"load_guest",side_effect=inspected_vm),\
             patch.object(n,"virsh",side_effect=guestvirsh),\
             patch.object(n,"nft_table_exists",return_value=existing),\
             patch.object(n,"collision_free",side_effect=(
                 n.NetworkBlocked("overlapping kernel route") if conflict else None)),\
             patch.object(n,"command",side_effect=nftcheck):
            return n.canonical_inputs(HOST,journal)

    def test_exact_guest_subnet_and_host_only_guard_plan(self):
        result=self.runplan()
        self.assertEqual(result["analysis_subnet"],CIDR)
        self.assertEqual(result["vm_count"],2)
        self.assertFalse(result["host_changes_made"])
        self.assertFalse(result["nft_reboot_persistence_tested"])
        self.assertFalse(result["production_network_approved"])
        self.assertIn('<port isolated="yes" />',result["network_xml"])
        self.assertNotIn("<forward",result["network_xml"])
        self.assertNotIn("<dhcp",result["network_xml"])
        self.assertIn('iifname "cape-lab0"',result["nft_rules"])

    def test_existing_nft_table_refused_without_ever_overwriting(self):
        with self.assertRaisesRegex(n.NetworkBlocked,"nft table exists"):
            self.runplan(existing=True)

    def test_any_running_vm_refuses_network_mutation(self):
        with self.assertRaisesRegex(n.NetworkBlocked,"Running VM"):
            self.runplan(running=True)

    def test_overlap_refused_before_network_or_firewall_apply(self):
        with self.assertRaisesRegex(n.NetworkBlocked,"overlapping"):
            self.runplan(conflict=True)

    def test_bad_kernel_address_inventory_blocks_auto_network(self):
        with patch.object(n.hostinfo,"parsed_routes",return_value=None),\
             patch.object(n.hostinfo,"json_command",return_value=[]),\
             patch.object(n.hostinfo,"parsed_addresses",return_value=[]),\
             patch.object(n.hostinfo,"libvirt_nets",return_value=[]):
            with self.assertRaisesRegex(n.NetworkBlocked,"inventory unavailable"):
                n.collision_free(CIDR)

    def test_no_operator_tty_means_no_installation_attempt(self):
        with patch.object(n.sys.stdin,"isatty",return_value=False),\
             patch.object(n,"canonical_inputs",
                          side_effect=AssertionError("Do not query host")):
            with self.assertRaisesRegex(n.NetworkBlocked,"interactive"):
                n.install(HOST,journal)

    def test_no_existing_guard_table_in_nft_inventory(self):
        a={"nftables":[{"metainfo":{"version":"1.0.0"}},
                        {"table":{"family":"inet","name":"docker"}},
                        {"table":{"family":"ip","name":"filter"}}]}
        bad={"nftables":[{"table":{"family":"inet","name":n.TABLE}}]}
        with patch.object(n,"command",return_value=json.dumps(a)):
            self.assertFalse(n.nft_table_exists())
        with patch.object(n,"command",return_value=json.dumps(bad)):
            self.assertTrue(n.nft_table_exists())

    def test_network_installer_no_unrelated_network_firewall_or_vm_changes(self):
        source=Path(n.__file__).read_text()
        self.assertIn('virsh("net-define",str(file),"--validate")',source)
        self.assertIn('virsh("net-start",NETWORK)',source)
        self.assertIn('command("nft","-f","-",input_text=initial["nft_rules"])',source)
        self.assertNotIn("flush ruleset",source.split("def install")[1])
        for bad in ('"virsh","destroy"', '"attach-interface"', '"snapshot-create-as"',
                    '"net-autostart"', '"systemctl","restart"',
                    '"iptables"', '"ufw"', '"shutdown"'):
            self.assertNotIn(bad,source)

if __name__=="__main__":unittest.main()
