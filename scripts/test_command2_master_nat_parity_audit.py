"""Offline tests for master-equivalent persistent NAT parity inspection.

All libvirt calls are fake; this module NEVER changes any real host/VM.
"""
import unittest
from unittest.mock import patch
import command2_master_nat_parity_audit as a

MASTER=('<domain type="kvm"><name>win11</name><uuid>'+a.MASTER_UUID+
        '</uuid><devices><interface type="network">'
        '<source network="default"/><mac address="52:54:00:62:a0:00"/>'
        '<model type="e1000e"/></interface></devices></domain>')
CLONE=('<domain type="kvm"><name>win11_1</name><uuid>'+a.CLONE_UUID+
       '</uuid><devices><interface type="network">'
       '<source network="cape-analysis-isolated"/>'
       '<mac address="02:0a:30:6a:3f:50"/>'
       '<model type="e1000e"/></interface></devices></domain>')
LIVE=CLONE.replace('</devices>',
       '<interface type="network"><source network="default"/>'
       '<mac address="02:ca:55:11:01:01"/><model type="e1000e"/>'
       '</interface></devices>')
NAT=('<network><name>default</name><forward mode="nat"/>'
     '<bridge name="virbr0"/>'
     '<ip address="192.168.122.1" netmask="255.255.255.0">'
     '<dhcp><range start="192.168.122.2" end="192.168.122.254"/>'
     '<host mac="52:54:00:65:aa:01" name="known" ip="192.168.122.88"/>'
     '</dhcp></ip></network>')
LEASES=('Expiry Time           MAC address         Protocol  IP address'
       '\n2026-10-12 19:23:45  52:54:00:12:34:56 ipv4 '
       '192.168.122.125/24 win11 01:abcd')

def fake_virsh(*args):
    if args[0]=="domuuid":
        return {"win11":a.MASTER_UUID,a.TRIAL:a.TRIAL_UUID,
                a.CLONE:a.CLONE_UUID}[args[1]]
    if args[0]=="domstate":
        return "running" if args[1]==a.CLONE else "shut off"
    if args==("snapshot-list",a.CLONE,"--name"):return a.CANDIDATE
    if args==("dumpxml","--inactive","win11"):return MASTER
    if args==("dumpxml","--inactive",a.CLONE):return CLONE
    if args==("dumpxml",a.CLONE):return LIVE
    if args==("net-dumpxml","default"):return NAT
    if args==("net-info","default"):return "Name: default\nActive: yes\nBridge: virbr0"
    if args==("net-dhcp-leases","default"):return LEASES
    raise AssertionError(args)

class MasterParity(unittest.TestCase):
    def test_real_master_one_nic_default_e1000e(self):
        self.assertEqual(a.guest_view(MASTER,"win11",a.MASTER_UUID),
                         [{"network":"default","mac":"52:54:00:62:a0:00",
                           "model":"e1000e","libvirt_port_isolated":False}])
        with self.assertRaises(a.NatParityBlocked):
            a.guest_view(MASTER.replace("default","cape-analysis-isolated"),
                         "win11_1",a.MASTER_UUID)

    def test_reserved_dhcp_pool_conflicts_must_not_be_assumed_free(self):
        answer=a.nat_details(NAT)
        self.assertEqual(answer["ipv4"]["subnet"],"192.168.122.0/24")
        self.assertEqual(answer["dynamic_dhcp_ranges"][0]["last"],
                         "192.168.122.254")
        self.assertEqual(answer["existing_dhcp_host_reservations"][0]["ipv4"],
                         "192.168.122.88")
        self.assertFalse(answer["automatic_safe_clone_static_ip_assigned"])
        with self.assertRaises(a.NatParityBlocked):
            a.nat_details(NAT.replace('mode="nat"','mode="bridge"'))

    def test_lease_parser_finds_existing_master_address(self):
        result=a.lease_inventory(LEASES)
        self.assertEqual(result["live_dhcp_leases"][0]["ipv4"],
                         "192.168.122.125")
        self.assertTrue(result[
            "lease_table_not_exhaustive_proof_of_static_ip_availability"])

    def test_full_host_plan_is_count_driven_and_no_vm_mutation(self):
        with patch.object(a.os,"geteuid",return_value=0),\
             patch.object(a.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(a,"virsh",side_effect=fake_virsh):
            found=a.assess(5)
        self.assertEqual(found["target_permanent_bridge"],"virbr0")
        self.assertEqual(found["target_clone_names"],
                         ["win11_1","win11_2","win11_3","win11_4","win11_5"])
        self.assertTrue(found["moving_clone_requires_approved_guest_ip_cape_config_updates"])
        self.assertFalse(found["libvirt_network_or_guest_modified"])
        self.assertFalse(found["unrestricted_malware_sample_egress_approved"])
        self.assertEqual(len(found["live_clone_nics"]),2)

    def test_master_network_mismatch_and_bad_clone_count_blocks(self):
        for count in (0,17,-1):
            with patch.object(a.os,"geteuid",return_value=0),\
                 patch.object(a.socket,"gethostname",return_value="CSE-SSL-55"):
                with self.assertRaises(a.NatParityBlocked):
                    a.assess(count)
        def unexpected(*args):
            if args==("dumpxml","--inactive","win11"):
                return MASTER.replace('network="default"','network="wrong"')
            return fake_virsh(*args)
        with patch.object(a.os,"geteuid",return_value=0),\
             patch.object(a.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(a,"virsh",side_effect=unexpected):
            with self.assertRaisesRegex(a.NatParityBlocked,"MASTER"):
                a.assess(1)

    def test_no_mutator_exposed(self):
        from pathlib import Path
        text=Path(a.__file__).read_text()
        for phrase in ('virsh("attach-interface"','virsh("detach-interface"',
            'virsh("net-update"','virsh("net-define"','virsh("snapshot-create"',
            'virsh("snapshot-revert"','virsh("destroy"','virsh("start"',
            'shell=True','os.unlink(','os.replace('):
            self.assertNotIn(phrase,text)

if __name__=="__main__":unittest.main()
