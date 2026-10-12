"""Synthetic read-only profile for 1..16 cloned master-style NAT guests."""
from pathlib import Path
from unittest.mock import patch
import unittest

import command2_portable_master_nat_profile as p

MASTER=(
 '<domain type="kvm"><name>win11</name>'
 '<uuid>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</uuid><devices>'
 '<interface type="network"><source network="default"/>'
 '<mac address="52:54:00:62:a0:00"/><model type="e1000e"/>'
 '</interface></devices></domain>')
NAT=('<network><name>default</name><forward mode="nat"/>'
     '<bridge name="virbr0"/>'
     '<ip address="192.168.122.1" netmask="255.255.255.0">'
     '<dhcp><range start="192.168.122.2" end="192.168.122.254"/>'
     '<host name="existing" mac="52:54:00:ee:00:01" '
     'ip="192.168.122.111"/></dhcp></ip></network>')
LEASE=("Expiry Time MAC address Protocol IP address Hostname\n"
       "2026-10-12 21:00:00 52:54:00:aa:bb:cc ipv4 "
       "192.168.122.131/24 win11_other")
J=Path("/root/cape-command2/command2-identity-reservation.json")
def rows(n):
    return [{"libvirt_name":"win11_"+str(i),
             "mac_candidate":f"02:ca:10:22:00:{i:02x}",
             "guest_static_ipv4_target":"192.168.240."+str(100+i)}
            for i in range(1,n+1)]
def fake(*args,**kwargs):
    if args==("domstate","win11"):return "shut off"
    if args==("domstate","win11_trial_1"):return "shut off"
    if args==("dumpxml","--inactive","win11"):return MASTER
    if args==("net-dumpxml","default"):return NAT
    if args==("net-info","default"):
        return "Name:           default\nActive:          yes\nBridge:          virbr0"
    if args==("net-dhcp-leases","default"):return LEASE
    if args==("list","--all","--name"):return "win11\nwin11_trial_1"
    raise AssertionError(args)
def setup(n,virsh=fake):
    return (
      patch.object(p.workflow,"canonical_host",return_value="lab02"),
      patch.object(p.os,"geteuid",return_value=0),
      patch.object(p.workflow.snapshotgate,"private_evidence_folder",
                   return_value=True),
      patch.object(p.workflow.snapshotgate,"reservation_rows",
                   return_value=rows(n)),
      patch.object(p,"virsh",side_effect=virsh))

class NATProfile(unittest.TestCase):
    def test_count_driven_source_parity_all_sixteen(self):
        for n in (1,5,16):
            a,b,c,d,e=setup(n)
            with a,b,c,d,e:
                report=p.inspect("lab02",J)
            self.assertEqual(report["count"],n)
            self.assertEqual(report["guest_names"],
                             ["win11_"+str(i) for i in range(1,n+1)])
            self.assertTrue(all(x["host_network"]=="default" and
                  x["bridge"]=="virbr0" and x["required_nic_model"]=="e1000e"
                  and x["gateway_ipv4"]=="192.168.122.1" for x in
                  report["guest_nat_candidates"]))
            self.assertTrue(all(not x["guest_nic_port_isolated"] for x in
                                report["guest_nat_candidates"]))
            self.assertEqual(report["guest_nat_candidates"][0]
                             ["desired_static_ipv4"],"192.168.122.201")
            self.assertFalse(report["project_portable_command2_finished"])
            self.assertFalse(report["all_machines_or_networks_modified"])
            self.assertTrue(report["real_unrestricted_malware_internet_not_approved"])

    def test_invalid_master_network_and_state_blocks(self):
        def wrong(*args,**kw):
            if args==("dumpxml","--inactive","win11"):
                return MASTER.replace('network="default"','network="isolated"')
            return fake(*args,**kw)
        a,b,c,d,e=setup(1,wrong)
        with a,b,c,d,e,self.assertRaisesRegex(p.PortableNatBlocked,"Master"):
            p.inspect("lab02",J)
        def notoff(*args,**kw):
            if args==("domstate","win11_trial_1"):return "running"
            return fake(*args,**kw)
        a,b,c,d,e=setup(1,notoff)
        with a,b,c,d,e,self.assertRaisesRegex(p.PortableNatBlocked,"Trial"):
            p.inspect("lab02",J)

    def test_lease_conflict_on_candidate_201_is_blocker(self):
        def taken(*args,**kw):
            if args==("net-dhcp-leases","default"):
                return LEASE.replace("192.168.122.131","192.168.122.201")
            return fake(*args,**kw)
        a,b,c,d,e=setup(3,taken)
        with a,b,c,d,e,self.assertRaisesRegex(p.PortableNatBlocked,"collides"):
            p.inspect("lab02",J)

    def test_unapproved_journal_mac_collision_blocks(self):
        duplicate=rows(2)
        duplicate[1]["mac_candidate"]=duplicate[0]["mac_candidate"]
        a,b,c,d,e=setup(2)
        with a,b,c,patch.object(p.workflow.snapshotgate,"reservation_rows",
                     return_value=duplicate),e,\
             self.assertRaisesRegex(p.PortableNatBlocked,"Duplicate"):
            p.inspect("lab02",J)

    def test_plan_never_controls_virsh_or_changes_windows(self):
        s=Path(p.__file__).read_text()
        for forbidden in ('"attach-interface"','"detach-interface"',
            '"net-update"','"net-define"','"snapshot-create-as"',
            '"snapshot-revert"','os.replace(', 'os.unlink(', 'write_text(',
            'write_bytes(', 'shell=True','Start-Process'):
            self.assertNotIn(forbidden,s)
if __name__=="__main__":unittest.main()
