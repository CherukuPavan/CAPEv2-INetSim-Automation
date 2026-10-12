"""Synthetic all-N postboot NAT guest Agent HTTP and host routing checks."""
from pathlib import Path
from unittest.mock import patch
import unittest
import xml.etree.ElementTree as ET

import command2_portable_master_nat_agent_batch as m

NET={"nat_network":"default","bridge":"virbr0",
     "ipv4":{"gateway":"192.168.122.1","subnet":"192.168.122.0/24"},
     "dynamic_dhcp_ranges":[{"first":"192.168.122.2",
                             "last":"192.168.122.254"}]}
def guests(n):
    return [{"libvirt_name":f"win11_{i}",
             "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}",
             "mac_candidate":f"02:ca:22:00:00:{i:02x}"}
            for i in range(1,n+1)]
def guestxml(row):
    return ('<domain type="kvm"><name>'+row["libvirt_name"]+'</name>'
            '<uuid>'+row["libvirt_uuid_candidate"]+'</uuid><devices>'
            '<interface type="network"><source network="default"/>'
            '<model type="e1000e"/><mac address="'+row["mac_candidate"]+
            '"/></interface></devices></domain>')
def root_with_hosts(rows):
    root=ET.Element("network")
    ip=ET.SubElement(root,"ip",address="192.168.122.1",
                       netmask="255.255.255.0")
    dhcp=ET.SubElement(ip,"dhcp")
    for i,row in enumerate(rows,1):
        ET.SubElement(dhcp,"host",mac=row["mac_candidate"],
                      ip=f"192.168.122.{200+i}",name=f"WIN11-{i}")
    return root
class MockedHost:
    def __init__(self,n):
        self.rows=guests(n)
        self.foreign=False
        self.agent_failed=False
        self.active_missing=False
        self.wrong_routes=False
    def v(self,*a):
        if a==("list","--name"):
            names=[r["libvirt_name"] for r in self.rows]
            if self.active_missing:names.pop()
            return "\n".join(names)
        if a==("list","--all","--name"):
            return "win11\nwin11_trial_1\n"+'\n'.join(
                   x["libvirt_name"] for x in self.rows)
        if a[0]=="domstate":
            return "shut off" if a[1] in ("win11","win11_trial_1") else "running"
        if a[0]=="domuuid":
            return next(x["libvirt_uuid_candidate"] for x in self.rows
                        if x["libvirt_name"]==a[1])
        if a[0]=="dumpxml":
            vm=a[-1]
            return guestxml(next(r for r in self.rows
                        if r["libvirt_name"]==vm))
        if a==("net-dhcp-leases","default"):
            return '\n'.join(f"2026-10-12 20:00:00 {row['mac_candidate']} "
               f"ipv4 192.168.122.{200+i}/24 WIN11-{i}"
               for i,row in enumerate(self.rows,1))
        raise AssertionError(a)
    def route(self,ip):
        return {"dev":"other" if self.wrong_routes else "virbr0",
                "prefsrc":"192.168.122.1"}
    def agent(self,ip,gateway):
        return {"valid":not self.agent_failed,
                "agent_version":"0.23",
                "admin_context_verified":True}

class AgentBatch(unittest.TestCase):
    def plan(self,n,broken=None):
        fake=MockedHost(n)
        if broken: setattr(fake,broken,True)
        xml=root_with_hosts(fake.rows)
        patches=[
          patch.object(m.attach,"journal_rows",return_value=fake.rows),
          patch.object(m.attach,"check_network_references",
                       return_value=(NET,(xml,xml))),
          patch.object(m.attach,"virsh",side_effect=fake.v),
          patch.object(m,"route",side_effect=fake.route),
          patch.object(m,"agent",side_effect=fake.agent),
        ]
        return fake,patches
    def test_all_n_read_only_success_never_promotes_snapshot(self):
        for n in (1,3,16):
            host,p=self.plan(n)
            with p[0],p[1],p[2],p[3],p[4]:
                report=m.check("lab02",Path("/root/command2-identity-reservation.json"))
            self.assertEqual(report["count"],n)
            self.assertTrue(report["all_nat_guest_mac_ip_agent_host_routes_verified"])
            self.assertFalse(report["CAPE_READY"])
            self.assertFalse(report["swtpm_reversion_proven"])
            self.assertFalse(report["host_guest_services_networks_modified"])
            self.assertTrue(all(row["cape_agent"]["valid"]
               and row["windows_actual_hostname_proven"] is False for
               row in report["guests"]))
    def test_missing_guest_or_wrong_route_or_agent_denied(self):
        for broken,exception in (
             ("active_missing","complete approved"),
             ("wrong_routes","Wrong host route"),
             ("agent_failed","CAPE Agent admin HTTP"),
        ):
            host,p=self.plan(2,broken)
            with self.subTest(broken=broken),p[0],p[1],p[2],p[3],p[4],\
                 self.assertRaisesRegex(m.BatchAgentBlocked,exception):
                m.check("lab02",Path("/root/command2-identity-reservation.json"))
    def test_source_nic_saved_and_live_exact(self):
        row=guests(1)[0]
        self.assertTrue(m.nic_xml(guestxml(row),row))
        wrong=guestxml(row).replace('network="default"','network="other"')
        with self.assertRaises(m.BatchAgentBlocked):
            m.nic_xml(wrong,row)
        bad=guestxml(row).replace(row["mac_candidate"],"02:ff:00:00:00:01")
        with self.assertRaises(m.BatchAgentBlocked):
            m.nic_xml(bad,row)
    def test_lease_duplicate_parser_refuses(self):
        text=("2026-10-12 aa:bb:cc:dd:ee:01 ipv4 192.168.122.201/24\n")
        self.assertEqual(m.read_lease(text),
                         [("aa:bb:cc:dd:ee:01","192.168.122.201")])
        with self.assertRaises(m.BatchAgentBlocked):
            m.read_lease(text+text)
    def test_no_mutator_or_malware_release(self):
        s=Path(m.__file__).read_text(encoding="utf-8")
        for forbidden in ('"attach-interface"','"detach-interface"',
             '"net-update"','"snapshot-revert"','"snapshot-create"',
             '"shutdown"','"destroy"','"start"','os.replace(',
             'shell=True','Set-MpPreference'):
            self.assertNotIn(forbidden,s)
if __name__=="__main__":unittest.main()
