"""Synthetic tests only; never reserve real DHCP or change libvirt."""
import json
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import command2_ssl55_nat_dhcp_reservation as s

BASE=("<network><name>default</name><forward mode='nat'/>"
      "<bridge name='virbr0'/>"
      "<ip address='192.168.122.1' netmask='255.255.255.0'>"
      "<dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp>"
      "</ip></network>")
EXACT="<host mac='02:ca:55:11:01:02' name='WIN11-1' ip='192.168.122.131'/>"
RESERVED=BASE.replace("</dhcp>",EXACT+"</dhcp>")
LEASE=("Expiry Time        MAC address        Protocol IP address Hostname\n"
       "2026-10-12 19:50:49 02:ca:55:11:01:02 ipv4 "
       "192.168.122.131/24 WIN11-1 01:02:ca:55:11:01:02")
DUAL={
    "vm":s.GUEST,"snapshot":s.dual.SNAP,
    "original_agent_still_reachable":True,
    "nat_agent_reachable":True,"old_adapter_detached":False,
    "nat_lease_observation":{
        "observed_nat_mac_lease_count":1,
        "observed_nat_ips_for_mac":["192.168.122.131"]}}
class DHCP(unittest.TestCase):
    def test_existing_default_nat_pool_is_within_same_subnet(self):
        from xml.etree import ElementTree as ET
        r=s.examine_network(ET.fromstring(BASE),"live")
        self.assertEqual(r["exact_guest_host_reservation_count"],0)
        rr=s.examine_network(ET.fromstring(RESERVED),"persistent")
        self.assertEqual(rr["exact_guest_host_reservation_count"],1)
        for conflict in (
            BASE.replace("</dhcp>",
                "<host mac='02:ca:55:11:01:02' name='X' ip='192.168.122.150'/>"
                "</dhcp>"),
            BASE.replace("</dhcp>",
                "<host mac='52:54:00:00:00:02' name='X' ip='192.168.122.131'/>"
                "</dhcp>"),
            BASE.replace("</dhcp>",
                "<host mac='52:54:00:00:00:02' name='WIN11-1' "
                "ip='192.168.122.190'/></dhcp>"),
        ):
            with self.subTest(xml=conflict),self.assertRaises(
                    s.ReservationBlocked):
                s.examine_network(ET.fromstring(conflict),"live")

    def test_plan_requires_exact_active_lease_and_two_agent_routes(self):
        state=[BASE]
        def virsh(*a):
            if a==("net-dhcp-leases","default"):return LEASE
            raise AssertionError(a)
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s.dual,"assess",return_value=DUAL),\
             patch.object(s.dual,"virsh",side_effect=virsh),\
             patch.object(s,"network_xml",side_effect=lambda inactive:(
                  __import__("xml.etree.ElementTree",fromlist=["fromstring"])
                    .fromstring(state[0]))):
            plan=s.inspect()
            self.assertEqual(plan["result"],
                "SSL55_WIN11_1_NAT_DHCP_RESERVATION_PLAN_ONLY")
            self.assertTrue(plan["host_cape_agent_at_nat_ip_verified"])
            self.assertFalse(plan["reservation_present_in_live_and_config"])
            state[0]=RESERVED
            verified=s.inspect()
            self.assertTrue(verified["reservation_present_in_live_and_config"])
            self.assertEqual(verified["result"],
                "SSL55_WIN11_1_NAT_DHCP_RESERVATION_VERIFIED")

    def test_readonly_blocks_conflicting_live_lease(self):
        lines=LEASE+("\n2026-10-12 19:52:00 52:54:00:ff:ff:ff ipv4 "
                      "192.168.122.131/24 OTHERVM")
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s.dual,"assess",return_value=DUAL),\
             patch.object(s.dual,"virsh",return_value=lines),\
             self.assertRaisesRegex(s.ReservationBlocked,"conflicting"):
            s.inspect()

    def test_live_and_persistent_half_applied_are_not_silently_retried(self):
        from xml.etree import ElementTree as ET
        with patch.object(s.os,"geteuid",return_value=0),\
             patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(s.dual,"assess",return_value=DUAL),\
             patch.object(s.dual,"virsh",return_value=LEASE),\
             patch.object(s,"network_xml",side_effect=lambda inactive:
                  ET.fromstring(BASE if inactive else RESERVED)),\
             self.assertRaisesRegex(s.ReservationBlocked,"inconsistent"):
            s.inspect()

    def test_exact_typed_apply_only_adds_one_host_in_both_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=[False]
            touched=[]
            from xml.etree import ElementTree as ET
            def v(*a):
                touched.append(a)
                if a[:1]==("net-update",):
                    self.assertEqual(a,("net-update","default","add",
                         "ip-dhcp-host",EXACT,"--live","--config"))
                    state[0]=True
                    return ""
                if a==("net-dhcp-leases","default"):
                    return LEASE
                raise AssertionError(a)
            original_stat=s.os.fstat
            fs=types.SimpleNamespace(st_uid=0,st_nlink=1,
                    st_mode=stat.S_IFREG|0o600)
            with patch.object(s,"LOCK",Path(tmp)/"reservation.lock"),\
                 patch.object(s.os,"fstat",return_value=fs),\
                 patch.object(s.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=s.APPROVE),\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(s.dual,"assess",return_value=DUAL),\
                 patch.object(s.dual,"virsh",side_effect=v),\
                 patch.object(s,"network_xml",side_effect=lambda inactive:
                     ET.fromstring(RESERVED if state[0] else BASE)):
                answer=s.apply()
            self.assertEqual(answer["result"],
                   "SSL55_NAT_IP_MAC_DHCP_RESERVATION_APPLIED_AND_VERIFIED")
            self.assertTrue(answer["reservation_present_in_live_and_config"])
            self.assertEqual(sum(a[0]=="net-update" for a in touched),1)

    def test_partial_update_marks_unknown_and_never_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            from xml.etree import ElementTree as ET
            attempted=[]
            def fail(*args):
                if args[0]=="net-update":
                    attempted.append(args)
                    raise s.dual.ReaddressBlocked("libvirt partial net update")
                if args[0]=="net-dhcp-leases":return LEASE
                raise AssertionError(args)
            fs=types.SimpleNamespace(st_uid=0,st_nlink=1,
                    st_mode=stat.S_IFREG|0o600)
            with patch.object(s,"LOCK",Path(tmp)/"reservation.lock"),\
                 patch.object(s.os,"fstat",return_value=fs),\
                 patch.object(s.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=s.APPROVE),\
                 patch.object(s.os,"geteuid",return_value=0),\
                 patch.object(s.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(s.dual,"assess",return_value=DUAL),\
                 patch.object(s.dual,"virsh",side_effect=fail),\
                 patch.object(s,"network_xml",return_value=ET.fromstring(BASE)),\
                 self.assertRaisesRegex(s.ReservationBlocked,
                                        "DHCP_NET_UPDATE_ATTEMPTED"):
                s.apply()
            self.assertEqual(len(attempted),1)

    def test_no_vm_snapshot_or_guest_mutators(self):
        src=Path(s.__file__).read_text()
        for forbidden in (
          'virsh("snapshot-revert"', 'virsh("snapshot-create"',
          'virsh("attach-interface"', 'virsh("detach-interface"',
          'virsh("shutdown"', 'virsh("destroy"','virsh("start"',
          'virsh("net-destroy"', 'os.replace(', 'shell=True'):
            self.assertNotIn(forbidden,src)
if __name__=="__main__":unittest.main()
