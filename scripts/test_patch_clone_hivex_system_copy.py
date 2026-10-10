#!/usr/bin/env python3
"""No actual hive/QCOW2 is edited in these tests."""
import unittest
from unittest.mock import patch
import patch_clone_hivex_system_copy as p

GUID="{bd7aa820-47b9-4dd6-a85f-db3bd6d77e74}"

class FakeHivex:
    def __init__(self):self.writes=[]
    def root(self):return "root"
    def node_set_value(self,node,record):self.writes.append((node,record))

class Tests(unittest.TestCase):
    def fixture(self):
        return {"controlset":1,
                "matched_static_interfaces":[{
                    "interface_guid":GUID,
                    "static_ipv4":p.OLD_IP,"subnet_mask":"255.255.255.0"}]}

    def test_hostname_static_ipv4_and_inetsim_dns_not_enabled(self):
        fake=FakeHivex()
        with patch.object(p.hiveins,"inspect",return_value=self.fixture()),\
             patch.object(p.hiveins,"require_child",
                          side_effect=lambda h,root,key:key):
            result=p.safely_patch(fake,p.OLD_IP,"192.168.240.101","WIN11-1")
        self.assertEqual(result["new_ip"],"192.168.240.101")
        self.assertFalse(result["guest_nic_hardware_mapping_verified"])
        self.assertEqual(len(fake.writes),9)
        changes={x["key"]:x for _,x in fake.writes}
        self.assertEqual(changes["IPAddress"]["value"],p.reg_multisz(["192.168.240.101"]))
        self.assertEqual(changes["DefaultGateway"]["value"],p.reg_multisz(["192.168.240.1"]))
        self.assertEqual(changes["NameServer"]["value"],p.reg_sz(""))
        self.assertEqual(changes["Hostname"]["value"],p.reg_sz("WIN11-1"))

    def test_gateway_address_reserved(self):
        with self.assertRaisesRegex(p.HivePatchBlocked,"conflicts"):
            p.safely_patch(FakeHivex(),p.OLD_IP,"192.168.240.1","WIN11-1")

    def test_old_ipv4_source_must_be_exact(self):
        with self.assertRaisesRegex(p.HivePatchBlocked,"previously"):
            p.safely_patch(FakeHivex(),"192.168.122.127","192.168.240.101","WIN11-1")

    def test_hostname_validation(self):
        with self.assertRaisesRegex(p.HivePatchBlocked,"hostname"):
            p.safely_patch(FakeHivex(),p.OLD_IP,"192.168.240.101","WIN11_1")

    def test_netbios_hostname_max_15(self):
        with self.assertRaisesRegex(p.HivePatchBlocked,"hostname"):
            p.safely_patch(FakeHivex(),p.OLD_IP,"192.168.240.101","SIXTEENCHARACTRS")

    def test_require_exactly_one_old_nic(self):
        data=self.fixture()
        data["matched_static_interfaces"]=[]
        with patch.object(p.hiveins,"inspect",return_value=data):
            with self.assertRaisesRegex(p.HivePatchBlocked,"Ambiguous"):
                p.safely_patch(FakeHivex(),p.OLD_IP,"192.168.240.101","WIN11-1")

    def test_nt_registry_multisz_utf16(self):
        self.assertEqual(p.reg_multisz(["192.168.240.101"]).decode("utf-16-le"),
                         "192.168.240.101\x00\x00")

if __name__=="__main__":unittest.main()
