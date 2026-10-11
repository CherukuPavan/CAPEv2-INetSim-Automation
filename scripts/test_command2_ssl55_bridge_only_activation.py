"""Offline-only synthetic test: SSL55 isolated bridge activation, no guest NIC."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_bridge_only_activation as b


def protected():
    return {"no_vm_or_network_changes":True,
            "existing_lab_firewall":{"expected_guard_shape":True},
            "analysis_network":{"active":"no"},
            "protected_domains":{
                "win11":{"uuid_verified":True,"power_state":"shut off",
                         "nic_counts":{"inactive":1}},
                "win11_1":{"uuid_verified":True,"power_state":"shut off",
                           "nic_counts":{"inactive":0}},
                "win11_trial_1":{"uuid_verified":True,"power_state":"shut off",
                                 "nic_counts":{"inactive":0}}}}
BASIC={
    "result":"SSL55_EXISTING_BRIDGE_ACTIVATION_PLAN_ONLY",
    "original_host_nft_tables":[("inet","cape_analysis_guard")],
}
NET_INFO="Name: cape-analysis-isolated\nActive: yes\nAutostart: no"
NET_POST='<domain><devices/></domain>'


class BridgeActivationTests(unittest.TestCase):
    def test_preflight_no_network_change(self):
        with patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.socket,"gethostname",return_value="cse-ssl-55"),\
             patch.object(b.guard,"SENTINEL",Path(__file__).parent),\
             patch.object(b,"service",return_value={}),\
             patch.object(b,"protected",return_value=True),\
             patch.object(b,"network",return_value=True),\
             patch.object(b,"host_collision",return_value=True),\
             patch.object(b,"nft_table_inventory",
                         return_value=[("inet","cape_analysis_guard")]),\
             patch.object(b,"virsh",
                          side_effect=AssertionError("No mutations")):
            result=b.plan()
        self.assertFalse(result["network_started"])
        self.assertFalse(result["nic_attached"])
        self.assertFalse(result["host_changed"])

    def test_collision_refuses_existing_host_route(self):
        fake=lambda *args: (
            [{"ifname":"eno1","address":"00:aa:bb:cc:dd:ee"}]
            if args==("ip","-j","link","show") else
            [{"dst":"192.168.240.0/24","dev":"docker0"}]
            if args==("ip","-j","-4","route","show","table","all") else
            [{"ifname":"eno1","addr_info":[]}]
        )
        with patch.object(b,"get_json",side_effect=fake):
            with self.assertRaisesRegex(b.BridgeBlocked,"collides"):
                b.host_collision()

    def test_live_vm_blocks_before_network(self):
        with patch.object(b.guard,"audit",return_value=protected()),\
             patch.object(b.boot,"domain_autostart",return_value=False),\
             patch.object(b,"virsh",return_value="win11_2"):
            with self.assertRaisesRegex(b.BridgeBlocked,"active"):
                b.protected()

    def test_no_reboot_guard_service_refuses_start(self):
        with patch.object(b,"read",return_value=(
            "LoadState=loaded\nUnitFileState=enabled\n"
            "ActiveState=inactive\nResult=success\nExecMainStatus=0\n"
            "ConditionResult=no")):
            with self.assertRaisesRegex(b.BridgeBlocked,"did not successfully"):
                b.service()

    def test_bad_port_l2_isolation_blocks_network(self):
        xml=('<network><name>cape-analysis-isolated</name>'
             '<bridge name="cape-lab0"/>'
             '<port isolated="no"/><dns enable="no"/>'
             '<ip address="192.168.240.1" netmask="255.255.255.0"/></network>')
        def virsh(*args):
            if args[0]=="net-info":
                return "Active: no\nAutostart: no\nPersistent: yes\nBridge: cape-lab0"
            return xml
        with patch.object(b,"virsh",side_effect=virsh):
            with self.assertRaisesRegex(b.BridgeBlocked,"L2"):
                b.network()

    def test_operator_refusal_leaves_bridge_inactive(self):
        with patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.sys.stdin,"isatty",return_value=True),\
             patch.object(b,"plan",return_value=BASIC),\
             patch("builtins.input",return_value="NO"),\
             patch.object(b,"virsh",
                          side_effect=AssertionError("No network start")):
            with self.assertRaisesRegex(b.BridgeBlocked,"No operator"):
                b.activate()

    def test_single_approved_net_start_no_vm_no_nic_no_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            invoked=[]
            def virsh(*args):
                invoked.append(args)
                if args==("net-start",b.NET):return "Network started"
                if args==("net-info",b.NET):return NET_INFO
                if args==("list","--name"):return ""
                if args[0]=="dumpxml":return NET_POST
                raise AssertionError("Unexpected virsh "+str(args))
            def getjson(*args):
                if args==("ip","-j","link","show"):
                    return [{"ifname":b.BRIDGE}]
                if args==("ip","-j","-4","addr","show"):
                    return [{"ifname":b.BRIDGE,"addr_info":[{
                        "family":"inet","local":b.BRIDGE_IP,"prefixlen":24}]}]
                if args==("ip","-j","-6","addr","show","dev",b.BRIDGE):
                    return [{"ifname":b.BRIDGE,"addr_info":[{
                        "family":"inet6","scope":"link"}]}]
                raise AssertionError("Unexpected ip "+str(args))
            lock=Path(td)/"lock"
            meta=type("FakeRootLock",(),{"st_mode":0o100600,
                  "st_uid":0,"st_nlink":1})()
            with patch.object(b.os,"geteuid",return_value=0),\
                 patch.object(b.os,"fstat",return_value=meta),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch.object(b,"plan",return_value=BASIC),\
                 patch.object(b,"LOCK",lock),\
                 patch("builtins.input",return_value=
                       "START-ISOLATED-BRIDGE-ONLY-SSL55"),\
                 patch.object(b,"virsh",side_effect=virsh),\
                 patch.object(b,"get_json",side_effect=getjson),\
                 patch.object(b,"nft_table_inventory",
                       return_value=BASIC["original_host_nft_tables"]),\
                 patch.object(b,"read",return_value="{}"),\
                 patch.object(b.guard,"guard_policy_structure",
                              return_value={}):
                result=b.activate()
        self.assertTrue(result["bridge_started"])
        self.assertFalse(result["cape_analysis_authorized"])
        self.assertFalse(result["snapshot_capture_authorized"])
        self.assertEqual([a for a in invoked if a[0]=="net-start"],
                         [("net-start",b.NET)])
        self.assertFalse(any(a[0] in ("attach-interface","start","snapshot-create-as")
                             for a in invoked))

    def test_unexpected_nft_table_after_start_reports_partial_state(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            def virsh(*args):
                calls.append(args)
                if args[0]=="net-start":return "started"
                if args[0]=="net-info":return NET_INFO
                if args[0]=="list":return ""
                if args[0]=="dumpxml":return NET_POST
                raise AssertionError("Unexpected "+str(args))
            def getjson(*args):
                if args[0:3]==("ip","-j","link"):return [{"ifname":b.BRIDGE}]
                if "-4" in args:return [{"ifname":b.BRIDGE,
                    "addr_info":[{"family":"inet","local":b.BRIDGE_IP,
                                  "prefixlen":24}]}]
                return [{"addr_info":[]}]
            meta=type("Lock",(),{"st_mode":0o100600,"st_uid":0,"st_nlink":1})()
            with patch.object(b.os,"geteuid",return_value=0),\
                 patch.object(b.os,"fstat",return_value=meta),\
                 patch.object(b.sys.stdin,"isatty",return_value=True),\
                 patch.object(b,"plan",return_value=BASIC),\
                 patch.object(b,"LOCK",Path(td)/"lock"),\
                 patch("builtins.input",return_value=
                       "START-ISOLATED-BRIDGE-ONLY-SSL55"),\
                 patch.object(b,"virsh",side_effect=virsh),\
                 patch.object(b,"get_json",side_effect=getjson),\
                 patch.object(b.guard,"guard_policy_structure",
                              return_value={}),\
                 patch.object(b,"read",return_value="{}"),\
                 patch.object(b,"nft_table_inventory",
                              return_value=[("inet","cape_analysis_guard"),
                                            ("ip","unexpected")]):
                with self.assertRaisesRegex(b.BridgeBlocked,"PARTIAL"):
                    b.activate()
        self.assertEqual(calls.count(("net-start",b.NET)),1)
        self.assertEqual(len([a for a in calls if a[0]=="attach-interface"]),0)

    def test_source_has_no_guest_or_firewall_mutators(self):
        src=Path(b.__file__).read_text()
        for val in ('"attach-interface"', '"net-define"', '"nft","--file"',
                    '"systemctl","enable"', '"snapshot-create-as"',
                    '"destroy"', '"shutdown"', '"domstart"'):
            self.assertNotIn(val,src)


if __name__=="__main__":
    unittest.main()
