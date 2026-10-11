"""Synthetic-only SSL55 win11_1 benign NIC attach regression; no VM touched."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import command2_ssl55_win11_1_benign_nic as x

NO_NIC_XML=(
    '<domain type="kvm"><name>win11_1</name><uuid>'+x.UUID+'</uuid>'
    '<os><nvram>'+x.EXPECTED_NVRAM+'</nvram></os>'
    '<devices><disk device="disk" type="file"><driver type="qcow2"/>'
    '<source file="'+x.EXPECTED_DISK+'"/></disk>'
    '<tpm><backend type="emulator" version="2.0"/></tpm></devices></domain>')
WITH_NIC_XML=NO_NIC_XML.replace('</devices>',(
    '<interface type="network"><source network="'+x.NET+'"/>'
    '<mac address="'+x.MAC+'"/><model type="e1000e"/></interface>'
    '</devices>'))
NET_XML=(
    '<network><name>'+x.NET+'</name><bridge name="'+x.BRIDGE+'"/>'
    '<port isolated="yes"/><dns enable="no"/>'
    '<ip address="'+x.BRIDGE_IP+'" netmask="255.255.255.0"/>'
    '</network>')


class NicTests(unittest.TestCase):
    def test_exact_zero_nic_clone_definition_and_uuid(self):
        def v(*args):
            if args[0]=="domuuid": return x.UUID
            if args[0]=="domstate":return "shut off"
            if args[0]=="dumpxml":return NO_NIC_XML
            raise AssertionError(args)
        with patch.object(x,"virsh",side_effect=v):
            self.assertIn("win11_1.command2.qcow2",
                          x.xml_clone_without_nic())

    def test_existing_or_wrong_nic_definition_refused(self):
        with patch.object(x,"virsh",side_effect=lambda *a:
             x.UUID if a[0]=="domuuid" else "shut off" if a[0]=="domstate"
             else WITH_NIC_XML):
            with self.assertRaisesRegex(x.BenignBlocked,"already has a NIC"):
                x.xml_clone_without_nic()

    def test_plan_no_guest_writes(self):
        with patch.object(x,"guard_and_guests",return_value=True),\
             patch.object(x,"xml_clone_without_nic",return_value=NO_NIC_XML),\
             patch.object(x,"virsh",side_effect=lambda *a:
                 "" if a[0]=="snapshot-list" else
                 (_ for _ in ()).throw(AssertionError("No VM writes"))):
            result=x.plan()
        self.assertEqual(result["result"],
                         "SSL55_WIN11_1_BENIGN_NIC_CONFIG_PLAN_ONLY")
        self.assertFalse(result["nic_connected"])
        self.assertFalse(result["analysis_authorized"])
        self.assertFalse(result["host_changed"])

    def test_snapshot_already_exists_refuses_nic_mutation(self):
        with patch.object(x,"guard_and_guests",return_value=True),\
             patch.object(x,"xml_clone_without_nic",return_value=NO_NIC_XML),\
             patch.object(x,"virsh",return_value="cape_ready_win11_1"):
            with self.assertRaisesRegex(x.BenignBlocked,"Unexpected clone snapshots"):
                x.plan()

    def test_wrong_network_isolation_port_refused(self):
        bad=NET_XML.replace('isolated="yes"','isolated="no"')
        def v(*a):
            return ("Active: yes\nAutostart: no\nPersistent: yes\nBridge: cape-lab0"
                    if a[0]=="net-info" else bad)
        with patch.object(x,"virsh",side_effect=v):
            with self.assertRaisesRegex(x.BenignBlocked,"refuses NAT"):
                x.checked_network()

    def test_unexpected_host_port_refuses_guest_connection(self):
        def v(*a):
            return ("Active: yes\nAutostart: no\nPersistent: yes\nBridge: cape-lab0"
                    if a[0]=="net-info" else NET_XML)
        def data(*args):
            if args==("ip","-j","link","show"):
                return [{"ifname":x.BRIDGE}]
            if args==("ip","-j","-4","addr","show"):
                return [{"ifname":x.BRIDGE,"addr_info":[{
                    "family":"inet","local":x.BRIDGE_IP,"prefixlen":24}]}]
            if args==("ip","-j","-4","route","show","table","all"):
                return [{"dst":str(x.SUBNET),"dev":x.BRIDGE}]
            if args==("ip","-j","-6","addr","show","dev",x.BRIDGE):
                return [{"addr_info":[]}]
            if args==("bridge","-j","link","show","master",x.BRIDGE):
                return [{"ifname":"vnet5"}]
            raise AssertionError(args)
        with patch.object(x,"virsh",side_effect=v),\
             patch.object(x,"read_json",side_effect=data):
            with self.assertRaisesRegex(x.BenignBlocked,"already has ports"):
                x.checked_network()

    def test_service_inactive_or_other_running_vm_blocks(self):
        with patch.object(x.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(x.guard,"SENTINEL",Path(__file__).parent),\
             patch.object(x.os,"geteuid",return_value=0),\
             patch.object(x.guard,"protected_domains",return_value={
                 "win11":{"power_state":"shut off","nic_counts":{"inactive":1}},
                 "win11_1":{"power_state":"shut off","nic_counts":{"inactive":0}},
                 "win11_trial_1":{"power_state":"shut off","nic_counts":{"inactive":0}}}),\
             patch.object(x.boot,"domain_autostart",return_value=False),\
             patch.object(x,"virsh",return_value="another_guest"):
            with self.assertRaisesRegex(x.BenignBlocked,"Another libvirt"):
                x.guard_and_guests()

    def test_declined_operator_attachment_never_mutates(self):
        with patch.object(x.sys.stdin,"isatty",return_value=True),\
             patch.object(x,"plan",return_value={}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(x,"virsh",
                          side_effect=AssertionError("No attach")):
            with self.assertRaisesRegex(x.BenignBlocked,"not authorized"):
                x.attach()

    def test_exactly_one_config_only_nic_attached_benign_never_boot(self):
        command_log=[]
        def v(*a):
            command_log.append(a)
            if a[0]=="attach-interface":
                self.assertEqual(a,(
                    "attach-interface","--domain",x.VM,"--type","network",
                    "--source",x.NET,"--model","e1000e","--mac",x.MAC,
                    "--config"))
                return ""
            if a==("dumpxml","--inactive",x.VM):return WITH_NIC_XML
            if a[0]=="dumpxml":return "PRESERVED_OTHER_XML"
            if a==("list","--name"):return ""
            if a==("domstate",x.VM):return "shut off"
            if a[0]=="snapshot-list":return ""
            raise AssertionError(a)
        with tempfile.TemporaryDirectory() as td:
            lock=Path(td)/"nic.lock"
            meta=type("RootLock",(),{"st_mode":0o100600,
                   "st_uid":0,"st_nlink":1})()
            with patch.object(x.sys.stdin,"isatty",return_value=True),\
                 patch.object(x.os,"fstat",return_value=meta),\
                 patch.object(x,"LOCK",lock),\
                 patch.object(x,"plan",return_value={"ok":True}),\
                 patch.object(x,"virsh",side_effect=v),\
                 patch.object(x.boot,"domain_autostart",return_value=False),\
                 patch("builtins.input",return_value=x.CONFIRM):
                result=x.attach()
        self.assertEqual(result["result"],
                         "SSL55_WIN11_1_BENIGN_ONLY_NIC_SAVED_SHUTOFF")
        self.assertFalse(result["malware_analysis_authorized"])
        self.assertFalse(result["guest_ipv4_static_applied"])
        self.assertFalse(result["snapshot_created"])
        self.assertEqual(sum(1 for c in command_log if c[0]=="attach-interface"),1)
        self.assertFalse(any(c[0] in ("start","shutdown","net-start",
                                     "snapshot-create-as")
                             for c in command_log))

    def test_unexpected_postchange_refuses_repeat_and_reports_partial(self):
        with tempfile.TemporaryDirectory() as td:
            meta=type("RootLock",(),{"st_mode":0o100600,
                   "st_uid":0,"st_nlink":1})()
            with patch.object(x.sys.stdin,"isatty",return_value=True),\
                 patch.object(x.os,"fstat",return_value=meta),\
                 patch.object(x,"LOCK",Path(td)/"nic.lock"),\
                 patch.object(x,"plan",return_value={"ok":True}),\
                 patch("builtins.input",return_value=x.CONFIRM),\
                 patch.object(x,"virsh",side_effect=lambda *a:
                     "" if a[0]=="attach-interface" else
                     '<domain><devices/></domain>' if a[0]=="dumpxml"
                     else "shut off"):
                with self.assertRaisesRegex(x.BenignBlocked,"PARTIAL"):
                    x.attach()

    def test_source_restricts_action_to_saved_guest_nic(self):
        code=Path(x.__file__).read_text()
        for forbidden in ('"snapshot-create-as"', '"net-start"',
                          '"nft","--file"', '"start"', '"shutdown"',
                          '"net-define"', '"destroy"'):
            self.assertNotIn(forbidden,code)


if __name__=="__main__":
    unittest.main()
