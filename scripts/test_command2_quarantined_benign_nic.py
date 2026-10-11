"""All mocked: quarantined link for benign tests without circular acceptance."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import command2_quarantined_benign_nic as q
import command2_guarded_isolated_nic as nic

HOST="approved-lab"
VM="win11_1"
UID="2981f61e-55fb-45a2-b889-26f037c08323"
MAC="02:20:30:40:50:60"
NET="192.168.240.0/24"
XML='<domain><name>win11_1</name><devices/></domain>'

def args():
    return (VM,HOST,UID,MAC,NET,"/synthetic-proof")

def fake_virsh(*argv):
    if argv==("list","--all","--name"):return "win11\nwin11_1"
    if argv==("domstate","win11"):return "shut off"
    if argv==("domstate","win11_1"):return "shut off"
    if argv==("dumpxml","--inactive","win11"):
        return '<domain><name>win11</name><devices><interface><mac address="52:54:00:00:00:ee"/></interface></devices></domain>'
    if argv==("dumpxml","--inactive","win11_1"):return XML
    raise AssertionError("Wrong libvirt invocation "+str(argv))

def fake_host(*argv,**kw):
    if argv==("ip","-j","link","show"):
        return '[{"ifname":"eno1","address":"00:ab:cd:ef:12:34"}]'
    if argv==("ip","-j","-4","route","show","table","all"):
        return '[{"dst":"192.168.240.0/24","dev":"cape-lab0"},{"dst":"10.23.96.0/20","dev":"eno1"}]'
    raise AssertionError("Unexpected ip command "+str(argv))

def patch_plan():
    return patch.multiple(nic)

class BenignQualificationTests(unittest.TestCase):
    def test_host_mac_route_inventory_checks_success(self):
        with patch.object(nic,"virsh",side_effect=fake_virsh),\
             patch.object(nic,"cmd",side_effect=fake_host):
            self.assertTrue(q.collision_check(VM,MAC,NET))

    def test_mac_collision_refused(self):
        def colliding(*a,**kw):
            if a[2:3]==("link",):
                return '[{"ifname":"eno1","address":"'+MAC+'"}]'
            return fake_host(*a,**kw)
        with patch.object(nic,"virsh",side_effect=fake_virsh),\
             patch.object(nic,"cmd",side_effect=colliding):
            with self.assertRaisesRegex(q.BenignNicBlocked,"MAC already"):
                q.collision_check(VM,MAC,NET)

    def test_nonbridge_subnet_route_overlap_refused(self):
        def colliding(*a,**kw):
            if a[2:3]==("-4",):
                return '[{"dst":"192.168.240.0/24","dev":"docker0"}]'
            return fake_host(*a,**kw)
        with patch.object(nic,"virsh",side_effect=fake_virsh),\
             patch.object(nic,"cmd",side_effect=colliding):
            with self.assertRaisesRegex(q.BenignNicBlocked,"overlaps"):
                q.collision_check(VM,MAC,NET)

    def test_incomplete_host_inventory_never_implies_safe(self):
        with patch.object(nic,"virsh",side_effect=fake_virsh),\
             patch.object(nic,"cmd",return_value="not-json"):
            with self.assertRaisesRegex(q.BenignNicBlocked,"Unverifiable"):
                q.collision_check(VM,MAC,NET)

    def test_plan_can_observe_host_without_claiming_analysis_approval(self):
        with patch.object(nic,"guard_host"),\
             patch.object(nic,"vm_identity",return_value=(
                 "192.168.240.101","192.168.240.1")),\
             patch.object(nic,"verify_clone_no_nic",return_value=XML),\
             patch.object(nic,"verify_network_live",return_value=True),\
             patch.object(q,"collision_check",return_value=True),\
             patch.object(q,"approval",return_value=True):
            report=q.plan(*args())
        self.assertEqual(report["result"],"COMMAND2_QUARANTINED_BENIGN_NIC_PLAN_ONLY")
        self.assertTrue(report["no_network_or_vm_changes"])
        self.assertTrue(report["approved_host_only_receipt"])
        self.assertFalse(report["cape_analysis_authorized"])
        self.assertFalse(report["running_snapshot_authorized"])

    def test_ssl55_guard_reused_before_mutation(self):
        with patch.object(nic.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(nic,"virsh",side_effect=AssertionError("No libvirt")):
            with self.assertRaisesRegex(nic.NicBlocked,"SSL55_REFERENCE_ONLY"):
                q.attach_for_benign_test(VM,"cse-ssl-55",UID,MAC,NET,"/fake")

    def test_declined_operator_authorization_never_attaches(self):
        with patch.object(nic,"guard_host"),\
             patch.object(q.os,"geteuid",return_value=0),\
             patch.object(q.sys.stdin,"isatty",return_value=True),\
             patch.object(q,"plan",return_value={
                 "approved_host_only_receipt":True}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(nic,"virsh",side_effect=AssertionError("No NIC attach")):
            with self.assertRaisesRegex(q.BenignNicBlocked,"Operator"):
                q.attach_for_benign_test(*args())

    def test_attach_quarantine_is_config_only_without_boot(self):
        observed=[]
        def fake(*argv):
            observed.append(argv)
            if argv[0]=="attach-interface":
                self.assertIn("--config",argv)
                self.assertNotIn("--live",argv)
                self.assertIn("e1000e",argv)
                return ""
            if argv==("dumpxml","--inactive",VM):
                return '<domain><devices><interface type="network"><source network="cape-analysis-isolated"/><mac address="'+MAC+'"/></interface></devices></domain>'
            if argv==("domstate",VM):return "shut off"
            raise AssertionError("Unexpected libvirt command "+str(argv))
        with tempfile.TemporaryDirectory() as td:
            with patch.object(nic,"guard_host"),\
                 patch.object(q.os,"geteuid",return_value=0),\
                 patch.object(q.os,"fstat",return_value=type(
                     "LockStat",(),{"st_mode":0o100600,"st_uid":0,
                                   "st_nlink":1})()),\
                 patch.object(q.sys.stdin,"isatty",return_value=True),\
                 patch.object(q,"LOCK",Path(td)/"benign.lock"),\
                 patch.object(q,"plan",return_value={
                     "approved_host_only_receipt":True}),\
                 patch("builtins.input",
                       return_value="ATTACH-QUARANTINED-BENIGN-WIN11_1"),\
                 patch.object(nic,"virsh",side_effect=fake):
                report=q.attach_for_benign_test(*args())
        self.assertEqual(report["result"],
            "COMMAND2_QUARANTINED_NIC_ATTACHED_SHUTOFF_BENIGN_ONLY")
        self.assertFalse(report["cape_analysis_authorized"])
        self.assertFalse(report["snapshot_authorized"])
        self.assertEqual(len([x for x in observed if x[0]=="attach-interface"]),1)
        self.assertFalse(any(x[0] in ("start","shutdown","net-start","destroy")
                             for x in observed))

    def test_no_root_or_tty_never_attaches(self):
        with patch.object(nic,"guard_host"),\
             patch.object(q.os,"geteuid",return_value=1000),\
             patch.object(nic,"virsh",side_effect=AssertionError("No guest access")):
            with self.assertRaisesRegex(q.BenignNicBlocked,"root"):
                q.attach_for_benign_test(*args())

if __name__=="__main__":
    unittest.main()
