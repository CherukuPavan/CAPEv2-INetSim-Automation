"""Offline-only guest NIC attachment tests. ZERO actual host changes."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_guarded_isolated_nic as n

VM="win11_1"
HOST="approved-target"
UUID="c84db20f-19b6-4a32-9609-a334ca4c37ad"
MAC="02:10:20:30:40:50"
SUBNET="192.168.240.0/24"
NETWORKXML=('<network><name>cape-analysis-isolated</name>'
            '<bridge name="cape-lab0"/><port isolated="yes"/><dns enable="no"/>'
            '<ip address="192.168.240.1" netmask="255.255.255.0"/>'
            '</network>')
NFT='''table inet cape_analysis_cmd2_guard {
 chain cape_guest_forward {
  type filter hook forward priority -150; policy accept;
  iifname "cape-lab0" counter packets 0 bytes 0 drop
 }
 chain cape_guest_input {
  type filter hook input priority -150; policy accept;
  iifname "cape-lab0" meta nfproto ipv6 counter packets 0 bytes 0 drop
  iifname "cape-lab0" ip daddr != 192.168.240.1 counter packets 0 bytes 0 drop
 }
}'''
DISK=('/images/win11_1.command2.qcow2')
NV='/nvram/win11_1.command2_VARS.fd'

def guest_xml(nic=""):
    return ('<domain type="kvm"><name>win11_1</name>'
            '<uuid>'+UUID+'</uuid>'
            '<os><nvram>'+NV+'</nvram></os>'
            '<devices><disk device="disk"/><tpm><backend type="emulator" version="2.0"/></tpm>'
            +nic+'</devices></domain>')

def faux_virsh(*a):
    if a==("net-info","cape-analysis-isolated"):
        return "Active: yes\nPersistent: yes"
    if a==("net-dumpxml","cape-analysis-isolated"):
        return NETWORKXML
    if a==("domuuid",VM):return UUID
    if a==("domstate",VM):return "shut off"
    if a==("dumpxml","--inactive",VM):
        return guest_xml()
    raise AssertionError("Unexpected host libvirt request "+str(a))


class AttachTests(unittest.TestCase):
    def test_legacy_and_first_boot_receipts_remain_strictly_separate(self):
        import json
        import os
        import stat
        base={"approved_host":HOST,"vm":VM,"uuid":UUID,"mac":MAC,
              "guest_ip":"192.168.240.101","operator":"test-operator",
              **{f:True for f in n.PROOF_FIELDS}}
        with tempfile.TemporaryDirectory() as td:
            receipt=Path(td)/"receipt.json"
            original_stat=Path.stat
            def root_owned(path,*args,**kwargs):
                value=original_stat(path,*args,**kwargs)
                data=list(value)
                data[4]=0
                return os.stat_result(data)
            def check(record):
                receipt.write_text(json.dumps(record),encoding="utf-8")
                receipt.chmod(0o600)
                return n.read_acceptance_receipt(str(receipt),VM,UUID,MAC,
                                                  "192.168.240.101",HOST)
            with patch.object(Path,"stat",root_owned):
                legacy={**base,
                        "kind":"COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V1"}
                self.assertTrue(check(legacy))
                with self.assertRaisesRegex(n.NicBlocked,"zero-NIC"):
                    check({**legacy,"windows_zero_nic_identity_verified":False})
                initial={**base,
                         "kind":"COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V2",
                         "windows_zero_nic_identity_verified":False,
                         "source_master_uuid":
                             "12345678-1234-4234-8234-000000000002",
                         "source_master_runner_sha256":"a"*64,
                         "source_master_personalizer_sha256":"b"*64,
                         **{f:True for f in n.BOOTSTRAP_FIRST_PROOF_FIELDS}}
                self.assertTrue(check(initial))
                for bad in (
                    {**initial,"windows_zero_nic_identity_verified":True},
                    {**initial,"source_master_runner_sha256":"not-a-hash"},
                    {**initial,"source_master_uuid":UUID},
                    {**initial,"one_nic_firstboot_pending":False},
                    {**initial,"host_ipv6_external_egress_negative_test":False},
                    {**initial,"l2_lateral_guest_containment_verified":False},
                ):
                    with self.assertRaises(n.NicBlocked):
                        check(bad)
                with self.assertRaises(n.NicBlocked):
                    check({**initial,"kind":"COMMAND2_FAKE_ACCEPTANCE_V3"})

    def test_plan_exact_vm_no_network_changes(self):
        with patch.object(n.socket,"gethostname",return_value=HOST),\
             patch.object(n,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
             patch.object(n,"virsh",side_effect=faux_virsh) as calls,\
             patch.object(n,"cmd",return_value=NFT),\
             patch.object(n,"read_acceptance_receipt",return_value=True):
            value=n.plan(VM,HOST,UUID,MAC,SUBNET,"/mock/receipt")
        self.assertTrue(value["acceptance_receipt_checked"])
        self.assertFalse(value["nic_attached"])
        self.assertFalse(value["runtime_egress_proved_by_this_tool"])
        self.assertNotIn("attach-interface",str(calls.call_args_list))

    def test_reference_and_renamed_reference_block_before_virsh(self):
        for name,present in (("cse-ssl-55",False),(HOST,True)):
            with patch.object(n.socket,"gethostname",return_value=name),\
                 patch.object(n,"SENTINEL", Path(__file__).parent if present else
                      Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
                 patch.object(n,"virsh",side_effect=AssertionError("No host access")):
                with self.assertRaisesRegex(n.NicBlocked,"SSL55_REFERENCE_ONLY"):
                    n.plan(VM,name,UUID,MAC,SUBNET)

    def test_unreviewed_subnet_or_vm_rejected(self):
        for vm,subnet in (("win11_17",SUBNET),
                          (VM,"8.8.8.0/24"),
                          (VM,"169.254.0.0/24"),
                          (VM,"192.168.122.0/24")):
            with self.subTest(vm=vm,subnet=subnet),self.assertRaises(n.NicBlocked):
                n.vm_identity(vm,UUID,MAC,subnet)

    def test_network_unsafe_nat_forward_dhcp_and_inactive_rejected(self):
        for text in (NETWORKXML.replace("</network>","<forward mode=\"nat\"/></network>"),
                     NETWORKXML.replace("</network>","<dhcp/></network>"),
                     NETWORKXML.replace("cape-lab0","virbr0")):
            with patch.object(n,"virsh",side_effect=lambda *a:
                    text if a[0]=="net-dumpxml" else faux_virsh(*a)),\
                 patch.object(n,"cmd",return_value=NFT):
                with self.assertRaises(n.NicBlocked):
                    n.verify_network_live(SUBNET,"192.168.240.1")
        with patch.object(n,"virsh",side_effect=lambda *a:
                "Active: no\nPersistent: yes" if a[0]=="net-info" else faux_virsh(*a)):
            with self.assertRaisesRegex(n.NicBlocked,"inactive"):
                n.verify_network_live(SUBNET,"192.168.240.1")

    def test_missing_or_disabled_linux_port_isolation_blocks_attach(self):
        for unsafe in (
            NETWORKXML.replace('<port isolated="yes"/>',''),
            NETWORKXML.replace('<port isolated="yes"/>','<port isolated="no"/>')):
            with patch.object(n,"virsh",side_effect=lambda *a:
                 unsafe if a[0]=="net-dumpxml" else faux_virsh(*a)), \
                 patch.object(n,"cmd",return_value=NFT):
                with self.assertRaisesRegex(n.NicBlocked,"port isolation"):
                    n.verify_network_live(SUBNET,"192.168.240.1")

    def test_guard_rules_must_include_input_ipv6_and_ipv4(self):
        for bad in (NFT.replace("meta nfproto ipv6","meta nfproto ip"),
                    NFT.replace("daddr != 192.168.240.1","daddr != 192.168.240.2"),
                    NFT.replace("priority -150","priority 0")):
            with patch.object(n,"virsh",side_effect=faux_virsh),\
                 patch.object(n,"cmd",return_value=bad):
                with self.assertRaises(n.NicBlocked):
                    n.verify_network_live(SUBNET,"192.168.240.1")

    def test_guest_must_be_shutoff_no_nics_and_independent(self):
        badnic='<interface type="network"><source network="default"/></interface>'
        with patch.object(n,"virsh",side_effect=lambda *a:
                 guest_xml(badnic) if a==("dumpxml","--inactive",VM) else faux_virsh(*a)):
            with self.assertRaisesRegex(n.NicBlocked,"already has NIC"):
                n.verify_clone_no_nic(VM,UUID)

    def test_attach_no_receipt_refused(self):
        with patch.object(n.socket,"gethostname",return_value=HOST),\
             patch.object(n,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
             patch.object(n.os,"geteuid",return_value=0),\
             patch.object(n.sys.stdin,"isatty",return_value=True),\
             patch.object(n,"plan",return_value={"acceptance_receipt_checked":False}),\
             patch.object(n,"virsh",side_effect=AssertionError("No write")):
            with self.assertRaisesRegex(n.NicBlocked,"receipt"):
                n.attach(VM,HOST,UUID,MAC,SUBNET,"/fake")

    def test_attach_single_saved_interface_mock(self):
        interfaces={"added":False}
        def virsh(*a):
            if a[0]=="attach-interface":
                self.assertIn("--config",a)
                self.assertNotIn("--live",a)
                self.assertIn("e1000e",a)
                interfaces["added"]=True
                return ""
            if a==("domstate",VM):return "shut off"
            if a==("dumpxml","--inactive",VM):
                nic=('<interface type="network"><source network="cape-analysis-isolated"/>'
                     f'<mac address="{MAC}"/></interface>') if interfaces["added"] else ""
                return guest_xml(nic)
            return faux_virsh(*a)
        with tempfile.TemporaryDirectory() as temp:
            lock=Path(temp)/"nic.lock"
            with patch.object(n.socket,"gethostname",return_value=HOST),\
                 patch.object(n,"SENTINEL",Path(__file__).with_name("_no_ssl55_sentinel_")) ,\
                 patch.object(n.os,"geteuid",return_value=0),\
                 patch.object(n.os,"fstat",return_value=type(
                     "RootLock",(),{"st_mode":0o100600,
                                    "st_uid":0,"st_nlink":1})()),\
                 patch.object(n.sys.stdin,"isatty",return_value=True),\
                 patch.object(n,"LOCK",lock),\
                 patch.object(n,"plan",return_value={"acceptance_receipt_checked":True}),\
                 patch.object(n,"virsh",side_effect=virsh),\
                 patch("builtins.input",return_value="ATTACH-CAPE-ONLY-WIN11_1"):
                report=n.attach(VM,HOST,UUID,MAC,SUBNET,"/fake")
        self.assertEqual(report["result"],"COMMAND2_SINGLE_ISOLATED_NIC_SAVED_NOT_BOOTED")
        self.assertTrue(interfaces["added"])
        self.assertFalse(report["snapshot_created"])
        self.assertFalse(report["guest_ip_applied_in_windows"])

    def test_no_firewall_or_libvirt_network_mutation(self):
        code=Path(n.__file__).read_text()
        for bad in ('"net-start"','"net-define"','"nft","add"',
                    '"nft","-f"','"start"','"shutdown"','"destroy"'):
            self.assertNotIn(bad,code)


if __name__=="__main__":
    unittest.main()
