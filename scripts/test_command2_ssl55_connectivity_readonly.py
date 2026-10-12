"""Offline exact SSL55 network topology audit; never alter actual interfaces."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_connectivity_readonly as c
NAME=c.VM
UID=c.UUID
DOMAIN=('<domain type="kvm"><name>'+NAME+'</name><uuid>'+UID+'</uuid>'
        '<devices><interface type="network">'
        '<source network="cape-analysis-isolated"/>'
        '<mac address="02:0a:30:6a:3f:50"/></interface></devices></domain>')
NETWORK=('<network><name>cape-analysis-isolated</name><bridge name="cape-lab0"/>'
         '<port isolated="yes"/><dns enable="no"/>'
         '<ip address="192.168.240.1" netmask="255.255.255.0"/></network>')
NFT={"nftables":[
    {"chain":{"name":x}} for x in ["cape_forward","cape_input","cape_output"]
]+[{"rule":{"chain":"cape_forward"}} for _ in range(3)]}

class InternetTopology(unittest.TestCase):
    def test_current_isolated_network_deliberately_cannot_forward_to_internet(self):
        seen=c.inspect_network(NETWORK)
        self.assertFalse(seen["libvirt_nat_enabled"])
        self.assertFalse(seen["guest_real_public_internet_available_via_this_bridge"])
        self.assertFalse(seen["libvirt_dns_enabled"])
        self.assertTrue(c.view_domain(DOMAIN)["one_isolated_nic_only"])
        self.assertTrue(c.infer_firewall(json.dumps(NFT))["guard_chain_names_present"])

    def test_network_drift_refuses_nat_instead_of_editing_guest_or_guard(self):
        for n in [
            NETWORK.replace('<port isolated="yes"/>',''),
            NETWORK.replace('<dns enable="no"/>',''),
            NETWORK.replace("</network>",'<forward mode="nat"/></network>'),
            NETWORK.replace("cape-lab0","virbr0")
        ]:
            with self.subTest(xml=n),self.assertRaises(c.ConnectivityAuditBlocked):
                c.inspect_network(n)
        with self.assertRaises(c.ConnectivityAuditBlocked):
            c.view_domain(DOMAIN.replace(
                'source network="cape-analysis-isolated"',
                'source network="default"'))

    def test_readonly_full_report_proves_expected_missing_internet(self):
        def virsh(*a):
            if a==("domuuid",NAME):return UID
            if a[0]=="domuuid":
                return dict([c.MASTER,c.TRIAL])[a[1]]
            if a[0]=="domstate":
                return "running" if a[1]==NAME else "shut off"
            if a==("list","--name"):return NAME
            if a==("snapshot-list",NAME,"--name"):return c.SNAP
            if a[0]=="dumpxml":return DOMAIN
            if a==("net-dumpxml",c.NET):return NETWORK
            raise AssertionError(a)
        def command(*a):
            if a[:4]==("nft","-j","list","table"):return json.dumps(NFT)
            if a[:4]==("ip","-4","route","get"):return "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.2"
            if a[:3]==("sysctl","-n","net.ipv4.ip_forward"):return "0"
            raise AssertionError(a)
        with patch.object(c.os,"geteuid",return_value=0),\
             patch.object(c.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(c,"virsh",side_effect=virsh),\
             patch.object(c,"cmd",side_effect=command):
            result=c.assess()
        self.assertEqual(result["result"],
            "SSL55_WIN11_1_PUBLIC_INTERNET_ABSENCE_EXPLAINED_READONLY")
        self.assertTrue(result["fix_requires_separate_approved_benign_provisioning_profile"])
        self.assertFalse(result["network_or_firewall_modified"])
        self.assertEqual(result["snapshot"],c.SNAP)

    def test_no_vm_or_host_mutators(self):
        src=Path(c.__file__).read_text()
        for token in ('virsh("start"','virsh("shutdown"','virsh("net-update"',
                      'virsh("attach-interface"','virsh("snapshot-create"',
                      'virsh("snapshot-revert"','"nft","add"',
                      '"nft","delete"','"sysctl","-w"','shell=True',
                      'os.replace(', 'open("w"'):
            self.assertNotIn(token,src)

if __name__=="__main__":unittest.main()
