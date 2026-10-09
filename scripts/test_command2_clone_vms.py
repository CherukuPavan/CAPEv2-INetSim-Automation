#!/usr/bin/env python3
"""No host mutations: CAPE config mapping and Command2 identity-plan tests."""
import copy
import unittest
from unittest.mock import patch
import register_cape_clones as cape
import command2_clone_vms as c

KVM="""# preserve this comment
[kvm]
machines = cuckoo1
interface = virbr0
dsn = qemu:///system

[cuckoo1]
label = cuckoo1
ip = 198.51.100.105
platform = windows
arch = x64
# keep this machine comment
"""

PROFILE={
 "schema":"cape-command2-profile-v1",
 "master":"win11","snapshot":"finalshutoffversion",
 "network":"cape-isolated", "disk_dir":"/var/lib/libvirt/images/cape-clones",
 "nvram_dir":"/var/lib/libvirt/qemu/nvram",
 "old_ipv4":"198.51.100.105","first_ipv4":"198.51.100.110",
 "mask":"255.255.255.0","gateway":"198.51.100.1",
 "dns":"198.51.100.2","cape_config":"/opt/CAPEv2/conf/kvm.conf",
 "snapshot_name":"cape_clean", "reserved_ipv4":["198.51.100.120"]
}

class CAPEConfigTests(unittest.TestCase):
    def test_preserves_comments_and_retains_real_machines(self):
        entries=[{"name":"win11_1","ip":"198.51.100.110"}]
        result=cape.render_config(KVM,entries,libvirt_existing={"win11","win11_1"},
                                  snapshot="cape_clean",interface="virbr2")
        self.assertIn("# preserve this comment",result)
        self.assertIn("# keep this machine comment",result)
        self.assertIn("machines = win11_1",result)
        self.assertIn("[cuckoo1]",result) # stale stanza preserved but not active
        self.assertIn("snapshot = cape_clean",result)
        self.assertIn("interface = virbr2",result)

    def test_retains_valid_existing_configured_domains(self):
        result=cape.render_config(KVM,[{"name":"win11_2","ip":"198.51.100.111"}],
                                  libvirt_existing={"cuckoo1","win11_2"},
                                  snapshot="cape_clean",interface="virbr2")
        self.assertIn("machines = cuckoo1,win11_2",result)

    def test_refuses_conflicting_name(self):
        with self.assertRaisesRegex(cape.CapeConfigError,"already configured"):
            cape.render_config(KVM,[{"name":"cuckoo1","ip":"198.51.100.111"}],
                               libvirt_existing={"cuckoo1"},
                               snapshot="cape_clean",interface="virbr2")

    def test_refuses_vm_missing_from_libvirt(self):
        with self.assertRaisesRegex(cape.CapeConfigError,"missing from libvirt"):
            cape.render_config(KVM,[{"name":"win11_1","ip":"198.51.100.111"}],
                               libvirt_existing=set(),
                               snapshot="cape_clean",interface="virbr2")


class IdentityTests(unittest.TestCase):
    def test_five_stable_unique_addresses_and_names(self):
        a=c.candidates(5,copy.deepcopy(PROFILE),{"win11"})
        self.assertEqual([x["name"] for x in a],
                         [f"win11_{i}" for i in range(1,6)])
        self.assertEqual(a[-1]["ip"],"198.51.100.114")
        self.assertEqual(a[0]["windows_hostname"],"WIN11-1")
        self.assertEqual(len(set(x["ip"] for x in a)),5)

    def test_duplicate_name_blocks(self):
        with self.assertRaisesRegex(c.ProvisionError,"already exists"):
            c.candidates(2,PROFILE,{"win11_2"})

    def test_reserved_ip_blocks(self):
        profile=dict(PROFILE,first_ipv4="198.51.100.120")
        with self.assertRaisesRegex(c.ProvisionError,"unavailable"):
            c.candidates(1,profile,set())

    def test_gateway_ip_blocks(self):
        profile=dict(PROFILE,first_ipv4=PROFILE["gateway"])
        with self.assertRaisesRegex(c.ProvisionError,"unavailable"):
            c.candidates(1,profile,set())

    def test_count_out_of_range_blocks(self):
        with self.assertRaisesRegex(c.ProvisionError,"between"):
            c.candidates(100,PROFILE,set())

    def test_network_nat_blocks(self):
        with patch.object(c,"virsh",
            return_value="<network><name>cape-isolated</name><forward mode='nat'/>"
                         "<bridge name='virbr2'/><ip address='198.51.100.1' "
                         "netmask='255.255.255.0'/></network>"):
            with self.assertRaises(c.clone_domain_xml.UnsafeDefinition):
                c.check_network("cape-isolated","198.51.100.110","255.255.255.0")

    def test_matching_no_forward_network_passes_xml_check(self):
        with patch.object(c,"virsh",
            return_value="<network><name>cape-isolated</name>"
                         "<bridge name='virbr2'/><ip address='198.51.100.1' "
                         "netmask='255.255.255.0'/></network>"):
            self.assertEqual(c.check_network("cape-isolated","198.51.100.110",
                                             "255.255.255.0"),"virbr2")

if __name__=="__main__":
    unittest.main()
