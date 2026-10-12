"""Pure offline regression for independent trusted Internet setup and final CAPE isolation."""
import unittest
import command2_connectivity_phase_contract as c

VM='win11_1'
ISO=('<network><name>cape-analysis-isolated</name>'
     '<bridge name="cape-lab0"/><port isolated="yes"/>'
     '<dns enable="no"/><ip address="192.168.240.1"/></network>')
NAT=('<network><name>cape-trusted-provisioning-nat</name>'
     '<forward mode="nat"/><bridge name="cape-setup-nat0"/>'
     '<ip address="192.168.244.1"><dhcp><range start="192.168.244.2" '
     'end="192.168.244.100"/></dhcp></ip></network>')
def domain(nics):
    return ('<domain type="kvm"><name>'+VM+'</name><uuid>'
            '732b2256-ee99-41fa-881d-fbf5c476d960</uuid><devices>'+
            ''.join('<interface type="network"><source network="'+net+'"/>'
                    '<mac address="'+mac+'"/></interface>'
                   for net,mac in nics)+'</devices></domain>')
ANALYSIS=domain([(c.ISOLATED,"02:0a:30:6a:3f:50")])
SETUP=domain([(c.ISOLATED,"02:0a:30:6a:3f:50"),
              (c.PROVISIONING,"02:0a:30:6a:3f:51")])

class NetworkPhase(unittest.TestCase):
    def test_existing_ssl55_isolated_network_is_intentionally_offline(self):
        result=c.assess(vm=VM,domain_xml=ANALYSIS,analysis_network_xml=ISO,
                        phase="analysis_isolated",
                        ipv4_negative_egress_verified=True,
                        ipv6_negative_egress_verified=True)
        self.assertTrue(result["internet_is_intentionally_simulated_or_blocked"])
        self.assertFalse(result["guest_unrestricted_real_internet_access"])
        self.assertFalse(result["malware_analysis_allowed"])

    def test_benign_internet_provisioning_requires_distinct_temporary_nat(self):
        okay=c.assess(vm=VM,domain_xml=SETUP,analysis_network_xml=ISO,
                      provisioning_network_xml=NAT,phase="trusted_setup",
                      approved_benign_setup=True,no_samples_running=True,
                      operator_external_egress_verified=True)
        self.assertTrue(okay["operator_real_internet_guest_test_verified"])
        self.assertFalse(okay["guest_ready_for_final_running_snapshot"])
        for kv in [
            {"approved_benign_setup":False,"no_samples_running":True},
            {"approved_benign_setup":True,"no_samples_running":False},
        ]:
            with self.assertRaises(c.ConnectivityBlocked):
                c.assess(vm=VM,domain_xml=SETUP,analysis_network_xml=ISO,
                    provisioning_network_xml=NAT,phase="trusted_setup",**kv)

    def test_final_snapshot_refuses_temporary_internet_nic_and_missing_tests(self):
        flags={"ipv4_negative_egress_verified":True,
               "ipv6_negative_egress_verified":True,
               "cape_agent_verified":True,"inetsim_verified":True}
        out=c.assess(vm=VM,domain_xml=ANALYSIS,analysis_network_xml=ISO,
                     phase="final_snapshot",**flags)
        self.assertTrue(out["network_only_snapshot_precondition_passed"])
        self.assertFalse(out["tpm_consistent_restore_proven"])
        with self.assertRaisesRegex(c.ConnectivityBlocked,"REMOVED"):
            c.assess(vm=VM,domain_xml=SETUP,analysis_network_xml=ISO,
                     phase="final_snapshot",**flags)
        for missing in flags:
            copy=dict(flags);copy[missing]=False
            with self.subTest(missing=missing),\
                 self.assertRaises(c.ConnectivityBlocked):
                c.assess(vm=VM,domain_xml=ANALYSIS,
                         analysis_network_xml=ISO,
                         phase="final_snapshot",**copy)

    def test_cannot_claim_isolation_from_nat_or_missing_bridge_guard(self):
        bad_iso=ISO.replace("<dns enable=\"no\"/>","<dns enable=\"yes\"/>")
        for bad in (bad_iso,
                    ISO.replace("<port isolated=\"yes\"/>",""),
                    ISO.replace("<bridge name=\"cape-lab0\"/>",
                                "<forward mode=\"nat\"/>")):
            with self.subTest(bad=bad),\
                 self.assertRaises(c.ConnectivityBlocked):
                c.assess(vm=VM,domain_xml=ANALYSIS,
                         analysis_network_xml=bad,
                         phase="analysis_isolated",
                         ipv4_negative_egress_verified=True,
                         ipv6_negative_egress_verified=True)
        bad_nat=NAT.replace('mode="nat"','mode="bridge"')
        with self.assertRaisesRegex(c.ConnectivityBlocked,"unapproved|Unapproved"):
            c.assess(vm=VM,domain_xml=SETUP,
                     analysis_network_xml=ISO,
                     provisioning_network_xml=bad_nat,
                     phase="trusted_setup",approved_benign_setup=True,
                     no_samples_running=True)

    def test_no_host_changes_or_malware_and_count_validation(self):
        from pathlib import Path
        source=Path(c.__file__).read_text()
        for bad in ('virsh("attach-interface"', 'virsh("net-update"',
                    'virsh("snapshot-create"', 'virsh("start"',
                    'subprocess.run(', 'nft -f ', 'shell=True',
                    'os.system('):
            self.assertNotIn(bad,source)
        with self.assertRaisesRegex(c.ConnectivityBlocked,"exact win11_N"):
            c.assess(vm="win11_20",domain_xml=ANALYSIS,
                     analysis_network_xml=ISO,
                     phase="analysis_isolated",
                     ipv4_negative_egress_verified=True,
                     ipv6_negative_egress_verified=True)

if __name__=="__main__":unittest.main()
