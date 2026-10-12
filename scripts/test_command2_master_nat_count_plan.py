"""Pure count-driven stable master-equivalent NAT reservations, no host ops."""
import unittest
import command2_master_nat_count_plan as m

def sample(count):
    audit={
      "result":"COMMAND2_MASTER_EQUIVALENT_PERSISTENT_NAT_AUDIT_ONLY",
      "target_permanent_libvirt_network":"default",
      "target_permanent_bridge":"virbr0",
      "source_vm_remains_off":True,
      "trial_remains_off":True,
      "libvirt_network_or_guest_modified":False,
      "target_clone_names":["win11_"+str(i) for i in range(1,count+1)],
      "historical_master_windows_ip_reference":"192.168.122.125",
      "lease_inventory":{"live_dhcp_leases":[
          {"mac":"52:54:00:00:33:44","ipv4":"192.168.122.153"}]},
      "network_info":{
        "nat_network":"default","bridge":"virbr0",
        "guest_network_has_unrestricted_egress_by_default":True,
        "ipv4":{"subnet":"192.168.122.0/24",
                "gateway":"192.168.122.1"},
        "dynamic_dhcp_ranges":[
           {"first":"192.168.122.2","last":"192.168.122.254"}],
        "existing_dhcp_host_reservations":[
           {"mac":"52:54:00:1a:2b:3c","ipv4":"192.168.122.51"}]}}
    rows=[{"libvirt_name":"win11_"+str(i),
           "mac_candidate":f"02:ca:42:00:00:{i:02x}"}
          for i in range(1,count+1)]
    return audit,rows
class MasterNatPlan(unittest.TestCase):
    def test_all_n_derive_unique_static_address_mac_nat_and_reservation(self):
        audit,rows=sample(5)
        out=m.allocate(audit,rows)
        self.assertEqual(out["count"],5)
        self.assertEqual([a["desired_static_ipv4"] for a in out["clones"]],
             ["192.168.122."+str(i) for i in range(201,206)])
        self.assertTrue(all(a["host_network"]=="default" and
                            a["gateway_ipv4"]=="192.168.122.1" and
                            a["guest_nic_port_isolated"] for a in out["clones"]))
        self.assertFalse(out["auto_apply_authorized"])
        self.assertFalse(out["safe_for_cape_malware"])
        self.assertIn("WIN11-1",out["clones"][0]["dhcp_reservation_xml_preview"])

    def test_existing_lease_on_expected_static_ip_is_blocking(self):
        audit,rows=sample(2)
        audit["lease_inventory"]["live_dhcp_leases"]=[
            {"mac":"52:54:00:dd:ee:ff","ipv4":"192.168.122.201"}]
        with self.assertRaisesRegex(m.NatPlanBlocked,"collides"):
            m.allocate(audit,rows)

    def test_duplicate_mac_and_existing_reservation_block(self):
        audit,rows=sample(2)
        rows[1]["mac_candidate"]=rows[0]["mac_candidate"]
        with self.assertRaisesRegex(m.NatPlanBlocked,"MAC"):
            m.allocate(audit,rows)
        audit,rows=sample(1)
        audit["network_info"]["existing_dhcp_host_reservations"].append({
            "mac":rows[0]["mac_candidate"],"ipv4":"192.168.122.88"})
        with self.assertRaisesRegex(m.NatPlanBlocked,"MAC"):
            m.allocate(audit,rows)

    def test_must_preserve_exact_source_nat_and_private_subnet(self):
        audit,rows=sample(1)
        audit["network_info"]["bridge"]="br0"
        with self.assertRaisesRegex(m.NatPlanBlocked,"details changed"):
            m.allocate(audit,rows)
        audit,rows=sample(1)
        audit["network_info"]["ipv4"]["subnet"]="8.8.8.0/24"
        with self.assertRaisesRegex(m.NatPlanBlocked,"private"):
            m.allocate(audit,rows)
        audit,rows=sample(1)
        audit["target_clone_names"]=["win11_4"]
        with self.assertRaisesRegex(m.NatPlanBlocked,"Count mismatch"):
            m.allocate(audit,rows)

    def test_no_write_or_stated_internet_guarantee(self):
        from pathlib import Path
        src=Path(m.__file__).read_text()
        for prohibited in ('subprocess.run','virsh("net-update"',
                           'virsh("define"','virsh("attach-interface"',
                           'os.system(','shell=True',
                           'CAPE_READY=True'):
            self.assertNotIn(prohibited,src)
if __name__=="__main__":unittest.main()
