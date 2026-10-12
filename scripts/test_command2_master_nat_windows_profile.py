"""Pure Windows NAT manifest from exact host-verified all-N attachment."""
import json
import unittest
import command2_master_nat_windows_profile as m

def report(n,subnet="192.168.122.0/24"):
    import ipaddress
    net=ipaddress.IPv4Network(subnet)
    rows=[];hosts=[]
    for i in range(1,n+1):
        ip=str(ipaddress.IPv4Address(int(net.network_address)+200+i))
        mac=f"02:ca:22:00:00:{i:02x}"
        rows.append({"vm":f"win11_{i}",
           "uuid":f"00000000-0000-4000-8000-{i:012d}",
           "reserved_mac":mac,
           "saved_nic_state":"SINGLE_MASTER_EQUIVALENT_NAT",
           "guest_not_started":True,"ip":ip})
        hosts.append({"name":f"WIN11-{i}","mac":mac,"ip":ip})
    return {"result":"COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED",
       "network":"default","bridge":"virbr0","guest_saved_nics_attached":True,
       "host_nat_dhcp_config_applied":True,"CAPE_READY":False,
       "guest_booted_or_configured":False,"guest_reservations":rows,
       "dhcp_hosts":hosts,"count":n}
class WindowsNat(unittest.TestCase):
    def test_one_to_sixteen_immutable_dns_gateway_mac_uuid(self):
        for n in (1,5,16):
            r=m.make(report(n))
            self.assertEqual(len(r),n)
            self.assertEqual(r[0]["ipv4"],"192.168.122.201")
            self.assertEqual(r[0]["default_gateway"],"192.168.122.1")
            self.assertEqual(r[0]["dns_ipv4"],"192.168.122.1")
            self.assertEqual(r[-1]["hostname"],f"WIN11-{n}")
            self.assertTrue(all(x["expected_nic_count"]==1 and
                 x["nic_network"]=="default" and
                 x["addressing"]=="libvirt_dhcp_reservation" for x in r))
            self.assertTrue(all(not x["malware_public_internet_authorized"]
                 for x in r))
            out=m.render_one(r[0])
            self.assertEqual(json.loads(out["json_bytes"]),
                             r[0])
            self.assertEqual(len(out["sha256"]),64)
    def test_portable_actual_master_subnet_not_hardcoded(self):
        x=m.make(report(3,"172.19.55.0/24"))
        self.assertEqual(x[0]["ipv4"],"172.19.55.201")
        self.assertEqual(x[0]["default_gateway"],"172.19.55.1")
        self.assertEqual(x[0]["subnet"],"172.19.55.0/24")
    def test_mismatch_and_unsafe_claim_rejected(self):
        for fail in [
           lambda a:a.update(CAPE_READY=True),
           lambda a:a.update(bridge="cape-lab0"),
           lambda a:a["dhcp_hosts"][0].update(ip="192.168.122.99"),
           lambda a:a["guest_reservations"][0].update(
                saved_nic_state="ZERO_NIC"),
           lambda a:a["guest_reservations"][0].update(vm="win11"),
        ]:
            x=report(2);fail(x)
            with self.subTest(x=x),self.assertRaises(m.NatGuestBlocked):
                m.make(x)
if __name__=="__main__":unittest.main()
