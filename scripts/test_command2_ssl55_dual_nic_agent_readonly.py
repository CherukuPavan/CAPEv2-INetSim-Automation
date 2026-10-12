"""No host mutation. Offline dual-network CAPE Agent probe regression."""
from unittest.mock import patch
import unittest
import json
from pathlib import Path
import command2_ssl55_dual_nic_agent_readonly as g

VM=g.VM
UUID=g.UID
XML=(
    '<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+'</uuid><devices>'
    '<interface type="network"><source network="cape-analysis-isolated"/>'
    '<mac address="02:0a:30:6a:3f:50"/><model type="e1000e"/></interface>'
    '<interface type="network"><source network="default"/>'
    '<mac address="02:ca:55:11:01:02"/><model type="e1000e"/></interface>'
    '</devices></domain>'
)
SNAP=('<domainsnapshot><name>'+g.SNAP+'</name><state>running</state>'
      '<memory snapshot="internal"/>'
      '<disks><disk name="sda" snapshot="internal"/>'
      '<disk name="sdb" snapshot="no"/></disks>'
      '<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+
      '</uuid></domain></domainsnapshot>')
ISO=('<network><name>cape-analysis-isolated</name><bridge name="cape-lab0"/>'
     '<port isolated="yes"/><dns enable="no"/></network>')
NAT=('<network><name>default</name><bridge name="virbr0"/>'
     '<forward mode="nat"/><ip address="192.168.122.1">'
     '<dhcp><range start="192.168.122.2" end="192.168.122.254"/></dhcp>'
     '</ip></network>')
LEASE=('Expiry Time MAC address Protocol IP address Hostname\n'
       '2026-10-12 19:25:00 02:ca:55:11:01:02 ipv4 '
       '192.168.122.131/24 WIN11-1')
def fake_virsh(*args):
    if args[0]=="domuuid":
        return {VM:UUID,g.MASTER[0]:g.MASTER[1],g.TRIAL[0]:g.TRIAL[1]}[args[1]]
    if args[0]=="domstate":
        return "running" if args[1]==VM else "shut off"
    if args==("list","--name"):return VM
    if args==("snapshot-list",VM,"--name"):return g.SNAP
    if args==("snapshot-dumpxml",VM,g.SNAP):return SNAP
    if args[0]=="dumpxml":return XML
    if args==("net-dumpxml","default"):return NAT
    if args==("net-dumpxml","cape-analysis-isolated"):return ISO
    if args==("net-dhcp-leases","default"):return LEASE
    raise AssertionError(args)
def route(*args,**kw):
    if args[:4]==("ip","-j","-4","route"):
        ip=args[-1]
        if ip=="192.168.240.101":
            return json.dumps([{"dev":"cape-lab0","prefsrc":"192.168.240.1"}])
        if ip=="192.168.122.131":
            return json.dumps([{"dev":"virbr0","prefsrc":"192.168.122.1"}])
    raise AssertionError(args)

class DualAgent(unittest.TestCase):
    def test_only_exact_persistent_and_isolated_nics_accepted(self):
        self.assertTrue(g.interfaces(XML)["persistent_and_live_two_expected_nics"])
        for bad in (
            XML.replace('network="default"','network="other"'),
            XML.replace('02:ca:55:11:01:02','02:ca:55:11:01:03'),
            XML.replace('<model type="e1000e"/>','<model type="virtio"/>'),
            XML.replace('<interface type="network"><source network="default"/>'
                        '<mac address="02:ca:55:11:01:02"/>'
                        '<model type="e1000e"/></interface>',''),
        ):
            with self.subTest(bad=bad),self.assertRaises(g.ReaddressBlocked):
                g.interfaces(bad)

    def test_original_and_nat_agent_probed_only_for_readonly_http_identity(self):
        def fake_agent(ip,src):
            self.assertEqual((ip,src),(
                "192.168.240.101","192.168.240.1") if ip.endswith(".101") else
                ("192.168.122.131","192.168.122.1"))
            return {"reachable_and_identified":True,
                    "outcome":"cape_agent_verified","agent_version":"0.23"}
        with patch.object(g.os,"geteuid",return_value=0),\
             patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(g,"virsh",side_effect=fake_virsh),\
             patch.object(g,"cmd",side_effect=route),\
             patch.object(g,"probe",side_effect=fake_agent) as probe:
            result=g.assess()
        self.assertEqual(probe.call_count,2)
        self.assertTrue(result["nat_agent_reachable"])
        self.assertTrue(result["original_agent_still_reachable"])
        self.assertEqual(result["nat_lease_observation"]["observed_nat_ips_for_mac"],
                         ["192.168.122.131"])
        self.assertFalse(result["old_adapter_detached"])
        self.assertFalse(result["cape_ip_registration_changed"])
        self.assertFalse(result["malware_analysis_allowed"])

    def test_second_snapshot_only_accepted_if_old_and_new_on_both_qcow_images(self):
        import json
        from unittest.mock import patch
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            disk=Path(td)/"disk.qcow2"
            uefi=Path(td)/"vars.qcow2"
            disk.write_bytes(b"synthetic")
            uefi.write_bytes(b"synthetic")
            def vm(*a):
                if a==("snapshot-list",VM,"--name"):
                    return g.SNAP+"\n"+g.POSTNAT
                if a==("snapshot-dumpxml",VM,g.POSTNAT):
                    return SNAP.replace(g.SNAP,g.POSTNAT)
                return fake_virsh(*a)
            def info(*a,**kw):
                if a[0]=="qemu-img":
                    return json.dumps({"format":"qcow2","snapshots":[
                        {"name":g.SNAP},{"name":g.POSTNAT}]})
                return route(*a,**kw)
            with patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(g,"POSTNAT_IMAGES",(str(disk),str(uefi))),\
                 patch.object(g,"virsh",side_effect=vm),\
                 patch.object(g,"cmd",side_effect=info),\
                 patch.object(g,"probe",return_value={
                     "reachable_and_identified":True,
                     "outcome":"cape_agent_verified","agent_version":"0.23"}):
                out=g.assess()
            self.assertTrue(out["postnat_running_snapshot_verified"])
            self.assertEqual(len(out["expected_running_snapshot_names"]),2)
            def failinfo(*a,**kw):
                if a[0]=="qemu-img":
                    return json.dumps({"format":"qcow2","snapshots":[
                        {"name":g.SNAP}]})
                return route(*a,**kw)
            with patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(g,"POSTNAT_IMAGES",(str(disk),str(uefi))),\
                 patch.object(g,"virsh",side_effect=vm),\
                 patch.object(g,"cmd",side_effect=failinfo),\
                 self.assertRaisesRegex(g.ReaddressBlocked,"checkpoint"):
                g.assess()

    def test_unknown_lease_is_not_interpreted_as_no_internet(self):
        with patch.object(g,"virsh",return_value=""):
            result=g.inventory_lease()
        self.assertEqual(result["observed_nat_mac_lease_count"],0)
        self.assertFalse(result["stable_dhcp_reservation_exists_verified"])
        self.assertTrue(result["lease_table_is_not_proof_of_current_or_future_ip"])

    def test_live_route_cannot_egress_other_bridge(self):
        def wrong(*args,**kwargs):
            if args[:4]==("ip","-j","-4","route"):
                return json.dumps([{"dev":"enp0s31f6","prefsrc":"10.23.105.55"}])
            raise AssertionError(args)
        with patch.object(g,"virsh",side_effect=fake_virsh),\
             patch.object(g,"cmd",side_effect=wrong),\
             self.assertRaisesRegex(g.ReaddressBlocked,"NOT local"):
            g.libvirt_networks()

    def test_no_host_guest_writes_or_samples(self):
        txt=Path(g.__file__).read_text(encoding="utf-8")
        for bad in ('virsh("attach-interface"','virsh("detach-interface"',
                    'virsh("snapshot-create"','virsh("snapshot-revert"',
                    'virsh("net-update"','virsh("define"','virsh("shutdown"',
                    'virsh("start"','shell=True',
                    'POST",','"POST"','Clear-Tpm'):
            self.assertNotIn(bad,txt)
if __name__=="__main__":unittest.main()
