"""Offline-only safety fixtures for guarded cold-boot SSL55 network restart."""
import unittest
from unittest.mock import patch
import command2_ssl55_cold_boot_resume as c

def xml(*,backed=False,net="cape-analysis-isolated",uid=None):
    chain=('<backingStore><source file="/tmp/master.img"/></backingStore>'
           if backed else '<backingStore/>')
    return (f'<domain><name>{c.VM}</name><uuid>{uid or c.UID}</uuid><os>'
            f'<nvram>{c.VARS}</nvram></os><devices>'
            '<disk device="disk"><driver type="qcow2"/>'
            f'<source file="{c.DISK}"/><target dev="sda"/>{chain}</disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '<interface type="network"><mac address="02:0a:30:6a:3f:50"/>'
            f'<source network="{net}"/></interface></devices></domain>')

class ReadonlyXml(unittest.TestCase):
    def test_exact_flattened_vm(self):
        self.assertTrue(c.check_xml(xml()))
    def test_reject_backing(self):
        with self.assertRaisesRegex(c.Blocked,"backing"):
            c.check_xml(xml(backed=True))
    def test_reject_default_nat(self):
        with self.assertRaisesRegex(c.Blocked,"NIC"):
            c.check_xml(xml(net="default"))
    def test_reject_uuid(self):
        with self.assertRaisesRegex(c.Blocked,"identity"):
            c.check_xml(xml(uid="other"))
    def test_net_rejects_nat_forward(self):
        net=('<network><name>cape-analysis-isolated</name>'
             '<bridge name="cape-lab0"/><port isolated="yes"/>'
             '<dns enable="no"/><forward mode="nat"/>'
             '<ip address="192.168.240.1" netmask="255.255.255.0"/>'
             '</network>')
        def vm(*a):
            if a[0]=="net-dumpxml":return net
            return "Active: no\nAutostart: no\nPersistent: yes\nBridge: cape-lab0"
        with patch.object(c,"virsh",side_effect=vm):
            with self.assertRaisesRegex(c.Blocked,"no-forward"):
                c.exact_network()
    def test_source_no_destructive_apis(self):
        from pathlib import Path
        src=Path(c.__file__).read_text()
        for needle in ('virsh("destroy"', 'virsh("shutdown"', 'virsh("net-destroy"',
                       'virsh("snapshot-create-as"', 'virsh("snapshot-revert"',
                       'virsh("attach-interface"', 'virsh("net-autostart"'):
            self.assertNotIn(needle,src)

class ResumeAction(unittest.TestCase):
    def fixture(self,net_active="no"):
        return {"result":"COLD_BOOT_RESUME_PLAN_PASS_NO_WRITES",
                "requires_net_start":net_active=="no",
                "network_active":net_active}
    def test_refusing_network_approval_does_not_start_anything(self):
        with patch.object(c.sys.stdin,"isatty",return_value=True),\
             patch.object(c,"plan",return_value=self.fixture()),\
             patch("builtins.input",return_value="NO"),\
             patch.object(c,"virsh",side_effect=AssertionError("Should not change host")):
            with self.assertRaisesRegex(c.Blocked,"activation not approved"):
                c.resume()
    def test_approved_inactive_network_then_vm_single_start(self):
        requests=[]
        def vm(*args):
            requests.append(args)
            if args==("net-start",c.NET):return "Network started"
            if args==("start",c.VM):return "Domain started"
            if args==("domstate",c.VM):return "running"
            raise AssertionError("Unexpected "+str(args))
        report=self.fixture()
        with patch.object(c.sys.stdin,"isatty",return_value=True),\
             patch.object(c,"plan",return_value=report),\
             patch("builtins.input",side_effect=[
                "START-ISOLATED-NETWORK-SSL55",
                "START-WIN11_1-AFTER-COLD-BACKUP"]),\
             patch.object(c,"bridge_active",return_value=None),\
             patch.object(c,"virsh",side_effect=vm),\
             patch.object(c,"agent",return_value=True):
            status=c.resume()
        self.assertEqual(status["result"],"COLD_BOOT_AGENT_VERIFIED")
        self.assertEqual(requests.count(("net-start",c.NET)),1)
        self.assertEqual(requests.count(("start",c.VM)),1)
    def test_approved_existing_network_does_not_start_network(self):
        requests=[]
        def vm(*args):
            requests.append(args)
            if args==("start",c.VM):return "Domain started"
            if args==("domstate",c.VM):return "running"
            raise AssertionError("Unexpected "+str(args))
        with patch.object(c.sys.stdin,"isatty",return_value=True),\
             patch.object(c,"plan",return_value=self.fixture("yes")),\
             patch("builtins.input",return_value="START-WIN11_1-AFTER-COLD-BACKUP"),\
             patch.object(c,"bridge_active",return_value=None),\
             patch.object(c,"virsh",side_effect=vm),\
             patch.object(c,"agent",return_value=True):
            out=c.resume()
        self.assertTrue(out["clone_running"])
        self.assertNotIn(("net-start",c.NET),requests)
    def test_no_tty_refuses(self):
        with patch.object(c.sys.stdin,"isatty",return_value=False),\
             patch.object(c,"plan",side_effect=AssertionError("No plan")):
            with self.assertRaisesRegex(c.Blocked,"terminal"):
                c.resume()

if __name__=="__main__":
    unittest.main()
