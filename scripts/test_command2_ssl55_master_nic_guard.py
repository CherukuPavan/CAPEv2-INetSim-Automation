"""Offline tests of the exact-original-master NIC repair guard.

All tests use mock libvirt XML. No guest, disk or host modification.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_master_nic_guard as g

NIC = ('<interface type="network"><mac address="52:54:00:12:34:56"/>'
       '<source network="default"/><model type="e1000e"/>'
       '<address type="pci" domain="0x0000" bus="0x00" '
       'slot="0x08" function="0x0"/></interface>')

def sample(nic=NIC, uuid=g.EXPECTED_UUID, disk="master.qcow2"):
    return (f'<domain type="kvm"><name>win11</name><uuid>{uuid}</uuid>'
            '<os><nvram>/private/vars.fd</nvram></os><devices>'
            f'<disk device="disk"><source file="/images/{disk}"/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            +nic+'</devices></domain>')

def fake_host(*v):
    if v == ('domuuid','win11'): return g.EXPECTED_UUID
    if v == ('domstate','win11'): return 'shut off'
    if v == ('snapshot-current','win11','--name'): return g.EXPECTED_SNAPSHOT
    if v == ('snapshot-list','win11','--name'): return g.EXPECTED_SNAPSHOT
    if v == ('dumpxml','--inactive','win11'): return sample(nic='')
    if v == ('list','--all','--name'): return 'win11'
    if v == ('net-info','default'): return 'Name: default'
    raise AssertionError('Unexpected libvirt command: '+str(v))

class GuardTests(unittest.TestCase):
    def test_exact_original_nic_accepted_only_when_missing(self):
        restored, mac = g.safe_nic(g.decode(sample()),g.decode(sample(nic='')))
        self.assertEqual(mac,"52:54:00:12:34:56")
        self.assertEqual(restored.find("source").get("network"),"default")
        self.assertEqual(restored.find("model").get("type"),"e1000e")
        with self.assertRaisesRegex(g.Blocked,"already has"):
            g.safe_nic(g.decode(sample()),g.decode(sample()))

    def test_unreviewed_network_or_adapter_rejected(self):
        for bad in (NIC.replace("e1000e","virtio"),
                    NIC.replace('network="default"','network="internet"'),
                    NIC.replace('type="network"','type="direct"'),
                    NIC.replace("</interface>",'<filterref filter="custom"/></interface>')):
            with self.subTest(bad=bad), self.assertRaises(g.Blocked):
                g.safe_nic(g.decode(sample(nic=bad)),g.decode(sample(nic='')))

    def test_duplicate_mac_and_pci_collision_are_blocked(self):
        other = ('<controller><address type="pci" domain="0x0000" '
                 'bus="0x00" slot="0x08" function="0x0"/></controller>')
        with self.assertRaisesRegex(g.Blocked,"PCI"):
            g.safe_nic(g.decode(sample()),g.decode(sample(nic=other)))
        def existing_mac(*v):
            if v==('list','--all','--name'): return 'win11\nother'
            if v==('dumpxml','--inactive','other'):
                return '<domain><devices>'+NIC+'</devices></domain>'
            if v==('domstate','other'): return 'shut off'
            raise AssertionError('Unexpected call')
        with patch.object(g,'virsh',side_effect=existing_mac):
            with self.assertRaisesRegex(g.Blocked,"MAC conflicts"):
                g.peer_mac_conflict("52:54:00:12:34:56")

    def test_protected_disk_uefi_tpm_fingerprint_never_ignored(self):
        a=g.protected_parts(g.decode(sample(nic='')))
        self.assertEqual(a,g.protected_parts(g.decode(sample())))
        self.assertNotEqual(a,g.protected_parts(g.decode(sample(nic='',disk='OTHER.qcow2'))))

    def test_readonly_plan_uses_no_attach_define_network_start_or_guest_boot(self):
        calls=[]
        def read(*v):
            calls.append(v)
            return fake_host(*v)
        with patch.object(g.socket,'gethostname',return_value='CSE-SSL-55.campus'),\
             patch.object(g.os,'geteuid',return_value=0),\
             patch.object(g,'preserved_xml',return_value=sample()),\
             patch.object(g,'virsh',side_effect=read):
            plan, device = g.read_state()
        self.assertFalse(plan["host_modified"])
        self.assertEqual(plan["result"],"SSL55_ORIGINAL_MASTER_NIC_REPAIR_PLAN_ONLY")
        self.assertEqual(len(plan["plan_sha256"]),64)
        self.assertIn('network="default"',device)
        self.assertFalse(any(x[0] in ("attach-device","define","start","net-start")
                             for x in calls))

    def test_unknown_host_cannot_touch_libvirt(self):
        with patch.object(g.socket,'gethostname',return_value='new-computer'),\
             patch.object(g,'virsh',side_effect=AssertionError("No host access")):
            with self.assertRaisesRegex(g.Blocked,"expected SSL-55"):
                g.read_state()

    def test_active_master_or_missing_authorization_refused(self):
        def running(*a):
            if a==("domuuid","win11"): return g.EXPECTED_UUID
            if a==("domstate","win11"): return "running"
            raise AssertionError("Should stop early")
        with patch.object(g.socket,'gethostname',return_value="CSE-SSL-55"),\
             patch.object(g.os,'geteuid',return_value=0),\
             patch.object(g,'virsh',side_effect=running):
            with self.assertRaisesRegex(g.Blocked,"shut off"):
                g.read_state()
        with patch.object(g.socket,'gethostname',return_value="CSE-SSL-55"),\
             patch.object(g.os,'geteuid',return_value=0),\
             patch.object(g.sys.stdin,'isatty',return_value=False),\
             patch.object(g,'virsh',side_effect=AssertionError("No VM mutations")):
            with self.assertRaisesRegex(g.Blocked,"interactive"):
                g.apply("0"*64)

    def test_correct_apply_changes_only_inactive_original_interface(self):
        actual={"xml":sample(nic='')}
        calls=[]
        def host(*a):
            calls.append(a)
            if a==("dumpxml","--inactive","win11"): return actual["xml"]
            if a[0]=="attach-device":
                self.assertEqual(a[1],"win11")
                self.assertEqual(a[3],"--config")
                actual["xml"]=sample(nic=Path(a[2]).read_text())
                return ""
            return fake_host(*a)
        with tempfile.TemporaryDirectory() as tmp:
            original_mkstemp=tempfile.mkstemp
            with patch.object(g.socket,"gethostname",return_value="CSE-SSL-55"),\
                 patch.object(g.os,"geteuid",return_value=0),\
                 patch.object(g,"preserved_xml",return_value=sample()),\
                 patch.object(g,"virsh",side_effect=host):
                plan,_=g.read_state()
                with patch.object(g,"LOCK",Path(tmp)/"lock"),\
                     patch.object(g.os,"fstat",return_value=type(
                         "RootLock",(),{"st_mode":0o100600,
                                        "st_uid":0,"st_nlink":1})()),\
                     patch.object(g.sys.stdin,"isatty",return_value=True),\
                     patch("builtins.input",return_value="RESTORE-ONLY-SHUTOFF-WIN11-SAVED-NIC"),\
                     patch.object(g.tempfile,"mkstemp",side_effect=lambda prefix,suffix,dir:
                                  original_mkstemp(prefix=prefix,suffix=suffix,dir=tmp)):
                    report=g.apply(plan["plan_sha256"])
        self.assertEqual(report["result"],"ORIGINAL_SHUTOFF_WIN11_SAVED_NIC_RESTORED")
        self.assertTrue(report["master_remains_shut_off"])
        self.assertEqual([x[0] for x in calls].count("attach-device"),1)
        self.assertFalse(any(x[0] in ("define","start","shutdown","net-start") for x in calls))

if __name__ == "__main__":
    unittest.main()
