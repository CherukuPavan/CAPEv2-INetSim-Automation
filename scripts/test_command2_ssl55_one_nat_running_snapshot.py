"""All mock-only guarded third one-NAT-NIC capture tests."""
import json
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch

import command2_ssl55_one_nat_running_snapshot as m
VM=m.VM
UUID=m.dual.UID
OLD=m.post.OLD
SECOND=m.post.NEW
THIRD=m.SNAP
DOM=('<domain type="kvm"><name>'+VM+'</name><uuid>'+UUID+'</uuid>'
     '<devices><interface type="network"><source network="default"/>'
     '<mac address="02:ca:55:11:01:02"/>'
     '<model type="e1000e"/></interface></devices>'
     '<memory unit="KiB">4194304</memory></domain>')
NAT=('<network><name>default</name><forward mode="nat"/>'
     '<bridge name="virbr0"/><ip address="192.168.122.1">'
     '<dhcp><range start="192.168.122.2" end="192.168.122.254"/>'
     '<host mac="02:ca:55:11:01:02" name="WIN11-1"'
     ' ip="192.168.122.131"/></dhcp></ip></network>')
def xml(name):
    nic=('<interface type="network"><source network="default"/>'
         '<mac address="02:ca:55:11:01:02"/><model type="e1000e"/>'
         '</interface>') if name==THIRD else (
         '<interface type="network"><source network="cape-analysis-isolated"/>'
         '<mac address="02:0a:30:6a:3f:50"/>'
         '<model type="e1000e"/></interface>')
    return ('<domainsnapshot><name>'+name+'</name><state>running</state>'
            '<memory snapshot="internal"/>'
            '<creationTime>'+str({
                OLD:1791823660,SECOND:1791833879,THIRD:1791836000}[name])+
            '</creationTime><disks><disk name="sda" snapshot="internal"/>'
            '<disk name="sdb" snapshot="no"/></disks><domain type="kvm">'
            '<name>'+VM+'</name><uuid>'+UUID+'</uuid><devices>'+nic+
            '</devices></domain></domainsnapshot>')

def virsh(captured=False):
    def query(*args,**kw):
        if args==("snapshot-list",VM,"--name"):
            return '\n'.join([OLD,SECOND]+([THIRD] if captured else []))
        if args[0]=="snapshot-dumpxml":
            return xml(args[-1])
        if args[0]=="domuuid":
            return {VM:UUID,m.dual.MASTER[0]:m.dual.MASTER[1],
                 m.dual.TRIAL[0]:m.dual.TRIAL[1]}[args[1]]
        if args[0]=="domstate":
            return "running" if args[1]==VM else "shut off"
        if args==("list","--name"):return VM
        if args[0]=="net-dumpxml":return NAT
        if args[0]=="dumpxml":return DOM
        raise AssertionError(args)
    return query

class OneNat(unittest.TestCase):
    def test_snapshot_inventory_ram_disk_embedded_one_nat_only(self):
        with patch.object(m.dual,"virsh",side_effect=virsh(False)):
            self.assertEqual(len(m.snapshots(False)),2)
        with patch.object(m.dual,"virsh",side_effect=virsh(True)):
            s=m.snapshots(True)
        self.assertEqual(len(s),3)
        self.assertTrue(s[THIRD]["running_ram_internal"])
        self.assertTrue(s[THIRD]["os_disk_sda_internal"])
        wrong=xml(THIRD).replace('network="default"','network="cape-analysis-isolated"')
        def bad(*a,**kw):
            if a==("snapshot-dumpxml",VM,THIRD):return wrong
            return virsh(True)(*a,**kw)
        with patch.object(m.dual,"virsh",side_effect=bad),\
             self.assertRaisesRegex(m.OneNatCaptureBlocked,"NOT single"):
            m.snapshots(True)

    def test_image_names_are_exact_old_second_third_in_both_files(self):
        with tempfile.TemporaryDirectory() as td:
            paths=[Path(td)/"os.qcow2",Path(td)/"ovmf.qcow2"]
            for p in paths:p.write_bytes(b"stub")
            def response(third):
                return json.dumps({"format":"qcow2",
                   "snapshots":[{"name":x} for x in
                                [OLD,SECOND]+([THIRD] if third else [])]})
            with patch.object(m.post,"OS_DISK",paths[0]),\
                 patch.object(m.post,"OVMF",paths[1]),\
                 patch.object(m.post,"cmd",return_value=response(False)):
                self.assertEqual(len(m.images(False)),2)
            with patch.object(m.post,"OS_DISK",paths[0]),\
                 patch.object(m.post,"OVMF",paths[1]),\
                 patch.object(m.post,"cmd",return_value=response(True)):
                self.assertTrue(m.images(True)["ovmf_qcow2"]
                                ["one_nat_checkpoint_present"])
            with patch.object(m.post,"OS_DISK",paths[0]),\
                 patch.object(m.post,"OVMF",paths[1]),\
                 patch.object(m.post,"cmd",return_value=response(False)),\
                 self.assertRaisesRegex(m.OneNatCaptureBlocked,"differs"):
                m.images(True)

    def test_one_nat_power_and_exact_host_reservation_guard(self):
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m.dual,"virsh",side_effect=virsh(True)),\
             patch.object(m.retired,"single_nat_views",return_value={
                "saved_and_live_one_exact_default_nat_nic":True}),\
             patch.object(m.dual,"probe",return_value={
                "reachable_and_identified":True}):
            g=m.network_and_power()
        self.assertTrue(g["nat_agent_verified"])
        self.assertTrue(g["dhcp_reservation_both_active_persistent"])
        def bad(*args,**kw):
            if args[0]=="net-dumpxml":
                return NAT.replace("192.168.122.131","192.168.122.150")
            return virsh(True)(*args,**kw)
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m.dual,"virsh",side_effect=bad),\
             patch.object(m.retired,"single_nat_views",return_value={
                "saved_and_live_one_exact_default_nat_nic":True}),\
             patch.object(m.dual,"probe",return_value={
                "reachable_and_identified":True}),\
             self.assertRaisesRegex(m.OneNatCaptureBlocked,"reservation"):
            m.network_and_power()

    def test_final_preflight_uses_headroom_not_bare_40g(self):
        with tempfile.TemporaryDirectory() as td:
            tpm=Path(td)/"tpm";tpm.mkdir()
            (tpm/"tpm2-00.permall").write_bytes(b"mock")
            with patch.object(m,"network_and_power",return_value={"ok":True}),\
                 patch.object(m,"snapshots",return_value={OLD:{},SECOND:{}}),\
                 patch.object(m,"images",return_value={"os_disk":{}}),\
                 patch.object(m.post,"TPM",tpm),\
                 patch.object(m.dual,"virsh",return_value=DOM),\
                 patch.object(m.os,"statvfs",return_value=SimpleNamespace(
                    f_bavail=55*1024**3,f_frsize=1)):
                plan=m.check(False)
            self.assertFalse(plan["CAPE_READY"])
            self.assertFalse(plan["captured"])
            self.assertEqual(plan["name"],THIRD)
            with patch.object(m,"network_and_power",return_value={"ok":True}),\
                 patch.object(m,"snapshots",return_value={OLD:{},SECOND:{}}),\
                 patch.object(m,"images",return_value={"os_disk":{}}),\
                 patch.object(m.post,"TPM",tpm),\
                 patch.object(m.dual,"virsh",return_value=DOM),\
                 patch.object(m.os,"statvfs",return_value=SimpleNamespace(
                    f_bavail=42*1024**3,f_frsize=1)),\
                 self.assertRaisesRegex(m.OneNatCaptureBlocked,"Insufficient"):
                m.check(False)

    def test_single_atomic_snapshot_with_separate_consent_and_reverify(self):
        with tempfile.TemporaryDirectory() as td:
            b={"guest_network":{"nat":True},
               "libvirt_snapshot_metadata":{OLD:{},SECOND:{}},
               "qemu_internal_images":{"os_disk":{"ok":True}}}
            after={**b,"captured":True}
            state=[False];calls=[]
            def create(*a,**kw):
                calls.append((a,kw))
                self.assertEqual(a,("snapshot-create-as","--domain",VM,
                                    "--name",THIRD,"--atomic"))
                self.assertEqual(kw,{"timeout":1800})
                state[0]=True
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.APPROVE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"check",side_effect=lambda x:after if x else b),\
                 patch.object(m.post,"virsh",side_effect=create),\
                 patch.object(m.dual,"virsh",
                              side_effect=AssertionError("wrong wrapper")):
                out=m.capture()
            self.assertTrue(out["captured"])
            self.assertEqual(len(calls),1)
            self.assertFalse(out["snapshot_safe_to_revert_with_current_swtpm"] if
                             "snapshot_safe_to_revert_with_current_swtpm" in out else False)

    def test_partial_capture_never_retries_or_reverts(self):
        with tempfile.TemporaryDirectory() as td:
            b={"guest_network":{"nat":True},
               "libvirt_snapshot_metadata":{OLD:{},SECOND:{}},
               "qemu_internal_images":{"os_disk":{"ok":True}}}
            count=[]
            def error(*a,**kw):
                count.append(a);raise m.OneNatCaptureBlocked("qemu failure")
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.APPROVE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"check",return_value=b),\
                 patch.object(m.post,"virsh",side_effect=error),\
                 patch.object(m.dual,"virsh",
                              side_effect=AssertionError("wrong wrapper")),\
                 self.assertRaisesRegex(m.OneNatCaptureBlocked,"POSSIBLY_PARTIAL"):
                m.capture()
            self.assertEqual(len(count),1)
            self.assertNotIn("snapshot-revert",str(count))
    def test_real_timeout_signature_prevents_original_ssl55_failure(self):
        import inspect
        # The actual physical failure was due to invoking dual.virsh
        # with timeout=1800, even though only post.virsh supports it.
        self.assertNotIn("timeout",
                         inspect.signature(m.dual.virsh).parameters)
        self.assertIn("timeout",
                      inspect.signature(m.post.virsh).parameters)
        body=inspect.getsource(m.capture)
        self.assertIn('post.virsh("snapshot-create-as"',body)
        self.assertNotIn('dual.virsh("snapshot-create-as"',body)

    def test_no_snapshot_deletion_or_restore_or_vm_power(self):
        s=Path(m.__file__).read_text(encoding="utf-8")
        for prohibited in ('"snapshot-revert"','"snapshot-delete"',
            '"destroy"','"shutdown"','"start"','os.replace(','shell=True',
            '"net-update"','"detach-interface"'):
            self.assertNotIn(prohibited,s)
if __name__=="__main__":unittest.main()
