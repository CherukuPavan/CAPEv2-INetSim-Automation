"""Mocked post-NAT single NIC migration; no physical guest/host writes."""
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import command2_ssl55_retire_isolated_nic as m

VM=m.VM
UID=m.dual.UID
DOMAIN=('<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
   '<os><nvram format="qcow2">'+str(m.post.OVMF)+'</nvram></os>'
   '<devices><disk device="disk"><source file="'+str(m.post.OS_DISK)+
   '"/></disk><tpm><backend type="emulator" version="2.0"/></tpm>'
   '<interface type="network"><source network="default"/>'
   '<mac address="'+m.ONLINE_MAC+'"/><model type="e1000e"/></interface>'
   '</devices></domain>')
class Retire(unittest.TestCase):
    def test_after_checks_nat_only_and_keeps_two_snapshot_images(self):
        names=m.post.OLD+"\n"+m.post.NEW
        def query(*a):
            if a==("snapshot-list",VM,"--name"):return names
            if a[:1]==("domuuid",):
                return {VM:UID,m.dual.MASTER[0]:m.dual.MASTER[1],
                        m.dual.TRIAL[0]:m.dual.TRIAL[1]}[a[1]]
            if a[:1]==("domstate",):return (
                "running" if a[1]==VM else "shut off")
            if a[0]=="dumpxml":return DOMAIN
            raise AssertionError(a)
        with patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(m.dual,"virsh",side_effect=query),\
             patch.object(m.dual,"probe",return_value={
                "reachable_and_identified":True}),\
             patch.object(m.post,"images",return_value={
                "os_disk":{"old_checkpoint_preserved":True},
                "uefi_qcow2":{"old_checkpoint_preserved":True}}):
            out=m.inspect_after()
        self.assertTrue(out["old_isolated_mac_removed_from_saved_and_live"])
        self.assertTrue(out["both_images_keep_both_prior_snapshot_labels"])
        self.assertFalse(out["swtpm_safe_revert_verified"])
        self.assertFalse(out["new_final_one_nic_running_snapshot_taken"])
    def test_unexpected_nic_rejected(self):
        with patch.object(m.dual,"virsh",return_value=DOMAIN.replace(
             'network="default"','network="cape-analysis-isolated"')),\
             self.assertRaisesRegex(m.RetireBlocked,"one-NIC"):
            m.single_nat_views()
    def test_before_requires_postnat_and_no_existing_cape_registration(self):
        ready={"new_snapshot_created":True,"CAPE_READY":False}
        unregistered={"registration":{
            "win11_1_registration_decision":"CREATE_NEW_STANZA"},
            "current_nat_agent_http_positive":True}
        with patch.object(m.post,"preflight",return_value=ready),\
             patch.object(m.cape,"inspect",return_value=unregistered):
            out=m.before()
        self.assertTrue(out["post_nat_running_snapshot_exists_in_both_images"])
        self.assertFalse(out["host_modified"])
        unregistered["registration"]["win11_1_registration_decision"]=(
            "UPDATE_EXISTING_STANZA")
        with patch.object(m.post,"preflight",return_value=ready),\
             patch.object(m.cape,"inspect",return_value=unregistered),\
             self.assertRaisesRegex(m.RetireBlocked,"not approved"):
            m.before()
    def test_only_exact_old_mac_detached_live_and_config(self):
        with tempfile.TemporaryDirectory() as td:
            calls=[]
            def virsh(*a):
                calls.append(a)
                if a[0]=="detach-interface":return ""
                raise AssertionError(a)
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                               st_uid=0,st_nlink=1)
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.PHRASE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"before",return_value={"ok":True}),\
                 patch.object(m,"inspect_after",return_value={
                    "old_isolated_mac_removed_from_saved_and_live":True}),\
                 patch.object(m.dual,"virsh",side_effect=virsh):
                report=m.retire()
            self.assertEqual(calls,[("detach-interface",VM,"network","--mac",
                                     m.MAC,"--live","--config")])
            self.assertFalse(report["final_snapshot_capture_permitted_automatically"])
    def test_partial_detach_error_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,
                               st_uid=0,st_nlink=1)
            calls=[]
            def bad(*a):
                calls.append(a)
                raise m.RetireBlocked("libvirt changed saved but not live")
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch("builtins.input",return_value=m.PHRASE),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch.object(m,"before",return_value={"ok":True}),\
                 patch.object(m.dual,"virsh",side_effect=bad),\
                 self.assertRaisesRegex(m.RetireBlocked,"POSSIBLE_PARTIAL"):
                m.retire()
            self.assertEqual(len(calls),1)
    def test_no_snapshot_capture_revert_or_wider_host_mutation(self):
        src=Path(m.__file__).read_text(encoding="utf-8")
        for token in ('"snapshot-create-as"','"snapshot-revert"',
           '"snapshot-delete"','"destroy"','"shutdown"','"start"',
           '"net-update"','os.replace(','shell=True'):
            self.assertNotIn(token,src)
if __name__=="__main__":unittest.main()
