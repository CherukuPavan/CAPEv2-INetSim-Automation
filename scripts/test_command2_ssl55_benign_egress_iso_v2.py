"""Offline tests for exact SSL55 benign-ISO gate; no host mutations."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_benign_egress_iso_v2 as b

def xml(*,source=None,network="cape-analysis-isolated",cdrom="sdb"):
    media=str(source or b.OLD)
    return (f'<domain><name>{b.VM}</name><uuid>{b.UUID}</uuid>'
            '<os><nvram>/var/lib/libvirt/qemu/nvram/'
            'win11_1.command2_VARS.fd</nvram></os><devices>'
            '<disk device="disk"><source file="'+b.DISK+'"/>'
            '<backingStore/></disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            '<interface><mac address="02:0a:30:6a:3f:50"/>'
            f'<source network="{network}"/></interface>'
            '<disk type="file" device="cdrom"><source file="'+media+'"/>'
            f'<target dev="{cdrom}"/><readonly/></disk>'
            '</devices></domain>')

class IsoGuards(unittest.TestCase):
    def test_reviewed_optical_model(self):
        self.assertEqual(b.domxml(xml())["target"],"sdb")
    def test_does_not_change_system_disk(self):
        with self.assertRaisesRegex(b.Blocked,"primary"):
            b.domxml(xml().replace(b.DISK,"/tmp/other.qcow2"))
    def test_refuse_new_media_before_user_authorization(self):
        with self.assertRaisesRegex(b.Blocked,"prior benign egress"):
            b.domxml(xml(source=b.NEW))
    def test_wrong_nic_refused(self):
        with self.assertRaisesRegex(b.Blocked,"NIC"):
            b.domxml(xml(network="default"))
    def test_wrong_cd_drive_refused(self):
        with self.assertRaisesRegex(b.Blocked,"Optical"):
            b.domxml(xml(cdrom="hdc"))
    def test_noninteractive_apply_no_mutation(self):
        with patch.object(b.sys.stdin,"isatty",return_value=False),\
             patch.object(b,"plan",side_effect=AssertionError("Must not plan")):
            with self.assertRaisesRegex(b.Blocked,"terminal"):
                b.apply(Path("p"),Path("c"))
    def test_declined_approval_does_not_run_media_update(self):
        with patch.object(b.sys.stdin,"isatty",return_value=True),\
             patch.object(b,"plan",return_value={"result":"PLAN"}),\
             patch("builtins.input",return_value="NO"),\
             patch.object(b,"virsh",side_effect=AssertionError("No mutation")):
            with self.assertRaisesRegex(b.Blocked,"approve"):
                b.apply(Path("p"),Path("c"))
    def test_v2_media_paths_are_distinct_and_never_reused(self):
        self.assertNotEqual(b.OLD,b.NEW)
        self.assertEqual(b.OLD.name,"win11_1.command2_benign_egress.iso")
        self.assertEqual(b.NEW.name,"win11_1.command2_benign_egress_v2.iso")

    def test_source_does_not_use_force_or_guest_exec(self):
        source=Path(b.__file__).read_text()
        for needle in ('virsh("destroy"', 'virsh("shutdown"',
                       'virsh("attach-interface"', 'virsh("snapshot-create-as"', 'virsh("snapshot-revert"',
                       'virsh("net-start"', 'virsh("net-autostart"',
                       '"--force"', '"qemu-monitor-command"'):
            self.assertNotIn(needle,source)


class RealisticVirshNetworkStatus(unittest.TestCase):
    NETWORK_INFO=("Name:           cape-analysis-isolated\n"
                  "UUID:           aaaa-bbbb\n"
                  "Active:         yes\n"
                  "Persistent:     yes\n"
                  "Autostart:      no\n"
                  "Bridge:         cape-lab0\n")

    def test_aligned_spaces_count_as_real_active_network(self):
        props=b.parse_network_info(self.NETWORK_INFO)
        self.assertEqual(props["active"],"yes")
        self.assertEqual(props["persistent"],"yes")
        self.assertEqual(props["autostart"],"no")
        self.assertEqual(props["bridge"],"cape-lab0")

    def test_multiple_spaces_and_tabs_are_accepted_as_whitespace(self):
        text="Active:\t yes\nPersistent:     yes\nAutostart: no\nBridge: cape-lab0"
        self.assertEqual(b.parse_network_info(text)["active"],"yes")

    def test_missing_or_duplicate_status_fails_closed(self):
        with self.assertRaisesRegex(b.Blocked,"Missing required"):
            b.parse_network_info("Active: yes")
        with self.assertRaisesRegex(b.Blocked,"Duplicate"):
            b.parse_network_info(self.NETWORK_INFO+"Active: no\n")

    def test_bad_boolean_format_refused(self):
        with self.assertRaisesRegex(b.Blocked,"Malformed"):
            b.parse_network_info(self.NETWORK_INFO.replace("Active:         yes","Active:         maybe"))

    def _execute_full_plan_with_network_status(self,active="yes"):
        from unittest.mock import patch
        import command2_ssl55_existing_guard_readonly as guard
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            old=root/"win11_1.command2_benign_egress.iso"
            new=root/"win11_1.command2_benign_egress_v2.iso"
            old.write_bytes(b"SAFE_FIX_OPTICAL_ISO")
            ps1=root/"probe.ps1"
            launcher=root/"run.cmd"
            ps1.write_text("Write-Host test",encoding="utf-8")
            launcher.write_text("@echo off",encoding="utf-8")

            netxml=('<network><name>cape-analysis-isolated</name>'
                    '<bridge name="cape-lab0"/>'
                    '<port isolated="yes"/>'
                    '<dns enable="no"/>'
                    '<ip address="192.168.240.1" netmask="255.255.255.0"/>'
                    '</network>')
            info=self.NETWORK_INFO.replace("Active:         yes",
                                           "Active:         "+active)
            commands=[]
            def fake_virsh(*args):
                commands.append(args)
                if args[:1]==("domuuid",):
                    return {b.VM:b.UUID,b.MASTER[0]:b.MASTER[1],
                            b.TRIAL[0]:b.TRIAL[1]}[args[1]]
                if args[:1]==("domstate",):
                    return "running" if args[1]==b.VM else "shut off"
                if args[:1]==("snapshot-list",):return ""
                if args[:1]==("dumpxml",):return xml()
                if args==("net-info",b.NET):return info
                if args==("net-dumpxml",b.NET):return netxml
                self.fail("Unexpected / possibly modifying virsh command: "+str(args))
            def fake_command(*args,**kw):
                if args[:2]==("systemctl","is-active"):return "active"
                if args[:3]==("nft","-j","list"):return '{"nftables":[]}'
                if args[:2]==("nft","list"):return 'table inet cape_analysis_guard'
                self.fail("Unexpected / potentially modifying host command "+str(args))
            with patch.object(b,"DIR",root),patch.object(b,"OLD",old), \
                 patch.object(b,"NEW",new),patch.object(b.os,"geteuid",return_value=0), \
                 patch.object(b.socket,"gethostname",return_value="CSE-SSL-55"), \
                 patch.object(b,"virsh",side_effect=fake_virsh), \
                 patch.object(b,"command",side_effect=fake_command), \
                 patch.object(b.shutil,"which",return_value="/usr/bin/genisoimage"), \
                 patch.object(guard,"guard_policy_structure",return_value={}):
                if active=="yes":
                    result=b.plan(ps1,launcher)
                    self.assertEqual(result["result"],"BENIGN_EGRESS_V2_ISO_PLAN_ONLY")
                    self.assertTrue(result["no_host_guest_changes"])
                else:
                    with self.assertRaisesRegex(b.Blocked,"network inactive"):
                        b.plan(ps1,launcher)
            self.assertFalse(new.exists())
            self.assertFalse(any(call[0] in ("change-media","start","net-start") for call in commands))

    def test_exact_full_preflight_accepts_spaced_active_libvirt_output(self):
        self._execute_full_plan_with_network_status(active="yes")

    def test_exact_full_preflight_refuses_actually_inactive_network(self):
        self._execute_full_plan_with_network_status(active="no")

if __name__=="__main__":
    unittest.main()
