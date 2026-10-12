"""Synthetic-only count-prompt golden master Command2 wizard tests."""
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest
import json

import command2_from_exact_master_bundle as m
import command1_export_existing_master as g

UUID="289d89be-68ec-4c62-90e1-ea930849266f"
def mocks(count):
    return {"host":"lab02","bundle":Path("/root/priv/cape-master-gold"),
            "template":Path("/root/priv/cape-master-gold/master-image.qcow2"),
            "disk_sha":"a"*64,"manifest_sha":"b"*64,
            "disk_dir":Path("/var/lib/libvirt/images"),
            "nvram_dir":Path("/var/lib/libvirt/qemu/nvram"),
            "journal_dir":Path("/root/j"),
            "iso_dir":Path("/root/isomedia")}

class GoldenWizard(unittest.TestCase):
    def test_wizard_prompts_for_additional_vm_count_not_total(self):
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch("builtins.input",return_value="3"):
            self.assertEqual(m.count_from_args(None),3)
        for n in (0,-1,17):
            with self.assertRaises(m.GoldenCommand2Blocked):
                m.count_from_args(n)
        with patch.object(m.sys.stdin,"isatty",return_value=False),\
             self.assertRaisesRegex(m.GoldenCommand2Blocked,"TTY"):
            m.count_from_args(None)

    def test_plan_never_claims_windows_boot_or_snapshots(self):
        with patch.object(m,"paths",return_value=mocks(3)),\
             patch.object(m.clones.stager,"virsh",return_value="shut off"),\
             patch.object(m.clones,"source_profile",
                          return_value=(UUID,Path("/original/uefi.fd"))),\
             patch.object(m.clones,"proposal",return_value=(
                  {"candidates":[{"libvirt_name":x}
                        for x in ("win11_1","win11_2","win11_3")]},
                  {"capacity_ok":True})),\
             patch.object(m.nat_plan,"check_active_nat",
                 return_value={"nat_network":"default","bridge":"virbr0",
                               "ipv4":{"subnet":"192.168.122.0/24"}}),\
             patch.object(m.golden,"MANIFEST",g.MANIFEST),\
             patch.object(m.json,"loads",return_value={
                     "master_uuid":UUID}),\
             patch.object(m.Path,"read_text",return_value="{}"):
            r=m.run("plan","lab02",Path("/root/priv/cape-master-gold"),
              Path("/disk"),Path("/vars"),Path("/journal"),Path("/isos"),3)
        self.assertEqual(r["count_additional_vms"],3)
        self.assertEqual(r["names"],["win11_1","win11_2","win11_3"])
        self.assertTrue(r["source_windows_apps_registry_files_preserved_by_image_clone"])
        self.assertFalse(r["Command2_finished"])
        self.assertFalse(r["all_N_guest_firstboot_automatic"])
        self.assertFalse(r["malware_execution_authorized"])

    def test_stage_does_not_misidentify_unattached_isos_as_finished_command2(self):
        args=("lab02",Path("/root/priv/cape-master-gold"),Path("/disk"),
              Path("/vars"),Path("/journal"),Path("/isos"),2)
        with patch.object(m,"paths",return_value=mocks(2)),\
             patch.object(m.clones.stager,"virsh",return_value="shut off"),\
             patch.object(m.clones,"source_profile",
                          return_value=(UUID,Path("/original/uefi.fd"))),\
             patch.object(m.clones,"proposal",
                         return_value=({},{"ram_checked":True})),\
             patch.object(m.nat_plan,"check_active_nat",
                 return_value={"nat_network":"default","bridge":"virbr0",
                               "ipv4":{"subnet":"192.168.122.0/24"}}),\
             patch.object(m.json,"loads",return_value={
                     "master_uuid":UUID}),\
             patch.object(m.Path,"read_text",return_value="{}"),\
             patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch("builtins.input",
                   return_value="STAGE-2-EXACT-MASTER-WINDOWS-CLONES"),\
             patch.object(m.clones,"execute",return_value={
                 "result":"COMMAND2_ZERO_NIC_GROUP_STAGE_RETURNED"}) as stager,\
             patch.object(m.nat,"apply",return_value={
                 "result":"COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED"}) as nic,\
             patch.object(m.media,"build",return_value={
                 "result":"COMMAND2_ALL_N_WINDOWS_NAT_ISOS_BUILT_NOT_ATTACHED"}) as media:
            o=m.run("stage",*args)
        stager.assert_called_once()
        nic.assert_called_once()
        media.assert_called_once()
        self.assertFalse(o["end_to_end_unattended_complete"])
        self.assertTrue(o["windows_guest_boot_and_identity_still_required"])
        self.assertFalse(o["malware_execution_authorized"])
        self.assertEqual(o["names"],["win11_1","win11_2"])

    def test_private_bundle_and_isolated_legacy_ip_not_deployed_directly(self):
        s=Path(m.__file__).read_text()
        for fragment in ('"snapshot-revert"','"snapshot-delete"',
              '"destroy"','"shutdown"','"net-update"',
              'shell=True','os.unlink(','os.replace('):
            self.assertNotIn(fragment,s)
        self.assertIn('"old_isolated_journal_ip_not_for_nic_application":True',s)
        self.assertIn('"legacy_guest_isolated_config_JSON_must_not_be_run":True',s)

if __name__=="__main__":unittest.main()
