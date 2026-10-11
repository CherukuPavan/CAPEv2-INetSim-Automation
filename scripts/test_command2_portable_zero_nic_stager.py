"""Offline synthetic safety tests; no actual disks, libvirt or VM creation."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_zero_nic_stager as stage


def entry(index=1):
    name=f"win11_{index}"
    return {"libvirt_name":name,
       "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{index:012d}",
       "smbios_generation_id_candidate":f"00000000-0000-4000-8001-{index:012d}",
       "mac_candidate":f"02:aa:bb:cc:dd:{index:02x}",
       "guest_static_ipv4_target":f"192.168.240.{100+index}",
       "windows_hostname_target":f"WIN11-{index}",
       "disk_target":f"/var/lib/libvirt/images/cape-analysis/{name}.command2.qcow2",
       "uefi_nvram_target":f"/var/lib/libvirt/qemu/nvram/{name}.command2_VARS.fd"}


def reservation_data(rows, host="approved"):
    return {"format":"CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION",
            "version":1,"host":host,"state":"CANDIDATES_RECORDED_NOT_APPLIED",
            "provisioning_started":False,"libvirt_domains_created":False,
            "host_network_modified":False,"guest_count":len(rows),"entries":rows}


class StageTests(unittest.TestCase):
    def test_reference_host_refuses_before_any_host_or_disk_call(self):
        with patch.object(stage.socket,"gethostname",return_value="CSE-SSL-55.campus"), \
             patch.object(stage,"exact_dir",side_effect=AssertionError("Filesystem touched")), \
             patch.object(stage,"virsh",side_effect=AssertionError("libvirt touched")):
            with self.assertRaisesRegex(stage.StageBlocked,"SSL55_REFERENCE_ONLY"):
                stage.execute(mode="stage",approved_host="cse-ssl-55",
                              journal_dir=Path("/unused"),template=Path("/unused"),
                              template_sha256="0"*64,master_nvram=Path("/unused"),
                              master_uuid="0"*36)

    def test_renamed_ssl55_preservation_sentinel_still_blocks_staging(self):
        with tempfile.TemporaryDirectory() as d:
            marker=Path(d)/"known-ssl55-preservation"
            marker.mkdir()
            with patch.object(stage.socket,"gethostname",return_value="renamed-reference"), \
                 patch.object(stage,"SSL55_PRESERVATION_SENTINEL",marker), \
                 patch.object(stage,"virsh",side_effect=AssertionError("No libvirt calls")), \
                 patch.object(stage,"atomic_note",side_effect=AssertionError("No writes")):
                with self.assertRaisesRegex(stage.StageBlocked,"preservation sentinel"):
                    stage.host_guard("renamed-reference",for_stage=True)

    def test_hostname_mismatch_and_root_required(self):
        with patch.object(stage.socket,"gethostname",return_value="elsewhere"):
            with self.assertRaisesRegex(stage.StageBlocked,"differs"):
                stage.host_guard("approved",for_stage=False)
        with patch.object(stage.socket,"gethostname",return_value="approved"), \
             patch.object(stage.os,"geteuid",return_value=1000):
            with self.assertRaisesRegex(stage.StageBlocked,"root"):
                stage.host_guard("approved",for_stage=True)

    def test_reservation_rejects_duplicate_uuid_and_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"journal";folder.mkdir(mode=0o700)
            file=folder/stage.reservation.RECORD_NAME
            def inspect(rows):
                file.write_text(json.dumps(reservation_data(rows)))
                file.chmod(0o600)
                with patch.object(stage,"exact_file",return_value=(1,2,3,4,5)), \
                     patch.object(stage,"exact_dir",return_value=folder):
                    return stage.reservation_entries(folder,"approved")
            self.assertEqual(len(inspect([entry()])),1)
            clash=entry(2)
            clash["libvirt_uuid_candidate"]=entry()["libvirt_uuid_candidate"]
            with self.assertRaisesRegex(stage.StageBlocked,"Duplicate"):
                inspect([entry(),clash])
            clash=entry(2)
            clash["disk_target"]=entry()["disk_target"]
            with self.assertRaisesRegex(stage.StageBlocked,"path"):
                inspect([entry(),clash])
            file.write_text(json.dumps(reservation_data([entry()],"different")))
            with patch.object(stage,"exact_file",return_value=(1,2,3,4,5)), \
                 patch.object(stage,"exact_dir",return_value=folder):
                with self.assertRaisesRegex(stage.StageBlocked,"Untrusted"):
                    stage.reservation_entries(folder,"approved")

    def test_real_preflight_must_pass_and_match_reserved_plan(self):
        with patch.object(stage.hostaudit,"collect",return_value={"synthetic":True}), \
             patch.object(stage.hostaudit,"evaluate",return_value={
                 "preflight_pass":False,"errors":["KVM_DEVICE_MISSING"]}):
            with self.assertRaisesRegex(stage.StageBlocked,"KVM_DEVICE_MISSING"):
                stage.target_host_preflight([entry()],"/template","192.168.240.0/24")
        with patch.object(stage.hostaudit,"collect",return_value={"synthetic":True}), \
             patch.object(stage.hostaudit,"evaluate",return_value={
                 "preflight_pass":True,
                 "planned_vms":[{"libvirt_name":"win11_1",
                                 "hostname":"WIN11-1",
                                 "planned_ipv4":"192.168.240.999",
                                 "disk":entry()["disk_target"],
                                 "nvram":entry()["uefi_nvram_target"]}]}):
            with self.assertRaisesRegex(stage.StageBlocked,"differs"):
                stage.target_host_preflight([entry()],"/template","192.168.240.0/24")

    def test_readonly_plan_no_mutating_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"journal";folder.mkdir(mode=0o700)
            with patch.object(stage.socket,"gethostname",return_value="approved"), \
                 patch.object(stage,"reservation_entries",return_value=[entry(),entry(2)]), \
                 patch.object(stage,"validate_inputs",return_value=(1,2,"/source/master.qcow2")), \
                 patch.object(stage,"target_host_preflight",return_value={"preflight_pass":True}), \
                 patch.object(stage,"assert_no_collision"), \
                 patch.object(stage,"virsh",return_value="<domain/>"), \
                 patch.object(stage,"free_bytes",return_value=1000*stage.GIB), \
                 patch.object(stage,"make_one",side_effect=AssertionError("VM creation attempted")), \
                 patch.object(stage,"atomic_note",side_effect=AssertionError("Journal wrote")):
                result=stage.execute(
                    mode="plan",approved_host="approved",journal_dir=folder,
                    template=Path("/approved/template.qcow2"),template_sha256="a"*64,
                    master_nvram=Path("/approved/VARS.fd"),
                    master_uuid="11111111-1111-4111-8111-111111111111")
            self.assertEqual(result["result"],"PORTABLE_COMMAND2_ZERO_NIC_STAGE_PLAN_ONLY")
            self.assertEqual(result["created"],[])
            self.assertFalse(result["windows_ip_assigned"])
            self.assertEqual(result["attached_nics"],0)

    def test_source_template_and_uefi_cannot_be_shared_with_other_domain(self):
        def fake_virsh(*argv):
            if argv == ("list","--all","--name"):
                return "win11\nother_guest"
            if argv == ("domstate","other_guest"):
                return "shut off"
            if argv == ("dumpxml","--inactive","other_guest"):
                return ('<domain><os><nvram>/approved/source-vars.fd</nvram></os>'
                        '<devices><disk><source file="/approved/unrelated.qcow2"/>'
                        '</disk></devices></domain>')
            self.fail("unexpected command "+str(argv))
        with patch.object(stage,"virsh",side_effect=fake_virsh):
            with self.assertRaisesRegex(stage.StageBlocked,"UEFI variables are shared"):
                stage.assert_cold_source_unshared(
                    "/approved/template.qcow2","/approved/source-vars.fd")

    def test_collision_rejects_existing_domain_before_creation(self):
        with patch.object(stage,"virsh",side_effect=lambda *a:
            "win11_1" if a[:2]==("list","--all") else ""):
            with self.assertRaisesRegex(stage.StageBlocked,"already defined"):
                stage.assert_no_collision([entry()])

    def test_insufficient_group_capacity_refuses_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"journal";folder.mkdir(mode=0o700)
            with patch.object(stage.socket,"gethostname",return_value="approved"), \
                 patch.object(stage,"reservation_entries",return_value=[entry(),entry(2)]), \
                 patch.object(stage,"validate_inputs",return_value=(1,2,"/master")), \
                 patch.object(stage,"target_host_preflight",return_value={"preflight_pass":True}), \
                 patch.object(stage,"assert_no_collision"), \
                 patch.object(stage,"virsh",return_value="<domain/>"), \
                 patch.object(stage,"free_bytes",return_value=96*stage.GIB), \
                 patch.object(stage,"atomic_note",side_effect=AssertionError("Unexpected write")):
                with self.assertRaisesRegex(stage.StageBlocked,"capacity"):
                    stage.execute(mode="plan",approved_host="approved",
                        journal_dir=folder,template=Path("/template"),
                        template_sha256="a"*64,master_nvram=Path("/vars"),
                        master_uuid="11111111-1111-4111-8111-111111111111")

    def test_intents_exclusively_published_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"journal";folder.mkdir(mode=0o700)
            path=folder/(stage.INTENT_PREFIX+"win11_1.json")
            stage.atomic_note(folder,path.name,{"stage":"BEFORE_ANY_CLONE_FILES"})
            self.assertEqual(json.loads(path.read_text())["stage"],"BEFORE_ANY_CLONE_FILES")
            with self.assertRaises(FileExistsError):
                stage.atomic_note(folder,path.name,{"stage":"retry"})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_prior_intent_refuses_plan_and_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/"journal";folder.mkdir(mode=0o700)
            (folder/(stage.INTENT_PREFIX+"win11_1.json")).write_text("{}")
            with patch.object(stage.socket,"gethostname",return_value="approved"), \
                 patch.object(stage,"reservation_entries",return_value=[entry()]), \
                 patch.object(stage,"validate_inputs",return_value=(1,2,"/master")), \
                 patch.object(stage,"target_host_preflight",return_value={"preflight_pass":True}), \
                 patch.object(stage,"assert_no_collision"), \
                 patch.object(stage,"virsh",return_value="<domain/>"), \
                 patch.object(stage,"free_bytes",return_value=500*stage.GIB):
                with self.assertRaisesRegex(stage.StageBlocked,"Previous staging intent"):
                    stage.execute(mode="plan",approved_host="approved",
                        journal_dir=folder,template=Path("/template"),
                        template_sha256="a"*64,master_nvram=Path("/vars"),
                        master_uuid="11111111-1111-4111-8111-111111111111")

    def test_make_one_retains_partial_intent_if_copy_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            disk=folder/"win11_1.command2.qcow2"
            vars=folder/"win11_1.command2_VARS.fd"
            row=entry();row["disk_target"]=str(disk);row["uefi_nvram_target"]=str(vars)
            with patch.object(stage,"virsh",return_value="shut off"), \
                 patch.object(stage,"exact_file",return_value=(1,2,3,4,5)), \
                 patch.object(stage,"free_bytes",return_value=1000*stage.GIB), \
                 patch.object(stage.renderer,"render_no_nic",return_value="<domain/>"), \
                 patch.object(stage,"assert_cold_source_unshared"), \
                 patch.object(stage,"run",side_effect=stage.StageBlocked("synthetic qemu failure")):
                with self.assertRaisesRegex(stage.StageBlocked,"incomplete stage"):
                    stage.make_one(row,master_xml="<domain/>",
                        master_disk="/master",master_nvram="/vars",
                        template=Path("/template"),source_stamp=(1,2,3,4,5),
                        vars_stamp=(1,2,3,4,5),logdir=folder)
            self.assertTrue((folder/(stage.INTENT_PREFIX+"win11_1.json")).exists())
            self.assertFalse(disk.exists())
            self.assertFalse(vars.exists())

    def test_full_synthetic_zero_nic_stage_emits_completion_and_independent_artifacts(self):
        import tempfile
        row=entry()
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            source=root/"source.qcow2";source.write_bytes(b"independent synthetic disk")
            fw=root/"master_VARS.fd";fw.write_bytes(b"synthetic firmware vars")
            row["disk_target"]=str(root/"win11_1.command2.qcow2")
            row["uefi_nvram_target"]=str(root/"win11_1.command2_VARS.fd")
            candidate_xml=(f'<domain><name>win11_1</name>'
                f'<uuid>{row["libvirt_uuid_candidate"]}</uuid>'
                f'<genid>{row["smbios_generation_id_candidate"]}</genid>'
                f'<os><nvram>{row["uefi_nvram_target"]}</nvram></os>'
                f'<devices><disk device="disk"><source file="{row["disk_target"]}"/>'
                '</disk><tpm><backend type="emulator" version="2.0"/></tpm>'
                '</devices></domain>')
            calls=[]
            def fake_run(*args,**kwargs):
                calls.append(args)
                if args[:2]==("qemu-img","convert"):
                    Path(args[-1]).write_bytes(b"synthetic fake QCOW2")
                    return ""
                if args[:2]==("qemu-img","info"):
                    return json.dumps({"format":"qcow2","virtual-size":stage.VIRTUAL_BYTES})
                if args[:2]==("qemu-img","check"):
                    return ""
                self.fail("unexpected host command: "+str(args))
            def fake_virsh(*args):
                if args==("domstate","win11") or args==("domstate","win11_1"):
                    return "shut off"
                if args==("dumpxml","--inactive","win11_1"):
                    return candidate_xml
                if args==("dumpxml","--inactive","win11"):
                    return "<domain/>"
                if args[0]=="define":
                    data=Path(args[1]).read_text()
                    self.assertNotIn("<interface",data)
                    return ""
                self.fail("unexpected libvirt call: "+str(args))
            orig_temp=tempfile.TemporaryDirectory
            with patch.object(stage,"exact_file",return_value=(1,2,3,4,5)), \
                 patch.object(stage,"free_bytes",return_value=1024*stage.GIB), \
                 patch.object(stage,"run",side_effect=fake_run), \
                 patch.object(stage,"virsh",side_effect=fake_virsh), \
                 patch.object(stage,"digest_file",wraps=stage.digest_file), \
                 patch.object(stage.crypto,"require_cleartext_candidate"), \
                 patch.object(stage.renderer,"render_no_nic",return_value=candidate_xml), \
                 patch.object(stage,"assert_cold_source_unshared"), \
                 patch.object(stage.os,"fchown"), \
                 patch.object(stage.tempfile,"TemporaryDirectory",
                              side_effect=lambda **kwargs: orig_temp(dir=td)):
                result=stage.make_one(row,master_xml="<domain/>",
                    master_disk="/source/master.qcow2",master_nvram=fw,
                    template=source,source_stamp=(1,2,3,4,5),
                    vars_stamp=(1,2,3,4,5),logdir=root)
            self.assertEqual(result["status"],"SHUT_OFF_ZERO_NICS_STAGED")
            self.assertEqual(result["nic_count"],0)
            self.assertTrue(Path(row["disk_target"]).exists())
            self.assertEqual(Path(row["uefi_nvram_target"]).read_bytes(),fw.read_bytes())
            self.assertTrue((root/(stage.INTENT_PREFIX+"win11_1.json")).exists())
            self.assertTrue((root/(stage.COMPLETE_PREFIX+"win11_1.json")).exists())
            self.assertTrue(any(call[:2]==("qemu-img","convert") for call in calls))
            self.assertFalse(list(root.glob(".command2-incomplete-*")))

    def test_source_does_not_start_or_attach_network(self):
        source=Path(stage.__file__).read_text()
        for code in ('virsh("start"', 'virsh("destroy"', 'virsh("shutdown"',
                     '"net-start"', '"attach-interface"', '"nft", "flush"',
                     '"systemctl", "enable"'):
            self.assertNotIn(code,source)
        self.assertIn('"network_attached":False',source)


if __name__=="__main__":
    unittest.main()
