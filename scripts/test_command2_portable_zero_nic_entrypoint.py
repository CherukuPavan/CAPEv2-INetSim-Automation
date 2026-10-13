"""Offline integration: candidate->reservation->staging gates (all mocked)."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_zero_nic_entrypoint as c


def sample_blueprint(count=2):
    rows=[]
    for i in range(1,count+1):
        rows.append({
            "libvirt_name":f"win11_{i}",
            "windows_hostname_target":f"WIN11-{i}",
            "guest_static_ipv4_target":f"192.168.240.{100+i}",
            "libvirt_uuid_candidate":f"00000000-0000-4000-8000-{i:012d}",
            "mac_candidate":f"02:aa:bb:cc:dd:{i:02x}",
            "disk_target":f"/images/win11_{i}.command2.qcow2",
            "uefi_nvram_target":f"/nvram/win11_{i}.command2_VARS.fd"})
    return {"result":"COMMAND2_CANDIDATE_IDENTITIES_ONLY",
            "requested_total":count,"candidates":rows}


def args(**extra):
    d=dict(count=2,approved_host="approved",disk_dir=Path("/images"),
           nvram_dir=Path("/nvram"),template=Path("/cold-template.qcow2"),
           template_sha256="a"*64,subnet="192.168.240.0/24",
           journal_dir=Path("/not-created"),mode="plan")
    d.update(extra)
    return d


class ControllerTests(unittest.TestCase):
    def test_ssl55_blocked_even_before_preflight(self):
        with patch.object(c.stager.socket,"gethostname",
                          return_value="CSE-SSL-55.campus"), \
             patch.object(c,"proposal",side_effect=AssertionError("No host scan")), \
             patch.object(c,"staging_dir",side_effect=AssertionError("No file writes")):
            with self.assertRaisesRegex(c.stager.StageBlocked,"SSL55_REFERENCE_ONLY"):
                c.execute(**args(mode="stage",approved_host="cse-ssl-55"))

    def test_plan_never_reserves_or_provisions(self):
        with patch.object(c,"guard_host"), \
             patch.object(c,"proposal",return_value=(
                 sample_blueprint(),{"resource_preflight_pass":True})), \
             patch.object(c.reserve,"reserve",side_effect=AssertionError("No reserve")), \
             patch.object(c.stager,"execute",side_effect=AssertionError("No stage")), \
             patch.object(c,"staging_dir",side_effect=AssertionError("No mkdir")):
            result=c.execute(**args())
        self.assertEqual(result["result"],"COMMAND2_ZERO_NIC_GROUP_PLAN_ONLY")
        self.assertEqual(result["names"],["win11_1","win11_2"])
        self.assertFalse(result["hosts_modified"])
        self.assertEqual(result["nics_attached"],0)

    def test_stage_requires_root_and_tty(self):
        with patch.object(c,"guard_host"), \
             patch.object(c,"proposal",return_value=(sample_blueprint(),{})), \
             patch.object(c.os,"geteuid",return_value=1000), \
             patch.object(c,"staging_dir",side_effect=AssertionError("No mkdir")):
            with self.assertRaisesRegex(c.Command2Blocked,"root"):
                c.execute(**args(mode="stage"))
        with patch.object(c,"guard_host"), \
             patch.object(c,"proposal",return_value=(sample_blueprint(),{})), \
             patch.object(c.os,"geteuid",return_value=0), \
             patch.object(c.sys.stdin,"isatty",return_value=False), \
             patch.object(c,"staging_dir",side_effect=AssertionError("No mkdir")):
            with self.assertRaisesRegex(c.Command2Blocked,"Interactive"):
                c.execute(**args(mode="stage"))

    def test_declined_authorization_is_nonmutating(self):
        with patch.object(c,"guard_host"), \
             patch.object(c,"proposal",return_value=(sample_blueprint(),{})), \
             patch.object(c.os,"geteuid",return_value=0), \
             patch.object(c.sys.stdin,"isatty",return_value=True), \
             patch("builtins.input",return_value="NO"), \
             patch.object(c,"staging_dir",side_effect=AssertionError("No mkdir")):
            with self.assertRaisesRegex(c.Command2Blocked,"approval"):
                c.execute(**args(mode="stage"))

    def test_stage_calls_reserved_identity_then_locked_stager(self):
        with tempfile.TemporaryDirectory() as td:
            state=Path(td)/"private";state.mkdir(mode=0o700)
            with patch.object(c,"guard_host"), \
                 patch.object(c,"proposal",return_value=(sample_blueprint(),{})), \
                 patch.object(c.os,"geteuid",return_value=0), \
                 patch.object(c.sys.stdin,"isatty",return_value=True), \
                 patch("builtins.input",return_value="APPROVE_COMMAND2_ZERO_NIC_APPROVED"), \
                 patch.object(c,"revalidate_before_reservation",return_value={"stage_resource_rechecked":True}), \
                 patch.object(c.stager,"virsh",return_value="<domain/>"), \
                 patch.object(c.stager,"validate_inputs",return_value=(1,2,"/src")) as master_check, \
                 patch.object(c.stager,"assert_no_collision"), \
                 patch.object(c,"staging_dir",return_value=state), \
                 patch.object(c.reserve,"reserve",return_value={
                     "guest_count":2,"guest_vm_created":False,
                     "status":"CANDIDATE_RESERVATION_RECORDED_NOT_DEPLOYED"}) as reserve_mock, \
                 patch.object(c,"source_profile",return_value=(
                     "f15ce036-e6e6-4bd4-955a-8b502ecf9581",Path("/firmware_VARS.fd"))), \
                 patch.object(c.stager,"execute",return_value={
                     "result":"PORTABLE_COMMAND2_ZERO_NIC_STAGED_NOT_PERSONALIZED",
                     "created":[{"name":"win11_1"},{"name":"win11_2"}]}) as stage_mock:
                outcome=c.execute(**args(mode="stage",journal_dir=state))
            self.assertEqual(outcome["result"],"COMMAND2_ZERO_NIC_GROUP_STAGE_RETURNED")
            self.assertFalse(outcome["production_ready"])
            self.assertEqual(len(outcome["guest_configuration_files"]),2)
            self.assertTrue((state/"command2-guest-config-win11_1.json").exists())
            self.assertTrue((state/"command2-guest-config-win11_2.json").exists())
            self.assertFalse(outcome["guest_personalization_done"])
            self.assertFalse(outcome["guest_personalization_done"])
            self.assertEqual(stage_mock.call_args.kwargs["mode"],"stage")
            self.assertEqual(stage_mock.call_args.kwargs["master_uuid"],
                             "f15ce036-e6e6-4bd4-955a-8b502ecf9581")
            self.assertEqual(reserve_mock.call_args.kwargs["expected_host"],"approved")
            master_check.assert_called_once()
            self.assertTrue(master_check.call_args.kwargs["audit_source"])

    def test_invalid_or_encrypted_master_blocked_before_journal_or_disk_write(self):
        # This failure used to happen only in the later stager, after
        # recording an exclusive journal that could not safely be retried.
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/"journal"
            checks=[]
            def impossible(*a,**kw):
                checks.append("template")
                raise c.stager.StageBlocked(
                    "Template plaintext Windows volume not verified")
            with patch.object(c,"guard_host"), \
                 patch.object(c,"proposal",return_value=(
                     sample_blueprint(),{"resource_preflight_pass":True})), \
                 patch.object(c.os,"geteuid",return_value=0), \
                 patch.object(c.sys.stdin,"isatty",return_value=True), \
                 patch("builtins.input",
                       return_value="APPROVE_COMMAND2_ZERO_NIC_APPROVED"), \
                 patch.object(c,"revalidate_before_reservation"), \
                 patch.object(c,"source_profile",return_value=(
                     "f15ce036-e6e6-4bd4-955a-8b502ecf9581",
                     Path("/firmware_VARS.fd"))), \
                 patch.object(c.stager,"virsh",return_value="<domain/>"), \
                 patch.object(c.stager,"validate_inputs",
                              side_effect=impossible), \
                 patch.object(c.reserve,"reserve") as reserve_mock, \
                 patch.object(c,"staging_dir") as mkdir_mock, \
                 patch.object(c.stager,"execute") as clone_mock:
                with self.assertRaisesRegex(c.stager.StageBlocked,
                                            "plaintext Windows"):
                    c.execute(**args(mode="stage",journal_dir=folder))
                reserve_mock.assert_not_called()
                mkdir_mock.assert_not_called()
                clone_mock.assert_not_called()
            self.assertEqual(checks,["template"])
            self.assertFalse(folder.exists())

    def test_master_memory_requirements_cannot_assume_four_gib(self):
        self.assertEqual(c.vm_memory_mib('<domain><memory unit="KiB">8388608</memory></domain>'),8192)
        with self.assertRaisesRegex(c.Command2Blocked,"RAM"):
            c.vm_memory_mib('<domain><memory unit="MiB">512</memory></domain>')
        with self.assertRaisesRegex(c.Command2Blocked,"memory unit"):
            c.vm_memory_mib('<domain><memory unit="units">4096</memory></domain>')

    def test_host_inventory_unique_mac_from_active_and_inactive(self):
        def virsh(*a):
            if a==("list","--all","--name"):return "win11\n"
            if a==("domuuid","win11"):return "f15ce036-e6e6-4bd4-955a-8b502ecf9581"
            if a==("domstate","win11"):return "shut off"
            if a==("dumpxml","--inactive","win11"):
                return '<domain><devices><interface><mac address="52:54:00:00:00:01"/></interface></devices></domain>'
            self.fail("Unexpected libvirt call: "+str(a))
        with patch.object(c.stager,"virsh",side_effect=virsh), \
             patch.object(c.audit,"json_command",return_value=[
                 {"ifname":"eno1","address":"00:16:3e:ab:cd:ef"}]):
            ids,macs=c.read_inventory()
        self.assertEqual(len(ids),1)
        self.assertIn("52:54:00:00:00:01",macs)
        self.assertIn("00:16:3e:ab:cd:ef",macs)


class StagingDriftTests(unittest.TestCase):
    def test_new_route_collision_before_reservation_is_blocked(self):
        facts={"available_ram_mib":60000}
        report={"preflight_pass":False,
                "errors":["ANALYSIS_SUBNET_OVERLAPS_ROUTES"],
                "detected_outbound_interface":"eno1"}
        with patch.object(c,"guard_host"), \
             patch.object(c.audit,"collect",return_value=facts), \
             patch.object(c.audit,"evaluate",return_value=report), \
             patch.object(c,"read_inventory",side_effect=AssertionError(
                 "Never reserve identities after failed recheck")):
            with self.assertRaisesRegex(c.Command2Blocked,"Pre-stage"):
                c.revalidate_before_reservation(
                    count=2,approved_host="approved",
                    disk_dir=Path("/images"),nvram_dir=Path("/nvram"),
                    template=Path("/base.qcow2"),
                    effective_subnet="192.168.241.0/24",
                    resources={"detected_outbound_interface":"eno1",
                               "actual_master_memory_mib":4096},
                    candidates=sample_blueprint())

    def test_outbound_interface_changed_refused(self):
        facts={"available_ram_mib":60000}
        report={"preflight_pass":True,"errors":[],
                "detected_outbound_interface":"enp7s0"}
        with patch.object(c,"guard_host"), \
             patch.object(c.audit,"collect",return_value=facts), \
             patch.object(c.audit,"evaluate",return_value=report):
            with self.assertRaisesRegex(c.Command2Blocked,"Outbound interface"):
                c.revalidate_before_reservation(
                    count=2,approved_host="approved",
                    disk_dir=Path("/images"),nvram_dir=Path("/nvram"),
                    template=Path("/base.qcow2"),
                    effective_subnet="192.168.241.0/24",
                    resources={"detected_outbound_interface":"eno1",
                               "actual_master_memory_mib":4096},
                    candidates=sample_blueprint())

    def test_valid_recheck_never_writes(self):
        facts={"available_ram_mib":60000}
        report={"preflight_pass":True,"errors":[],
                "detected_outbound_interface":"enp1s0"}
        with patch.object(c,"guard_host"), \
             patch.object(c.audit,"collect",return_value=facts), \
             patch.object(c.audit,"evaluate",return_value=report), \
             patch.object(c,"read_inventory",return_value=([],[])), \
             patch.object(c,"staging_dir",side_effect=AssertionError("Writes forbidden")):
            output=c.revalidate_before_reservation(
                count=2,approved_host="approved",
                disk_dir=Path("/images"),nvram_dir=Path("/nvram"),
                template=Path("/base.qcow2"),
                effective_subnet="192.168.241.0/24",
                resources={"detected_outbound_interface":"enp1s0",
                           "actual_master_memory_mib":4096},
                candidates=sample_blueprint())
        self.assertTrue(output["stage_resource_rechecked"])


if __name__=="__main__":
    unittest.main()
