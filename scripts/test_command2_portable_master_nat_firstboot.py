"""Mock-only count-driven master-NAT clone first boot with guarded paused VM."""
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch

import command2_portable_master_nat_firstboot as m
VM="win11_1"
UUID="00000000-0000-4000-8000-000000000001"
MAC="02:ca:22:00:00:01"
SOURCE="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
ROW={"libvirt_name":VM,"libvirt_uuid_candidate":UUID,
     "mac_candidate":MAC,"disk_target":"/srv/clone/win11_1.qcow2",
     "uefi_nvram_target":"/srv/nvram/win11_1.fd"}
NAT=("<network><name>default</name><forward mode='nat'/>"
     "<bridge name='virbr0'/><ip address='192.168.122.1'>"
     "<dhcp><host mac='"+MAC+"' ip='192.168.122.201' "
     "name='WIN11-1'/></dhcp></ip></network>")
XML=("<domain type='kvm'><name>"+VM+"</name><uuid>"+UUID+
     "</uuid><os><nvram>"+ROW["uefi_nvram_target"]+"</nvram></os>"
     "<devices><disk device='disk'><source file='"+ROW["disk_target"]+
     "'/></disk><tpm><backend type='emulator' version='2.0'/></tpm>"
     "<interface type='network'><source network='default'/>"
     "<mac address='"+MAC+"'/><model type='e1000e'/></interface>"
     "</devices></domain>")
BASE={"result":"COMMAND2_MASTER_NAT_CLONE_FIRSTBOOT_PLAN_ONLY",
      "vm":VM,"uuid":UUID,"mac":MAC,
      "expected_reserved_ip":"192.168.122.201"}
JOURNAL=Path("/root/private/command2-identity-reservation.json")

class NatFirstBoot(unittest.TestCase):
    def test_plan_requires_exact_stopped_one_nic_nat_ip_and_no_snapshots(self):
        def fake(*args,**kw):
            if args==("list","--name"):return ""
            if args==("domstate",VM):return "shut off"
            if args==("snapshot-list",VM,"--name"):return ""
            if args[0]=="dumpxml":return XML
            raise AssertionError(args)
        net={"nat_network":"default","bridge":"virbr0",
             "ipv4":{"subnet":"192.168.122.0/24"}}
        from xml.etree.ElementTree import fromstring
        with patch.object(m.network.workflow,"canonical_host",return_value="lab02"),\
             patch.object(m.os,"geteuid",return_value=0),\
             patch.object(m.network,"journal_rows",return_value=[ROW]),\
             patch.object(m.network.profile,"check_master",return_value={
                  "master_left_shut_off":True}),\
             patch.object(m.network,"check_network_references",
                          return_value=(net,[fromstring(NAT),fromstring(NAT)])),\
             patch.object(m.network,"check_exact_guest",return_value={
                 "saved_nic_state":"SINGLE_MASTER_EQUIVALENT_NAT"}),\
             patch.object(m.network,"virsh",side_effect=fake):
            result=m.checked("lab02",JOURNAL,VM)
        self.assertTrue(result["source_master_shut_off"])
        self.assertEqual(result["expected_reserved_ip"],"192.168.122.201")
        self.assertFalse(result["windows_actual_boot_verified"])
        self.assertFalse(result["malware_analysis_authorized"])
    def test_second_guest_may_boot_only_after_prior_running_windows_verified(self):
        import ipaddress
        current="win11_2"
        oldrow={**ROW}
        net={"ipv4":{"subnet":"192.168.122.0/24",
                      "gateway":"192.168.122.1"}}
        cert={"format":"COMMAND2_WINDOWS_NAT_INDEPENDENT_ACCEPTANCE_V1",
              "host":"lab02","vm":VM,"uuid":UUID,"mac":MAC,
              "target_nat_ip":"192.168.122.201",
              "malware_analysis_authorized":False,
              "swtpm_consistent_revert_proven":False,
              **{x:True for x in (
                  "guest_hostname_effective","guest_only_expected_mac",
                  "guest_dhcp_exact_reserved_ipv4",
                  "guest_default_nat_gateway_and_dns",
                  "real_guest_https_from_nat_ipv4",
                  "guest_script_ran_in_verify_readonly_mode",
                  "CAPE_agent_through_new_nat_and_L2_mac_verified")}}
        def prior(*args,**kw):
            if args==("list","--name"):return VM
            if args==("domuuid",VM):return UUID
            if args==("domstate",VM):return "running"
            if args[0]=="dumpxml":return XML
            raise AssertionError(args)
        with patch.object(m.network,"virsh",side_effect=prior),\
             patch.object(m.transport,"verified_evidence_folder",
                          return_value=Path("/root/evidence")),\
             patch.object(m.acceptance.approved,"trusted_stage_json",
                          return_value=cert),\
             patch.object(m.agent_batch,"nic_xml",return_value=True),\
             patch.object(m.agent_batch,"route",
                          return_value={"dev":"virbr0",
                                        "prefsrc":"192.168.122.1"}),\
             patch.object(m.agent_batch,"agent",return_value={"valid":True}),\
             patch.object(m.transport,"mac_of_neighbor",return_value=MAC):
            found=m.completed_running_clones("lab02",[oldrow],current,net,
                Path("/root/evidence"))
            self.assertEqual(found[0]["reserved_ip"],"192.168.122.201")
            def prior_and_selected(*args,**kwargs):
                if args==("list","--name"):return VM+"\\n"+current
                return prior(*args,**kwargs)
            with patch.object(m.network,"virsh",side_effect=prior_and_selected):
                selected_running=m.completed_running_clones(
                    "lab02",[oldrow],current,net,Path("/root/evidence"),
                    requested_is_running=True)
            self.assertEqual(len(selected_running),1)
            self.assertEqual(selected_running[0]["vm"],VM)
            cert["real_guest_https_from_nat_ipv4"]=False
            with self.assertRaisesRegex(m.NatBootBlocked,"lacks exact"):
                m.completed_running_clones("lab02",[oldrow],current,net,
                     Path("/root/evidence"))
            cert["real_guest_https_from_nat_ipv4"]=True
            with self.assertRaisesRegex(m.NatBootBlocked,"not-yet-personalized"):
                m.completed_running_clones("lab02",[oldrow],"win11_1",net,
                     Path("/root/evidence"))

    def test_live_mac_must_be_exact(self):
        with patch.object(m.network,"virsh",return_value=XML):
            self.assertTrue(m.live_identity(VM,BASE))
        with patch.object(m.network,"virsh",
                          return_value=XML.replace(MAC,"02:ca:22:00:00:22")):
            with self.assertRaisesRegex(m.NatBootBlocked,"NIC"):
                m.live_identity(VM,BASE)
    def test_approved_start_paused_guard_resume_running(self):
        state=["shut off"]
        calls=[]
        def tool(*a,**kw):
            calls.append((a,kw))
            if a[:1]==("start",):
                self.assertEqual(a,("start",VM,"--paused"))
                self.assertEqual(kw,{"timeout":180})
                state[0]="paused"
                return ""
            if a[:1]==("resume",):
                self.assertEqual(a,("resume",VM))
                self.assertEqual(kw,{"timeout":120})
                state[0]="running"
                return ""
            if a==("domstate",VM):return state[0]
            if a==("domstate","win11"):return "shut off"
            raise AssertionError(a)
        fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m,"checked",return_value=BASE),\
                 patch.object(m,"live_identity",return_value=True) as proof,\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch("builtins.input",
                    return_value="BOOT-TRUSTED-MASTER-NAT-CLONE-WIN11_1"),\
                 patch.object(m.network,"virsh",side_effect=tool):
                result=m.boot("lab02",JOURNAL,VM)
            self.assertEqual([x[0][0] for x in calls],
                             ["start","domstate","domstate",
                              "resume","domstate"])
            self.assertEqual(proof.call_count,2)
            self.assertTrue(result["hypervisor_guest_running"])
            self.assertFalse(result["windows_actual_boot_verified"])
    def test_partial_resume_failure_preserves_paused_guest_no_retry(self):
        fs=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
        calls=[]
        def blocked(*a,**kw):
            calls.append(a)
            if a[0]=="start":return ""
            if a==("domstate",VM):return "paused"
            if a==("domstate","win11"):return "shut off"
            if a[0]=="resume":raise m.NatBootBlocked("resume refused")
            raise AssertionError(a)
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,"LOCK",Path(td)/"lock"),\
                 patch.object(m,"checked",return_value=BASE),\
                 patch.object(m,"live_identity",return_value=True),\
                 patch.object(m.sys.stdin,"isatty",return_value=True),\
                 patch.object(m.os,"fstat",return_value=fs),\
                 patch("builtins.input",
                    return_value="BOOT-TRUSTED-MASTER-NAT-CLONE-WIN11_1"),\
                 patch.object(m.network,"virsh",side_effect=blocked),\
                 self.assertRaisesRegex(m.NatBootBlocked,"PAUSED_OR_PARTIAL"):
                m.boot("lab02",JOURNAL,VM)
            self.assertEqual(sum(z[0]=="start" for z in calls),1)
            self.assertEqual(sum(z[0]=="resume" for z in calls),1)
            self.assertFalse(any(z[0] in ("destroy","snapshot-revert",
                           "snapshot-delete","shutdown") for z in calls))
    def test_no_unsafe_host_or_guest_mutator(self):
        text=Path(m.__file__).read_text(encoding="utf-8")
        for bad in ('"destroy"','"shutdown"','"snapshot-delete"',
           '"snapshot-revert"','"detach-interface"','"net-update"',
           'os.replace(','shell=True','Set-MpPreference'):
            self.assertNotIn(bad,text)

if __name__=="__main__":unittest.main()
