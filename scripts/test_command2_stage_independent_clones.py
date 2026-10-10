#!/usr/bin/env python3
"""Offline-only multi-clone cold staging unit tests; no host mutations."""
import unittest
from unittest.mock import patch
from pathlib import Path
import xml.etree.ElementTree as ET
import command2_stage_independent_clones as m
import stage_first_no_nic_windows_clone as stage
from test_stage_first_no_nic_windows_clone import fixture

class Tests(unittest.TestCase):
    def test_numbering_hostname_ip_paths_and_no_duplication(self):
        items=m.planned(5)
        self.assertEqual([x["name"] for x in items],
                         ["win11_1","win11_2","win11_3","win11_4","win11_5"])
        self.assertEqual([x["windows_hostname"] for x in items],
                         ["WIN11-1","WIN11-2","WIN11-3","WIN11-4","WIN11-5"])
        self.assertEqual([x["future_ipv4"] for x in items],
                         ["192.168.240."+str(i) for i in range(101,106)])
        for item in items:
            self.assertTrue(item["disk"].endswith(item["name"]+".command2.qcow2"))
            self.assertTrue(item["nvram"].endswith(item["name"]+".command2_VARS.fd"))
            self.assertNotEqual(item["disk"],str(m.BASE/(item["name"]+".qcow2")))
            self.assertNotEqual(item["nvram"],str(m.NVBASE/(item["name"]+"_VARS.fd")))
        self.assertEqual(len(set(x["disk"] for x in items)),5)
        self.assertEqual(len(set(x["nvram"] for x in items)),5)

    def test_legacy_recovery_disk_is_never_the_command2_destination(self):
        entry=m.planned(1)[0]
        self.assertEqual(entry["name"],"win11_1")
        self.assertEqual(Path(entry["disk"]).name,"win11_1.command2.qcow2")
        self.assertEqual(Path(entry["nvram"]).name,"win11_1.command2_VARS.fd")
        self.assertNotEqual(Path(entry["disk"]).name,"win11_1.qcow2")
        self.assertNotEqual(Path(entry["nvram"]).name,"win11_1_VARS.fd")
        # Different storage names, same requested libvirt domain win11_1;
        # stage uses O_EXCL, destination checks, and never deletes old disks.

    def test_clone_count_bounded(self):
        for bad in (0,-1,17):
            with self.subTest(bad=bad),self.assertRaisesRegex(m.MultiStageError,"between"):
                m.planned(bad)

    def test_verified_no_nic_renderer_reused_not_natted(self):
        uid="af0ba1c2-f4c4-49a5-9111-513a9c405cae"
        item=m.planned(1)[0]
        xml=stage.render(fixture(),identifier=uid,
            name=item["name"],disk=Path(item["disk"]),
            nvram=Path(item["nvram"]))
        root=ET.fromstring(xml)
        self.assertEqual(root.findtext("name"),"win11_1")
        self.assertEqual(root.findtext("uuid"),uid)
        self.assertEqual(root.findtext("./os/nvram"),item["nvram"])
        self.assertEqual(root.find("./devices/disk[@device='disk']/source").get("file"),
                         item["disk"])
        self.assertFalse(root.findall("./devices/interface"))
        self.assertFalse(root.findall("./devices/channel"))
        self.assertFalse(root.findall("./devices/redirdev"))
        self.assertEqual(root.find("./devices/tpm/backend").get("version"),"2.0")
        self.assertEqual(root.find("./devices/graphics").get("listen"),"127.0.0.1")

    def test_renderer_refuses_path_alias_or_wrong_directory(self):
        with self.assertRaisesRegex(stage.StageError,"protected staging"):
            stage.render(fixture(),identifier="af0ba1c2-f4c4-49a5-9111-513a9c405cae",
                name="win11_1",disk="/var/lib/libvirt/images/win11_1.qcow2",
                nvram=str(m.NVBASE/"win11_1_VARS.fd"))

    def test_plan_keeps_disk_and_domain_untouched(self):
        entry=m.planned(1)
        with patch.object(m,"preflight",return_value=(entry,fixture(),("template",),("vars",),
                                              {"host_free_gib":512,"conservative_required_gib":94})),\
             patch.object(m,"provision") as prod,\
             patch.object(m.os,"open",return_value=99),\
             patch.object(m.os,"fstat") as fstat,\
             patch.object(m.os,"close"),\
             patch.object(m.fcntl,"flock"),\
             patch.object(m,"check",wraps=m.check):
            fstat.return_value.st_uid=0
            fstat.return_value.st_mode=0o600
            result=m.deploy(1,"plan")
        self.assertEqual(result["result"],"MULTI_CLONE_ZERO_NIC_PLAN_ONLY")
        prod.assert_not_called()

    def test_failure_retains_previously_created_clones(self):
        item=m.planned(2)
        def fake(entry,*args):
            if entry["name"]=="win11_2":raise m.MultiStageError("synthetic failed copy")
            return dict(entry,result="STAGED_SHUT_OFF_ZERO_NICS")
        with patch.object(m,"preflight",return_value=(item,fixture(),("template",),("vars",),
                                              {"host_free_gib":512,"conservative_required_gib":158})),\
             patch.object(m,"provision",side_effect=fake),\
             patch.object(m.os,"open",return_value=99),\
             patch.object(m.os,"fstat") as fstat,\
             patch.object(m.os,"close"),\
             patch.object(m.fcntl,"flock"):
            fstat.return_value.st_uid=0
            fstat.return_value.st_mode=0o600
            outcome=m.deploy(2,"stage")
        self.assertEqual(outcome["result"],"BLOCKED_OR_PARTIAL_REVIEW_REQUIRED")
        self.assertEqual([x["name"] for x in outcome["created"]],["win11_1"])
        self.assertFalse(outcome["analysis_network_connected"])
        self.assertFalse(outcome["malware_execution_authorized"])

    def test_copied_disk_must_verify_plaintext_before_nvram_or_domain_define(self):
        import json
        import tempfile
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            disk=root/"win11_1.qcow2"
            firmware=root/"win11_1_VARS.fd"
            entry={"name":"win11_1","disk":str(disk),
                   "nvram":str(firmware),"future_ipv4":"192.168.240.101"}
            def fake_cmd(*args,**kwargs):
                if args[:2]==("qemu-img","convert"):
                    Path(args[-1]).write_bytes(b"synthetic-qcow2")
                    return ""
                if args[:2]==("qemu-img","info"):
                    return json.dumps({"format":"qcow2",
                        "virtual-size":m.VIRTUAL_SIZE})
                return ""
            with (
                patch.object(m,"BASE",root),
                patch.object(m,"run_command",side_effect=fake_cmd) as calls,
                patch.object(m,"stamp",return_value=("fixed",)),
                patch.object(m,"virsh",return_value="shut off") as virsh_mock,
                patch.object(m.verified,"render",return_value="<domain/>"),
                patch.object(m.crypto,"require_cleartext_candidate",
                    side_effect=m.crypto.VolumeProbeError("encrypted")),
            ):
                with self.assertRaisesRegex(m.MultiStageError,"VERIFY_PLAINTEXT_OS"):
                    m.provision(entry,fixture(),("fixed",),("fixed",),set())
            self.assertFalse(disk.exists())
            self.assertFalse(firmware.exists())
            self.assertFalse(any(call.args[0]=="define" for call in virsh_mock.call_args_list))

    def test_verify_definition_rejects_natted_nic(self):
        item=m.planned(1)[0]
        uid="af0ba1c2-f4c4-49a5-9111-513a9c405cae"
        xml=stage.render(fixture(),identifier=uid,
            name=item["name"],disk=Path(item["disk"]),
            nvram=Path(item["nvram"]))
        xml=xml.replace("</devices>",'<interface type="network"><source network="default"/></interface></devices>')
        with patch.object(m,"virsh",side_effect=lambda *args:(
               "shut off" if args[0]=="domstate" else xml)),\
             patch.object(m,"run_command",return_value='{"format":"qcow2","virtual-size":68719476736}'):
            with self.assertRaisesRegex(m.MultiStageError,"unexpected|Unexpected"):
                m.verify_definition(item,uid)

if __name__=="__main__":
    unittest.main()
