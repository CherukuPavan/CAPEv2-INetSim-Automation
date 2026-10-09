#!/usr/bin/env python3
"""Mock full Command 2 lifecycle: never touch real disks, guests or libvirt."""
from pathlib import Path
import unittest
from unittest.mock import patch

import command2_clone_vms as c

MASTER = """<domain><name>win11</name>
<uuid>289d89be-68ec-4c62-90e1-ea930849266f</uuid></domain>"""

PROFILE = {
    "master":"win11", "snapshot":"finalshutoffversion",
    "disk_dir":"/var/lib/libvirt/images/clones",
    "nvram_dir":"/var/lib/libvirt/qemu/nvram",
    "old_ipv4":"198.51.100.105","mask":"255.255.255.0",
    "gateway":"198.51.100.1","dns":"198.51.100.2",
    "network":"cape-isolated", "snapshot_name":"cape-clean"
}
GUEST={"name":"win11_1","ip":"198.51.100.110","windows_hostname":"WIN11-1"}


class LifecycleTests(unittest.TestCase):
    def run_flow(self, fail_agent: bool=False):
        steps=[]
        def mark(what):
            def action(*args,**kwargs):
                steps.append(what)
                if what == "export":
                    return {"executed":True}
                if what == "agent":
                    if fail_agent:
                        raise RuntimeError("Wrong CAPE agent")
                    self.assertEqual(kwargs["interface"],"virbr2")
                    self.assertEqual(kwargs["expected_mac"],
                                     c.make_mac("289d89be-68ec-4c62-90e1-ea930849266f","win11_1"))
                    return {"ping":"PASS","cape_curl_equivalent":"PASS"}
                if what == "render":
                    return "<domain/>"
                return None
            return action
        operations=["export","ip","nvram","render","define","verifyxml",
                    "tpm","agent","snapshot","shutdown"]
        patches=[
            patch.object(c.export_cold_master_disk,"export",side_effect=mark("export")),
            patch.object(c.personalize_clone_windows,"prepare",side_effect=mark("ip")),
            patch.object(c,"copy_nvram",side_effect=mark("nvram")),
            patch.object(c.clone_domain_xml,"render",side_effect=mark("render")),
            patch.object(c,"define",side_effect=mark("define")),
            patch.object(c,"verify_clone_definition",side_effect=mark("verifyxml")),
            patch.object(c.guard_vm_tpm_socket,"prepare",side_effect=mark("tpm")),
            patch.object(c.verify_clone_agent,"wait_for_agent",side_effect=mark("agent")),
            patch.object(c,"snapshot_running",side_effect=mark("snapshot")),
            patch.object(c,"guest_shutdown",side_effect=mark("shutdown")),
            patch.object(c,"virsh",side_effect=lambda *args,**kwargs: steps.append("virsh:"+args[0])),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        events=[]
        if fail_agent:
            with self.assertRaisesRegex(RuntimeError,"Wrong CAPE agent"):
                c.create_one(GUEST,PROFILE,MASTER,
                    "/var/lib/libvirt/qemu/nvram/win11_VARS.fd","virbr2",
                    lambda e: events.append(e["state"]))
        else:
            result=c.create_one(GUEST,PROFILE,MASTER,
                "/var/lib/libvirt/qemu/nvram/win11_VARS.fd","virbr2",
                lambda e: events.append(e["state"]))
            self.assertEqual(result["agent_verification"]["ping"],"PASS")
        return steps,events

    def test_full_verified_clone_pipeline_order(self):
        steps,events=self.run_flow()
        self.assertEqual(steps[:7],
                         ["export","ip","nvram","render","define","verifyxml","tpm"])
        self.assertEqual(steps.count("agent"),3)
        self.assertIn("virsh:snapshot-revert",steps)
        self.assertLess(steps.index("ip"),steps.index("virsh:start"))
        self.assertLess(steps.index("tpm"),steps.index("virsh:start"))
        self.assertLess(steps.index("snapshot"),steps.index("virsh:snapshot-revert"))
        self.assertEqual(events[-1],"CLONE_SHUT_OFF_READY_FOR_CAPE_REGISTRATION")

    def test_agent_failure_stops_only_new_clone_without_snapshot(self):
        steps,events=self.run_flow(fail_agent=True)
        self.assertIn("virsh:destroy",steps)
        self.assertNotIn("snapshot",steps)
        self.assertNotIn("virsh:snapshot-revert",steps)
        self.assertNotIn("CLONE_SHUT_OFF_READY_FOR_CAPE_REGISTRATION",events)

if __name__=="__main__":
    unittest.main()
