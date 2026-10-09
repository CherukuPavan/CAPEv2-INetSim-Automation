#!/usr/bin/env python3
"""Offline Command 1 master handoff validation fixtures, no host access."""
import copy
import unittest

import command1_master_checkpoint as gate

BASE="/var/lib/libvirt/images/win11.qcow2"
OLD="/var/lib/libvirt/images/win11.basicinstallwinsnapshot"
MID="/var/lib/libvirt/images/win11.Afterfull"
TOP="/var/lib/libvirt/images/win11.finalshutoffversion"

def inventory():
    chain=[
        {"filename":TOP,"format":"qcow2","backing_filename":MID,
         "virtual_size":64*1024**3},
        {"filename":MID,"format":"qcow2","backing_filename":OLD,
         "virtual_size":64*1024**3},
        {"filename":OLD,"format":"qcow2","backing_filename":BASE,
         "virtual_size":64*1024**3},
        {"filename":BASE,"format":"qcow2","virtual_size":64*1024**3},
    ]
    return {
        "schema":"cape-master-vm-inventory-v1",
        "host":{"hostname":"synthetic-host"},
        "vm":{"name":"win11","uuid":"289d89be-68ec-4c62-90e1-ea930849266f",
              "state":"shut off","current_snapshot":"finalshutoffversion",
              "memory_kib":4194304,"vcpus":4,
              "qemu_guest_agent_channel_configured":False,
              "disks":[{"device":"disk","source_file":TOP,"format":"qcow2"}]},
        "snapshots":{"items":[
            {"name":"Afterfull","state":"running",
             "memory":{"snapshot":"external"},"disks":[]},
            {"name":"finalshutoffversion","state":"shutoff",
             "memory":{"snapshot":"no"},
             "disks":[{"snapshot":"external","source":TOP}]}]},
        "storage":{TOP:{"path":TOP,"backing_chain":chain,
                         "filesystem_available_bytes":600*1024**3}},
        "networks":[{"name":"default","forward_mode":"nat"}],
    }

class Tests(unittest.TestCase):
    def test_canonical_four_layer_snapshot_passes_structural(self):
        result=gate.validate_master(inventory())
        self.assertEqual(result["stage1_snapshot_structure"],"PASS")
        self.assertEqual(result["master"]["cold_snapshot"],"finalshutoffversion")
        self.assertEqual(result["master"]["layer_count"],4)
        self.assertEqual(result["changes"],"NONE; read-only checkpoint")
        self.assertTrue(any("Command 2" in x for x in result["pending_acceptance"]))

    def test_running_snapshot_refused(self):
        source=inventory()
        source["vm"]["current_snapshot"]="Afterfull"
        report=gate.validate_master(source)
        self.assertEqual(report["stage1_snapshot_structure"],"BLOCKED")
        self.assertTrue(report["blockers"])

    def test_missing_backing_layer_refused(self):
        source=inventory()
        chain=source["storage"][TOP]["backing_chain"]
        chain[0]["backing_filename"]="/missing"
        report=gate.validate_master(source)
        self.assertEqual(report["stage1_snapshot_structure"],"BLOCKED")

    def test_nonshutoff_master_refused(self):
        source=inventory()
        source["vm"]["state"]="running"
        report=gate.validate_master(source)
        self.assertEqual(report["stage1_snapshot_structure"],"BLOCKED")

    def test_snapshot_name_not_hardcoded(self):
        source=inventory()
        source["vm"]["current_snapshot"]="my-cold"
        source["snapshots"]["items"][1]["name"]="my-cold"
        report=gate.validate_master(source)
        self.assertEqual(report["master"]["cold_snapshot"],"my-cold")
        self.assertEqual(report["stage1_snapshot_structure"],"PASS")

    def test_missing_uuid_fails(self):
        source=inventory()
        source["vm"]["uuid"]="invalid"
        self.assertEqual(gate.validate_master(source)["stage1_snapshot_structure"],"BLOCKED")

if __name__=="__main__":
    unittest.main()
