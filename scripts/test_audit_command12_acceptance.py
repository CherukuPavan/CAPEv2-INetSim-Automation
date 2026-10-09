#!/usr/bin/env python3
"""Synthetic read-only acceptance audit tests; no host/VM operations."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import audit_command12_acceptance as a

class Tests(unittest.TestCase):
    def test_missing_optional_tool_has_unknown_version(self):
        with patch.object(a.shutil,"which",return_value=None):
            value=a.probe_version("virt-win-reg",["virt-win-reg","--version"])
        self.assertFalse(value["installed"])
        self.assertIsNone(value["version"])

    def test_collect_is_observational(self):
        fake={"schema":"cape-master-vm-inventory-v1",
              "host":{"hostname":"synthetic"},
              "vm":{"name":"win11","state":"shut off"},
              "snapshots":{},"storage":{},"networks":[],
              "cape":{},"warnings":[]}
        with patch.object(a.audit_clone_master,"collect",return_value=fake), \
             patch.object(a.command1_master_checkpoint,"validate_master",
                          return_value={"stage1_snapshot_structure":"BLOCKED"}), \
             patch.object(a,"probe_version",return_value={
                 "installed":False,"path":None,"version":None}), \
             patch.object(a,"read_value",return_value="0"), \
             patch.object(a.audit_clone_master,"virsh",
                          return_value={"ok":True,"stdout":"isolated\\n"}):
            value=a.collect("win11")
        self.assertEqual(value["mode"],"READ_ONLY")
        self.assertEqual(value["libvirt_network_names"],["isolated"])
        self.assertFalse(value["deployment_approved"])
        self.assertEqual(value["master_checkpoint"]["stage1_snapshot_structure"],
                         "BLOCKED")

    def test_probe_uses_fixed_version_command_without_shell(self):
        class Proc:
            returncode=0
            stdout="qemu-img version 9.2.2\\n"
            stderr=""
        with patch.object(a.shutil,"which",return_value="/usr/bin/qemu-img"), \
             patch.object(a.subprocess,"run",return_value=Proc()) as runner:
            value=a.probe_version("qemu-img",["qemu-img","--version"])
        self.assertIn("9.2.2",value["version"])
        self.assertNotIn("shell",runner.call_args.kwargs)

if __name__=="__main__":
    unittest.main()
