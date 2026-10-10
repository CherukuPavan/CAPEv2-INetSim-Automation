#!/usr/bin/env python3
"""Synthetic preboot audit checks; no QEMU/libvirt/AppArmor access."""
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import audit_first_no_nic_windows_clone as a

class Tests(unittest.TestCase):
    def test_running_master_blocks_before_disk_access(self):
        with patch.object(a.os,"geteuid",return_value=0), \
             patch.object(a,"virsh",return_value="running"), \
             patch.object(a,"safe_regular") as check:
            with self.assertRaisesRegex(a.AuditError,"Original master is running"):
                a.inspect_domain()
            check.assert_not_called()

    def test_missing_root_blocks_before_virsh(self):
        with patch.object(a.os,"geteuid",return_value=1000), \
             patch.object(a,"virsh") as virsh:
            with self.assertRaisesRegex(a.AuditError,"sudo"):
                a.inspect_domain()
            virsh.assert_not_called()

    def test_disabled_apparmor_blocks(self):
        with patch.object(Path,"read_text",return_value="N"):
            with self.assertRaisesRegex(a.AuditError,"AppArmor is not enabled"):
                a.inspect_host()

    def test_report_contains_no_secrets(self):
        with patch.object(a,"inspect_domain",return_value=None), \
             patch.object(a,"inspect_disk",return_value={
                 "clone_qcow2_independent":True}), \
             patch.object(a,"inspect_host",return_value={
                 "trial_swtpm_socket_rule":"MISSING_REQUIRES_REVIEW"}):
            out=io.StringIO()
            with redirect_stdout(out):
                a.main()
            report=json.loads(out.getvalue())
            self.assertEqual(report["status"],
                             "OFFLINE_TRIAL_CLONE_PREBOOT_AUDIT_PASSED")
            self.assertEqual(report["guest_nic_count"],0) if "guest_nic_count" in report else None
            self.assertNotIn("tpm_secret",out.getvalue().lower())
            self.assertTrue(report["clone_vm_shutoff"])

if __name__=="__main__":
    unittest.main()
