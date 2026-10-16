"""Offline tests: no host service restart, VM action or real CAPE changes."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import command123_repair_rollback as m


def state(blob):
    if blob is None:
        return None
    return {"sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob),
            "uid": os.getuid(), "gid": os.getgid(), "mode": 0o600}


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.conf = self.root / "conf"
        self.conf.mkdir(mode=0o700)
        self.receipt = self.root / "receipt" / "manifest.json"
        self.receipt.parent.mkdir(mode=0o700)
        self.doc = {
            "schema": 1, "host": "newhost", "phase": "sealed",
            "files": {name: {"before": None, "after": None}
                      for name in m.NAMES},
        }
        p = mock.patch.object(m, "CONF", self.conf)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(m, "read_manifest", return_value=self.doc)
        p.start()
        self.addCleanup(p.stop)

    def put(self, name, data):
        path = self.conf / name
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def test_fresh_host_baseline_before_cape_exists(self):
        recovery = self.root / "recovery"
        recovery.mkdir(mode=0o700)
        with mock.patch.object(m, "ROOT", recovery), \
             mock.patch.object(m, "CONF", self.root / "not-installed"), \
             mock.patch.object(m, "ensure_root"), \
             mock.patch.object(m, "private_folder"), \
             mock.patch.object(m, "approve"), \
             mock.patch.object(m, "current_host", return_value="newhost"):
            result = m.baseline("newhost")
        stored = json.loads(Path(result["receipt"]).read_text())
        self.assertEqual(stored["phase"], "baseline")
        self.assertTrue(all(row["before"] is None for row in
                            stored["files"].values()))

    def test_repair_missing_file_recreates_exact_sealed_content(self):
        self.doc["files"]["api.conf"]["after"] = state(b"good-sealed")
        with mock.patch.object(m, "no_live_workloads"), \
             mock.patch.object(m, "approve"), \
             mock.patch.object(m, "checked_blob",
                               return_value=b"good-sealed"), \
             mock.patch.object(m, "replace_manifest"), \
             mock.patch.object(m.os, "fchown"):
            result = m.apply(self.receipt, "newhost", "repair")
        self.assertEqual(result["result"], "CAPE_REPAIR_TRACKED_CONFIGS_DONE")
        self.assertEqual((self.conf / "api.conf").read_bytes(), b"good-sealed")

    def test_repair_only_missing_sealed_configuration(self):
        self.doc["files"]["api.conf"]["after"] = state(b"expected-api")
        plan = m.state_plan(self.receipt, "newhost", "repair")
        d = {item["config"]: item["action"] for item in plan["actions"]}
        self.assertTrue(plan["can_apply"])
        self.assertEqual(d["api.conf"], "recreate_from_sealed")
        self.assertEqual(d["routing.conf"], "keep")

    def test_repair_refuses_to_replace_modified_config(self):
        self.doc["files"]["api.conf"]["after"] = state(b"desired")
        path = self.put("api.conf", b"unrelated-operator-edit")
        result = m.state_plan(self.receipt, "newhost", "repair")
        self.assertFalse(result["can_apply"])
        self.assertIn("api.conf", result["blocked"])
        self.assertEqual(path.read_bytes(), b"unrelated-operator-edit")

    def test_rollback_new_file_uses_private_quarantine(self):
        self.doc["files"]["kvm.conf"]["after"] = state(b"generated")
        path = self.put("kvm.conf", b"generated")
        plan = m.state_plan(self.receipt, "newhost", "rollback")
        d = {item["config"]: item["action"] for item in plan["actions"]}
        self.assertEqual(d["kvm.conf"], "quarantine_new_config")
        with mock.patch.object(m, "no_live_workloads"), \
             mock.patch.object(m, "approve"), \
             mock.patch.object(m, "private_folder"), \
             mock.patch.object(m, "replace_manifest"):
            result = m.apply(self.receipt, "newhost", "rollback")
        self.assertEqual(result["result"], "CAPE_ROLLBACK_TRACKED_CONFIGS_DONE")
        self.assertFalse(path.exists())
        self.assertEqual(
            (self.receipt.parent / "quarantine" / "kvm.conf").read_bytes(),
            b"generated")

    def test_rollback_restores_exact_before_data(self):
        before = b"old-before"
        after = b"new-after"
        self.doc["files"]["api.conf"]["before"] = state(before)
        self.doc["files"]["api.conf"]["after"] = state(after)
        target = self.put("api.conf", after)
        with mock.patch.object(m, "no_live_workloads"), \
             mock.patch.object(m, "approve"), \
             mock.patch.object(m, "checked_blob", return_value=before), \
             mock.patch.object(m, "replace_manifest"):
            m.apply(self.receipt, "newhost", "rollback")
        self.assertEqual(target.read_bytes(), before)

    def test_rollback_refuses_unknown_changes(self):
        self.doc["files"]["api.conf"]["before"] = state(b"original")
        self.doc["files"]["api.conf"]["after"] = state(b"installed")
        target = self.put("api.conf", b"edited by operator")
        result = m.state_plan(self.receipt, "newhost", "rollback")
        self.assertFalse(result["can_apply"])
        with mock.patch.object(m, "no_live_workloads"), \
             mock.patch.object(m, "approve"):
            with self.assertRaises(m.RecoveryBlocked):
                m.apply(self.receipt, "newhost", "rollback")
        self.assertEqual(target.read_bytes(), b"edited by operator")

    def test_partial_receipt_cannot_mutate(self):
        self.doc["phase"] = "partial"
        with mock.patch.object(m, "no_live_workloads"), \
             mock.patch.object(m, "approve"):
            with self.assertRaises(m.RecoveryBlocked):
                m.apply(self.receipt, "newhost", "repair")

    def test_original_hosts_rejected(self):
        for hostname in ("CSE-SSL-55", "CSE-SSL-46"):
            with mock.patch.object(m.socket, "gethostname",
                                   return_value=hostname):
                with self.assertRaises(m.RecoveryBlocked):
                    m.current_host(hostname)

    def test_config_paths_fixed_and_symlinks_rejected(self):
        with self.assertRaises(m.RecoveryBlocked):
            m.guard_file_path(self.root / "random.conf")
        external = self.root / "elsewhere"
        external.write_text("not a CAPE config")
        (self.conf / "api.conf").symlink_to(external)
        with self.assertRaises(m.RecoveryBlocked):
            m.snapshot_file(self.conf / "api.conf")

    def test_live_vm_check_refuses_nonzero_running_domains(self):
        def fake_run(cmd, **kwargs):
            if cmd[0] == "systemctl":
                return SimpleNamespace(returncode=0,
                    stdout="LoadState=not-found\nActiveState=inactive\n")
            if "list" in cmd:
                return SimpleNamespace(returncode=0,stdout="win11_1\n")
            return SimpleNamespace(returncode=0,stdout="running\n")
        with mock.patch.object(m.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(
                    m.RecoveryBlocked,"Cannot prove every CAPE service"):
                m.no_live_workloads()

    def test_paused_and_suspended_guests_block_config_recovery(self):
        for state in ("paused", "pmsuspended", "crashed"):
            with self.subTest(state=state):
                def fake(cmd, **kwargs):
                    if cmd[0] == "systemctl":
                        return SimpleNamespace(returncode=0,
                            stdout="LoadState=not-found\nActiveState=inactive\n")
                    if "list" in cmd:
                        return SimpleNamespace(returncode=0,
                                               stdout="win11_1\n")
                    return SimpleNamespace(returncode=0,stdout=state+"\n")
                with mock.patch.object(m.subprocess,"run",side_effect=fake):
                    with self.assertRaisesRegex(
                            m.RecoveryBlocked,"Cannot prove every CAPE service"):
                        m.no_live_workloads()

    def test_failed_unit_blocks_even_without_running_guest(self):
        def fake(cmd, **kwargs):
            if cmd[0] == "systemctl":
                return SimpleNamespace(returncode=0,
                    stdout="LoadState=loaded\nActiveState=failed\n")
            raise AssertionError("Must refuse failed CAPE service first")
        with mock.patch.object(m.subprocess,"run",side_effect=fake):
            with self.assertRaisesRegex(
                    m.RecoveryBlocked,"Cannot prove every CAPE service"):
                m.no_live_workloads()

    def test_live_cape_unit_blocks(self):
        with mock.patch.object(m.subprocess, "run",
                               return_value=SimpleNamespace(
                                 returncode=0,
                                 stdout="LoadState=loaded\nActiveState=active\n")):
            with self.assertRaises(m.RecoveryBlocked):
                m.no_live_workloads()

if __name__ == "__main__":
    unittest.main()
