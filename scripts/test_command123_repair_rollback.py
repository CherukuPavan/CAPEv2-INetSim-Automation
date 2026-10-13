"""Offline tests: no host service restart, VM action or real CAPE changes."""
import hashlib
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
            "uid": 0, "gid": 0, "mode": 0o600}


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
        with mock.patch.object(m, "no_live_workloads"), \\
             mock.patch.object(m, "approve"), \\
             mock.patch.object(m, "private_folder"), \\
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
        with mock.patch.object(m, "no_live_workloads"), \\
             mock.patch.object(m, "approve"), \\
             mock.patch.object(m, "checked_blob", return_value=before), \\
             mock.patch.object(m, "replace_manifest"):
            m.apply(self.receipt, "newhost", "rollback")
        self.assertEqual(target.read_bytes(), before)

    def test_rollback_refuses_unknown_changes(self):
        self.doc["files"]["api.conf"]["before"] = state(b"original")
        self.doc["files"]["api.conf"]["after"] = state(b"installed")
        target = self.put("api.conf", b"edited by operator")
        result = m.state_plan(self.receipt, "newhost", "rollback")
        self.assertFalse(result["can_apply"])
        with mock.patch.object(m, "no_live_workloads"), \\
             mock.patch.object(m, "approve"):
            with self.assertRaises(m.RecoveryBlocked):
                m.apply(self.receipt, "newhost", "rollback")
        self.assertEqual(target.read_bytes(), b"edited by operator")

    def test_partial_receipt_cannot_mutate(self):
        self.doc["phase"] = "partial"
        with mock.patch.object(m, "no_live_workloads"), \\
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
                return SimpleNamespace(returncode=3)
            return SimpleNamespace(returncode=0, stdout="dummy-vm-uuid")
        with mock.patch.object(m.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(m.RecoveryBlocked):
                m.no_live_workloads()

    def test_live_cape_unit_blocks(self):
        with mock.patch.object(m.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0)):
            with self.assertRaises(m.RecoveryBlocked):
                m.no_live_workloads()


if __name__ == "__main__":
    unittest.main()
