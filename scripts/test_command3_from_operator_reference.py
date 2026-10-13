"""Synthetic-only Command3 one-entrypoint orchestration regression tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import command3_from_operator_reference as m

INITIAL = {
    "api": {"result":"COMMAND3_API_RATELIMIT_PLAN_ONLY",
            "status":"NO_CHANGE_ALREADY_CONFIGURED",
            "before_sha256":"a", "after_sha256":"a"},
    "auxiliary": {"result":"COMMAND3_AUXILIARY_PLAN_ONLY",
                  "status":"ALREADY_CONFIGURED",
                  "before_sha256":"b", "after_sha256":"b"},
    "cuckoo": {"result":"COMMAND3_CUCKOO_STEP3_PLAN_ONLY",
               "status":"READY_TO_APPLY",
               "before_sha256":"c", "after_sha256":"cc"},
    "kvm": {"result":"COMMAND3_KVM_ALL_N_PLAN_ONLY",
            "source_sha256":"d", "target_sha256":"dd"},
    "mitmdump": {"result":"COMMAND3_MITMDUMP_STEP5_PLAN_ONLY",
                 "status":"READY_TO_APPLY",
                 "before_sha256":"e", "after_sha256":"ee"},
}
ROUTE = {
    "result":"COMMAND3_ROUTING_STEP6_UNSAFE_REFERENCE_PLAN_ONLY",
    "unsupported_automatic_apply":True, "host_modified":False,
}
ORDER = ["api","auxiliary","cuckoo","kvm","mitmdump"]

class JoinedCommand3Tests(unittest.TestCase):
    def context(self, tmp):
        base = Path(tmp) / "CAPEv2" / "conf"
        base.mkdir(parents=True)
        return SimpleNamespace(
            approved_host="other-host",
            journal=Path(tmp) / "journal.json",
            master_ip="192.168.122.125",
            master_snapshot="Afterfull", tag="win11",
            conf_dir=base,
            backup_dir=Path(tmp) / "backups",
            witness_dir=Path(tmp) / "witness",
            db_dsn_file=None)

    def patch_plans(self, test):
        return [
            patch.object(m.api, "plan", return_value=deepcopy(INITIAL["api"])),
            patch.object(m.aux, "plan", return_value=deepcopy(INITIAL["auxiliary"])),
            patch.object(m.cuckoo, "plan",
                         return_value=deepcopy(INITIAL["cuckoo"])),
            patch.object(m.kvm, "plan", return_value=deepcopy(INITIAL["kvm"])),
            patch.object(m.mitm, "plan",
                         return_value=deepcopy(INITIAL["mitmdump"])),
            patch.object(m.route, "plan", return_value=deepcopy(ROUTE)),
            patch.object(m, "target_tmpfs_ready",
                         return_value={"status":"TARGET_ON_MOUNT_READY"}),
        ]

    def test_config_path_layout_and_step_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.context(tmp)
            resolved = m.named_configs(args.conf_dir)
            self.assertEqual(list(resolved), [
                "api", "auxiliary", "cuckoo", "kvm", "mitmdump", "routing"])
            self.assertEqual(resolved["kvm"].name, "kvm.conf")

    def test_plan_readonly_and_routing_not_claimed_applied(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.tmpfs, "assess",
                return_value={"cape_tmpfs_prerequisite_ready":True}))
            stack.enter_context(patch.object(m.services, "report",
                side_effect=AssertionError("Plan must not inspect services")))
            stack.enter_context(patch.object(m.api, "apply",
                side_effect=AssertionError("No config writes")))
            result = m.review(args)
            self.assertEqual([r["name"] for r in result["config_stages"]],
                             ORDER)
            self.assertEqual(result["pending_changes"],
                             ["cuckoo", "kvm", "mitmdump"])
            self.assertFalse(result["host_modified"])
            self.assertFalse(result["CAPE_READY"])
            self.assertFalse(result["five_config_files_match_target"])
            self.assertTrue(result["verified_target_tmpfs_mounted"])
            self.assertFalse(result["routing_auto_apply_supported"])
            self.assertFalse(result["service_auto_restart_supported"])
            self.assertIsNone(result["service_readiness"])

    def test_verify_reads_service_without_mutating(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.tmpfs, "assess",
                return_value={"cape_tmpfs_prerequisite_ready":True}))
            ser = stack.enter_context(patch.object(m.services, "report",
                return_value={"all_services_active_now":True,
                              "CAPE_READY":False}))
            result = m.review(args, verify=True)
            self.assertEqual(result["result"],
                             "COMMAND3_JOINED_VERIFY_READ_ONLY")
            self.assertFalse(result["CAPE_READY"])
            self.assertTrue(result["all_five_service_units_active_readonly"])
            self.assertFalse(result["five_config_files_match_target"])
            ser.assert_called_once_with(
                args.conf_dir / "routing.conf", "verify",
                args.conf_dir / "cuckoo.conf")

    def test_operator_refusal_makes_no_receipt_or_write(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(m.sys.stdin, "isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="other-host"))
            stack.enter_context(patch("builtins.input",return_value="NO"))
            stack.enter_context(patch.object(m, "write_witness",
                side_effect=AssertionError("Never write witness")))
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "not approved"):
                m.configure(args)
            self.assertFalse(args.witness_dir.exists())

    def test_all_five_applied_and_every_milestone_recorded(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.os, "geteuid", return_value=0))
            stack.enter_context(patch.object(m.sys.stdin, "isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="other-host"))
            stack.enter_context(patch("builtins.input",
                                              return_value=m.APPROVAL))
            stack.enter_context(patch.object(m,"private_witness_dir",
                                              return_value=args.witness_dir))
            checkpoints = []
            stack.enter_context(patch.object(
                m, "write_witness",
                side_effect=lambda path, value, **kwargs:
                    checkpoints.append(deepcopy(value))))
            run_order = []
            def apply(name):
                run_order.append(name)
                return {"result":"OK_"+name, "applied":True,
                        "backup_path":"/private/backups/"+name}
            stack.enter_context(patch.object(
                m.api,"apply", side_effect=lambda *a: apply("api")))
            stack.enter_context(patch.object(
                m.aux,"apply", side_effect=lambda *a: apply("auxiliary")))
            stack.enter_context(patch.object(
                m.cuckoo,"apply", side_effect=lambda *a: apply("cuckoo")))
            stack.enter_context(patch.object(
                m.kvm,"apply", side_effect=lambda *a: apply("kvm")))
            stack.enter_context(patch.object(
                m.mitm,"apply", side_effect=lambda *a: apply("mitmdump")))
            stack.enter_context(patch.object(m.services, "report",
                side_effect=AssertionError("No service operations")))
            result = m.configure(args)
            self.assertEqual(run_order, ORDER)
            self.assertEqual([s["name"] for s in result["steps"]], ORDER)
            self.assertEqual(result["result"],
                             "COMMAND3_FIVE_CONFIG_FILES_APPLIED_NO_RESTART")
            self.assertEqual(checkpoints[0]["result"],
                             "COMMAND3_CONFIG_BATCH_STARTED")
            self.assertEqual(checkpoints[-1]["result"], result["result"])
            self.assertFalse(result["services_restarted"])
            self.assertFalse(result["Command3_final_release_complete"])
            for step in checkpoints:
                self.assertNotIn("password", str(step).lower())

    def test_apply_stops_after_failed_step_with_partial_witness(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.os,"geteuid",return_value=0))
            stack.enter_context(patch.object(m.sys.stdin,"isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="other-host"))
            stack.enter_context(patch("builtins.input",return_value=m.APPROVAL))
            stack.enter_context(patch.object(m, "private_witness_dir",
                                              return_value=args.witness_dir))
            milestones=[]
            stack.enter_context(patch.object(m, "write_witness",
                side_effect=lambda path,val,**kw:
                    milestones.append(deepcopy(val))))
            stack.enter_context(patch.object(m.api,"apply",
                return_value={"result":"API_OK","applied":True}))
            stack.enter_context(patch.object(m.aux,"apply",
                side_effect=RuntimeError("SENSITIVE_DO_NOT_WRITE")))
            cuckoo=stack.enter_context(patch.object(m.cuckoo,"apply",
                side_effect=AssertionError("Do not continue")))
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "PARTIAL_OR_UNKNOWN"):
                m.configure(args)
            self.assertEqual(milestones[-1]["failed_step"], "auxiliary")
            self.assertEqual(milestones[-1]["result"],
                             "COMMAND3_CONFIG_BATCH_PARTIAL_OR_UNKNOWN")
            self.assertNotIn("SENSITIVE_DO_NOT_WRITE",str(milestones))
            self.assertEqual(milestones[-1]["completed"][0]["name"],"api")
            cuckoo.assert_not_called()

    def test_missing_target_tmpfs_blocks_config_before_any_file_write(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            for p in self.patch_plans(self):
                stack.enter_context(p)
            stack.enter_context(patch.object(m.os,"geteuid",return_value=0))
            stack.enter_context(patch.object(m.sys.stdin,"isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="other-host"))
            stack.enter_context(patch.object(m,"target_tmpfs_ready",
                 side_effect=m.Command3PipelineBlocked("missing tmpfs")))
            a=stack.enter_context(patch.object(m.api,"apply",
                      side_effect=AssertionError("No partial changes")))
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "missing tmpfs"):
                m.configure(args)
            a.assert_not_called()
            self.assertFalse(args.witness_dir.exists())

    def test_actual_target_mount_checks_require_tmpfs_and_cape_owner(self):
        import stat
        fake = SimpleNamespace(st_mode=stat.S_IFDIR|0o750,
                               st_uid=1500,st_gid=1600)
        vfs = SimpleNamespace(f_bavail=6000,f_frsize=1024*1024)
        with patch.object(m.tmpfs,"mount_fstype",return_value="tmpfs"), \
             patch.object(m.tmpfs,"cape_ids",return_value=(1500,1600)), \
             patch.object(m.os,"stat",return_value=fake), \
             patch.object(m.os,"statvfs",return_value=vfs), \
             patch.object(m.Path, "is_symlink",return_value=False):
            data=m.target_tmpfs_ready()
            self.assertEqual(data["status"],"TARGET_ON_MOUNT_READY")
            self.assertEqual(data["required_free_mib"],4096)
            with patch.object(m.tmpfs,"mount_fstype",return_value=None), \
                 self.assertRaisesRegex(m.Command3PipelineBlocked,
                                         "not actually mounted"):
                m.target_tmpfs_ready()
            vfs.f_bavail=3000
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "enough available tmpfs"):
                m.target_tmpfs_ready()

    def test_protected_ssl55_never_applies_even_with_root(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args = self.context(td)
            args.approved_host="CSE-SSL-55"
            stack.enter_context(patch.object(m.os,"geteuid",return_value=0))
            stack.enter_context(patch.object(m.sys.stdin,"isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="CSE-SSL-55"))
            stack.enter_context(patch.object(m,"five_plans",
                side_effect=AssertionError("Never even plan mutation")))
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "SSL-55"):
                m.configure(args)

    def test_rejects_plan_drift_after_initial_approval(self):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            args=self.context(td)
            paths=m.named_configs(args.conf_dir)
            stable=[(name,deepcopy(val)) for name,val in INITIAL.items()]
            changed=deepcopy(stable)
            changed[0][1]["after_sha256"]="drifted"
            pre=stack.enter_context(patch.object(
                m,"five_plans",side_effect=[(paths,stable),(paths,changed)]))
            stack.enter_context(patch.object(m.os,"geteuid",return_value=0))
            stack.enter_context(patch.object(m.sys.stdin,"isatty",
                                              return_value=True))
            stack.enter_context(patch.object(m.socket,"gethostname",
                                              return_value="other-host"))
            stack.enter_context(patch.object(m.route,"plan",
                                              return_value=deepcopy(ROUTE)))
            stack.enter_context(patch.object(m,"target_tmpfs_ready",
                  return_value={"status":"TARGET_ON_MOUNT_READY"}))
            stack.enter_context(patch("builtins.input",return_value=m.APPROVAL))
            w=stack.enter_context(patch.object(m,"write_witness"))
            with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                        "changed before batch"):
                m.configure(args)
            w.assert_not_called()
            self.assertEqual(pre.call_count,2)

    def test_real_witness_created_private_and_second_write_rejects_untrusted(self):
        with tempfile.TemporaryDirectory() as td:
            record = Path(td)/"receipt.json"
            m.write_witness(record, {"step":1}, first=True)
            self.assertEqual(record.read_text().strip(),'{\n  "step": 1\n}')
            self.assertEqual(record.stat().st_mode & 0o777,0o600)
            # In unprivileged CI the second update must refuse a witness
            # that isn't genuinely root owned.
            if record.stat().st_uid != 0:
                with self.assertRaisesRegex(m.Command3PipelineBlocked,
                                            "Untrusted existing witness"):
                    m.write_witness(record, {"step":2})
            else:
                m.write_witness(record, {"step":2})
                self.assertIn('"step": 2', record.read_text())


if __name__ == "__main__":
    unittest.main()
