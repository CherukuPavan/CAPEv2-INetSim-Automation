"""Synthetic tests for tracked rootless CAPE Python312 offline installation."""
from __future__ import annotations

from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import command1_cape_runtime_rootless_stage as stage


class RootlessRuntimeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="cape-rootless-unit-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.target_root=self.root/"runtimes"
        self.target_root.mkdir()
        self.checkout=self.root/"CAPEv2"
        self.checkout.mkdir()
        self.transaction="e"*32
        self.revision="a"*40
        self.account=SimpleNamespace(
            pw_name="cape", pw_uid=777, pw_gid=777)
        self.source_entry={
            "kind":"cape_source","status":"sealed",
            "target":str(self.checkout),"revision":self.revision,
            "after":{"revision":self.revision,"file_count":100}
        }
        self.document={
            "phase":"active",
            "entries":[dict(self.source_entry)]
        }
        self.manifest=self.root/"approved-manifest.json"
        self.manifest.write_text(json.dumps({
            "wheels":{"gevent":{"version":"24.2.1"},
                      "greenlet":{"version":"3.0.3"}}}))
        self.lock=self.root/"exact-170-lock.txt"
        self.lock.write_text("approved fixture")
        self.wheels=self.root/"wheels"
        self.wheels.mkdir()
        self.uv=self.root/"trusted-uv"
        self.python=self.root/"python3.12"
        self.params=(
            "test-host",self.transaction,self.manifest,self.lock,
            self.wheels,"1"*64,self.uv,"2"*64,self.python,"3"*64,
            "cape"
        )
        self.proposed={
            "transaction":self.transaction,
            "runtime_target":str(self.target_root/self.transaction/"venv"),
            "cape_upstream_source":str(self.checkout),
            "source_commit":self.revision,
            "packages_verified":2,
            "result":"CAPE_ROOTLESS_OFFLINE_INSTALL_PLAN_ONLY"
        }

    def stubs(self,stack):
        stack.enter_context(mock.patch.object(stage.tx,"host_guard"))
        stack.enter_context(mock.patch.object(
            stage,"verified_runtime_release",return_value="26.04"))
        stack.enter_context(mock.patch.object(
            stage.tx,"load",return_value=(self.root/"receipt.json",
                                         self.document)))
        stack.enter_context(mock.patch.object(
            stage.source,"pristine",
            return_value=self.source_entry["after"]))
        stack.enter_context(mock.patch.object(
            stage,"sha_file",
            side_effect=lambda p: "2"*64 if p==self.uv else "3"*64))
        stack.enter_context(mock.patch.object(
            stage.wheels,"plan",
            return_value={"source_sha":self.revision,
                          "packages_verified":2}))
        stack.enter_context(mock.patch.object(
            stage,"verify_root_immutable_inputs",
            return_value={
                "immutable_input_paths_verified":7,
                "immutable_root_owned_wheels_verified":2}))
        stack.enter_context(mock.patch.object(
            stage,"user_account",return_value=self.account))
        stack.enter_context(mock.patch.object(
            stage,"stage_parent",return_value=self.target_root))

    def test_runtime_inputs_reject_world_writable_staging_ancestors(self):
        # The /tmp parent is intentionally world writable. Production
        # runtime artifacts must live in a root-owned protected tree.
        for _ in range(160):
            (self.wheels / ("pkg%03d-1.0-py3-none-any.whl" % _)).write_bytes(
                b"reviewed fixture")
        with self.assertRaisesRegex(stage.RuntimeBlocked,
                                    "writable/untrusted"):
            stage.verify_root_immutable_inputs(
                manifest=self.manifest,lock=self.lock,
                wheelhouse=self.wheels,uv=self.uv,
                python=self.python,cape_source=self.checkout)

    def test_root_owned_protected_170_wheels_accepted_under_mocked_stat(self):
        import os
        import stat
        real = Path.lstat
        for n in range(170):
            (self.wheels / ("package%03d-1.0-py3-none-any.whl" % n)).write_bytes(
                b"benign bytes")
        self.uv.write_bytes(b"mock-uv")
        self.python.write_bytes(b"mock-python")
        from types import SimpleNamespace
        def protected(node):
            current=real(node)
            # Filesystem ownership is simulated; the test never chowns or
            # mutates actual host directories or privileged /opt locations.
            return SimpleNamespace(
                st_uid=0,st_mode=current.st_mode & ~0o022,
                st_nlink=current.st_nlink,st_size=current.st_size)
        with mock.patch.object(Path,"lstat",new=protected):
            witness=stage.verify_root_immutable_inputs(
                manifest=self.manifest,lock=self.lock,
                wheelhouse=self.wheels,uv=self.uv,
                python=self.python,cape_source=self.checkout)
        self.assertEqual(witness["immutable_root_owned_wheels_verified"],170)
        self.assertGreater(witness["immutable_input_paths_verified"],7)

    def test_nonroot_wheel_or_group_writable_root_wheel_is_refused(self):
        from types import SimpleNamespace
        import stat
        real=Path.lstat
        victim=self.wheels/"bad-1.0-py3-none-any.whl"
        for n in range(159):
            (self.wheels / ("good%03d-1.0-py3-none-any.whl" % n)).write_bytes(
                b"test")
        victim.write_bytes(b"test")
        self.uv.write_bytes(b"mock-uv")
        self.python.write_bytes(b"mock-python")
        for fault in ("foreign-owner","group-writable"):
            def read(node):
                current=real(node)
                st_mode=current.st_mode & ~0o022
                st_uid=0
                if node == victim:
                    if fault == "foreign-owner":
                        st_uid=999
                    else:
                        st_mode |= 0o020
                return SimpleNamespace(
                    st_uid=st_uid,st_mode=st_mode,
                    st_nlink=current.st_nlink,st_size=current.st_size)
            with self.subTest(fault=fault), \
                 mock.patch.object(Path,"lstat",new=read):
                with self.assertRaisesRegex(
                        stage.RuntimeBlocked,"not root-owned"):
                    stage.verify_root_immutable_inputs(
                        manifest=self.manifest,lock=self.lock,
                        wheelhouse=self.wheels,uv=self.uv,
                        python=self.python,cape_source=self.checkout)

    def test_runtime_rejects_jammy_before_opening_ledger_or_wheelhouse(self):
        with mock.patch.object(stage.apt,"verify_host",return_value="22.04"), \
             mock.patch.object(stage.tx,"host_guard"), \
             mock.patch.object(stage.tx,"load") as load:
            with self.assertRaisesRegex(stage.RuntimeBlocked,
                                        "Ubuntu 26.04"):
                stage.plan(*self.params)
        load.assert_not_called()

    def test_runtime_rejects_noble_before_opening_ledger_or_wheelhouse(self):
        with mock.patch.object(stage.apt,"verify_host",return_value="24.04"), \
             mock.patch.object(stage.tx,"host_guard"), \
             mock.patch.object(stage.tx,"load") as load:
            with self.assertRaisesRegex(stage.RuntimeBlocked,
                                        "Ubuntu 26.04"):
                stage.plan(*self.params)
        load.assert_not_called()

    def test_plan_binds_source_and_wheel_manifest_to_transaction(self):
        with ExitStack() as stack:
            self.stubs(stack)
            result=stage.plan(*self.params)
        self.assertEqual(result["source_commit"],self.revision)
        self.assertEqual(result["runtime_uid"],777)
        self.assertTrue(result["no_network_or_remote_package_builds"])
        self.assertFalse(result["production_CAPE_services_started"])
        self.assertFalse(result["Windows_running_snapshot_tested"])

    def test_plan_refuses_previous_runtime_attempt(self):
        self.document["entries"].append({
            "kind":stage.RUNTIME_KIND,"status":"prepared"})
        with ExitStack() as stack:
            self.stubs(stack)
            with self.assertRaisesRegex(stage.RuntimeBlocked,
                                        "already been attempted"):
                stage.plan(*self.params)

    def test_plan_refuses_source_and_manifest_mismatch(self):
        with ExitStack() as stack:
            self.stubs(stack)
            stack.enter_context(mock.patch.object(
                stage.wheels,"plan",return_value={
                    "source_sha":"f"*40,"packages_verified":2}))
            with self.assertRaisesRegex(stage.RuntimeBlocked,
                                        "not for this CAPE source"):
                stage.plan(*self.params)

    def test_apply_journals_prepared_before_starting_unprivileged_code(self):
        events=[]
        def persist(*args,**kwargs):
            entries=args[1]["entries"]
            events.append(("receipt",entries[-1]["status"]))
        def run(*args,**kw):
            events.append(("child",len(events)))
            program=args[1]
            if program[1:3]==["pip","list"]:
                return json.dumps([
                    {"name":"gevent","version":"24.2.1"},
                    {"name":"greenlet","version":"3.0.3"}])
            if program[-1]=="--help":
                return "usage: cuckoo.py [-h]\\n--help\\n"
            return ""
        with ExitStack() as st:
            self.stubs(st)
            st.enter_context(mock.patch.object(stage,"plan",
                return_value=self.proposed))
            st.enter_context(mock.patch.object(stage.os,"geteuid",
                return_value=0))
            st.enter_context(mock.patch.object(
                stage.sys.stdin,"isatty",return_value=True))
            st.enter_context(mock.patch("builtins.input",
                return_value=stage.APPROVAL+"-"+self.transaction))
            st.enter_context(mock.patch.object(
                stage.tx,"exclusive_transaction_lock",
                return_value=nullcontext()))
            st.enter_context(mock.patch.object(
                stage.tx,"atomic_receipt",side_effect=persist))
            st.enter_context(mock.patch.object(
                stage,"rootless_command",side_effect=run))
            st.enter_context(mock.patch.object(stage.os,"chown"))
            st.enter_context(mock.patch.object(stage.tx,"fsync_dir"))
            result=stage.apply(*self.params)
        self.assertEqual(result["packages"],2)
        self.assertFalse(result["CAPE_full_services_started"])
        self.assertEqual(self.document["entries"][-1]["status"],"sealed")
        self.assertEqual(events[0],("receipt","prepared"))
        self.assertEqual(events[-1],("receipt","sealed"))
        self.assertEqual(sum(i[0]=="child" for i in events),4)

    def test_failed_child_preserves_partial_owned_runtime_without_retry(self):
        calls=[]
        with ExitStack() as st:
            self.stubs(st)
            st.enter_context(mock.patch.object(
                stage,"plan",return_value=self.proposed))
            st.enter_context(mock.patch.object(
                stage.os,"geteuid",return_value=0))
            st.enter_context(mock.patch.object(
                stage.sys.stdin,"isatty",return_value=True))
            st.enter_context(mock.patch("builtins.input",
                return_value=stage.APPROVAL+"-"+self.transaction))
            st.enter_context(mock.patch.object(
                stage.tx,"exclusive_transaction_lock",
                return_value=nullcontext()))
            st.enter_context(mock.patch.object(
                stage.tx,"atomic_receipt",
                side_effect=lambda *args: calls.append(
                    args[1]["entries"][-1]["status"])))
            run=st.enter_context(mock.patch.object(
                stage,"rootless_command",
                side_effect=stage.RuntimeBlocked("simulated uv fail")))
            st.enter_context(mock.patch.object(stage.os,"chown"))
            st.enter_context(mock.patch.object(stage.tx,"fsync_dir"))
            with self.assertRaisesRegex(stage.RuntimeBlocked,
                                        "simulated uv fail"):
                stage.apply(*self.params)
        self.assertEqual(calls,["prepared"])
        self.assertEqual(run.call_count,1)
        self.assertEqual(self.document["entries"][-1]["status"],"prepared")
        self.assertTrue((self.target_root/self.transaction).is_dir())

    def test_unapproved_operator_cannot_start_installer(self):
        with ExitStack() as st:
            self.stubs(st)
            st.enter_context(mock.patch.object(
                stage,"plan",return_value=self.proposed))
            st.enter_context(mock.patch.object(stage.os,"geteuid",
                return_value=0))
            st.enter_context(mock.patch.object(stage.sys.stdin,"isatty",
                return_value=True))
            st.enter_context(mock.patch("builtins.input",return_value="NO"))
            run=st.enter_context(mock.patch.object(
                stage,"rootless_command"))
            with self.assertRaisesRegex(stage.RuntimeBlocked,"declined"):
                stage.apply(*self.params)
            run.assert_not_called()


if __name__=="__main__":
    unittest.main()
