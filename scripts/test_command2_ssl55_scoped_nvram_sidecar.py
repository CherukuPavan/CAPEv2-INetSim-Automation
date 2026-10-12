"""Scoped SSL55 clone-only NVRAM sidecar admission, offline mocks only.

No libvirt, QEMU, backup or SSL55 host is modified in these tests.
"""
import json
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
import command2_ssl55_scoped_nvram_sidecar as m

UUID=m.UID

class ScopedFirmware(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.vars=self.root/"win11_1.command2_VARS.fd"
        self.disk=self.root/"win11_1.command2.qcow2"
        self.side=Path(str(self.vars)+".qcow2")
        self.disk.write_bytes(b"independent disk")
        self.vars.write_bytes(b"x"*540672)
        self.orig=(m.DISK,m.VARS,m.SIDE)
        m.DISK=self.disk
        m.VARS=self.vars
        m.SIDE=self.side
        self.addCleanup(lambda:setattr(m,"DISK",self.orig[0]))
        self.addCleanup(lambda:setattr(m,"VARS",self.orig[1]))
        self.addCleanup(lambda:setattr(m,"SIDE",self.orig[2]))
    def mocked_inspect(self,state="running"):
        def virsh(*args):
            if args[0]=="domuuid":
                return {"win11_1":m.UID,"win11":m.reference.MASTER[1],
                        "win11_trial_1":m.reference.TRIAL[1]}[args[1]]
            if args[0]=="domstate":
                return state if args[1]=="win11_1" else "shut off"
            if args[0]=="snapshot-list":return ""
            if args[0]=="dumpxml":return "<domain/>"
            raise AssertionError(args)
        def cmd(*args,**kwargs):
            if args[:2]==("qemu-img","info"):
                return json.dumps({"format":"raw" if args[-1]==str(self.vars)
                                   else "qcow2","virtual-size":64*1024**3})
            raise AssertionError(args)
        from contextlib import ExitStack
        stack=ExitStack()
        self.addCleanup(stack.close)
        for obj,name,kwargs in [
            (m.socket,"gethostname",{"return_value":"CSE-SSL-55"}),
            (m.os,"geteuid",{"return_value":0}),
            (m,"virsh",{"side_effect":virsh}),
            (m.reference,"checkdomain",{"return_value":{
                "xml_nvram_format":"raw","disk_backing_empty":True}}),
            (m,"run",{"side_effect":cmd}),
            (m,"verify_existing_bundle",{"return_value":{
                "manifest_sha256":"a"*64,"byte_verified_member_count":3}}),
            (m.os,"statvfs",{"return_value":type("FS",(),{
                "f_bavail":int(90*1024**3/4096),"f_frsize":4096})()}),
        ]:
            stack.enter_context(patch.object(obj,name,**kwargs))
        return stack
    def test_readonly_plan_identifies_required_stop_when_running(self):
        self.mocked_inspect("running")
        data=m.inspect()
        self.assertTrue(data["requires_clean_shutdown_before_prepare"])
        self.assertFalse(data["running_snapshot_created"])
        self.assertFalse(self.side.exists())
        self.assertFalse(data["swtpm_atomic_snapshot_restore_verified"])
    def test_preparation_refuses_running_guest_before_writing(self):
        self.mocked_inspect("running")
        with patch.object(m.sys.stdin,"isatty",return_value=True):
            with self.assertRaisesRegex(m.SSL55PrepareBlocked,"NO LIVE CONVERSION"):
                m.prepare()
        self.assertFalse(self.side.exists())
    def test_reference_master_or_trial_state_mismatch_blocks(self):
        self.mocked_inspect("shut off")
        original=m.virsh
        def abnormal(*args):
            if args==("domstate","win11"):return "running"
            return original(*args)
        with patch.object(m,"virsh",side_effect=abnormal):
            with self.assertRaisesRegex(m.SSL55PrepareBlocked,"master or trial"):
                m.inspect()
    def test_wrong_host_refuses_no_mutations(self):
        with patch.object(m.socket,"gethostname",return_value="not-ssl55"),\
             patch.object(m.os,"geteuid",return_value=0):
            with self.assertRaisesRegex(m.SSL55PrepareBlocked,"canonical"):
                m.inspect()
    def test_existing_sidecar_is_not_overwritten(self):
        self.mocked_inspect("shut off")
        self.side.write_text("unknown existing artifact")
        with self.assertRaisesRegex(m.SSL55PrepareBlocked,"sidecar already"):
            m.inspect()
        self.assertEqual(self.side.read_text(),"unknown existing artifact")
    def test_source_backup_hash_must_match_recorded_digest(self):
        self.mocked_inspect("shut off")
        self.vars.write_bytes(b"n"*540672)
        real=m.sha256(self.vars)
        with patch.object(m,"verify_existing_bundle",side_effect=m.SSL55PrepareBlocked(
              "Saved cold recovery hash/length changed")):
            with self.assertRaisesRegex(m.SSL55PrepareBlocked,"cold recovery"):
                m.inspect()
        self.assertEqual(m.sha256(self.vars),real)
    def test_scoped_script_has_no_snapshot_revert_or_master_mutator(self):
        source=Path(m.__file__).read_text(encoding="utf-8")
        for bad in ('virsh("destroy"', 'virsh("shutdown"',
                    'virsh("snapshot-create"', 'virsh("snapshot-revert"',
                    'virsh("define"', 'virsh("start"',
                    'run("qemu-img","rebase"',"shell=True"):
            self.assertNotIn(bad,source)
    def test_prepare_only_writes_sidecar_after_shut_off_and_approval(self):
        self.mocked_inspect("shut off")
        expected={
            "result":"SSL55_WIN11_1_QCOW2_OVMF_SIDECAR_PLAN_ONLY",
            "vm_state":"shut off","raw_sha256":m.sha256(self.vars)}
        def info():
            return dict(expected)
        original_run=m.run
        def simulate(*argv,timeout=120):
            if argv[:2]==("qemu-img","convert"):
                Path(argv[-1]).write_bytes(b"simulated QCOW2 bytes")
                return ""
            if argv[:2] in (("qemu-img","check"),("qemu-img","compare")):
                return ""
            if argv[:2]==("qemu-img","info"):
                return json.dumps({"format":"qcow2",
                                   "virtual-size":self.vars.stat().st_size})
            return original_run(*argv,timeout=timeout)
        lock=self.root/"lock"
        fdstat=type("Lock",(),{"st_mode":stat.S_IFREG|0o600,
                              "st_uid":0,"st_nlink":1})()
        with patch.object(m,"LOCK",lock),\
             patch.object(m,"inspect",side_effect=info),\
             patch.object(m,"run",side_effect=simulate),\
             patch.object(m.os,"chown"),\
             patch.object(m.os,"fstat",return_value=fdstat),\
             patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch("builtins.input",
                   return_value="PREPARE-SSL55-CLONE-NVRAM-QCOW2"):
            result=m.prepare()
        self.assertTrue(self.side.exists())
        self.assertTrue(result["original_raw_kept"])
        self.assertFalse(result["running_snapshot_created"])
        self.assertFalse(result["guest_vm_xml_changed"])

if __name__=="__main__":
    unittest.main()
