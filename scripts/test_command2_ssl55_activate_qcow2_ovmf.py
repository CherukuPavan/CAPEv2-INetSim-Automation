"""Offline tests: SSL55 source pinned, stopped only, backup-before-define."""
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import command2_ssl55_activate_qcow2_ovmf as m

VM=m.VM
UID=m.UID
BASE_XML=(
    '<domain type="kvm"><name>'+VM+'</name><uuid>'+UID+'</uuid>'
    '<os><loader readonly="yes" type="pflash">'
    '/usr/share/OVMF/OVMF_CODE.fd</loader><nvram format="raw">'+str(m.RAW)+
    '</nvram></os><devices><disk type="file" device="disk">'
    '<driver type="qcow2"/><source file="'+str(m.ref.DISK)+'"/>'
    '</disk><interface type="network">'
    '<source network="cape-analysis-isolated"/>'
    '<mac address="02:0a:30:6a:3f:50"/></interface>'
    '<tpm><backend type="emulator" version="2.0"/></tpm>'
    '</devices></domain>')

class SSL55Activate(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.dir=Path(self.t.name)
        self.bkup=self.dir/m.BACKUP_FILE
        self.original_sha=m.XML_SHA
        m.XML_SHA=m.sha(BASE_XML.encode())
        self.addCleanup(lambda:setattr(m,"XML_SHA",self.original_sha))
        self.current=[BASE_XML]
        self.power=["shut off"]
        self.events=[]
    def stub_virsh(self,*args):
        self.events.append(args)
        if args[0]=="domuuid":
            return {"win11_1":UID,"win11":m.ref.MASTER[1],
                    "win11_trial_1":m.ref.TRIAL[1]}[args[1]]
        if args[0]=="domstate":
            return self.power[0] if args[1]==VM else "shut off"
        if args[0]=="snapshot-list":return ""
        if args[0]=="dumpxml":
            return self.current[0]
        if args[0]=="define":
            self.current[0]=Path(args[1]).read_text(encoding="utf-8")
            return "Domain defined"
        raise AssertionError(args)
    def mocked(self):
        from contextlib import ExitStack
        stack=ExitStack()
        self.addCleanup(stack.close)
        for obj,attr,kwargs in [
            (m,"guarded_existing_files",{"return_value":{
                "cold_manifest_sha256":m.MANIFEST_SHA,
                "sidecar_sha256":m.SIDE_SHA,
                "raw_sha256":m.RAW_SHA}}),
            (m,"virsh",{"side_effect":self.stub_virsh}),
            (m,"location",{"return_value":self.bkup}),
        ]:
            stack.enter_context(patch.object(obj,attr,**kwargs))
        return stack

    def test_transform_changes_only_firmware_format_and_path(self):
        out=m.transform_saved(BASE_XML)
        self.assertIn(str(m.SIDE),out.decode())
        self.assertIn('nvram format="qcow2"',out.decode())
        self.assertNotIn('<nvram format="raw"',out.decode())
        self.assertIn(str(m.ref.DISK),out.decode())
        self.assertIn('02:0a:30:6a:3f:50',out.decode())

    def test_wrong_nic_tpm_master_disk_or_firmware_refused(self):
        changes=[
            ("02:0a:30:6a:3f:50","02:aa:bb:cc:dd:ee"),
            ('network="cape-analysis-isolated"','network="default"'),
            ('type="emulator" version="2.0"','type="passthrough" version="2.0"'),
            (str(m.ref.DISK),'/another/master.qcow2'),
            (str(m.RAW),'/not-the-original.fd'),
            ('readonly="yes"','readonly="no"'),
        ]
        for old,new in changes:
            with self.subTest(old=old):
                with self.assertRaises(m.TransitionBlocked):
                    m.transform_saved(BASE_XML.replace(old,new))
        with self.assertRaisesRegex(m.TransitionBlocked,"passthrough"):
            m.transform_saved(BASE_XML.replace("</devices>",
                                "<hostdev/></devices>"))

    def test_plan_is_non_mutating_and_rejects_stale_domain_hash(self):
        self.mocked()
        data=m.plan(self.dir)
        self.assertTrue(data["risk_acknowledgement_required_for_apply"])
        self.assertFalse(data["snapshot_created"])
        self.assertFalse(self.bkup.exists())
        self.assertEqual(self.current[0],BASE_XML)
        self.current[0]=self.current[0].replace("win11_1","unexpected")
        with self.assertRaisesRegex(m.TransitionBlocked,"Stored guest XML"):
            m.plan(self.dir)

    def test_prepare_rejects_preexisting_private_backup(self):
        self.mocked()
        self.bkup.write_text("other session")
        with self.assertRaisesRegex(m.TransitionBlocked,"Prior XML backup"):
            m.plan(self.dir)

    def test_apply_preserves_original_xml_then_defines_stopped_guest(self):
        self.mocked()
        original_tmp=tempfile.NamedTemporaryFile
        def safe_temp(*args,**kwargs):
            kwargs["dir"]=self.dir
            return original_tmp(*args,**kwargs)
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch("builtins.input",
                   return_value="ACTIVATE-SSL55-WIN11_1-QCOW2-OVMF-ONLY"),\
             patch.object(m.tempfile,"NamedTemporaryFile",side_effect=safe_temp),\
             patch.object(m,"LOCK",self.dir/"lock"),\
             patch.object(m.os,"fstat",return_value=types.SimpleNamespace(
                   st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)),\
             patch.object(m.Path,"stat",autospec=True) as pstat:
            # Original XML backup is owned by root in a production run.
            original_stat=Path.stat
            pstat.side_effect=lambda path,*a,**kw:(
                types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,
                                      st_nlink=1)
                if str(path)==str(self.bkup) else original_stat(path,*a,**kw))
            res=m.apply(self.dir)
        self.assertEqual(res["result"],"SSL55_WIN11_1_QCOW2_OVMF_SAVED_XML_VERIFIED_OFF")
        self.assertEqual(self.bkup.read_text(),BASE_XML)
        self.assertIn(str(m.SIDE),self.current[0])
        self.assertEqual(self.power[0],"shut off")
        self.assertNotIn(("start",VM),self.events)
        self.assertNotIn(("snapshot-create",VM),self.events)

    def test_failed_define_leaves_original_backup_for_recovery(self):
        self.mocked()
        called=[]
        def fail_define(*args):
            if args[0]=="define":
                called.append(args)
                raise m.TransitionBlocked("libvirt define refused")
            return self.stub_virsh(*args)
        original_tmp=tempfile.NamedTemporaryFile
        def safe_temp(*args,**kwargs):
            kwargs["dir"]=self.dir
            return original_tmp(*args,**kwargs)
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch("builtins.input",
                   return_value="ACTIVATE-SSL55-WIN11_1-QCOW2-OVMF-ONLY"),\
             patch.object(m.tempfile,"NamedTemporaryFile",side_effect=safe_temp),\
             patch.object(m,"LOCK",self.dir/"lock"),\
             patch.object(m,"virsh",side_effect=fail_define),\
             patch.object(m.os,"fstat",return_value=types.SimpleNamespace(
                   st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)):
            with self.assertRaisesRegex(m.TransitionBlocked,"define refused"):
                m.apply(self.dir)
        self.assertEqual(self.bkup.read_text(),BASE_XML)
        self.assertEqual(self.current[0],BASE_XML)
        self.assertEqual(len(called),1)

    def test_file_scope_is_only_existing_ssl55_clone(self):
        source=Path(m.__file__).read_text(encoding="utf-8")
        for forbidden in (
            'virsh("start"','virsh("destroy"','virsh("snapshot-create"',
            'virsh("snapshot-revert"','virsh("shutdown"','virsh("undefine"',
            'shell=True'):
            self.assertNotIn(forbidden,source)

if __name__=="__main__":
    unittest.main()
