"""Count-driven running snapshot batch is fail-closed and source-data bound.

Synthetic admissions ONLY: no snapshots or guests touched in CI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import command2_portable_snapshot_capture_batch as m

HOST="approved-other-host"
def row(i):
    return {"libvirt_name":f"win11_{i}",
            "libvirt_uuid_candidate":f"12345678-1234-4234-8234-{i:012d}",
            "mac_candidate":f"02:aa:bb:cc:dd:{i:02x}",
            "disk_target":f"/private/win11_{i}.command2.qcow2",
            "guest_static_ipv4_target":f"192.168.240.{100+i}"}

class SnapshotBatch(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.journal=self.root/"command2-identity-reservation.json"
        self.journal.write_text("canonical-journal")
        self.evidence=self.root/"evidence"
        self.evidence.mkdir()
        self.rows=[row(1),row(2)]
        for r in self.rows:
            (self.evidence/r["libvirt_name"]).mkdir()
        self.index={"format":m.FORMAT,"host":HOST,"guest_count":2,
                    "entries":{r["libvirt_name"]:
                               {"manifest_sha256":"a"*64} for r in self.rows}}
        self.indexfile=self.evidence/"snapshot-recovery-index.json"
        self.write_index()
    def write_index(self):
        self.indexfile.write_text(json.dumps(self.index))
    def mocked(self):
        def mock_load(journal,host,vm):
            r=next(r for r in self.rows if r["libvirt_name"]==vm)
            return r,"192.168.240.0/24",Path("/private/config.json")
        def fake_plan(vm,host,uid,mac,ip,receipt,subnet):
            return {"required_acceptance_receipt_provided":True,
                    "receipt_sha256":"b"*64}
        def fake_stack(vm):
            return {"uefi_variable_store_real_format":"qcow2",
                    "swtpm2_present":True,"guest_ram_bytes":4*1024**3}
        fs=type("ST",(),{"st_uid":0,"st_nlink":1,
             "st_mode":stat.S_IFREG|0o600,"st_size":234})()
        statfs=type("FS",(),{"f_frsize":4096,"f_bavail":int(120*1024**3/4096)})()
        from contextlib import ExitStack
        stack=ExitStack()
        self.addCleanup(stack.close)
        for obj,name,kwargs in [
            (m.workflow,"canonical_host",{"return_value":HOST}),
            (m.os,"geteuid",{"return_value":0}),
            (m.batch,"private_evidence_folder",{}),
            (m.batch,"reservation_rows",{"return_value":self.rows}),
            (m.workflow,"load_guest",{"side_effect":mock_load}),
            (m,"private_index",{"return_value":self.index}),
            (m.snapshot,"plan",{"side_effect":fake_plan}),
            (m.recovery,"inspect",{"return_value":{"manifest_sha256":"a"*64}}),
            (m.native,"inspect",{"side_effect":fake_stack}),
            (m.os,"stat",{"return_value":type("D",(),{"st_dev":5})()}),
            (m.os,"statvfs",{"return_value":statfs}),
        ]:
            stack.enter_context(patch.object(obj,name,**kwargs))
        return stack

    def test_preflight_two_exact_guests_and_reserve(self):
        self.mocked()
        data=m.checked_inputs(HOST,self.journal,self.evidence)
        self.assertEqual(data["guest_count"],2)
        self.assertEqual([r["vm"] for r in data["guests"]],
                         ["win11_1","win11_2"])
        self.assertFalse(data["running_snapshots_created"])
        self.assertFalse(data["actual_tpm_state_rollback_verified"])

    def test_missing_or_extra_or_fake_guest_is_refused(self):
        self.mocked()
        self.index["entries"]["win11_3"]={"manifest_sha256":"a"*64}
        with self.assertRaisesRegex(m.CaptureBatchBlocked,"guest set"):
            m.checked_inputs(HOST,self.journal,self.evidence)
        self.index["entries"].pop("win11_3")
        self.index["entries"]["win11_2"]={"manifest_sha256":"bad"}
        with self.assertRaisesRegex(m.CaptureBatchBlocked,"reviewed"):
            m.checked_inputs(HOST,self.journal,self.evidence)

    def test_no_write_plan_never_runs_capture(self):
        self.mocked()
        with patch.object(m.subprocess,"run") as proc:
            self.assertEqual(m.run(HOST,self.journal,self.evidence,"plan"),0)
            proc.assert_not_called()

    def test_capture_stops_on_second_failure_without_retry(self):
        self.mocked()
        calls=[]
        def child(args,check=False):
            calls.append(args)
            return type("Result",(),{"returncode":0 if len(calls)==1 else 3})()
        with patch.object(m.sys.stdin,"isatty",return_value=True),\
             patch.object(m.subprocess,"run",side_effect=child):
            self.assertEqual(m.run(HOST,self.journal,self.evidence,"capture"),2)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0][calls[0].index("--vm")+1],"win11_1")
        self.assertEqual(calls[1][calls[1].index("--vm")+1],"win11_2")
        self.assertIn("--reviewed-manifest-sha",calls[0])

    def test_ssl55_is_never_allowed(self):
        with patch.object(m.workflow.socket,"gethostname",
                          return_value="CSE-SSL-55"):
            with self.assertRaisesRegex(m.workflow.WorkflowBlocked,"Protected"):
                m.checked_inputs("cse-ssl-55",self.journal,self.evidence)

    def test_invalid_evidence_index_is_rejected_with_no_capture(self):
        with patch.object(m.batch,"private_evidence_folder"),\
             patch.object(m.Path,"stat",
                 return_value=type("ST",(),{"st_mode":stat.S_IFREG|0o644,
                               "st_uid":0,"st_nlink":1,"st_size":200})()):
            with self.assertRaisesRegex(m.CaptureBatchBlocked,"root/private"):
                m.private_index(self.evidence)

if __name__=="__main__":
    unittest.main()
