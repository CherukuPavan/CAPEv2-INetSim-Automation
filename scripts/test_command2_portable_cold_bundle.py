"""Offline synthetic full cold QCOW2+UEFI+swtpm capture/restore tests.

Uses ONLY disposable sub-1KiB tempfile fixtures; no hypervisor or
master VM is accessed. All subprocess/libvirt interactions are mocked.
"""
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
import json

import command2_portable_cold_bundle as b

VM="win11_1"
UID="48452448-2647-471f-8c3e-69630737e75b"
HOST="approved-test-host"


def fixture(path):
    p=Path(path)
    disk=p/"win11_1.command2.qcow2"
    vars=p/"win11_1.command2_VARS.fd"
    tpm=p/"swtpm"/UID/"tpm2"
    tpm.mkdir(parents=True)
    disk.write_bytes(b"benign qcow2 fake")
    vars.write_bytes(b"uefi variables fake")
    (tpm/"tpm2-00.permall").write_bytes(b"private tpm state fake")
    (tpm/".lock").write_bytes(b"")
    return disk,vars,tpm


def synthetic_guest(disk,vars,tpm):
    files=[(x,x.stat()) for x in sorted(tpm.iterdir())]
    observed=[(disk,disk.stat()),(vars,vars.stat())]+files
    return {"vm":VM,"uuid":UID,"disk":disk,"nvram":vars,
            "swtpm_dir":tpm,"tpm_files":files,
            "stamps":{str(p):(st.st_dev,st.st_ino,st.st_size,
                                 st.st_mtime_ns,st.st_ctime_ns)
                      for p,st in observed},
            "image_virtual_bytes":64*b.GIB}


class ColdBundleTests(unittest.TestCase):
    def test_wrong_host_protected_no_vm_calls(self):
        with patch.object(b.socket,"gethostname",return_value="CSE-SSL-55"),\
             patch.object(b,"virsh",side_effect=AssertionError("No host reads")):
            with self.assertRaisesRegex(b.ColdBlocked,"SSL55_REFERENCE_ONLY"):
                b.host_guard("cse-ssl-55")

    def test_renamed_ssl55_marker_also_blocks(self):
        with patch.object(b.socket,"gethostname",return_value=HOST),\
             patch.object(b,"SENTINEL",Path(__file__).parent):
            with self.assertRaisesRegex(b.ColdBlocked,"SSL55_REFERENCE_ONLY"):
                b.host_guard(HOST)

    def test_full_synthetic_capture_sha_verify_and_guarded_restore(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            disk,vars,tpm=fixture(root)
            checkpoint=root/"checkpoint"
            def state(*_):return synthetic_guest(disk,vars,tpm)
            real_fstat=os.fstat
            def root_only_fstat(fd):
                # Preserve all actual file metadata and change ONLY
                # ownership in this synthetic unprivileged CI fixture.
                items=list(real_fstat(fd))
                items[stat.ST_UID]=0
                return os.stat_result(items)
            with patch.object(b,"host_guard"),\
                 patch.object(b.os,"fstat",side_effect=root_only_fstat),\
                 patch.object(b,"safe_folder",side_effect=lambda p:Path(p)),\
                 patch.object(b,"free_bytes",return_value=200*b.GIB),\
                 patch.object(b,"state",side_effect=state),\
                 patch.object(b.os,"geteuid",return_value=0),\
                 patch.object(b.os,"chown"):
                capture=b.capture(VM,UID,HOST,checkpoint)
                self.assertEqual(capture["result"],"COMMAND2_FULL_COLD_BUNDLE_CAPTURED")
                self.assertEqual(capture["files_captured"],4)
                manifest,manifest_sha=b.verify_bundle(VM,UID,HOST,checkpoint)
                self.assertEqual(len(manifest_sha),64)
                self.assertTrue(manifest["capture_complete"])
                disk.write_bytes(b"changed after benign sample")
                vars.write_bytes(b"changed vars")
                (tpm/"tpm2-00.permall").write_bytes(b"changed tpm")
                with patch.object(b,"LOCK",root/"bundle.lock"),\
                     patch.object(b.sys.stdin,"isatty",return_value=True),\
                     patch("builtins.input",
                           return_value="RESTORE-COLD-DISPOSABLE-WIN11_1"),\
                     patch.object(b,"virsh",return_value="shut off"):
                    result=b.restore(VM,UID,HOST,checkpoint,manifest_sha)
            self.assertEqual(result["result"],
                             "COMMAND2_COLD_GUEST_FILES_RESTORED_NOT_BOOT_VERIFIED")
            self.assertEqual(disk.read_bytes(),b"benign qcow2 fake")
            self.assertEqual(vars.read_bytes(),b"uefi variables fake")
            self.assertEqual((tpm/"tpm2-00.permall").read_bytes(),
                             b"private tpm state fake")
            self.assertTrue((checkpoint/b.INTENT_NAME).exists())
            self.assertTrue((checkpoint/b.DONE_NAME).exists())
            self.assertTrue(list(root.glob("win11_1.command2.qcow2.pre-restore-*")))
            self.assertFalse(result["full_boot_tpm_uefi_cape_validation"])

    def test_preexisting_checkpoint_never_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            disk,vars,tpm=fixture(root)
            checkpoint=root/"checkpoint";checkpoint.mkdir()
            with patch.object(b,"host_guard"),\
                 patch.object(b.os,"geteuid",return_value=0),\
                 patch.object(b,"state",return_value=synthetic_guest(disk,vars,tpm)),\
                 patch.object(b,"safe_folder",side_effect=lambda p:Path(p)):
                with self.assertRaisesRegex(b.ColdBlocked,"already exists"):
                    b.capture(VM,UID,HOST,checkpoint)

    def test_source_tpm_regular_symlink_required(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            disk,vars,tpm=fixture(root)
            (tpm/"tpm2-00.permall").unlink()
            (tpm/"tpm2-00.permall").symlink_to(disk)
            # Explicit symlink is disallowed even if it points to a
            # regular disk file, without any libvirt command invocation.
            with self.assertRaisesRegex(b.ColdBlocked,"linked"):
                b.safe_regular(tpm/"tpm2-00.permall")

    def test_restore_requires_exact_manifest_sha_and_tty(self):
        with patch.object(b,"host_guard"),\
             patch.object(b.os,"geteuid",return_value=0),\
             patch.object(b.sys.stdin,"isatty",return_value=False):
            with self.assertRaisesRegex(b.ColdBlocked,"Interactive"):
                b.restore(VM,UID,HOST,"/fake", "0"*64)

    def test_no_live_nic_or_snapshot_mutations_in_code(self):
        source=Path(b.__file__).read_text(encoding="utf-8")
        for forbidden in ('"net-start"', '"attach-interface"',
                          '"snapshot-create-as"', '"snapshot-revert"',
                          '"start"', '"destroy"', '"shutdown"'):
            self.assertNotIn(forbidden,source)


if __name__=="__main__":
    unittest.main()
