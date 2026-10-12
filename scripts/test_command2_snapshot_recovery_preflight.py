"""Synthetic cold-bundle integrity gate; NEVER a live guest operation."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import command2_snapshot_recovery_preflight as b

VM="win11_1"
UID="12345678-1234-4234-8234-123456789abc"

class Recovery(unittest.TestCase):
    def fixture(self,folder):
        root=Path(folder)
        root.chmod(0o700)
        payloads={
            "disk.qcow2":b"DISPOSABLE_OS_DISK",
            "UEFI_VARS.fd":b"DISPOSABLE_OVMF_STATE",
            "swtpm/tpm2-00.permall":b"DISPOSABLE_TPM_STATE",
        }
        (root/"swtpm").mkdir(mode=0o700)
        metadata={}
        for name,data in payloads.items():
            path=root/name;path.write_bytes(data);path.chmod(0o600)
            metadata[name]={"bytes":len(data),
                           "sha256":hashlib.sha256(data).hexdigest()}
        manifest={
            "kind":"COMMAND2_FULL_COLD_BUNDLE_V1",
            "vm":VM,"uuid":UID,"capture_complete":True,
            "source_vm_shutoff":True,
            "disk":"/tmp/test/win11_1.command2.qcow2",
            "nvram":"/tmp/test/win11_1.command2_VARS.fd",
            "swtpm_dir":"/var/lib/libvirt/swtpm/"+UID+"/tpm2",
            "entries":metadata,
        }
        p=root/b.EXPECTED_MANIFEST;p.write_text(json.dumps(manifest))
        p.chmod(0o600)
        return payloads,manifest

    def inspect_fake_root(self,folder):
        # File owner must be ROOT in production; CI runs unprivileged.
        real=Path.stat
        def rootstat(obj,*a,**kw):
            st=real(obj,*a,**kw)
            fields=list(st)
            fields[4]=0
            return os.stat_result(fields)
        with patch.object(Path,"stat",rootstat):
            return b.inspect(VM,UID,folder)

    def test_all_disk_ovmf_tpm_hashes_verified(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            out=self.inspect_fake_root(td)
        self.assertEqual(out["result"],"COMMAND2_FULL_COLD_RECOVERY_BYTES_VERIFIED")
        self.assertEqual(len(out["members"]),3)
        self.assertTrue(out["all_member_hashes_recomputed"])
        self.assertFalse(out["cold_restore_physically_proven_by_this_check"])

    def test_tampered_tpm_fails(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            (Path(td)/"swtpm/tpm2-00.permall").write_bytes(b"MUTATED")
            with self.assertRaisesRegex(b.RecoveryBlocked,"hash/length"):
                self.inspect_fake_root(td)

    def test_missing_uefi_fails(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            (Path(td)/"UEFI_VARS.fd").unlink()
            with self.assertRaisesRegex(b.RecoveryBlocked,"missing"):
                self.inspect_fake_root(td)

    def test_symlink_substitution_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            path=Path(td)/"UEFI_VARS.fd"
            path.unlink();path.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(b.RecoveryBlocked,"symlinked"):
                self.inspect_fake_root(td)

    def test_modified_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            p=Path(td)/b.EXPECTED_MANIFEST
            m=json.loads(p.read_text());m["capture_complete"]=False
            p.write_text(json.dumps(m))
            with self.assertRaisesRegex(b.RecoveryBlocked,"complete stopped"):
                self.inspect_fake_root(td)

    def test_extra_unknown_bundle_member_refused(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td)
            p=Path(td)/b.EXPECTED_MANIFEST
            m=json.loads(p.read_text())
            m["entries"]["../outside"]={"bytes":1,"sha256":"f"*64}
            p.write_text(json.dumps(m))
            with self.assertRaisesRegex(b.RecoveryBlocked,"Unexpected recovery"):
                self.inspect_fake_root(td)

    def test_no_vm_host_or_network_commands(self):
        raw=Path(b.__file__).read_text()
        for cmd in ('virsh','qemu-img','snapshot-create','snapshot-revert',
                    'shutdown','net-start','rm -rf','subprocess.run'):
            self.assertNotIn(cmd,raw)

if __name__=="__main__":unittest.main()
