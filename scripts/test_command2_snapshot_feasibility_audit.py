#!/usr/bin/env python3
"""Offline regression tests only: no libvirt or TPM state access."""
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import command2_snapshot_feasibility_audit as a

def xml(nic=""):
    return (
        '<domain type="kvm"><name>win11_1</name><uuid>' + a.UUID +
        '</uuid><os><nvram>' + str(a.NVRAM) + '</nvram></os><devices>'
        '<disk type="file" device="disk"><source file="' + str(a.DISK) +
        '"/></disk><tpm><backend type="emulator" version="2.0"/></tpm>'
        + nic + '</devices></domain>'
    )

class Tests(unittest.TestCase):
    def test_xml_exact_zero_nic(self):
        self.assertTrue(a.check_xml(xml(), True)["zero_nics"])
        self.assertEqual(a.check_xml(xml(), False)["tpm"], "emulator-2.0")

    def test_nic_fail_closed(self):
        with self.assertRaisesRegex(a.AuditBlocked, "interface"):
            a.check_xml(xml('<interface type="network"/>'), True)

    def test_wrong_firmware_blocked(self):
        with self.assertRaisesRegex(a.AuditBlocked, "firmware"):
            a.check_xml(xml().replace(a.NVRAM.name, "wrong_VARS.fd"), True)

    def test_wrong_tpm_type_blocked(self):
        with self.assertRaisesRegex(a.AuditBlocked, "TPM"):
            a.check_xml(xml().replace('version="2.0"', 'version="1.2"'), True)

    def test_tpm_inventory_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / a.UUID / "tpm2"
            directory.mkdir(parents=True)
            (directory / "tpm2-00.permall").write_bytes(b"unit-test-only")
            with patch.object(a, "TPMROOT", root), patch.object(a, "TPMDIR", directory):
                result = a.inspect_tpm()
            self.assertFalse(result["contents_read"])
            self.assertEqual(result["files_metadata_only"][0]["file"], "tpm2-00.permall")
            self.assertNotIn("unit-test-only", str(result))

    def test_missing_permall_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / a.UUID / "tpm2"
            directory.mkdir(parents=True)
            with patch.object(a, "TPMROOT", root), patch.object(a, "TPMDIR", directory):
                with self.assertRaisesRegex(a.AuditBlocked, "permanent"):
                    a.inspect_tpm()

    def test_capacity_conservative(self):
        enough = SimpleNamespace(f_bavail=97, f_frsize=a.GiB)
        low = SimpleNamespace(f_bavail=60, f_frsize=a.GiB)
        with patch.object(a.os, "statvfs", return_value=enough):
            good = a.storage()
        with patch.object(a.os, "statvfs", return_value=low):
            insufficient = a.storage()
        self.assertTrue(good["conservative_capacity_pass_at_audit"])
        self.assertFalse(insufficient["conservative_capacity_pass_at_audit"])
        self.assertFalse(good["snapshot_or_copy_authorized"])

    def test_source_contains_no_dangerous_management_commands(self):
        source = Path(a.__file__).read_text()
        for command in ("snapshot-revert", "snapshot-create", "qemu-img check",
                        "virsh start", "virsh shutdown", "net-start",
                        "nft flush", "systemctl restart", "os.remove(",
                        "shutil.copy", "write_bytes("):
            with self.subTest(command=command):
                self.assertNotIn(command, source)

if __name__ == "__main__":
    unittest.main()
