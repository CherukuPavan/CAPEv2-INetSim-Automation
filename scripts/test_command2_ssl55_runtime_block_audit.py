"""Synthetic exact-domain and open-inode audit tests; no host VM actions."""
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_ssl55_runtime_block_audit as a

def domain(backing=True):
    chain = ('<backingStore><source file="' + a.SOURCES[0] +
             '"/><backingStore/></backingStore>') if backing else '<backingStore/>'
    return ('<domain><name>' + a.VM + '</name><uuid>' + a.UID +
            '</uuid><os><loader type="pflash" format="raw">OVMF</loader>' +
            '<nvram format="raw">' + a.VARS + '</nvram></os><devices>' +
            '<disk device="disk"><driver type="qcow2"/><source file="' +
            a.DISK + '"/>' + chain + '</disk>' +
            '<tpm><backend type="emulator" version="2.0"/></tpm>' +
            '<interface type="network"><source network="cape-analysis-isolated"/>' +
            '<mac address="02:0a:30:6a:3f:50"/></interface>' +
            '</devices></domain>')

class GraphAuditTests(unittest.TestCase):
    def test_chain_vs_independent_xml(self):
        self.assertEqual(a.domain_summary(domain())["backing_paths_in_xml"], [a.SOURCES[0]])
        self.assertEqual(a.domain_summary(domain(False))["backing_paths_in_xml"], [])
    def test_wrong_disk_or_nic_or_uuid_refused(self):
        for raw in (domain().replace(a.DISK, "/tmp/other"),
                    domain().replace("02:0a:30:6a:3f:50", "02:ff:ff:ff:ff:ff"),
                    domain().replace(a.UID, "wrong-uuid")):
            with self.subTest(raw=raw), self.assertRaises(a.Blocked):
                a.domain_summary(raw)
    def test_qemu_process_unique_exact_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, uuid in (("123", a.UID), ("124", "other-uuid")):
                p = root / name
                p.mkdir()
                (p / "comm").write_text("qemu-system-x86\n")
                (p / "cmdline").write_bytes(
                    b"qemu-system-x86_64\0-name\0guest=win11_1,debug-threads=on\0-uuid\0" +
                    uuid.encode() + b"\0")
            self.assertEqual(a.qemu_pid(root), 123)
    def test_qemu_process_ambiguous_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("123", "124"):
                p = root / name
                p.mkdir()
                (p / "comm").write_text("qemu-system-x86\n")
                (p / "cmdline").write_bytes(
                    b"qemu-system-x86_64\0guest=win11_1\0" + a.UID.encode() + b"\0")
            with self.assertRaisesRegex(a.Blocked,"uniquely"):
                a.qemu_pid(root)
    def test_inode_tracking_detects_open_file_even_via_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            disk = root / "disk.qcow2"
            disk.write_bytes(b"synthetic only")
            proc_fd = root / "fakeproc" / "123" / "fd"
            proc_fd.mkdir(parents=True)
            (proc_fd / "7").symlink_to(disk)
            with patch.object(a, "WATCHED", (str(disk), str(root / "missing"))):
                result = a.open_disk_fds(123, root / "fakeproc")
            self.assertEqual(result["matching_open_file_descriptors"][str(disk)][0]["fd"], "7")
            self.assertEqual(result["matching_open_file_descriptors"][str(root / "missing")], [])
    def test_source_never_sends_monitor_or_mutating_commands(self):
        source = Path(a.__file__).read_text()
        for phrase in ('virsh("qemu-monitor-command"', 'virsh("snapshot-create-as"',
                       'virsh("snapshot-revert"', 'read("qemu-img", "check"',
                       'read("qemu-img", "convert"', 'read("qemu-img", "rebase"'):
            self.assertNotIn(phrase, source)

if __name__ == "__main__":
    unittest.main()
