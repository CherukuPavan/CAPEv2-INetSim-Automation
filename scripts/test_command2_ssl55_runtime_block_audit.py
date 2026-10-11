"""Synthetic block-graph parsing and strict nonmutation regression tests."""
import unittest
from unittest.mock import patch
import command2_ssl55_runtime_block_audit as a

def sample(chain=True):
    backing = ('<backingStore><source file="' + a.SOURCES[0] +
               '"/><backingStore/></backingStore>') if chain else '<backingStore/>'
    return ('<domain><name>' + a.VM + '</name><uuid>' + a.UID +
            '</uuid><os><loader type="pflash" format="raw">OVMF</loader>' +
            '<nvram format="raw">' + a.VARS + '</nvram></os><devices>' +
            '<disk device="disk"><driver type="qcow2"/><source file="' +
            a.DISK + '"/>' + backing + '</disk>' +
            '<tpm><backend type="emulator" version="2.0"/></tpm>' +
            '<interface type="network"><source network="cape-analysis-isolated"/>' +
            '<mac address="02:0a:30:6a:3f:50"/></interface>' +
            '</devices></domain>')

class GraphAuditTests(unittest.TestCase):
    def test_xml_original_chain(self):
        self.assertEqual(a.domain_summary(sample())["backing_paths_in_xml"], [a.SOURCES[0]])
    def test_empty_xml_chain(self):
        self.assertEqual(a.domain_summary(sample(False))["backing_paths_in_xml"], [])
    def test_exact_guard_rejects_wrong_disk(self):
        with self.assertRaisesRegex(a.Blocked,"disk"):
            a.domain_summary(sample().replace(a.DISK, "/tmp/wrong.qcow2"))
    def test_exact_guard_rejects_wrong_nic(self):
        with self.assertRaisesRegex(a.Blocked,"NIC"):
            a.domain_summary(sample().replace("02:0a:30:6a:3f:50",
                                              "02:ff:ff:ff:ff:ff"))
    def test_nested_qmp_paths(self):
        value = [{"inserted": {"image": {"filename": a.DISK,
                                          "backing-image": {"filename": a.SOURCES[0]}}}}]
        self.assertEqual(a.referenced_paths(value), [a.DISK, a.SOURCES[0]])
    def test_qmp_mutating_command_rejected(self):
        with patch.object(a, "virsh", side_effect=AssertionError("Virsh must not run")):
            with self.assertRaisesRegex(a.Blocked,"non-query"):
                a.qmp_query("block-commit")
    def test_source_has_no_vm_writes(self):
        from pathlib import Path
        source = Path(a.__file__).read_text(encoding="utf-8")
        for cmd in ('"snapshot-create-as"', '"snapshot-revert"', '"net-start"',
                    '"destroy"', '"shutdown"', '"rebase"', '"convert"'):
            self.assertNotIn(cmd, source)

if __name__ == "__main__":
    unittest.main()
