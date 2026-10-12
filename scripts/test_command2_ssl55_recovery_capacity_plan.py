"""Offline tests of the SSL55 read-only clone recovery capacity checker."""
import unittest
import command2_ssl55_recovery_capacity_plan as c

def sample(backing=False, network="cape-analysis-isolated"):
    chain = '<backingStore><source file="/tmp/parent"/></backingStore>' if backing else '<backingStore/>'
    return (f'<domain><name>{c.NAME}</name><uuid>{c.UUID}</uuid>'
            f'<os><nvram>{c.NVRAM}</nvram></os><devices>'
            f'<disk device="disk"><source file="{c.DISK}"/>{chain}</disk>'
            '<tpm><backend type="emulator" version="2.0"/></tpm>'
            f'<interface><source network="{network}"/></interface>'
            '</devices></domain>')

class RecoveryCapacity(unittest.TestCase):
    def test_expected_clone(self):
        c.xml_check(sample())
    def test_wrong_disk_chain_rejected(self):
        with self.assertRaises(c.Blocked):
            c.xml_check(sample(backing=True))
    def test_wrong_network_rejected(self):
        with self.assertRaises(c.Blocked):
            c.xml_check(sample(network="default"))
    def test_wrong_uuid_rejected(self):
        with self.assertRaises(c.Blocked):
            c.xml_check(sample().replace(c.UUID, "unknown"))
if __name__ == "__main__":
    unittest.main()
