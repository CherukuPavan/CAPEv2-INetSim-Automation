"""Reject other libvirt domains using clone storage (no host calls)."""
import unittest
from unittest.mock import patch
import command2_cold_checkpoint as c

class Tests(unittest.TestCase):
    def mock_virsh(self, disk_path=None, nvram_path=None):
        def call(*args):
            if args==('list','--all','--name'):return 'win11_1\nother_guest'
            if args==('domstate','other_guest'):return 'shut off'
            if args==('dumpxml','--inactive','other_guest'):
                d=f'<disk><source file="{disk_path}"/></disk>' if disk_path else ''
                n=f'<os><nvram>{nvram_path}</nvram></os>' if nvram_path else ''
                return f'<domain>{n}<devices>{d}</devices></domain>'
            raise AssertionError('unexpected virsh query: '+str(args))
        return call
    def test_other_vm_shares_disk(self):
        with patch.object(c,'virsh',side_effect=self.mock_virsh(disk_path=str(c.DISK))):
            with self.assertRaisesRegex(c.Blocked,'shares protected clone'):
                c.assert_no_shared_artifacts()
    def test_other_vm_shares_nvram(self):
        with patch.object(c,'virsh',side_effect=self.mock_virsh(nvram_path=str(c.NVRAM))):
            with self.assertRaisesRegex(c.Blocked,'shares clone UEFI'):
                c.assert_no_shared_artifacts()
    def test_other_vm_independent(self):
        with patch.object(c,'virsh',side_effect=self.mock_virsh(disk_path='/var/lib/libvirt/images/unrelated.qcow2')):
            c.assert_no_shared_artifacts()
if __name__=='__main__':unittest.main()
