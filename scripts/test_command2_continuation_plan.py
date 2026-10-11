"""Pure/read-only count reconciliation tests; never call real libvirt."""
from pathlib import Path
import unittest
from unittest.mock import patch
import command2_continuation_plan as p

class Tests(unittest.TestCase):
    def test_count_five_preserves_one_and_plans_four(self):
        report=p.classify(5,{'win11_1'},set(),400*p.GiB)
        self.assertEqual([v['name'] for v in report['missing']],
                         ['win11_2','win11_3','win11_4','win11_5'])
        self.assertEqual([v['hostname'] for v in report['missing']],
                         ['WIN11-2','WIN11-3','WIN11-4','WIN11-5'])
        self.assertEqual(report['missing'][-1]['future_ipv4'],'192.168.240.105')
        self.assertTrue(report['capture_and_network_not_authorized'])
    def test_five_insufficient_space(self):
        report=p.classify(5,{'win11_1'},set(),96*p.GiB)
        self.assertFalse(report['storage_nominally_sufficient'])
        self.assertTrue(report['staging_not_authorized'])
        self.assertEqual(report['needed_conservative_gib'],286)
    def test_collision_blocks_other_vm(self):
        report=p.classify(3,{'win11_1','win11_2'},set(),300*p.GiB)
        self.assertEqual(report['blockers'],['Existing unverified domain: win11_2'])
    def test_collision_blocks_existing_disk(self):
        target=p.cold.DISK.parent/'win11_2.command2.qcow2'
        report=p.classify(2,{'win11_1'},{target},300*p.GiB)
        self.assertTrue(report['blockers'])
    def test_invalid_counts(self):
        for value in (0,17,-1,1.5):
            with self.assertRaises(p.cold.Blocked):
                p.classify(value,{'win11_1'},set(),300*p.GiB)
    def test_missing_verified_first_vm(self):
        with self.assertRaisesRegex(p.cold.Blocked,'missing'):
            p.classify(2,set(),set(),300*p.GiB)
    def test_requires_authoritative_guards(self):
        with patch.object(p.cold,'virsh',return_value='win11_1\nwin11_trial_1'),\
             patch.object(p.cold,'guards',side_effect=p.cold.Blocked('unsafe host')):
            with self.assertRaisesRegex(p.cold.Blocked,'unsafe host'):
                p.current_inventory()
if __name__=='__main__':unittest.main()
