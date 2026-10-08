import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from audit_kvm_modprobe import inspect_lines, inspect_file, effective_config_check, main

PRE = '-e blacklist kvm_intel\nblacklist kvm\n'
POST = '# Malformed directive preserved for review: -e blacklist kvm_intel\nblacklist kvm\n'

class KvmModprobeTests(unittest.TestCase):
    def test_pre_correction_malformed(self):
        r = inspect_lines(PRE)
        self.assertEqual(r['findings'][0]['code'], 'UNRECOGNIZED_MODPROBE_DIRECTIVE')
        self.assertEqual(r['kvm_loading_policy_rules'][0]['module'], 'kvm')
    def test_post_correction_clean_but_policy_review(self):
        r = inspect_lines(POST)
        self.assertEqual(r['findings'], [])
        self.assertTrue(r['kvm_autoload_policy_requires_review'])
        self.assertEqual(r['kvm_loading_policy_rules'][0]['directive'], 'blacklist')
    def test_no_policy_is_only_one_file(self):
        r = inspect_lines('# nothing\noptions kvm ignore_msrs=Y\n')
        self.assertFalse(r['kvm_autoload_policy_requires_review'])
        self.assertTrue(r['no_guest_safety_or_reboot_assurance'])
    def test_intentionally_blacklisted_intel(self):
        r = inspect_lines('blacklist kvm_intel\n')
        self.assertEqual(r['kvm_loading_policy_rules'][0]['module'], 'kvm_intel')
    def test_install_override_detected(self):
        r = inspect_lines('install kvm /bin/false\n')
        self.assertEqual(r['kvm_loading_policy_rules'][0]['directive'], 'install')
    def test_non_kvm_rule_ignored_as_kvm(self):
        r = inspect_lines('blacklist floppy\n')
        self.assertFalse(r['kvm_autoload_policy_requires_review'])
    def test_malformed_blacklist_args(self):
        r = inspect_lines('blacklist kvm garbage\n')
        self.assertEqual(r['findings'][0]['code'], 'UNEXPECTED_BLACKLIST_ARGUMENTS')
    def test_invalid_unknown_and_empty(self):
        r = inspect_lines('garbage\nblacklist\n')
        self.assertEqual(len(r['findings']), 2)
    def test_missing_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                inspect_file(Path(temp) / 'missing')
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'real').write_text(POST)
            (root / 'symlink').symlink_to(root / 'real')
            with self.assertRaises(ValueError):
                inspect_file(root / 'symlink')
    def test_clean_modprobe(self):
        with patch('audit_kvm_modprobe.subprocess.run', return_value=SimpleNamespace(returncode=0, stderr='')):
            self.assertTrue(effective_config_check()['clean'])
    def test_warning_modprobe_fails(self):
        with patch('audit_kvm_modprobe.subprocess.run', return_value=SimpleNamespace(returncode=0, stderr='bad config')):
            self.assertFalse(effective_config_check()['clean'])
    def test_post_correction_cli_still_requires_review(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'modprobe.conf'
            p.write_text(POST)
            self.assertEqual(main(['--config', str(p)]), 2)
    def test_status_without_rule_not_guarantee_of_isolation(self):
        r=inspect_lines('options kvm report_ignored_msrs=N\n')
        self.assertTrue(r['no_guest_safety_or_reboot_assurance'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
