import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from audit_kvm_build_step7 import analyze_log, audit_username

class BuildAuditTests(unittest.TestCase):
    def test_build_pass_line_not_certification(self):
        r = analyze_log('Setting up qemu (9.2.2) ...\n')
        self.assertEqual(r['overall_status'], 'UNVERIFIED_REQUIRES_POST_INSTALL_CHECKS')
        self.assertFalse(r['safe_to_rerun_upstream_all'])
    def test_known_errors_never_pass(self):
        text = ('libkmod: ERROR blah blacklist-kvm.conf line 1: ignoring bad line\n'
                'ERROR: Cannot uninstall cryptography 41.0.7, RECORD file not found\n'
                "dpkg: warning: trying to overwrite '/usr/share/qemu/firmware/example'\n")
        r = analyze_log(text)
        self.assertEqual(r['overall_status'], 'UNVERIFIED_WITH_ERRORS')
        self.assertEqual(len(r['important_findings']), 3)
    def test_log_not_quoted_and_secret_absent(self):
        secret='a-secret-string-specific-to-fixture'
        r=analyze_log('Password='+secret+'\nERROR: Cannot uninstall cryptography 41.0.7, RECORD file not found')
        self.assertNotIn(secret, str(r))
    def test_mid_build_detected(self):
        self.assertTrue(analyze_log('[1683/3252] Compiling stuff\n')['captured_log_starts_mid_build'])
    def test_full_start_not_flagged(self):
        self.assertFalse(analyze_log('Starting build...\n')['captured_log_starts_mid_build'])
    def test_missing_account_refused(self):
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            audit_username('unknown_user_cape_7777', Path('/tmp/missing'))
    def test_root_refused(self):
        with self.assertRaisesRegex(ValueError, 'non-root'):
            audit_username('root', Path('/tmp/missing'))
    def test_invalid_username_refused(self):
        with self.assertRaisesRegex(ValueError,'Invalid'):
            audit_username('foo;reboot', Path('/tmp/missing'))
    def test_current_nonroot_user_and_source(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'kvm-qemu.sh'
            p.write_text('#!/bin/bash\nusername=$SUDO_USER\n#username=$2\n')
            account = SimpleNamespace(pw_uid=1000,pw_dir=d)
            with patch('audit_kvm_build_step7.pwd.getpwnam',return_value=account):
                v=audit_username('operator',p)
            self.assertEqual(v['requested_nonroot_user'],'operator')
            self.assertFalse(v['second_argument_used_as_user_in_inspected_source'])
    def test_active_argument_parsing_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'kvm-qemu.sh';p.write_text('username=$SUDO_USER\nusername=$2\n')
            account=SimpleNamespace(pw_uid=1000,pw_dir=d)
            with patch('audit_kvm_build_step7.pwd.getpwnam',return_value=account):
                with self.assertRaisesRegex(ValueError, 'argument'):
                    audit_username('operator',p)

if __name__=='__main__': unittest.main(verbosity=2)
