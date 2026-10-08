import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from audit_sysctl_alias import active_definitions, audit_paths, read_active_sysctl


class AliasTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.primary = root / 'sysctl.conf'
        self.alias = root / 'sysctl.d' / '99-sysctl.conf'
        self.alias.parent.mkdir()
        self.primary.write_text('# sample\nnet.ipv4.tcp_syncookies = 0\n')
        self.alias.symlink_to('../sysctl.conf')

    def test_ss55_layout_same_inode(self):
        r = audit_paths(self.primary, self.alias)
        self.assertTrue(r['same_underlying_file'])
        self.assertTrue(r['alias_is_symlink'])
        self.assertTrue(r['alias_resolves_to_primary'])

    def test_duplicate_view_is_one_underlying_file(self):
        r = audit_paths(self.primary, self.alias)
        self.assertEqual(r['primary_definitions'], r['alias_definitions'])
        self.assertEqual(len(r['primary_definitions']), 1)

    def test_disabled_value_flags(self):
        self.assertIn('PERSISTENT_SYN_COOKIES_NOT_ENABLED', audit_paths(self.primary, self.alias)['findings'])

    def test_enabled_value_not_flagged(self):
        self.primary.write_text('net.ipv4.tcp_syncookies = 1\n')
        self.assertNotIn('PERSISTENT_SYN_COOKIES_NOT_ENABLED', audit_paths(self.primary, self.alias)['findings'])

    def test_independent_files_block(self):
        self.alias.unlink(); self.alias.write_text('net.ipv4.tcp_syncookies = 1\n')
        self.assertIn('DIFFERENT_UNDERLYING_FILES', audit_paths(self.primary, self.alias)['findings'])

    def test_missing_alias_block(self):
        self.alias.unlink()
        self.assertIn('CONFIG_PATH_MISSING_OR_NOT_REGULAR', audit_paths(self.primary, self.alias)['findings'])

    def test_missing_primary_block(self):
        self.primary.unlink()
        self.assertIn('CONFIG_PATH_MISSING_OR_NOT_REGULAR', audit_paths(self.primary, self.alias)['findings'])

    def test_duplicate_settings_block(self):
        self.primary.write_text('net.ipv4.tcp_syncookies = 0\nnet.ipv4.tcp_syncookies=1\n')
        self.assertIn('MISSING_OR_DUPLICATE_ACTIVE_SETTING', audit_paths(self.primary, self.alias)['findings'])

    def test_comment_ignored(self):
        self.assertEqual(active_definitions('#net.ipv4.tcp_syncookies=0\nnet.ipv4.tcp_syncookies=1\n'), [{'line_number':2,'value':'1'}])

    def test_whitespace_and_comment(self):
        defs = active_definitions('  net.ipv4.tcp_syncookies = 1  # comment\n')
        self.assertEqual(defs[0]['value'], '1')

    def test_source_does_not_change(self):
        before = self.primary.read_bytes()
        audit_paths(self.primary, self.alias)
        self.assertEqual(before, self.primary.read_bytes())

    def test_active_sysctl_readonly(self):
        with patch('audit_sysctl_alias.subprocess.run', return_value=SimpleNamespace(stdout='1\n')):
            self.assertEqual(read_active_sysctl(), {'checked':True,'value':'1'})

    def test_bad_runtime_response_redacted(self):
        with patch('audit_sysctl_alias.subprocess.run', return_value=SimpleNamespace(stdout='secret\n')):
            self.assertEqual(read_active_sysctl()['value'], '<UNRECOGNIZED>')

    def test_broken_link_block(self):
        self.alias.unlink();self.alias.symlink_to('missing')
        self.assertIn('CONFIG_PATH_MISSING_OR_NOT_REGULAR', audit_paths(self.primary, self.alias)['findings'])

    def test_not_root_owned_fails_open_not(self):
        # Temporary file is usually owned by unprivileged test uid; if root,
        # simply assert the field accurately reflects its stat result.
        v=audit_paths(self.primary, self.alias)
        self.assertEqual(v['primary_root_owned'], self.primary.stat().st_uid == 0 and self.primary.stat().st_gid == 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
