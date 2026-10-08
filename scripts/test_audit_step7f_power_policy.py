import unittest
from audit_step7f_power_policy import analyze

TARGETS = ('sleep.target', 'suspend.target', 'hibernate.target', 'hybrid-sleep.target')


def fixture():
    lines=['========== STEP 7F POWER MANAGEMENT REVIEW ==========']
    for target in TARGETS:
        lines += [f'---------- {target} ----------', 'Enabled state:', 'masked',
                  'Unit properties:', 'LoadState=masked', 'ActiveState=inactive',
                  'FragmentPath=/etc/systemd/system/'+target, 'SourcePath=',
                  'UnitFileState=masked', 'Persistent configuration:',
                  'lrwxrwxrwx 1 root root 9 Oct 9 02:30 /etc/systemd/system/'+target+' -> /dev/null',
                  '/dev/null', 'Runtime configuration:',
                  'No direct runtime override at /run/systemd/system/'+target]
    lines += ['========== UPSTREAM INSTALLER MASK COMMAND ==========',
              '76:systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target',
              '========== REBOOT REQUIREMENT ==========', 'Reboot-required marker: PRESENT',
              '========== STEP 7F REVIEW COMPLETE ==========']
    return '\n'.join(lines)+'\n'


class Step7FTests(unittest.TestCase):
    def test_all_four_masked(self):
        r=analyze(fixture())
        self.assertEqual(r['status'], 'PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED')
        self.assertEqual([v['status'] for v in r['target_states'].values()],
                         ['PERSISTENTLY_MASKED']*4)
    def test_no_auto_unmask(self):
        self.assertFalse(analyze(fixture())['authorized_to_unmask'])
    def test_reboot_not_proven(self):
        self.assertFalse(analyze(fixture())['reboot_verified'])
    def test_guest_isolation_not_proven(self):
        self.assertFalse(analyze(fixture())['guest_network_isolation_verified'])
    def test_detects_missing_target(self):
        txt=fixture()
        start=txt.index('---------- hybrid-sleep.target ----------')
        end=txt.index('========== UPSTREAM INSTALLER MASK COMMAND ==========', start)
        r=analyze(txt[:start]+txt[end:])
        self.assertEqual(r['target_states']['hybrid-sleep.target']['status'], 'NOT_REPORTED')
    def test_wrong_fragment(self):
        r=analyze(fixture().replace('FragmentPath=/etc/systemd/system/sleep.target',
                                    'FragmentPath=/run/systemd/system/sleep.target'))
        self.assertIn('MASK_STATE_INCONSISTENT_sleep_target',r['finding_codes'])
    def test_missing_symlink(self):
        r=analyze(fixture().replace('/etc/systemd/system/suspend.target -> /dev/null',
                                    '/etc/systemd/system/suspend.target -> /tmp/foo'))
        self.assertIn('MASK_STATE_INCONSISTENT_suspend_target',r['finding_codes'])
    def test_unmasked_detected(self):
        r=analyze(fixture().replace('---------- sleep.target ----------\nEnabled state:\nmasked',
                                    '---------- sleep.target ----------\nEnabled state:\nenabled'))
        self.assertIn('MASK_STATE_INCONSISTENT_sleep_target',r['finding_codes'])
    def test_no_installer_line(self):
        r=analyze(fixture().replace('76:systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target',''))
        self.assertIn('INSTALLER_MASK_LINE_NOT_CONFIRMED',r['finding_codes'])
    def test_reboot_marker_present(self):
        self.assertTrue(analyze(fixture())['reboot_required_marker_reported'])
    def test_reboot_marker_absent(self):
        self.assertFalse(analyze(fixture().replace('Reboot-required marker: PRESENT',
                                                  'Reboot-required marker: ABSENT'))['reboot_required_marker_reported'])
    def test_no_identity_or_secret_echo(self):
        self.assertNotIn('PRIVATE_TEST_IP_2468',str(analyze(fixture()+'PRIVATE_TEST_IP_2468\n')))
    def test_missing_header_refused(self):
        with self.assertRaises(ValueError): analyze('bad')
    def test_missing_completion_detected(self):
        r=analyze(fixture().replace('========== STEP 7F REVIEW COMPLETE ==========', ''))
        self.assertIn('REPORT_INCOMPLETE',r['finding_codes'])


if __name__=='__main__':
    unittest.main(verbosity=2)
