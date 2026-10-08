import unittest
from audit_step7e_kvm_policy import analyze, split_report

SAMPLE = '''========== STEP 7E KVM POLICY VERIFICATION ==========
========== EFFECTIVE MODPROBE CONFIGURATION CHECK ==========
Modprobe configuration parsing: PASSED
========== EFFECTIVE KVM MODPROBE RULES ==========
blacklist kvm
options kvm ignore_msrs=Y
options kvm report_ignored_msrs=N
========== CURRENTLY LOADED KVM MODULES ==========
kvm_intel             540672  0
kvm                  1507328  1 kvm_intel
========== KVM MODULE AVAILABILITY ==========
/lib/modules/6.8.0-generic/kernel/arch/x86/kvm/kvm.ko.zst
/lib/modules/6.8.0-generic/kernel/arch/x86/kvm/kvm-intel.ko.zst
========== KVM MODULE DRY RUN ==========
Testing: kvm
Dry-run exit status: SUCCESS
Testing: kvm_intel
Dry-run exit status: SUCCESS
========== KVM BLACKLIST-AWARE DRY RUN ==========
Blacklist-aware dry-run exit status: SUCCESS
========== LIBVIRT SERVICE ==========
active
========== CURRENT TCP SYN COOKIE SETTING ==========
net.ipv4.tcp_syncookies = 1
========== VERIFICATION COMPLETE ==========
No reboot performed.
'''

class Step7EReportTests(unittest.TestCase):
    def test_happy_diagnostic_report_not_boot_ready(self):
        r=analyze(SAMPLE)
        self.assertEqual(r['status'], 'BASIC_KVM_CHECKS_PASS_POLICY_REVIEW')
        self.assertFalse(r['boot_autoload_verified'])
        self.assertFalse(r['guest_isolation_verified'])
    def test_known_blacklist_is_review(self):
        r=analyze(SAMPLE)
        self.assertEqual(r['policy_rules'], [{'action':'blacklist','module':'kvm'}])
        self.assertTrue(r['blacklist_policy_review_required'])
    def test_msr_options(self):
        r=analyze(SAMPLE)
        self.assertEqual(r['recognized_kvm_options'], ['ignore_msrs=Y','report_ignored_msrs=N'])
    def test_modules_and_files(self):
        r=analyze(SAMPLE)
        self.assertEqual(r['loaded_kvm_modules'], ['kvm','kvm_intel'])
        self.assertEqual(r['kvm_module_files_seen'], ['kvm','kvm-intel'])
    def test_dry_runs_do_not_certify_boot(self):
        r=analyze(SAMPLE)
        self.assertTrue(r['blacklist_aware_dry_run_successful'])
        self.assertFalse(r['boot_autoload_verified'])
    def test_absent_parser_status(self):
        r=analyze(SAMPLE.replace('Modprobe configuration parsing: PASSED','Modprobe configuration parsing: FAILED'))
        self.assertIn('MODPROBE_PARSE_NOT_CONFIRMED',r['blockers'])
    def test_no_modules(self):
        r=analyze(SAMPLE.replace('kvm_intel             540672  0','not found').replace('kvm                  1507328  1 kvm_intel','not found'))
        self.assertIn('EXPECTED_KVM_MODULES_NOT_CONFIRMED_LOADED',r['blockers'])
    def test_not_active(self):
        r=analyze(SAMPLE.replace('========== LIBVIRT SERVICE ==========\nactive','========== LIBVIRT SERVICE ==========\ninactive'))
        self.assertIn('LIBVIRT_ACTIVE_NOT_CONFIRMED',r['blockers'])
    def test_syn_cookie_regression(self):
        r=analyze(SAMPLE.replace('net.ipv4.tcp_syncookies = 1','net.ipv4.tcp_syncookies = 0'))
        self.assertIn('TCP_SYN_COOKIES_NOT_CONFIRMED_ENABLED',r['blockers'])
    def test_incomplete_report(self):
        r=analyze(SAMPLE.replace('========== VERIFICATION COMPLETE ==========', '========== OTHER =========='))
        self.assertIn('REPORT_INCOMPLETE',r['blockers'])
    def test_missing_cpu_driver_dry_run(self):
        r=analyze(SAMPLE.replace('Testing: kvm_intel\nDry-run exit status: SUCCESS', 'Testing: kvm_intel\nDry-run exit status: FAILED'))
        self.assertIn('CPU_DRIVER_DRYRUN_NOT_CONFIRMED_SUCCESS',r['blockers'])
    def test_account_private_text_redacted(self):
        r=analyze(SAMPLE+'SENSITIVE_TEST_SECRET_24680\n')
        self.assertNotIn('SENSITIVE_TEST_SECRET_24680',str(r))
    def test_invalid_header(self):
        with self.assertRaises(ValueError): split_report('bad\n')
    def test_amd_driver_supported(self):
        text=SAMPLE.replace('kvm_intel             540672  0','kvm_amd             540672  0').replace('Testing: kvm_intel','Testing: kvm_amd').replace('kvm-intel.ko.zst','kvm-amd.ko.zst')
        self.assertEqual(analyze(text)['status'], 'BASIC_KVM_CHECKS_PASS_POLICY_REVIEW')

if __name__ == '__main__':
    unittest.main(verbosity=2)
