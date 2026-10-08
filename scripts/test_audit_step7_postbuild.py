import sys
from pathlib import Path
import unittest
from audit_step7_postbuild import assess, sections

REPORT = '''========== STEP 7 POST-BUILD VERIFICATION ==========
========== CURRENT USER ==========
operator
uid=1000(operator) gid=1000(operator) groups=1000(operator),27(sudo)
kvm:x:993:root,operator
libvirt:x:1008:root,operator
========== QEMU EXECUTABLE ==========
/usr/bin/qemu-system-x86_64
QEMU emulator version 9.2.2
========== LIBVIRT EXECUTABLE ==========
/usr/bin/virsh
11.1.0
========== LIBVIRT SYSTEM CONNECTION ==========
Compiled against library: libvirt 11.1.0
Using library: libvirt 11.1.0
Running hypervisor: QEMU 9.2.2
========== LIBVIRT NETWORKS ==========
 Name State Autostart Persistent
 default active no no
========== LIBVIRT VIRTUAL MACHINES ==========
 Id Name State
========== LIBVIRT SERVICES ==========
active
inactive
inactive
========== RELEVANT PACKAGES ==========
dpkg-query: no packages found matching libvirt-clients
========== PACKAGE HOLDS ==========
qemu
========== KVM DEVICE ==========
INFO: /dev/kvm exists
KVM acceleration can be used
========== KVM MODULE CONFIGURATION ==========
-e blacklist kvm_intel
blacklist kvm
========== TCP SYN COOKIE CONFIGURATION ==========
net.ipv4.tcp_syncookies = 0
========== POWER MANAGEMENT TARGETS ==========
masked
masked
masked
========== ORIGINAL INSTALLATION LOG ==========
ls: cannot access '/tmp/foo.log': No such file or directory
========== REBOOT REQUIREMENT ==========
System reports reboot required
========== VERIFICATION FINISHED ==========
'''

class PostbuildTests(unittest.TestCase):
    def result(self, report=REPORT):
        return assess(report)
    def codes(self, report=REPORT):
        return {f['code'] for f in self.result(report)['findings']}
    def test_sample_reproduces_critical_issues(self):
        c=self.codes()
        self.assertIn('DEFAULT_NETWORK_TRANSIENT',c)
        self.assertIn('MALFORMED_MODPROBE_FILE',c)
        self.assertIn('TCP_SYN_COOKIES_NOT_ENABLED_OR_UNKNOWN',c)
    def test_qemu_libvirt_kvm_positive(self):
        c=self.result()['checks']
        self.assertTrue(c['qemu_binary_and_version'])
        self.assertTrue(c['system_libvirt_connects_to_qemu'])
        self.assertTrue(c['kvm_acceleration_available'])
    def test_group_database_not_active_session(self):
        c=self.result()['checks']
        self.assertTrue(c['kvm_account_membership_listed'])
        self.assertFalse(c['kvm_current_session_membership'])
    def test_active_session_groups_are_accepted(self):
        s=REPORT.replace('groups=1000(operator),27(sudo)', 'groups=1000(operator),27(sudo),993(kvm),1008(libvirt)')
        self.assertNotIn('KVM_MEMBERSHIP_NOT_ACTIVE_IN_SESSION',self.codes(s))
        self.assertNotIn('LIBVIRT_MEMBERSHIP_NOT_ACTIVE_IN_SESSION',self.codes(s))
    def test_monolithic_libvirt_inactive_modular_not_error(self):
        self.assertNotIn('LIBVIRTD_NOT_CONFIRMED_ACTIVE',self.codes())
    def test_network_persistent_yes_autostart_yes(self):
        s=REPORT.replace('default active no no','default active yes yes')
        self.assertNotIn('DEFAULT_NETWORK_TRANSIENT',self.codes(s))
        self.assertNotIn('DEFAULT_NETWORK_AUTOSTART_DISABLED',self.codes(s))
    def test_qemu_package_held_is_review(self):
        self.assertIn('QEMU_PACKAGE_HELD',self.codes())
    def test_sleep_targets_masked_detected(self):
        self.assertEqual(self.result()['checks']['masked_power_management_targets_count'],3)
    def test_missing_log_detected(self):
        self.assertIn('ORIGINAL_INSTALL_LOG_NOT_FOUND_AT_EXPECTED_PATH',self.codes())
    def test_reboot_pending_review(self):
        self.assertIn('REBOOT_PENDING_REVIEW_REQUIRED',self.codes())
    def test_password_lines_not_echoed(self):
        s=REPORT + 'PASSWD="fake-private-fixture"\n'
        self.assertNotIn('fake-private-fixture',str(self.result(s)))
    def test_report_not_containment_proof(self):
        self.assertFalse(self.result()['authorizes_malware_execution'])
        self.assertFalse(self.result()['guest_network_isolation_verified'])
    def test_missing_header_rejected(self):
        with self.assertRaises(ValueError):
            sections('incomplete')
    def test_no_distro_libvirt_package_not_broken_runtime(self):
        self.assertTrue(self.result()['checks']['distro_libvirt_packages_missing'])
        self.assertTrue(self.result()['checks']['system_libvirt_connects_to_qemu'])

if __name__ == '__main__': unittest.main(verbosity=2)
