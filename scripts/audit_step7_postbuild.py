#!/usr/bin/env python3
"""Read-only analysis of the Step 7 consolidated post-build terminal report.

The program does not call sudo, execute the installer, modify networking, or
assume that successful QEMU/libvirt commands imply working malware isolation.
It emits only known state fields and fixed diagnostic codes (no raw host data).
"""
import argparse
import json
from pathlib import Path
import re
import sys

HEADINGS = re.compile(r'^==========\s+(.+?)\s+==========$', re.MULTILINE)


def sections(text):
    matches = list(HEADINGS.finditer(text))
    if not matches or matches[0].group(1) != 'STEP 7 POST-BUILD VERIFICATION':
        raise ValueError('Step 7 report header missing')
    return {m.group(1): text[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(text)].strip()
            for i, m in enumerate(matches)}


def assess(text):
    parts = sections(text)
    checks = {}
    findings = []

    def finding(code, severity):
        findings.append({'code': code, 'severity': severity})

    def section(name):
        if name not in parts:
            finding('REPORT_SECTION_MISSING_' + name.replace(' ', '_'), 'blocker')
        return parts.get(name, '')

    qemu = section('QEMU EXECUTABLE')
    virsh = section('LIBVIRT EXECUTABLE')
    connection = section('LIBVIRT SYSTEM CONNECTION')
    kvm = section('KVM DEVICE')
    user = section('CURRENT USER')
    nets = section('LIBVIRT NETWORKS')
    services = section('LIBVIRT SERVICES')
    modprobe = section('KVM MODULE CONFIGURATION')
    sysctl = section('TCP SYN COOKIE CONFIGURATION')
    targets = section('POWER MANAGEMENT TARGETS')
    section('LIBVIRT VIRTUAL MACHINES')
    packages = section('RELEVANT PACKAGES')
    holds = section('PACKAGE HOLDS')
    log = section('ORIGINAL INSTALLATION LOG')
    reboot = section('REBOOT REQUIREMENT')

    checks['qemu_binary_and_version'] = bool(re.search(r'^/\S*/qemu-system-x86_64\s*$', qemu, re.M) and
                                             re.search(r'QEMU emulator version\s+\d+\.\d+', qemu))
    checks['virsh_present'] = bool(re.search(r'^/\S*/virsh\s*$', virsh, re.M) and
                                  re.search(r'^\d+\.\d+(?:\.\d+)?\s*$', virsh, re.M))
    checks['system_libvirt_connects_to_qemu'] = ('Compiled against library: libvirt' in connection and
                                                   'Using library: libvirt' in connection and
                                                   'Running hypervisor: QEMU' in connection)
    checks['kvm_acceleration_available'] = ('/dev/kvm exists' in kvm and
                                             'KVM acceleration can be used' in kvm)
    for label in ('qemu_binary_and_version', 'virsh_present', 'system_libvirt_connects_to_qemu',
                  'kvm_acceleration_available'):
        if not checks[label]:
            finding('FAILED_' + label.upper(), 'blocker')

    # The network report does not establish firewall policy or malware safety.
    default = re.search(r'^\s*default\s+(active|inactive)\s+(yes|no)\s+(yes|no)\s*$', nets, re.M)
    checks['default_libvirt_network_seen'] = bool(default)
    checks['default_network_active'] = bool(default and default.group(1) == 'active')
    checks['default_network_autostart'] = bool(default and default.group(2) == 'yes')
    checks['default_network_persistent'] = bool(default and default.group(3) == 'yes')
    if not default:
        finding('DEFAULT_NETWORK_MISSING_OR_UNPARSEABLE', 'review')
    else:
        if not checks['default_network_persistent']:
            finding('DEFAULT_NETWORK_TRANSIENT', 'blocker')
        if not checks['default_network_autostart']:
            finding('DEFAULT_NETWORK_AUTOSTART_DISABLED', 'review')

    checks['monolithic_libvirtd_active'] = bool(re.search(r'^active\s*$', services, re.M))
    if not checks['monolithic_libvirtd_active']:
        finding('LIBVIRTD_NOT_CONFIRMED_ACTIVE', 'blocker')
    # Modular virtqemud/virtnetworkd being inactive is not necessarily a failure
    # when libvirtd is running and the system hypervisor connection succeeded.

    session_id = next((line for line in user.splitlines() if line.startswith('uid=')), '')
    username = next((line for line in user.splitlines() if re.fullmatch(r'[a-z_][a-z0-9_-]*', line)), '')
    current_groups = session_id.partition('groups=')[2]
    for grp in ('kvm', 'libvirt'):
        in_database = bool(re.search(r'^' + grp + r':[^\n]*:(?:[^\n]*,)?' + re.escape(username) + r'(?:,|$)', user, re.M)) if username else False
        in_session = bool(re.search(r'\d+\(' + grp + r'\)', current_groups))
        checks[grp + '_account_membership_listed'] = in_database
        checks[grp + '_current_session_membership'] = in_session
        if in_database and not in_session:
            finding(grp.upper() + '_MEMBERSHIP_NOT_ACTIVE_IN_SESSION', 'review')

    checks['malformed_module_config'] = bool(re.search(r'^\s*-e\s+blacklist\s+', modprobe, re.M))
    if checks['malformed_module_config']:
        finding('MALFORMED_MODPROBE_FILE', 'blocker')
    checks['module_blacklist_directive_present'] = bool(re.search(r'^\s*blacklist\s+kvm(?:_intel|_amd)?\b', modprobe, re.M))
    if checks['module_blacklist_directive_present']:
        finding('KVM_MODULE_BLACKLIST_POLICY_REQUIRES_REVIEW', 'review')

    checks['tcp_syncookies_enabled'] = bool(re.search(r'net\.ipv4\.tcp_syncookies\s*=\s*1\b', sysctl))
    if not checks['tcp_syncookies_enabled']:
        finding('TCP_SYN_COOKIES_NOT_ENABLED_OR_UNKNOWN', 'blocker')

    masked = len(re.findall(r'^masked\s*$', targets, re.M))
    checks['masked_power_management_targets_count'] = masked
    if masked:
        finding('POWER_MANAGEMENT_TARGETS_MASKED', 'review')

    checks['custom_qemu_package_held'] = bool(re.search(r'^qemu\s*$', holds, re.M))
    if checks['custom_qemu_package_held']:
        finding('QEMU_PACKAGE_HELD', 'review')
    # Absent Ubuntu packaging is expected with a source build; don't interpret
    # 'no packages found' as proof that libvirt/SeaBIOS binaries aren't installed.
    checks['distro_libvirt_packages_missing'] = 'no packages found matching libvirt-clients' in packages

    checks['original_log_present_at_expected_path'] = 'cannot access' not in log and '.log' in log
    if not checks['original_log_present_at_expected_path']:
        finding('ORIGINAL_INSTALL_LOG_NOT_FOUND_AT_EXPECTED_PATH', 'review')
    checks['reboot_reported_required'] = 'System reports reboot required' in reboot
    if checks['reboot_reported_required']:
        finding('REBOOT_PENDING_REVIEW_REQUIRED', 'review')

    return {'status': 'REVIEW_REQUIRED' if findings else 'HOST_BASIC_CHECKS_PASS_ONLY',
            'checks': checks, 'findings': findings,
            'guest_network_isolation_verified': False,
            'authorizes_malware_execution': False,
            'authorizes_reboot_or_installer_rerun': False,
            'ssl55_mutated_by_this_audit': False}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path, help='Consolidated Step 7 post-build text report')
    p.add_argument('--json-out', type=Path, help='Write new restricted JSON file; never overwrite')
    args = p.parse_args(argv)
    try:
        parsed = assess(args.report.read_text(encoding='utf-8'))
    except (ValueError, OSError, UnicodeError):
        parsed = {'status': 'AUDIT_INCOMPLETE', 'authorizes_malware_execution': False}
    data = json.dumps(parsed, indent=2, sort_keys=True)
    print(data)
    if args.json_out:
        import os
        try:
            fd = os.open(args.json_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(data + '\n')
        except OSError:
            print('Could not create private report file', file=sys.stderr)
            return 2
    return 0 if parsed['status'] == 'HOST_BASIC_CHECKS_PASS_ONLY' else 2


if __name__ == '__main__':
    sys.exit(main())
