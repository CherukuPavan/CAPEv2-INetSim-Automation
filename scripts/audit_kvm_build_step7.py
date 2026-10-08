#!/usr/bin/env python3
"""Read-only CAPEv2 Step 7 build-log and Ubuntu-user audit; never deploys QEMU."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import sys

FINDINGS = (
    ('BROKEN_MODPROBE_CONFIG', r'libkmod: ERROR.*blacklist-kvm\.conf.*bad line', 'error'),
    ('PIP_DISTRO_PACKAGE_CONFLICT', r'ERROR: Cannot uninstall cryptography .*RECORD file not found', 'error'),
    ('OVMF_PACKAGE_FILE_COLLISION', r'dpkg: warning: trying to overwrite .*firmware/', 'error'),
    ('LIBVIRT_DISTRO_PACKAGES_PURGED', r'Removing libvirt-(?:clients|daemon)', 'warning'),
    ('LIBVIRT_APT_PACKAGE_NOT_FOUND', r'E: Unable to locate package libvirt', 'warning'),
    ('EXISTING_KVM_GROUP', r'fatal: The group [\x60\']kvm[\'] already exists', 'warning'),
    ('SEABIOS_CONFIG_MISSING_ON_FIRST_EDIT', r'sed: can.t read \.config: No such file', 'warning'),
    ('PYTHON2_DEPENDENCY_PROBLEM', r'python-enum34\s+: Depends: python2:', 'warning'),
    ('SEABIOS_COMPILE_WARNING', r'warning: .__builtin_memcpy. reading 6 bytes from a region of size 5', 'warning'),
)


def analyze_log(text):
    """Only emitted labels and counters: no log lines, paths, credentials or host IPs."""
    findings = []
    for code, pattern, severity in FINDINGS:
        count = len(re.findall(pattern, text, re.IGNORECASE))
        if count:
            findings.append({'code': code, 'severity': severity, 'occurrences': count})
    first = next((s.strip() for s in text.splitlines() if s.strip()), '')
    incomplete_start = bool(re.match(r'^\[\d+/(?:\d+)\] Compiling', first))
    stages = {
        'custom_qemu_package_configured': 'Setting up qemu (9.2.2)' in text,
        'seabios_firmware_copied': '[+] Patched bios.bin placed correctly' in text,
        'libvirt_python_installed': 'Successfully installed libvirt-python-11.1.0' in text,
        'virt_manager_install_activity': 'virt-manager/virtManager/' in text,
        'kvm_acceleration_reported_usable': 'KVM acceleration can be used' in text,
        'reboot_requested': '[+] Please reboot' in text,
    }
    return {
        'overall_status': 'UNVERIFIED_WITH_ERRORS' if findings else 'UNVERIFIED_REQUIRES_POST_INSTALL_CHECKS',
        'captured_log_starts_mid_build': incomplete_start,
        'important_findings': findings,
        'observed_stage_indicators': stages,
        'installer_exit_status_known': False,
        'functional_post_install_checks_completed': False,
        'safe_to_rerun_upstream_all': False,
        'no_guest_network_isolation_verified': True,
    }


def audit_username(username, source):
    """Validate explicit deployment user, without trusting a shell argument or executing source."""
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*[$]?', username):
        raise ValueError('Invalid Ubuntu account name')
    try:
        account = pwd.getpwnam(username)
    except KeyError as exc:
        raise ValueError('Specified Ubuntu account does not exist') from exc
    if account.pw_uid == 0:
        raise ValueError('Target Ubuntu account must be non-root')
    if not account.pw_dir or not os.path.isdir(account.pw_dir):
        raise ValueError('User home directory is not available')
    try:
        content = source.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise ValueError('Cannot read upstream installer script') from exc
    if not re.search(r'^username=\$SUDO_USER\s*$', content, re.MULTILINE):
        raise ValueError('Upstream username assignment differs; manual review required')
    if re.search(r'^[ \t]*username=["\']?\$2\b', content, re.MULTILINE):
        raise ValueError('Script also appears to read argument $2; inspect actual precedence')
    return {
        'requested_nonroot_user': username,
        'uid': account.pw_uid,
        'source_username_resolves_from_sudo_user': True,
        'second_argument_used_as_user_in_inspected_source': False,
        'installer_execution_authorized': False,
        'note': 'Future wrapper must enforce the validated user through sudo -u / SUDO_USER; do not rely on $2.',
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--log', required=True, type=Path)
    p.add_argument('--script', type=Path, help='Optional local upstream installer for read-only user semantics audit')
    p.add_argument('--user', help='Intended existing non-root Ubuntu username, used with --script')
    p.add_argument('--report', type=Path, help='Optional new private JSON report; never overwrites')
    args = p.parse_args()
    if bool(args.script) != bool(args.user):
        p.error('--script and --user must be supplied together')
    try:
        result = analyze_log(args.log.read_text(encoding='utf-8', errors='replace'))
        if args.user:
            result['user_preflight'] = audit_username(args.user, args.script)
    except (OSError, ValueError) as exc:
        # Avoid exposing potentially sensitive host paths, shell contents or the log itself.
        result = {'overall_status': 'AUDIT_INCOMPLETE', 'reason': type(exc).__name__,
                  'safe_to_rerun_upstream_all': False}
    output = json.dumps(result, indent=2, sort_keys=True)
    print(output)
    if args.report:
        try:
            fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(output + '\n')
        except OSError:
            print('Refused or unable to create private report', file=sys.stderr)
            return 2
    return 2 if result.get('overall_status') != 'UNVERIFIED_REQUIRES_POST_INSTALL_CHECKS' else 1


if __name__ == '__main__':
    sys.exit(main())
