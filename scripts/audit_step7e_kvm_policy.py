#!/usr/bin/env python3
"""Read-only, redacting parser of the manually gathered Step 7E KVM policy report.

This parses evidence, does not inspect or alter the current host, and NEVER
asserts boot-time KVM availability or safe guest networking.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

HEADER = re.compile(r'^========== (.+?) ==========$', re.MULTILINE)
MODULES = {'kvm', 'kvm_intel', 'kvm_amd'}


def split_report(raw):
    found = list(HEADER.finditer(raw))
    if not found or found[0].group(1) != 'STEP 7E KVM POLICY VERIFICATION':
        raise ValueError('Invalid Step 7E report header')
    return {m.group(1): raw[m.end():found[i+1].start() if i+1 < len(found) else len(raw)].strip()
            for i, m in enumerate(found)}


def analyze(raw):
    sections = split_report(raw)
    def sec(name):
        return sections.get(name, '')
    rules = []
    options = []
    for line in sec('EFFECTIVE KVM MODPROBE RULES').splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] not in MODULES:
            continue
        if parts[0] in ('blacklist', 'install', 'remove'):
            rules.append({'action': parts[0], 'module': parts[1]})
        elif parts[0] == 'options':
            for option in parts[2:]:
                # Fixed recognized names and values only; no raw config text emitted.
                if option in ('ignore_msrs=Y', 'ignore_msrs=N', 'report_ignored_msrs=Y', 'report_ignored_msrs=N'):
                    options.append(option)
    loaded = sorted(set(m.group(1) for line in sec('CURRENTLY LOADED KVM MODULES').splitlines()
                        if (m := re.match(r'^(kvm|kvm_intel|kvm_amd)\s+\d+', line))))
    module_names = sorted(set(m.group(1) for line in sec('KVM MODULE AVAILABILITY').splitlines()
                              if (m := re.search(r'/((?:kvm|kvm-intel|kvm-amd))\.ko(?:\.[A-Za-z0-9]+)?$', line))))
    normal = sec('KVM MODULE DRY RUN')
    normal_runs = {}
    for mod in ('kvm', 'kvm_intel', 'kvm_amd'):
        match = re.search(r'^Testing: '+re.escape(mod)+r'\s*\nDry-run exit status: (SUCCESS|FAILED)\s*$', normal, re.M)
        normal_runs[mod] = match.group(1) if match else 'NOT_REPORTED'
    parsed = sec('EFFECTIVE MODPROBE CONFIGURATION CHECK')
    parse_ok = re.search(r'^Modprobe configuration parsing: PASSED$', parsed, re.M) is not None
    blacklisted_dryrun = 'Blacklist-aware dry-run exit status: SUCCESS' in sec('KVM BLACKLIST-AWARE DRY RUN')
    libvirtd_active = re.search(r'^active$', sec('LIBVIRT SERVICE'), re.M) is not None
    cookie_enabled = re.search(r'^net\.ipv4\.tcp_syncookies\s*=\s*1$', sec('CURRENT TCP SYN COOKIE SETTING'), re.M) is not None
    report_complete = 'VERIFICATION COMPLETE' in sections
    blockers = []
    if not parse_ok: blockers.append('MODPROBE_PARSE_NOT_CONFIRMED')
    if not {'kvm', 'kvm_intel'}.issubset(set(loaded)) and not {'kvm', 'kvm_amd'}.issubset(set(loaded)):
        blockers.append('EXPECTED_KVM_MODULES_NOT_CONFIRMED_LOADED')
    if not libvirtd_active: blockers.append('LIBVIRT_ACTIVE_NOT_CONFIRMED')
    if not cookie_enabled: blockers.append('TCP_SYN_COOKIES_NOT_CONFIRMED_ENABLED')
    if not report_complete: blockers.append('REPORT_INCOMPLETE')
    if not normal_runs['kvm'] == 'SUCCESS': blockers.append('KVM_DRYRUN_NOT_CONFIRMED_SUCCESS')
    if not any(normal_runs[x] == 'SUCCESS' for x in ('kvm_intel', 'kvm_amd')):
        blockers.append('CPU_DRIVER_DRYRUN_NOT_CONFIRMED_SUCCESS')
    return {
        'status': 'BASIC_KVM_CHECKS_PASS_POLICY_REVIEW' if not blockers else 'INCOMPLETE_OR_FAILED_CHECKS',
        'blockers': blockers,
        'loaded_kvm_modules': loaded,
        'kvm_module_files_seen': module_names,
        'modprobe_config_parsed': parse_ok,
        'policy_rules': rules,
        'recognized_kvm_options': sorted(set(options)),
        'normal_dry_runs': normal_runs,
        'blacklist_aware_dry_run_successful': blacklisted_dryrun,
        'libvirtd_reported_active': libvirtd_active,
        'tcp_syn_cookies_reported_enabled': cookie_enabled,
        'blacklist_policy_review_required': bool(rules),
        'boot_autoload_verified': False,
        'host_policy_approved': False,
        'guest_isolation_verified': False,
        'authorizes_reboot_or_malware_execution': False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path)
    p.add_argument('--output', type=Path, help='New private JSON output (never overwrite)')
    args = p.parse_args(argv)
    try:
        result = analyze(args.report.read_text(encoding='utf-8', errors='replace'))
    except (ValueError, OSError):
        result = {'status': 'AUDIT_FAILED', 'boot_autoload_verified': False,
                  'guest_isolation_verified': False,
                  'authorizes_reboot_or_malware_execution': False}
    rendered = json.dumps(result, sort_keys=True, indent=2)
    print(rendered)
    if args.output:
        try:
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(rendered + '\n')
        except OSError:
            print('Private output cannot be created without overwrite', file=sys.stderr)
            return 2
    return 0 if result['status'] == 'BASIC_KVM_CHECKS_PASS_POLICY_REVIEW' else 2

if __name__ == '__main__':
    sys.exit(main())
