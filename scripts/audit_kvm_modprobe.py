#!/usr/bin/env python3
"""Read-only, fail-closed review of a local KVM modprobe configuration file.

This only inspects ONE named file and optionally asks modprobe to parse the
host's effective configuration. It never installs, edits or loads modules and
cannot certify boot-time KVM or guest-network isolation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

KVM_MODULES = frozenset({'kvm', 'kvm_intel', 'kvm_amd'})
DIRECTIVES = frozenset({'alias', 'blacklist', 'install', 'remove', 'options',
                        'softdep', 'weakdep'})


def inspect_lines(contents):
    findings = []
    rules = []
    for line_no, raw in enumerate(contents.splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith('#'):
            continue
        parts = value.split()
        directive = parts[0]
        if directive not in DIRECTIVES:
            findings.append({'code': 'UNRECOGNIZED_MODPROBE_DIRECTIVE',
                             'line': line_no})
            continue
        if len(parts) < 2:
            findings.append({'code': 'INCOMPLETE_MODPROBE_DIRECTIVE',
                             'line': line_no})
            continue
        target = parts[1]
        if directive == 'blacklist' and len(parts) != 2:
            findings.append({'code': 'UNEXPECTED_BLACKLIST_ARGUMENTS',
                             'line': line_no})
        if target in KVM_MODULES and directive in {'blacklist', 'install', 'remove'}:
            rules.append({'directive': directive, 'module': target, 'line': line_no})
    return {'findings': findings, 'kvm_loading_policy_rules': rules,
            'kvm_autoload_policy_requires_review': bool(rules),
            'no_guest_safety_or_reboot_assurance': True}


def inspect_file(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError('File missing, not regular, or symlink: separate policy review needed')
    try:
        return inspect_lines(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError) as exc:
        raise ValueError('Cannot read module policy file') from exc


def effective_config_check():
    """Read-only modprobe parse query: no module load and no changes."""
    try:
        run = subprocess.run(['modprobe', '--showconfig'], capture_output=True,
                             timeout=10, check=False, text=True)
    except (OSError, subprocess.SubprocessError):
        return {'checked': False, 'clean': False}
    return {'checked': True, 'clean': run.returncode == 0 and not run.stderr.strip()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path,
                        default=Path('/etc/modprobe.d/blacklist-kvm.conf'))
    parser.add_argument('--check-effective', action='store_true',
                        help='Run read-only modprobe --showconfig parse check')
    parser.add_argument('--report', type=Path,
                        help='Write new private JSON report (never overwrites)')
    args = parser.parse_args(argv)
    try:
        result = inspect_file(args.config)
        if args.check_effective:
            result['effective_config'] = effective_config_check()
    except ValueError:
        result = {'findings': [{'code': 'CONFIG_UNAVAILABLE_OR_UNTRUSTED'}],
                  'kvm_autoload_policy_requires_review': True,
                  'no_guest_safety_or_reboot_assurance': True}
    result['safe_to_change_system'] = False
    result['safe_to_run_malware'] = False
    report = json.dumps(result, indent=2, sort_keys=True)
    print(report)
    if args.report:
        try:
            fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(report + '\n')
        except OSError:
            print('Refused or unable to write report without overwrite', file=sys.stderr)
            return 2
    return 2 if (result['findings'] or result['kvm_autoload_policy_requires_review'] or
                 (args.check_effective and not result.get('effective_config', {}).get('clean'))) else 0


if __name__ == '__main__':
    sys.exit(main())
