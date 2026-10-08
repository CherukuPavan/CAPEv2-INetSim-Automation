#!/usr/bin/env python3
"""Read-only offline assessment of a Step 7F systemd power target report.

Never runs systemctl, changes host settings, or authorizes power-policy edits.
All emitted fields are fixed labels and booleans; no raw host identities included.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

TARGETS = ('sleep.target', 'suspend.target', 'hibernate.target', 'hybrid-sleep.target')


def analyze(text):
    if '========== STEP 7F POWER MANAGEMENT REVIEW ==========' not in text:
        raise ValueError('Expected Step 7F report header missing')
    states = {}
    issues = []
    for target in TARGETS:
        match = re.search(r'^---------- ' + re.escape(target) +
                          r' ----------\s*\n(.*?)(?=^---------- |^==========|\Z)',
                          text, re.MULTILINE | re.DOTALL)
        if not match:
            states[target] = {'status': 'NOT_REPORTED'}
            issues.append('MISSING_TARGET_BLOCK_' + target.replace('.', '_'))
            continue
        block = match.group(1)
        en = re.search(r'^Enabled state:\s*\n([^\n]+)', block, re.MULTILINE)
        state = en.group(1).strip() if en else 'UNKNOWN'
        load = re.search(r'^LoadState=([^\n]+)', block, re.MULTILINE)
        unit = re.search(r'^UnitFileState=([^\n]+)', block, re.MULTILINE)
        fragment = re.search(r'^FragmentPath=([^\n]+)', block, re.MULTILINE)
        link = re.search(r'^lrwx[^\n]* /etc/systemd/system/' + re.escape(target) +
                         r' -> /dev/null\s*$', block, re.MULTILINE)
        runtime_absent = ('No direct runtime override at /run/systemd/system/' + target) in block
        consistent = (state == 'masked' and load is not None and load.group(1) == 'masked'
                      and unit is not None and unit.group(1) == 'masked'
                      and fragment is not None and fragment.group(1) == '/etc/systemd/system/' + target
                      and link is not None)
        states[target] = {
            'status': 'PERSISTENTLY_MASKED' if consistent else 'INCOMPLETE_OR_DIFFERENT',
            'enabled_masked': state == 'masked',
            'load_masked': bool(load and load.group(1) == 'masked'),
            'persistent_symlink_to_dev_null': bool(link),
            'direct_runtime_override_absent': runtime_absent,
        }
        if not consistent:
            issues.append('MASK_STATE_INCONSISTENT_' + target.replace('.', '_'))
    installer_line_found = bool(re.search(
        r'^\d+:systemctl mask sleep\.target suspend\.target hibernate\.target hybrid-sleep\.target\s*$',
        text, re.MULTILINE))
    if not installer_line_found:
        issues.append('INSTALLER_MASK_LINE_NOT_CONFIRMED')
    reboot_marker = 'Reboot-required marker: PRESENT' in text
    complete = '========== STEP 7F REVIEW COMPLETE ==========' in text
    if not complete:
        issues.append('REPORT_INCOMPLETE')
    return {
        'status': 'PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED' if not issues else 'INCOMPLETE_OR_UNEXPECTED',
        'target_states': states, 'finding_codes': issues,
        'upstream_installer_mask_command_observed': installer_line_found,
        'reboot_required_marker_reported': reboot_marker,
        'user_power_policy_review_required': True,
        'authorized_to_unmask': False,
        'host_changed_by_this_audit': False,
        'reboot_verified': False,
        'guest_network_isolation_verified': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, help='Create a new private JSON report without overwriting')
    args = parser.parse_args(argv)
    try:
        data = analyze(args.report.read_text(encoding='utf-8', errors='replace'))
    except (OSError, ValueError):
        data = {'status': 'AUDIT_INCOMPLETE', 'authorized_to_unmask': False,
                'guest_network_isolation_verified': False}
    serial = json.dumps(data, indent=2, sort_keys=True)
    print(serial)
    if args.output:
        try:
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(serial + '\n')
        except OSError:
            print('Unable to create private output (no overwrite)', file=sys.stderr)
            return 2
    return 0 if data['status'] == 'PERSISTENT_MASKS_VERIFIED_REVIEW_REQUIRED' else 2


if __name__ == '__main__':
    sys.exit(main())
