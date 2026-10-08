#!/usr/bin/env python3
"""Read-only sysctl file identity and single-setting audit.

Does not execute sysctl --system, change active kernel parameters, edit files,
certify boot persistence, or approve malware analysis. Default paths mirror an
Ubuntu layout, but all paths are overridable on other supported hosts.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

COOKIE_PATTERN = re.compile(r'^\s*net\.ipv4\.tcp_syncookies\s*=\s*([^\s#]+)(?:\s*(?:#.*)?)?$')


def active_definitions(text):
    """Ignore commented lines; return numbered active key definitions only."""
    return [{'line_number': i, 'value': match.group(1)}
            for i, line in enumerate(text.splitlines(), 1)
            if (match := COOKIE_PATTERN.fullmatch(line))]


def audit_paths(primary, alias):
    """Never read or include unrelated lines of potentially sensitive configs."""
    report = {'primary': str(primary), 'alias': str(alias), 'findings': [],
              'edits_authorized': False, 'reboot_safety_verified': False}
    for path in (primary, alias):
        if not path.exists() or not path.is_file():
            report['findings'].append('CONFIG_PATH_MISSING_OR_NOT_REGULAR')
            return report
    try:
        primary_resolved = primary.resolve(strict=True)
        alias_resolved = alias.resolve(strict=True)
        pstat = primary.stat()
        astat = alias.stat()
        report['primary_is_symlink'] = primary.is_symlink()
        report['alias_is_symlink'] = alias.is_symlink()
        report['same_underlying_file'] = (pstat.st_dev, pstat.st_ino) == (astat.st_dev, astat.st_ino)
        report['alias_resolves_to_primary'] = alias_resolved == primary_resolved
        report['primary_root_owned'] = pstat.st_uid == 0 and pstat.st_gid == 0
        report['primary_mode'] = oct(pstat.st_mode & 0o777)
        definitions = active_definitions(primary.read_text(encoding='utf-8'))
        alias_definitions = active_definitions(alias.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, RuntimeError):
        report['findings'].append('CONFIG_READ_FAILED')
        return report
    report['primary_definitions'] = definitions
    report['alias_definitions'] = alias_definitions
    if not report['same_underlying_file']:
        report['findings'].append('DIFFERENT_UNDERLYING_FILES')
    if not report['alias_resolves_to_primary']:
        report['findings'].append('ALIAS_RESOLUTION_MISMATCH')
    if len(definitions) != 1 or len(alias_definitions) != 1:
        report['findings'].append('MISSING_OR_DUPLICATE_ACTIVE_SETTING')
    elif definitions != alias_definitions:
        report['findings'].append('MISMATCHED_DEFINITIONS')
    if definitions and any(x['value'] != '1' for x in definitions):
        report['findings'].append('PERSISTENT_SYN_COOKIES_NOT_ENABLED')
    if report['primary_is_symlink']:
        report['findings'].append('PRIMARY_IS_SYMLINK_REVIEW_REQUIRED')
    if not report['primary_root_owned']:
        report['findings'].append('PRIMARY_NOT_ROOT_OWNED')
    return report


def read_active_sysctl():
    try:
        res = subprocess.run(['sysctl', '-n', 'net.ipv4.tcp_syncookies'],
                             capture_output=True, text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return {'checked': False, 'value': None}
    value = res.stdout.strip()
    return {'checked': True, 'value': value if value in ('0', '1', '2') else '<UNRECOGNIZED>'}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--primary', type=Path, default=Path('/etc/sysctl.conf'))
    ap.add_argument('--alias', type=Path, default=Path('/etc/sysctl.d/99-sysctl.conf'))
    ap.add_argument('--check-active', action='store_true')
    ap.add_argument('--report', type=Path, help='New private JSON report; no overwrite')
    args = ap.parse_args(argv)
    result = audit_paths(args.primary, args.alias)
    if args.check_active:
        result['active_runtime'] = read_active_sysctl()
        if not result['active_runtime']['checked'] or result['active_runtime']['value'] != '1':
            result['findings'].append('ACTIVE_SYN_COOKIES_NOT_ENABLED_OR_UNKNOWN')
    result['status'] = 'REVIEW_REQUIRED' if result['findings'] else 'LOCAL_FILE_CHECKS_PASS_ONLY'
    output = json.dumps(result, indent=2, sort_keys=True)
    print(output)
    if args.report:
        try:
            fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(output + '\n')
        except OSError:
            print('Could not create private report', file=sys.stderr)
            return 2
    return 2 if result['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
