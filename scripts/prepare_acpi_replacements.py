#!/usr/bin/env python3
"""DRAFT: audit and (with explicit approval) patch nine CAPEv2 <WOOT> assignments.

ACPI header fields only justify a candidate for BXPC_REPLACER. The other
fields are unrelated device/BIOS identifiers and must come from a reviewed
per-field profile. Nothing is installed or modified unless --apply is given.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

VARS = (
    'PEN_REPLACER', 'SCSI_REPLACER', 'ATAPI_REPLACER',
    'MICRODRIVE_REPLACER', 'BOCHS_BLOCK_REPLACER',
    'BOCHS_BLOCK_REPLACER2', 'BOCHS_BLOCK_REPLACER3',
    'BXPC_REPLACER', 'BOCHS_SEABIOS_BLOCK_REPLACER',
)
DEVICE_VARS = tuple(x for x in VARS if x != 'BXPC_REPLACER')
ASSIGNMENT = re.compile(r"^(?P<key>[A-Z][A-Z0-9_]*)='(?P<value>[^'\r\n]*)'$", re.M)
SAFE_VALUE = re.compile(r'^[A-Za-z0-9]{2,8}$')
DEFAULT_DSDT = '/sys/firmware/acpi/tables/DSDT'

class Refusal(Exception):
    pass

def die(message):
    raise Refusal(message)

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def dsdt_fields(path):
    try:
        raw = path.read_bytes()
    except OSError as exc:
        die(f'Cannot read DSDT {path}: {exc}. Use an authorized diagnostic stage.')
    if len(raw) < 36 or raw[:4] != b'DSDT':
        die('ACPI input is not a DSDT table header')
    length = int.from_bytes(raw[4:8], 'little')
    if length != len(raw):
        die(f'DSDT length mismatch: header={length}, actual={len(raw)}')
    if sum(raw) % 256:
        die('DSDT checksum invalid; cannot trust header')
    try:
        oem = raw[10:16].decode('ascii').rstrip(' ')
        table = raw[16:24].decode('ascii').rstrip(' ')
    except UnicodeDecodeError:
        die('Non-ASCII DSDT OEM field; manual examination required')
    return {'oem_id': oem, 'oem_table_id': table}

def bxpc_candidate(fields):
    # BXPC is four ASCII bytes in the inspected upstream source. Do not pad,
    # truncate or guess which field is intended if both yield different IDs.
    candidates = {key: value for key, value in fields.items()
                  if re.fullmatch('[A-Za-z0-9]{4}', value)}
    choices = set(candidates.values())
    if not choices:
        die('Neither DSDT OEM field is an exact 4-character ASCII identifier; manual review required')
    if len(choices) > 1:
        die(f'Conflicting 4-character ACPI candidates {candidates}; manual review required')
    return choices.pop(), list(candidates)

def review_profile(path):
    if path is None:
        die('An explicit reviewed JSON profile for the eight device/BIOS variables is required')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        die(f'Cannot parse profile: {exc}')
    if not isinstance(value, dict) or set(value) != set(DEVICE_VARS):
        die(f'Profile must contain exactly these eight keys: {list(DEVICE_VARS)}')
    for key, label in value.items():
        if not isinstance(label, str) or not SAFE_VALUE.fullmatch(label):
            die(f'Unsafe or unsupported value for {key}: require 2..8 ASCII letters/digits')
    return value

def parse_assignments(content):
    matches = {}
    for m in ASSIGNMENT.finditer(content):
        key = m.group('key')
        if key in VARS:
            if key in matches:
                die(f'Duplicate {key} assignment')
            matches[key] = m
    if set(matches) != set(VARS):
        die(f'Unexpected script layout: required nine assignments, missing {sorted(set(VARS)-set(matches))}')
    return matches

def generate(content, choices):
    found = parse_assignments(content)
    old_vals = {name: m.group('value') for name, m in found.items()}
    placeholder_count = content.count('<WOOT>')
    if placeholder_count == 0:
        if old_vals == choices:
            return content, 'already-matches'
        die('No placeholders remain, but current values differ from reviewed profile; refusing overwrite')
    if placeholder_count != 9 or any(v != '<WOOT>' for v in old_vals.values()):
        die(f'Expected exactly nine untouched <WOOT> assignments; found {placeholder_count} placeholders. Refusing partial or unknown patch')
    # Replace only the nine known values, preserving every other byte.
    out = content
    for name, m in sorted(found.items(), key=lambda x: x[1].start(), reverse=True):
        start, stop = m.span('value')
        out = out[:start] + choices[name] + out[stop:]
    if '<WOOT>' in out:
        die('Verification failed: placeholder remains after patch')
    if any(parse_assignments(out)[name].group('value') != choices[name] for name in VARS):
        die('Verification failed: one or more values differ')
    return out, 'planned'

def patch_atomically(path, before_bytes, after_bytes, backup_dir):
    if path.is_symlink() or not path.is_file():
        die('Target is missing or a symlink; refusing write')
    try:
        before_stat = path.stat()
        if path.read_bytes() != before_bytes:
            die('File changed since validation; refusing write')
        backup_dir.mkdir(parents=True, exist_ok=True)
        if backup_dir.is_symlink():
            die('Backup directory is a symlink; refusing write')
        tag = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid4().hex[:8]
        backup = backup_dir / f'{path.name}.{tag}.bak'
        with backup.open('xb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(before_bytes)
            out.flush()
            os.fsync(out.fileno())
        if sha256(backup.read_bytes()) != sha256(before_bytes):
            die('Backup hash mismatch; refusing write')
        fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'wb') as out:
                os.fchmod(out.fileno(), stat.S_IMODE(before_stat.st_mode))
                if os.geteuid() == 0:
                    os.fchown(out.fileno(), before_stat.st_uid, before_stat.st_gid)
                out.write(after_bytes)
                out.flush()
                os.fsync(out.fileno())
            if path.read_bytes() != before_bytes:
                die('File changed concurrently; refusing atomic replacement')
            os.replace(name, path)
            if path.read_bytes() != after_bytes:
                die('Post-write content verification failed; backup retained')
        finally:
            if os.path.exists(name):
                os.unlink(name)
        print(f'BACKUP: {backup}')
        print('APPLIED: nine validated variable substitutions; source mode/ownership preserved')
    except OSError as exc:
        die(f'Write/backup failed: {exc}')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--script', type=Path, required=True, help='Absolute path to installer/kvm-qemu.sh')
    ap.add_argument('--dsdt', type=Path, default=Path(DEFAULT_DSDT))
    ap.add_argument('--profile', type=Path, help='Reviewed JSON values for eight non-ACPI variables')
    ap.add_argument('--apply', action='store_true', help='Enable guarded backup+write; otherwise read-only')
    ap.add_argument('--expected-sha256', help='Expected original kvm-qemu.sh SHA256; required to modify a pristine source')
    ap.add_argument('--backup-dir', type=Path, help='Where to store backups outside the CAPEv2 checkout')
    args = ap.parse_args()
    if not args.script.is_absolute() or args.script.is_symlink() or not args.script.is_file():
        die('--script must be an existing, absolute, non-symlink file')
    if args.script.name != 'kvm-qemu.sh' or args.script.parent.name != 'installer':
        die('Target must be named installer/kvm-qemu.sh')
    fields = dsdt_fields(args.dsdt)
    print('DSDT OEM ID:', repr(fields['oem_id']))
    print('DSDT OEM Table ID:', repr(fields['oem_table_id']))
    proposed_bxpc, sources = bxpc_candidate(fields)
    print(f'Validated four-character BXPC candidate: {proposed_bxpc} (field: {sources})')
    before_bytes = args.script.read_bytes()
    try:
        before = before_bytes.decode('utf-8')
    except UnicodeError:
        die('Installer source is not valid UTF-8')
    current = parse_assignments(before)
    print('Source SHA256:', sha256(before_bytes))
    print('Current variable values:', json.dumps({k: m.group('value') for k, m in current.items()}, sort_keys=True))
    if not args.profile:
        print('AUDIT ONLY: no reviewed profile for non-ACPI device/BIOS fields. No changes made.')
        return 0 if not args.apply else 2
    profile = review_profile(args.profile)
    choices = dict(profile, BXPC_REPLACER=proposed_bxpc)
    after, status = generate(before, choices)
    if status == 'already-matches':
        print('VERIFIED NO-OP: all nine values already match selected profile; no changes made')
        return 0
    if not args.apply:
        print('DRY RUN: exact nine replacements are validated; no files changed')
        for line in difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile='before', tofile='candidate', lineterm=''):
            print(line)
        return 0
    if not args.expected_sha256 or not re.fullmatch(r'[a-fA-F0-9]{64}', args.expected_sha256):
        die('--apply requires a verified original --expected-sha256; do not apply to unknown CAPEv2 source versions')
    if sha256(before_bytes) != args.expected_sha256.lower():
        die('Original script SHA256 does not match pinned expectation; refusing write')
    if args.backup_dir is None or not args.backup_dir.is_absolute():
        die('--apply requires an absolute --backup-dir outside the CAPEv2 checkout')
    repo_root = args.script.parent.parent.resolve()
    back_path = args.backup_dir.resolve()
    if back_path == repo_root or repo_root in back_path.parents:
        die('Backup directory must be outside the entire CAPEv2 checkout')
    patch_atomically(args.script, before_bytes, after.encode('utf-8'), args.backup_dir)
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Refusal as exc:
        print(f'REFUSED: {exc}', file=sys.stderr)
        sys.exit(2)
