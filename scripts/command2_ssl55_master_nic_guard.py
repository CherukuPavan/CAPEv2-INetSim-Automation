#!/usr/bin/env python3
"""Guarded ORIGINAL SSL-55 win11 saved-NIC restoration; plan is read-only.

apply changes ONLY the shut-off master's saved interface using
virsh attach-device --config and an explicitly approved plan fingerprint.
Never touches win11_1, trial guests, disks, checkpoints or host networking.
"""
from __future__ import annotations
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

MASTER = 'win11'
EXPECTED_UUID = '289d89be-68ec-4c62-90e1-ea930849266f'
EXPECTED_SNAPSHOT = 'finalshutoffversion'
PRESERVED = Path('/var/backups/cape-win11-preservation/win11-state-92POdfNc/metadata/domain.xml')
LOCK = Path('/run/lock/cape-ssl55-master-nic-restore.lock')
MAX_XML = 1024 * 1024

class Blocked(RuntimeError):
    pass

def need(test, message):
    if not test:
        raise Blocked(message)

def run(*cmd, timeout=20):
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True,
                              check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked('Unavailable/timed-out host command: ' + cmd[0]) from exc
    need(proc.returncode == 0, 'Read/command failed: ' + ' '.join(cmd[:3]) +
         ' (exit ' + str(proc.returncode) + ')')
    return proc.stdout.strip()

def virsh(*args):
    return run('virsh', '-c', 'qemu:///system', *args)

def host_guard():
    need(socket.gethostname().split('.', 1)[0].lower() in
         ('ssl-55', 'cse-ssl-55'), 'Not the expected SSL-55 reference host')
    need(os.geteuid() == 0, 'Root required for protected master metadata')

def preserved_xml():
    for part in (PRESERVED, *PRESERVED.parents):
        need(not part.is_symlink(), 'Preserved backup has symlink ancestor')
    try:
        info = PRESERVED.lstat()
    except OSError as exc:
        raise Blocked('Protected master domain backup unavailable') from exc
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
         info.st_nlink == 1 and info.st_size <= MAX_XML and
         not info.st_mode & 0o022,
         'Unexpected protected master XML backup ownership/permissions')
    return PRESERVED.read_text(encoding='utf-8')

def decode(xml, master_name=MASTER):
    need(isinstance(xml, str) and len(xml.encode('utf-8')) < MAX_XML,
         'Unexpected libvirt XML length')
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise Blocked('Unreadable libvirt XML') from exc
    need(root.tag == 'domain' and root.get('type') == 'kvm' and
         root.findtext('name') == master_name and
         root.findtext('uuid') == EXPECTED_UUID,
         'Original Windows master identity does not match protected record')
    return root

def safe_nic(backup_root, current_root):
    original = backup_root.findall('./devices/interface')
    current = current_root.findall('./devices/interface')
    need(len(original) == 1, 'Preserved master has unexpected NIC count')
    need(len(current) == 0, 'Current master already has a NIC; no repair authorized')
    nic = original[0]
    need(nic.get('type') == 'network', 'Original NIC was not network backed')
    allowed_tags = {'mac', 'model', 'source', 'address', 'alias', 'target', 'link'}
    need(all(child.tag in allowed_tags for child in nic),
         'Unexpected original NIC options require manual review')
    for tag in ('mac', 'model', 'source'):
        need(len(nic.findall(tag)) == 1, 'Original adapter missing exactly one ' + tag)
    src, mac, model = nic.find('source'), nic.find('mac'), nic.find('model')
    mac_addr = mac.get('address', '').lower()
    need(src.get('network') == 'default' and len(src.attrib) == 1,
         'Preserved NIC is not the exact default-network adapter')
    need(model.get('type') == 'e1000e' and len(model.attrib) == 1,
         'Preserved Windows adapter model differs from e1000e')
    need(re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', mac_addr) is not None and
         int(mac_addr[:2], 16) & 1 == 0 and mac_addr != '00:00:00:00:00:00',
         'Invalid original MAC')
    old_addr = nic.find('address')
    if old_addr is not None:
        need(old_addr.get('type') == 'pci', 'Unreviewed adapter address type')
        canonical = {key: old_addr.get(key) for key in
                     ('domain', 'bus', 'slot', 'function')}
        need(all(canonical.values()), 'Incomplete saved NIC PCI placement')
        for other in current_root.findall('.//address'):
            if other.get('type') != 'pci':
                continue
            existing = {key: other.get(key) for key in canonical}
            need(existing != canonical, 'Original adapter PCI address is now occupied')
    kept = copy.deepcopy(nic)
    for ephemeral in ('alias', 'target'):
        for node in list(kept.findall(ephemeral)):
            kept.remove(node)
    return kept, mac_addr

def protected_parts(root):
    """Fingerprint VM state not permitted to change when adding a NIC."""
    watched = (
        './devices/disk', './devices/tpm', './os/nvram', './os/loader',
        './memory', './currentMemory', './vcpu', './genid', './uuid',
        './devices/controller', './devices/hostdev', './devices/filesystem',
    )
    def canonical(node):
        element = copy.deepcopy(node)
        for desc in element.iter():
            if desc.text is not None:
                desc.text = desc.text.strip()
            if desc.tail is not None:
                desc.tail = desc.tail.strip()
        return ET.tostring(element, encoding='unicode')
    return {xpath: [canonical(node) for node in root.findall(xpath)]
            for xpath in watched}

def peer_mac_conflict(mac_addr):
    names = [v.strip() for v in virsh('list', '--all', '--name').splitlines()
             if v.strip() and v.strip() != MASTER]
    for peer in names:
        xmls = [virsh('dumpxml', '--inactive', peer)]
        if virsh('domstate', peer) in ('running', 'paused'):
            xmls.append(virsh('dumpxml', peer))
        for xml in xmls:
            try:
                root = ET.fromstring(xml)
            except ET.ParseError as exc:
                raise Blocked('Other libvirt domain XML invalid') from exc
            for node in root.findall('./devices/interface/mac'):
                need((node.get('address') or '').lower() != mac_addr,
                     'Saved master MAC conflicts with another libvirt guest')

def read_state():
    host_guard()
    need(virsh('domuuid', MASTER).lower() == EXPECTED_UUID,
         'Protected master libvirt UUID mismatch')
    need(virsh('domstate', MASTER).strip() == 'shut off',
         'Protected master must remain shut off')
    snapshot = virsh('snapshot-current', MASTER, '--name')
    snapshot_names = virsh('snapshot-list', MASTER, '--name').splitlines()
    need(snapshot == EXPECTED_SNAPSHOT,
         'Protected master current snapshot changed; no NIC repair')
    backup = preserved_xml()
    current = virsh('dumpxml', '--inactive', MASTER)
    old = decode(backup)
    new = decode(current)
    protected = protected_parts(new)
    restored, mac_addr = safe_nic(old, new)
    peer_mac_conflict(mac_addr)
    info = virsh('net-info', 'default')
    need(re.search(r'^Name:\s*default\s*$', info, re.M | re.I),
         'Expected default libvirt network missing')
    candidate = ET.tostring(restored, encoding='unicode')
    hashed = {
        'master': MASTER, 'uuid': EXPECTED_UUID,
        'snapshot': snapshot, 'snapshot_names': snapshot_names,
        'current_xml_sha256': hashlib.sha256(current.encode()).hexdigest(),
        'preserved_xml_sha256': hashlib.sha256(backup.encode()).hexdigest(),
        'device_xml_sha256': hashlib.sha256(candidate.encode()).hexdigest(),
        'protected_parts_sha256': hashlib.sha256(json.dumps(protected,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'nic_model': 'e1000e', 'network': 'default', 'mac': mac_addr,
    }
    plan_sha = hashlib.sha256(json.dumps(hashed, sort_keys=True,
                              separators=(',', ':')).encode()).hexdigest()
    return {'result': 'SSL55_ORIGINAL_MASTER_NIC_REPAIR_PLAN_ONLY',
            'plan_sha256': plan_sha,
            'fingerprints': hashed,
            'master_is_shut_off': True,
            'original_nic_missing_now': True,
            'no_guest_started': True, 'master_disk_changed': False,
            'master_snapshot_changed': False, 'guest_nic_attached': False,
            'analysis_network_activated': False, 'host_modified': False,
            'warning': 'Restores a default NAT-capable NIC to the shut-off clean master ONLY; no malware execution permitted'}, candidate

def apply(plan_hash):
    host_guard()
    need(re.fullmatch('[0-9a-f]{64}', plan_hash or '') is not None,
         'Require expected exact reviewed SHA256 from read-only plan')
    need(sys.stdin.isatty(), 'Run apply from an interactive terminal; no heredoc')
    phrase = 'RESTORE-ONLY-SHUTOFF-WIN11-SAVED-NIC'
    need(input('Type ' + phrase + ' to authorize restoring master NIC: ') == phrase,
         'Explicit operator authorization missing')
    need(not LOCK.is_symlink(), 'Unexpected libvirt repair lock symlink')
    lockfd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        meta = os.fstat(lockfd)
        need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and
             stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1,
             'Unsafe master repair lock metadata')
        fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        plan, device_xml = read_state()
        need(plan_hash == plan['plan_sha256'],
             'Reviewed network repair plan is STALE or different')
        fd, name = tempfile.mkstemp(prefix='cape-win11-nic-', suffix='.xml',
                                    dir='/run')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(device_xml)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(name, 0o600)
            virsh('attach-device', MASTER, name, '--config')
        finally:
            os.unlink(name)
        need(virsh('domstate', MASTER).strip() == 'shut off',
             'Master no longer shut off; STOP')
        need(virsh('snapshot-current', MASTER, '--name') == EXPECTED_SNAPSHOT,
             'Master current snapshot changed after NIC restoration; STOP')
        need(virsh('snapshot-list', MASTER, '--name').splitlines() ==
             plan['fingerprints']['snapshot_names'],
             'Master snapshot inventory changed; STOP')
        preserved_after = preserved_xml()
        need(hashlib.sha256(preserved_after.encode()).hexdigest() ==
             plan['fingerprints']['preserved_xml_sha256'],
             'Protected master preservation backup changed; STOP')
        master = decode(virsh('dumpxml', '--inactive', MASTER))
        after = master.findall('./devices/interface')
        need(len(after) == 1 and
             after[0].find('source').get('network') == 'default' and
             after[0].find('model').get('type') == 'e1000e' and
             after[0].find('mac').get('address').lower() == plan['fingerprints']['mac'],
             'Saved NIC differs from preserved original; MANUAL REVIEW, no blind rollback')
        need(master.findtext('./uuid') == EXPECTED_UUID,
             'Master identity unexpectedly changed; STOP')
        protected_now = protected_parts(master)
        protected_hash = hashlib.sha256(json.dumps(protected_now,
            sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        need(protected_hash == plan['fingerprints']['protected_parts_sha256'],
             'Protected disk/UEFI/TPM or resource definition changed; STOP')
        return {'result': 'ORIGINAL_SHUTOFF_WIN11_SAVED_NIC_RESTORED',
                'uuid': EXPECTED_UUID, 'snapshot': EXPECTED_SNAPSHOT,
                'interface_count': 1, 'network': 'default',
                'master_remains_shut_off': True, 'win11_1_untouched': True,
                'trial_untouched': True, 'host_firewall_untouched': True,
                'network_not_started': True, 'no_other_vm_created': True}
    finally:
        os.close(lockfd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('plan', 'apply'), default='plan')
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    try:
        if args.mode == 'plan':
            result, _ = read_state()
        else:
            result = apply(args.plan_sha256)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ET.ParseError, TypeError, AttributeError,
            ValueError) as exc:
        print('BLOCKED: ' + str(exc), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
