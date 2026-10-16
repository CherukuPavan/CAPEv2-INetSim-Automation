#!/usr/bin/env python3
"""One safe NEW-HOST three-command diagnostic report for a stopped deployment.

This is read-only and intentionally does not try to 'repair' uncertain VM,
TPM, routing, package, firewall or storage state. It never invokes malware,
external egress probes, VM start/revert, package changes or cloud login.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

import command2_native_snapshot_stack_guard as snapshot_guard

SENSITIVE_OS_HOSTS = frozenset(("cse-ssl-55", "ssl-55", "cse-ssl-46", "ssl-46"))
UNITS = ("cape.service", "cape-processor.service", "cape-rooter.service",
         "cape-web.service", "suricata.service")
BINARIES = ("python3", "git", "rclone", "virsh", "qemu-img",
            "qemu-system-x86_64", "swtpm", "systemctl")
PACKAGES = ("python3", "python3-venv", "python3-pip",
            "git", "qemu-system-x86", "qemu-utils",
            "libvirt-clients", "libvirt-daemon-system",
            "ovmf", "swtpm", "swtpm-tools", "postgresql")
CONF = Path("/opt/CAPEv2/conf")
NAMES = ("api.conf", "auxiliary.conf", "cuckoo.conf", "kvm.conf",
         "mitmdump.conf", "routing.conf")
VM_PATTERN = re.compile(r"(?:win11|win11_(?:[1-9]|1[0-6]))\Z")


class DoctorBlocked(RuntimeError):
    pass


def need(ok, msg):
    if not ok:
        raise DoctorBlocked(msg)


def check_host(name):
    actual = socket.gethostname().split(".", 1)[0].lower()
    need(actual == name.lower().split(".", 1)[0] and
         actual not in SENSITIVE_OS_HOSTS and
         re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", actual),
         "Only approved non-source target hostname")
    return actual


def read_command(*argv, timeout=12, max_bytes=65536):
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None
    if p.returncode or len(p.stdout) > max_bytes:
        return None
    return p.stdout.strip()


def package_status():
    result = {}
    for name in PACKAGES:
        val = read_command("dpkg-query", "-W", "-f=${Status}", name)
        result[name] = val == "install ok installed"
    return result


def service_status():
    status = {}
    for unit in UNITS:
        data = read_command("systemctl", "show", "--no-pager",
                            "--property=LoadState,ActiveState,Result", unit)
        if data is None:
            status[unit] = "UNAVAILABLE"
            continue
        props = dict(item.split("=", 1) for item in data.splitlines()
                     if "=" in item and item.split("=", 1)[0] in
                     ("LoadState", "ActiveState", "Result"))
        status[unit] = {
            "loaded": props.get("LoadState") == "loaded",
            "active": props.get("ActiveState") == "active",
            "last_result": props.get("Result", "UNKNOWN")[:80],
        }
    return status


def vm_status(count):
    vms = read_command("virsh", "-c", "qemu:///system",
                       "list", "--all", "--name")
    if vms is None:
        return {"libvirt_query_available": False,
                "expected_additional_vm_count": count,
                "all_expected_vms_present": False,
                "all_domains_shut_off": False,
                "libvirt_inventory_stable": False,
                "no_vm_lifecycle_mutation": True}
    raw_names = [line.strip() for line in vms.splitlines() if line.strip()]
    # A read-only repair report is unsafe if defined third-party guests
    # were omitted or their state cannot be inspected. Bound the number of
    # state probes and require exact names without duplicated inventory.
    inventory_valid = (
        len(raw_names) <= 256 and len(raw_names) == len(set(raw_names)) and
        all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", n) for n in raw_names))
    names = set(raw_names) if inventory_valid else set()
    states = ({name: read_command("virsh", "-c", "qemu:///system",
                                  "domstate", name)
               for name in raw_names} if inventory_valid else {})
    reread = read_command("virsh", "-c", "qemu:///system",
                          "list", "--all", "--name")
    stable = (inventory_valid and reread is not None and
              raw_names == [line.strip() for line in reread.splitlines()
                            if line.strip()])
    all_off = stable and all(state == "shut off" for state in states.values())
    expected = ["win11"] + ["win11_" + str(i)
                             for i in range(1, count + 1)]
    details = {}
    for name in expected:
        if name not in names:
            details[name] = {"present": False}
            continue
        state = states.get(name)
        snaps = read_command("virsh", "-c", "qemu:///system",
                             "snapshot-list", name, "--name")
        details[name] = {
            "present": True,
            "state": state if state is not None else "UNKNOWN",
            "snapshot_names": snaps.splitlines()[:100]
                              if snaps is not None else None,
            "running_snapshot_TPM_safe": False,
            "windows_boot_agent_verified": False,
        }
    return {
        "libvirt_query_available": True,
        "all_domains_shut_off": bool(all_off),
        "libvirt_inventory_stable": bool(stable),
        "defined_domain_count": len(raw_names) if inventory_valid else None,
        "no_vm_lifecycle_mutation": True,
        "expected_additional_vm_count": count,
        "all_expected_vms_present": all(n in names for n in expected),
        "actual_vm_names_matched": sorted(n for n in names
                                          if VM_PATTERN.fullmatch(n)),
        "expected_vm_details": details,
        "snapshot_names_do_not_prove_revert_safety": True,
    }


def snapshot_stack_status():
    """Inspect installed libvirt daemon/QEMU versions; never infer TPM safety."""
    raw = read_command("virsh", "-c", "qemu:///system",
                       "version", "--daemon")
    if raw is None:
        return {"version_evidence_available": False,
                "versions_meet_conservative_snapshot_lab_floor": False,
                "running_windows_tpm_restore_proven": False}
    try:
        parsed = snapshot_guard.parse_versions(raw)
    except (snapshot_guard.NativeBlocked, ValueError, TypeError):
        return {"version_evidence_available": False,
                "versions_meet_conservative_snapshot_lab_floor": False,
                "running_windows_tpm_restore_proven": False}
    return {"version_evidence_available": True, **parsed,
            "running_windows_tpm_restore_proven": False}


def os_status():
    result = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k in ("ID", "VERSION_ID", "PRETTY_NAME"):
                    result[k] = v.strip().strip('"')
    except OSError:
        pass
    return result


def storage_status(where):
    path = Path(where)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        return {"path": str(path), "available": False}
    try:
        stat = os.statvfs(path)
        return {
            "path": str(path), "available": True,
            "free_gib": round(stat.f_bavail * stat.f_frsize / 1024**3, 2),
        }
    except OSError:
        return {"path": str(path), "available": False}


def inventory(host, count, storage):
    name = check_host(host)
    need(type(count) is int and 0 <= count <= 16,
         "Count must be 0..16 additional VMs")
    binaries = {binary: shutil.which(binary) is not None for
                binary in BINARIES}
    packages = package_status()
    services = service_status()
    vm = vm_status(count)
    snapshot_stack = snapshot_stack_status()
    tmpfs = read_command("findmnt", "--mountpoint", "/mnt/tmpfs",
                         "-n", "-o", "FSTYPE")
    configs = {
        name: (CONF / name).is_file() and not (CONF / name).is_symlink()
        for name in NAMES}
    blockers = []
    osinfo = os_status()
    if osinfo.get("ID") != "ubuntu" or osinfo.get("VERSION_ID") not in (
            "24.04", "26.04"):
        blockers.append("TARGET_OS_NOT_IN_APPROVED_UBUNTU_FAMILIES")
    if not snapshot_stack["versions_meet_conservative_snapshot_lab_floor"]:
        blockers.append("NATIVE_RUNNING_SNAPSHOT_STACK_NOT_ADMITTED")
    if not vm.get("libvirt_inventory_stable"):
        blockers.append("LIBVIRT_DOMAIN_INVENTORY_UNVERIFIED_OR_CHANGED")
    if not vm.get("all_domains_shut_off"):
        blockers.append("LIBVIRT_DOMAIN_LIVE_OR_STATE_UNKNOWN")
    if not Path("/dev/kvm").exists():
        blockers.append("KVM_DEVICE_MISSING")
    if not binaries["virsh"]:
        blockers.append("LIBVIRT_COMMAND_MISSING")
    if not packages.get("postgresql"):
        blockers.append("POSTGRESQL_NOT_INSTALLED")
    if tmpfs != "tmpfs":
        blockers.append("CAPE_TMPFS_NOT_MOUNTED")
    if not all(configs.values()):
        blockers.append("CAPE_CONFIGURATION_INCOMPLETE")
    if not vm.get("all_expected_vms_present"):
        blockers.append("EXPECTED_WINDOWS_DOMAINS_MISSING")
    if not all(isinstance(item, dict) and
               item.get("loaded") and item.get("active")
               for item in services.values()):
        blockers.append("CAPE_FIVE_SERVICE_HEALTH_UNPROVEN")
    return {
        "result": "CAPE_NEW_HOST_READ_ONLY_REPAIR_DOCTOR",
        "hostname": name, "requested_additional_clones": count,
        "operating_system": osinfo,
        "binaries": binaries, "apt_package_presence": packages,
        "libvirt": vm, "snapshot_stack": snapshot_stack,
        "service_status": services,
        "cape_config_present": configs,
        "tmpfs_mounted": tmpfs == "tmpfs",
        "guest_storage": storage_status(storage),
        "blockers": blockers,
        "INetSim_deferred_by_operator": True,
        "no_guest_started_reverted_or_changed": True,
        "no_package_service_network_or_secret_changed": True,
        "rollback_and_repair_require_proven_per_resource_history": True,
        "TPM_snapshot_two_cycle_recovery_proven": False,
        "running_snapshot_not_accepted_from_versions_or_names": True,
        "release_cleared_for_live_malware": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--approved-host", required=True)
    p.add_argument("--additional-count", type=int, default=0)
    p.add_argument("--storage-dir", type=Path,
                   default=Path("/var/lib/libvirt/images"))
    args = p.parse_args()
    try:
        print(json.dumps(inventory(args.approved_host, args.additional_count,
                                   args.storage_dir), sort_keys=True, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "result": "CAPE_REPAIR_DOCTOR_BLOCKED",
            "error_type": type(exc).__name__,
            "VMs_or_host_modified": False,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
