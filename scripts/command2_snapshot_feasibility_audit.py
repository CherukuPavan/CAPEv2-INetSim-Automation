#!/usr/bin/env python3
"""SSL-55 Command 2A snapshot feasibility audit; zero host/guest mutations.

Read-only inventory for the already booted, networkless win11_1 guest:
exact domain state/config, libvirt snapshot metadata, clone-only swtpm
state-file *metadata* (never data), UEFI, host versions and storage budget.
NOT a snapshot operation or permission to roll back any disk.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

NAME = "win11_1"
UUID = "732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER = ("win11", "289d89be-68ec-4c62-90e1-ea930849266f", "shut off")
TRIAL = ("win11_trial_1", "e75f6fef-347d-462f-9738-4de3df6bfa74", "running")
DISK = Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
NVRAM = Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TPMROOT = Path("/var/lib/libvirt/swtpm")
TPMDIR = TPMROOT / UUID / "tpm2"
NETWORK = "cape-analysis-isolated"
GiB = 1024 ** 3
# Conservative bounded estimate; NOT approval to allocate a snapshot/clone.
VIRTUAL_GIB = 64
RESERVE_GIB = 30

class AuditBlocked(RuntimeError):
    pass

def need(ok, message):
    if not ok:
        raise AuditBlocked(message)

def cmd(*argv):
    try:
        proc = subprocess.run(argv, text=True, capture_output=True, timeout=90,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditBlocked("Host command unavailable: " + argv[0]) from exc
    need(proc.returncode == 0, "Command failed: " + " ".join(argv[:2]) +
         " (exit " + str(proc.returncode) + ")")
    return proc.stdout.strip()

def virsh(*args):
    return cmd("virsh", "-c", "qemu:///system", *args)

def identity(name, uuid, state):
    need(virsh("domuuid", name).lower() == uuid, "Unexpected UUID: " + name)
    need(virsh("domstate", name).lower() == state, "Unexpected state: " + name)

def check_xml(xml, live):
    root = ET.fromstring(xml)
    need(root.findtext("name") == NAME and root.findtext("uuid") == UUID,
         "Unexpected clone name or UUID")
    disks = root.findall("./devices/disk[@device='disk']")
    need(len(disks) == 1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file") == str(DISK),
         "Unexpected clone disk")
    need(root.findtext("./os/nvram") == str(NVRAM),
         "Unexpected clone firmware vars")
    tpm = root.findall("./devices/tpm")
    need(len(tpm) == 1 and tpm[0].find("backend") is not None and
         tpm[0].find("backend").get("type") == "emulator" and
         tpm[0].find("backend").get("version") == "2.0",
         "Unexpected TPM backend")
    for tag in ("interface", "hostdev", "filesystem", "channel", "redirdev",
                "smartcard", "shmem", "vsock"):
        need(not root.findall("./devices/" + tag), "Unexpected device: " + tag)
    # No port, disk or TPM secrets included in report.
    return {"name": NAME, "identity": "EXACT", "zero_nics": True,
            "disk": DISK.name, "nvram": NVRAM.name,
            "tpm": "emulator-2.0", "view": "live" if live else "inactive"}

def metadata(path):
    need(not path.is_symlink() and path.is_file(), "Missing or symlinked artifact: " + path.name)
    info = path.stat()
    need(stat.S_ISREG(info.st_mode), "Not a regular file: " + path.name)
    return {"file": path.name, "bytes": info.st_size,
            "allocated_bytes_approx": info.st_blocks * 512,
            "owner_uid": info.st_uid, "group_gid": info.st_gid,
            "mode": format(stat.S_IMODE(info.st_mode), "04o")}

def inspect_tpm():
    # NEVER read TPM secrets; inventory only exact clone-UUID subtree.
    need(TPMROOT.is_dir() and not TPMROOT.is_symlink(),
         "Unexpected libvirt swtpm root")
    parent = TPMROOT / UUID
    need(parent.is_dir() and not parent.is_symlink(),
         "Clone-specific swtpm UUID directory missing")
    need(TPMDIR.is_dir() and not TPMDIR.is_symlink(),
         "Clone-specific swtpm/tpm2 directory missing")
    records = []
    for item in sorted(TPMDIR.iterdir(), key=lambda p: p.name):
        need(not item.is_symlink(), "Symlink in clone swtpm state")
        if item.is_file():
            records.append(metadata(item))
        elif item.is_dir():
            raise AuditBlocked("Unexpected nested swtpm state directory")
        else:
            raise AuditBlocked("Unexpected swtpm state file type")
    need(any(row["file"].endswith(".permall") for row in records),
         "No TPM2 permanent state file found")
    return {"directory": str(TPMDIR), "files_metadata_only": records,
            "contents_read": False, "guest_tpm_restore_tested": False}

def storage():
    fs = os.statvfs(str(DISK.parent))
    free = fs.f_bavail * fs.f_frsize
    conservative = (VIRTUAL_GIB + RESERVE_GIB) * GiB
    return {"free_bytes": free,
            "free_gib_approx": round(free / GiB, 2),
            "disk_virtual_gib_assumed_from_prior_evidence": VIRTUAL_GIB,
            "conservative_cold_copy_and_reserve_gib": VIRTUAL_GIB + RESERVE_GIB,
            "conservative_capacity_pass_at_audit": free >= conservative,
            "snapshot_or_copy_authorized": False,
            "more_clones_authorized": False}

def first_line(value):
    lines = [line for line in value.splitlines() if line.strip()]
    return lines[0] if lines else "VERSION_OUTPUT_NOT_CAPTURED"

def perform():
    need(os.geteuid() == 0, "Run with sudo/root")
    identity(NAME, UUID, "running")
    identity(*MASTER)
    identity(*TRIAL)
    net = virsh("net-info", NETWORK)
    need(re.search(r"^Active:\s+no\s*$", net, re.M | re.I) and
         re.search(r"^Autostart:\s+no\s*$", net, re.M | re.I),
         "Analysis network unexpectedly enabled")
    clone = [check_xml(virsh("dumpxml", NAME), True),
             check_xml(virsh("dumpxml", "--inactive", NAME), False)]
    trial = ET.fromstring(virsh("dumpxml", TRIAL[0]))
    need(not trial.findall("./devices/interface"),
         "Proven trial guest has network adapters")
    snapshots = virsh("snapshot-list", NAME, "--name").splitlines()
    need(not any(x.strip() for x in snapshots),
         "Clone has unexpected existing snapshot metadata: manual review")
    need(DISK != NVRAM and DISK.exists() and NVRAM.exists(),
         "Clone files unavailable")
    data = {"result": "COMMAND2A_SNAPSHOT_FEASIBILITY_READ_ONLY",
            "original_master_preserved": True,
            "trial_unchanged_zero_nics": True,
            "analysis_network_inactive": True,
            "guest_nics": 0,
            "clone_domain_views": clone,
            "existing_libvirt_snapshots": snapshots,
            "qcow2_metadata_only": metadata(DISK),
            "uefi_vars_metadata_only": metadata(NVRAM),
            "clone_tpm": inspect_tpm(),
            "host_versions": {"virsh": virsh("version").splitlines()[:8],
                              "qemu_img": first_line(cmd("qemu-img", "--version")),
                              "swtpm": first_line(cmd("swtpm", "--version"))},
            "storage": storage(),
            "cold_consistent_copy_verified": False,
            "snapshot_revert_verified": False,
            "live_memory_swtpm_atomic_snapshot_verified": False,
            "no_changes_made": True}
    return data

if __name__ == "__main__":
    try:
        print(json.dumps(perform(), indent=2, sort_keys=True))
    except (AuditBlocked, ET.ParseError, OSError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
