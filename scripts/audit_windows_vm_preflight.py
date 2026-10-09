#!/usr/bin/env python3
"""Read-only first-Windows-guest preflight, before creating a CAPEv2 VM.

Never starts guests, provisions TPMs, changes ISO/home permissions or alters
libvirt networks. The private JSON report does not include host IPs, passwords,
libvirt network XML, machine serials or guest files. No sample execution.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any
import xml.etree.ElementTree as ET

URI = "qemu:///system"


def cmd(argv: list[str], timeout: int = 12) -> tuple[int, str]:
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=False)
        return done.returncode, done.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""


def forwarding_mode(xml: str) -> str:
    try:
        root = ET.fromstring(xml)
        if root.tag != "network":
            return "unknown"
        forward = root.find("forward")
        return "none" if forward is None else forward.attrib.get("mode", "unspecified")
    except ET.ParseError:
        return "unknown"


def readable_directories(path: Path) -> list[dict[str, Any]]:
    """Observe parent traversal modes; don't presume the QEMU service UID."""
    results = []
    current = path.parent
    parents = []
    while True:
        parents.append(current)
        if current == current.parent:
            break
        current = current.parent
    for parent in reversed(parents):
        try:
            info = parent.stat()
            results.append({"component": "home" if parent == Path.home() else "other",
                            "path_present": True,
                            "traverse_others": bool(info.st_mode & stat.S_IXOTH),
                            "traverse_group": bool(info.st_mode & stat.S_IXGRP)})
        except OSError:
            results.append({"component": "unknown", "path_present": False})
    return results


def get_preflight(iso: Path | None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": "CAPEv2 first Windows guest, read-only host preflight",
        "changes_made": False,
        "guest_created": False,
        "isolation_verified": False,
        "ready_for_live_malware": False,
        "checks": {},
    }
    checks = out["checks"]
    count = os.cpu_count()
    checks["logical_cpus"] = count if count is not None else "unknown"

    try:
        rows = Path("/proc/meminfo").read_text().splitlines()
        mem = {}
        for line in rows:
            match = re.match(r"^(MemTotal|MemAvailable):\s+(\d+) kB", line)
            if match:
                mem[match.group(1)] = int(match.group(2)) * 1024
        checks["ram_gib"] = round(mem.get("MemTotal", 0) / (1024 ** 3), 2)
        checks["available_ram_gib"] = round(mem.get("MemAvailable", 0) / (1024 ** 3), 2)
    except OSError:
        checks["ram_gib"] = "unknown"
        checks["available_ram_gib"] = "unknown"

    try:
        storage = shutil.disk_usage("/var/lib/libvirt/images")
        checks["libvirt_images_free_gib"] = round(storage.free / (1024 ** 3), 2)
    except OSError:
        checks["libvirt_images_free_gib"] = "unknown"

    names = ("virsh", "virt-install", "virt-manager", "qemu-system-x86_64",
             "qemu-img", "swtpm", "swtpm_setup")
    checks["tools_available"] = {name: shutil.which(name) is not None for name in names}
    for folder in ("/usr/share/OVMF", "/usr/share/edk2/ovmf"):
        if Path(folder).is_dir():
            checks["uefi_ovmf_firmware_present"] = True
            break
    else:
        checks["uefi_ovmf_firmware_present"] = False

    rc, version = cmd(["virsh", "-c", URI, "version"])
    checks["libvirt_system_connection"] = rc == 0
    checks["libvirt_qemu_version_detected"] = bool(re.search(r"Running hypervisor:\s*QEMU", version)) if rc == 0 else False

    rc, names_raw = cmd(["virsh", "-c", URI, "list", "--all", "--name"])
    checks["defined_vm_count"] = len([x for x in names_raw.splitlines() if x.strip()]) if rc == 0 else "unknown"
    checks["cuckoo1_defined"] = "cuckoo1" in names_raw.splitlines() if rc == 0 else "unknown"

    rc, network_xml = cmd(["virsh", "-c", URI, "net-dumpxml", "default"])
    checks["default_libvirt_forward_mode"] = forwarding_mode(network_xml) if rc == 0 else "unknown"
    checks["default_network_safe_for_malware"] = False  # must validate host + guest, IPv4 and IPv6

    rc, active = cmd(["systemctl", "is-active", "virtqemud.service"])
    checks["virtqemud_running"] = active == "active" if rc == 0 else False

    if iso is not None:
        iso = iso.expanduser()
        try:
            info = iso.stat()
            checks["iso_exists_regular"] = stat.S_ISREG(info.st_mode) and info.st_size > 0
            checks["iso_size_bytes"] = info.st_size
            checks["iso_parent_access_review"] = not all(
                item["traverse_others"] for item in readable_directories(iso)
                if item["path_present"]
            )
            checks["iso_access_by_qemu_identity_tested"] = False
            checks["iso_sha256_microsoft_verified_in_this_run"] = False
        except OSError:
            checks["iso_exists_regular"] = False
            checks["iso_access_by_qemu_identity_tested"] = False
        # ISO provenance must be verified separately via inspect_windows_media.py.
    blockers = []
    if not checks["tools_available"]["swtpm"]:
        blockers.append("swtpm missing: install distro swtpm + swtpm-tools before attaching emulated TPM 2.0")
    if not checks["tools_available"]["swtpm_setup"]:
        blockers.append("swtpm_setup missing: software TPM state initialization tools not verified")
    if not checks["libvirt_system_connection"]:
        blockers.append("libvirt system connection unavailable")
    if checks["default_libvirt_forward_mode"] in ("nat", "route", "open"):
        blockers.append("default network forwards traffic; do not attach malware guest")
    elif checks["default_libvirt_forward_mode"] in ("unknown", "unspecified"):
        blockers.append("default network forwarding cannot be determined")
    if iso is not None and checks.get("iso_access_by_qemu_identity_tested") is False:
        blockers.append("ISO access by the actual QEMU service account not yet verified")
    out["provisioning_review_items"] = blockers
    out["result"] = "PREFLIGHT_REVIEW_REQUIRED" if blockers else "BASIC_PREFLIGHT_ONLY"
    out["next"] = "Review VM sizing, firmware/TPM, ISO access and dedicated non-NAT isolated network; no live malware."
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, help="Downloaded ISO path; no file reading or hashing")
    parser.add_argument("--report", type=Path, help="NEW private JSON path; no overwrite")
    args = parser.parse_args()
    out = args.report.expanduser().absolute() if args.report else (
        Path.home() / ("SSL_VM_Preflight_" + str(os.getpid()) + ".json"))
    if out.is_symlink() or out.exists():
        parser.error("Refusing to overwrite an existing or symlink report")
    result = get_preflight(args.iso)
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        json.dump(result, fp, indent=2, sort_keys=True)
        fp.write("\n")
    print("Private read-only report:", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
