#!/usr/bin/env python3
"""Read-only Commands 1–2 host acceptance evidence.

No package install, reboot, VM lifecycle/snapshot action, guest writes,
network mutation, QEMU image conversion, or CAPE service restart.
Writes one private JSON-in-TXT report with masked sensitive fields.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import audit_clone_master
import command1_master_checkpoint

PROBES = {
    "python3": ["python3", "--version"],
    "virsh": ["virsh", "--version"],
    "qemu-img": ["qemu-img", "--version"],
    "virt-win-reg": ["virt-win-reg", "--version"],
    "swtpm": ["swtpm", "--version"],
    "apparmor_parser": ["apparmor_parser", "--version"],
    "virt-install": ["virt-install", "--version"],
    "virt-manager": ["virt-manager", "--version"],
    "kvm-ok": None,
    "curl": ["curl", "--version"],
    "ping": None,
    "ip": ["ip", "-V"],
}


def read_value(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()[:300]
    except OSError:
        return None


def probe_version(name: str, command: list[str] | None) -> dict:
    binary = shutil.which(name)
    result = {"installed": bool(binary), "path": binary, "version": None}
    if binary is None or command is None:
        return result
    try:
        run = subprocess.run(command, capture_output=True, text=True,
                             timeout=8, check=False)
        version = (run.stdout or run.stderr).splitlines()
        if run.returncode == 0 and version:
            # Keep only first line, never arbitrary tool stderr dumps.
            result["version"] = version[0][:180]
        else:
            result["version"] = "VERSION_CHECK_FAILED"
    except (OSError, subprocess.TimeoutExpired):
        result["version"] = "VERSION_CHECK_FAILED"
    return result


def collect(vm: str) -> dict:
    guest = audit_clone_master.collect(vm)
    checkpoint = command1_master_checkpoint.validate_master(guest)
    result: dict = {
        "schema": "cape-command12-acceptance-report-v1",
        "collected_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "READ_ONLY",
        "master": vm,
        "host": guest.get("host"),
        "vm": guest.get("vm"),
        "snapshots": guest.get("snapshots"),
        "storage": guest.get("storage"),
        "networks": guest.get("networks"),
        "cape": guest.get("cape"),
        "inventory_warnings": guest.get("warnings"),
        "master_checkpoint": checkpoint,
        "dependencies": {
            name: probe_version(name, command)
            for name, command in PROBES.items()
        },
        "host_network_control": {
            "ipv4_forwarding_enabled":
                read_value("/proc/sys/net/ipv4/ip_forward"),
            "ipv6_forwarding_enabled":
                read_value("/proc/sys/net/ipv6/conf/all/forwarding"),
            "apparmor_enabled":
                read_value("/sys/module/apparmor/parameters/enabled"),
        },
        "scope": "Ubuntu host and libvirt read-only queries; does not inspect Windows application install state",
        "deployment_approved": False,
    }
    try:
        result["libvirt_network_names"] = audit_clone_master.virsh(
            "net-list", "--all", "--name")
    except Exception:
        result["libvirt_network_names"] = "UNKNOWN"
    # Use just sanitized stdout for network enumeration.
    if isinstance(result["libvirt_network_names"], dict):
        record = result["libvirt_network_names"]
        result["libvirt_network_names"] = (
            record["stdout"].splitlines()[:60] if record.get("ok") else [])
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="win11")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not args.vm or not audit_clone_master.VM_RE.fullmatch(args.vm):
            raise ValueError("Invalid master domain name")
        result = collect(args.vm)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.output, os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                     getattr(os,"O_NOFOLLOW",0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result,out,indent=2,sort_keys=True)
            out.write("\n")
        print("Read-only report:",args.output)
        print("Master snapshot structure:",
              result["master_checkpoint"]["stage1_snapshot_structure"])
        print("Missing tools:",
              ", ".join(n for n, x in result["dependencies"].items()
                        if not x["installed"]) or "none")
        print("No guest, snapshot, software or host configuration changed.")
        return 0 if result["master_checkpoint"]["stage1_snapshot_structure"]=="PASS" else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("BLOCKED:",exc,file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
