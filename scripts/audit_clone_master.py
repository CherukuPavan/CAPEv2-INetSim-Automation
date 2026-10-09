#!/usr/bin/env python3
"""Read-only, evidence-driven inventory of a CAPE Windows master libvirt VM.

No VM lifecycle actions, no disk writes, no snapshot restore, no guest commands
that modify state. Produces one private JSON-formatted TXT report.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

LIMIT = 40
VM_RE = re.compile(r"[a-zA-Z0-9_.-]{1,100}\Z")
SENSITIVE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[^\s]+")
EXIT_CODES = {0: "ok", 1: "error", 2: "unexpected"}


def run(*argv: str, timeout: int = 18) -> dict:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, check=False)
        return {
            "ok": p.returncode == 0,
            "stdout": p.stdout[:32000],
            "error": SENSITIVE.sub(r"\1=[redacted]", p.stderr[:1200]),
            "exit_code": p.returncode,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "stdout": "", "error": str(exc)[:1000], "exit_code": None}


def virsh(*args: str, timeout: int = 18) -> dict:
    return run("sudo", "-n", "virsh", "-c", "qemu:///system", *args, timeout=timeout)


def single(command: dict) -> str | None:
    return command["stdout"].strip() if command["ok"] else None


def checked_xml(command: dict, label: str, warnings: list[str]) -> ET.Element | None:
    if not command["ok"]:
        warnings.append(f"{label} unavailable: {command['error'] or 'command returned nonzero'}")
        return None
    try:
        return ET.fromstring(command["stdout"])
    except ET.ParseError:
        warnings.append(f"{label} returned invalid XML")
        return None


def domain_summary(root: ET.Element) -> dict:
    result: dict = {
        "name": root.findtext("./name"),
        "uuid": root.findtext("./uuid"),
        "domain_type": root.get("type"),
        "machine_type": (root.find("./os/type").get("machine")
                         if root.find("./os/type") is not None else None),
        "memory_kib": None,
        "vcpus": None,
        "disks": [],
        "interfaces": [],
        "tpm": [],
        "nvram_present": root.find("./os/nvram") is not None,
        "qemu_guest_agent_channel_configured": False,
    }
    memory = root.find("./memory")
    if memory is not None:
        raw = memory.text
        unit = (memory.get("unit") or "KiB").lower()
        factors = {"kib": 1, "mib": 1024, "gib": 1048576, "kb": 1000 / 1024,
                   "mb": 1000000 / 1024, "gb": 1000000000 / 1024, "b": 1 / 1024}
        if raw and unit in factors:
            try:
                result["memory_kib"] = int(int(raw.strip()) * factors[unit])
            except ValueError:
                pass
    cpu = root.findtext("./vcpu")
    result["vcpus"] = int(cpu) if cpu and cpu.isdigit() else None
    for disk in root.findall("./devices/disk"):
        source = disk.find("source")
        target = disk.find("target")
        driver = disk.find("driver")
        result["disks"].append({
            "device": disk.get("device"),
            "type": disk.get("type"),
            "target": target.get("dev") if target is not None else None,
            "source_file": source.get("file") if source is not None else None,
            "source_dev": source.get("dev") if source is not None else None,
            "format": driver.get("type") if driver is not None else None,
            "readonly": disk.find("readonly") is not None,
        })
    for nic in root.findall("./devices/interface"):
        source, mac, model = (nic.find("source"), nic.find("mac"), nic.find("model"))
        result["interfaces"].append({
            "type": nic.get("type"),
            "network": source.get("network") if source is not None else None,
            "bridge": source.get("bridge") if source is not None else None,
            "mac": mac.get("address") if mac is not None else None,
            "model": model.get("type") if model is not None else None,
        })
    for tpm in root.findall("./devices/tpm"):
        backend = tpm.find("backend")
        result["tpm"].append({"model": tpm.get("model"),
                              "backend": backend.get("type") if backend is not None else None})
    for ch in root.findall("./devices/channel"):
        tgt = ch.find("target")
        if tgt is not None and tgt.get("name") == "org.qemu.guest_agent.0":
            result["qemu_guest_agent_channel_configured"] = True
    return result


def snapshot_summary(root: ET.Element) -> dict:
    result: dict = {
        "name": root.findtext("./name"),
        "parent": root.findtext("./parent/name"),
        "state": root.findtext("./state"),
        "creation_time": root.findtext("./creationTime"),
        "memory": None,
        "disks": [],
    }
    mem = root.find("./memory")
    if mem is not None:
        result["memory"] = {"snapshot": mem.get("snapshot"),
                            "file": mem.get("file")}
    for disk in root.findall("./disks/disk"):
        src = disk.find("source")
        result["disks"].append({
            "name": disk.get("name"),
            "snapshot": disk.get("snapshot"),
            "source": src.get("file") if src is not None else None,
        })
    return result


def network_summary(root: ET.Element) -> dict:
    forward = root.find("./forward")
    bridge = root.find("./bridge")
    return {
        "name": root.findtext("./name"),
        "uuid": root.findtext("./uuid"),
        "forward_mode": forward.get("mode") if forward is not None else None,
        "bridge": bridge.get("name") if bridge is not None else None,
        "ip4_subnets": [
            {"address": a.get("address"), "netmask": a.get("netmask"),
             "prefix": a.get("prefix")}
            for a in root.findall("./ip") if a.get("family", "ipv4") == "ipv4"
        ],
    }


def file_metadata(name: str) -> dict:
    p = Path(name)
    info: dict = {"path": name, "exists": False}
    try:
        s = p.lstat()
        info.update({"exists": True, "symlink": stat.S_ISLNK(s.st_mode),
                     "regular_file": stat.S_ISREG(s.st_mode), "bytes": s.st_size,
                     "mode": oct(stat.S_IMODE(s.st_mode)),
                     "uid": s.st_uid, "gid": s.st_gid})
    except OSError as exc:
        info["note"] = str(exc)
    return info


def collect(vm: str) -> dict:
    if not VM_RE.fullmatch(vm):
        raise ValueError("Unsafe VM name; use letters, digits, dot, hyphen, underscore")
    warnings: list[str] = []
    result: dict = {
        "schema": "cape-master-vm-inventory-v1",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": {"hostname": socket.gethostname(),
                 "kernel": os.uname().release,
                 "os_release": {}, "tools": {},
                 "kvm_device": Path("/dev/kvm").exists()},
        "vm": {"requested": vm}, "snapshots": {},
        "storage": {}, "networks": [], "cape": {},
        "warnings": warnings, "classification": "READ_ONLY_EVIDENCE_NOT_DEPLOYMENT_APPROVAL",
    }
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith(("ID=", "VERSION_ID=", "PRETTY_NAME=")):
                k, v = line.split("=", 1)
                result["host"]["os_release"][k] = v.strip('"')
    except OSError:
        warnings.append("OS release could not be read")
    for tool in ("sudo", "virsh", "qemu-img", "python3", "apparmor_parser",
                 "virt-clone", "virt-sysprep", "guestfish"):
        result["host"]["tools"][tool] = shutil.which(tool)
    try:
        text = Path("/proc/meminfo").read_text()
        for key in ("MemTotal", "MemAvailable"):
            found = re.search(rf"^{key}:\s+(\d+)\s+kB", text, re.M)
            result["host"][key + "_kib"] = int(found.group(1)) if found else None
    except OSError:
        warnings.append("Could not read host memory information")
    sudo = run("sudo", "-n", "true", timeout=5)
    if not sudo["ok"]:
        warnings.append("Noninteractive sudo unavailable: run 'sudo -v' beforehand")
        return result
    state = virsh("domstate", vm)
    state_text = single(state)
    result["vm"]["state"] = state_text
    if state_text is None:
        warnings.append(f"Cannot inspect VM state: {state['error']}")
        return result
    xml = checked_xml(virsh("dumpxml", "--inactive", vm), "inactive VM definition", warnings)
    if xml is None:
        return result
    summary = domain_summary(xml)
    result["vm"].update(summary)
    if summary["name"] != vm:
        warnings.append("VM XML name does not match requested VM")
    result["vm"]["current_snapshot"] = single(virsh("snapshot-current", vm, "--name"))
    snapnames = virsh("snapshot-list", vm, "--name")
    rows: list[dict] = []
    if snapnames["ok"]:
        names = [name for name in snapnames["stdout"].splitlines() if name.strip()]
        if len(names) > LIMIT:
            warnings.append(f"Snapshot count exceeds reporting limit {LIMIT}")
        for name in names[:LIMIT]:
            item = checked_xml(virsh("snapshot-dumpxml", vm, name),
                               "snapshot metadata", warnings)
            if item is not None:
                rows.append(snapshot_summary(item))
    else:
        warnings.append("Cannot list VM snapshots")
    result["snapshots"] = {"count_reported": len(rows), "items": rows}
    if not rows:
        warnings.append("No snapshot metadata found; cloning source not established")
    if state_text.lower() not in ("shut off", "shutoff"):
        warnings.append("VM is running: qemu-img inspection skipped to avoid live-image locking")
    for disk in summary["disks"]:
        if disk.get("device") == "disk" and disk.get("source_file"):
            path = disk["source_file"]
            result["storage"][path] = file_metadata(path)
            try:
                info = os.statvfs(str(Path(path).parent))
                result["storage"][path]["filesystem_available_bytes"] = info.f_bavail * info.f_frsize
            except OSError:
                pass
            if state_text.lower() in ("shut off", "shutoff") and shutil.which("qemu-img"):
                chain = run("sudo", "-n", "qemu-img", "info", "--output=json",
                            "--backing-chain", path, timeout=30)
                if chain["ok"]:
                    try:
                        raw = json.loads(chain["stdout"])
                        result["storage"][path]["backing_chain"] = [
                            {"filename": a.get("filename"), "format": a.get("format"),
                             "backing_filename": a.get("full-backing-filename") or a.get("backing-filename"),
                             "virtual_size": a.get("virtual-size"),
                             "actual_size": a.get("actual-size"),
                             "corrupt_flag": a.get("format-specific", {}).get("data", {}).get("corrupt")}
                            for a in raw if isinstance(a, dict)
                        ]
                    except (ValueError, TypeError):
                        warnings.append("qemu-img returned invalid backing-chain JSON")
                else:
                    warnings.append("qemu-img cannot inspect shut-off backing chain (possibly locked by other guests)")
    for nic in summary["interfaces"]:
        if nic["type"] == "network" and nic["network"]:
            net = checked_xml(virsh("net-dumpxml", nic["network"]),
                              f"libvirt network {nic['network']}", warnings)
            if net is not None:
                n = network_summary(net)
                if n not in result["networks"]:
                    result["networks"].append(n)
                if n["forward_mode"] in ("nat", "route", "open"):
                    warnings.append(f"Network {n['name']} has forwarding mode {n['forward_mode']}; do NOT infer malware containment")
        elif nic["type"] in ("bridge", "direct"):
            warnings.append("Master VM uses bridge/direct networking; isolation requires independent verification")
    if state_text.lower() == "running":
        address = virsh("domifaddr", vm, "--source", "agent", timeout=8)
        result["vm"]["guest_agent_ip_observation"] = {
            "available": address["ok"],
            "summary": address["stdout"][:1500] if address["ok"] else "not available",
        }
        if not address["ok"]:
            warnings.append("QEMU guest agent IP observation unavailable; guest IP must be verified separately")
    for name in ("/etc/libvirt/qemu.conf",
                 "/etc/apparmor.d/abstractions/libvirt-qemu"):
        result["host"].setdefault("policy_files", []).append(file_metadata(name))
    result["cape"] = {
        "machine_registration": "NOT_VERIFIED_FROM_LIBVIRT_INVENTORY",
        "agent": "NOT_VERIFIED_FROM_LIBVIRT_INVENTORY",
        "static_ip_in_windows": "NOT_VERIFIED_UNLESS_GUEST_AGENT_REPORTS_IP",
        "shutdown_backup_consistency": "REQUIRES_CONFIRMATION",
    }
    if result["vm"]["current_snapshot"] is None:
        warnings.append("No current libvirt snapshot was reported")
    warnings.append("Running snapshots may contain VM memory and are not automatically portable clone templates")
    warnings.append("Snapshot names/states do not prove the shutdown backup is a full standalone image")
    warnings.append("CAPE configuration, unique guest IP/hostname, TPM state, isolation and rollback remain acceptance gates")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", default="win11")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        data = collect(args.vm)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.report, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as fp:
            json.dump(data, fp, indent=2, sort_keys=True)
            fp.write("\n")
        print(f"REPORT: {args.report}")
        print(f"VM: {args.vm}; state: {data['vm'].get('state', 'unknown')}; snapshot metadata: {data['snapshots'].get('count_reported',0)}")
        print(f"Warnings: {len(data['warnings'])}; no VM/guest configuration was changed")
        if data["vm"].get("state") is None or data["vm"].get("uuid") is None:
            print("INCOMPLETE: review report and privilege requirements", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
