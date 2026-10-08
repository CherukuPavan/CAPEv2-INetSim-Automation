#!/usr/bin/env python3
"""Static, read-only risk audit of local CAPEv2 upstream installer scripts.

NO invocation of kvm-qemu.sh (not even --help), cape2.sh, root commands, pip,
apt, git, network, or service modifications. Known side-effect patterns from
SSL-55 manual installation are reported without dumping credentials or config.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

RULES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "kvm": (
        ("sleep-target masks", r"systemctl\s+mask\s+sleep\.target", "BLOCK"),
        ("KVM blacklist edits", r"blacklist\s+kvm|blacklist-kvm\.conf", "REVIEW"),
        ("possible package purge/holds", r"(?i)apt(?:-get)?\s+[^\n]*(?:purge|hold)|apt-mark\s+hold", "BLOCK"),
        ("firmware overwrite", r"(?i)force-overwrite|dpkg\s+[^\n]*--force", "BLOCK"),
        ("host GRUB changes", r"(?i)(update-grub|/etc/default/grub)", "REVIEW"),
        ("host sysctl changes", r"(?i)(sysctl\s+-w|/etc/sysctl\.conf|tcp_syncookies)", "REVIEW"),
        ("host modprobe changes", r"/etc/modprobe\.d", "REVIEW"),
        ("non-portable ACPI placeholder", r"<WOOT>", "REVIEW"),
        ("host reboot", r"(?m)^[^#\n]*\b(?:reboot|shutdown\s+-r)\b", "BLOCK"),
    ),
    "cape": (
        ("timezone changes", r"timedatectl\s+set-timezone", "BLOCK"),
        ("hard-coded password assignment", r"(?m)^[ \t]*(?:PASSWD|PASSWORD)=", "BLOCK"),
        ("external APT sources", r"(?i)(/etc/apt/sources\.list\.d|repo\.mongodb\.org)", "REVIEW"),
        ("disabled AppArmor confinement", r"\baa-disable\b|\baa-complain\b", "BLOCK"),
        ("sudoers modifications", r"/etc/sudoers\.d", "REVIEW"),
        ("privileged cron modifications", r"\bcrontab\s+-", "REVIEW"),
        ("direct network route changes", r"/etc/iproute2/rt_tables|ip\s+route\s+add", "BLOCK"),
        ("service restarts", r"\bsystemctl\s+restart\b", "REVIEW"),
        ("shell glob env-copy", r"conf/default/\*\.env", "REVIEW"),
        ("global pip installation", r"(?i)\bpip3?\s+install\b", "REVIEW"),
        ("CAPE libvirt install stage", r"\binstall_libvirt\b", "REVIEW"),
    ),
}


def audit_text(content: str, kind: str) -> dict[str, object]:
    result: list[dict[str, object]] = []
    for label, regex, severity in RULES[kind]:
        occurrences = len(re.findall(regex, content))
        result.append({"risk": label, "severity": severity,
                       "occurrences": occurrences, "found": occurrences > 0})
    return {"kind": kind, "rules": result,
            "blocking_patterns": sum(r["severity"] == "BLOCK" and r["found"] for r in result)}


def read_script(path: Path, kind: str) -> dict[str, object]:
    content = path.read_text(encoding="utf-8", errors="replace")
    report = audit_text(content, kind)
    report.update({"script_name": path.name,
                   "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                   "size_bytes": path.stat().st_size})
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kvm", type=Path, help="Local, unexecuted kvm-qemu.sh path")
    p.add_argument("--cape", type=Path, help="Local, unexecuted cape2.sh path")
    p.add_argument("--report", type=Path, required=True, help="New private JSON report path")
    args = p.parse_args()
    if not args.kvm and not args.cape:
        p.error("Supply at least one local script")
    output = {"mode": "STATIC_ONLY", "execution_authorized": False,
              "safe_to_auto_run_upstream": False, "scripts": []}
    for kind in ("kvm", "cape"):
        path = getattr(args, kind)
        if path is None:
            continue
        if not path.is_file() or path.is_symlink():
            p.error("Script missing or symlink: " + kind)
        output["scripts"].append(read_script(path, kind))
    outpath = args.report.expanduser().absolute()
    if outpath.is_symlink() or outpath.exists():
        p.error("Refusing output overwrite or symlink")
    outpath.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(outpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        json.dump(output, fp, indent=2, sort_keys=True)
        fp.write("\n")
    print("Static-only report:", outpath)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
