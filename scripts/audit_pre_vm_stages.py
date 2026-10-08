#!/usr/bin/env python3
"""Read-only SSL-55-derived CAPEv2 stages 1-11 audit, portable across Ubuntu hosts.

No apt, pip, network or systemd modifications are performed. No credentials,
IP addresses, full journals or sensitive configuration content are collected.
The report is private by default (0600) and is NOT intended for Git commits.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

OPTIONAL_DISTRIBUTIONS = ("ImageHash", "deepdiff", "binGraph", "HTTPReplay", "Socks5man", "pyattck")
CAPE_SERVICES = ("cape.service", "cape-rooter.service", "cape-processor.service", "cape-web.service",
                 "mongodb.service", "mongod.service", "postgresql.service", "suricata.service")
RISKY_WORDS = re.compile(r"(?i)(token|password|passwd|secret|authorization|credential|private[ -]?key)")


def run(argv: list[str], *, timeout: int = 12) -> tuple[int, str]:
    """Shell-free invocation, bounded output. Callers must not print arbitrary output."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, check=False)
        return p.returncode, p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""


def first_line(text: str) -> str:
    return (text.splitlines() or [""])[0][:160]


def package_state(name: str) -> str:
    rc, out = run(["dpkg-query", "-W", "-f=${Status}", name])
    return "installed" if rc == 0 and out == "install ok installed" else "absent-or-incomplete"


def service_state(name: str) -> dict[str, str]:
    rc, out = run(["systemctl", "show", name, "--property=LoadState",
                   "--property=ActiveState", "--property=SubState",
                   "--property=UnitFileState", "--no-pager"])
    if rc != 0:
        return {"LoadState": "unknown", "ActiveState": "unknown"}
    result = {}
    for line in out.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def network_forward_mode(xml: str) -> str:
    """Absent <forward> means no libvirt forward, NOT proven host containment."""
    try:
        root = ET.fromstring(xml)
        fwd = root.find("forward")
        return "none" if fwd is None else (fwd.get("mode") or "unspecified")
    except ET.ParseError:
        return "invalid-xml"


def apt_release_mix() -> str:
    found: set[str] = set()
    paths = [Path("/etc/apt/sources.list")]
    folder = Path("/etc/apt/sources.list.d")
    if folder.is_dir():
        paths.extend(p for p in folder.iterdir() if p.is_file() and p.suffix in (".list", ".sources"))
    for path in paths:
        try:
            for line in path.read_text(errors="replace").splitlines():
                stripped = line.lstrip()
                if not stripped or stripped.startswith("#"):
                    continue
                for release in ("focal", "jammy", "noble"):
                    if re.search(r"(?<![a-z])" + release + r"(?![a-z])", stripped, re.I):
                        found.add(release)
        except (PermissionError, OSError):
            continue
    return ",".join(sorted(found)) if found else "unknown"


class Audit:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, step: str, check: str, status: str, detail: str) -> None:
        # All detail strings are generated from approved constants or sanitized metadata.
        if status not in ("PASS", "WARN", "BLOCKED", "UNKNOWN", "PENDING"):
            raise ValueError("Unexpected status")
        if RISKY_WORDS.search(detail):
            detail = "[redacted]"
        self.rows.append((step, check, status, detail))

    def collect(self) -> None:
        os_release = {}
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    os_release[k] = v.strip('"')
        except OSError:
            pass
        self.add("01", "Ubuntu OS", "PASS" if os_release.get("ID") == "ubuntu" else "BLOCKED",
                 "ID=" + os_release.get("ID", "unknown") + " VERSION_ID=" + os_release.get("VERSION_ID", "unknown"))
        rc, uname = run(["uname", "-m"])
        self.add("01", "Architecture", "PASS" if rc == 0 and uname == "x86_64" else "BLOCKED",
                 "x86_64" if uname == "x86_64" else "unsupported-or-unknown")
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text(errors="replace")
        except OSError:
            cpuinfo = ""
        flags = bool(re.search(r"\b(vmx|svm)\b", cpuinfo))
        self.add("01", "Virtualization CPU flag", "PASS" if flags else "BLOCKED", "vmx/svm available" if flags else "not exposed")
        rc, route = run(["ip", "-4", "route", "get", "1.1.1.1"])
        match = re.search(r"\bdev\s+([^\s]+)", route)
        self.add("01", "Uplink discovery", "PASS" if rc == 0 and match else "UNKNOWN",
                 "interface=" + match.group(1) if rc == 0 and match else "no unambiguous selected interface; not proof of Internet")
        self.add("02", "cpu-checker", "PASS" if package_state("cpu-checker") == "installed" else "PENDING",
                 "package " + package_state("cpu-checker"))
        self.add("03", "/dev/kvm", "PASS" if Path("/dev/kvm").exists() else "BLOCKED",
                 "device present" if Path("/dev/kvm").exists() else "device absent")
        if shutil.which("kvm-ok"):
            rc, output = run(["kvm-ok"])
            self.add("03", "KVM acceleration", "PASS" if rc == 0 else "BLOCKED",
                     "kvm-ok passed" if rc == 0 else "kvm-ok failed")
        else:
            self.add("03", "KVM acceleration", "UNKNOWN", "kvm-ok missing: provision cpu-checker separately")
        self.add("04", "Git", "PASS" if shutil.which("git") else "PENDING",
                 "executable exists" if shutil.which("git") else "requires bootstrap")

        candidates = (Path.home() / "CAPEv2", Path("/opt/CAPEv2"))
        for folder in candidates:
            if (folder / ".git").exists():
                rc, sha = run(["git", "-c", "safe.directory=" + str(folder),
                               "-C", str(folder), "rev-parse", "--verify", "HEAD"])
                self.add("04", "Git source " + ("home" if folder == candidates[0] else "opt"),
                         "PASS" if rc == 0 and re.fullmatch(r"[a-fA-F0-9]{40}", sha) else "WARN",
                         "checkout with valid revision" if rc == 0 and len(sha) == 40 else "revision unknown")
        self.add("05", "ACPI tools", "PASS" if shutil.which("iasl") else "PENDING",
                 "iasl available" if shutil.which("iasl") else "acpica-tools not verified")
        installer = Path.home() / "CAPEv2/installer/kvm-qemu.sh"
        if installer.is_file():
            try:
                count = installer.read_text(errors="replace").count("<WOOT>")
            except OSError:
                count = -1
            self.add("05", "Host-specific installer placeholders", "WARN" if count > 0 else "UNKNOWN",
                     "remaining placeholder count=" + str(count) + "; automated unsafe DSDT substitutions prohibited")
        else:
            self.add("05", "Installer source", "UNKNOWN", "not accessible under current user's home")

        self.add("06", "APT release inventory", "WARN" if len(apt_release_mix().split(",")) > 1 else "PASS",
                 "active-source releases=" + apt_release_mix())
        rc, qemu = run(["qemu-system-x86_64", "--version"])
        self.add("07", "QEMU", "PASS" if rc == 0 else "PENDING",
                 first_line(qemu) if rc == 0 and "QEMU" in qemu else "unavailable")
        rc, libvirt = run(["virsh", "-c", "qemu:///system", "version"])
        self.add("07", "libvirt system connection", "PASS" if rc == 0 else "PENDING",
                 "virsh connected" if rc == 0 else "unavailable (permissions/service/installation)")
        self.add("07", "TCP syncookies",
                 "PASS" if Path("/proc/sys/net/ipv4/tcp_syncookies").exists() and Path("/proc/sys/net/ipv4/tcp_syncookies").read_text().strip() == "1" else "WARN",
                 "enabled" if Path("/proc/sys/net/ipv4/tcp_syncookies").exists() and Path("/proc/sys/net/ipv4/tcp_syncookies").read_text().strip() == "1" else "unexpected/unknown")
        for target in ("sleep", "suspend", "hibernate", "hybrid-sleep"):
            rc, state = run(["systemctl", "is-enabled", target + ".target"])
            self.add("07", target + " target", "WARN" if state == "masked" else "PASS",
                     "masked (host-wide; never silently unmask)" if state == "masked" else "not reported masked")
        self.add("08", "virt-manager", "PASS" if shutil.which("virt-manager") else "PENDING",
                 "executable exists (GUI unverified)" if shutil.which("virt-manager") else "not in PATH")

        rc, domains = run(["virsh", "-c", "qemu:///system", "list", "--all", "--name"])
        vm_names = [line.strip() for line in domains.splitlines() if line.strip()] if rc == 0 else []
        self.add("09", "libvirt defined VMs", "PASS" if rc == 0 else "UNKNOWN",
                 "defined VM count=" + str(len(vm_names)) if rc == 0 else "cannot enumerate VMs")
        rc, default_xml = run(["virsh", "-c", "qemu:///system", "net-dumpxml", "default"])
        if rc == 0:
            mode = network_forward_mode(default_xml)
            self.add("09", "default network isolation", "BLOCKED" if mode != "none" else "WARN",
                     "forward mode=" + mode + "; never use as malware network; no negative-guest tests")
        else:
            self.add("09", "default network isolation", "UNKNOWN", "network not present or inaccessible")
        self.add("09", "cuckoo1 guest", "PASS" if "cuckoo1" in vm_names else "PENDING",
                 "defined (snapshot and isolation unverified)" if "cuckoo1" in vm_names else "not defined")

        cape = Path("/opt/CAPEv2")
        self.add("10", "CAPEv2 project", "PASS" if (cape / "pyproject.toml").is_file() else "PENDING",
                 "/opt/CAPEv2 project files present" if (cape / "pyproject.toml").is_file() else "missing project")
        for name in ("cuckoo", "reporting", "routing", "auxiliary"):
            found = (cape / "conf" / (name + ".conf")).is_file()
            self.add("10", "CAPE " + name + " config", "PASS" if found else "PENDING",
                     "present" if found else "missing")
        for service in CAPE_SERVICES:
            state = service_state(service)
            active = state.get("ActiveState", "unknown")
            if service == "mongod.service" and service_state("mongodb.service").get("ActiveState") == "active":
                status, detail = "PASS", "alternative mongodb.service active; mongod.service optional"
            else:
                status = "PASS" if active == "active" else ("BLOCKED" if active == "failed" else "PENDING")
                detail = "load=" + state.get("LoadState", "?") + " active=" + active + " sub=" + state.get("SubState", "?")
            self.add("10", service, status, detail)
        rc, pg = run(["pg_isready", "-h", "127.0.0.1", "-p", "5432"])
        self.add("10", "PostgreSQL readiness", "PASS" if rc == 0 else "PENDING",
                 "accepting local connections" if rc == 0 else "not confirmed")
        self.add("11", "Poetry binary for cape", "PASS" if Path("/etc/poetry/bin/poetry").is_file() else "PENDING",
                 "present" if Path("/etc/poetry/bin/poetry").is_file() else "not found")
        self.check_cape_venv()

    def check_cape_venv(self) -> None:
        """Run both discovery AND inspection as cape; never test permissions as invoker."""
        if not shutil.which("sudo") or not Path("/etc/poetry/bin/poetry").exists():
            self.add("11", "cape virtualenv", "UNKNOWN", "sudo or service Poetry missing")
            return
        command = ["sudo", "-n", "-u", "cape", "-H",
                   "/etc/poetry/bin/poetry", "-C", "/opt/CAPEv2",
                   "env", "info", "--executable"]
        rc, path = run(command)
        if rc != 0 or not path.startswith("/") or "\n" in path:
            self.add("11", "cape virtualenv", "UNKNOWN", "not queryable without sudo/service account")
            return
        rc, _ = run(["sudo", "-n", "-u", "cape", "-H", "test", "-x", path])
        if rc != 0:
            self.add("11", "cape virtualenv", "BLOCKED", "python not executable by service account")
            return
        self.add("11", "cape virtualenv", "PASS", "service account can execute selected interpreter")
        code = ("import importlib.metadata as m, json\n"
                "names = " + repr(OPTIONAL_DISTRIBUTIONS) + "\n"
                "d = {}\n"
                "for n in names:\n"
                "    try:\n"
                "        d[n] = m.version(n)\n"
                "    except m.PackageNotFoundError:\n"
                "        d[n] = None\n"
                "print(json.dumps(d))\n")
        rc, output = run(["sudo", "-n", "-u", "cape", "-H", path, "-B", "-c", code], timeout=20)
        try:
            data = json.loads(output) if rc == 0 else {}
        except ValueError:
            data = {}
        for name in OPTIONAL_DISTRIBUTIONS:
            version = data.get(name)
            self.add("11", "Optional: " + name, "PASS" if version else "PENDING",
                     "installed " + str(version)[:40] if version else "not installed/unknown in cape interpreter")

    def render(self) -> str:
        header = [
            "CAPEv2 pre-VM installation audit (manual SSL-55 Steps 1-11)",
            "READ ONLY; generated by scripts/audit_pre_vm_stages.py",
            "No APT/pip operations, system-wide changes, VM creation or malware execution.",
            "NOTE: PASS means this individual check succeeded, not full readiness.",
            "A non-forwarding libvirt network alone does NOT prove guest or host containment.",
            "",
        ]
        for step, check, status, detail in self.rows:
            header.append(f"[Step {step}] {status:<7} {check}: {detail}")
        counts = {s: sum(1 for r in self.rows if r[2] == s)
                  for s in ("PASS", "PENDING", "UNKNOWN", "WARN", "BLOCKED")}
        header.extend(["", "SUMMARY " + " ".join(f"{k}={v}" for k, v in counts.items()),
                       "RELEASE GATE: NOT CLEARED (Windows guest, INetSim, IPv4/IPv6 egress tests pending).",
                       "Do not commit this report: review for private host details before sharing."])
        return "\n".join(header) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=None,
                        help="Output TXT path; default private timestamped file under home.")
    args = parser.parse_args()
    audit = Audit()
    audit.collect()
    report = args.report
    if report is None:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report = Path.home() / ("CAPEv2_PreVM_Audit_" + timestamp + ".txt")
    report = report.expanduser().absolute()
    if report.is_symlink():
        parser.error("Refusing symlink report destination")
    report.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if report.exists():
        parser.error("Refusing to overwrite an existing report")
    fd = os.open(str(report), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(audit.render())
    print("Read-only report:", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
