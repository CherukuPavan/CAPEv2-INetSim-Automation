#!/usr/bin/env python3
"""Command 2 target-host READ-ONLY inventory and fail-closed capacity plan.

No package installs, guest creation, filesystem writes, network configuration,
firewall actions, VM power changes or sample execution. Uses only local host
metadata and read-only libvirt commands. Not a deployment authorization.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

import command2_portable_fresh_count_plan as count_plan

GIB = 1024**3
MIB = 1024**2
REQUIRED_TOOLS = ("virsh", "qemu-img", "ip")
RECOMMENDED_RAM_PER_GUEST_MIB = 4096
HOST_RAM_RESERVE_MIB = 8192


def read_os_release(path="/etc/os-release"):
    try:
        entries = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                if re.fullmatch(r"[A-Z_]+", k):
                    entries[k] = v.strip().strip('"').strip("'")
        return {"id": entries.get("ID", ""), "version": entries.get("VERSION_ID", "")}
    except OSError:
        return {"id": "", "version": ""}


def run_readonly(*cmdline, timeout=15):
    try:
        result = subprocess.run(cmdline, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def json_command(*cmdline):
    raw = run_readonly(*cmdline)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, list) else None


def parsed_routes(value):
    """Kernel route inventory: omit the generic default route, not overlaps."""
    if value is None:
        return None
    nets = set()
    for obj in value:
        if not isinstance(obj, dict):
            return None
        dest = obj.get("dst", "default")
        if dest in ("default", "0.0.0.0/0"):
            continue
        try:
            cidr = str(ipaddress.IPv4Network(dest, strict=False))
        except (ValueError, TypeError):
            return None
        nets.add(cidr)
    return sorted(nets)


def parsed_addresses(value):
    if value is None:
        return None
    nets = set()
    for obj in value:
        if not isinstance(obj, dict) or not isinstance(obj.get("addr_info"), list):
            return None
        for rec in obj["addr_info"]:
            if rec.get("family") != "inet":
                continue
            try:
                addr = rec["local"]
                prefix = int(rec["prefixlen"])
                nets.add(str(ipaddress.IPv4Network(addr + "/" + str(prefix),
                                                 strict=False)))
            except (ValueError, KeyError, TypeError):
                return None
    return sorted(nets)



def parse_outbound_interface(route_lookup):
    """Parse kernel-only route lookup without surfacing src/gateway secrets."""
    if not isinstance(route_lookup, list) or len(route_lookup) != 1:
        return None
    route = route_lookup[0]
    if not isinstance(route, dict):
        return None
    dev = route.get("dev")
    if not isinstance(dev, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,32}", dev):
        return None
    return dev if dev != "lo" else None

def libvirt_nets():
    names = run_readonly("virsh", "-c", "qemu:///system", "net-list",
                         "--all", "--name")
    if names is None:
        return None
    import xml.etree.ElementTree as ET
    ranges = []
    for name in names.splitlines():
        name = name.strip()
        if not name:
            continue
        # Never call net-start or net-define. net-dumpxml is read-only.
        raw = run_readonly("virsh", "-c", "qemu:///system", "net-dumpxml", name)
        if raw is None:
            return None
        try:
            root = ET.fromstring(raw)
            for n in root.findall("./ip"):
                if n.get("family", "ipv4") not in ("ipv4", ""):
                    continue
                addr, mask, prefix = n.get("address"), n.get("netmask"), n.get("prefix")
                if addr and (mask or prefix):
                    suffix = mask or prefix
                    ranges.append(str(ipaddress.IPv4Network(
                        addr + "/" + suffix, strict=False)))
        except (ValueError, ET.ParseError):
            return None
    return sorted(set(ranges))


def memory_available_mib():
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
        match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", text, re.M)
        return int(match.group(1)) // 1024 if match else None
    except OSError:
        return None


def virt_flag_present():
    try:
        data = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except OSError:
        return False
    return bool(re.search(r"\b(?:vmx|svm)\b", data))


def directory_free_gib(path):
    try:
        p = Path(path)
        if not p.is_dir() or p.is_symlink():
            return None
        s = os.statvfs(str(p))
        return round(s.f_bavail * s.f_frsize / GIB, 3)
    except OSError:
        return None


def local_ref_host():
    return platform.node().split(".", 1)[0].casefold() in (
        "cse-ssl-55", "ssl-55")


def template_metadata(path):
    """Do not read image contents; only qemu-img info on a regular file.

    Source-template readiness remains unverified until separate complete
    Command 1 provenance / BitLocker / Windows guest acceptance.
    """
    p = Path(path)
    try:
        s = p.lstat()
    except OSError:
        return {"visible": False, "qcow2_flat": False}
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        return {"visible": False, "qcow2_flat": False}
    raw = run_readonly("qemu-img", "info", "--output=json", str(p))
    if raw is None:
        return {"visible": True, "qcow2_flat": False}
    try:
        val = json.loads(raw)
        valid = (val.get("format") == "qcow2" and
                 val.get("virtual-size") == 64*GIB and
                 not val.get("backing-filename") and
                 not val.get("full-backing-filename"))
        return {"visible": True, "qcow2_flat": bool(valid)}
    except (ValueError, AttributeError):
        return {"visible": True, "qcow2_flat": False}


def collect(disk_dir, nvram_dir, template):
    tools = {x: shutil.which(x) is not None for x in REQUIRED_TOOLS}
    domain_raw = run_readonly("virsh", "-c", "qemu:///system",
                             "list", "--all", "--name") if tools["virsh"] else None
    domains = (sorted(set(n.strip() for n in domain_raw.splitlines() if n.strip()))
               if domain_raw is not None else None)
    master_off = None
    if domains is not None and "win11" in domains:
        master_off = (run_readonly("virsh", "-c", "qemu:///system",
                                  "domstate", "win11") or "").strip() == "shut off"
    occupied = []
    for idx in range(1, count_plan.MAX_COUNT + 1):
        for target in (Path(disk_dir) / ("win11_" + str(idx) + ".command2.qcow2"),
                       Path(nvram_dir) / ("win11_" + str(idx) + ".command2_VARS.fd")):
            if target.exists() or target.is_symlink():
                occupied.append(str(target))
    try:
        kvm = Path("/dev/kvm")
        kvm_char = stat.S_ISCHR(kvm.stat().st_mode)
    except OSError:
        kvm_char = False
    return {
        "reference_ssl55": local_ref_host(),
        "os": read_os_release(),
        "architecture": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "vmx_svm_cpu_flag": virt_flag_present(),
        "kvm_character_device": kvm_char,
        "kvm_access_current_user": os.access("/dev/kvm", os.R_OK | os.W_OK),
        "tools_found": tools,
        "available_ram_mib": memory_available_mib(),
        "disk_free_gib": directory_free_gib(disk_dir),
        "nvram_dir_exists": Path(nvram_dir).is_dir() and
                            not Path(nvram_dir).is_symlink(),
        "source_master_shutoff": master_off,
        "existing_domain_names": domains,
        "existing_target_artifact_paths": occupied,
        "kernel_ipv4_routes": parsed_routes(json_command(
            "ip", "-j", "-4", "route", "show", "table", "all")) if tools["ip"] else None,
        "kernel_ipv4_addresses": parsed_addresses(json_command(
            "ip", "-j", "-4", "addr", "show")) if tools["ip"] else None,
        "outbound_interface": parse_outbound_interface(json_command(
            "ip", "-j", "-4", "route", "get", "1.1.1.1")) if tools["ip"] else None,
        "libvirt_ipv4_networks": libvirt_nets() if tools["virsh"] else None,
        "template": template_metadata(template) if tools["qemu-img"] else
                    {"visible": False, "qcow2_flat": False},
    }


CANDIDATE_ISOLATED_SUBNETS = (
    "192.168.240.0/24", "192.168.241.0/24", "192.168.242.0/24",
    "172.28.240.0/24", "10.254.240.0/24"
)


def suggest_nonoverlapping_subnet(routes, addresses, networks):
    """Suggestion only; never mutate network or implicitly change IP plan."""
    if not all(isinstance(z, list) for z in (routes, addresses, networks)):
        return None
    try:
        claimed = [ipaddress.IPv4Network(z, strict=False)
                   for z in (routes + addresses + networks)]
    except (ValueError, TypeError):
        return None
    for candidate in CANDIDATE_ISOLATED_SUBNETS:
        block = ipaddress.IPv4Network(candidate)
        if block.is_private and not any(block.overlaps(existing) for existing in claimed):
            return candidate
    return None


def evaluate(profile, count, disk_dir, nvram_dir, cidr):
    """Fail-closed readiness on supplied/synthetic inventory; no mutations."""
    errors = []
    def require(test, reason):
        if not test:
            errors.append(reason)

    require(not profile.get("reference_ssl55"), "SSL55_REFERENCE_ONLY_NO_NEW_VMS")
    osrel = profile.get("os") or {}
    require(osrel.get("id") == "ubuntu", "NOT_UBUNTU")
    # Candidate Ubuntu releases only; full support matrix not host-accepted.
    require(osrel.get("version") in ("22.04", "24.04"),
            "UBUNTU_RELEASE_NOT_IN_CANDIDATE_MATRIX")
    require(profile.get("architecture") == "x86_64", "HOST_NOT_X86_64")
    require(profile.get("vmx_svm_cpu_flag") is True, "CPU_VIRTUALIZATION_NOT_EXPOSED")
    require(profile.get("kvm_character_device") is True, "KVM_DEVICE_MISSING")
    if profile.get("kvm_access_current_user") is False:
        # A privilege-aware installer may use sudo, but planning must not
        # infer that the current account can start KVM guests.
        errors.append("CURRENT_USER_CANNOT_ACCESS_KVM")
    for name in REQUIRED_TOOLS:
        require((profile.get("tools_found") or {}).get(name) is True,
                "MISSING_TOOL_" + name.replace("-", "_").upper())
    require(profile.get("source_master_shutoff") is True,
            "UNVERIFIED_COMMAND1_MASTER_OR_MASTER_RUNNING")
    require((profile.get("template") or {}).get("qcow2_flat") is True,
            "TEMPLATE_METADATA_NOT_VERIFIED_FLAT_64G")
    require(profile.get("nvram_dir_exists") is True, "NVRAM_DIR_NOT_AVAILABLE")
    require(isinstance(profile.get("outbound_interface"), str) and
            bool(profile.get("outbound_interface")),
            "DEFAULT_OUTBOUND_INTERFACE_UNAVAILABLE")

    existing = profile.get("existing_domain_names")
    if not isinstance(existing, list):
        errors.append("LIBVIRT_DOMAIN_INVENTORY_UNAVAILABLE")
        existing = []
    occupied = profile.get("existing_target_artifact_paths")
    if not isinstance(occupied, list):
        errors.append("ARTIFACT_INVENTORY_UNAVAILABLE")
        occupied = []

    routes = profile.get("kernel_ipv4_routes")
    addrs = profile.get("kernel_ipv4_addresses")
    networks = profile.get("libvirt_ipv4_networks")
    try:
        target = ipaddress.IPv4Network(cidr, strict=True)
    except (ValueError, TypeError) as exc:
        raise count_plan.PortablePlanBlocked("Invalid requested analysis network") from exc
    for kind, records in (("routes", routes), ("addresses", addrs),
                          ("libvirt_networks", networks)):
        if not isinstance(records, list):
            errors.append("MISSING_" + kind.upper() + "_INVENTORY")
            continue
        try:
            overlaps = [x for x in records if
                        target.overlaps(ipaddress.IPv4Network(x, strict=False))]
        except (ValueError, TypeError):
            errors.append("INVALID_" + kind.upper() + "_INVENTORY")
            continue
        if overlaps:
            # Does not disclose campus IP/route details in reports.
            errors.append("ANALYSIS_SUBNET_OVERLAPS_" + kind.upper())

    mem = profile.get("available_ram_mib")
    require(type(mem) is int and
            mem >= HOST_RAM_RESERVE_MIB + count*RECOMMENDED_RAM_PER_GUEST_MIB,
            "INSUFFICIENT_AVAILABLE_RAM_FOR_COUNT")
    cores = profile.get("logical_cpus")
    require(type(cores) is int and cores >= 2, "INSUFFICIENT_CPU_INFORMATION")
    free = profile.get("disk_free_gib")
    if type(free) not in (int, float) or free < 0:
        errors.append("DISK_FREE_SPACE_UNKNOWN")
        free = 0
    result = count_plan.plan_fresh(
        count, disk_dir=disk_dir, nvram_dir=nvram_dir,
        analysis_subnet=cidr, free_gib=free,
        existing_domains=existing, occupied_artifacts=occupied)
    if not result["capacity_estimate_pass"]:
        errors.append("INSUFFICIENT_CONSERVATIVE_DISK_CAPACITY")
    return {
        "result": "COMMAND2_READ_ONLY_TARGET_HOST_PREFLIGHT",
        "requested_vm_count": count,
        "analysis_subnet": cidr,
        "planned_vms": result["planned_vms"],
        "storage_required_gib": result["conservative_required_gib"],
        "storage_reported_free_gib": free,
        "guest_memory_assumed_mib": RECOMMENDED_RAM_PER_GUEST_MIB,
        "host_memory_reserve_mib": HOST_RAM_RESERVE_MIB,
        "errors": sorted(set(errors)),
        "detected_outbound_interface": profile.get("outbound_interface"),
        "suggested_nonoverlapping_subnet_only": suggest_nonoverlapping_subnet(
            routes, addrs, networks),
        "suggested_subnet_not_automatically_applied": True,
        "preflight_pass": not errors,
        "ssl55_new_vm_prohibited": bool(profile.get("reference_ssl55")),
        "ipv4_overlap_checked": all(isinstance(z, list) for z in
                                    (routes, addrs, networks)),
        "ipv6_containment_checked": False,
        "firewall_persistence_checked": False,
        "template_windows_and_tpm_semantics_verified": False,
        "guest_isolation_egress_tested": False,
        "deploy_authorized": False,
        "host_modified": False,
        "note": "Inventory/preflight success is NOT deployment or network approval",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--disk-dir", required=True)
    parser.add_argument("--nvram-dir", required=True)
    parser.add_argument("--template", required=True)
    parser.add_argument("--subnet", default="192.168.240.0/24")
    opts = parser.parse_args()
    try:
        profile = collect(opts.disk_dir, opts.nvram_dir, opts.template)
        result = evaluate(profile, opts.count, opts.disk_dir,
                          opts.nvram_dir, opts.subnet)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["preflight_pass"] else 2
    except (count_plan.PortablePlanBlocked, OSError, ValueError) as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
