#!/usr/bin/env python3
"""Pure read-only Command 2 plan for a NEW supported machine (no VMs created).

This model receives an explicit host profile. It does not inspect or install
Ubuntu/libvirt/Windows; those validations belong to future portable Command
1/2 preflights. Count means TOTAL analysis guests win11_1..win11_N.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import PurePosixPath
import sys

MAX_COUNT = 4096  # model-safety cap, NOT a target host entitlement
GIB = 1024**3

class PortablePlanBlocked(ValueError):
    pass

def need(test, why):
    if not test:
        raise PortablePlanBlocked(why)

def clean_dir(path):
    need(isinstance(path, str) and path.startswith("/") and "\x00" not in path,
         "Absolute Unix artifact directory required")
    need(".." not in path.split("/") and path.rstrip("/") != "",
         "Unsafe artifact directory")
    return str(PurePosixPath(path))

def plan_fresh(total, *, disk_dir, nvram_dir, analysis_subnet,
               free_gib, existing_domains=(), occupied_artifacts=(),
               virtual_disk_gib=64, reserve_gib=30):
    """Produce a host-independent NO-WRITE plan from caller-supplied facts.

    Existing names/paths are collision evidence only, NOT an authorization to
    reuse or replace a VM. Actual host inventory and isolation must be checked.
    """
    need(type(total) is int and 1 <= total <= MAX_COUNT,
         "Count must be an integer from 1 to " + str(MAX_COUNT))
    disk_base = clean_dir(disk_dir)
    nvram_base = clean_dir(nvram_dir)
    need(disk_base != nvram_base, "Disk and firmware directories must differ")
    need(type(free_gib) in (float, int) and free_gib >= 0,
         "Nonnegative available GiB required")
    need(type(virtual_disk_gib) is int and 1 <= virtual_disk_gib <= 1024,
         "Unsafe virtual disk size")
    need(type(reserve_gib) is int and 30 <= reserve_gib <= 1024,
         "Require at least 30 GiB unallocated operating reserve")
    try:
        net = ipaddress.IPv4Network(analysis_subnet, strict=True)
    except (ValueError, TypeError) as err:
        raise PortablePlanBlocked("Invalid isolated IPv4 subnet") from err
    need(not net.is_global and not net.is_multicast and
         not net.is_link_local and not net.is_loopback,
         "Analysis subnet must not be publicly routed, multicast or loopback")
    need(str(net) != "192.168.122.0/24",
         "Do not plan guests on common libvirt default NAT subnet")
    need(net.num_addresses >= total + 102,
         "Analysis subnet too small for the assigned host-address offset")
    # Command 1 provides a protected source master 'win11' on a fresh host.
    # Its presence is expected; never include it among the guest targets.
    domains = set(existing_domains)
    need("win11_trial_1" not in domains,
         "Unexpected trial VM on new target: inspect before provisioning")
    occupied = {str(path) for path in occupied_artifacts}
    entries = []
    for i in range(1, total+1):
        name = f"win11_{i}"
        disk = str(PurePosixPath(disk_base) / (name + ".command2.qcow2"))
        nvram = str(PurePosixPath(nvram_base) / (name + ".command2_VARS.fd"))
        need(name not in domains, "Existing VM collision: " + name)
        need(disk not in occupied and nvram not in occupied,
             "Existing disk/NVRAM collision: " + name)
        ip = ipaddress.IPv4Address(int(net.network_address) + i + 100)
        need(ip in net and ip != net.broadcast_address,
             "Guest IPv4 out of network range")
        entries.append({"libvirt_name": name, "hostname": f"WIN11-{i}",
                        "planned_ipv4": str(ip), "disk": disk, "nvram": nvram,
                        "new_uuid_required": True, "new_mac_required": True,
                        "new_tpm_state_required": True,
                        "guest_ip_not_yet_assigned": True})
    needed = total*virtual_disk_gib + reserve_gib
    return {"result": "PORTABLE_COMMAND2_FRESH_MACHINE_PLAN_ONLY",
            "target_vm_total": total, "subnet": str(net),
            "planned_vms": entries,
            "conservative_required_gib": needed,
            "caller_supplied_free_gib": free_gib,
            "capacity_estimate_pass": free_gib >= needed,
            "network_isolation_verified": False,
            "host_profile_verified": False,
            "guest_operating_system_verified": False,
            "virtualization_preflight_verified": False,
            "no_vm_created": True, "deployment_authorized": False,
            "warning": "Illustrative host profile: not permission to stage guests"}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count",type=int)
    parser.add_argument("--disk-dir",required=True)
    parser.add_argument("--nvram-dir",required=True)
    parser.add_argument("--subnet",default="192.168.240.0/24")
    parser.add_argument("--free-gib",type=float,required=True)
    args=parser.parse_args()
    try:
        count=args.count
        if count is None:
            need(sys.stdin.isatty(),"--count N required in noninteractive mode")
            count=int(input("TOTAL desired Windows analysis VMs [subject to host/subnet capacity]: "))
        out=plan_fresh(count,disk_dir=args.disk_dir,nvram_dir=args.nvram_dir,
                       analysis_subnet=args.subnet,free_gib=args.free_gib)
        print(json.dumps(out,indent=2,sort_keys=True))
        return 0 if out["capacity_estimate_pass"] else 2
    except (PortablePlanBlocked,ValueError,KeyboardInterrupt) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
