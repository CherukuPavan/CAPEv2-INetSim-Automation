#!/usr/bin/env python3
"""Command 3 Step 6: read-only CAPE routing.conf proposed diff and safety gate.

The operator's SSL-55 screenshot requests [routing]:
  enable_pcap = yes, route = internet, internet = virbr0
and retains nat=yes, no_local_routing=yes, rt_table=main.

CRITICAL: Upstream CAPEv2 docs define "internet" as the host's external
dirty-line uplink, NOT virbr0 (libvirt default VM-side NAT bridge).
Furthermore the VM default NAT already permits real egress regardless of
CAPE route=none. This profile CANNOT be safely applied unattended.
This module deliberately has NO apply mode, file writer, service, rooter,
firewall, guest, snapshot, or sample operations. It reports a safe summary
without exposing unrelated configuration or credentials.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

import command3_cape_api_ratelimit as guard

CONF = Path("/opt/CAPEv2/conf/routing.conf")
SECTION = guard.API_SECTION
OPTION = re.compile(
    r"^([ \t]*)([A-Za-z][A-Za-z0-9_]*)([ \t]*=[ \t]*)"
    r"([^#;\r\n]*?)([ \t]*(?:[;#][^\r\n]*)?)(\r?\n|)$")
KEY = re.compile(r"^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]*=")
TARGET = {
    "enable_pcap": "yes",
    "route": "internet",
    "internet": "virbr0",
    "nat": "yes",
    "no_local_routing": "yes",
    "rt_table": "main",
}
CHANGED_KEYS = ("enable_pcap", "route", "internet")
NOT_DEPLOYABLE = "BLOCKED_DIRTY_LINE_VM_BRIDGE_AND_PUBLIC_EGRESS"

class RoutingBlocked(guard.Command3Blocked):
    pass

def need(value, explanation):
    if not value:
        raise RoutingBlocked(explanation)

def read_conf(path):
    path = Path(path)
    need(path.is_absolute() and path.name == "routing.conf" and
         path.parent.name == "conf",
         "Expected absolute CAPE conf/routing.conf")
    for part in (path, *path.parents):
        need(not part.is_symlink(), "Symlinked routing.conf path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             0 < st.st_size <= guard.MAX_BYTES and
             not (stat.S_IMODE(st.st_mode) & 0o022),
             "Unsafe CAPE routing.conf file type/permissions/size")
        data = os.read(fd, guard.MAX_BYTES + 1)
        need(len(data) == st.st_size, "routing.conf changed during read")
        return data, st
    finally:
        os.close(fd)

def proposed_diff(original):
    """Compute exact operator-requested changes without writing a file."""
    try:
        data = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RoutingBlocked("routing.conf is not UTF-8") from exc
    need(bool(data) and "\0" not in data and
         "\r" not in data.replace("\r\n", ""),
         "Invalid routing.conf text or mixed line endings")
    lines = data.splitlines(keepends=True)
    section = None
    count = 0
    found = {}
    for idx, line in enumerate(lines):
        header = SECTION.fullmatch(line.rstrip("\r\n"))
        if header:
            section = header.group(1).strip().lower()
            count += int(section == "routing")
            continue
        if section != "routing" or line.lstrip().startswith(("#", ";")):
            continue
        possible = KEY.match(line)
        if possible is None or possible.group(1).lower() not in TARGET:
            continue
        key = possible.group(1).lower()
        need(key not in found, "Duplicate [routing] " + key + " option")
        parsed = OPTION.fullmatch(line)
        need(parsed is not None and parsed.group(2).lower() == key,
             "Malformed reviewed [routing] " + key + " option")
        val = parsed.group(4).strip()
        need(val != "" and len(val) <= 128 and
             bool(re.fullmatch(r"[A-Za-z0-9_.-]+", val)),
             "Unrecognizable existing [routing] " + key + " value")
        found[key] = (idx, parsed, val)
    need(count == 1, "Expected exactly one [routing] section")
    need(len(found) == len(TARGET),
         "Missing required [routing] keys: " +
         ",".join(sorted(set(TARGET) - set(found))))
    changes = []
    for key, target in TARGET.items():
        idx, match, old = found[key]
        if key in ("enable_pcap", "nat", "no_local_routing"):
            need(old in ("yes", "no"),
                 "Invalid existing boolean in [routing] " + key)
        if key == "route":
            need(old in ("none", "internet", "drop", "inetsim"),
                 "Unreviewed existing routing mode")
        if old == target:
            continue
        if key not in CHANGED_KEYS:
            # These values were unchanged in the operator's BEFORE/AFTER
            # screenshot: unexpected host divergence must be investigated.
            raise RoutingBlocked("Unchanged operator reference differs: " + key)
        lines[idx] = (match.group(1) + match.group(2) + match.group(3) +
                      target + match.group(5) + match.group(6))
        changes.append({"setting": "[routing] " + key,
                        "existing": old, "proposed": target})
    proposal = "".join(lines).encode("utf-8")
    need(proposal != b"", "Empty routing.conf proposal")
    return proposal, changes

def plan(path):
    original, meta = read_conf(path)
    new, changes = proposed_diff(original)
    return {
        "result": "COMMAND3_ROUTING_STEP6_UNSAFE_REFERENCE_PLAN_ONLY",
        "config": str(path),
        "exact_operator_reference": dict(TARGET),
        "requested_differences": changes,
        "changed_option_count": len(changes),
        "before_sha256": guard.sha(original),
        "proposed_sha256": guard.sha(new),
        "file_size": meta.st_size,
        "status": NOT_DEPLOYABLE,
        "why": ("CAPE's internet field is an external dirty-line host "
                "uplink; virbr0 is a libvirt VM NAT bridge, not that uplink. "
                "Internet routing and default NAT may expose analysis traffic."),
        "enable_pcap_requested": True,
        "independent_network_isolation_and_rooter_validation_required": True,
        "nat_already_allows_internet_even_when_cape_route_none": True,
        "unsupported_automatic_apply": True,
        "requires_reviewed_inetsim_or_isolated_routing_profile": True,
        "host_modified": False,
        "service_restarted": False,
        "VMs_started_or_reverted": False,
        "CAPE_READY": False,
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", default="plan", choices=("plan",),
                   help="Plan only: this internet/virbr0 configuration cannot be applied safely")
    p.add_argument("--conf", type=Path, default=CONF)
    args = p.parse_args()
    try:
        print(json.dumps(plan(args.conf), sort_keys=True, indent=2), flush=True)
        return 0
    except (RoutingBlocked, guard.Command3Blocked, OSError, ValueError) as exc:
        print(json.dumps({"result": "COMMAND3_ROUTING_STEP6_BLOCKED",
                          "reason": str(exc),
                          "no_network_or_service_mutation": True},
                         sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
