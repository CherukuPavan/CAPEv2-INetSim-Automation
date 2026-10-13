#!/usr/bin/env python3
"""Command 3 final step: READ-ONLY five-service restart readiness.

Operator-supplied service sequence is preserved as a reference, while CAPE
upstream's documented startup order has rooter before CAPE processes.

No apply, no restart and no bypass. This is intentionally NOT a service
restarting script while the user-supplied internet/virbr0 routing profile,
default NAT real-Internet egress, guest revert, and firewall containment are
unverified. Run after configs are saved to inspect exact systemd units and
active states; do not interpret unit 'active' as a safe analysis environment.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import command3_cape_routing as routing

OPERATOR_ORDER = (
    "cape.service",
    "cape-processor.service",
    "cape-rooter.service",
    "cape-web.service",
    "suricata.service",
)
# Derived from upstream CAPEv2 systemd instructions (START, not a claim
# that a restart has identical ordering requirements).
UPSTREAM_START_ORDER = (
    "cape-rooter.service",
    "cape-processor.service",
    "cape.service",
    "cape-web.service",
)
PROPS = ("LoadState", "ActiveState", "SubState", "Result", "FragmentPath")
REQUIRED_ROUTING = ("route", "internet", "enable_pcap")
ROUTING_SECTION = routing.SECTION
OPTION = routing.OPTION

class ServicesBlocked(RuntimeError):
    pass

def need(test, why):
    if not test:
        raise ServicesBlocked(why)

def routing_status(raw):
    """Read one [routing] section; never infer containment from these keys."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ServicesBlocked("Non-UTF8 routing.conf") from exc
    need("\x00" not in text, "Invalid routing.conf binary content")
    in_section = False
    section_count = 0
    values = {}
    for line in text.splitlines(keepends=True):
        head = ROUTING_SECTION.fullmatch(line.rstrip("\r\n"))
        if head:
            in_section = head.group(1).strip().lower() == "routing"
            if in_section:
                section_count += 1
            continue
        if not in_section or line.lstrip().startswith(("#", ";")):
            continue
        key = routing.KEY.match(line)
        if not key or key.group(1).lower() not in REQUIRED_ROUTING:
            continue
        name = key.group(1).lower()
        need(name not in values, "Duplicate reviewed routing key: " + name)
        parsed = OPTION.fullmatch(line)
        need(parsed is not None, "Malformed [routing] " + name)
        val = parsed.group(4).strip()
        need(re.fullmatch(r"[A-Za-z0-9_.-]+", val) is not None,
             "Unsafe/unrecognized [routing] value: " + name)
        values[name] = val.lower()
    need(section_count == 1 and len(values) == len(REQUIRED_ROUTING),
         "Missing or duplicated routing configuration sections/options")
    need(values["route"] in ("none", "internet", "inetsim", "drop") and
         values["enable_pcap"] in ("yes", "no"),
         "Unexpected routing mode or pcap option")
    return values

def systemd_status(unit):
    """Restricted, read-only systemctl show. No shell, unit modifications."""
    need(unit in OPERATOR_ORDER, "Unapproved systemd unit")
    try:
        data = subprocess.check_output(
            ["systemctl", "show", "--no-pager",
             "--property=" + ",".join(PROPS), unit],
            stderr=subprocess.DEVNULL, text=True, timeout=8)
    except (OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        raise ServicesBlocked("Unable to inspect approved service " +
                              unit + ": " + type(exc).__name__) from exc
    selected = {}
    for row in data.splitlines():
        if "=" in row:
            key, value = row.split("=", 1)
            if key in PROPS:
                need(key not in selected, "Duplicate systemd field " + key)
                selected[key] = value.strip()
    need(all(x in selected for x in PROPS),
         "Incomplete systemctl show response for " + unit)
    return {
        "unit": unit,
        "loaded": selected["LoadState"] == "loaded",
        "active": selected["ActiveState"] == "active",
        "load_state": selected["LoadState"],
        "active_state": selected["ActiveState"],
        "sub_state": selected["SubState"],
        "last_result": selected["Result"],
        "installed_fragment": bool(selected["FragmentPath"]),
    }

def report(conf_path, mode="plan"):
    need(mode in ("plan", "verify"), "Read-only inspection modes only")
    original, st = routing.read_conf(conf_path)
    current = routing_status(original)
    units = [systemd_status(name) for name in OPERATOR_ORDER]
    need(len(units) == 5 and
         [row["unit"] for row in units] == list(OPERATOR_ORDER),
         "Missing/misordered operator service definitions")
    # No automatic restart is permitted even for 'route = none'.
    # A libvirt 'default' NAT bridge may forward to the real Internet
    # independently of CAPE's chosen route mode.
    blockers = []
    if current["route"] == "internet":
        blockers.append("CAPE internet mode directs analysis to external egress")
    if current["internet"] == "virbr0":
        blockers.append("virbr0 is the VM NAT bridge, not an approved dirty-line uplink")
    blockers.extend([
        "CAPE/INetSim guest containment and deny-egress not attested",
        "VM swtpm-consistent snapshot restore and benign CAPE cycles not attested",
        "Firewall restrictions around wildcard resultserver/API not attested",
    ])
    if not all(x["loaded"] for x in units):
        blockers.append("One or more named services not installed/loaded")
    if mode == "verify" and not all(x["active"] for x in units):
        blockers.append("One or more named services not active")
    return {
        "result": ("COMMAND3_FIVE_SERVICE_PLAN_ONLY" if mode == "plan"
                   else "COMMAND3_FIVE_SERVICE_READ_ONLY_STATUS"),
        "operator_requested_order": list(OPERATOR_ORDER),
        "upstream_documented_cape_start_order": list(UPSTREAM_START_ORDER),
        "suricata_handled_separately": True,
        "service_checks": units,
        "routing_file": str(conf_path),
        "routing_file_sha256": routing.guard.sha(original),
        "routing_file_bytes": st.st_size,
        "routing_review": current,
        "all_service_units_loaded": all(x["loaded"] for x in units),
        "all_services_active_now": all(x["active"] for x in units),
        "services_have_just_been_restarted_verified": False,
        "restart_apply_authorized": False,
        "restart_automated": False,
        "blocking_issues": blockers,
        "safe_to_run_untrusted_samples": False,
        "snapshot_restore_tpm_proven": False,
        "CAPE_READY": False,
        "host_modified": False,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "verify"), default="plan")
    parser.add_argument("--routing-conf", type=Path,
                        default=Path("/opt/CAPEv2/conf/routing.conf"))
    a = parser.parse_args()
    try:
        print(json.dumps(report(a.routing_conf, a.mode),
                         sort_keys=True, indent=2), flush=True)
        return 0
    except (ServicesBlocked, routing.RoutingBlocked,
            routing.guard.Command3Blocked, ValueError, OSError) as exc:
        print(json.dumps({
            "result": "COMMAND3_FIVE_SERVICE_INSPECTION_BLOCKED",
            "reason": str(exc),
            "no_restart_or_network_changes": True,
        }, sort_keys=True), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
