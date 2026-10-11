#!/usr/bin/env python3
"""Command 2: pure, NON-DEPLOYABLE SSL55 firewall persistence design.

Consumes a previous strict read-only boot-persistence report. Produces
a fail-closed recovery plan, not an installer, and DOES NOT enable any
service, write nftables, attach NICs, start networks or reboot. The
systemd unit below is a DRAFT, not safe to install before its referenced
reconciler, startup ordering and host packet tests exist.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

EXPECTED_KIND = "SSL55_COMMAND2_NFT_BOOT_PERSISTENCE_INSPECTION_ONLY"
DOMAINS = ("win11", "win11_1", "win11_trial_1")


class PersistenceBlocked(ValueError):
    pass


def require(ok, why):
    if not ok:
        raise PersistenceBlocked(why)


def plan(report: dict) -> dict:
    require(type(report) is dict and report.get("result") == EXPECTED_KIND,
            "Wrong strict SSL55 boot-persistence source")
    require(report.get("network_or_guest_changed") is False and
            report.get("existing_guard_expected_structure_now") is True,
            "Existing guard shape was not safely established")
    network = report.get("analysis_network")
    require(type(network) is dict and
            network.get("active") == "no" and
            network.get("autostart") == "no" and
            network.get("persistent") == "yes" and
            network.get("bridge") == "cape-lab0" and
            network.get("nonforward_no_dhcp_known_subnet") is True,
            "Dedicated private libvirt network not inactive and isolated")
    require(report.get("analysis_network_and_clones_autostart_disabled") is True,
            "One or more protected machines or networks could autostart")
    autostart = report.get("domain_autostart_enabled")
    power = report.get("vm_powerstates")
    require(type(autostart) is dict and type(power) is dict and
            set(autostart) == set(DOMAINS) and set(power) == set(DOMAINS) and
            all(autostart[vm] is False and power[vm] == "shut off"
                for vm in DOMAINS),
            "Protected VMs not confirmed shut off with autostart off")
    conf = report.get("nftables_config_metadata")
    require(type(conf) is dict and conf.get("exists") is True and
            conf.get("file_safe_to_inspect") is True and
            conf.get("root_controlled") is True,
            "Firewall base configuration unavailable or untrusted")
    units = report.get("service_show_observations")
    require(type(units) is dict, "Missing systemd observations")
    nft = units.get("nftables.service")
    oldguard = units.get("cape-analysis-guard.service")
    require(type(nft) is dict and type(oldguard) is dict and
            nft.get("query_succeeded") is True and
            oldguard.get("query_succeeded") is True,
            "Cannot determine existing service status")
    require(nft.get("load_state") == "loaded" and
            nft.get("unit_file_state") == "disabled" and
            nft.get("boot_enabled_observed") is False and
            oldguard.get("load_state") == "not-found" and
            oldguard.get("boot_enabled_observed") is False,
            "Existing firewall service environment differs from inspected host")
    require(conf.get("global_flush_present") is True and
            conf.get("guard_reference_present") is False and
            conf.get("includes_present") is False,
            "Existing base nftables.conf is different; re-inspect before designing")
    require(report.get("safe_to_activate_bridge") is False and
            report.get("safe_to_attach_win11_1_nic") is False and
            report.get("safe_to_assume_guard_survives_reboot") is False,
            "Input report improperly claims deployment permission")

    return {
        "result": "COMMAND2_SSL55_FIREWALL_PERSISTENCE_DESIGN_ONLY",
        "observed_nftables_service": "loaded_disabled",
        "observed_cape_guard_service": "not_found",
        "global_flush_in_base_nft_config": True,
        "current_guard_present_but_ephemeral": True,
        "recommended_isolation": (
            "Dedicated CAPE-only replay unit and guarded reconcile helper. "
            "Do not enable nftables.service, edit /etc/nftables.conf, "
            "flush ruleset, or disturb Docker/libvirt/campus firewall."),
        "ordered_development_stages": [
            "Build strict existing-guard identity and exact-policy replay helper",
            "Generate root-controlled dedicated unit with reviewed boot ordering",
            "Verify no service start/enable while other firewall is changed",
            "Test no CAPE network/guest autostart before guard",
            "Witness service restart and full host reboot on approved host",
            "Only then consider quarantined benign guest NIC with real IPv4/IPv6 probes",
            "Require CAPE agent reachability, Windows identity/IP, running snapshot/revert",
        ],
        "unresolved_live_tests": {
            "unit_installation": False,
            "guard_replay_after_boot": False,
            "reboot_survival": False,
            "firewall_restart_race": False,
            "ipv4_egress_negative": False,
            "ipv6_egress_negative": False,
            "l2_guest_separation": False,
            "agent_http": False,
        },
        "nftables_service_enable_authorized": False,
        "cape_service_enable_authorized": False,
        "bridge_start_authorized": False,
        "guest_nic_attach_authorized": False,
        "snapshot_capture_authorized": False,
        "host_modified": False,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path, required=True)
    args = ap.parse_args()
    try:
        p = args.report
        require(p.is_file() and not p.is_symlink(),
                "Expected saved read-only report")
        require(p.stat().st_size <= 65536, "Unreasonable report size")
        result = plan(json.loads(p.read_text(encoding="utf-8")))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (PersistenceBlocked, OSError, ValueError, TypeError) as err:
        print("BLOCKED: " + str(err), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
