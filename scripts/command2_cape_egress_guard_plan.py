#!/usr/bin/env python3
"""PURE proposal for host-scoped CAPE bridge egress isolation (NO APPLY).

Renders a dedicated nftables INET table, no host commands, no file writes.
This is not a certified network guard: bridge forwarding and guest L2
isolation, existing firewall interactions, ipv6 and persistence must be
validated on a separate approved target before attaching guest NICs.

DO NOT RUN OR APPLY THESE RULES ON SSL-55.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
import hashlib
import re


class GuardPlanBlocked(ValueError):
    pass


TABLE = "cape_analysis_cmd2_guard"
BRIDGE = "cape-lab0"


def require(test, why):
    if not test:
        raise GuardPlanBlocked(why)


def render_cape_egress_guard(analysis_subnet="192.168.240.0/24",
                             bridge=BRIDGE, table=TABLE):
    """No user-supplied shell interpolation permitted."""
    require(table == TABLE and bridge == BRIDGE,
            "Only audited fixed bridge/table identifiers allowed")
    try:
        net = IPv4Network(analysis_subnet, strict=True)
    except (ValueError, TypeError) as exc:
        raise GuardPlanBlocked("Malformed canonical analysis subnet") from exc
    rfc1918 = (IPv4Network("10.0.0.0/8"),
               IPv4Network("172.16.0.0/12"),
               IPv4Network("192.168.0.0/16"))
    require(net.prefixlen == 24 and
            any(net.subnet_of(block) for block in rfc1918) and
            str(net) != "192.168.122.0/24",
            "Only RFC1918 nondefault /24 analysis subnets are candidates")
    host_ip = IPv4Address(int(net.network_address) + 1)
    # Policy chain accept applies only to OTHER traffic; our explicit
    # cape-lab0 drop rules never alter unrelated Docker/campus bridges.
    rules = (
        f"table inet {table} {{\n"
        "  chain cape_guest_forward {\n"
        "    type filter hook forward priority -150; policy accept;\n"
        f'    iifname "{bridge}" counter drop\n'
        "  }\n"
        "  chain cape_guest_input {\n"
        "    type filter hook input priority -150; policy accept;\n"
        f'    iifname "{bridge}" meta nfproto ipv6 counter drop\n'
        f'    iifname "{bridge}" ip daddr != {host_ip} counter drop\n'
        "  }\n"
        "}\n"
    )
    forbidden = ("flush ruleset", "delete table", "systemctl", "add chain",
                 "net-start", "iptables", "ufw", "ip link", "masquerade", "dnat")
    require(not any(x in rules.lower() for x in forbidden),
            "Generated rules contain an unapproved host/network action")
    return {
        "result": "COMMAND2_CANDIDATE_NFT_GUARD_RULES_ONLY",
        "analysis_bridge": bridge, "analysis_subnet": str(net),
        "host_bridge_ipv4": str(host_ip),
        "dedicated_nft_table": table,
        "ruleset_text": rules,
        "ruleset_sha256": hashlib.sha256(rules.encode()).hexdigest(),
        "creates_files": False, "changes_nftables": False,
        "changes_docker": False, "changes_campus_network": False,
        "changes_libvirt": False, "attaches_nics": False,
        "nft_syntax_on_target_verified": False,
        "ipv4_runtime_negative_egress_verified": False,
        "ipv6_runtime_negative_egress_verified": False,
        "l2_guest_segmentation_verified": False,
        "reboot_persistence_verified": False,
        "inet_sim_positive_paths_verified": False,
        "cape_positive_paths_verified": False,
        "deployment_authorized": False,
        "caution": "Candidate L3 isolation only. Verify existing nft priority, "
                   "bridge L2 traffic, all IPv4/IPv6 routes, host input policy, "
                   "persistence and CAPE/INetSim interoperability separately.",
    }


def main():
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--subnet", default="192.168.240.0/24")
    arguments = ap.parse_args()
    try:
        print(json.dumps(render_cape_egress_guard(arguments.subnet),
                         sort_keys=True, indent=2))
    except GuardPlanBlocked as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
