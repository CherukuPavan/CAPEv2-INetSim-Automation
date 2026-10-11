#!/usr/bin/env python3
"""Pure sequential Command 2 IP allocator: NEW VM = previous Windows clone IP+1.

The protected master 'win11' is NOT an analysis VM predecessor: it may
have a different libvirt default/NAT subnet. For a fresh analysis network
with no clones, the first guest starts at host bridge IPv4 + 100
(default 192.168.240.101). For existing, each guest IP MUST have been
verified inside Windows and the previous guest must be present.

Only plans; never reserves an address, attaches NICs, edits Windows,
creates VM definitions, or probes host routes.
"""
from __future__ import annotations
import ipaddress
import re

MAX_GUESTS = 16
RFC1918 = tuple(ipaddress.IPv4Network(s) for s in
                ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))


class SequentialIPBlocked(ValueError):
    pass


def require(check, reason):
    if not check:
        raise SequentialIPBlocked(reason)


def network_ok(cidr):
    try:
        network=ipaddress.IPv4Network(cidr,strict=True)
    except (TypeError,ValueError,AttributeError) as exc:
        raise SequentialIPBlocked("Invalid analysis subnet") from exc
    require(network.prefixlen==24 and
            any(network.subnet_of(parent) for parent in RFC1918) and
            str(network)!="192.168.122.0/24",
            "Only nondefault RFC1918 /24 analysis network supported")
    return network


def safe_ip(raw,network):
    require(type(raw) is str,"Expected a literal IPv4 string")
    try:
        ip=ipaddress.IPv4Address(raw)
    except (TypeError,ValueError,ipaddress.AddressValueError) as exc:
        raise SequentialIPBlocked("Unexpected IPv4 address") from exc
    require(str(ip)==raw and ip in network and
            ip != network.network_address and
            ip != network.broadcast_address,
            "IPv4 address not canonical usable private analysis address")
    return ip


def allocate(total, subnet="192.168.240.0/24", *,
             existing_verified=(), occupied_other_ips=()):
    """Return only NEW guest candidates, never touch 1..existing slots.

    existing_verified rows must contain name win11_N, ipv4, and
    verified_in_windows is True. Supplying such a row is an operator
    evidence claim, NOT this module independently observing Windows.
    """
    require(type(total) is int and 1<=total<=MAX_GUESTS,
            "Total Windows analysis guests must be 1..16")
    network=network_ok(subnet)
    bridge_ip=ipaddress.IPv4Address(int(network.network_address)+1)
    previous=ipaddress.IPv4Address(int(network.network_address)+100)
    seen_ips={bridge_ip}
    seen_names=set()
    rows=[]
    require(type(existing_verified) in (list,tuple),
            "Existing inventory must be an ordered list")
    for i,row in enumerate(existing_verified,1):
        require(type(row) is dict and
                row.get("libvirt_name")==f"win11_{i}" and
                row.get("verified_in_windows") is True and
                row.get("verification_source")=="guest_os_readback",
                "Existing clone inventory missing, out of order or not Windows-verified")
        actual=safe_ip(row.get("ipv4"),network)
        require(actual == ipaddress.IPv4Address(int(previous)+1) and
                actual not in seen_ips,
                "Existing analysis guest IP sequence is not strictly previous+1")
        previous=actual
        seen_ips.add(actual)
        seen_names.add(row["libvirt_name"])
        rows.append({"libvirt_name":row["libvirt_name"],
                     "ipv4":str(actual),
                     "already_verified_in_windows":True})
    require(len(rows)<=total,
            "Existing verified clones exceed requested TOTAL")
    other=set()
    for raw in occupied_other_ips:
        ip=safe_ip(raw,network)
        require(ip not in other,"Duplicated other-occupant IP inventory")
        other.add(ip)
    require(not (other & seen_ips),
            "Other occupied IP overlaps bridge or verified existing guest")
    new=[]
    for i in range(len(rows)+1,total+1):
        candidate=ipaddress.IPv4Address(int(previous)+1)
        require(candidate in network and candidate!=network.broadcast_address,
                "Previous+1 would exceed usable analysis subnet")
        require(candidate not in seen_ips and candidate not in other,
                "Exactly previous+1 IP is occupied: refuse rather than silently skip")
        name=f"win11_{i}"
        require(name not in seen_names,"Existing Windows guest name collision")
        new.append({"libvirt_name":name,"windows_hostname":f"WIN11-{i}",
                    "planned_ipv4":str(candidate),
                    "previous_analysis_guest_ipv4":str(previous),
                    "guest_static_ip_applied":False,
                    "nic_attached":False})
        previous=candidate
        seen_ips.add(candidate)
        seen_names.add(name)
    return {
        "result":"COMMAND2_PREVIOUS_ANALYSIS_VM_IP_PLUS_ONE_PLAN_ONLY",
        "subnet":str(network),"bridge_ipv4":str(bridge_ip),
        "requested_total":total,
        "existing_verified_guest_count":len(rows),
        "new_guest_count":len(new),
        "existing_guests":rows,"new_guests":new,
        "master_vm_excluded_from_sequence":True,
        "source_host_ips_verified_by_this_tool":False,
        "guest_static_ips_applied":False,
        "network_isolation_verified":False,
        "no_host_or_guest_changes":True,
    }


def main():
    import argparse,json,sys
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count",type=int,required=True)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--existing-json",help="JSON LIST of verified guest OS IP evidence")
    ap.add_argument("--other-occupied-ip",action="append",default=[])
    args=ap.parse_args()
    try:
        existing=json.loads(args.existing_json) if args.existing_json else []
        print(json.dumps(allocate(args.count,args.subnet,
              existing_verified=existing,
              occupied_other_ips=args.other_occupied_ip),indent=2,sort_keys=True))
        return 0
    except (SequentialIPBlocked,ValueError,TypeError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
