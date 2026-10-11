#!/usr/bin/env python3
"""Pure libvirt isolated CAPE subnet XML design; NO host/network changes.

Contains NO forward, default NAT, route, DHCP, exposed DNS, NIC attachment,
or guest boots. Produces a candidate network definition for independent
review and separate-host IPv4+IPv6 containment testing.
"""
from __future__ import annotations
from ipaddress import IPv4Address, IPv4Network
import re
import xml.etree.ElementTree as ET


class NetworkPlanBlocked(ValueError):
    pass


def need(value, why):
    if not value:
        raise NetworkPlanBlocked(why)


def plan(network_name, bridge_name, subnet, reserved_ips=()):
    need(network_name == "cape-analysis-isolated",
         "Unexpected CAPE network name")
    need(bridge_name == "cape-lab0",
         "Unexpected CAPE bridge name")
    try:
        net = IPv4Network(subnet, strict=True)
    except (ValueError, TypeError) as e:
        raise NetworkPlanBlocked("Unparseable analysis subnet") from e
    need(net.is_private and net.prefixlen == 24 and
         str(net) != "192.168.122.0/24" and not net.is_link_local,
         "Analysis network must use a private nondefault /24")
    host_ip = IPv4Address(int(net.network_address) + 1)
    used = {str(host_ip)}
    for raw in reserved_ips:
        try:
            addr = IPv4Address(raw)
        except (ValueError, TypeError) as e:
            raise NetworkPlanBlocked("Invalid reserved VM IPv4") from e
        need(addr in net and addr not in (net.network_address, net.broadcast_address)
             and str(addr) not in used,
             "Duplicate, host-owned or off-subnet guest address")
        used.add(str(addr))
    network = ET.Element("network")
    ET.SubElement(network, "name").text = network_name
    ET.SubElement(network, "bridge", {"name":bridge_name,"stp":"off","delay":"0"})
    ET.SubElement(network, "dns", {"enable":"no"})
    ET.SubElement(network, "ip", {"address":str(host_ip),
                                 "netmask":str(net.netmask)})
    text = ET.tostring(network,encoding="unicode")
    parsed = ET.fromstring(text)
    need(parsed.find("forward") is None and parsed.find(".//route") is None
         and parsed.find(".//dhcp") is None and
         parsed.find("./dns").get("enable") == "no",
         "Generated network is not a completely isolated no-DHCP design")
    return {"result":"COMMAND2_ISOLATED_NETWORK_XML_PLAN_ONLY",
            "network":network_name, "bridge":bridge_name,
            "ipv4_subnet":str(net), "bridge_ipv4":str(host_ip),
            "libvirt_network_xml":text,
            "libvirt_forward_present":False,
            "dns_enabled":False,"dhcp_enabled":False,
            "guest_ipv6_disabled_or_blocked_verified":False,
            "nftables_guard_installed":False,
            "nftables_guard_reboot_verified":False,
            "ipv4_external_egress_negative_test":False,
            "ipv6_external_egress_negative_test":False,
            "cape_host_to_guest_path_verified":False,
            "network_defined_on_host":False,"network_started":False,
            "guest_nic_attached":False,"nic_attachment_authorized":False}


if __name__ == "__main__":
    import argparse,json,sys
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--vm-ip",action="append",default=[])
    args=ap.parse_args()
    try:
        print(json.dumps(plan("cape-analysis-isolated","cape-lab0",
                              args.subnet,args.vm_ip),indent=2,sort_keys=True))
    except NetworkPlanBlocked as e:
        print("BLOCKED: "+str(e),file=sys.stderr)
        raise SystemExit(2)
