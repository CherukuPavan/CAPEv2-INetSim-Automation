#!/usr/bin/env python3
"""Read-only SSL-55 libvirt network inventory before clone NIC customization.

Classifies libvirt virtual networks by XML *only*; nonforward XML is
only a candidate, NEVER a verified egress-isolation certificate.
No new networks, NICs, firewall changes, guest boots or malware samples.
Do not copy full libvirt XML / host firewall / user data into logs.
"""
from __future__ import annotations
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

MAX_NETWORKS = 128
NET_NAME = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")

class NetworkAuditError(RuntimeError):
    pass

def require(ok:bool, message:str)->None:
    if not ok:raise NetworkAuditError(message)

def check_network_xml(xml_text:str)->dict:
    try:
        root=ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NetworkAuditError("Malformed libvirt network XML") from exc
    require(root.tag=="network","Unexpected libvirt network root")
    name=root.findtext("name")
    require(isinstance(name,str) and NET_NAME.fullmatch(name),
            "Unexpected network name")
    bridge=root.find("bridge")
    bridge_name=bridge.get("name") if bridge is not None else None
    forward=root.find("forward")
    forward_mode=forward.get("mode","unspecified") if forward is not None else "none"
    virtualports=root.findall("virtualport")
    portgroups=root.findall("portgroup")
    addresses=[]
    ipv6_present=False
    unknown_ip=False
    for ip in root.findall("ip"):
        address=ip.get("address")
        family=ip.get("family","ipv4")
        if family=="ipv6" or (address and ":" in address):
            ipv6_present=True
            continue
        if family!="ipv4" or not address:
            unknown_ip=True
            continue
        subnet=ip.get("netmask")
        prefix=ip.get("prefix")
        try:
            require(bool(subnet) != bool(prefix),
                    "Ambiguous libvirt network IPv4 prefix/netmask")
            length=ipaddress.IPv4Network("0.0.0.0/"+(subnet or prefix)).prefixlen
            interface=ipaddress.IPv4Interface(address+"/"+str(length))
        except (ValueError,NetworkAuditError) as exc:
            unknown_ip=True
            continue
        dhcp=ip.find("dhcp")
        ranges=[]
        if dhcp is not None:
            for item in dhcp.findall("range"):
                low=item.get("start")
                high=item.get("end")
                if low and high:
                    try:
                        start=ipaddress.IPv4Address(low)
                        stop=ipaddress.IPv4Address(high)
                        if start > stop or start not in interface.network or stop not in interface.network:
                            unknown_ip=True
                            continue
                        ranges.append({"from":str(start),"to":str(stop)})
                    except ValueError:
                        unknown_ip=True
        addresses.append({"bridge_ipv4":str(interface.ip),
                          "subnet":str(interface.network),
                          "dhcp_ranges":ranges,
                          "dhcp_reservations":len(dhcp.findall("host")) if dhcp is not None else 0})
    reasons=[]
    if forward is not None:reasons.append("FORWARDING_XML_PRESENT")
    if name=="default":reasons.append("DEFAULT_LIBVIRT_NETWORK_NOT_FOR_ANALYSIS")
    if not bridge_name:reasons.append("NO_BRIDGE")
    if ipv6_present:reasons.append("IPV6_XML_PRESENT")
    if len(addresses)!=1 or unknown_ip:reasons.append("AMBIGUOUS_IPV4_NETWORK")
    if virtualports or portgroups:reasons.append("UNKNOWN_PORT_VIRTUALIZATION")
    if root.find("dns") is not None:
        # DNS itself does not establish egress, but could mask the lab's
        # planned Inetsim service. Explicitly document this ambiguity.
        reasons.append("LIBVIRT_DNS_CONFIG_PRESENT")
    # Other host routing/firewall/cross-interface details are unknown.
    return {"name":name,
            "bridge":bridge_name,
            "forward_mode":forward_mode,
            "ipv4":addresses,
            "has_ipv6_xml":ipv6_present,
            "xml_candidate_only":not reasons,
            "blocking_or_review_reasons":reasons,
            "host_egress_isolation_verified":False}

def run(*args:str)->str:
    try:
        return subprocess.run(args,check=True,text=True,capture_output=True,
                              timeout=45).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise NetworkAuditError("Failed read-only host command: "+args[0]) from e

def virsh(*args:str)->str:
    return run("virsh","-c","qemu:///system",*args)

def check_guest_zero_nic()->None:
    require(virsh("domstate","win11")=="shut off",
            "Original master unexpectedly running")
    require(virsh("domstate","win11_trial_1")=="running",
            "Trial clone must be running for this inventory")
    live=ET.fromstring(virsh("dumpxml","win11_trial_1"))
    inactive=ET.fromstring(virsh("dumpxml","--inactive","win11_trial_1"))
    for data in (live,inactive):
        require(data.findtext("uuid")=="e75f6fef-347d-462f-9738-4de3df6bfa74",
                "Trial identity unexpectedly changed")
        require(not data.findall("./devices/interface"),
                "Unexpected network interface appeared in the trial")

def inventory()->dict:
    check_guest_zero_nic()
    names=virsh("net-list","--all","--name").splitlines()
    require(0<=len(names)<=MAX_NETWORKS,"Unexpected number of libvirt networks")
    require(len(names)==len(set(names)),"Duplicate libvirt network entries")
    networks=[]
    for name in sorted(names):
        require(bool(NET_NAME.fullmatch(name)),"Unexpected libvirt network name")
        record=check_network_xml(virsh("net-dumpxml",name))
        require(record["name"]==name,"Libvirt network name mismatch")
        info=virsh("net-info",name)
        active=re.search(r"^Active:\s+(yes|no)\s*$",info,re.M|re.I)
        require(active is not None,"Cannot determine network active state")
        record["active"]=active.group(1).lower()=="yes"
        networks.append(record)
    def sysctl(path):
        p=Path(path)
        return p.read_text().strip() if p.is_file() else "UNKNOWN"
    return {
        "result":"LIBVIRT_NETWORK_CANDIDATE_INVENTORY_READ_ONLY",
        "master_vm_shut_off":True,
        "trial_guest_running_no_nic":True,
        "network_count":len(networks),
        "networks":networks,
        "host_ipv4_forwarding":sysctl("/proc/sys/net/ipv4/ip_forward"),
        "host_ipv6_forwarding":sysctl("/proc/sys/net/ipv6/conf/all/forwarding"),
        "network_connection_changed":False,
        "host_firewall_changed":False,
        "clone_windows_registry_changed":False,
        "host_egress_isolation_verified":False,
        "note":"This is libvirt XML only. Do NOT attach trial NIC until route/firewall/negative-egress checks."
    }

def main()->int:
    try:
        print(json.dumps(inventory(),indent=2,sort_keys=True),flush=True)
        return 0
    except (NetworkAuditError,ET.ParseError,OSError,ValueError) as e:
        print("BLOCKED: "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
