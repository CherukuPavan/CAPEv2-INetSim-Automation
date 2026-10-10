#!/usr/bin/env python3
"""Read-only SSL-55 host route/firewall topology inventory for isolated CAPE NIC design.

Does NOT change sysctls, libvirt, NICs, iptables, nftables, UFW or Docker.
Sanitizes firewall rule expressions/addresses; output is a design input only,
never proof of guest egress isolation.
"""
from __future__ import annotations
from collections import Counter
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

TRIAL="win11_trial_1"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
MAX_ROUTES=4096

class NetworkContextError(RuntimeError):pass

def require(ok,message):
    if not ok:raise NetworkContextError(message)

def query(args,timeout=30):
    try:
        p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode==0 else None

def virsh(*args):
    r=query(["virsh","-c","qemu:///system",*args])
    require(r is not None,"Cannot read libvirt state")
    return r.strip()

def check_untouched_guest():
    require(virsh("domstate","win11")=="shut off","Original master is not shut off")
    require(virsh("domstate",TRIAL)=="running","Trial VM not running")
    for options in (("dumpxml",TRIAL),("dumpxml","--inactive",TRIAL)):
        xml=ET.fromstring(virsh(*options))
        require(xml.findtext("name")==TRIAL and
                xml.findtext("uuid")==TRIAL_UUID and
                not xml.findall("./devices/interface"),
                "Trial guest changed or unexpectedly has a NIC")

def read_ip_json(family,*args):
    result=query(["ip","-j",family,*args])
    require(result is not None,"Cannot read iproute2 "+family+" data")
    obj=json.loads(result)
    require(isinstance(obj,list) and len(obj)<=MAX_ROUTES,
            "Unexpected route/interface count")
    return obj

def summarize_routes(routes,family):
    rows=[]
    for item in routes:
        if not isinstance(item,dict):continue
        dest=item.get("dst","default")
        try:
            subnet="default" if dest=="default" else str(ipaddress.ip_network(dest,strict=False))
        except ValueError:
            subnet="UNPARSEABLE"
        rows.append({"dst":subnet,
                     "dev":str(item.get("dev","UNKNOWN"))[:100],
                     "table":str(item.get("table","main"))[:30],
                     "type":str(item.get("type","unicast"))[:30]})
    return rows

def summarize_addresses(records):
    out=[]
    for entry in records:
        if not isinstance(entry,dict):continue
        iface=str(entry.get("ifname","UNKNOWN"))[:100]
        prefixes=[]
        for a in entry.get("addr_info",[]):
            if not isinstance(a,dict) or a.get("family")!="inet":continue
            try:
                cidr=ipaddress.IPv4Interface(
                    str(a["local"])+"/"+str(a["prefixlen"])).network
                prefixes.append(str(cidr))
            except (KeyError,ValueError,TypeError):
                prefixes.append("UNKNOWN")
        out.append({"interface":iface,"ipv4_subnets":sorted(set(prefixes)),
                    "operstate":str(entry.get("operstate","UNKNOWN"))[:32]})
    return out

def summarize_nft(raw):
    if raw is None:return {"available":False}
    try:
        obj=json.loads(raw)
        records=obj["nftables"]
        require(isinstance(records,list) and len(records)<=50000,
                "Unexpected nftables ruleset length")
        chains=[]
        counts=Counter()
        family_tables=set()
        for entry in records:
            if not isinstance(entry,dict):continue
            if isinstance(entry.get("table"),dict):
                t=entry["table"]
                family_tables.add((str(t.get("family","?")),str(t.get("name","?"))))
            if isinstance(entry.get("chain"),dict):
                ch=entry["chain"]
                chains.append({"family":ch.get("family"),"table":ch.get("table"),
                     "chain":ch.get("name"),"hook":ch.get("hook","none"),
                     "policy":ch.get("policy","none")})
            if isinstance(entry.get("rule"),dict):
                rule=entry["rule"]
                expressions=rule.get("expr",[])
                if isinstance(expressions,list):
                    keys={str(k) for e in expressions if isinstance(e,dict) for k in e}
                    for key in ("accept","drop","reject","masquerade","snat","dnat",
                                "jump","goto","queue","notrack"):
                        if key in keys:counts[key]+=1
                counts["total"]+=1
        return {"available":True,"tables":[{"family":f,"name":t}
                      for f,t in sorted(family_tables)][:100],
                "chains":chains[:250],"rule_count":counts["total"],
                "action_counts":dict(counts)}
    except (ValueError,TypeError,KeyError,NetworkContextError):
        return {"available":True,"parse":"UNAVAILABLE"}

def summarize_iptables(tool,table):
    if not shutil.which(tool):return {"available":False}
    args=[tool,"-w","2","-t",table,"-S"]
    raw=query(args)
    if raw is None:return {"available":True,"readable":False}
    lines=raw.splitlines()
    require(len(lines)<=50000,"Unexpected iptables output")
    policies={}
    chains=Counter()
    actions=Counter()
    for line in lines:
        fields=line.split()
        if len(fields)>=3 and fields[0]=="-P":
            policies[fields[1]]=fields[2]
        if len(fields)>=3 and fields[0]=="-A":
            chains[fields[1]]+=1
            for n,x in enumerate(fields):
                if x in ("-j","--jump","-g","--goto") and n+1<len(fields):
                    actions[fields[n+1]]+=1
    return {"available":True,"readable":True,"table":table,
            "policies":policies,"chains":dict(chains),
            "target_counts":dict(actions)}

def main():
    check_untouched_guest()
    interfaces=read_ip_json("-4","address","show")
    ip4=read_ip_json("-4","route","show","table","all")
    ip6=read_ip_json("-6","route","show","table","all")
    rule4=read_ip_json("-4","rule","show")
    rule6=read_ip_json("-6","rule","show")
    nft=summarize_nft(query(["nft","-j","list","ruleset"]) if shutil.which("nft") else None)
    ipt=[summarize_iptables(tool,table)
         for tool in ("iptables","ip6tables") for table in ("filter","nat")]
    ufw=query(["ufw","status"]) if shutil.which("ufw") else None
    ufwstatus=next((x.strip() for x in (ufw or "").splitlines()
                    if x.lower().startswith("status:")),"UNKNOWN")
    candidates=["10.202.253.0/24","172.29.250.0/24","192.168.240.0/24"]
    used=[]
    for entry in ip4:
        if not isinstance(entry,dict):continue
        try:
            if entry.get("dst","default")!="default":
                used.append(ipaddress.ip_network(entry["dst"],strict=False))
        except (ValueError,KeyError,TypeError):pass
    for record in summarize_addresses(interfaces):
        for n in record["ipv4_subnets"]:
            try:used.append(ipaddress.ip_network(n))
            except ValueError:pass
    checks=[]
    for candidate in candidates:
        net=ipaddress.ip_network(candidate)
        checks.append({"provisional_cidr":candidate,
                       "overlaps_local_host_routes_or_addresses":
                           any(net.overlaps(x) for x in used if x.version==4),
                       "remote_site_collision_unknown":True})
    return {
        "result":"HOST_ANALYSIS_NETWORK_CONTEXT_READ_ONLY",
        "master_shutoff":True,"trial_running_zero_nics":True,
        "ipv4_interfaces":summarize_addresses(interfaces),
        "ipv4_routes":summarize_routes(ip4,"v4"),
        "ipv6_route_count":len(ip6),
        "ipv4_policy_rule_count":len(rule4),
        "ipv6_policy_rule_count":len(rule6),
        "iptables":ipt,"nftables":nft,"ufw":ufwstatus,
        "subnet_candidates_not_approved":checks,
        "host_network_modified":False,
        "host_firewall_modified":False,
        "guest_network_modified":False,
        "egress_containment_proved":False,
        "note":"Read-only topology, firewall policy and route inventory only. No candidate approved until design + negative egress tests."
    }

if __name__=="__main__":
    try:
        print(json.dumps(main(),indent=2,sort_keys=True))
    except (OSError,NetworkContextError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        sys.exit(2)
