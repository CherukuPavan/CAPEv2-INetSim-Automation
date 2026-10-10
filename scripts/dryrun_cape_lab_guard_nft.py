#!/usr/bin/env python3
"""Read-only nftables candidate-policy validation for SSL-55 CAPE lab bridge.

This tool NEVER applies firewall rules: calls only nft --check --file.
The libvirt cape-analysis-isolated network MUST remain INACTIVE and the
win11_trial_1 VM MUST have zero NICs. A passing dry-run does not prove
runtime isolation. No malware must be executed based on this result.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
TABLE="cape_analysis_guard"
ADDRESS="192.168.240.1"
SUBNET="192.168.240.0/24"
TRIAL="win11_trial_1"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"

class DryRunBlocked(RuntimeError): pass

def need(ok:bool,msg:str):
    if not ok: raise DryRunBlocked(msg)

def execute(*args,timeout=90):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise DryRunBlocked("Unable to execute "+args[0]) from e
    need(p.returncode==0,"Read-only command failed: "+args[0]+
         " (exit="+str(p.returncode)+")")
    return p.stdout.strip()

def virsh(*args):
    return execute("virsh","-c","qemu:///system",*args)

def policy_text():
    # At dry-run stage only: no INetSim guest-initiated services yet.
    # FORWARD: stop routed lab traffic in either direction.
    # INPUT: accept only established/related replies from the lab,
    # directed at the host's CAPE-side IPv4 address.
    # OUTPUT: allow host-initiated CAPE agent TCP 8000 only.
    # Other host networking/interfaces are outside these interface matches.
    return f'''table inet {TABLE} {{
    chain cape_forward {{
        type filter hook forward priority -50; policy accept;
        iifname "{BRIDGE}" drop
        oifname "{BRIDGE}" drop
    }}
    chain cape_input {{
        type filter hook input priority -50; policy accept;
        iifname "{BRIDGE}" ip daddr {ADDRESS} ct state established,related accept
        iifname "{BRIDGE}" drop
    }}
    chain cape_output {{
        type filter hook output priority -50; policy accept;
        oifname "{BRIDGE}" ip daddr {SUBNET} tcp dport 8000 accept
        oifname "{BRIDGE}" drop
    }}
}}
'''

def validate_policy(source:str):
    need("flush ruleset" not in source and "delete table" not in source,
         "Draft contains a destructive nftables operation")
    root=f"table inet {TABLE} {{"
    need(source.startswith(root),"Unexpected nftables table family/name")
    for token in ('hook forward priority -50; policy accept;',
                  'hook input priority -50; policy accept;',
                  'hook output priority -50; policy accept;',
                  f'iifname "{BRIDGE}" drop',
                  f'oifname "{BRIDGE}" drop',
                  f'iifname "{BRIDGE}" ip daddr {ADDRESS} ct state established,related accept',
                  f'oifname "{BRIDGE}" ip daddr {SUBNET} tcp dport 8000 accept'):
        need(token in source,"Missing fail-closed proposed nft guard expression")
    need(source.count('type filter hook ')==3,"Unexpected nft hook count")
    need(source.count('drop')==4,"Unexpected nft guard-drop count")
    need(source.count(' accept')==2,"Unexpected nft explicit-accept count")

def check_guest_and_network():
    need(os.geteuid()==0,"Run using sudo")
    need(virsh("domstate","win11")=="shut off",
         "Original master unexpectedly running")
    need(virsh("domstate",TRIAL)=="running",
         "Trial clone must be running with zero NICs")
    for args in (("dumpxml",TRIAL),("dumpxml","--inactive",TRIAL)):
        guest=ET.fromstring(virsh(*args))
        need(guest.findtext("uuid")==TRIAL_UUID and
             guest.findtext("name")==TRIAL and
             not guest.findall("./devices/interface"),
             "Trial clone identity or zero-NIC status changed")
    info=virsh("net-info",NETWORK)
    need(re.search(r"^Active:\s+no\s*$",info,re.M|re.I) is not None,
         "Lab network is not inactive")
    need(re.search(r"^Autostart:\s+no\s*$",info,re.M|re.I) is not None,
         "Lab network autostart is enabled")
    xml=ET.fromstring(virsh("net-dumpxml",NETWORK))
    need(xml.tag=="network" and xml.findtext("name")==NETWORK,
         "Lab network identity differs")
    need(xml.find("forward") is None,"Lab network has forwarding")
    b=xml.find("bridge")
    p=xml.find("port")
    dns=xml.find("dns")
    ips=xml.findall("ip")
    need(b is not None and b.get("name")==BRIDGE and
         p is not None and p.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         len(ips)==1 and ips[0].get("address")==ADDRESS and
         ips[0].get("netmask")=="255.255.255.0" and
         ips[0].find("dhcp") is None,
         "Inactive libvirt candidate differs from approved design")
    interfaces=json.loads(execute("ip","-j","link","show"))
    need(isinstance(interfaces,list) and
         not any(i.get("ifname")==BRIDGE for i in interfaces),
         "Lab bridge exists unexpectedly; abort dry-run gate")
    return True

def nft_tables(raw):
    try:
        object=json.loads(raw)
        entries=object["nftables"]
        need(isinstance(entries,list),"Unexpected nftables JSON")
        return sorted((str(x["table"].get("family")),
                       str(x["table"].get("name")))
                      for x in entries if isinstance(x,dict)
                      and isinstance(x.get("table"),dict))
    except (ValueError,TypeError,KeyError) as e:
        raise DryRunBlocked("Invalid nftables table inventory") from e

def perform():
    check_guest_and_network()
    src=policy_text()
    validate_policy(src)
    before=nft_tables(execute("nft","-j","list","ruleset"))
    need(("inet",TABLE) not in before,
         "Guard table already exists: refuse to overwrite it")
    with tempfile.TemporaryDirectory(prefix="cape-nft-check-",dir="/run") as td:
        path=Path(td)/"candidate.nft"
        path.write_text(src,encoding="utf-8")
        path.chmod(0o600)
        # nft --check does not apply changes to the kernel ruleset.
        execute("nft","--check","--file",str(path))
    after=nft_tables(execute("nft","-j","list","ruleset"))
    need(before==after,"Host nft table inventory changed during dry-run")
    check_guest_and_network()
    return {"result":"LAB_GUARD_NFT_DRY_RUN_PASSED",
            "network":NETWORK,"bridge":BRIDGE,
            "network_active":False,"trial_vm_nics":0,
            "draft_nft_table":TABLE,
            "policy_sha256":hashlib.sha256(src.encode()).hexdigest(),
            "priority":-50,"family":"inet",
            "draft_rules":{"forward":"DROP both directions on lab bridge",
                           "input":"ALLOW established replies to lab-host IPv4 only; DROP other lab ingress",
                           "output":"ALLOW IPv4 host-to-guest TCP/8000; DROP other host egress to lab"},
            "external_host_interfaces_mentioned":False,
            "nft_check_only":True,
            "host_firewall_modified":False,
            "host_network_modified":False,
            "guest_nic_attached":False,
            "runtime_egress_containment_verified":False,
            "inerTSim_services_enabled":False,
            "note":"Syntax-only draft. Do NOT start network or attach guest NICs until reviewed, installed and runtime negative tests succeed."}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=["check"],default="check")
    parser.parse_args()
    try:
        print(json.dumps(perform(),indent=2,sort_keys=True),flush=True)
        return 0
    except (DryRunBlocked,OSError,ET.ParseError,ValueError) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
