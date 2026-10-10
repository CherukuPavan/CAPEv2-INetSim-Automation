#!/usr/bin/env python3
"""Read-only, allowlisted firewall chain order and nft hook-priority inventory.

No firewall rule content, addresses, secrets, packet counters or user-supplied
comments are reported. Structural ordering/targets only. Is NOT certification
that a future malware-analysis interface has no egress.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
MAX_LINES=50000
CHAIN=re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")
IFACE=re.compile(r"[A-Za-z0-9_.:+-]{1,100}\Z")
TARGET=re.compile(r"[A-Za-z0-9_.:-]{1,120}\Z")

class RuleAuditError(RuntimeError):pass

def need(ok,msg):
    if not ok:raise RuleAuditError(msg)

def read_command(*args):
    try:
        p=subprocess.run(args,check=False,capture_output=True,text=True,timeout=60)
    except (OSError,subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode==0 else None

def virsh(*args):
    out=read_command("virsh","-c","qemu:///system",*args)
    need(out is not None,"Cannot read libvirt state")
    return out.strip()

def scrub(raw,pattern):
    if isinstance(raw,str) and pattern.fullmatch(raw):return raw
    return "REDACTED"

def preflight():
    need(virsh("domstate","win11")=="shut off","Original master not shut off")
    need(virsh("domstate",VM)=="running","Trial VM not running")
    for args in (("dumpxml",VM),("dumpxml","--inactive",VM)):
        xml=ET.fromstring(virsh(*args))
        need(xml.findtext("name")==VM and xml.findtext("uuid")==UUID and
             not xml.findall("./devices/interface"),
             "VM identity changed or guest NIC attached")
    return True

def parse_iptables(text, family, table):
    lines=text.splitlines()
    need(len(lines)<=MAX_LINES,"Excessive iptables output")
    result={"family":family,"table":table,
            "policies":{},"ordered_chains":[]}
    counts={}
    ordered=[]
    for line in lines:
        tokens=line.split()
        if len(tokens)>=3 and tokens[0]=="-P":
            chain=scrub(tokens[1],CHAIN)
            result["policies"][chain]=scrub(tokens[2],TARGET)
        if len(tokens)>=3 and tokens[0]=="-A":
            chain=scrub(tokens[1],CHAIN)
            counts[chain]=counts.get(chain,0)+1
            actions=[]
            interfaces=[]
            known={"-j":"jump","--jump":"jump","-g":"goto","--goto":"goto",
                   "-i":"iif","--in-interface":"iif",
                   "-o":"oif","--out-interface":"oif"}
            for idx, token in enumerate(tokens[:-1]):
                if token in known:
                    val=tokens[idx+1]
                    if token in ("-i","--in-interface","-o","--out-interface"):
                        interfaces.append({known[token]:scrub(val,IFACE)})
                    else:
                        actions.append({known[token]:scrub(val,TARGET)})
            ordered.append({"chain":chain,"position":counts[chain],
                            "actions":actions,"interfaces":interfaces,
                            "unreported_conditions_present":True})
    need(len(ordered)<=MAX_LINES,"Excessive chain rules")
    result["ordered_chains"]=ordered
    return result

def parse_nft(text):
    try:
        obj=json.loads(text)
        entries=obj["nftables"]
        need(isinstance(entries,list) and len(entries)<=MAX_LINES,
             "Excessive nftables output")
    except (ValueError,TypeError,KeyError) as exc:
        raise RuleAuditError("Cannot parse nftables JSON") from exc
    chains=[]
    for row in entries:
        if not isinstance(row,dict) or not isinstance(row.get("chain"),dict):
            continue
        c=row["chain"]
        hook=c.get("hook")
        if hook not in ("input","output","forward","prerouting","postrouting"):
            continue
        priority=c.get("prio",c.get("priority","UNKNOWN"))
        # Preserve integer/known textual priority only, never raw expression.
        if not isinstance(priority,int):
            priority=priority if priority in ("raw","mangle","dstnat","filter","security","srcnat") else "UNKNOWN"
        chains.append({
            "family":scrub(c.get("family"),TARGET),
            "table":scrub(c.get("table"),CHAIN),
            "chain":scrub(c.get("name"),CHAIN),
            "hook":hook,"priority":priority,
            "policy":c.get("policy") if c.get("policy") in ("accept","drop") else "UNKNOWN"
        })
    return chains

def main():
    preflight()
    out={"result":"FIREWALL_CHAIN_ORDER_READ_ONLY",
         "master_shutoff":True,"trial_running_zero_nics":True,
         "iptables_ordered":[],"nft_base_chains":[],
         "host_policy_changed":False,"network_changed":False,
         "isolation_approved":False}
    for program in ("iptables","ip6tables"):
        for table in ("filter","nat"):
            result=read_command(program,"-w","2","-t",table,"-S")
            if result is None:
                out["iptables_ordered"].append(
                    {"family":program,"table":table,"available":False})
            else:
                data=parse_iptables(result,program,table)
                data["available"]=True
                out["iptables_ordered"].append(data)
    raw=read_command("nft","-j","list","ruleset")
    if raw is None:
        out["nft_readable"]=False
    else:
        out["nft_readable"]=True
        out["nft_base_chains"]=parse_nft(raw)
    out["note"]="Match conditions deliberately omitted. This is only a rule-order design audit; no analysis network can be attached or samples run based on these results."
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    try:main()
    except (RuleAuditError,OSError,ET.ParseError,ValueError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        sys.exit(2)
