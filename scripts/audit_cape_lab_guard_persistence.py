#!/usr/bin/env python3
"""Read-only audit of CAPE nftables guard reboot persistence on a shared host.

No service enable/start/restart, nft modification, network activation,
NIC attachment, firewall reload, systemctl daemon-reload, or guest reboot.
Only prints allowlisted structural metadata; NEVER emits nftables.conf,
systemd unit text or sensitive firewall expressions.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

GUARD="cape_analysis_guard"
NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
VM="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
SERVICES=(
    "nftables.service","netfilter-persistent.service","iptables.service",
    "firewalld.service","ufw.service","docker.service",
    "libvirtd.service","virtnetworkd.service","virtqemud.service",
    "cape-lab-guard.service",
)
UNIT_VALUES=("LoadState","ActiveState","UnitFileState","ExecStart","ExecStop",
             "ExecReload","Before","After","FragmentPath","DropInPaths")

class AuditBlocked(RuntimeError):pass

def require(ok,message):
    if not ok:raise AuditBlocked(message)

def command(args,*,required=True,timeout=50):
    try:
        result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        if required:raise AuditBlocked("Cannot inspect "+args[0]) from exc
        return None
    if result.returncode!=0:
        if required:raise AuditBlocked("Read-only query failed: "+args[0])
        return None
    return result.stdout.strip()

def virsh(*args):
    return command(["virsh","-c","qemu:///system",*args])

def guest_network_gate():
    require(virsh("domstate","win11")=="shut off",
            "Original master is not shut off")
    require(virsh("domstate",VM)=="running",
            "Trial guest is not in expected running state")
    for arg in (("dumpxml",VM),("dumpxml","--inactive",VM)):
        root=ET.fromstring(virsh(*arg))
        require(root.findtext("name")==VM and root.findtext("uuid")==UUID and
                not root.findall("./devices/interface"),
                "Trial guest acquired a NIC or changed identity")
    info=virsh("net-info",NETWORK)
    require(re.search(r"^Active:\s+no\s*$",info,re.M|re.I),
            "Analysis network is unexpectedly active")
    require(re.search(r"^Autostart:\s+no\s*$",info,re.M|re.I),
            "Analysis network autostart is already enabled")
    root=ET.fromstring(virsh("net-dumpxml",NETWORK))
    bridge=root.find("bridge")
    require(root.findtext("name")==NETWORK and root.find("forward") is None and
            bridge is not None and bridge.get("name")==BRIDGE,
            "Analysis libvirt network definition changed")
    return True

def inspect_guard():
    raw=command(["nft","-j","list","table","inet",GUARD])
    try: items=json.loads(raw)["nftables"]
    except (ValueError,KeyError,TypeError) as exc:
        raise AuditBlocked("Unparseable CAPE guard structure") from exc
    require(isinstance(items,list) and len(items)<=1000,
            "Unexpected CAPE guard table size")
    tables=[x["table"] for x in items if isinstance(x,dict)
            and isinstance(x.get("table"),dict)]
    require(len(tables)==1 and tables[0].get("family")=="inet"
            and tables[0].get("name")==GUARD,
            "Expected dedicated CAPE guard table missing")
    chains={x["chain"].get("name"):x["chain"] for x in items
            if isinstance(x,dict) and isinstance(x.get("chain"),dict)}
    hooks={"cape_forward":"forward","cape_input":"input","cape_output":"output"}
    require(set(chains)==set(hooks),"CAPE guard chain set has changed")
    for name,hook in hooks.items():
        c=chains[name]
        require(c.get("hook")==hook and c.get("type")=="filter" and
                c.get("prio",c.get("priority"))==-50 and
                c.get("policy")=="accept",
                "CAPE guard base hook, priority or policy changed")
    rules={name:[] for name in hooks}
    for obj in items:
        if not isinstance(obj,dict) or not isinstance(obj.get("rule"),dict):
            continue
        r=obj["rule"]
        require(r.get("family")=="inet" and r.get("table")==GUARD and
                r.get("chain") in rules,"Unexpected CAPE guard rule")
        actions=[v for expr in r.get("expr",[]) if isinstance(expr,dict)
                 for v in ("accept","drop") if v in expr]
        require(len(actions)==1,"CAPE nft expression has changed")
        rules[r["chain"]].append(actions[0])
    require(rules=={"cape_forward":["drop","drop"],
                    "cape_input":["accept","drop"],
                    "cape_output":["accept","drop"]},
            "CAPE nft guard rule order changed")
    # This is structure only; other code has already checked interface/address.
    return {"family":"inet","table":GUARD,"priority":-50,
            "expected_hook_chains_verified":True,
            "rule_verdict_order_verified":True}

def analyze_nftables_conf(path:Path)->dict:
    result={"exists":path.exists() or path.is_symlink(),
            "is_symlink":path.is_symlink(),"safe_to_replace":False}
    if not result["exists"]:return result
    if path.is_symlink():
        result["inspection"]="BLOCKED_SYMLINK"
        return result
    state=path.stat()
    if not stat.S_ISREG(state.st_mode) or state.st_size>2*1024*1024:
        result["inspection"]="BLOCKED_TYPE_OR_SIZE"
        return result
    try:
        lines=path.read_text(encoding="utf-8",errors="replace").splitlines()
    except OSError:
        result["inspection"]="UNREADABLE"
        return result
    # Remove '#' comments; no content is displayed outside this function.
    executable=[line.split("#",1)[0].strip() for line in lines]
    executable=[line for line in executable if line]
    whole="\n".join(executable)
    result.update({
        "inspection":"STRUCTURE_ONLY",
        "file_root_owned":state.st_uid==0,
        "noncomment_line_count":len(executable),
        "flush_ruleset_present":bool(re.search(r"(?m)^flush\s+ruleset\b",whole)),
        "other_flush_or_delete_present":bool(re.search(
            r"(?m)^\s*(?:flush\s+(?!ruleset\b)|delete\s+)",whole)),
        "include_directive_count":sum(
            bool(re.match(r"^include\s+",line)) for line in executable),
        "has_cape_guard_table_definition":bool(re.search(
            r"\btable\s+inet\s+cape_analysis_guard\b",whole)),
        "safe_to_replace":False,
    })
    return result

def summarize_unit(raw:str|None,name:str)->dict:
    if raw is None:
        return {"unit":name,"inspectable":False}
    parsed={}
    for line in raw.splitlines():
        key,sep,value=line.partition("=")
        if sep and key in UNIT_VALUES:
            parsed[key]=value
    enabled=parsed.get("UnitFileState","unknown")
    active=parsed.get("ActiveState","unknown")
    load=parsed.get("LoadState","unknown")
    cmdline="\n".join(parsed.get(field,"") for field in
                       ("ExecStart","ExecStop","ExecReload"))
    return {"unit":name,"inspectable":True,
            "load_state":load if load in
             ("loaded","not-found","masked","error","bad-setting") else "OTHER",
            "active_state":active if active in
             ("active","inactive","failed","activating","deactivating") else "OTHER",
            "enable_state":enabled if enabled in (
                "enabled","disabled","static","masked","indirect","alias",
                "generated","transient","linked","linked-runtime",
                "enabled-runtime","masked-runtime") else "OTHER",
            "exec_mentions_nft":bool(re.search(r"\bnft\b",cmdline)),
            "exec_mentions_iptables_restore":bool(re.search(
                r"iptables-restore|ip6tables-restore",cmdline)),
            "unit_mentions_flush_ruleset":bool(re.search(
                r"flush\s+ruleset",cmdline,re.I)),
            "before_docker":bool(re.search(r"\bdocker\.service\b",
                parsed.get("Before",""))),
            "before_virtnetworkd":bool(re.search(
                r"\bvirtnetworkd\.service\b",parsed.get("Before",""))),
            "before_libvirtd":bool(re.search(
                r"\blibvirtd\.service\b",parsed.get("Before",""))),
            "after_network_pre":bool(re.search(
                r"\bnetwork-pre\.target\b",parsed.get("After",""))),
            "unit_dropins_present":bool(parsed.get("DropInPaths","").strip()),
            "raw_unit_commands_uploaded":False}

def inventory():
    guest_network_gate()
    guard=inspect_guard()
    units=[]
    for unit in SERVICES:
        raw=command(["systemctl","show","--no-pager",
                     *[f"--property={key}" for key in UNIT_VALUES],unit],
                    required=False)
        units.append(summarize_unit(raw,unit))
    info=command(["systemctl","cat","--no-pager","nftables.service"],
                 required=False)
    unit_scan={"nftables_unit_text_readable":info is not None,
               "unit_text_mentions_flush_ruleset":
                   bool(re.search(r"(?m)^\s*(?:ExecStart|ExecStop|ExecReload).*flush\s+ruleset",
                                  info or "")),
               "unit_text_mentions_nftables_conf":
                   "/etc/nftables.conf" in (info or ""),
               "raw_unit_text_uploaded":False}
    config=analyze_nftables_conf(Path("/etc/nftables.conf"))
    guest_network_gate()
    # Never state persistence is verified from a status/config inspection.
    return {"result":"CAPE_GUARD_PERSISTENCE_READ_ONLY_AUDIT",
            "guest_vm_nics":0,"lab_network_active":False,
            "guard":guard,
            "service_units":units,
            "nftables_unit":unit_scan,
            "nftables_conf":config,
            "services_enabled_or_modified":False,
            "nft_tables_changed":False,
            "libvirt_network_changed":False,
            "guard_reboot_persistence_verified":False,
            "analysis_network_approved":False,
            "warning":"Do not enable/restart nftables.service or flush ruleset on shared host. Need safe dedicated boot-ordered guard service and test before lab network activation."}

def main():
    try:
        print(json.dumps(inventory(),indent=2,sort_keys=True),flush=True)
        return 0
    except (AuditBlocked,OSError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        return 2
if __name__=="__main__":
    sys.exit(main())
