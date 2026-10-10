#!/usr/bin/env python3
"""Guarded, create-only ephemeral CAPE lab nftables guard installation.

No bridge/network activation, guest NIC attachment, route changes, table
flush, service changes or global firewall policy changes. Only installs
the new table inet cape_analysis_guard while lab network remains INACTIVE.
This guard is NOT persistent through reboot yet: require a separate
boot-ordered persistence design BEFORE enabling any lab network autostart.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import dryrun_cape_lab_guard_nft as draft

NAME=draft.TABLE
LOCK=Path("/run/lock/cape-cold-export.lock")

class GuardInstallBlocked(RuntimeError):pass

def need(ok,msg):
    if not ok:raise GuardInstallBlocked(msg)

def execute(*args):
    try:
        result=subprocess.run(args,capture_output=True,text=True,
                              timeout=90,check=True)
        return result.stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as err:
        raise GuardInstallBlocked("Host action failed: "+args[0]) from err

def has_table():
    result=subprocess.run(["nft","-j","list","table","inet",NAME],
                          capture_output=True,text=True,timeout=60)
    if result.returncode!=0:
        return False
    try:
        obj=json.loads(result.stdout)
        return any(
            isinstance(item,dict) and isinstance(item.get("table"),dict)
            and item["table"].get("family")=="inet"
            and item["table"].get("name")==NAME
            for item in obj.get("nftables",[])
        )
    except (TypeError,ValueError,KeyError):
        raise GuardInstallBlocked("Unreadable existing CAPE nftables table")

def verify_installed():
    obj=json.loads(execute("nft","-j","list","table","inet",NAME))
    rows=obj.get("nftables",[])
    need(isinstance(rows,list),"Unexpected CAPE nftables JSON")
    tables=[r["table"] for r in rows if isinstance(r,dict) and "table" in r]
    need(len(tables)==1 and tables[0].get("family")=="inet"
         and tables[0].get("name")==NAME,"CAPE guard table identity mismatch")
    chains={r["chain"].get("name"):r["chain"] for r in rows
            if isinstance(r,dict) and isinstance(r.get("chain"),dict)}
    need(set(chains)=={"cape_forward","cape_input","cape_output"},
         "CAPE guard chain set differs")
    for label,hook in (("cape_forward","forward"),("cape_input","input"),
                       ("cape_output","output")):
        ch=chains[label]
        need(ch.get("hook")==hook and ch.get("type")=="filter"
             and ch.get("prio",ch.get("priority"))==-50
             and ch.get("policy")=="accept",
             "CAPE nft base chain hook/priority/policy unexpected")
    entries=[r["rule"] for r in rows if isinstance(r,dict)
             and isinstance(r.get("rule"),dict)]
    per_chain={name:[] for name in chains}
    for rule in entries:
        chain=rule.get("chain")
        need(rule.get("family")=="inet" and rule.get("table")==NAME
             and chain in per_chain,"Unexpected CAPE firewall rule scope")
        per_chain[chain].append(rule)
    need({k:len(v) for k,v in per_chain.items()}=={
         "cape_forward":2,"cape_input":2,"cape_output":2},
         "Unexpected CAPE guard rule count")
    action_counts={}
    for chain,rules in per_chain.items():
        action_counts[chain]=[]
        for rule in rules:
            expressions=rule.get("expr")
            need(isinstance(expressions,list),"Malformed CAPE nft rule expression")
            actions=[]
            for expression in expressions:
                need(isinstance(expression,dict),
                     "Unexpected CAPE nft expression type")
                actions.extend(x for x in ("accept","drop") if x in expression)
            need(len(actions)==1,"Unexpected CAPE verdict count")
            action_counts[chain].append(actions[0])
    need(action_counts=={
        "cape_forward":["drop","drop"],
        "cape_input":["accept","drop"],
        "cape_output":["accept","drop"]},
        "CAPE nft allow/drop ordering mismatch")
    # Explicit readback of intended addresses and iface matches via
    # canonical nft textual dump; do not emit raw rules in logs.
    text=execute("nft","list","table","inet",NAME)
    for token in (f'iifname "{draft.BRIDGE}"',
                  f'oifname "{draft.BRIDGE}"',
                  draft.ADDRESS,
                  draft.SUBNET,
                  "tcp dport 8000",
                  "ct state established,related"):
        need(token in text,"Critical CAPE guard interface/address mismatch")
    return True

def preflight():
    need(os.geteuid()==0,"Requires sudo")
    try:draft.check_guest_and_network()
    except draft.DryRunBlocked as e:
        raise GuardInstallBlocked(str(e)) from e
    script=draft.policy_text()
    draft.validate_policy(script)
    need(not has_table(),"CAPE guard nftables table already exists; do not overwrite")
    return script

def install():
    need(not LOCK.is_symlink(),"Unsafe shared VM/network lock path")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    published=False
    try:
        info=os.fstat(fd)
        need(info.st_uid==0 and not info.st_mode&0o077,
             "Unsafe root-owned network lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        source=preflight()
        with tempfile.TemporaryDirectory(prefix="cape-nft-create-",dir="/run") as tmp:
            path=Path(tmp)/"guard.nft"
            path.write_text(source,encoding="utf-8")
            path.chmod(0o600)
            # Syntax validation before any write.
            execute("nft","--check","--file",str(path))
            # Atomic nft batch creates only this new private table.
            execute("nft","--file",str(path))
        published=True
        try:
            verify_installed()
            draft.check_guest_and_network()
        except Exception:
            # The network remains inactive by design; retain guard
            # rather than temporarily removing containment without
            # an independently verified safe state.
            print("CRITICAL: CAPE table may exist but could not be verified. "
                  "Do not start network or connect guests. Manual review needed.",
                  file=sys.stderr)
            raise
        return {"result":"CAPE_NFT_GUARD_INSTALLED_UNDER_INACTIVE_NETWORK",
                "nft_family":"inet","table":NAME,
                "policy_sha256":hashlib.sha256(source.encode()).hexdigest(),
                "scope":"only bridge "+draft.BRIDGE,
                "priority":-50,
                "table_verified":True,
                "host_other_firewall_chains_modified":False,
                "lab_network_active":False,
                "trial_guest_nic_count":0,
                "guard_persistent_across_reboot":False,
                "runtime_isolation_verified":False,
                "warning":"Do not activate lab or connect NIC before staged persistence and explicit negative egress tests"}
    finally:
        os.close(fd)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=["plan","install"],default="plan")
    mode=parser.parse_args(argv).mode
    try:
        if mode=="plan":
            source=preflight()
            result={"result":"CAPE_GUARD_INSTALL_PLAN_ONLY",
                    "policy_sha256":hashlib.sha256(source.encode()).hexdigest(),
                    "table":NAME,"host_modified":False}
        else:result=install()
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (GuardInstallBlocked,draft.DryRunBlocked,OSError,ValueError,
            ET.ParseError,subprocess.TimeoutExpired) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        return 2
if __name__=="__main__":sys.exit(main())
