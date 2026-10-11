#!/usr/bin/env python3
"""SSL-55 win11_1 read-only CAPE nft rule + reboot persistence audit.

Never starts a libvirt network, attaches a guest NIC, changes firewall,
edits files, starts a VM, or captures/restores a snapshot. Presence of
rules is NOT real IPv4/IPv6 isolation or reboot-persistence proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
CLONE_UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
TABLE="cape_analysis_guard"
NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
EXPECTED_CHAINS={"cape_forward":("forward",["drop","drop"]),
                 "cape_input":("input",["accept","drop"]),
                 "cape_output":("output",["accept","drop"])}


class AuditBlocked(RuntimeError):
    pass


def need(test, reason):
    if not test:
        raise AuditBlocked(reason)


def command(*argv):
    try:
        p=subprocess.run(argv,timeout=20,capture_output=True,
                         text=True,check=False)
    except (OSError,subprocess.TimeoutExpired):
        return None
    return p.stdout.strip() if p.returncode==0 else None


def virsh(*args):
    out=command("virsh","-c","qemu:///system",*args)
    need(out is not None,"libvirt read-only check unavailable: "+args[0])
    return out


def protected_domains():
    expected=(("win11",MASTER_UUID),("win11_1",CLONE_UUID),
              ("win11_trial_1",TRIAL_UUID))
    records={}
    for name,uuid in expected:
        need(virsh("domuuid",name).lower()==uuid,
             "Protected VM identity mismatch: "+name)
        state=virsh("domstate",name).strip()
        need(state in ("running","shut off","paused"),
             "Unexpected VM state: "+name)
        views=[("inactive",virsh("dumpxml","--inactive",name))]
        if state in ("running","paused"):
            views.append(("live",virsh("dumpxml",name)))
        counts={}
        for view,xml in views:
            root=ET.fromstring(xml)
            need(root.tag=="domain" and root.findtext("name")==name and
                 root.findtext("uuid")==uuid,
                 "Guest libvirt XML identity mismatch: "+name)
            interfaces=root.findall("./devices/interface")
            counts[view]=len(interfaces)
            if name in ("win11_1","win11_trial_1"):
                need(not interfaces,
                     "Protected clone/trial NIC unexpectedly changed: "+name)
            elif name=="win11" and view=="inactive":
                need(len(interfaces)==1 and
                     interfaces[0].get("type")=="network" and
                     interfaces[0].find("source") is not None and
                     interfaces[0].find("source").get("network")=="default",
                     "Original win11 saved NIC no longer matches restoration")
        records[name]={"uuid_verified":True,"power_state":state,
                       "nic_counts":counts}
    need(records["win11"]["power_state"]=="shut off",
         "Protected original Windows master must remain off")
    need(records["win11_1"]["power_state"]=="shut off",
         "Audit requires existing isolated win11_1 shut off")
    return records


def network_status():
    info=virsh("net-info",NETWORK)
    items={}
    for line in info.splitlines():
        key,sep,value=line.partition(":")
        if sep:
            items[key.strip().lower()]=value.strip().lower()
    xml=ET.fromstring(virsh("net-dumpxml",NETWORK))
    ip=xml.findall("./ip")
    bridge=xml.find("bridge")
    correct=(xml.tag=="network" and xml.findtext("name")==NETWORK and
             bridge is not None and bridge.get("name")==BRIDGE and
             xml.find("forward") is None and
             not xml.findall(".//dhcp") and not xml.findall(".//route") and
             len(ip)==1 and ip[0].get("address")=="192.168.240.1" and
             ip[0].get("netmask")=="255.255.255.0" and
             ip[0].get("family") in (None,"ipv4"))
    return {"defined":True,"active":items.get("active"),
            "autostart":items.get("autostart"),
            "persistent":items.get("persistent"),
            "bridge":items.get("bridge"),
            "nonforward_no_dhcp_known_subnet":bool(correct)}


def guard_policy_structure(json_text, nft_text):
    """Pure conservative policy-shape comparison, NOT packet testing."""
    try:
        doc=json.loads(json_text)
    except (ValueError,TypeError) as exc:
        raise AuditBlocked("Invalid nftables JSON response") from exc
    rows=doc.get("nftables") if type(doc) is dict else None
    need(type(rows) is list and len(rows)<2000,
         "Unexpected CAPE nftables JSON shape")
    tables=[x["table"] for x in rows if type(x) is dict and
            type(x.get("table")) is dict]
    need(len(tables)==1 and tables[0].get("family")=="inet" and
         tables[0].get("name")==TABLE,
         "CAPE nftables table identity differs")
    chains={}
    rules={}
    for item in rows:
        if type(item) is not dict:
            continue
        chain=item.get("chain")
        if type(chain) is dict:
            chains[chain.get("name")]=chain
        rule=item.get("rule")
        if type(rule) is dict:
            rules.setdefault(rule.get("chain"),[]).append(rule)
    need(set(chains)==set(EXPECTED_CHAINS) and
         set(rules)==set(EXPECTED_CHAINS),
         "Expected three CAPE guard chains missing or extras present")
    verdicts={}
    for name,(hook,actions) in EXPECTED_CHAINS.items():
        chain=chains[name]
        need(chain.get("type")=="filter" and
             chain.get("hook")==hook and
             chain.get("prio",chain.get("priority"))==-50 and
             chain.get("policy")=="accept",
             "Unexpected CAPE firewall hook/priority/base policy")
        need(len(rules[name])==len(actions),
             "Unexpected CAPE guard rule count")
        found=[]
        for rule in rules[name]:
            need(rule.get("table")==TABLE and rule.get("family")=="inet",
                 "CAPE nft rule outside dedicated inet scope")
            expr=rule.get("expr")
            need(type(expr) is list, "Unexpected nft rule expressions")
            verdict=[v for e in expr if type(e) is dict
                     for v in ("drop","accept") if v in e]
            need(len(verdict)==1,
                 "Unexpected guard rule verdict")
            found.append(verdict[0])
        need(found==actions, "CAPE verdict ordering differs")
        verdicts[name]=found
    tokens=('iifname "cape-lab0"', 'oifname "cape-lab0"',
            "192.168.240.1", "192.168.240.0/24",
            "tcp dport 8000", "ct state established,related")
    need(all(token in nft_text for token in tokens),
         "CAPE guard expected bridge/address/port tokens missing")
    # These checks are intentionally insufficient for a firewall certificate.
    return {"expected_chain_hooks_and_order":True,
            "rule_verdict_sequences":verdicts,
            "bridge_addr_agent_port_tokens_present":True,
            "ipv4_ipv6_packet_path_tested":False,
            "l2_between_guests_tested":False}


def proposed_analysis_mac():
    """Deterministic local-unicast NIC plan for the existing clone only.

    The MAC is a candidate, not a reserved/attached address. Compare
    against ALL live/inactive libvirt NICs and host interfaces.
    """
    payload=("CAPE_COMMAND2_SSL55_WIN11_1|" + CLONE_UUID).encode("ascii")
    digest=hashlib.sha256(payload).digest()[:5]
    wanted="02:"+":".join(f"{x:02x}" for x in digest)
    names=[x.strip() for x in virsh("list","--all","--name").splitlines()
           if x.strip()]
    need("win11_1" in names and len(set(names))==len(names),
         "Libvirt inventory incomplete/duplicate VM names")
    occupied=set()
    for name in names:
        views=[virsh("dumpxml","--inactive",name)]
        if virsh("domstate",name).strip() in ("running","paused"):
            views.append(virsh("dumpxml",name))
        for text in views:
            root=ET.fromstring(text)
            need(root.tag=="domain" and root.findtext("name")==name,
                 "Cannot associate libvirt MAC inventory with exact domain")
            for mac in root.findall("./devices/interface/mac"):
                value=mac.get("address")
                if value:
                    occupied.add(value.lower())
    links=command("ip","-j","link","show")
    need(links is not None,
         "Cannot read host NIC MAC inventory")
    try:
        data=json.loads(links)
    except (ValueError,TypeError) as exc:
        raise AuditBlocked("Invalid host link inventory JSON") from exc
    need(type(data) is list and len(data)<=8192,
         "Unexpected/oversized host NIC list")
    for link in data:
        need(type(link) is dict,"Unexpected host NIC item")
        mac=link.get("address")
        if type(mac) is str:
            occupied.add(mac.lower())
    return {"proposed_mac":wanted,
            "mac_inventory_complete":True,
            "host_or_libvirt_mac_collision":wanted in occupied,
            "guest_ipv4_proposal":"192.168.240.101",
            "guest_hostname_proposal":"WIN11-1",
            "mac_reserved_or_attached":False,
            "approval_to_attach":False}


def service_state(name):
    enabled=command("systemctl","is-enabled",name)
    active=command("systemctl","is-active",name)
    return {"enabled_state":enabled if enabled in
            ("enabled","disabled","static","masked","indirect") else "unknown",
            "active_state":active if active in
            ("active","inactive","failed") else "unknown"}


def audit():
    host=socket.gethostname().split(".",1)[0].lower()
    need(host in ("ssl-55","cse-ssl-55") and
         SENTINEL.is_dir() and not SENTINEL.is_symlink(),
         "Expected protected SSL-55 preservation host not present")
    need(os.geteuid()==0,"Read-only nftables inspection requires sudo")
    domains=protected_domains()
    network=network_status()
    raw_json=command("nft","-j","list","table","inet",TABLE)
    raw_text=command("nft","list","table","inet",TABLE)
    if raw_json is None or raw_text is None:
        firewall={"guard_present":False,"expected_guard_shape":False}
    else:
        try:
            parsed=guard_policy_structure(raw_json,raw_text)
        except AuditBlocked as exc:
            firewall={"guard_present":True,
                      "expected_guard_shape":False,
                      "shape_error":str(exc)}
        else:
            firewall={"guard_present":True,
                      "expected_guard_shape":True,
                      "shape_details":parsed}
    nic_candidate=proposed_analysis_mac()
    services={
        "nftables.service":service_state("nftables.service"),
        "cape-analysis-guard.service":service_state(
            "cape-analysis-guard.service")
    }
    return {
        "result":"SSL55_EXISTING_COMMAND2_NFT_PERSISTENCE_AUDIT_ONLY",
        "protected_domains":domains,
        "analysis_network":network,
        "existing_lab_firewall":firewall,
        "service_observations":services,
        "win11_1_candidate_nic_not_applied":nic_candidate,
        "boot_replay_dependency_verified":False,
        "reboot_persistence_actually_tested":False,
        "ipv4_external_egress_negative_test":False,
        "ipv6_external_egress_negative_test":False,
        "guest_l2_isolation_verified":False,
        "cape_agent_http_tested":False,
        "safe_to_attach_analysis_nic":False,
        "safe_to_capture_running_snapshot":False,
        "no_vm_or_network_changes":True,
        "next":"Review guard and persistent boot-order design before activating lab network",
    }


def main():
    import argparse
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(audit(),indent=2,sort_keys=True))
        return 0
    except (AuditBlocked,ET.ParseError,OSError,ValueError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
