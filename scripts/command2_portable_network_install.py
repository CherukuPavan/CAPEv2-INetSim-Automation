#!/usr/bin/env python3
"""OTHER-host-only isolated CAPE network + dedicated nft table installer.

Modes: plan (read-only); install (typed-approved create-only).
Creates ONLY the reserved cape-analysis-isolated libvirt network and
inet cape_analysis_cmd2_guard nft table. Never deletes/replaces rules or
any network, changes unrelated bridge, configures NICs, boots guests,
enables net-autostart, or changes systemd. Reboot persistence, real IPv6,
negative peer L2 packet paths and CAPE/INetSim positives remain UNTESTED.
No automatic rollback/retry if a partially completed step is observed.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_portable_workflow as workflow
import command2_target_host_preflight as hostinfo
import command2_isolated_network_xml_plan as libvirtnet
import command2_cape_egress_guard_plan as nftplan
import command2_portable_network_transaction as owned_network

LOCK=Path("/run/lock/cape-command2-network-install.lock")
NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
TABLE="cape_analysis_cmd2_guard"
class NetworkBlocked(RuntimeError):pass

def need(ok,why):
    if not ok:raise NetworkBlocked(why)
def command(*argv,input_text=None,timeout=35):
    try:
        v=subprocess.run(argv,text=True,input=input_text,capture_output=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise NetworkBlocked("Host utility missing or timed out: "+argv[0]) from e
    need(v.returncode==0,"Host utility failed: "+argv[0])
    return v.stdout.strip()
def virsh(*args):
    return command("virsh","-c","qemu:///system",*args)

def nft_table_exists():
    raw=command("nft","-j","list","tables")
    obj=json.loads(raw)
    entries=obj.get("nftables")
    need(type(entries) is list,"Unexpected host nft inventory format")
    for entry in entries:
        need(type(entry) is dict,"Malformed nft inventory entry")
        tb=entry.get("table")
        if tb is None:continue
        need(type(tb) is dict and type(tb.get("family")) is str and
             type(tb.get("name")) is str,
             "Malformed nft table identifier")
        if tb["family"]=="inet" and tb["name"]==TABLE:
            return True
    return False

def collision_free(cidr):
    nets=hostinfo.parsed_routes(hostinfo.json_command(
        "ip","-j","-4","route","show","table","all"))
    addresses=hostinfo.parsed_addresses(hostinfo.json_command(
        "ip","-j","-4","addr","show"))
    libvirt=hostinfo.libvirt_nets()
    need(all(type(x) is list for x in (nets,addresses,libvirt)),
         "Kernel/network occupancy inventory unavailable")
    target=ipaddress.IPv4Network(cidr)
    need(not any(target.overlaps(ipaddress.IPv4Network(x,strict=False))
                 for x in nets+addresses+libvirt),
         "Reserved analysis subnet now collides with host routes/interfaces/libvirt")
    links=hostinfo.json_command("ip","-j","link","show")
    need(type(links) is list and all(type(e) is dict for e in links),
         "Kernel interface inventory unavailable")
    need(not any(x.get("ifname")==BRIDGE for x in links),
         "CAPE bridge name exists before approved install")

def canonical_inputs(host,journal):
    try:workflow.canonical_host(host)
    except workflow.WorkflowBlocked as e:raise NetworkBlocked(str(e)) from e
    need(os.geteuid()==0,"Root required to inspect root-private reservation")
    rows=workflow.snapshotgate.reservation_rows(journal,host)
    need(rows and Path(journal).name=="command2-identity-reservation.json",
         "Canonical guest reservation missing")
    _,subnet,_=workflow.load_guest(journal,host,"win11_1")
    for row in rows:
        _,current,_=workflow.load_guest(journal,host,row["libvirt_name"])
        need(current==subnet,"Mixed analysis subnet in ordered reservation")
    need(not virsh("list","--name").strip(),
         "Running VM present; do not mutate shared networking")
    nets=virsh("net-list","--all","--name").splitlines()
    need(NETWORK not in (x.strip() for x in nets),
         "CAPE libvirt network already exists: no overwrite")
    collision_free(subnet)
    need(not nft_table_exists(),"Dedicated CAPE nft table exists; no overwrite")
    reserved=[r["guest_static_ipv4_target"] for r in rows]
    network=libvirtnet.plan(NETWORK,BRIDGE,subnet,reserved)
    rules=nftplan.render_cape_egress_guard(subnet)
    # nft -c validates the proposed text but MUST NOT commit any rules.
    command("nft","--check","-f","-",input_text=rules["ruleset_text"])
    return {
       "result":"COMMAND2_PORTABLE_ISOLATED_NETWORK_CREATE_ONLY_PLAN",
       "approved_host":host,"journal":str(journal),"vm_count":len(rows),
       "analysis_subnet":subnet,"network_name":NETWORK,"bridge":BRIDGE,
       "network_xml":network["libvirt_network_xml"],
       "network_xml_sha256":hashlib.sha256(
             network["libvirt_network_xml"].encode()).hexdigest(),
       "nft_table":TABLE,"nft_rules_sha256":rules["ruleset_sha256"],
       "nft_rules":rules["ruleset_text"],
       "libvirt_network_preexisting":False,
       "nft_table_preexisting":False,
       "guests_running":False,
       "nft_candidate_syntax_checked":True,
       "host_changes_made":False,
       "guest_ipv4_ipv6_negative_egress_tested":False,
       "bridge_peer_l2_packet_negative_tested":False,
       "nft_reboot_persistence_tested":False,
       "analysis_network_autostart_enabled":False,
       "production_network_approved":False,
    }

def install(host,journal):
    need(sys.stdin.isatty(),"Direct interactive terminal approval required")
    initial=canonical_inputs(host,journal)
    print(json.dumps(initial,indent=2,sort_keys=True),flush=True)
    expected="INSTALL-CAPE-ISOLATED-LAB-ONLY"
    need(input("Type "+expected+" to create only the CAPE nft table and libvirt network: ")==
         expected,"Operator did not approve CAPE-only network")
    need(not LOCK.is_symlink(),"Unsafe existing CAPE network install lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "CAPE network installation lock unsafe")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise NetworkBlocked("Concurrent network install") from e
        need(canonical_inputs(host,journal)==initial,
             "Host subnet, domain list or network/firewall state changed after approval")
        # Mutation ownership receipt is fsynced BEFORE nft can create a
        # table. Stale or partially applied installation is never repeated.
        owned_network.begin(host,journal,initial)
        # nft batch contains only a new precisely named table/chain creation.
        # If later libvirt action fails, keep table and refuse blind retry.
        command("nft","-f","-",input_text=initial["nft_rules"])
        owned_network.advance(journal,"prepared","nft_applied")
        with tempfile.TemporaryDirectory(prefix="cape-net-def-",dir="/run") as td:
            file=Path(td)/"isolated.xml"
            file.write_text(initial["network_xml"],encoding="utf-8")
            file.chmod(0o600)
            virsh("net-define",str(file),"--validate")
        owned_network.advance(journal,"nft_applied","network_defined")
        netxml=ET.fromstring(virsh("net-dumpxml",NETWORK))
        need(netxml.findtext("name")==NETWORK and
             netxml.find("forward") is None and
             netxml.find("port") is not None and
             netxml.find("port").get("isolated")=="yes",
             "Defined CAPE network differs from approved isolated XML")
        virsh("net-start",NETWORK)
        owned_network.advance(journal,"network_defined","network_started")
        info=virsh("net-info",NETWORK)
        need(re.search(r"(?mi)^Active:\s+yes\s*$",info) is not None and
             re.search(r"(?mi)^Autostart:\s+no\s*$",info) is not None,
             "CAPE network unexpectedly inactive/autostart enabled")
        nft=command("nft","-a","list","table","inet",TABLE)
        need("cape_guest_forward" in nft and "cape_guest_input" in nft and
             BRIDGE in nft,"CAPEv2 dedicated nft guard runtime differs")
        need(not virsh("list","--name").strip(),
             "Unexpected guest started during safe network staging")
        readback = {
            "post_live_libvirt_xml_sha256": hashlib.sha256(
                virsh("net-dumpxml",NETWORK).encode()).hexdigest(),
            "post_nft_stateless_sha256": hashlib.sha256(
                command("nft","-j","-s","list","table","inet",TABLE).encode()
            ).hexdigest(),
        }
        owned_network.advance(journal,"network_started","verified",
                              post_state=readback)
        return {
           "result":"COMMAND2_PORTABLE_CAPE_LAB_DEFINED_ACTIVE_NOT_REBOOT_VERIFIED",
           "approved_host":host,"subnet":initial["analysis_subnet"],
           "guard_table":TABLE,"isolated_network":NETWORK,
           "unrelated_host_firewall_not_flushed":True,
           "network_autostart_enabled":False,
           "nft_persistence_or_reboot_tested":False,
           "l2_ipv6_external_guest_packet_tests_complete":False,
           "positive_cape_inetsim_guest_paths_tested":False,
           "guest_nics_attached":False,
           "production_network_authorized":False,
           "operator_must_not_blindly_retry":True,
           "root_private_network_intent_recorded_before_mutation":True,
           "network_ownership_receipt":str(owned_network.record_path(journal))
        }
    finally:os.close(fd)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("plan","install"),default="plan")
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--journal",required=True,type=Path)
    a=ap.parse_args()
    try:
        result=canonical_inputs(a.approved_host,a.journal) if a.mode=="plan" else install(
            a.approved_host,a.journal)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (NetworkBlocked,workflow.WorkflowBlocked,
            workflow.snapshotgate.GateBlocked,
            libvirtnet.NetworkPlanBlocked,nftplan.GuardPlanBlocked,
            OSError,ValueError,TypeError,ET.ParseError) as e:
        print(json.dumps({"result":"COMMAND2_PORTABLE_NETWORK_INSTALL_BLOCKED",
             "reason":str(e),"automatic_retry_permitted":False},
             sort_keys=True,indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
