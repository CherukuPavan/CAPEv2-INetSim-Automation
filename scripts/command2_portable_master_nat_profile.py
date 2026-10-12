#!/usr/bin/env python3
"""OTHER-host Command 2 all-N MASTER-EQUIVALENT persistent NAT PLAN ONLY.

Uses the existing host-pinned identity reservation journal (win11_1..N,
unique already-generated MACs) and the actual *shut-off* protected source
win11 NIC on libvirt default NAT. It checks current active libvirt NAT
bridge/subnet/DHCP ranges, reservations and visible leases; constructs
one permanent e1000e NAT NIC per clone, static Windows address/DNS
target, same-MAC DHCP host reservation, CAPE Agent and future snapshot
plan WITHOUT touching any VM, network, guest or CAPE service.

The previous all-N allocator used an isolated 192.168.240.0/24
analysis-only profile. That older pipeline CANNOT be applied blindly to
master-style 192.168.122.0/24; its Windows IPv4, DHCP, CAPE and guest
snapshot receipts require profile-specific regeneration and checks.
Neither lease absence nor this preview is a guarantee an IP is free.
Unrestricted NAT and arbitrary malware execution are NOT approved.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import os
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_portable_workflow as workflow
import command2_master_nat_parity_audit as ref
import command2_master_nat_count_plan as planning

class PortableNatBlocked(RuntimeError):pass
def need(x,reason):
    if not x:raise PortableNatBlocked(reason)
def virsh(*args,timeout=35):
    try:
        p=subprocess.run(["virsh","-c","qemu:///system",*args],
                         capture_output=True,text=True,timeout=timeout,
                         check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PortableNatBlocked("Read-only libvirt query missing/timed out") from exc
    need(p.returncode==0 and len(p.stdout)<512*1024,
         "Read-only libvirt query failed: "+args[0])
    return p.stdout.strip()

def check_master():
    # This phase is for a NEW machine; SSL55 remains protected and
    # is not allowed through the generic portable dispatcher.
    need(virsh("domstate","win11").lower()=="shut off",
         "Approved source Windows master must remain shut off")
    domain=ET.fromstring(virsh("dumpxml","--inactive","win11"))
    need(domain.tag=="domain" and domain.get("type")=="kvm" and
         domain.findtext("name")=="win11" and
         domain.findtext("uuid"),"Unexpected source master XML")
    nics=domain.findall("./devices/interface")
    need(len(nics)==1,"Source master should have exactly one NIC")
    x=nics[0]
    src=x.find("source");mod=x.find("model");mac=x.find("mac")
    need(x.get("type")=="network" and
         src is not None and src.get("network")=="default" and
         mod is not None and mod.get("type")=="e1000e" and
         mac is not None and ref.MAC_RE.fullmatch(mac.get("address") or ""),
         "Master does not match default NAT e1000e reference")
    return {"master_name":"win11",
            "master_nic_network":"default",
            "master_nic_model":"e1000e",
            "master_left_shut_off":True}

def check_active_nat():
    raw=virsh("net-dumpxml","default")
    net=ref.nat_details(raw)
    info={}
    for line in virsh("net-info","default").splitlines():
        k,colon,v=line.partition(":")
        if colon:
            k=k.strip().lower()
            need(k not in info,"Duplicate virsh net-info field")
            info[k]=v.strip().lower()
    need(info.get("name")=="default" and
         info.get("active")=="yes" and
         info.get("bridge")=="virbr0",
         "Master-equivalent default NAT must actually be active")
    return net

def assemble_reference(host,count,net):
    observed=ref.lease_inventory(virsh("net-dhcp-leases","default"))
    names=["win11_"+str(i) for i in range(1,count+1)]
    return {"result":"COMMAND2_MASTER_EQUIVALENT_PERSISTENT_NAT_AUDIT_ONLY",
            "target_permanent_libvirt_network":"default",
            "target_permanent_bridge":"virbr0",
            "source_vm_remains_off":True,"trial_remains_off":True,
            "libvirt_network_or_guest_modified":False,
            "target_clone_names":names,
            "network_info":net,
            "lease_inventory":observed,
            # This is a NEW host; SSL55-specific prior Windows IP
            # 192.168.122.125 is not assumed to hold on other hosts.
            "historical_master_windows_ip_reference":None}

def inspect(host,journal):
    host=workflow.canonical_host(host)
    need(os.geteuid()==0,"Root needed for reserved canonical guest journal")
    journal=Path(journal)
    need(journal.is_absolute() and
         journal.name=="command2-identity-reservation.json",
         "Expected absolute canonical private guest journal")
    workflow.snapshotgate.private_evidence_folder(journal.parent)
    rows=workflow.snapshotgate.reservation_rows(journal,host)
    need(type(rows) is list and 1<=len(rows)<=16,
         "Require actual existing 1..16 guest reservation rows")
    required=["win11_"+str(i) for i in range(1,len(rows)+1)]
    need([r["libvirt_name"] for r in rows]==required,
         "Journal VM rows are not exact count-driven win11_N identities")
    master=check_master()
    # Existing trial is protected when present; unlike the SSL55-only
    # reference, a fresh host may not have a trial domain at all.
    names=[n.strip() for n in
           virsh("list","--all","--name").splitlines() if n.strip()]
    need(len(names)==len(set(names)),"Duplicate libvirt domain names")
    if "win11_trial_1" in names:
        need(virsh("domstate","win11_trial_1").lower()=="shut off",
             "Trial domain must remain powered off")
    net=check_active_nat()
    proof=assemble_reference(host,len(rows),net)
    candidates=[{"libvirt_name":x["libvirt_name"],
                 "mac_candidate":x["mac_candidate"]} for x in rows]
    try:
        proposed=planning.allocate(proof,candidates)
    except planning.NatPlanBlocked as exc:
        raise PortableNatBlocked("NAT IP/MAC allocation blocked: "+str(exc)) from exc
    need(proposed["auto_apply_authorized"] is False,
         "Unsafe allocator auto-apply flag")
    for x in proposed["clones"]:
        need(x["guest_nic_port_isolated"] is False,
             "Default NAT planner incorrectly assumed guest isolation")
        x["public_nat_requires_independent_analysis_egress_policy"]=True
        x["old_isolated_guest_ip_from_journal_must_not_be_reused"]=True
    return {
       "result":"COMMAND2_PORTABLE_MASTER_DEFAULT_NAT_ALL_N_PLAN_ONLY",
       "host":host,"count":len(rows),
       "guest_names":required,
       "source_master":master,
       "active_default_network":net,
       "guest_nat_candidates":proposed["clones"],
       "live_lease_count":len(proof["lease_inventory"]["live_dhcp_leases"]),
       "previous_isolated_profile_not_automatically_reused":True,
       "permanent_nat_required_for_every_guest":True,
       "per_guest_dhcp_reservation_needs_application":True,
       "per_guest_windows_gateway_dns_needs_setup":True,
       "per_guest_cape_agent_nat_ip_probe_required":True,
       "per_guest_cape_machine_registration_required":True,
       "per_guest_running_ram_disk_uefi_snapshot_required":True,
       "swtpm_era_matched_backup_and_twice_benign_revert_required":True,
       "real_unrestricted_malware_internet_not_approved":True,
       "all_machines_or_networks_modified":False,
       "operator_approved_apply_supported":False,
       "project_portable_command2_finished":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan",),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        print(json.dumps(inspect(a.approved_host,a.journal),
                         indent=2,sort_keys=True))
        return 0
    except (PortableNatBlocked,workflow.WorkflowBlocked,
            workflow.snapshotgate.GateBlocked,
            ref.NatPlanBlocked,planning.NatPlanBlocked,
            OSError,ValueError,TypeError,KeyError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_PORTABLE_MASTER_NAT_PROFILE_BLOCKED",
                          "reason":str(exc),"host_mutated":False},
                         sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
