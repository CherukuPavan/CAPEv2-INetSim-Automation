#!/usr/bin/env python3
"""Guarded OTHER-HOST all-N persistent MASTER NAT provisioning for ZERO-NIC VMs.

PLAN inspects the exact canonical 1..16 Command2 private identity journal,
shut-off source, running default/virbr0 NAT, DHCP leases/reservations, all
VM saved+live NIC MACs and stopped ZERO-NIC clone definitions. No writes.
APPLY (explicit typed N-level approval) creates each clone's persistent
libvirt DHCP host reservation and attaches its ONLY saved e1000e interface
to the already existing default NAT. Stops IMMEDIATELY on any partial
change; NEVER retries, deletes, reverts, reboots, starts, or edits a
master/trial. The old isolated journal IPs are not deployed into the NAT.
VERIFY checks saved libvirt state and live+inactive DHCP reservations.
Windows guest DHCP, hostname, agent reachability, public HTTPS and
TPM-safe revert must be independently proved before CAPE registration.

This is a BENIGN provisioning operation, not a malware execution release.
Plain libvirt default NAT provides unrestricted Internet by default and
does NOT provide analysis containment without another guard.
"""
from __future__ import annotations
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_portable_master_nat_profile as profile
import command2_portable_workflow as workflow
import command2_master_nat_count_plan as allocator

NETWORK="default"
BRIDGE="virbr0"
GUESTNAME=re.compile(r"win11_([1-9]|1[0-6])\Z")
LOCK=Path("/run/lock/cape-command2-master-nat-apply.lock")
class NatAttachBlocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise NatAttachBlocked(msg)
def virsh(*args,timeout=90):
    return profile.virsh(*args,timeout=timeout)

def journal_rows(host,journal):
    workflow.canonical_host(host)
    need(os.geteuid()==0,"NAT provisioning root only")
    path=Path(journal)
    need(path.is_absolute() and
         path.name=="command2-identity-reservation.json",
         "Require exact absolute canonical private reservation journal")
    workflow.snapshotgate.private_evidence_folder(path.parent)
    rows=workflow.snapshotgate.reservation_rows(path,host)
    need(type(rows) is list and 1<=len(rows)<=16,
         "Missing approved 1..16 reserved clone identities")
    need([r.get("libvirt_name") for r in rows]==[
         f"win11_{i}" for i in range(1,len(rows)+1)],
         "Expected ordered count-driven cloned guest names")
    return rows

def check_exact_guest(row, expected_mac=None):
    vm=row["libvirt_name"]
    need(GUESTNAME.fullmatch(vm) is not None,
         "Unapproved VM identity")
    need(virsh("domuuid",vm).lower()==row["libvirt_uuid_candidate"] and
         virsh("domstate",vm).lower()=="shut off",
         "Clone must exist with reserved UUID and remain SHUT OFF")
    xml=ET.fromstring(virsh("dumpxml","--inactive",vm))
    need(xml.tag=="domain" and xml.get("type")=="kvm" and
         xml.findtext("name")==vm and
         xml.findtext("uuid")==row["libvirt_uuid_candidate"],
         "Guest saved XML identity changed")
    disks=xml.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==row["disk_target"] and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "VM independent OS disk path differs from reservation")
    firmware=xml.find("./os/nvram")
    need(firmware is not None and
         (firmware.text or "").strip() in (
         row["uefi_nvram_target"],row["uefi_nvram_target"]+".qcow2"),
         "Unexpected guest independently copied UEFI variable store")
    tpm=xml.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Clone requires independent emulated TPM2 device")
    nics=xml.findall("./devices/interface")
    if expected_mac is None:
        need(not nics,"Only ZERO-NIC staged clones may be attached")
    else:
        need(len(nics)==1,"Clone must have exactly one permanent NAT NIC")
        x=nics[0]
        src=x.find("source");mac=x.find("mac");model=x.find("model")
        need(x.get("type")=="network" and
             src is not None and src.get("network")==NETWORK and
             mac is not None and
             (mac.get("address") or "").lower()==expected_mac.lower() and
             model is not None and model.get("type")=="e1000e",
             "Persistent VM NIC differs from preapproved NAT/MAC/model")
    # A true zero-NIC fresh clone has no preexisting snapshots.
    need(not virsh("snapshot-list",vm,"--name").strip(),
         "Existing clone snapshots require manual review, never mutate NIC")
    return {"vm":vm,"uuid":row["libvirt_uuid_candidate"],
            "reserved_mac":row["mac_candidate"],
            "saved_nic_state":("ZERO_NIC" if expected_mac is None
                               else "SINGLE_MASTER_EQUIVALENT_NAT"),
            "guest_not_started":True}

def check_network_references():
    profile.check_master()
    details=profile.check_active_nat()
    need(details["nat_network"]==NETWORK and details["bridge"]==BRIDGE,
         "Master NAT reference changed")
    xmls=[]
    for flag in (False,True):
        x=ET.fromstring(virsh("net-dumpxml",NETWORK,
                *(("--inactive",) if flag else ())))
        net=x.find("forward");bridge=x.find("bridge")
        need(x.tag=="network" and x.findtext("name")==NETWORK and
             net is not None and net.get("mode","nat")=="nat" and
             bridge is not None and bridge.get("name")==BRIDGE,
             "Expected active and persistent default NAT")
        xmls.append(x)
    return details,xmls

def occupied_domain_macs():
    names=[n.strip() for n in virsh("list","--all","--name").splitlines()
           if n.strip()]
    need(len(names)==len(set(names)),"Duplicate known libvirt domain names")
    seen=set()
    for vm in names:
        if vm=="win11_trial_1":
            need(virsh("domstate",vm).lower()=="shut off",
                 "Protected trial must be shut off")
        root=ET.fromstring(virsh("dumpxml","--inactive",vm))
        need(root.findtext("name")==vm and root.findtext("uuid") and
             root.tag=="domain",
             "Unrecognized libvirt domain inventory")
        for mac in root.findall("./devices/interface/mac"):
            address=(mac.get("address") or "").lower()
            need(allocator.MAC_RE.fullmatch(address) is not None,
                 "Existing VM has malformed MAC")
            need(address not in seen,"Duplicate existing VM NIC MAC")
            seen.add(address)
    return seen

def reservations(root):
    found=[]
    for x in root.findall("./ip/dhcp/host"):
        found.append((x.get("mac","").lower(),x.get("ip"),x.get("name")))
    need(len(found)==len(set(found)),
         "Duplicate libvirt static DHCP hosts in default NAT")
    return found

def build(host,journal,already):
    need(type(already) is bool,"Expected explicit plan/verify state")
    rows=journal_rows(host,journal)
    need(not virsh("list","--name").strip(),
         "Require ALL host guest domains off during NAT attachment")
    net,views=check_network_references()
    # Live and persistent NAT must agree on the source master's gateway,
    # subnet and DHCP ranges BEFORE touching any guest or reservation.
    persistent=profile.ref.nat_details(
         ET.tostring(views[1],encoding="unicode"))
    need(net["ipv4"]==persistent["ipv4"] and
         net["dynamic_dhcp_ranges"]==persistent["dynamic_dhcp_ranges"],
         "Active and persistent default NAT gateway/DHCP pool differ")
    leases=profile.ref.lease_inventory(virsh("net-dhcp-leases",NETWORK))
    domain_macs=occupied_domain_macs()
    wanted=[r["mac_candidate"].lower() for r in rows]
    need(len(set(wanted))==len(wanted),
         "Reserved clone MACs are not all distinct")
    if not already:
        need(not set(wanted).intersection(domain_macs),
             "Reserved new MAC collides with existing live/saved VM")
        report=profile.inspect(host,Path(journal))
        candidates=report["guest_nat_candidates"]
        need(len(candidates)==len(rows),
             "Master NAT allocation count inconsistent")
    else:
        # Once DHCP hosts exist, allocator correctly refuses to allocate
        # same IP again. Reconstruct EXACT deterministic candidate targets
        # without falsely treating them as newly available.
        subnet=ipaddress.IPv4Network(net["ipv4"]["subnet"])
        need(subnet.prefixlen==24 and subnet.is_private and
             str(ipaddress.IPv4Address(int(subnet.network_address)+1))==
             net["ipv4"]["gateway"],
             "Approved source master's private /24 NAT gateway changed")
        candidates=[]
        for i,r in enumerate(rows,1):
            ip=str(ipaddress.IPv4Address(int(subnet.network_address)+200+i))
            candidates.append({"libvirt_name":r["libvirt_name"],
                "nic_mac":r["mac_candidate"].lower(),
                "desired_static_ipv4":ip,"required_nic_model":"e1000e"})
    expected=[]
    for row,candidate in zip(rows,candidates):
        need(candidate["libvirt_name"]==row["libvirt_name"] and
             candidate["nic_mac"]==row["mac_candidate"].lower() and
             candidate["required_nic_model"]=="e1000e",
             "Planner MAC or guest name inconsistent with journal")
        state=check_exact_guest(row,
              expected_mac=candidate["nic_mac"] if already else None)
        expected.append({**state,"ip":candidate["desired_static_ipv4"]})
    pairs=[]
    for ent in expected:
        ip=ent["ip"];mac=ent["reserved_mac"].lower()
        name="WIN11-"+ent["vm"].split("_")[1]
        pairs.append((mac,ip,name))
    live=set(reservations(views[0]))
    saved=set(reservations(views[1]))
    need(live==saved,
         "Existing default NAT DHCP reservations differ live vs config")
    if already:
        need(all(x in live for x in pairs),
             "Missing expected guest reservation in live+config")
        need(len({x[1] for x in live})==len(live) and
             len({x[0] for x in live})==len(live) and
             len({x[2] for x in live})==len(live),
             "Conflicting NAT DHCP host MAC/IP/name duplicate")
    else:
        need(all(mac not in {x[0] for x in live} and
                 ip not in {x[1] for x in live} and
                 name not in {x[2] for x in live} for mac,ip,name in pairs),
             "NAT DHCP IP/MAC/hostname already reserved")
        # Lease list is not authoritative for third-party manual static IPs.
        # The planner already checks all observed leases vs the candidate.
        need(all(ip not in {x["ipv4"] for x in leases["live_dhcp_leases"]}
                 for mac,ip,name in pairs),
             "Exact candidate NAT IP already has observed DHCP lease")
    return {"result":("COMMAND2_MASTER_NAT_ALL_N_SAVED_STATE_VERIFIED"
                       if already else "COMMAND2_MASTER_NAT_ALL_N_ATTACH_PLAN"),
       "host":host,"count":len(rows),
       "network":NETWORK,"bridge":BRIDGE,
       "guest_reservations":expected,
       "dhcp_hosts":[{"mac":m,"ip":ip,"name":n} for m,ip,n in pairs],
       "guest_power_state":"shut off",
       "master_state":"shut off",
       "existing_dhcp_reservations_consistent":True,
       "all_preexisting_vm_macs_checked":True,
       "host_nat_dhcp_config_applied":already,
       "guest_saved_nics_attached":already,
       "guest_booted_or_configured":False,
       "guest_windows_dhcp_and_hostname_verified":False,
       "CAPE_READY":False,
       "snapshots_created":False,
       "swtpm_consistent_revert_proven":False,
       "public_malware_egress_authorized":False,
       "auto_retry_on_partial_failure":False}

def apply(host,journal):
    need(sys.stdin.isatty(),"A direct operator TTY is required")
    baseline=build(host,journal,False)
    print(json.dumps(baseline,sort_keys=True,indent=2),flush=True)
    approval=("STAGE-"+str(baseline["count"])+
              "-PERSISTENT-MASTER-NAT-GUESTS-BENIGN-ONLY")
    need(input("Type "+approval+" to attach NICs and reserve IPs: ")==
         approval,"Operator denied N guest network staging")
    need(not LOCK.is_symlink(),"Unsafe global NAT provisioning lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    mutated=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Untrusted NAT provisioning lock metadata")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NatAttachBlocked("Concurrent NAT operation in progress") from exc
        latest=build(host,journal,False)
        need(latest==baseline,
             "Host/VM/NAT state changed after operator consent")
        for item in baseline["dhcp_hosts"]:
            xml=("<host mac='"+item["mac"]+"' name='"+
                 item["name"]+"' ip='"+item["ip"]+"'/>")
            ET.fromstring(xml)
            mutated=True
            virsh("net-update",NETWORK,"add","ip-dhcp-host",xml,
                  "--live","--config",timeout=120)
            guest="win11_"+item["name"].split("-")[1]
            virsh("attach-interface",guest,"network",NETWORK,"--mac",
                  item["mac"],"--model","e1000e","--config",timeout=150)
        verified=build(host,journal,True)
        return {**verified,
          "result":"COMMAND2_ALL_N_MASTER_NAT_NICS_AND_DHCP_APPLIED_VERIFIED",
          "guest_booted_or_configured":False,
          "no_automatic_cape_registration":True}
    except Exception as exc:
        if mutated:
            raise NatAttachBlocked(
                "NAT_APPLY_ATTEMPTED_POSSIBLE_PARTIAL_GUEST_OR_DHCP_STATE: "
                "STOP. Do NOT rerun, delete, restart libvirt, boot samples "
                "or revert. Inspect each saved VM NIC and both net-dumpxml "
                "default views. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","apply","verify"),
                   default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        output=(apply(a.approved_host,a.journal) if a.mode=="apply" else
                build(a.approved_host,a.journal,a.mode=="verify"))
        print(json.dumps(output,sort_keys=True,indent=2),flush=True)
        return 0
    except (NatAttachBlocked,profile.PortableNatBlocked,
            workflow.WorkflowBlocked,workflow.snapshotgate.GateBlocked,
            allocator.NatPlanBlocked,ValueError,OSError,TypeError,KeyError,
            ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_ALL_N_PROVISION_BLOCKED",
                          "reason":str(exc),
                          "no_automatic_rollback_or_retry":True,
                          "host_mutation_possible_only_in_apply":a.mode=="apply"},
                         sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
