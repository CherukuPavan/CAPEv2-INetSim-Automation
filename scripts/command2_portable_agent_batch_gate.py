#!/usr/bin/env python3
"""Read-only all-N post-firstboot CAPE Agent + isolated live VM check.

Requires the exact private count-driven Command2 identity journal and
a live, independently host-isolated lab. This does NOT attest Windows
hostname/static-IP config, software TPM, snapshots or malware containment
from an agent HTTP result alone. No VM starts or write operations.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import command2_portable_workflow as workflow
import command2_portable_approved_firstboot as firstboot
import command2_guarded_isolated_nic as nic
import command2_cape_agent_probe as agent
import command2_running_snapshot_batch_gate as batch

class AgentBatchBlocked(RuntimeError):pass

def need(ok,why):
    if not ok:raise AgentBatchBlocked(why)

def virsh(*args):
    return firstboot.virsh(*args)

def check_one_live(row):
    vm=row["libvirt_name"]
    uid=row["libvirt_uuid_candidate"]
    need(virsh("domuuid",vm).lower()==uid and
         virsh("domstate",vm).lower()=="running",
         "Expected independent CAPE Windows clone must be running: "+vm)
    # Saved and live NIC graphs must BOTH describe the reserved isolated
    # interface. Do not call an agent on an unexpected NAT/host NIC.
    iso=Path(row["disk_target"]).parent/(vm+".command2_network_approved.iso")
    before=virsh("dumpxml","--inactive",vm)
    live=virsh("dumpxml",vm)
    firstboot.inspect_xml(before,vm,row,iso)
    firstboot.inspect_xml(live,vm,row,iso)
    for field in (
        "./devices/disk[@device='disk']/source",
        "./devices/interface/mac",
        "./devices/interface/source",
        "./devices/disk[@device='cdrom']/source",
        "./os/nvram",
    ):
        left=ET.fromstring(before).find(field)
        right=ET.fromstring(live).find(field)
        need(left is not None and right is not None and
             left.attrib==right.attrib and left.text==right.text,
             "Live/saved guest critical device drift for "+vm)
    return {"vm":vm,"uuid":uid,"expected_ip":row["guest_static_ipv4_target"],
            "isolated_nic_saved_and_live":True,
            "guest_running":True}

def audit(host,journal):
    workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for canonical private journal")
    need(isinstance(journal,Path) and journal.is_absolute() and
         journal.name=="command2-identity-reservation.json",
         "Exact private Command2 reservation required")
    batch.private_evidence_folder(journal.parent)
    rows=batch.reservation_rows(journal,host)
    need(bool(rows),"Empty Command2 count reservation")
    need(virsh("domstate","win11").lower()=="shut off",
         "Protected source Windows master should remain shut off")
    _,subnet,_=workflow.load_guest(journal,host,rows[0]["libvirt_name"])
    for row in rows:
        _,current,_=workflow.load_guest(journal,host,row["libvirt_name"])
        need(current==subnet,"Command2 guest subnets drifted")
    net=ipaddress.IPv4Network(subnet)
    bridge_ip=str(ipaddress.IPv4Address(int(net.network_address)+1))
    need(nic.verify_network_live(subnet,bridge_ip),
         "Host isolated nft/network runtime not admitted")
    preflight=[check_one_live(row) for row in rows]
    result=[]
    passed=0
    for item in preflight:
        record={**item,"status":"BLOCKED"}
        try:
            detail=agent.probe_agent(item["expected_ip"])
            need(detail.get("result")=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED" and
                 detail.get("guest_ip")==item["expected_ip"] and
                 detail.get("guest_agent_admin") is True,
                 "Unexpected CAPE Agent response")
            record["agent_version"]=detail["version"]
            record["status"]="AGENT_HTTP_ADMIN_VERIFIED"
            passed+=1
        except (AgentBatchBlocked,agent.AgentBlocked,OSError,ValueError,TypeError,KeyError) as err:
            record["reason"]=str(err)
        result.append(record)
    return {"result":"COMMAND2_ALL_GUESTS_CAPE_AGENT_CHECK_READONLY",
            "host":host,"count":len(rows),
            "positive_agent_count":passed,
            "all_agent_probes_passed":passed==len(rows),
            "guests":result,"no_guest_or_network_changes":True,
            "windows_hostname_ip_verified_in_guest":False,
            "zero_ipv4_ipv6_egress_rechecked_by_this_probe":False,
            "tpm_firmware_restore_proven":False,
            "running_snapshot_created":False,
            "command2_complete":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        report=audit(a.approved_host,a.journal)
        print(json.dumps(report,sort_keys=True,indent=2))
        return 0 if report["all_agent_probes_passed"] else 2
    except (AgentBatchBlocked,workflow.WorkflowBlocked,
            workflow.snapshotgate.GateBlocked,firstboot.ApprovedBootBlocked,
            nic.NicBlocked,OSError,ValueError,TypeError,ET.ParseError) as err:
        print(json.dumps({"result":"COMMAND2_ALL_GUEST_AGENT_AUDIT_BLOCKED",
              "reason":str(err),"guest_or_network_modified":False},
              sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
