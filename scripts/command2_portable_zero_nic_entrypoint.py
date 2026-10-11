#!/usr/bin/env python3
"""Command 2 development entrypoint: plan or stage ZERO-NIC clones on NEW host.

NOT the finished two-command installer. In --mode stage on an approved
separate host, can allocate large disk images and define shut-off VMs.
NO NIC is connected, no guest is booted, no Windows hostname/IP applied.
Never run on the protected SSL-55 reference machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_target_host_preflight as audit
import command2_guest_identity_blueprint as identity
import command2_identity_reservation_journal as reserve
import command2_portable_zero_nic_stager as stager
import command2_windows_guest_config as guestconfig
import command2_isolated_network_xml_plan as netdesign


class Command2Blocked(RuntimeError):
    pass


def require(condition, why):
    if not condition:
        raise Command2Blocked(why)


def read_inventory():
    """Source read-only UUID/MAC inventory from inactive + live libvirt and NICs."""
    raw=stager.virsh("list","--all","--name")
    domains=[n for n in raw.splitlines() if n.strip()]
    uuids=[]
    macs=[]
    for vm in domains:
        uuids.append(stager.virsh("domuuid",vm).strip().lower())
        xmls=[stager.virsh("dumpxml","--inactive",vm)]
        if stager.virsh("domstate",vm).strip() == "running":
            xmls.append(stager.virsh("dumpxml",vm))
        for raw_xml in xmls:
            root=ET.fromstring(raw_xml)
            for mac in root.findall("./devices/interface/mac"):
                value=mac.get("address")
                if value:
                    macs.append(value.lower())
    raw_network=audit.json_command("ip","-j","link","show")
    require(type(raw_network) is list,
            "Cannot verify all existing host interface MAC addresses")
    for item in raw_network:
        require(type(item) is dict,"Malformed host link inventory")
        val=item.get("address","").lower()
        if val and val!="00:00:00:00:00:00" and len(val.split(":"))==6:
            macs.append(val)
    # Duplicates between live and inactive XML are legitimate; de-duplicate.
    return sorted(set(uuids)), sorted(set(macs))


def source_profile():
    xml=stager.virsh("dumpxml","--inactive","win11")
    root=ET.fromstring(xml)
    require(root.findtext("name")=="win11","Expected exact Command 1 Windows master")
    master_uuid=stager.virsh("domuuid","win11").strip().lower()
    require(root.findtext("uuid")==master_uuid,"Master UUID or definition differs")
    nvram=root.findtext("./os/nvram")
    require(isinstance(nvram,str) and nvram.startswith("/"),
            "Missing source OVMF NVRAM")
    return master_uuid,Path(nvram)


def vm_memory_mib(master_xml):
    root=ET.fromstring(master_xml)
    m=root.find("memory")
    require(m is not None and m.text and m.text.strip().isdigit(),
            "Windows master RAM XML missing")
    unit=m.get("unit","KiB")
    value=int(m.text.strip())
    conversions={"KiB":1/1024,"MiB":1,"GiB":1024,
                 "k":1/1024,"M":1,"G":1024}
    require(unit in conversions,"Unreviewed Windows master memory unit")
    mib=int(value*conversions[unit])
    require(mib>=2048 and mib<=65536,
            "Unreasonable Windows master RAM allocation")
    return mib


def guard_host(approved_host, mode):
    stager.host_guard(approved_host,for_stage=(mode=="stage"))


def proposal(*,count,approved_host,disk_dir,nvram_dir,template,subnet):
    guard_host(approved_host,"plan")
    facts=audit.collect(str(disk_dir),str(nvram_dir),str(template),count)
    report=audit.evaluate(facts,count,str(disk_dir),str(nvram_dir),subnet)
    require(report["preflight_pass"],
            "Target-host read-only preflight blocks provisioning: "+
            ",".join(report["errors"]))
    master_xml=stager.virsh("dumpxml","--inactive","win11")
    guest_ram_mib=vm_memory_mib(master_xml)
    need=count*guest_ram_mib + audit.HOST_RAM_RESERVE_MIB
    require(facts.get("available_ram_mib") is not None and
            facts["available_ram_mib"]>=need,
            "Insufficient available RAM for actual cloned VM sizing")
    uuids,macs=read_inventory()
    candidate=identity.blueprint(report,existing_uuids=uuids,
                                 existing_macs=macs)
    # Validate all per-guest Windows config schemas while still read-only.
    for row in candidate["candidates"]:
        guestconfig.make_guest_config(row,subnet)
    network_plan=netdesign.plan("cape-analysis-isolated","cape-lab0",
                                subnet,[r["guest_static_ipv4_target"]
                                        for r in candidate["candidates"]])
    return candidate,{"actual_master_memory_mib":guest_ram_mib,
                      "available_ram_mib":facts["available_ram_mib"],
                      "required_total_gib":report["storage_required_gib"],
                      "isolated_network_design_only":network_plan,
                      "resource_preflight_pass":True}


def staging_dir(path):
    folder=Path(path)
    require(folder.is_absolute() and not folder.is_symlink(),
            "Absolute nonsymlink root-private state directory required")
    parent=folder.parent
    stager.exact_dir(parent)
    if not folder.exists():
        folder.mkdir(mode=0o700)
    stager.exact_dir(folder,mode=0o700)
    return folder


def execute(*, count,approved_host,disk_dir,nvram_dir,template,
            template_sha256,subnet,journal_dir,mode):
    require(mode in ("plan","stage"),"Unsupported Command 2 stage")
    guard_host(approved_host,mode)
    candidates,resources=proposal(
        count=count,approved_host=approved_host,disk_dir=disk_dir,
        nvram_dir=nvram_dir,template=template,subnet=subnet)
    report={"result":"COMMAND2_ZERO_NIC_GROUP_PLAN_ONLY",
            "requested_total":count,
            "names":[r["libvirt_name"] for r in candidates["candidates"]],
            "target_host":approved_host,
            "resources":resources,
            "guest_personalization_done":False,
            "network_isolation_verified":False,
            "nics_attached":0,"guests_booted":0,
            "hosts_modified":False}
    if mode=="plan":
        return report
    require(os.geteuid()==0,"Separate-host staging requires root")
    require(sys.stdin.isatty(),"Interactive operator terminal required")
    need_phrase="APPROVE_COMMAND2_ZERO_NIC_"+approved_host.upper()
    require(input("Type "+need_phrase+" to reserve and stage guests: ")==need_phrase,
            "Explicit operator approval missing")
    # Before any persistent reservation, refuse a preexisting journal
    # from a prior invocation rather than regenerate random identities.
    folder=Path(journal_dir)
    if folder.exists():
        require(not (folder/reserve.RECORD_NAME).exists(),
                "Existing identity reservation: manual reconcile before retry")
    folder=staging_dir(folder)
    recorded=reserve.reserve(candidates,folder,expected_host=approved_host)
    require(recorded["guest_count"]==count and not recorded["guest_vm_created"],
            "Reservation output mismatches expected count")
    # Private, exclusively created per-VM configuration files. These
    # are NOT auto-delivered or run in Windows until a verified bootstrap
    # channel is installed and host network containment has been accepted.
    configs=[]
    for row in candidates["candidates"]:
        config=guestconfig.make_guest_config(row,subnet)
        filename="command2-guest-config-"+row["libvirt_name"]+".json"
        stager.atomic_note(folder,filename,config)
        checksum=hashlib.sha256((json.dumps(config,sort_keys=True,
                   separators=(",",":"))+"\n").encode("utf-8")).hexdigest()
        configs.append({"name":row["libvirt_name"],
                        "configuration_sha256":checksum,
                        "configuration_created_but_not_delivered":True})
    master_uuid,master_nvram=source_profile()
    stage_report=stager.execute(
        mode="stage",approved_host=approved_host,journal_dir=folder,
        template=Path(template),template_sha256=template_sha256,
        master_nvram=master_nvram,master_uuid=master_uuid,subnet=subnet)
    return {"result":"COMMAND2_ZERO_NIC_GROUP_STAGE_RETURNED",
            "reservation_status":recorded["status"],
            "staging":stage_report,
            "guest_configuration_files":configs,
            "guest_personalization_done":False,
            "network_isolation_verified":False,
            "production_ready":False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","stage"),default="plan")
    ap.add_argument("--count",type=int)
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--disk-dir",type=Path,required=True)
    ap.add_argument("--nvram-dir",type=Path,required=True)
    ap.add_argument("--template",type=Path,required=True)
    ap.add_argument("--template-sha256",required=True)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--journal-dir",type=Path,required=True)
    args=ap.parse_args()
    try:
        count=args.count
        if count is None:
            require(sys.stdin.isatty(),"Count required in noninteractive mode")
            count=int(input("TOTAL requested Windows VMs (1-16): "))
        result=execute(
            count=count,approved_host=args.approved_host,
            disk_dir=args.disk_dir,nvram_dir=args.nvram_dir,
            template=args.template,template_sha256=args.template_sha256,
            subnet=args.subnet,journal_dir=args.journal_dir,mode=args.mode)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (Command2Blocked, stager.StageBlocked, identity.BlueprintBlocked,
            reserve.ReservationBlocked, OSError,ValueError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
