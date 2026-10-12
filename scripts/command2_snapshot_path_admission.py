#!/usr/bin/env python3
"""Command 2 snapshot lifecycle inventory for ALL requested Windows clones.

Read-only bridge from the portable count-driven reservation to the staged
OVMF QCOW2 conversion and CAPE snapshot gates. Never calls virsh snapshot,
define, start, destroy, revert, or changes firmware or network.

The canonical SSL-55 reference is *inspect-only*; its RAW pflash is NOT
convertible while running. On other hosts this planner reports the first
missing phase for EACH VM. It does not manufacture approval witnesses.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
PILOT_UUID="732b2256-ee99-41fa-881d-fbf5c476d960"

class AdmissionBlocked(RuntimeError):pass

def require(condition, message):
    if not condition:raise AdmissionBlocked(message)

def virsh(*args):
    try:
        res=subprocess.run(["virsh","-c","qemu:///system",*args],
                           text=True,capture_output=True,timeout=30)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AdmissionBlocked("Read-only libvirt query unavailable") from exc
    require(res.returncode==0 and len(res.stdout)<512*1024,
            "Read-only libvirt query returned failure")
    return res.stdout.strip()

def classify_xml(vm, expected_uuid, raw, state, names):
    root=ET.fromstring(raw)
    require(root.tag=="domain" and root.findtext("name")==vm and
            root.findtext("uuid")==expected_uuid,
            "VM exact UUID/name changed")
    require(state in ("running","shut off"),
            "VM has unexpected state")
    disks=root.findall("./devices/disk[@device='disk']")
    require(len(disks)==1 and disks[0].find("source") is not None and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type")=="qcow2",
            "Expected standalone single QCOW2 OS disk")
    backing=disks[0].find("backingStore")
    require(backing is None or
            (backing.find("source") is None and
             backing.find("backingStore") is None),
            "Unexpected backing chain in guest XML")
    tpm=root.find("./devices/tpm/backend")
    require(tpm is not None and tpm.get("type")=="emulator" and
            tpm.get("version")=="2.0",
            "Independent Windows TPM2 expected")
    nv=root.find("./os/nvram")
    require(nv is not None and nv.text and
            nv.text.endswith("/"+vm+".command2_VARS.fd") or
            (nv is not None and nv.text and
             nv.text.endswith("/"+vm+".command2_VARS.fd.qcow2")),
            "Unexpected OVMF guest NVRAM path")
    format=nv.get("format","raw")
    require(format in ("raw","qcow2"),"Unexpected OVMF NVRAM format")
    nics=root.findall("./devices/interface")
    require(len(nics)<=1,"Unexpected multiple analysis guest NICs")
    if nics:
        source=nics[0].find("source")
        require(nics[0].get("type")=="network" and source is not None and
                source.get("network")=="cape-analysis-isolated",
                "Analysis guest connected to non-isolated libvirt network")
    snap="cape_ready_"+vm
    snap_exists=snap in names
    if format=="raw":
        require(nv.text.endswith(".fd"),
                "RAW NVRAM XML points to QCOW2 sidecar")
        phase="STANDALONE_RAW_OVMF_SNAPSHOT_BLOCKED"
        action=("If disposable, first verify full stopped-state disk/OVMF/swtpm "
                "backup AND real cold restore; then shut down guest and "
                "prepare/activate a separate QCOW2 OVMF sidecar.")
    elif not nv.text.endswith(".fd.qcow2"):
        phase="NVRAM_FORMAT_PATH_MISMATCH"
        action="Refuse snapshot; inspect saved and actual QEMU NVRAM format."
    elif not nics:
        phase="ZERO_NIC_STAGE_NOT_ANALYSIS_READY"
        action="Complete guarded guest identity and isolated-NIC/Windows IP acceptance."
    elif not snap_exists:
        phase="RUNNING_SNAPSHOT_NOT_YET_CAPTURED"
        action=("Verify running Agent, real isolation and cold recovery proof; "
                "capture each guest's own running memory+disk snapshot on approved lab host.")
    else:
        phase="SNAPSHOT_METADATA_AND_REAL_REVERT_EVIDENCE_REQUIRED"
        action=("Inspect running snapshot XML and witness two benign TPM/UEFI/"
                "Windows/Agent/IPv4/IPv6/L2 reversions; shut VM off for CAPE.")
    return {"vm":vm,"uuid":expected_uuid,"state":state,
            "ovmf_xml_format":format,"ovmf_xml_path":nv.text,
            "isolated_nic_count":len(nics),
            "expected_running_snapshot":snap,
            "snapshot_name_exists":snap_exists,
            "phase":phase,"next_required_work":action,
            "vm_snapshot_revert_proven_by_inventory":False,
            "tpm_state_revert_proven_by_inventory":False,
            "snapshot_created":False}

def rows_from_reserved_journal(path, host):
    """Use the exact existing count-driven reservation; no regenerated IDs."""
    p=Path(path)
    require(p.is_absolute() and p.name=="command2-identity-reservation.json"
            and p.is_file() and not p.is_symlink(),
            "Exact existing absolute reservation journal required")
    ds=p.parent.stat()
    require(ds.st_uid==0 and stat.S_IMODE(ds.st_mode)&0o077==0 and
            not p.parent.is_symlink(),
            "Reservation directory must be root-private")
    meta=p.stat()
    require(meta.st_uid==0 and meta.st_nlink==1 and
            stat.S_IMODE(meta.st_mode)&0o077==0 and
            meta.st_size<=128*1024,
            "Reservation file must be root-private and bounded")
    data=json.loads(p.read_text(encoding="utf-8"))
    require(type(data) is dict and
            data.get("format")=="CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION" and
            data.get("version")==1 and data.get("host")==host and
            data.get("host_network_modified") is False,
            "Reservation schema or host mismatch")
    entries=data.get("entries")
    count=data.get("guest_count")
    require(type(count) is int and 1<=count<=16 and
            type(entries) is list and len(entries)==count,
            "Invalid staged VM count")
    result=[]
    for index,entry in enumerate(entries,1):
        require(type(entry) is dict and
                entry.get("libvirt_name")==f"win11_{index}" and
                type(entry.get("libvirt_uuid_candidate")) is str,
                "Invalid ordered VM identity reservation")
        result.append((entry["libvirt_name"],
                       entry["libvirt_uuid_candidate"]))
    return result

def inventory(guest_expectations):
    seen=set()
    values=[]
    require(len({vm for vm,_ in guest_expectations})==len(guest_expectations),
            "Guest name/UUID list invalid or duplicated")
    require(len({uuid for _,uuid in guest_expectations})==len(guest_expectations),
            "Guest name/UUID list invalid or duplicated")
    for vm,uuid in guest_expectations:
        require(type(vm) is str and VM_RE.fullmatch(vm) is not None and
                type(uuid) is str and len(uuid)==36 and
                vm not in seen,"Guest name/UUID list invalid or duplicated")
        seen.add(vm)
        require(virsh("domuuid",vm).lower()==uuid,
                "Guest libvirt UUID mismatch: "+vm)
        state=virsh("domstate",vm).lower()
        root=virsh("dumpxml","--inactive",vm)
        snames=set(virsh("snapshot-list",vm,"--name").splitlines())
        values.append(classify_xml(vm,uuid,root,state,snames))
    require(bool(values),"No Command 2 guests requested")
    return {"result":"COMMAND2_SNAPSHOT_LIFECYCLE_INVENTORY_READONLY",
            "host":socket.gethostname().split(".",1)[0].lower(),
            "guest_count":len(values),"guests":values,
            "no_guest_or_network_mutation":True,
            "all_snapshots_working":False,
            "production_ready":False}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--reference-ssl55",action="store_true",
                    help="Inspect exact existing SSL-55 win11_1 only")
    ap.add_argument("--guest",action="append",default=[],
                    help="Other-host strict VM=UUID (repeat for all reserved VMs)")
    ap.add_argument("--journal",type=Path,\n                    help="Other-host count-driven root-private reservation journal")\n    a=ap.parse_args()
    try:
        host=socket.gethostname().split(".",1)[0].lower()
        if a.reference_ssl55:
            require(host=="cse-ssl-55" and not a.guest and a.journal is None,
                    "SSL55 reference request on wrong host or mixed target")
            require(virsh("domuuid","win11").lower()==MASTER_UUID and
                    virsh("domstate","win11").lower()=="shut off",
                    "Protected SSL55 master changed")
            rows=[("win11_1",PILOT_UUID)]
        else:
            require(host not in ("cse-ssl-55","ssl-55"),
                    "Reference host refuses other-host candidate operations")
            require(not (a.guest and a.journal),
                    "Choose --journal or explicit --guest, never both")
            if a.journal is not None:
                require(os.geteuid()==0,
                        "Root required to read private count-driven journal")
                rows=rows_from_reserved_journal(a.journal,host)
            else:
                require(bool(a.guest),"Explicit per-VM reserved UUIDs required")
                rows=[]
                for item in a.guest:
                    pair=item.split("=",1)
                    require(len(pair)==2,"Use --guest win11_N=reserved-uuid")
                    rows.append(tuple(pair))
        print(json.dumps(inventory(rows),sort_keys=True,indent=2))
        return 0
    except (AdmissionBlocked,ET.ParseError,TypeError,ValueError) as exc:
        print(json.dumps({"result":"COMMAND2_SNAPSHOT_INVENTORY_BLOCKED",
                          "reason":str(exc),"host_modified":False}),
              file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
