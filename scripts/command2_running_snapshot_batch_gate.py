#!/usr/bin/env python3
"""Read-only Command2 FINAL per-VM CAPE running snapshot + revert audit.

Runs only on an explicitly approved OTHER host. This is a verifier, NOT a
snapshot creation, reversion, VM start, or CAPE registration tool.
A recorded operator witness is not cryptographic hardware attestation.
No user may treat internal disk+RAM metadata as swtpm/UEFI restoration proof.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

PREFIX="win11_"
GIB=1024**3
REFERENCE={"cse-ssl-55","ssl-55"}
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
REQUIRED_CYCLE=(
    "snapshot_captured_while_guest_running",
    "snapshot_internal_memory_verified",
    "snapshot_internal_disk_verified",
    "real_benign_snapshot_revert_executed",
    "post_revert_agent_http_admin_verified",
    "post_revert_windows_identity_ip_verified",
    "post_revert_uefi_nvram_consistency_verified",
    "post_revert_swtpm2_consistency_verified",
    "second_benign_revert_cycle_verified",
    "network_egress_and_l2_reverified_after_revert",
    "master_disk_unmodified",
)
class GateBlocked(RuntimeError):pass

def need(ok,why):
    if not ok:raise GateBlocked(why)

def rootfile(path,limit=128*1024):
    p=Path(path)
    need(p.is_absolute() and p.is_file() and not p.is_symlink(),
         "Expected root-private witness/journal file missing")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and
         stat.S_IMODE(s.st_mode)&0o077==0 and s.st_size<=limit,
         "Witness/journal file is not private or has unsafe metadata")
    return json.loads(p.read_text(encoding="utf-8"))

def run(*args):
    try:p=subprocess.run(args,check=False,text=True,capture_output=True,timeout=30)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise GateBlocked("Libvirt read-only utility unavailable: "+args[0]) from e
    need(p.returncode==0,"Libvirt read-only query failed: "+args[0])
    return p.stdout.strip()
def virsh(*args):return run("virsh","-c","qemu:///system",*args)

def host_guard(host):
    actual=socket.gethostname().split(".",1)[0].lower()
    need(os.geteuid()==0,"Root needed for private evidence")
    need(actual not in REFERENCE and not SENTINEL.exists() and
         not SENTINEL.is_symlink(),"SSL55 reference host protected")
    need(type(host) is str and
         re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",host) and
         actual==host,"Explicit approved OTHER-host identity required")

def reservation_rows(journal,host):
    data=rootfile(journal)
    need(type(data) is dict and data.get("format")==
         "CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION" and
         data.get("version")==1 and data.get("host")==host and
         data.get("host_network_modified") is False,
         "Unknown or unsuitable reservation journal")
    rows=data.get("entries");n=data.get("guest_count")
    need(type(n) is int and 1<=n<=16 and type(rows) is list and
         len(rows)==n,"Command2 guest count not 1..16")
    seen_uuid=set();seen_mac=set();seen_ip=set()
    for i,row in enumerate(rows,1):
        need(type(row) is dict and row.get("libvirt_name")==f"win11_{i}" and
             row.get("windows_hostname_target")==f"WIN11-{i}",
             "Guest identities not sequential")
        uid=row.get("libvirt_uuid_candidate")
        mac=row.get("mac_candidate")
        ip=row.get("guest_static_ipv4_target")
        need(type(uid) is str and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",uid) and
             type(mac) is str and re.fullmatch(r"02:(?:[0-9a-f]{2}:){4}[0-9a-f]{2}",mac) and
             type(ip) is str and
             uid not in seen_uuid and mac not in seen_mac and ip not in seen_ip,
             "Malformed or duplicate VM identity")
        seen_uuid.add(uid);seen_mac.add(mac);seen_ip.add(ip)
    return rows

def expected_guest(row, subnet):
    net=ipaddress.IPv4Network(subnet,strict=True)
    name=row["libvirt_name"]
    index=int(VM_RE.fullmatch(name).group(1))
    need(net.prefixlen==24 and net.is_private and
         net!=ipaddress.IPv4Network("192.168.122.0/24") and
         row["guest_static_ipv4_target"]==
             str(ipaddress.IPv4Address(int(net.network_address)+100+index)),
         "Guest IP/subnet differs from reserved offset")
    return name,"cape_ready_"+name

def live_domain(name,row):
    need(virsh("domuuid",name).lower()==row["libvirt_uuid_candidate"],
         "Libvirt UUID changed")
    need(virsh("domstate",name).lower()=="running",
         "CAPE snapshot requires a RUNNING guest for each VM")
    root=ET.fromstring(virsh("dumpxml",name))
    need(root.findtext("name")==name and
         root.findtext("uuid")==row["libvirt_uuid_candidate"],
         "Running XML guest identity differs")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==row["mac_candidate"],
         "Unexpected guest NIC (default NAT/LAN forbidden)")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Expected one QCOW2 Windows OS disk")
    firmware=root.find("./os/nvram")
    need(firmware is not None and
         firmware.text==row["uefi_nvram_target"],
         "Guest OVMF state not independently assigned")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Expected dedicated swtpm TPM2")
    need(not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem"),
         "Unexpected host passthrough")
    return {"running":True,"isolated_nic":True,
            "single_qcow2_disk":True,"swtpm2_present":True,
            "nvram_format":firmware.get("format","raw")}

def snapshot_metadata(name,snap):
    listed=virsh("snapshot-list",name,"--name").splitlines()
    need(listed.count(snap)==1,
         "CAPE running snapshot missing or ambiguously named")
    root=ET.fromstring(virsh("snapshot-dumpxml",name,snap))
    need(root.tag=="domainsnapshot" and root.findtext("name")==snap and
         root.findtext("state")=="running",
         "Snapshot was not recorded as RUNNING")
    mem=root.find("memory");disks=root.findall("./disks/disk")
    need(mem is not None and mem.get("snapshot")=="internal" and
         len(disks)==1 and disks[0].get("snapshot")=="internal",
         "CAPE snapshot lacks BOTH internal running memory and OS disk")
    return {"snapshot_name":snap,"state":"running",
            "memory_snapshot":"internal","os_disk_snapshot":"internal",
            "firmware_or_tpm_restored_by_metadata_alone":False}

def witness_gate(path,name,row,snapshot,host):
    data=rootfile(path,64*1024)
    need(type(data) is dict and
         data.get("format")=="COMMAND2_RUNNING_SNAPSHOT_REVERT_WITNESS_V1" and
         data.get("host")==host and data.get("vm")==name and
         data.get("uuid")==row["libvirt_uuid_candidate"] and
         data.get("mac")==row["mac_candidate"] and
         data.get("guest_ip")==row["guest_static_ipv4_target"] and
         data.get("snapshot")==snapshot,
         "Witness was not recorded for exact VM/host/snapshot")
    need(all(data.get(k) is True for k in REQUIRED_CYCLE),
         "Actual running revert + TPM/UEFI + repeated benign acceptance incomplete")
    op=data.get("operator")
    need(type(op) is str and len(op.strip())>=3 and
         data.get("witness_details") and
         isinstance(data["witness_details"],str) and
         len(data["witness_details"].strip())>=20,
         "Missing recorded operator and concrete witness details")
    return {"operator_witness_received":True,
            "real_attestation_cryptographically_verified":False,
            "required_revert_gates_recorded":len(REQUIRED_CYCLE)}

def evaluate(rows,subnet,host,journal,witness_dir):
    entries=[];passed=0
    for row in rows:
        name=row["libvirt_name"]
        result={"vm":name,"status":"BLOCKED"}
        try:
            guest,snap=expected_guest(row,subnet)
            result["runtime"]=live_domain(guest,row)
            result["snapshot"]=snapshot_metadata(guest,snap)
            witness=Path(witness_dir)/(name+".running-snapshot-witness.json")
            result["revert_witness"]=witness_gate(witness,guest,row,snap,host)
            result["status"]="WITNESS_AND_LIVE_SNAPSHOT_GATES_RECORDED"
            passed+=1
        except (GateBlocked,OSError,ValueError,ET.ParseError,TypeError) as exc:
            result["blocker"]=str(exc)
        entries.append(result)
    return {"result":"COMMAND2_PER_VM_SNAPSHOT_RELEASE_READ_ONLY",
            "expected_vms":len(rows),"witnessed_gates_count":passed,
            "all_vm_snapshots_and_revert_evidence_present":passed==len(rows),
            "vm_results":entries,
            "running_snapshot_created_by_this_script":False,
            "revert_performed_by_this_script":False,
            "raw_pflash_swtpm_atomic_restore_guaranteed_by_metadata":False,
            "operator_witness_is_independent_hardware_proof":False,
            "real_two_vm_benign_parallel_cape_tested_here":False,
            "production_release_authorized_by_this_script":False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--subnet",required=True)
    p.add_argument("--witness-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        host_guard(a.approved_host)
        need(a.witness_dir.is_absolute() and a.witness_dir.is_dir() and
             not a.witness_dir.is_symlink(),"Missing approved witness directory")
        rows=reservation_rows(a.journal,a.approved_host)
        out=evaluate(rows,a.subnet,a.approved_host,a.journal,a.witness_dir)
        print(json.dumps(out,indent=2,sort_keys=True))
        return 0 if out["all_vm_snapshots_and_revert_evidence_present"] else 2
    except (GateBlocked,OSError,ValueError,TypeError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_SNAPSHOT_RELEASE_BLOCKED",
                          "reason":str(exc),"host_changes_made":False},
                         indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
