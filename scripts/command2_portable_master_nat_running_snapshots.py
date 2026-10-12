#!/usr/bin/env python3
"""OTHER-HOST all-N RUNNING golden master-NAT snapshot candidates.

After EACH uniquely identified Windows clone has a root-private independent
guest hostname/DHCP/DNS/real HTTPS witness and the whole N NAT Agent batch
is healthy, create one visible libvirt internal RAM+Windows QCOW2+UEFI QCOW2
checkpoint per VM. Original master win11 remains shut off. No guest first
boots/configuration occur here. Failure stops immediately and preserves
earlier successful captures; no auto-retry/revert/delete/reboot.

CRITICAL: swtpm2 persistent/volatile state is NOT captured atomically by
native QEMU snapshots. These are experimental RUNNING checkpoint candidates,
NOT a CAPE-safe-revert or malware-execution permission.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_portable_master_nat_agent_batch as agents
import command2_native_snapshot_stack_guard as native
import command2_portable_nat_agent_verify as witness
import command2_portable_master_nat_attach as attach

GIB=1024**3
RESERVE=40*GIB
LOCK=Path("/run/lock/cape-command2-master-nat-snapshot-batch.lock")
RECEIPT_SUFFIX=witness.SUFFIX
class NATSnapshotBlocked(RuntimeError):pass
def need(x,msg):
    if not x:raise NATSnapshotBlocked(msg)

def images(row,with_snapshot):
    name=row["libvirt_name"]
    snap="cape_one_nat_"+name
    labels={}
    xml=ET.fromstring(attach.virsh("dumpxml","--inactive",name))
    disk=xml.find("./devices/disk[@device='disk']/source")
    nv=xml.find("./os/nvram")
    need(disk is not None and disk.get("file")==row["disk_target"] and
         nv is not None and nv.get("format")=="qcow2" and
         (nv.text or "") in (row["uefi_nvram_target"]+".qcow2",
                             row["uefi_nvram_target"]),
         "Independent Windows OS / QCOW2 UEFI image differs from golden clone")
    for key,path in (("Windows_OS",Path(disk.get("file"))),
                     ("QCOW2_UEFI",Path(nv.text))):
        need(path.is_absolute() and path.is_file() and
             not path.is_symlink() and path.stat().st_nlink==1,
             "Non-independent or symlinked guest image: "+key)
        info=json.loads(native.command(
            "qemu-img","info","-U","--output=json",str(path)))
        need(type(info) is dict and info.get("format")=="qcow2" and
             not info.get("backing-filename"),
             "Snapshot image is not independent QCOW2: "+key)
        x=info.get("snapshots",[])
        need(type(x) is list and all(type(a) is dict and
             type(a.get("name")) is str for a in x),
             "Malformed QEMU checkpoint inventory: "+key)
        names=[a["name"] for a in x]
        need(names==([snap] if with_snapshot else []),
             "Unexpected/partial QEMU internal snapshot labels: "+key)
        labels[key]={"path":str(path),"checkpoint_names":names,
                     "qcow2_standalone":True}
    return labels

def libvirt_snapshot(vm,exists):
    name="cape_one_nat_"+vm
    rows=[s.strip() for s in attach.virsh("snapshot-list",vm,"--name")
          .splitlines() if s.strip()]
    need(rows==([name] if exists else []),
         "Unexpected libvirt snapshot inventory for "+vm)
    if not exists:return {"snapshot_already_exists":False}
    raw=ET.fromstring(attach.virsh("snapshot-dumpxml",vm,name))
    mem=raw.find("memory")
    dom=raw.find("domain")
    disks=raw.findall("./disks/disk")
    need(raw.tag=="domainsnapshot" and raw.findtext("name")==name and
         raw.findtext("state")=="running" and
         mem is not None and mem.get("snapshot")=="internal" and
         dom is not None and
         dom.findtext("name")==vm and
         sum(x.get("name")=="sda" and x.get("snapshot")=="internal"
             for x in disks)==1,
         "Live RAM + Windows system disk not captured in libvirt")
    nics=dom.findall("./devices/interface")
    need(len(nics)==1 and nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="default" and
         nics[0].find("model") is not None and
         nics[0].find("model").get("type")=="e1000e",
         "Snapshot embedded guest not one permanent master default NAT NIC")
    return {"snapshot_already_exists":True,"captured_running_ram":True,
            "captured_Windows_system_disk":True,
            "snapshot_name":name}

def attest_guest(row,host,evidence):
    folder=witness.transport.verified_evidence_folder(evidence)
    f=folder/(row["libvirt_name"]+RECEIPT_SUFFIX)
    data=witness.approved.trusted_stage_json(f)
    vm=row["libvirt_name"]
    need(data.get("format")=="COMMAND2_WINDOWS_NAT_INDEPENDENT_ACCEPTANCE_V1" and
         data.get("host")==host and data.get("vm")==vm and
         data.get("uuid")==row["libvirt_uuid_candidate"] and
         data.get("mac")==row["mac_candidate"].lower() and
         data.get("target_nat_ip") and
         data.get("CAPE_agent_through_new_nat_and_L2_mac_verified") is True and
         all(data.get(k) is True for k in (
           "guest_hostname_effective",
           "guest_only_expected_mac","guest_dhcp_exact_reserved_ipv4",
           "guest_default_nat_gateway_and_dns",
           "real_guest_https_from_nat_ipv4",
           "guest_script_ran_in_verify_readonly_mode")) and
         data.get("running_memory_disk_uefi_snapshot_captured") is False and
         data.get("swtpm_consistent_revert_proven") is False and
         data.get("malware_analysis_authorized") is False,
         "Exact Windows NAT DHCP/hostname/HTTPS acceptance missing: "+vm)
    return hashlib.sha256(f.read_bytes()).hexdigest()

def assess(host,journal,evidence_dir,with_snapshots):
    need(isinstance(with_snapshots,bool),"Expected exact plan or verify state")
    rows=attach.journal_rows(host,journal)
    need(1<=len(rows)<=16,"Expected exact 1..16 cloned Windows identities")
    batch=agents.check(host,journal)
    need(batch["count"]==len(rows) and
         batch["result"]=="COMMAND2_ALL_N_MASTER_NAT_AGENTS_RUNNING_VERIFIED_READONLY",
         "N running NAT/Agent MAC and DHCP verification incomplete")
    journal_sha=hashlib.sha256(Path(journal).read_bytes()).hexdigest()
    allmem=0
    filesystems={}
    checked=[]
    for row,proof in zip(rows,batch["guests"]):
        vm=row["libvirt_name"]
        need(proof["vm"]==vm and
             proof["mac"]==row["mac_candidate"].lower() and
             proof["reserved_unique_mac_ip_live_and_persistent"] is True and
             proof["saved_live_one_master_nat_nic"] is True and
             proof["host_gateway_route_verified"] is True and
             proof["cape_agent"]["valid"] is True,
             "Guest Agent/MAC identity differs from canonical journal")
        receipt_sha=attest_guest(row,host,evidence_dir)
        stack=native.inspect(vm)
        need(stack.get("uefi_variable_store_real_format")=="qcow2" and
             stack.get("swtpm2_present") is True and
             stack.get("snapshot_created") is False,
             "Guest running QCOW2 UEFI/swtpm snapshot admission failed")
        metadata=libvirt_snapshot(vm,with_snapshots)
        qemu=images(row,with_snapshots)
        ram=stack["guest_ram_bytes"];allmem+=ram
        disk=Path(row["disk_target"])
        filesystems[disk.stat().st_dev]=disk.parent
        checked.append({"vm":vm,"uuid":row["libvirt_uuid_candidate"],
            "expected_name":"cape_one_nat_"+vm,
            "saved_windows_witness_sha256":receipt_sha,
            "libvirt_running_snapshot":metadata,
            "Windows_OS_and_UEFI_qcow2_snapshots":qemu,
            "guest_ram_bytes":ram,
            "snapshot_captured":with_snapshots,
            "swtpm_state_consistency_at_checkpoint_proved":False})
    if not with_snapshots:
        for folder in filesystems.values():
            st=os.statvfs(folder)
            need(st.f_bavail*st.f_frsize>=RESERVE+2*allmem+2*GIB,
                 "Not enough shared storage for N running RAM checkpoints + reserve")
    return {"result":("COMMAND2_MASTER_NAT_ALL_N_RUNNING_CANDIDATES_VERIFIED"
                      if with_snapshots else
                      "COMMAND2_MASTER_NAT_ALL_N_SNAPSHOT_PREFLIGHT"),
        "host":host,"count":len(rows),
        "journal_sha256":journal_sha,
        "guest_snapshots":checked,
        "all_guest_windows_hostname_dhcp_dns_https_proven":True,
        "all_running_native_snapshots_created":with_snapshots,
        "previously_captured_snapshots_will_not_be_deleted":True,
        "swtpm_epoch_matched_backup_and_twice_benign_revert_proven":False,
        "real_public_malware_access_authorized":False,
        "CAPE_READY":False,
        "no_vm_restart_revert_or_shutdown_requested":True}

def capture(host,journal,evidence_dir):
    need(sys.stdin.isatty(),"Interactive full N snapshot approval required")
    before=assess(host,journal,evidence_dir,False)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    phrase=f"CAPTURE-{before['count']}-MASTER-NAT-RUNNING-TPM-UNVERIFIED"
    need(input("Type "+phrase+" for guarded N running candidates: ")==phrase,
         "Operator declined N running Windows snapshot candidates")
    need(not LOCK.is_symlink(),"Untrusted snapshot lock path")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "Root-private snapshot lock required")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise NATSnapshotBlocked("Concurrent snapshot batch running") from e
        now=assess(host,journal,evidence_dir,False)
        need(now==before,"N guests/journal/Windows evidence changed after consent")
        for guest in before["guest_snapshots"]:
            vm=guest["vm"]
            # Recheck current guest old-state, without requiring all remaining
            # guests to be snapshot-free after previous members are captured.
            need(not attach.virsh("snapshot-list",vm,"--name").strip(),
                 "Unexpected preexisting snapshot on "+vm)
            attempted=True
            attach.virsh("snapshot-create-as","--domain",vm,
                         "--name",guest["expected_name"],
                         "--atomic",timeout=1800)
            libvirt_snapshot(vm,True)
            images(next(r for r in attach.journal_rows(host,journal)
                        if r["libvirt_name"]==vm),True)
        return assess(host,journal,evidence_dir,True)
    except Exception as exc:
        if attempted:
            raise NATSnapshotBlocked(
                "RUNNING_SNAPSHOT_BATCH_ATTEMPTED_PARTIAL_STATE_POSSIBLE: "
                "STOP; do not retry, delete, revert or restart Windows. "+
                str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","capture","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--evidence-dir",type=Path,required=True)
    args=p.parse_args()
    try:
        value=(capture(args.approved_host,args.journal,args.evidence_dir)
               if args.mode=="capture" else assess(args.approved_host,args.journal,
                          args.evidence_dir,args.mode=="verify"))
        print(json.dumps(value,sort_keys=True,indent=2),flush=True)
        return 0
    except (NATSnapshotBlocked,agents.BatchAgentBlocked,
            native.NativeBlocked,attach.NatAttachBlocked,
            attach.profile.PortableNatBlocked,
            attach.workflow.WorkflowBlocked,ValueError,TypeError,
            KeyError,OSError,ET.ParseError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND2_MASTER_NAT_RUNNING_SNAPSHOTS_BLOCKED",
             "reason":str(exc),"do_not_auto_retry_or_revert":True,
             "no_TPM_safe_restore_claim":True},sort_keys=True),
             file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
