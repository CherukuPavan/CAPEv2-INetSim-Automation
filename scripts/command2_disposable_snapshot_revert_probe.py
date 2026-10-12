#!/usr/bin/env python3
"""One operator-approved CAPE-style running-snapshot revert on OTHER host.

A destructive revert is permitted ONLY on approved disposable Command2
guests with a byte-verified separate disk/OVMF/swtpm cold bundle, a
libvirt running-memory + internal disk snapshot and correct one-NIC
isolated network. The VM must be SHUT OFF before revert, matching
standard CAPE LibVirtMachinery.start() semantics.

Does NOT create/alter the snapshot, stop/force-stop or power-cycle any
guest, modify host policy or authorize malware. A successful revert + agent
HTTP test is NOT proof of swtpm, Secure Boot, BitLocker, IPv6/L2 isolation
or repeated revert consistency. These require actual guest/off-guest proof.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import command2_portable_workflow as flow
import command2_running_snapshot_batch_gate as batch
import command2_snapshot_recovery_preflight as cold
import command2_native_snapshot_stack_guard as native
import command2_cape_agent_probe as agent

LOCK=Path("/run/lock/cape-command2-disposable-revert.lock")
class RevertBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise RevertBlocked(why)
def virsh(*args,timeout=90):
    try:r=subprocess.run(["virsh","-c","qemu:///system",*args],
            capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise RevertBlocked("Libvirt command unavailable or timed out") from e
    need(r.returncode==0,"Libvirt requested operation returned failure: "+args[0])
    return r.stdout.strip()

def plan(host,journal,vm,bundle,manifest_sha):
    try:flow.canonical_host(host)
    except flow.WorkflowBlocked as e:raise RevertBlocked(str(e)) from e
    need(os.geteuid()==0,"Root required for protected full cold bundle")
    row,subnet,_=flow.load_guest(journal,host,vm)
    uid=row["libvirt_uuid_candidate"]
    need(type(manifest_sha) is str and re.fullmatch(r"[0-9a-f]{64}",manifest_sha),
         "Exact reviewed cold manifest SHA256 is required")
    reviewed=cold.inspect(vm,uid,bundle,manifest_sha)
    need(virsh("domuuid",vm).lower()==uid and
         virsh("domstate",vm).lower()=="shut off",
         "Exact disposable clone must be SHUT OFF before snapshot revert")
    need(virsh("domstate","win11").lower()=="shut off",
         "Original Windows source must be shut off")
    need(not virsh("list","--name").strip(),
         "Another guest running; one isolated benign revert test at a time")
    # Final CAPE snapshot gate uses the INACTIVE domain because CAPE
    # starts from a VM that is currently shut off.
    vmstate=batch.live_domain(vm,row)
    snap="cape_ready_"+vm
    meta=batch.snapshot_metadata(vm,snap)
    # The saved firmware must be active QCOW2 on disk and in XML.
    # The modern stack helper requires an active guest XML. A stopped
    # domain lacks live RAM, so validate the static firmware via the
    # strict final batch gate above instead.
    need(vmstate.get("nvram_format")=="qcow2" and
         meta["state"]=="running" and
         meta["memory_snapshot"]=="internal" and
         meta["os_disk_snapshot"]=="internal",
         "Candidate lacks native QCOW2 firmware + running memory/disk snapshot")
    return {
        "result":"COMMAND2_DISPOSABLE_RUNNING_REVERT_PLAN_ONLY",
        "host":host,"vm":vm,"uuid":uid,
        "guest_ip":row["guest_static_ipv4_target"],
        "subnet":subnet,
        "snapshot":snap,
        "reviewed_full_cold_recovery_manifest_sha256":reviewed["manifest_sha256"],
        "cold_bundle_files_rehashed":True,
        "one_disposable_guest_shut_off":True,
        "master_off":True,
        "snapshot_captured_running_internal_disk_ram":True,
        "qcow2_ovmf_active":True,
        "guest_modified":False,"snapshot_reverted":False,
        "swtpm_uefi_atomic_rollback_proven":False,
        "repeated_benign_cycles_proven":False,
        "safe_for_malware":False,
    }

def revert_once(host,journal,vm,bundle,manifest_sha):
    need(sys.stdin.isatty(),"Direct local approval terminal required")
    prior=plan(host,journal,vm,bundle,manifest_sha)
    print(json.dumps(prior,sort_keys=True,indent=2),flush=True)
    phrase="REVERT-BENIGN-DISPOSABLE-"+vm.upper()
    need(input("Type "+phrase+" to revert ONLY this already-shut-off test guest: ")==phrase,
         "Operator did not authorize destructive snapshot revert")
    need(not LOCK.is_symlink(),"Unsafe revert lock path")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe revert lock metadata")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise RevertBlocked("Another benign revert active") from e
        now=plan(host,journal,vm,bundle,manifest_sha)
        need(now==prior,"Snapshot, recovery bytes or guest state changed before approval")
        # NO --force; no --running override; libvirt uses saved RUNNING state.
        # A failure can leave the guest partially reverted. Never auto retry.
        virsh("snapshot-revert",vm,prior["snapshot"],timeout=1800)
        need(virsh("domstate",vm).lower()=="running",
             "Post-revert VM not running: preserve guest state and investigate")
        probe=agent.probe_agent(prior["guest_ip"])
        need(probe.get("result")=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
             "Reverted VM's CAPE Agent did not pass admin HTTP probe")
        return {
            "result":"COMMAND2_ONE_BENIGN_RUNNING_SNAPSHOT_REVERT_AGENT_REACHABLE",
            "vm":vm,"snapshot":prior["snapshot"],
            "guest_running_after_revert":True,
            "post_revert_agent_http_verified":True,
            "cold_backup_preserved_by_code":True,
            "firmware_and_tpm_guest_consistency_verified":False,
            "negative_ipv4_ipv6_and_peer_l2_retested":False,
            "second_benign_revert_cycle_completed":False,
            "cape_parallel_jobs_tested":False,
            "production_ready":False,
            "next_manual_actions":"Preserve off-guest Windows marker/TPM/Secure Boot baseline; "
               "compare post-revert, verify network safety; shut down Windows cleanly "
               "before separately approving another identical benign revert cycle"
        }
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","revert-once"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--recovery-bundle",type=Path,required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    try:
        result=plan(a.approved_host,a.journal,a.vm,a.recovery_bundle,
                    a.manifest_sha256) if a.mode=="plan" else revert_once(
                    a.approved_host,a.journal,a.vm,a.recovery_bundle,
                    a.manifest_sha256)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (RevertBlocked,flow.WorkflowBlocked,batch.GateBlocked,
            cold.RecoveryBlocked,native.NativeBlocked,OSError,ValueError,
            TypeError) as e:
        print(json.dumps({"result":"COMMAND2_DISPOSABLE_REVERT_BLOCKED",
             "reason":str(e),"blind_retry_authorized":False},indent=2),
             file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
