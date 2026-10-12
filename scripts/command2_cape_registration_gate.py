#!/usr/bin/env python3
"""OTHER host: CAPE KVM registration only AFTER each VM passed running revert.

Modes: plan (READ ONLY) and apply (explicit terminal approval, config-only).
Never boots/stops/reverts/snapshots guests or changes host networking.
No service reload/restart and no malware. Real end-to-end CAPE benign test
must still follow; operator witness alone is NOT independent attestation.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import xml.etree.ElementTree as ET

import command2_running_snapshot_batch_gate as gate
import register_cape_clones as reg

LOCK=Path("/run/lock/cape-command2-cape-registration.lock")
class RegBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise RegBlocked(why)
def conf_file(p):
    p=Path(p)
    need(p.is_absolute() and p.suffix==".conf" and
         p.name=="kvm.conf" and p.is_file() and not p.is_symlink(),
         "Explicit existing CAPE kvm.conf required")
    st=p.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         not st.st_mode&0o022 and st.st_size<512*1024,
         "CAPE config file permissions/size not safe")
    for ancestor in p.parents:
        need(not ancestor.is_symlink(),
             "Symlinked CAPE config parent path not accepted")
    return p
def read_host_vms():
    all_vm=set(gate.virsh("list","--all","--name").splitlines())
    return all_vm
def plan(host,journal,subnet,witness_dir,kvm_conf):
    gate.host_guard(host)
    gate.private_evidence_folder(Path(journal).parent)
    gate.private_evidence_folder(witness_dir)
    rows=gate.reservation_rows(journal,host)
    receipts=gate.evaluate(rows,subnet,host,journal,witness_dir)
    need(receipts["all_vm_snapshots_and_revert_evidence_present"] is True,
         "Per-VM CAPE running snapshot and full TPM/OVMF benign revert evidence incomplete")
    path=conf_file(kvm_conf)
    before=path.read_bytes()
    original=before.decode("utf-8")
    guests=[{"name":r["libvirt_name"],"ip":r["guest_static_ipv4_target"],
             "snapshot":"cape_ready_"+r["libvirt_name"]}
             for r in rows]
    need(len(set(g["snapshot"] for g in guests))==len(guests),
         "Duplicate CAPE per-VM snapshot labels")
    existing=read_host_vms()
    need(all(g["name"] in existing for g in guests),
         "Some accepted analysis guests are no longer registered with libvirt")
    new=reg.render_config(original,guests,libvirt_existing=existing,
                          snapshot="UNUSED_SINGLE_SNAPSHOT",interface="cape-lab0")
    # Double-check each generated stanza contains exactly the VM-specific
    # running snapshot, never the global compatibility fallback.
    for g in guests:
        section=re.search(r"(?ms)^\["+re.escape(g["name"])+r"\]\n(.*?)(?=^\[|\Z)",new)
        need(section is not None and
             re.search(r"(?m)^snapshot\s*=\s*"+re.escape(g["snapshot"])+r"\s*$",
                       section.group(1)) is not None,
             "Expected per-guest CAPE snapshot stanza missing")
    need("UNUSED_SINGLE_SNAPSHOT" not in new,
         "Global snapshot fallback was used unexpectedly")
    return {"result":"COMMAND2_CAPE_REGISTRATION_SNAPSHOT_VERIFIED_PLAN_ONLY",
            "approved_target_host":host,
            "vm_count":len(guests),
            "registered_guest_proposals":guests,
            "prior_kvm_conf_sha256":hashlib.sha256(before).hexdigest(),
            "proposed_kvm_conf_sha256":hashlib.sha256(new.encode()).hexdigest(),
            "snapshot_metadata_and_operator_witnesses_checked":True,
            "operator_witness_independently_cryptographically_verified":False,
            "cape_parallel_benign_analysis_completed":False,
            "config_path":str(path),
            "host_modified":False,"production_release_authorized":False}

def apply(host,journal,subnet,witness_dir,kvm_conf):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root and direct terminal approval required")
    baseline=plan(host,journal,subnet,witness_dir,kvm_conf)
    print(json.dumps(baseline,sort_keys=True,indent=2),flush=True)
    need(input("Type REGISTER-CAPE-PER-VM-SNAPSHOTS to update only kvm.conf: ")==
         "REGISTER-CAPE-PER-VM-SNAPSHOTS","Operator did not authorize CAPE configuration")
    need(not LOCK.is_symlink(),"Unsafe registration lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(st.st_uid==0 and st.st_nlink==1 and
             stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600,
             "CAPE registration lock unsafe")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise RegBlocked("Another CAPE registration active") from exc
        need(plan(host,journal,subnet,witness_dir,kvm_conf)==baseline,
             "CAPE config or VM/snapshot evidence changed after approval")
        rows=gate.reservation_rows(journal,host)
        guests=[{"name":r["libvirt_name"],"ip":r["guest_static_ipv4_target"],
                 "snapshot":"cape_ready_"+r["libvirt_name"]} for r in rows]
        original=Path(kvm_conf).read_text(encoding="utf8")
        content=reg.render_config(original,guests,libvirt_existing=read_host_vms(),
                                  snapshot="UNUSED_SINGLE_SNAPSHOT",interface="cape-lab0")
        need(hashlib.sha256(content.encode()).hexdigest()==baseline["proposed_kvm_conf_sha256"],
             "CAPE config changed while finalizing")
        # Existing helper writes a never-overwritten rollback backup and
        # atomically replaces ONLY user-specified CAPE kvm.conf.
        backup=reg.apply_config(Path(kvm_conf),content)
        need(Path(kvm_conf).read_text(encoding="utf8")==content,
             "CAPE config post-write verification failed; preserve backup")
        return {"result":"COMMAND2_CAPE_PER_VM_KVM_CONF_UPDATED_NOT_STARTED",
                "vm_count":len(guests),"backup":str(backup),
                "new_conf_sha256":baseline["proposed_kvm_conf_sha256"],
                "cape_service_restarted":False,
                "guest_power_state_changed":False,
                "analysis_jobs_submitted":False,
                "second_host_real_cape_parallel_test_verified":False,
                "production_release_authorized":False}
    finally:os.close(fd)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("plan","apply"),default="plan")
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--journal",type=Path,required=True)
    ap.add_argument("--subnet",required=True)
    ap.add_argument("--witness-dir",type=Path,required=True)
    ap.add_argument("--kvm-conf",type=Path,required=True)
    a=ap.parse_args()
    try:
        result=plan(a.approved_host,a.journal,a.subnet,a.witness_dir,
                    a.kvm_conf) if a.mode=="plan" else apply(
                      a.approved_host,a.journal,a.subnet,a.witness_dir,a.kvm_conf)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (RegBlocked,gate.GateBlocked,reg.CapeConfigError,OSError,
            ValueError,TypeError,ET.ParseError) as e:
        print(json.dumps({"result":"COMMAND2_CAPE_REGISTRATION_BLOCKED",
                          "reason":str(e),
                          "automatic_vm_actions":False},indent=2),
              file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
