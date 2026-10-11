#!/usr/bin/env python3
"""Guarded BENIGN CAPE snapshot-revert smoke test, OTHER host only.

Reverting overwrites VM runtime/disk state. This is never automatic,
never done on SSL-55, and never performed before a separately verified
cold checkpoint / host network isolation acceptance. No malware tests.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import xml.etree.ElementTree as ET

import command2_running_cape_snapshot_gate as snap
import command2_cape_agent_probe as probe

LOCK = Path("/run/lock/cape-command2-benign-revert.lock")


class RevertBlocked(RuntimeError):
    pass


def require(test, why):
    if not test:
        raise RevertBlocked(why)


def snapshot_check(vm, name):
    listing = snap.virsh("snapshot-list", vm, "--name").splitlines()
    require(name in listing, "Expected CAPE snapshot not found")
    root = ET.fromstring(snap.virsh("snapshot-dumpxml", vm, name))
    require(root.tag == "domainsnapshot" and
            root.findtext("name") == name,
            "Snapshot XML not the requested checkpoint")
    memory = root.find("memory")
    disks = root.findall("./disks/disk")
    require(memory is not None and memory.get("snapshot") == "internal" and
            len(disks) == 1 and disks[0].get("snapshot") == "internal",
            "Refuse snapshot lacking INTERNAL running memory + disk")
    return True


def plan(vm, host, uid, mac, ip, receipt, subnet="192.168.240.0/24"):
    snap.target_guard(host)
    name = snap.planned_name(vm)
    snap.saved_xml_checks(vm,uid,mac,ip,subnet)
    snap.read_receipt(receipt,vm,uid,mac,ip)
    snapshot_check(vm,name)
    return {"result":"COMMAND2_RUNNING_SNAPSHOT_BENIGN_REVERT_PLAN_ONLY",
            "vm":vm,"snapshot":name,"target_host":host,
            "snapshot_contains_internal_disk_and_memory":True,
            "snapshot_reverted":False,"guest_changed":False,
            "tpm_uefi_revert_verified":False,
            "guest_agent_reachability_after_revert_verified":False,
            "warning":"Revert is DESTRUCTIVE to present guest state. "
                      "Requires a verified full cold checkpoint and "
                      "separate approved benign VM testing environment."}


def revert_benign(vm,host,uid,mac,ip,receipt,subnet="192.168.240.0/24"):
    snap.target_guard(host)
    require(os.geteuid()==0,"Root required for CAPE benign revert")
    require(sys.stdin.isatty(),"Direct interactive terminal required")
    p=plan(vm,host,uid,mac,ip,receipt,subnet)
    # Do not infer cold consistency from a libvirt snapshot. A signed
    # independent acceptance record must attest the full TPM/UEFI/disk
    # cold checkpoint has separately passed capture + restore/reboot.
    parent=Path(receipt)
    signed=json.loads(parent.read_text(encoding="utf-8"))
    require(signed.get("full_cold_checkpoint_restore_tested") is True and
            signed.get("authorized_benign_revert_test") is True,
            "Missing verified QCOW2+UEFI+swtpm rollback and benign-test approval")
    phrase="REVERT-BENIGN-"+vm.upper()
    require(input("Type "+phrase+" to revert the disposable running guest: ")==phrase,
            "Operator did not approve destructive benign revert")
    require(not LOCK.is_symlink(),"Unsafe revert lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
                stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
                "Unsafe revert lock")
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        plan(vm,host,uid,mac,ip,receipt,subnet)
        # Real revert operation changes disk/memory state on approved
        # disposable machine; no blind fallback, retry or deletion.
        snap.virsh("snapshot-revert",vm,p["snapshot"],"--running")
        require(snap.virsh("domstate",vm)=="running",
                "Guest not running after benign revert; manual review")
        snap.saved_xml_checks(vm,uid,mac,ip,subnet)
        ready=probe.probe_agent(ip)
        require(ready["result"]=="COMMAND2_CAPE_AGENT_READONLY_VERIFIED",
                "CAPE agent not ready after restored snapshot")
        return {"result":"COMMAND2_BENIGN_RUNNING_SNAPSHOT_REVERT_AGENT_VERIFIED",
                "vm":vm,"snapshot":p["snapshot"],
                "agent_version":ready["version"],"guest_running":True,
                "snapshot_revert_performed":True,
                "no_sample_executed":True,
                "swtpm_nvram_bitlocker_state_verified_by_guest":False,
                "production_complete":False}
    finally:
        os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","revert-benign"),default="plan")
    ap.add_argument("--vm",required=True)
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--uuid",required=True)
    ap.add_argument("--mac",required=True)
    ap.add_argument("--guest-ip",required=True)
    ap.add_argument("--subnet",default="192.168.240.0/24")
    ap.add_argument("--receipt",type=Path,required=True)
    args=ap.parse_args()
    try:
        if args.mode=="plan":
            out=plan(args.vm,args.approved_host,args.uuid,args.mac,
                     args.guest_ip,args.receipt,args.subnet)
        else:
            out=revert_benign(args.vm,args.approved_host,args.uuid,args.mac,
                              args.guest_ip,args.receipt,args.subnet)
        print(json.dumps(out,sort_keys=True,indent=2))
        return 0
    except (RevertBlocked,snap.SnapshotBlocked,probe.AgentBlocked,
            OSError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
