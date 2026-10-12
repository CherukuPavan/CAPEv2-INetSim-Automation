#!/usr/bin/env python3
"""SSL55 guarded post-snapshot retirement of OLD isolated guest NIC.

Use ONLY after the new post-NAT running checkpoint is confirmed inside
BOTH Windows OS + QCOW2 OVMF, and before any FINAL new one-NIC snapshot.
Original master/trial, both prior snapshots, independent TPM and host
bridges remain untouched. Old CAPE registration must not point to the
retired IP; new NAT Agent 192.168.122.131:8000 is verified before and
after. Live+saved detachment of exact old MAC only, typed BENIGN approval.
No DHCP/Windows changes, no malware execution, no restart/revert.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_ssl55_postnat_running_snapshot as post
import command2_ssl55_cape_nat_registration_discovery as cape
import command2_ssl55_dual_nic_agent_readonly as dual

VM="win11_1"
MAC="02:0a:30:6a:3f:50"
ONLINE_MAC="02:ca:55:11:01:02"
LOCK=Path("/run/lock/cape-ssl55-one-nat-nic-migration.lock")
PHRASE="RETIRE-OLD-SSL55-ISOLATED-NIC-BENIGN-ONLY"

class RetireBlocked(RuntimeError):pass
def need(cond,reason):
    if not cond:raise RetireBlocked(reason)
def original_snapshot_names():
    vals=sorted(x.strip() for x in dual.virsh("snapshot-list",VM,"--name")
                .splitlines() if x.strip())
    need(vals==sorted((post.OLD,post.NEW)),
         "Expected both preserved old+postNAT snapshots, no others")
    return vals
def single_nat_views():
    names=[]
    for arguments in (("dumpxml","--inactive",VM),("dumpxml",VM)):
        root=ET.fromstring(dual.virsh(*arguments))
        need(root.tag=="domain" and root.findtext("name")==VM and
             root.findtext("uuid")==dual.UID,
             "Unexpected running/saved clone identity")
        interfaces=root.findall("./devices/interface")
        need(len(interfaces)==1,
             "Only ONE default NAT NIC allowed in final guest profile")
        nic=interfaces[0]
        src=nic.find("source");mac=nic.find("mac");model=nic.find("model")
        need(nic.get("type")=="network" and src is not None and
             src.get("network")=="default" and
             mac is not None and
             mac.get("address","").lower()==ONLINE_MAC and
             model is not None and model.get("type")=="e1000e",
             "Saved/live one-NIC guest MUST match protected master-style NAT")
        disk=root.findall("./devices/disk[@device='disk']")
        nv=root.find("./os/nvram")
        tpm=root.find("./devices/tpm/backend")
        need(len(disk)==1 and disk[0].find("source") is not None and
             disk[0].find("source").get("file")==str(post.OS_DISK) and
             nv is not None and nv.get("format")=="qcow2" and
             (nv.text or "").strip()==str(post.OVMF) and
             tpm is not None and tpm.get("type")=="emulator" and
             tpm.get("version")=="2.0",
             "Protected disk, firmware, TPM must remain original")
        names.append("saved" if "--inactive" in arguments else "live")
    return {"saved_and_live_one_exact_default_nat_nic":True}

def inspect_after():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Protected SSL55 root only")
    need(dual.virsh("domuuid",VM).lower()==dual.UID and
         dual.virsh("domstate",VM).lower()=="running",
         "Exact clone must remain running")
    for vm,uid in (dual.MASTER,dual.TRIAL):
        need(dual.virsh("domuuid",vm).lower()==uid and
             dual.virsh("domstate",vm).lower()=="shut off",
             "Protected source/trial power state changed")
    original_snapshot_names()
    exact=single_nat_views()
    # Dual agent proof no longer valid after old NIC detach; test NAT only.
    probe=dual.probe("192.168.122.131","192.168.122.1")
    need(probe.get("reachable_and_identified") is True,
         "CAPE Agent not reachable over retained permanent NAT")
    q=post.images(post.NEW,True)
    return {"result":"SSL55_ONE_PERMANENT_MASTER_NAT_NIC_ONLY_VERIFIED",
            "vm":VM,"nat_agent_verified":True,
            "retained_mac":ONLINE_MAC,
            "nat_reserved_ip":"192.168.122.131",
            "old_isolated_mac_removed_from_saved_and_live":True,
            "snapshots_preserved":list((post.OLD,post.NEW)),
            "both_images_keep_both_prior_snapshot_labels":True,
            "qemu_checkpoint_images":q,**exact,
            "new_final_one_nic_running_snapshot_taken":False,
            "swtpm_safe_revert_verified":False,
            "malware_analysis_allowed":False}

def before():
    accepted=post.preflight(True)
    need(accepted["new_snapshot_created"] is True and
         accepted["CAPE_READY"] is False,
         "Post-NAT running checkpoint must be captured and independently verified")
    state=cape.inspect("/opt/CAPEv2/conf/kvm.conf")
    need(state["registration"]["win11_1_registration_decision"]==
         "CREATE_NEW_STANZA" and
         state["current_nat_agent_http_positive"] is True,
         "CAPE configuration changed, old NIC retirement not approved")
    return {"result":"SSL55_OLD_ISOLATED_NIC_RETIREMENT_PLAN_ONLY",
            "vm":VM,"old_mac_to_remove":MAC,
            "permanent_nat_retained":ONLINE_MAC,
            "currently_two_persistent_nics":True,
            "post_nat_running_snapshot_exists_in_both_images":True,
            "original_snapshot_preserved":True,
            "cape_registration_still_not_added":True,
            "safe_for_malware_execution":False,
            "host_modified":False}

def retire():
    need(sys.stdin.isatty(),"Direct operator interactive terminal required")
    initial=before()
    print(json.dumps(initial,indent=2,sort_keys=True),flush=True)
    need(input("Type "+PHRASE+" to retire old NIC only: ")==PHRASE,
         "Operator did not approve exact old NIC detachment")
    need(not LOCK.is_symlink(),"Unsafe root migration lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Untrusted migration lock ownership/permissions")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RetireBlocked("Another host NIC migration in progress") from exc
        need(before()==initial,
             "Original and post-NAT snapshots/agent/host changed since approval")
        attempted=True
        dual.virsh("detach-interface",VM,"network",
                   "--mac",MAC,"--live","--config")
        result=inspect_after()
        return {**result,
                "result":"SSL55_OLD_NIC_REMOVED_LIVE_AND_PERSISTENT_VERIFIED",
                "old_nic_detach_attempted":True,
                "final_snapshot_capture_permitted_automatically":False}
    except Exception as exc:
        if attempted:
            raise RetireBlocked(
                "OLD_NIC_DETACH_ATTEMPTED_POSSIBLE_PARTIAL_LIVE_CONFIG: "
                "STOP. Do not retry/shutdown/revert or run samples. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","retire","verify"),default="plan")
    a=parser.parse_args()
    try:
        result=(before() if a.mode=="plan" else
                inspect_after() if a.mode=="verify" else retire())
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except (RetireBlocked,post.CaptureBlocked,cape.CapeDiscoveryBlocked,
            cape.reserve.ReservationBlocked,dual.ReaddressBlocked,
            ValueError,OSError,TypeError,KeyError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_OLD_ISOLATED_NIC_RETIREMENT_BLOCKED",
            "reason":str(exc),
            "no_guest_power_or_snapshot_revert_requested":True,
            "do_not_retry_if_detach_was_attempted":True},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
