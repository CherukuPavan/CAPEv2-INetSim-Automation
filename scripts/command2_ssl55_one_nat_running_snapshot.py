#!/usr/bin/env python3
"""Protected SSL55 final one-NAT-NIC RUNNING snapshot CANDIDATE.

After distinct successfully verified pre-NAT and post-NAT experimental
snapshots, and AFTER old isolated NIC retired from live+saved XML,
capture one new internal QEMU RAM+Windows OS disk+OVMF snapshot with
only original-master-equivalent persistent default NAT adapter.
No snapshot is reverted, deleted or renamed; swtpm state is NOT part of
these libvirt checkpoints. This is NOT verified CAPE-restorable; actual
TPM-aware restore twice on a disposable VM remains compulsory.
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

import command2_ssl55_retire_isolated_nic as retired
import command2_ssl55_postnat_running_snapshot as post
import command2_ssl55_dual_nic_agent_readonly as dual

VM=retired.VM
SNAP="cape_one_nat_win11_1"
EARLIER=(post.OLD,post.NEW)
LOCK=Path("/run/lock/cape-ssl55-one-nat-running-candidate.lock")
APPROVE="CAPTURE-SSL55-ONE-NAT-RUNNING-TPM-NOT-RESTORE-PROVEN"
MIN_FREE=40*1024**3
GIB=1024**3

class OneNatCaptureBlocked(RuntimeError): pass
def need(x,why):
    if not x:raise OneNatCaptureBlocked(why)

def snapshots(expect_new):
    """Snapshot names and exact post-capture memory/disk/guest NIC proof."""
    names=[x.strip() for x in dual.virsh("snapshot-list",VM,"--name")
           .splitlines() if x.strip()]
    expected=sorted([*EARLIER]+([SNAP] if expect_new else []))
    need(sorted(names)==expected and len(names)==len(expected),
         "Unexpected protected libvirt snapshot inventory; NO retry")
    metadata={}
    for name in expected:
        raw=ET.fromstring(dual.virsh("snapshot-dumpxml",VM,name))
        memory=raw.find("memory")
        dom=raw.find("domain")
        disks=raw.findall("./disks/disk")
        when=raw.findtext("creationTime")
        need(raw.tag=="domainsnapshot" and raw.findtext("name")==name and
             raw.findtext("state")=="running" and
             memory is not None and memory.get("snapshot")=="internal" and
             dom is not None and dom.findtext("name")==VM and
             dom.findtext("uuid")==dual.UID and
             sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
                 for d in disks)==1 and
             len({d.get("name") for d in disks})==len(disks) and
             when is not None and when.isdecimal(),
             "Missing verified running RAM/Windows OS disk snapshot "+name)
        if name==SNAP:
            nics=dom.findall("./devices/interface")
            need(len(nics)==1 and
                 nics[0].get("type")=="network" and
                 nics[0].find("source") is not None and
                 nics[0].find("source").get("network")=="default" and
                 nics[0].find("mac") is not None and
                 nics[0].find("mac").get("address","").lower()==retired.ONLINE_MAC,
                 "New running snapshot embedded VM is NOT single master NAT NIC")
        metadata[name]={"running_ram_internal":True,
                        "os_disk_sda_internal":True,
                        "snapshot_epoch":int(when)}
    if expect_new:
        need(metadata[SNAP]["snapshot_epoch"]>=
             metadata[post.NEW]["snapshot_epoch"],
             "One-NAT snapshot timestamp precedes post-NAT checkpoint")
    return metadata

def images(expect_new):
    needed=sorted([*EARLIER]+([SNAP] if expect_new else []))
    found={}
    for label,path in (("os_disk",post.OS_DISK),
                       ("ovmf_qcow2",post.OVMF)):
        need(path.is_file() and not path.is_symlink(),
             "Expected original standalone image missing: "+label)
        st=path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
             "Non-private/symlink image alias: "+label)
        details=json.loads(post.cmd("qemu-img","info","-U",
                          "--output=json",str(path),timeout=90))
        entries=details.get("snapshots",[])
        need(type(details) is dict and details.get("format")=="qcow2" and
             not details.get("backing-filename") and
             type(entries) is list and len(entries)<=128 and
             all(type(r) is dict and
                 type(r.get("name")) is str for r in entries),
             "Unapproved QEMU image format/snapshot table for "+label)
        names=[r["name"] for r in entries]
        need(sorted(names)==needed and len(names)==len(needed),
             "QEMU image internal snapshot table differs: "+label)
        found[label]={"standalone_qcow2":True,
                      "snapshot_names":names,
                      "old_checkpoints_preserved":True,
                      "one_nat_checkpoint_present":expect_new}
    return found

def network_and_power():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Exact protected SSL55 root only")
    need(dual.virsh("domuuid",VM).lower()==dual.UID and
         dual.virsh("domstate",VM).lower()=="running",
         "Expected exact clone RUNNING")
    for name,uuid in (dual.MASTER,dual.TRIAL):
        need(dual.virsh("domuuid",name).lower()==uuid and
             dual.virsh("domstate",name).lower()=="shut off",
             "Source/trial guest has unexpectedly changed")
    need(dual.virsh("list","--name").splitlines()==[VM],
         "Unknown other guest running")
    nic=retired.single_nat_views()
    response=dual.probe("192.168.122.131","192.168.122.1")
    need(response.get("reachable_and_identified") is True,
         "CAPE Agent 0.23 no longer reachable on reserved NAT IP")
    # DHCP remains fixed by existing config host reservation in BOTH
    # active and persistent libvirt NAT network definitions.
    for inactive in (False,True):
        x=ET.fromstring(dual.virsh("net-dumpxml","default",
                        *(("--inactive",) if inactive else ())))
        need(x.tag=="network" and x.findtext("name")=="default" and
             x.find("forward") is not None and
             x.find("forward").get("mode","nat")=="nat" and
             x.find("bridge") is not None and
             x.find("bridge").get("name")=="virbr0",
             "Default NAT changed while final one-NIC checkpoint planned")
        hosts=x.findall(".//dhcp/host")
        exact=[h for h in hosts if
               h.get("ip")=="192.168.122.131" and
               (h.get("mac") or "").lower()=="02:ca:55:11:01:02" and
               h.get("name")=="WIN11-1"]
        need(len(exact)==1 and
             not any(h is not exact[0] and
                 (h.get("ip")=="192.168.122.131" or
                  (h.get("mac") or "").lower()=="02:ca:55:11:01:02")
                 for h in hosts),
             "Exact NAT DHCP lease reservation no longer unique")
    return {"master_and_trial_off":True,
            "guest_running":True,"nat_agent_verified":True,
            "dhcp_reservation_both_active_persistent":True,**nic}

def check(expect_new):
    network=network_and_power()
    snap=snapshots(expect_new)
    disks=images(expect_new)
    need(post.TPM.is_dir() and not post.TPM.is_symlink() and
         (post.TPM/"tpm2-00.permall").is_file(),
         "Dedicated swtpm state missing")
    xml=ET.fromstring(dual.virsh("dumpxml","--inactive",VM))
    m=xml.find("memory")
    need(m is not None and m.text is not None and m.text.isdecimal() and
         m.get("unit") in ("KiB","MiB","GiB"),
         "Unknown guest RAM memory unit")
    ram=int(m.text)*{"KiB":1024,"MiB":1024**2,
                     "GiB":1024**3}[m.get("unit")]
    need(2*GIB<=ram<=32*GIB,"Unexpected guest memory size")
    fs=os.statvfs(post.OS_DISK.parent)
    free=fs.f_bavail*fs.f_frsize
    threshold=MIN_FREE if expect_new else MIN_FREE+2*ram+2*GIB
    need(free>=threshold,
         "Insufficient protected shared volume free space for live snapshot")
    return {"result":("SSL55_ONE_NAT_RUNNING_CANDIDATE_VERIFIED"
                      if expect_new else "SSL55_ONE_NAT_RUNNING_CANDIDATE_PLAN_ONLY"),
            "vm":VM,"name":SNAP,"captured":expect_new,
            "protected_previous_snapshots":list(EARLIER),
            "libvirt_snapshot_metadata":snap,"qemu_internal_images":disks,
            "guest_network":network,
            "free_storage_gib":round(free/GIB,2),
            "guest_memory_gib":round(ram/GIB,2),
            "swtpm_synchronized_state_restored_twice":False,
            "snapshot_safe_to_revert_with_current_swtpm":False,
            "CAPE_READY":False,
            "automatic_cape_registration_authorized":False,
            "malware_execution_authorized":False,
            "operator_current_one_nat_snapshot_visible_in_gui":False,
            "snapshot_revert_or_guest_power_operation_performed":False}

def capture():
    need(sys.stdin.isatty(),"Operator terminal TTY required")
    before=check(False)
    print(json.dumps(before,indent=2,sort_keys=True),flush=True)
    need(input("Type "+APPROVE+" to capture running ONE-NAT candidate: ")==APPROVE,
         "Explicit TPM-UNVERIFIED candidate consent missing")
    need(not LOCK.is_symlink(),"Unsafe snapshot lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Snapshot lock not root-private")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OneNatCaptureBlocked("Overlapping single-NAT snapshot operation") from exc
        again=check(False)
        need(before["guest_network"]==again["guest_network"] and
             before["libvirt_snapshot_metadata"]==again["libvirt_snapshot_metadata"] and
             before["qemu_internal_images"]==again["qemu_internal_images"],
             "Snapshot guest/network metadata changed after approval")
        attempted=True
        # Important: dual.virsh(*args) does NOT accept timeout=.
        # post.virsh(*args,timeout=) is the bounded wrapper successfully
        # exercised by the prior real post-NAT snapshot capture.
        post.virsh("snapshot-create-as","--domain",VM,"--name",SNAP,
                   "--atomic",timeout=1800)
        after=check(True)
        return {**after,
                "result":"SSL55_ONE_NAT_RUNNING_CANDIDATE_CAPTURED_VERIFIED",
                "snapshot_mutation_attempted":True}
    except Exception as exc:
        if attempted:
            raise OneNatCaptureBlocked(
                "ONE_NAT_SNAPSHOT_CAPTURE_ATTEMPTED_POSSIBLY_PARTIAL_OS_OR_UEFI: "
                "Do NOT retry, revert, delete snapshots, stop or reboot. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","capture","verify"),default="plan")
    a=p.parse_args()
    try:
        ans=(check(False) if a.mode=="plan" else
             check(True) if a.mode=="verify" else capture())
        print(json.dumps(ans,indent=2,sort_keys=True),flush=True)
        return 0
    except (OneNatCaptureBlocked,retired.RetireBlocked,
            post.CaptureBlocked,dual.ReaddressBlocked,ValueError,TypeError,
            OSError,KeyError,ET.ParseError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"SSL55_ONE_NAT_SNAPSHOT_BLOCKED",
             "reason":str(exc),
             "do_not_auto_retry_or_revert":True,
             "tpm_revert_not_yet_proven":True},
             sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
