#!/usr/bin/env python3
"""SSL55 guarded post-NAT RUNNING snapshot candidate (TPM RESTORE NOT PROVEN).

Captures *current* saved and live two-NIC Windows guest RAM + QCOW2 OS
and UEFI internal snapshots under a NEW independent label. Preserves
prior 'cape_candidate_win11_1' as-is. NO VM restart, no TPM state copy,
no snapshot revert, no CAPE registration, no INetSim config changes and
no claim of safe malware analysis. Prior working NAT IP 192.168.122.131,
MAC 02:ca:55:11:01:02 and original CAPE Agent 192.168.240.101 are
checked before and after. Actual QEMU snapshot labels must exist in
BOTH independent QCOW2 images; libvirt XML metadata alone is not enough.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import command2_ssl55_dual_nic_agent_readonly as dual

VM="win11_1"
OLD="cape_candidate_win11_1"
NEW="cape_postnat_win11_1"
OS_DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
OVMF=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd.qcow2")
TPM=Path("/var/lib/libvirt/swtpm")/dual.UID/"tpm2"
LOCK=Path("/run/lock/cape-ssl55-postnat-running-snapshot.lock")
MIN_FREE=40*1024**3
GIB=1024**3
APPROVE="CAPTURE-SSL55-POSTNAT-RAM-DISK-UEFI-TPM-UNVERIFIED"

class CaptureBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise CaptureBlocked(why)

def cmd(*args,timeout=60):
    try:
        x=subprocess.run(args,capture_output=True,text=True,
                         check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise CaptureBlocked("Host tool unavailable or timed out: "+args[0]) from exc
    need(x.returncode==0 and len(x.stdout)<1_000_000,
         "Host tool returned failure: "+args[0])
    return x.stdout.strip()

def virsh(*args,timeout=60):
    return cmd("virsh","-c","qemu:///system",*args,timeout=timeout)

def images(name,expected_present):
    """Prove both OS and UEFI image contain the named checkpoint exactly once."""
    result={}
    for label,path in (("os_disk",OS_DISK),("uefi_qcow2",OVMF)):
        need(path.is_file() and not path.is_symlink(),
             "Expected exact standalone QCOW2 image missing: "+label)
        st=path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
             "QCOW2 image is alias/hardlink: "+label)
        parsed=json.loads(cmd("qemu-img","info","-U","--output=json",
                              str(path),timeout=90))
        need(type(parsed) is dict and parsed.get("format")=="qcow2" and
             not parsed.get("backing-filename"),
             "Image is not standalone QCOW2: "+label)
        snaps=parsed.get("snapshots",[])
        need(type(snaps) is list and len(snaps)<=128 and
             all(type(s) is dict and type(s.get("name")) is str
                 and len(s["name"])<128 for s in snaps),
             "Invalid internal QEMU snapshot list: "+label)
        names=[s["name"] for s in snaps]
        need(names.count(OLD)==1,
             "Original experiment snapshot lost from "+label)
        need(names.count(name)==int(expected_present),
             "Exact newly requested snapshot unexpectedly exists/missing in "+label)
        need(len(set(names))==len(names) and
             set(names).issubset({OLD,NEW}),
             "Unknown QCOW2 internal snapshot state in "+label)
        result[label]={"old_checkpoint_preserved":True,
                       "new_checkpoint_present_once":expected_present,
                       "qcow2_standalone":True,
                       "snapshot_names":names}
    return result

def snapshot_xml(name):
    root=ET.fromstring(virsh("snapshot-dumpxml",VM,name))
    memory=root.find("memory")
    disks=root.findall("./disks/disk")
    embedded=root.find("domain")
    need(root.tag=="domainsnapshot" and
         root.findtext("name")==name and
         root.findtext("state")=="running" and
         memory is not None and memory.get("snapshot")=="internal" and
         embedded is not None and
         embedded.findtext("name")==VM and embedded.findtext("uuid")==dual.UID,
         "Snapshot does not capture running RAM and exact clone identity")
    need(sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
             for d in disks)==1 and
         len({d.get("name") for d in disks})==len(disks) and
         all(d.get("name")=="sda" or
             (d.get("name")=="sdb" and d.get("snapshot")=="no")
             for d in disks) and len(disks) in (1,2),
         "Snapshot does not capture exact Windows OS disk sda")
    timestamp=root.findtext("creationTime")
    need(timestamp is not None and timestamp.isdecimal(),
         "Missing snapshot creationTime")
    return {"running_ram_internal":True,"windows_os_disk_sda_internal":True,
            "auxiliary_firmware_entry_safe":True,
            "snapshot_epoch":int(timestamp)}

def domain_views():
    expected=[
       ("cape-analysis-isolated","02:0a:30:6a:3f:50","e1000e"),
       ("default","02:ca:55:11:01:02","e1000e")]
    for mode in (("dumpxml","--inactive",VM),("dumpxml",VM)):
        root=ET.fromstring(virsh(*mode))
        need(root.tag=="domain" and root.get("type")=="kvm" and
             root.findtext("name")==VM and root.findtext("uuid")==dual.UID,
             "Exact clone identity differs")
        disk=root.findall("./devices/disk[@device='disk']")
        nvram=root.find("./os/nvram")
        tpm=root.find("./devices/tpm/backend")
        need(len(disk)==1 and disk[0].find("driver") is not None and
             disk[0].find("driver").get("type")=="qcow2" and
             disk[0].find("source") is not None and
             disk[0].find("source").get("file")==str(OS_DISK),
             "Expected original guest OS QCOW2 changed")
        need(nvram is not None and nvram.get("format")=="qcow2" and
             (nvram.text or "").strip()==str(OVMF),
             "Expected QCOW2 OVMF changed")
        need(tpm is not None and tpm.get("type")=="emulator" and
             tpm.get("version")=="2.0",
             "Original independent swtpm 2.0 device not found")
        nics=[]
        for n in root.findall("./devices/interface"):
            src=n.find("source");mac=n.find("mac");model=n.find("model")
            need(n.get("type")=="network" and
                 src is not None and mac is not None and model is not None,
                 "Unexpected guest interface")
            nics.append((src.get("network"),
                         (mac.get("address") or "").lower(),model.get("type")))
        need(sorted(nics)==sorted(expected) and len(nics)==2,
             "Original and permanent NAT interface state differs")
        need(not any(root.findall("./devices/"+tag) for tag in
                     ("hostdev","filesystem","redirdev","channel","shmem","vsock")),
             "Unreviewed host access device in clone")
    return {"saved_and_live_same_two_nics":True,
            "nat_is_persistent_in_guest_definition":True,
            "master_style_nat_ip_dhcp_reserved":True}

def preflight(expect_new):
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Only exact protected SSL55 root")
    summary=dual.assess()
    need(summary["original_agent_still_reachable"] is True and
         summary["nat_agent_reachable"] is True,
         "Both CAPE Agent 0.23 paths must respond before snapshot")
    need(summary["nat_lease_observation"]["observed_nat_ips_for_mac"]==
         ["192.168.122.131"],
         "Expected NAT MAC's observed 192.168.122.131 lease missing")
    # The DHCP reservation must remain in BOTH live and saved views.
    for flag in (False,True):
        root=ET.fromstring(virsh("net-dumpxml","default",
                              *(("--inactive",) if flag else ())))
        dhcp=root.findall(".//dhcp/host")
        matches=[x for x in dhcp if
             (x.get("mac") or "").lower()=="02:ca:55:11:01:02" and
             x.get("ip")=="192.168.122.131" and
             (x.get("name") or "").upper()=="WIN11-1"]
        need(len(matches)==1 and
             not any(x.get("ip")=="192.168.122.131" and x not in matches
                     for x in dhcp),
             "Persistently reserved exact NAT host MAC/IP changed")
    network=domain_views()
    listed=sorted(x.strip() for x in
                  virsh("snapshot-list",VM,"--name").splitlines() if x.strip())
    need(listed==sorted([OLD,NEW] if expect_new else [OLD]),
         "Unexpected libvirt snapshot inventory; do NOT retry")
    old=snapshot_xml(OLD)
    new=snapshot_xml(NEW) if expect_new else None
    proofs=images(NEW,expect_new)
    need(TPM.is_dir() and not TPM.is_symlink() and
         (TPM/"tpm2-00.permall").is_file(),
         "Independent swtpm state missing")
    free=os.statvfs(OS_DISK.parent)
    avail=free.f_bavail*free.f_frsize
    mem=ET.fromstring(virsh("dumpxml","--inactive",VM)).find("memory")
    need(mem is not None and mem.text is not None and
         mem.text.isdecimal() and mem.get("unit") in ("KiB","MiB","GiB"),
         "Unknown VM RAM size")
    ram=int(mem.text)*{"KiB":1024,"MiB":1024**2,
                      "GiB":1024**3}[mem.get("unit")]
    need(2*GIB<=ram<=32*GIB,
         "Guest RAM outside reviewed running snapshot bounds")
    # Apply needs 2xRAM headroom; verification only requires reserve.
    reserve=MIN_FREE if expect_new else MIN_FREE+2*ram+2*GIB
    need(avail>=reserve,"Free space below 40GiB + guest RAM safety margin")
    return {
       "result":("SSL55_POSTNAT_RUNNING_SNAPSHOT_INDEPENDENTLY_VERIFIED"
                 if expect_new else "SSL55_POSTNAT_RUNNING_SNAPSHOT_PLAN_ONLY"),
       "vm":VM,"vm_running":True,"snapshot_name":NEW,
       "previous_snapshot_name":OLD,
       "prior_snapshot_proof":old,
       "new_snapshot_proof":new,
       "image_checkpoints":proofs,
       "new_snapshot_created":expect_new,
       "guest_network_state_at_capture":"TWO_PERSISTENT_ADAPTERS_OLD_ISOLATED_PLUS_DEFAULT_NAT",
       "network_checks":network,
       "nat_agent_ip":"192.168.122.131",
       "legacy_agent_ip":"192.168.240.101",
       "storage_available_gib":round(avail/GIB,2),
       "guest_memory_gib":round(ram/GIB,2),
       "master_trial_off":True,
       "pre_existing_snapshot_not_reverted_or_deleted":True,
       "swtpm_epoch_consistent_checkpoint_captured":False,
       "tpm_safe_revert_approved":False,
       "CAPE_READY":False,
       "snapshot_for_final_one_nic_config":False,
       "malware_execution_authorized":False,
       "host_mutation_performed_by_preflight":False
    }

def capture():
    need(sys.stdin.isatty(),"Direct operator terminal required for snapshot")
    before=preflight(False)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVE+" to create a new RUNNING candidate: ")==APPROVE,
         "Operator did not approve distinct post-NAT snapshot candidate")
    need(not LOCK.is_symlink(),"Unreviewed root snapshot lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Snapshot lock has unsafe owner or mode")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CaptureBlocked("Another exact host snapshot operation active") from exc
        again=preflight(False)
        need(again["image_checkpoints"]==before["image_checkpoints"] and
             again["network_checks"]==before["network_checks"] and
             again["prior_snapshot_proof"]==before["prior_snapshot_proof"],
             "Snapshot/disk/NAT topology differs after operator approval")
        attempted=True
        virsh("snapshot-create-as","--domain",VM,"--name",NEW,
              "--atomic",timeout=1800)
        after=preflight(True)
        need(after["new_snapshot_proof"]["snapshot_epoch"]>=
             before["prior_snapshot_proof"]["snapshot_epoch"],
             "Post-NAT capture timestamp inconsistent with old snapshot")
        return {**after,"result":"SSL55_POSTNAT_RUNNING_SNAPSHOT_CAPTURED_AND_CHECKED",
            "snapshot_capture_attempted":True,
            "new_snapshot_visible_in_libvirt_snapshot_list":True,
            "virt_manager_gui_refreshed_and_visually_verified":False,
            "tpmsafe_reversion_tested":False}
    except Exception as exc:
        if attempted:
            raise CaptureBlocked(
                "SNAPSHOT_CAPTURE_ATTEMPTED_POSSIBLE_PARTIAL_DISK_OR_UEFI_STATE: "
                "STOP, DO NOT RETRY, DELETE, REVERT OR REBOOT. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","capture","verify"),default="plan")
    a=p.parse_args()
    try:
        result=(preflight(False) if a.mode=="plan" else
                preflight(True) if a.mode=="verify" else capture())
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except (CaptureBlocked,dual.ReaddressBlocked,OSError,ValueError,
            TypeError,KeyError,json.JSONDecodeError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_POSTNAT_RUNNING_SNAPSHOT_BLOCKED",
            "reason":str(exc),
            "snapshot_or_guest_state_may_have_changed_only_if_capture_attempted":True,
            "do_not_autoretry_or_revert":True,
            "full_tpm_consistent_restore_not_proven":True},
            sort_keys=True),file=sys.stderr,flush=True)
        return 2
if __name__=="__main__":raise SystemExit(main())
