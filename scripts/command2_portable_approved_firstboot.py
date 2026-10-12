#!/usr/bin/env python3
"""Approved one-NIC first Windows boot, on separately accepted OTHER host only.

This closes the zero-NIC-rename -> shutoff -> NIC manual-firstboot loop:
a Windows Command1 master with independently verified SYSTEM bootstrap,
a previously physically proven isolated network and exact one-NIC firstboot
receipt permit a guest first boot with a guarded NIC and approved optical ISO.
The Windows startup task then handles hostname -> reboot -> static IPv4.

No capture of disk/RAM snapshot, no CAPE sample, no master writes.
Host checks cannot independently prove Windows rename or agent readiness.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_portable_identity_boot as bootbase
import command2_portable_workflow as workflow
import command2_guarded_isolated_nic as nic
import command2_portable_guest_identity_attach as attachment
import command2_portable_network_approval_iso as approval

LOCK=Path("/run/lock/cape-command2-approved-firstboot.lock")
GIB=1024**3
class ApprovedBootBlocked(RuntimeError):pass

def need(ok,why):
    if not ok: raise ApprovedBootBlocked(why)

def virsh(*args,timeout=40):
    return bootbase.virsh(*args,timeout=timeout)

def inspect_xml(raw,vm,row,iso):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and
         root.findtext("uuid")==row["libvirt_uuid_candidate"],
         "Guest identity/KVM XML mismatch")
    for tag in ("hostdev","filesystem","redirdev","channel","shmem","vsock"):
        need(not root.findall("./devices/"+tag),
             "Unapproved guest host-connected device: "+tag)
    net=root.findall("./devices/interface")
    need(len(net)==1 and net[0].get("type")=="network" and
         net[0].find("source") is not None and
         net[0].find("source").get("network")==nic.NETWORK and
         net[0].find("mac") is not None and
         net[0].find("mac").get("address","").lower()==row["mac_candidate"],
         "Expected exactly one reviewed isolated NIC and reserved MAC")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==row["disk_target"],
         "Unreviewed clone OS disk")
    backing=disks[0].find("backingStore")
    need(backing is None or
         (backing.find("source") is None and
          backing.find("backingStore") is None),
         "Windows clone has an unwanted master backing chain")
    firmware=root.find("./os/nvram")
    need(firmware is not None and
         firmware.text==row["uefi_nvram_target"] and
         firmware.get("format","raw")=="raw",
         "Existing independent OVMF variable store differs before first boot")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0","Independent swtpm2 missing")
    cd=root.findall("./devices/disk[@device='cdrom']")
    need(len(cd)==1 and cd[0].find("readonly") is not None and
         cd[0].find("source") is not None and
         cd[0].find("source").get("file")==str(iso),
         "Previously approved CAPE_CMD2 optical image not inserted")
    return root

def iso_file(iso,name):
    need(re.fullmatch(r"[a-z-]{3,40}\.(?:json|sha256)",name) is not None,
         "Unknown optical media path")
    try:
        p=subprocess.run(["isoinfo","-R","-i",str(iso),"-x","/"+name],
                         check=False,capture_output=True,timeout=35)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ApprovedBootBlocked("Cannot read approved optical ISO") from exc
    need(p.returncode==0 and len(p.stdout)<128*1024,
         "Missing/oversized approved optical entry: "+name)
    return p.stdout

def checked_plan(host,journal,vm,receipt):
    workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for private approved boot evidence")
    row,subnet,config=workflow.load_guest(journal,host,vm)
    need(type(receipt) is Path and receipt.is_absolute(),
         "Exact absolute network acceptance receipt required")
    # Validate the privileged receipt metadata/size before reading its bytes.
    need(nic.read_acceptance_receipt(str(receipt),vm,row["libvirt_uuid_candidate"],
                                    row["mac_candidate"],
                                    row["guest_static_ipv4_target"],host),
         "Physical host isolation/Command1 master bootstrap unaccepted")
    acceptance=json.loads(receipt.read_text(encoding="utf-8"))
    need(acceptance.get("kind")=="COMMAND2_SEPARATE_HOST_NETWORK_ACCEPTANCE_V2",
         "First one-NIC Windows boot requires V2 master bootstrap acceptance")
    need(virsh("domuuid",vm).lower()==row["libvirt_uuid_candidate"] and
         virsh("domstate",vm).lower()=="shut off",
         "Exact guest must remain shut off before approved first boot")
    need(virsh("domstate","win11").lower()=="shut off" and
         virsh("domuuid","win11").lower()==acceptance["source_master_uuid"],
         "Protected Command1 source master identity/state does not match pinned V2 receipt")
    need(not virsh("snapshot-list",vm,"--name").strip(),
         "New guest cannot inherit existing libvirt snapshot")
    info=virsh("dominfo",vm)
    need(re.search(r"(?mi)^Autostart:\s+(?:disable|disabled|no)\s*$",info),
         "Guest unexpectedly set to autostart")
    bridge_ip=str(ipaddress.IPv4Address(
        int(ipaddress.IPv4Network(subnet).network_address)+1))
    need(nic.verify_network_live(subnet,bridge_ip),
         "Dedicated physical host isolation not active")
    disk=Path(row["disk_target"])
    varsfile=Path(row["uefi_nvram_target"])
    need(disk.is_absolute() and disk.is_file() and not disk.is_symlink() and
         varsfile.is_absolute() and varsfile.is_file() and
         not varsfile.is_symlink(),
         "Independent Windows clone disk/firmware missing")
    meta=json.loads(bootbase.command("qemu-img","info","--output=json",str(disk)))
    need(meta.get("format")=="qcow2" and not meta.get("backing-filename") and
         meta.get("virtual-size")==64*GIB,
         "Expected flat 64GiB independent Windows QCOW2")
    iso=disk.parent/(vm+".command2_network_approved.iso")
    attachment.safe_root_file(iso,4*1024**2)
    saved=virsh("dumpxml","--inactive",vm)
    root=inspect_xml(saved,vm,row,iso)
    conf=config.read_bytes()
    need(iso_file(iso,"guest-config.json")==conf and
         iso_file(iso,"guest-config.sha256").strip().decode("ascii","replace")==
             hashlib.sha256(conf).hexdigest(),
         "Guest configuration on approved ISO differs from immutable journal")
    expected={
        "format":"COMMAND2_HOST_NETWORK_APPROVAL_V1",
        "guest_uuid":row["libvirt_uuid_candidate"],
        "guest_name":vm,
        "guest_mac":row["mac_candidate"],
        "host_ipv4_negative_egress_verified":True,
        "host_ipv6_negative_egress_verified":True,
        "reboot_persistence_verified":True,
        "guest_l2_separation_verified":True,
    }
    proof=approval.canonical(expected)
    need(iso_file(iso,"network-approved.json")==proof and
         iso_file(iso,"network-approved.sha256").strip().decode("ascii","replace")==
             hashlib.sha256(proof).hexdigest(),
         "Optical host network approval is missing, stale or unrecognized")
    mem=root.find("memory")
    need(mem is not None and mem.get("unit")=="KiB" and
         mem.text is not None and mem.text.isdecimal(),
         "Guest memory source/unit unreviewed")
    ram=int(mem.text)//1024
    available=bootbase.free_memory_mib()
    need(2048<=ram<=65536 and available>=ram+6144,
         "Insufficient host RAM for first approved Windows boot")
    return {
        "result":"COMMAND2_APPROVED_ONE_NIC_FIRSTBOOT_PLAN_ONLY",
        "vm":vm,"host":host,"uuid":row["libvirt_uuid_candidate"],
        "expected_mac":row["mac_candidate"],
        "expected_ipv4_after_reboot":row["guest_static_ipv4_target"],
        "identity_iso_sha256":hashlib.sha256(iso.read_bytes()).hexdigest(),
        "host_receipt_sha256":hashlib.sha256(receipt.read_bytes()).hexdigest(),
        "saved_xml_sha256":hashlib.sha256(saved.encode()).hexdigest(),
        "host_network_readback_checked":True,"guest_shut_off":True,
        "master_shut_off":True,"guest_ram_mib":ram,
        "guest_identity_verified_in_windows":False,
        "guest_static_ipv4_verified_in_windows":False,
        "source_master_task_execution_proved_here":False,
        "ready_for_running_snapshot":False,"host_changed":False,
    }

def approved_boot(host,journal,vm,receipt):
    need(sys.stdin.isatty(),"Physical operator terminal required")
    initial=checked_plan(host,journal,vm,receipt)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    phrase="BOOT-ISOLATED-ONE-NIC-"+vm.upper()
    need(input("Type "+phrase+" to boot only the reviewed Windows clone: ")==
         phrase,"No firstboot approval")
    need(not LOCK.is_symlink(),"Unsafe approved firstboot lock path")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe root-only boot lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ApprovedBootBlocked("Another approved guest firstboot running") from exc
        need(checked_plan(host,journal,vm,receipt)==initial,
             "Host network, image, ISO or evidence changed after authorization")
        # Start paused, check live NIC/passthrough before allowing guest execution.
        virsh("start",vm,"--paused",timeout=180)
        need(virsh("domstate",vm).lower()=="paused",
             "Firstboot guest did not remain paused; manual review mandatory")
        row,subnet,_=workflow.load_guest(journal,host,vm)
        disk=Path(row["disk_target"])
        iso=disk.parent/(vm+".command2_network_approved.iso")
        inspect_xml(virsh("dumpxml",vm),vm,row,iso)
        bridge_ip=str(ipaddress.IPv4Address(
            int(ipaddress.IPv4Network(subnet).network_address)+1))
        need(nic.verify_network_live(subnet,bridge_ip) and
             virsh("domstate","win11").lower()=="shut off",
             "Isolated network/master changed; leave guest paused for review")
        virsh("resume",vm,timeout=90)
        need(virsh("domstate",vm).lower()=="running",
             "Guest did not resume correctly; do not retry")
        inspect_xml(virsh("dumpxml",vm),vm,row,iso)
        return {
            "result":"COMMAND2_APPROVED_ONE_NIC_WINDOWS_BOOT_STARTED_ONLY",
            "vm":vm,"guest_running":True,
            "host_isolated_nic_before_guest_cpu":True,
            "windows_host_rename_and_restart_observed":False,
            "static_ipv4_proved":False,
            "cape_agent_reachable_verified":False,
            "swtpm_uefi_running_snapshot_proven":False,
            "ready_for_production":False,
        }
    finally:
        os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","boot"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    try:
        result=(checked_plan(a.approved_host,a.journal,a.vm,a.receipt)
                if a.mode=="plan" else
                approved_boot(a.approved_host,a.journal,a.vm,a.receipt))
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (ApprovedBootBlocked,bootbase.BootBlocked,
            workflow.WorkflowBlocked,workflow.snapshotgate.GateBlocked,
            nic.NicBlocked,attachment.AttachBlocked,OSError,
            ValueError,TypeError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND2_ONE_NIC_FIRSTBOOT_BLOCKED",
              "reason":str(exc),
              "paused_or_partially_started_guest_may_need_manual_review":True,
              "automatic_cleanup_or_retry":False},sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
