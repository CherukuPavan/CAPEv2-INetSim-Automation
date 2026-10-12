#!/usr/bin/env python3
"""Guarded first ZERO-NIC Windows clone boot on an approved OTHER host.

This is a real host action, not a simulated Windows boot or verified hostname.
Requires previously attached exact per-clone identity ISO and a trusted
Command 1 Windows SYSTEM startup bootstrap installed in the source template.
Plan is read-only. Boot requires TTY + per-VM typed approval, starts PAUSED,
inspects the live devices and resumes only if no NIC/host passthrough exists.
Never touches the protected SSL55 reference or the original master.
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
import subprocess
import sys
import xml.etree.ElementTree as ET

import command2_portable_workflow as workflow
import command2_portable_guest_identity_attach as media
import command2_portable_guest_identity_iso as identity

LOCK=Path("/run/lock/cape-command2-first-identity-boot.lock")
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
GIB=1024**3
class BootBlocked(RuntimeError): pass

def need(ok, message):
    if not ok: raise BootBlocked(message)

def command(*args, timeout=40):
    try:
        p=subprocess.run(args,check=False,capture_output=True,text=True,
                         timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BootBlocked("Host command unavailable/timeout: "+str(args[0])) from exc
    need(p.returncode==0,"Host command refused: "+str(args[0]))
    return p.stdout.strip()

def virsh(*args,timeout=40):
    return command("virsh","-c","qemu:///system",*args,timeout=timeout)

def read_domain(raw,name,row,expected_iso):
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==name and
         root.findtext("uuid")==row["libvirt_uuid_candidate"],
         "VM identity or KVM domain differs from reservation")
    need(not root.findall("./devices/interface") and
         not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem") and
         not root.findall("./devices/hostdev") and
         not root.findall("./devices/redirdev") and
         not root.findall("./devices/channel") and
         not root.findall("./devices/shmem") and
         not root.findall("./devices/vsock"),
         "First guest boot must have zero NICs and zero host passthrough")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==row["disk_target"],
         "Unreviewed Windows OS disk or format")
    backing=disks[0].find("backingStore")
    need(backing is None or
         (backing.find("source") is None and
          backing.find("backingStore") is None),
         "Windows OS disk has unapproved libvirt backing chain")
    nv=root.find("./os/nvram")
    need(nv is not None and nv.text==row["uefi_nvram_target"] and
         nv.get("format","raw")=="raw",
         "First-boot fresh reserved RAW UEFI NVRAM unexpectedly changed")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Independent guest emulator TPM2 required")
    cds=root.findall("./devices/disk[@device='cdrom']")
    need(len(cds)==1 and cds[0].find("readonly") is not None and
         cds[0].find("source") is not None and
         cds[0].find("source").get("file")==str(expected_iso),
         "Correct previously staged identity-only CD-ROM not inserted")
    return True

def free_memory_mib():
    mem=Path("/proc/meminfo").read_text(encoding="ascii")
    m=re.search(r"(?m)^MemAvailable:\s+([0-9]+)\s+kB$",mem)
    need(m is not None,"Host available-memory information missing")
    return int(m.group(1))//1024

def checked_plan(host,journal,vm):
    workflow.canonical_host(host)
    need(os.geteuid()==0,"Root required for clone evidence/VM admission")
    need(type(vm) is str and VM_RE.fullmatch(vm) is not None,
         "One existing win11_1..win11_16 guest required")
    _,_,config=workflow.load_guest(journal,host,vm)
    rows=workflow.snapshotgate.reservation_rows(journal,host)
    index=int(VM_RE.fullmatch(vm).group(1))-1
    need(index<len(rows) and rows[index]["libvirt_name"]==vm,
         "Guest not in ordered Command 2 journal")
    row=rows[index]
    need(virsh("domuuid",vm).lower()==row["libvirt_uuid_candidate"] and
         virsh("domstate",vm).lower()=="shut off",
         "Identity VM UUID/state must be shut off before first boot")
    need(virsh("domstate","win11").lower()=="shut off",
         "Original Command1 Windows master must remain SHUT OFF")
    need(not virsh("snapshot-list",vm,"--name").strip(),
         "First identity boot may not overwrite any snapshot")
    info=virsh("dominfo",vm)
    need(re.search(r"(?mi)^Autostart:\s+(?:disable|disabled|no)\s*$",info)
         is not None,"Clone autostart unexpectedly enabled/unknown")
    disk=Path(row["disk_target"])
    nvram=Path(row["uefi_nvram_target"])
    need(disk.is_absolute() and disk.is_file() and not disk.is_symlink() and
         nvram.is_absolute() and nvram.is_file() and not nvram.is_symlink(),
         "Dedicated guest disk/NVRAM not regular independent files")
    dinfo=json.loads(command("qemu-img","info","--output=json",str(disk)))
    need(dinfo.get("format")=="qcow2" and
         not dinfo.get("backing-filename") and
         dinfo.get("virtual-size")==64*GIB,
         "OS disk is not a verified standalone 64GiB QCOW2")
    iso=disk.parent/(vm+".command2_identity.iso")
    journaliso=Path(journal).parent/(vm+".command2_identity.iso")
    media.safe_root_file(iso,4*1024**2)
    identity.guarded_regular(journaliso,4*1024**2)
    image=iso.read_bytes()
    need(hashlib.sha256(image).digest()==
         hashlib.sha256(journaliso.read_bytes()).digest(),
         "Libvirt optical media differs from private reservation ISO")
    archived,checksum=media.media_contents(iso)
    payload=config.read_bytes()
    need(archived==payload and
         checksum.strip().decode("ascii","replace")==
         hashlib.sha256(payload).hexdigest(),
         "Guest identity ISO is not the pinned canonical guest JSON")
    saved=virsh("dumpxml","--inactive",vm)
    read_domain(saved,vm,row,iso)
    root=ET.fromstring(saved)
    memory=root.find("memory")
    need(memory is not None and memory.get("unit")=="KiB" and
         memory.text is not None and memory.text.isdecimal(),
         "Guest RAM unit/config unreviewed")
    required_mib=int(memory.text)//1024
    need(2048<=required_mib<=65536 and
         free_memory_mib()>=required_mib+6144,
         "Insufficient available RAM for guarded first Windows boot")
    return {
        "result":"COMMAND2_ZERO_NIC_IDENTITY_BOOT_PLAN_ONLY",
        "host":host,"vm":vm,"uuid":row["libvirt_uuid_candidate"],
        "disk":str(disk),"firmware":str(nvram),
        "identity_iso":str(iso),"identity_iso_sha256":
            hashlib.sha256(image).hexdigest(),
        "saved_domain_xml_sha256":hashlib.sha256(saved.encode()).hexdigest(),
        "memory_mib":required_mib,
        "host_memory_available_mib":free_memory_mib(),
        "master_shut_off":True,"clone_shut_off":True,
        "guest_identity_verified_in_windows":False,
        "windows_system_bootstrap_verified_on_this_host":False,
        "static_ipv4_configured":False,"guest_network_attached":False,
        "guest_booted":False,"host_changes_made":False,
        "running_snapshot_created":False,"production_ready":False,
    }

def boot(host,journal,vm):
    need(sys.stdin.isatty(),"Interactive TTY required for VM boot")
    initial=checked_plan(host,journal,vm)
    print(json.dumps(initial,sort_keys=True,indent=2),flush=True)
    approval="BOOT-ZERO-NIC-IDENTITY-"+vm.upper()
    need(input("Type "+approval+" for isolated identity-only Windows boot: ")==
         approval,"No operator boot approval")
    need(not LOCK.is_symlink(),"Unsafe identity boot serialization lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe global guest boot lock")
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise BootBlocked("Concurrent guest boot") from exc
        need(checked_plan(host,journal,vm)==initial,
             "Guest/journal/host resources changed since approval")
        # Paused first, to verify the actual devices before allowing guest CPU.
        virsh("start",vm,"--paused",timeout=180)
        need(virsh("domstate",vm).lower()=="paused",
             "VM started but was not PAUSED; inspect live guest; no automatic destroy")
        rows=workflow.snapshotgate.reservation_rows(journal,host)
        row=rows[int(VM_RE.fullmatch(vm).group(1))-1]
        live=virsh("dumpxml",vm)
        iso=Path(initial["identity_iso"])
        read_domain(live,vm,row,iso)
        # Never resume a changed guest device graph or master.
        need(virsh("domstate","win11").lower()=="shut off",
             "Protected source master state changed; leave clone paused")
        virsh("resume",vm,timeout=90)
        need(virsh("domstate",vm).lower()=="running",
             "Guest resume failed; inspect VM before any further action")
        read_domain(virsh("dumpxml",vm),vm,row,iso)
        return {
            "result":"COMMAND2_FIRST_ZERO_NIC_IDENTITY_BOOT_STARTED_ONLY",
            "vm":vm,"uuid":initial["uuid"],
            "live_zero_nic_verified_before_resume":True,
            "guest_running":True,
            "windows_bootstrap_task_executed_verified":False,
            "windows_hostname_verified":False,
            "guest_static_ip_applied":False,
            "cape_agent_or_running_snapshot_verified":False,
            "must_check_guest_identity_and_safe_shutdown_before_nic":True,
            "master_changed":False,"production_ready":False,
        }
    finally:
        os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","boot"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",required=True,type=Path)
    p.add_argument("--vm",required=True)
    a=p.parse_args()
    try:
        result=(checked_plan(a.approved_host,a.journal,a.vm) if a.mode=="plan"
                else boot(a.approved_host,a.journal,a.vm))
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (BootBlocked,workflow.WorkflowBlocked,
            workflow.snapshotgate.GateBlocked,identity.MediaBlocked,
            media.AttachBlocked,OSError,ValueError,TypeError,
            ET.ParseError,IndexError) as exc:
        print(json.dumps({"result":"COMMAND2_FIRST_IDENTITY_BOOT_BLOCKED",
              "reason":str(exc),
              "VM_MAY_BE_PAUSED_IF_START_SUCCEEDED":True,
              "do_not_retry_without_state_inspection":True},
              sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
