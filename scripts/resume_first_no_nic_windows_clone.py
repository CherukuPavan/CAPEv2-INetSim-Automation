#!/usr/bin/env python3
"""Guarded first RESUME of paused zero-NIC disposable Windows 11 trial VM.

Requires a previously verified, paused win11_trial_1. Rechecks preserved
original master and trial VM live XML, no NIC/passthrough/USB/host channels,
local-only display, independent disk+UEFI+TPM identity. Resumes ONLY the
trial guest. Windows may now write to the trial QCOW2, NVRAM and its own
new swtpm state. Does not touch original master/template or add network.
No malware execution, package installs, registry edits or guest automation.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

NAME="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_trial_1.qcow2")
TEMPLATE=Path("/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2")
NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_trial_1_VARS.fd")
MASTER="win11"
MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
SNAP="finalshutoffversion"
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
RULE=Path("/etc/apparmor.d/abstractions/libvirt-qemu.d/98-cape-swtpm-"+UUID)
EXPECTED_RULE="  /run/libvirt/qemu/swtpm/*-win11_trial_1-swtpm.sock rw,\n"
FORBIDDEN=("interface","redirdev","redirfilter","channel","hostdev",
           "filesystem","smartcard","shmem","vsock","crypto")

class ResumeBlocked(RuntimeError):
    pass

def ensure(ok:bool,message:str)->None:
    if not ok:
        raise ResumeBlocked(message)

def cmd(*args:str)->str:
    try:
        return subprocess.run(args,check=True,capture_output=True,text=True,
                              timeout=120).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise ResumeBlocked("Host command failed: "+args[0]) from e

def virsh(*args:str)->str:
    return cmd("virsh","-c","qemu:///system",*args)

def check_firmware_and_files()->None:
    for p in (DISK,TEMPLATE,NVRAM):
        ensure(p.is_file() and not p.is_symlink(),"Trial disk/template/NVRAM unavailable")
    for p in (DISK,TEMPLATE):
        info=p.stat()
        ensure(stat.S_ISREG(info.st_mode) and info.st_uid==0 and
               (info.st_mode & 0o077)==0,
               "Windows image is not protected as root-private")
    ensure(DISK.resolve()!=TEMPLATE.resolve(),"Clone disk aliases immutable template")
    source_nvram=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
    ensure(source_nvram.is_file() and
           (source_nvram.stat().st_dev,source_nvram.stat().st_ino)!=
           (NVRAM.stat().st_dev,NVRAM.stat().st_ino),
           "Clone and master firmware stores overlap")
    ensure(RULE.is_file() and not RULE.is_symlink() and
           RULE.read_text()==EXPECTED_RULE,"Trial-specific TPM AppArmor rule missing")
    ensure(Path("/sys/module/apparmor/parameters/enabled").read_text().strip()=="Y",
           "Host AppArmor disabled")

def check_master()->None:
    ensure(virsh("domstate",MASTER)=="shut off","Original master is running")
    ensure(virsh("domuuid",MASTER)==MASTER_UUID,"Original master UUID changed")
    ensure(virsh("snapshot-current",MASTER,"--name")==SNAP,
           "Original master cold snapshot pointer changed")
    ensure(BACKUP.is_dir() and not BACKUP.is_symlink() and
           BACKUP.stat().st_uid==0 and (BACKUP.stat().st_mode & 0o077)==0,
           "Protected master backup unavailable")
    backup=ET.fromstring((BACKUP/"metadata/domain.xml").read_text())
    master=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
    ensure(master.findtext("uuid")==backup.findtext("uuid")==MASTER_UUID,
           "Original master XML identity changed")
    disk=master.find("./devices/disk[@device='disk']/source")
    ensure(disk is not None and disk.get("file")==OVERLAY,
           "Original maintenance overlay was detached")
    ensure(virsh("snapshot-dumpxml",MASTER,SNAP)==
           (BACKUP/"metadata/snapshot-finalshutoffversion.xml").read_text().strip(),
           "Original snapshot metadata changed")

def check_trial(xmltext:str)->None:
    root=ET.fromstring(xmltext)
    ensure(root.tag=="domain" and root.get("type")=="kvm" and
           root.findtext("name")==NAME and root.findtext("uuid")==UUID,
           "Trial identity or hypervisor changed")
    disks=root.findall("./devices/disk[@device='disk']")
    ensure(len(disks)==1 and disks[0].find("source") is not None and
           disks[0].find("source").get("file")==str(DISK) and
           disks[0].find("driver") is not None and
           disks[0].find("driver").get("type")=="qcow2",
           "Unexpected trial system disk")
    ensure(root.findtext("./os/nvram")==str(NVRAM),"Trial firmware path changed")
    tpms=root.findall("./devices/tpm")
    ensure(len(tpms)==1,"Trial must have exactly one TPM")
    backend=tpms[0].find("backend")
    ensure(backend is not None and backend.get("type")=="emulator" and
           backend.get("version")=="2.0",
           "Trial TPM is not an independent v2 emulator")
    src=backend.find("source")
    if src is not None:
        path=src.get("path","")
        ensure(path.startswith("/run/libvirt/qemu/swtpm/") and NAME in path
               and "win11-swtpm.sock" not in path,
               "Trial swtpm socket points outside dedicated runtime")
    for typ in FORBIDDEN:
        ensure(not root.findall("./devices/"+typ),
               "Trial contains unexpected host/network device: "+typ)
    ensure(not any(x.tag.endswith("}commandline") for x in root.iter()),
           "Trial guest inherited unreviewed QEMU extension")
    graphics=root.findall("./devices/graphics")
    ensure(len(graphics)==1 and
           graphics[0].get("type") in ("spice","vnc") and
           graphics[0].get("listen") in ("127.0.0.1","::1"),
           "Trial graphics listener may be exposed")
    for listener in graphics[0].findall("listen"):
        ensure(listener.get("type")=="address" and
               listener.get("address") in ("127.0.0.1","::1"),
               "Trial graphics has unexpected network listener")

def preflight()->dict:
    ensure(os.geteuid()==0,"Use sudo to check QEMU/libvirt state")
    check_master()
    check_firmware_and_files()
    ensure(virsh("domuuid",NAME)==UUID,"Trial libvirt UUID changed")
    ensure(virsh("domstate",NAME).lower() in ("paused","paused (user)"),
           "Trial VM must already be paused; no implicit start")
    check_trial(virsh("dumpxml",NAME))
    check_trial(virsh("dumpxml","--inactive",NAME))
    return {"trial":NAME,"uuid":UUID,"original_master_shutoff":True,
            "trial_state":"PAUSED","trial_network_interfaces":0,
            "trial_host_shares":0,"template_untouched":True}

def perform(mode:str)->dict:
    ensure(mode in ("plan","resume"),"Unsupported resume mode")
    report=preflight()
    if mode=="plan":
        return dict(report,result="RESUME_PLAN_READ_ONLY",
                    guest_resumed=False)
    print("PASS: Original master remains shut off",flush=True)
    print("PASS: Paused trial identity and separate disk/NVRAM/TPM",flush=True)
    print("PASS: Zero live NICs and no host integration devices",flush=True)
    print("Resuming ONLY the offline-network trial guest...",flush=True)
    virsh("resume",NAME)
    try:
        ensure(virsh("domstate",NAME)=="running",
               "Trial guest did not enter running state")
        check_trial(virsh("dumpxml",NAME))
        check_master()
    except Exception:
        # Never unconditionally force shutdown an already booting Windows
        # guest. Safely PAUSE only the disposable trial if validation fails.
        try:
            if virsh("domstate",NAME)=="running":
                virsh("suspend",NAME)
                print("SAFETY_PAUSE: suspended ONLY trial VM after postcheck issue",
                      flush=True)
        except Exception:
            print("CRITICAL: Trial resume postcheck failed and pause could not be confirmed",
                  flush=True)
        raise
    return dict(report,result="TRIAL_WINDOWS_RESUMED_WITH_ZERO_NICS",
                trial_state="RUNNING",guest_resumed=True,
                live_network_interfaces=0,
                original_master_shutoff=True,
                software_verified_in_guest=False,
                windows_login_verified=False,
                guest_static_ip_verified=False,
                warning="Do not attach networks or run malware; inspect console next")

def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","resume"),default="plan")
    opts=parser.parse_args(argv)
    try:
        import json
        print(json.dumps(perform(opts.mode),sort_keys=True,indent=2))
        return 0
    except (ResumeBlocked,ET.ParseError,OSError,ValueError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
