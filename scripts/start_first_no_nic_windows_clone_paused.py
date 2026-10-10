#!/usr/bin/env python3
"""Guarded first START-PAUSED of the independent zero-NIC Windows trial VM.

Only VM 'win11_trial_1' with known UUID may be started, and only with
'virsh start --paused'. This is an *authorized benign boot-readiness probe*,
not a Windows boot or malware analysis. The guest CPUs are not resumed.
No snapshot, VM XML, networking, host security, or master source changes.

If the paused guest unexpectedly exposes NIC/host integration devices or
has altered its identity, fail shut and stop ONLY the disposable clone.
The original 'win11' master stays shut off. No VM is resumed by this script.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

NAME="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
MASTER="win11"
SNAP="finalshutoffversion"
DISK="/var/lib/libvirt/images/cape-clones-staging/win11_trial_1.qcow2"
NVRAM="/var/lib/libvirt/qemu/nvram/win11_trial_1_VARS.fd"
TEMPLATE="/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2"
MASTER_OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
RULE=Path("/etc/apparmor.d/abstractions/libvirt-qemu.d/98-cape-swtpm-"+UUID)
EXPECTED_RULE="  /run/libvirt/qemu/swtpm/*-win11_trial_1-swtpm.sock rw,\n"
FORBIDDEN=("interface","redirdev","redirfilter","channel","hostdev",
           "filesystem","smartcard","shmem","vsock","crypto")
MEMORY_RESERVE_KIB=3*1024*1024

class PausedStartError(RuntimeError):pass

def require(ok,reason):
    if not ok:raise PausedStartError(reason)

def call(*args,timeout=120):
    try:
        return subprocess.run(args,check=True,capture_output=True,text=True,
                              timeout=timeout).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise PausedStartError("Host command failed: "+args[0]) from exc

def virsh(*args):
    return call("virsh","-c","qemu:///system",*args)

def check_xml(text,*,live):
    xml=ET.fromstring(text)
    require(xml.tag=="domain" and xml.findtext("name")==NAME and
            xml.findtext("uuid")==UUID,"Unexpected clone identity")
    disks=xml.findall("./devices/disk[@device='disk']")
    require(len(disks)==1 and disks[0].get("type")=="file" and
            disks[0].find("source") is not None and
            disks[0].find("source").get("file")==DISK and
            disks[0].find("driver") is not None and
            disks[0].find("driver").get("type")=="qcow2",
            "Unexpected cloned system disk")
    nv=xml.find("./os/nvram")
    require(nv is not None and (nv.text or "").strip()==NVRAM,
            "Trial clone UEFI variables changed")
    tpms=xml.findall("./devices/tpm")
    require(len(tpms)==1 and tpms[0].find("backend") is not None and
            tpms[0].find("backend").get("type")=="emulator" and
            tpms[0].find("backend").get("version")=="2.0",
            "Trial clone TPM emulator mismatch")
    src=tpms[0].find("./backend/source")
    if src is not None:
        path=src.get("path","")
        require(path.startswith("/run/libvirt/qemu/swtpm/") and
                NAME in path and "win11-swtpm.sock" not in path,
                "Trial clone swtpm backend unexpectedly shares a socket")
    for device in FORBIDDEN:
        require(not xml.findall("./devices/"+device),
                "Unexpected connected trial-VM device: "+device)
    require(not any(e.tag.endswith("}commandline") for e in xml.iter()),
            "Trial VM has unreviewed QEMU extension")
    graphics=xml.findall("./devices/graphics")
    require(len(graphics)==1 and graphics[0].get("type") in ("spice","vnc"),
            "Unexpected clone graphics")
    require(graphics[0].get("listen") in ("127.0.0.1","::1"),
            "Clone graphics is not loopback-only")
    for listener in graphics[0].findall("listen"):
        require(listener.get("type")=="address" and
                listener.get("address") in ("127.0.0.1","::1"),
                "Unexpected graphics listener")
    require(xml.findtext("./uuid")!="289d89be-68ec-4c62-90e1-ea930849266f",
            "Original master UUID unexpectedly present")
    if live:
        require(xml.find("devices/emulator") is not None,
                "Live QEMU emulator path unavailable")
    return xml

def require_files():
    for file in (Path(DISK),Path(TEMPLATE)):
        require(file.is_file() and not file.is_symlink(),
                "Windows disk image missing")
    require(Path(DISK).resolve()!=Path(TEMPLATE).resolve(),
            "Trial clone disk aliases independent master template")
    for file in (Path(NVRAM),):
        require(file.is_file() and not file.is_symlink(),
                "Trial clone UEFI NVRAM unavailable")
    require(not RULE.is_symlink() and RULE.is_file() and
            RULE.read_text()==EXPECTED_RULE,
            "Trial-only swtpm AppArmor permission not verified")
    require(Path("/sys/module/apparmor/parameters/enabled").read_text().strip()=="Y",
            "AppArmor has been disabled")
    require(BACKUP.is_dir() and not BACKUP.is_symlink() and
            BACKUP.stat().st_uid==0 and not BACKUP.stat().st_mode & 0o077,
            "Original preservation backup unavailable")

def require_states():
    require(virsh("domstate",MASTER)=="shut off",
            "Original master must remain shut off")
    require(virsh("snapshot-current",MASTER,"--name")==SNAP,
            "Original cold snapshot pointer changed")
    original=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
    saved=ET.fromstring((BACKUP/"metadata/domain.xml").read_text())
    require(original.findtext("uuid")==saved.findtext("uuid"),
            "Original UUID differs from backup")
    source=original.find("./devices/disk[@device='disk']/source")
    require(source is not None and source.get("file")==MASTER_OVERLAY,
            "Original master disk is no longer its maintenance overlay")
    require(virsh("snapshot-dumpxml",MASTER,SNAP)==
            (BACKUP/"metadata/snapshot-finalshutoffversion.xml").read_text().strip(),
            "Original cold snapshot metadata changed")

def confirm_memory(inactive_xml):
    mem=inactive_xml.find("./memory")
    require(mem is not None and mem.text and
            mem.get("unit","KiB")=="KiB",
            "Unsupported VM memory format")
    requested=int(mem.text)
    report=Path("/proc/meminfo").read_text()
    match=re.search(r"^MemAvailable:\s+(\d+)\s+kB$",report,re.M)
    require(match is not None and
            int(match.group(1)) >= requested+MEMORY_RESERVE_KIB,
            "Host lacks safe free memory reserve for trial guest")

def examine():
    require(os.geteuid()==0,"Use sudo to check libvirt and TPM")
    require_files()
    require_states()
    require(virsh("domstate",NAME)=="shut off",
            "Trial clone is not shut off; do not start twice")
    require(virsh("domuuid",NAME)==UUID,
            "Trial UUID unexpectedly changed")
    inactive=check_xml(virsh("dumpxml","--inactive",NAME),live=False)
    confirm_memory(inactive)
    require(Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd").resolve()!=Path(NVRAM).resolve(),
            "Trial NVRAM path aliases original UEFI variables")
    return {"clone_name":NAME,
            "clone_uuid":UUID,
            "original_master_offline":True,
            "trial_vm_offline":True,
            "trial_vm_network_interfaces":0,
            "trial_vm_host_shares":0,
            "trial_rule_verified":True,
            "vm_started":False}

def paused_start():
    preflight=examine()
    print("PASS: Master shut off, snapshot preserved; trial clone is isolated",flush=True)
    print("PASS: Trial AppArmor TPM rule, independent disk/NVRAM and memory reserve",flush=True)
    try:
        virsh("start",NAME,"--paused")
    except PausedStartError:
        # Failed start can leave partial swtpm state. Do not force off any
        # guest because libvirt may not have created the trial yet.
        if virsh("domstate",NAME)=="running":
            raise PausedStartError("Unexpected RUNNING trial VM after start error; stop it manually")
        raise
    # Guard live XML/state; if it is running, never claim paused safety.
    try:
        state=virsh("domstate",NAME).lower()
        require(state in ("paused","paused (user)"),
                "Trial VM did not remain paused")
        check_xml(virsh("dumpxml",NAME),live=True)
        require(virsh("domstate",MASTER)=="shut off",
                "Original master started unexpectedly")
        # No real network interfaces (not even disconnected)
        # and no QEMU USB redirection in the live domain.
        preflight.update({
            "result":"TRIAL_FIRST_START_PAUSED_SAFE",
            "trial_vm_state":"PAUSED",
            "live_guest_nics":0,
            "live_usb_redirection":0,
            "live_host_shares":0,
            "new_tpm_emulator_started_by_libvirt":True,
            "guest_cpus_resumed":False,
            "windows_boot_verified":False,
            "guest_ip_personalized":False,
            "original_master_offline":True,
            "vm_started":True
        })
        return preflight
    except Exception as exc:
        try:
            virsh("destroy",NAME)
            print("SAFETY_STOP: stopped ONLY disposable trial clone",flush=True)
        except Exception:
            print("CRITICAL: trial clone live checks failed and safe stop failed;",
                  "manually inspect before proceeding",file=sys.stderr)
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","start-paused"),default="plan")
    args=parser.parse_args()
    try:
        result=examine() if args.mode=="plan" else paused_start()
        print(json.dumps(result,indent=2,sort_keys=True))
    except (PausedStartError,OSError,ET.ParseError,ValueError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":
    main()
