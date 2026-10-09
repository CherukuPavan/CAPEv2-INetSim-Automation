#!/usr/bin/env python3
"""Safely stage/launch an original-TPM Windows maintenance session.

This is a host-only, explicitly authorized maintenance operation, NOT a
CAPE analysis guest boot. It must never be run on untrusted samples.
It changes only the original *inactive domain definition* to point to the
already-existing COW overlay and removes its NIC, USB redirection and guest
channels. It verifies paused libvirt live XML before resuming Windows.
No BitLocker change is performed here.

On failure before Windows resumes: stop the paused guest, restore original
domain definition and do not touch/commit the source QCOW2.
On success: Windows is running against the working overlay. Leave domain
in maintenance mode until an operator verifies guest unlock/BitLocker
status. Restore original definition only after clean shutdown and review.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from plan_win11_maintenance_xml import plan, MaintenancePlanError

VM="win11"
SNAP="finalshutoffversion"
DISK="/var/lib/libvirt/images/win11.finalshutoffversion"
OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-cold-export.lock")

class MaintenanceBootError(RuntimeError):
    pass

def require(ok:bool, msg:str)->None:
    if not ok: raise MaintenanceBootError(msg)

def run(*args:str,timeout:int=90)->str:
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if p.returncode:
        # Never echo original libvirt XML or private-state data.
        raise MaintenanceBootError(f"{args[0]} {args[3] if len(args)>3 and args[0]=='virsh' else args[1] if len(args)>1 else ''} failed (exit {p.returncode}): {p.stderr.strip()[-700:]}")
    return p.stdout.strip()

def virsh(*args:str,timeout:int=90)->str:
    return run("virsh","-c","qemu:///system",*args,timeout=timeout)

def state():
    return virsh("domstate",VM)

def xml_host_safe(xml:str,expected_uuid:str,orig_tpm:bytes,orig_nvram:str)->None:
    root=ET.fromstring(xml)
    require(root.findtext("./name")==VM and root.findtext("./uuid")==expected_uuid,
            "Guest identity changed unexpectedly")
    nvr=root.find("./os/nvram")
    require(nvr is not None and (nvr.text or "").strip()==orig_nvram,
            "Guest UEFI variable store path changed")
    tpm=root.find("./devices/tpm")
    require(tpm is not None and ET.tostring(tpm)==orig_tpm,
            "Guest TPM backend settings changed")
    disks=root.findall("./devices/disk[@device='disk']")
    require(len(disks)==1,"Guest has unexpected system disks")
    src=disks[0].find("source")
    require(src is not None and src.get("file")==OVERLAY,
            "Guest did not select standalone maintenance overlay")
    for tag in ("interface","redirdev","redirfilter","channel",
                "hostdev","filesystem","smartcard","shmem","vsock"):
        require(not root.findall("./devices/"+tag),
                "Unwanted host-connected VM device: "+tag)

def preflight() -> tuple[str, str, bytes, str, str]:
    require(os.geteuid()==0,"Run with sudo on SSL-55")
    require(state()=="shut off","win11 must be shut off to begin")
    require(virsh("snapshot-current",VM,"--name")==SNAP,
            "Original master snapshot changed")
    info=virsh("dominfo",VM)
    require(re.search(r"^Autostart:\s+disable\s*$",info,re.M|re.I),
            "Master autostart is not confirmed disabled")
    require(re.search(r"^Managed save:\s+no\s*$",info,re.M|re.I),
            "Managed-save status unknown or active; stop before starting")
    require(BACKUP.is_dir() and not BACKUP.is_symlink() and
            BACKUP.stat().st_uid==0 and BACKUP.stat().st_mode & 0o077 == 0,
            "Protected private backup location unavailable")
    dom_file=BACKUP/"metadata/domain.xml"
    snap_file=BACKUP/"metadata/snapshot-"+SNAP+".xml"
    require(dom_file.is_file() and snap_file.is_file() and
            not dom_file.is_symlink() and not snap_file.is_symlink(),
            "Original protected domain/snapshot metadata unavailable")
    original=virsh("dumpxml","--inactive",VM)
    require(dom_file.read_text().strip()==original,
            "Original domain definition no longer matches protected backup")
    snap=snap_file.read_text().strip()
    require(virsh("snapshot-dumpxml",VM,SNAP)==snap,
            "Snapshot metadata differs from protected backup")
    root=ET.fromstring(original)
    expected_uuid=root.findtext("./uuid")
    nvram_node=root.find("./os/nvram")
    tpm_node=root.find("./devices/tpm")
    require(expected_uuid and nvram_node is not None and tpm_node is not None,
            "Master UUID/firmware/TPM identity missing")
    nvram=(nvram_node.text or "").strip()
    require(nvram=="/var/lib/libvirt/qemu/nvram/win11_VARS.fd",
            "Unexpected master NVRAM location")
    require(Path(nvram).is_file() and not Path(nvram).is_symlink(),
            "Original NVRAM state not present")
    require((BACKUP/"private/original_VARS.fd").is_file() and
            (BACKUP/"private/swtpm").is_dir(),
            "Original protected firmware/TPM backup not found")
    # Never read/copy or expose private swtpm state bytes.
    tpm_dir=Path("/var/lib/libvirt/swtpm")/expected_uuid
    require(tpm_dir.is_dir() and not tpm_dir.is_symlink(),
            "Original TPM state directory unavailable")
    overlay=Path(OVERLAY)
    require(overlay.is_file() and not overlay.is_symlink(),
            "Approved detached QCOW2 overlay unavailable")
    rows=json.loads(run("qemu-img","info","--output=json",
                        "--backing-chain",OVERLAY,timeout=120))
    require(isinstance(rows,list) and len(rows)==5 and
            all(r.get("format")=="qcow2" for r in rows) and
            rows[0].get("filename")==OVERLAY and
            rows[0].get("virtual-size")==64*1024**3 and
            rows[0].get("full-backing-filename")==DISK and
            rows[1].get("filename")==DISK,
            "Maintenance overlay no longer references verified cold master")
    planned,_=plan(original,DISK,OVERLAY)
    return original, snap, ET.tostring(tpm_node), nvram, planned

def execute() -> dict:
    require(not LOCK.is_symlink(),"Unsafe export/maintenance lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    redefined=False
    resumed=False
    original=""
    try:
        ls=os.fstat(fd)
        require(ls.st_uid==0 and not ls.st_mode & 0o077,
                "Unsafe maintenance lock permissions")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        original,snap,tpm,nvram,maintenance=preflight()
        uuid=ET.fromstring(original).findtext("./uuid")
        print("PASS: Shut-off master, preserved state, cold snapshot and overlay")
        with tempfile.TemporaryDirectory(prefix="cape-win11-maintenance-",dir="/run") as tmp:
            xml=Path(tmp)/"offline.xml"
            xml.write_text(maintenance)
            os.chmod(xml,0o600)
            print("Defining temporary no-NIC/no-USB maintenance domain...",flush=True)
            redefined=True
            virsh("define",str(xml),"--validate")
            xml_host_safe(virsh("dumpxml","--inactive",VM),uuid,tpm,nvram)
            require(state()=="shut off","VM unexpectedly started during definition")
            require(virsh("snapshot-dumpxml",VM,SNAP)==snap,
                    "Original snapshot metadata changed on redefine")
            print("PASS: Inactive maintenance XML has zero network adapters")
            print("Starting VM PAUSED to validate the live device inventory...",flush=True)
            virsh("start",VM,"--paused",timeout=180)
            require(state()=="paused","VM did not enter paused pre-boot state")
            xml_host_safe(virsh("dumpxml",VM),uuid,tpm,nvram)
            require(virsh("snapshot-dumpxml",VM,SNAP)==snap,
                    "Snapshot metadata changed while paused")
            print("PASS: Live paused VM has zero network adapters")
            print("Resuming Windows for authorized benign maintenance...",flush=True)
            # Once resume is attempted do not automatically destroy a running
            # guest on error; preserve state and require manual assessment.
            resumed=True
            virsh("resume",VM,timeout=90)
            require(state()=="running","Windows maintenance VM is not running")
            xml_host_safe(virsh("dumpxml",VM),uuid,tpm,nvram)
        return {
            "result":"ISOLATED_ORIGINAL_TPM_MAINTENANCE_BOOT_STARTED",
            "master_domain":VM,
            "working_disk":OVERLAY,
            "cold_source_qcow2_not_modified_by_script":True,
            "network_interfaces_live":0,
            "usb_redirections_live":0,
            "guest_channels_live":0,
            "uses_original_vm_uuid":True,
            "uses_original_nvram_and_tpm":True,
            "bitlocker_decryption_requested":False,
            "original_domain_restored":False,
            "windows_desktop_verified":False,
            "next_step":"Open original win11 in virt-manager; report desktop vs BitLocker recovery. Do not enter or share keys."
        }
    finally:
        if redefined and not resumed:
            # No guest has executed Windows instructions yet; paused boot
            # may have initialized emulator state, so avoid calling this a
            # full restore of actual TPM/NVRAM after test failure.
            try:
                if state()=="paused":
                    virsh("destroy",VM,timeout=120)
                if state()=="shut off" and original:
                    with tempfile.TemporaryDirectory(prefix="cape-win11-restore-",dir="/run") as tmp:
                        backup=Path(tmp)/"original.xml"
                        backup.write_text(original)
                        os.chmod(backup,0o600)
                        virsh("define",str(backup),"--validate")
                    require(virsh("dumpxml","--inactive",VM).strip()==original.strip(),
                            "Original domain XML restore check failed")
                    print("RECOVERY: original inactive domain definition restored")
                else:
                    print("URGENT: Original domain not restored; DO NOT BOOT",file=sys.stderr)
            except Exception as exc:
                print("URGENT: Offline domain restoration failed; DO NOT BOOT "
                      f"({type(exc).__name__})",file=sys.stderr)
        os.close(fd)

def main() -> int:
    try:
        print(json.dumps(execute(),indent=2,sort_keys=True))
        return 0
    except (MaintenanceBootError,MaintenancePlanError,OSError,ValueError,
            ET.ParseError,subprocess.TimeoutExpired,json.JSONDecodeError) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        print("If win11 remains running, do not forcibly power it off;"
              " check guest state before restoring any original XML",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
