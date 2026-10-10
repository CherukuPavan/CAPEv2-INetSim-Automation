#!/usr/bin/env python3
"""Read-only pre-boot acceptance audit for the first disposable Windows clone.

No VM start, redefine, snapshot, AppArmor changes, TPM initialization,
network connection or guest image writes. Reports allowlisted metadata.
Original master must be offline and in the known maintenance definition.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
MASTER="win11"
SNAP="finalshutoffversion"
MASTER_OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
ROOT=Path("/var/lib/libvirt/images/cape-clones-staging")
DISK=ROOT/"win11_trial_1.qcow2"
TEMPLATE=ROOT/"win11_decrypted_template.qcow2"
NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_trial_1_VARS.fd")
MASTER_NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
TPM_ROOT=Path("/var/lib/libvirt/swtpm")
PROFILE_ROOT=Path("/etc/apparmor.d/libvirt")
ABSTRACTION=Path("/etc/apparmor.d/abstractions/libvirt-qemu")
RULEDIR=Path("/etc/apparmor.d/abstractions/libvirt-qemu.d")
RULE=RULEDIR/("98-cape-swtpm-"+UUID)

class AuditError(RuntimeError): pass

def must(condition,message):
    if not condition:
        raise AuditError(message)

def run(*args):
    try:
        return subprocess.run(args,capture_output=True,text=True,check=True,
                              timeout=120).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise AuditError("Failed host check: "+args[0]) from exc

def virsh(*args):return run("virsh","-c","qemu:///system",*args)

def safe_regular(p:Path,private:bool=False):
    must(p.is_file() and not p.is_symlink(),"Missing regular file: "+str(p))
    q=p.stat()
    must(stat.S_ISREG(q.st_mode),"Not regular: "+str(p))
    if private:
        must(q.st_uid==0 and (q.st_mode & 0o077)==0,
             "Plaintext Windows disk is not root-private: "+str(p))
    return q

def inspect_domain():
    must(os.geteuid()==0,"Use sudo to inspect root-private VM state")
    must(virsh("domstate",MASTER)=="shut off","Original master is running")
    must(virsh("domstate",VM)=="shut off","First clone already running")
    must(virsh("snapshot-current",MASTER,"--name")==SNAP,
         "Original cold snapshot pointer changed")
    must(BACKUP.is_dir() and not BACKUP.is_symlink() and
         BACKUP.stat().st_uid==0 and (BACKUP.stat().st_mode & 0o077)==0,
         "Protected original-identity backup unavailable")
    orig_saved=ET.fromstring((BACKUP/"metadata/domain.xml").read_text())
    master=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
    must(orig_saved.findtext("uuid")==master.findtext("uuid"),
         "Original master UUID changed")
    orig_disk=master.find("./devices/disk[@device='disk']/source")
    must(orig_disk is not None and orig_disk.get("file")==MASTER_OVERLAY,
         "Master changed away from maintenance overlay")
    snap=(BACKUP/("metadata/snapshot-"+SNAP+".xml")).read_text().strip()
    must(virsh("snapshot-dumpxml",MASTER,SNAP)==snap,
         "Original cold snapshot metadata changed")
    clone=ET.fromstring(virsh("dumpxml","--inactive",VM))
    must(clone.findtext("name")==VM and clone.findtext("uuid")==UUID,
         "Trial clone identity changed")
    must(clone.findtext("uuid")!=master.findtext("uuid"),
         "Clone shares master libvirt UUID")
    disks=clone.findall("./devices/disk[@device='disk']")
    must(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(DISK),
         "Trial clone disk mismatch")
    nvram=clone.find("./os/nvram")
    must(nvram is not None and (nvram.text or "").strip()==str(NVRAM),
         "Trial clone's NVRAM path mismatch")
    must(nvram.text.strip()!=(master.findtext("./os/nvram") or "").strip(),
         "Trial clone shares original NVRAM file")
    tpm=clone.findall("./devices/tpm")
    must(len(tpm)==1 and tpm[0].get("model") in ("tpm-tis","tpm-crb"),
         "Unexpected clone TPM model")
    backend=tpm[0].find("backend")
    must(backend is not None and backend.get("type")=="emulator" and
         backend.get("version")=="2.0","Clone TPM must be emulator 2.0")
    # libvirt can add a runtime socket source even for auto-generated TPMs.
    source=backend.find("source")
    if source is not None:
        address=source.get("path","")
        must(address.startswith("/run/libvirt/qemu/swtpm/") and
             VM in address and "win11-swtpm.sock" not in address,
             "Clone TPM socket points outside its own libvirt runtime")
    for tag in ("interface","hostdev","filesystem","redirdev","redirfilter",
                "channel","smartcard","shmem","vsock","crypto"):
        must(not clone.findall("./devices/"+tag),
             "Clone contains forbidden host/network device: "+tag)
    must(not any(node.tag.endswith("}commandline") for node in clone.iter()),
         "Unreviewed QEMU command-line extension")
    graphics=clone.findall("./devices/graphics")
    must(len(graphics)==1 and graphics[0].get("type") in ("spice","vnc") and
         graphics[0].get("listen") in ("127.0.0.1","::1"),
         "Clone graphics is not loopback-only")
    for listen in graphics[0].findall("listen"):
        must(listen.get("type")=="address" and
             listen.get("address") in ("127.0.0.1","::1"),
             "Clone graphics has unexpected listener")
    return clone

def inspect_disk():
    for p in (DISK,TEMPLATE):
        safe_regular(p,private=True)
    disk=json.loads(run("qemu-img","info","--output=json",str(DISK)))
    template=json.loads(run("qemu-img","info","--output=json",str(TEMPLATE)))
    for name,item in (("clone",disk),("source",template)):
        must(item.get("format")=="qcow2" and
             item.get("virtual-size")==64*1024**3 and
             not item.get("backing-filename") and
             not item.get("full-backing-filename"),
             name+" disk has unexpected backing or capacity")
    # No full image conversion; this is an offline, read-only integrity check.
    run("qemu-img","check","-q","-f","qcow2",str(DISK))
    nv=safe_regular(NVRAM)
    orig=safe_regular(MASTER_NVRAM)
    must(nv.st_ino!=orig.st_ino or nv.st_dev!=orig.st_dev,
         "Original and clone UEFI NVRAM are hardlinked/shared")
    must(nv.st_size==orig.st_size==540672,
         "Unexpected UEFI NVRAM size")
    return {
        "clone_qcow2_independent":True,
        "clone_disk_root_private":True,
        "original_template_root_private":True,
        "clone_nvram_separate_inode":True,
        "clone_nvram_bytes":nv.st_size,
        "clone_nvram_uid":nv.st_uid,
        "clone_nvram_gid":nv.st_gid,
        "clone_nvram_mode":oct(stat.S_IMODE(nv.st_mode)),
        "source_nvram_uid":orig.st_uid,
        "source_nvram_gid":orig.st_gid,
        "source_nvram_mode":oct(stat.S_IMODE(orig.st_mode)),
        "free_disk_gib":round(shutil.disk_usage(DISK.parent).free/1024**3,1),
    }

def inspect_host():
    must(Path("/sys/module/apparmor/parameters/enabled").read_text().strip()=="Y",
         "AppArmor is not enabled")
    must(ABSTRACTION.is_file() and not ABSTRACTION.is_symlink(),
         "Libvirt AppArmor abstraction absent")
    must(re.search(r"^\s*(?:#include|include)\s+if\s+exists\s+"
                   r"<abstractions/libvirt-qemu\.d>\s*$",
                   ABSTRACTION.read_text(),re.M),
         "Libvirt AppArmor local include unsupported")
    must(RULEDIR.is_dir() and not RULEDIR.is_symlink(),
         "Libvirt AppArmor include directory missing")
    must(Path("/usr/sbin/apparmor_parser").is_file(),
         "AppArmor parser unavailable")
    must(shutil.which("swtpm") and shutil.which("qemu-img"),
         "TPM emulator or QEMU tooling absent")
    actual_rule=RULE.read_text() if RULE.is_file() and not RULE.is_symlink() else None
    expected_rule=f"  /run/libvirt/qemu/swtpm/*-{VM}-swtpm.sock rw,\n"
    must(actual_rule is None or actual_rule==expected_rule,
         "Conflicting trial-VM-specific AppArmor rule exists")
    clone_tpm_dir=TPM_ROOT/UUID
    if clone_tpm_dir.exists():
        must(clone_tpm_dir.is_dir() and not clone_tpm_dir.is_symlink(),
             "Unexpected new TPM state file type")
    return {
        "apparmor_enabled":True,
        "apparmor_local_include_available":True,
        "trial_swtpm_socket_rule":"PRESENT" if actual_rule==expected_rule else "MISSING_REQUIRES_REVIEW",
        "trial_tpm_state_created_before_first_boot":clone_tpm_dir.exists(),
        "original_tpm_state_copied_by_audit":False,
        "vm_started_by_audit":False,
        "apparmor_changed_by_audit":False,
        "guest_nic_count":0,
    }

def main():
    clone=inspect_domain()
    images=inspect_disk()
    host=inspect_host()
    print(json.dumps({
        "status":"OFFLINE_TRIAL_CLONE_PREBOOT_AUDIT_PASSED",
        "clone":VM,
        "clone_uuid":UUID,
        "master_vm_shutoff":True,
        "clone_vm_shutoff":True,
        "source_snapshot_unchanged":True,
        "unique_clone_tpm_emulator":True,
        "next_gate":"review AppArmor policy and DAC before paused first boot",
        **images,**host
    },indent=2,sort_keys=True))

if __name__=="__main__":
    try:main()
    except (AuditError,OSError,ValueError,ET.ParseError,json.JSONDecodeError) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        sys.exit(2)
