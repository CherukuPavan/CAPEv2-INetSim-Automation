#!/usr/bin/env python3
"""Maintenance-XML reversible *offline* define drill for original Windows VM.

Requires an operator on SSL-55. The only libvirt mutation is: define a
no-NIC, no-USB-redirection temporary disk-overlay XML, verify it, then
redefine the preserved original XML. Never start or snapshot-revert a VM.
FAIL-CLOSED: on any error following define, attempt original XML recovery.
This validates only libvirt metadata restoration, NOT TPM/Windows unlock.
"""
from __future__ import annotations
import argparse
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from plan_win11_maintenance_xml import plan, MaintenancePlanError

VM="win11"
SNAP="finalshutoffversion"
OLD="/var/lib/libvirt/images/win11.finalshutoffversion"
NEW="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-cold-export.lock")

class DrillError(RuntimeError): pass

def need(ok,reason):
    if not ok: raise DrillError(reason)

def run(*args):
    try:
        return subprocess.run(args,check=True,capture_output=True,text=True,
                              timeout=90).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise DrillError(f"Command {args[0]} failed") from e

def virsh(*args):
    return run("virsh","-c","qemu:///system",*args)

def assert_shutoff():
    need(virsh("domstate",VM)=="shut off",
         "Guest is not shut off; stop and investigate")

def check_original():
    assert_shutoff()
    need(virsh("snapshot-current",VM,"--name")==SNAP,
         "Cold snapshot pointer changed")
    actual=virsh("dumpxml","--inactive",VM)
    root=ET.fromstring(actual)
    need(root.findtext("name")==VM,"Unexpected domain name")
    need(root.find("./devices/disk[@device='disk']/source").get("file")==OLD,
         "Original disk source was not restored")
    need(len(root.findall("./devices/interface"))==1 and
         len(root.findall("./devices/redirdev"))==2 and
         len(root.findall("./devices/channel"))==1,
         "Original host integration devices not restored")
    return actual

def check_maintenance(reference):
    assert_shutoff()
    need(virsh("snapshot-current",VM,"--name")==SNAP,
         "Cold snapshot pointer changed during temporary definition")
    before=ET.fromstring(reference)
    current=ET.fromstring(virsh("dumpxml","--inactive",VM))
    need(current.findtext("./name")==VM and
         current.findtext("./uuid")==before.findtext("./uuid"),
         "Original VM identity changed")
    need(current.find("./os/nvram").text.strip()==
         before.find("./os/nvram").text.strip(),"UEFI NVRAM path changed")
    need(ET.tostring(current.find("./devices/tpm"))==
         ET.tostring(before.find("./devices/tpm")),
         "Original TPM configuration changed")
    need(len(current.findall("./devices/disk[@device='disk']"))==1 and
         current.find("./devices/disk[@device='disk']/source").get("file")==NEW,
         "Maintenance overlay not selected")
    for tag in ("interface","redirdev","redirfilter","channel"):
        need(not current.findall("./devices/"+tag),
             "Unwanted guest-connected device in maintenance XML")
    return True

def fingerprint(path):
    st=path.stat()
    return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)

def main():
    need(os.geteuid()==0,"Run only with sudo on SSL-55")
    need(not LOCK.is_symlink(),"Unsafe lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    altered=False
    original=""
    try:
        s=os.fstat(fd)
        need(s.st_uid==0 and not s.st_mode & 0o077,
             "Unsafe lock file ownership or permissions")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        assert_shutoff()
        need(virsh("snapshot-current",VM,"--name")==SNAP,
             "Master snapshot changed")
        dominfo=virsh("dominfo",VM).lower()
        need("autostart:      disable" in dominfo or
             any("autostart:" in l and "disable" in l
                 for l in dominfo.splitlines()),
             "VM autostart is not confirmed disabled")
        need(BACKUP.is_dir() and not BACKUP.is_symlink() and
             BACKUP.stat().st_uid==0 and not BACKUP.stat().st_mode & 0o077,
             "Protected backup directory missing or not root-private")
        saved=BACKUP/"metadata"/"domain.xml"
        snap=BACKUP/"metadata"/"snapshot-"+SNAP+".xml"
        need(saved.is_file() and snap.is_file() and
             not saved.is_symlink() and not snap.is_symlink(),
             "Original XML/snapshot preservation files unavailable")
        original=virsh("dumpxml","--inactive",VM)
        need(saved.read_text().strip()==original.strip(),
             "Original domain differs from preserved backup")
        need(snap.read_text().strip()==virsh("snapshot-dumpxml",VM,SNAP).strip(),
             "Current snapshot metadata differs from preserved backup")
        need(Path(NEW).is_file() and not Path(NEW).is_symlink(),
             "Detached maintenance overlay missing")
        nvram=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
        need(nvram.is_file() and not nvram.is_symlink(),
             "Original firmware file missing")
        # Only metadata inspected, never reads or publishes TPM state.
        tpm_root=Path("/var/lib/libvirt/swtpm")/virsh("domuuid",VM)
        need(tpm_root.is_dir() and not tpm_root.is_symlink(),
             "Original TPM state directory missing")
        protected=[nvram]+[p for p in tpm_root.rglob("*") if p.is_file()]
        need(len(protected)==3,"Unexpected number of original firmware/TPM files")
        old_state={str(p):fingerprint(p) for p in protected}
        proposed,summary=plan(original,OLD,NEW)
        print("PASS: Original XML, cold snapshot, TPM/NVRAM metadata, "
              "and detached overlay available",flush=True)
        with tempfile.TemporaryDirectory(prefix="cape-xml-rollback-",dir="/run") as tmp:
            maintenance=Path(tmp)/"maintenance.xml"
            maintenance.write_text(proposed)
            os.chmod(maintenance,0o600)
            # Actual libvirt redefine (no boot); autostart is blocked.
            print("Testing temporary offline libvirt definition...",flush=True)
            altered=True
            virsh("define",str(maintenance),"--validate")
            check_maintenance(original)
            print("PASS: Temporary configuration has zero NICs, USB "
                  "redirections and channels",flush=True)
            # NOW restore the original untouched definition.
            print("Restoring original libvirt definition offline...",flush=True)
            virsh("define",str(saved),"--validate")
            check_original()
            restored=virsh("dumpxml","--inactive",VM)
            need(restored.strip()==original.strip(),
                 "Domain round-trip differs from original XML; review before boot")
            need(virsh("snapshot-dumpxml",VM,SNAP).strip()==
                 snap.read_text().strip(),"Snapshot metadata changed")
            need({str(p):fingerprint(p) for p in protected}==old_state,
                 "Original TPM/NVRAM file metadata changed")
            altered=False
        print("RESULT: OFFLINE MAINTENANCE DEFINITION AND "
              "ORIGINAL RESTORE VERIFIED",flush=True)
        print("ORIGINAL_DOMAIN_RESTORED=YES")
        print("MASTER_STATE=shut off")
        print("ORIGINAL_TPM_NVRAM_FILES_UNCHANGED=YES")
        print("ORIGINAL_SNAPSHOT_METADATA_UNCHANGED=YES")
        print("GUEST_BOOTED=NO")
        print("BITLOCKER_CHANGED=NO")
        print("MAINTENANCE_OVERLAY_ATTACHED_AFTER_TEST=NO")
        print("RESTORE_OF_WINDOWS_UNLOCK_TESTED=NO")
    finally:
        if altered:
            try:
                print("ROLLBACK: Attempting to restore original "
                      "libvirt definition while guest is shut off...",flush=True)
                assert_shutoff()
                need(bool(original),"Original XML not captured")
                with tempfile.TemporaryDirectory(prefix="cape-rollback-",dir="/run") as tmp:
                    p=Path(tmp)/"original.xml"
                    p.write_text(original)
                    os.chmod(p,0o600)
                    virsh("define",str(p),"--validate")
                    check_original()
                print("ROLLBACK: Original disk definition restored; "
                      "verify other invariants before boot",flush=True)
            except Exception as exc:
                print("CRITICAL: ORIGINAL LIBVIRT DEFINITION RESTORE "
                      f"NOT CONFIRMED: {type(exc).__name__}. DO NOT START WIN11",
                      file=sys.stderr)
        os.close(fd)

if __name__=="__main__":
    try: main()
    except (DrillError,MaintenancePlanError,ET.ParseError,OSError) as exc:
        print("BLOCKED:",str(exc),file=sys.stderr)
        sys.exit(2)
