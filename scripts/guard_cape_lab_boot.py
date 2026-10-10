#!/usr/bin/env python3
"""Idempotent boot/recovery hook for the SINGLE named CAPE nft guard.

Service installation is a SEPARATE reviewed step. This script itself:
- if exact CAPE table exists, verify its structure and NEVER overwrite it;
- if absent, syntax-check and create ONLY inet cape_analysis_guard;
- never flush/delete other firewall tables, change policies, start VMs,
  enable networks, modify systemd, restart Docker/libvirt or open egress.

A successful run is NOT proof of guest traffic containment. Keep the
CAPE libvirt analysis network autostart DISABLED until independently
verified startup gating and negative egress checks are complete.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import dryrun_cape_lab_guard_nft as draft
import install_cape_lab_guard_nft as installer

LOCK=Path("/run/lock/cape-cold-export.lock")

class GuardBootError(RuntimeError):pass

def require(ok,msg):
    if not ok:raise GuardBootError(msg)

def nft_exists():
    try:
        proc=subprocess.run(["nft","-j","list","table","inet",draft.TABLE],
                            capture_output=True,text=True,timeout=30)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise GuardBootError("Cannot determine existing CAPE guard state") from exc
    if proc.returncode==0:
        return True
    # Distinguish genuine missing table from inaccessible nft backend.
    # An intentional no-mutation netlink LIST TABLE with no table should
    # return a nonzero and an 'No such file or directory' diagnostic.
    if ("No such file or directory" in proc.stderr or
        "does not exist" in proc.stderr):
        return False
    raise GuardBootError("Cannot distinguish missing guard from nft backend failure")

def prepare_source():
    src=draft.policy_text()
    draft.validate_policy(src)
    require(hashlib.sha256(src.encode()).hexdigest()==
            installer.APPROVED_POLICY_SHA256,
            "Unapproved or drifted CAPE guard source")
    return src

def reconcile():
    require(os.geteuid()==0,"CAPE boot guard requires root")
    require(not LOCK.is_symlink(),"Unsafe guard lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        require(st.st_uid==0 and not st.st_mode&0o077,
                "Unsafe guard-lock ownership/permissions")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        source=prepare_source()
        if nft_exists():
            installer.verify_installed()
            return {
                "result":"EXISTING_CAPE_GUARD_VERIFIED_NO_CHANGE",
                "guard_table":draft.TABLE,"new_firewall_table_created":False,
                "reboot_persistence_proven":False,
                "malware_isolation_verified":False}
        with tempfile.TemporaryDirectory(prefix="cape-boot-guard-",
                                         dir="/run") as td:
            p=Path(td)/"guard.nft"
            p.write_text(source,encoding="utf-8")
            p.chmod(0o600)
            installer.execute("nft","--check","--file",str(p))
            # In normal boot, no separate analysis VM should run until
            # this dedicated service has completed. There is deliberately
            # NO network start here: this code adds firewall rules ONLY.
            installer.execute("nft","--file",str(p))
        installer.verify_installed()
        return {"result":"CAPEv2_GUARD_CREATED_AND_VERIFIED",
                "guard_table":draft.TABLE,"new_firewall_table_created":True,
                "reboot_persistence_proven":False,
                "malware_isolation_verified":False}
    finally:
        os.close(fd)

def main():
    try:
        print(json.dumps(reconcile(),sort_keys=True,indent=2))
        return 0
    except (GuardBootError,installer.GuardInstallBlocked,draft.DryRunBlocked,
            ValueError,OSError,subprocess.TimeoutExpired) as exc:
        print("BLOCKED: CAPE lab guard boot verification failed ("+
              type(exc).__name__+"); do not attach guest NICs",
              file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
