#!/usr/bin/env python3
"""One READ-ONLY SSL55 host-dependency + exact master capacity report.

Designed only for the operator's protected CSE-SSL-55 reference. Reads
actual CAPE Git checkout SHA (if present), QEMU/libvirt installed binary
metadata, non-secret INetSim presence, root rclone-config file metadata,
and the protected win11's exact OS image/UEFI/TPM/snapshot *metadata*.

Runs as root solely to inspect libvirt and swtpm; it never modifies any
file, VM, snapshot, package, service, rclone remote or guest network.
No OAuth, DB password, Windows/TPM contents, Git config, sample data,
environment values, systemd ExecStart or secret filenames in output.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys

import command1_actual_master_export_capacity as capacity

CAPE=Path("/opt/CAPEv2")
PROGRAMS=("qemu-system-x86_64","qemu-img","virsh",
          "virt-install","swtpm","rclone","poetry","inetsim")
CONFIG=Path("/root/.config/rclone/rclone.conf")

class FingerprintBlocked(RuntimeError):
    pass

def need(value, message):
    if not value:raise FingerprintBlocked(message)

def safe_readonly(argv, seconds=15):
    # Call sites supply fixed executables and no untrusted data.
    try:
        proc=subprocess.run(argv,capture_output=True,text=True,
                            check=False,timeout=seconds)
        if proc.returncode!=0 or len(proc.stdout)>8192:
            return None
        return proc.stdout.strip()
    except (OSError,subprocess.TimeoutExpired,UnicodeError):
        return None

def read_binary_facts():
    rows={}
    for app in PROGRAMS:
        path=shutil.which(app)
        if not path:
            rows[app]={"discoverable_on_root_path":False}
            continue
        binary=Path(path)
        final=binary.resolve()
        # Never print argv, shell environment or sensitive systemd unit.
        origin="unknown"
        details=safe_readonly(["dpkg-query","-S",str(binary)])
        if details and re.match(r"^[a-zA-Z0-9.+_-]+:",details):
            origin="dpkg_managed_path"
        elif str(final).startswith("/usr/local/"):
            origin="possibly_local_build"
        elif str(final).startswith("/usr/"):
            origin="system_path_dpkg_not_confirmed"
        else:
            origin="nonstandard_binary_path"
        rows[app]={
            "discoverable_on_root_path":True,
            "path":str(binary)[:220],
            "resolved_path":str(final)[:220],
            "package_provenance":origin,
        }
    return rows

def cape_revision():
    result={"root_present":CAPE.is_dir() and not CAPE.is_symlink(),
            "git_metadata_present":(CAPE/".git").exists(),
            "git_commit_sha40":None,
            "source_uncommitted_tracked_changes":None}
    if not result["root_present"]:return result
    # Git rev-parse has no index refresh or working-tree file writes.
    # Avoid git status: even a read-oriented status may refresh metadata.
    standard=["git","--no-optional-locks",
              "-c","safe.directory=/opt/CAPEv2","-C",str(CAPE)]
    sha=safe_readonly(standard+["rev-parse","--verify","HEAD"])
    if sha and re.fullmatch(r"[a-f0-9]{40}",sha):
        result["git_commit_sha40"]=sha
    result["uncommitted_changes_not_assessed"]=True
    return result

def root_crypt_config_status():
    p=CONFIG
    if not p.exists() or p.is_symlink():
        return {"root_rclone_config_exists":False,
                "root_crypt_remote_configured":None}
    st=p.stat()
    private=(stat.S_ISREG(st.st_mode) and st.st_uid==0
             and stat.S_IMODE(st.st_mode)==0o600
             and st.st_nlink==1)
    # Never parse/emit OAuth tokens/crypt passphrases.
    return {"root_rclone_config_exists":True,
            "config_metadata_root_0600":private,
            "root_crypt_remote_configured":None}

def inetsim_presence():
    return {
        "inetsim_binary_discoverable":shutil.which("inetsim") is not None,
        "etc_inetsim_directory":Path("/etc/inetsim").is_dir(),
        "opt_INetSim_directory":Path("/opt/INetSim").is_dir(),
        "inetsim_live_service_verified":False,
        "inetsim_actual_install_completed":False,
    }

def run(storage):
    need(os.geteuid()==0,
         "Root needed to inspect protected exact master metadata")
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Read-only reference fingerprint is restricted to SSL-55")
    result={
        "result":"SSL55_DEEP_SOURCE_HOST_FINGERPRINT_READ_ONLY",
        "hostname":"CSE-SSL-55",
        "cape_repository":cape_revision(),
        "virtualization_binary_metadata":read_binary_facts(),
        "inetsim_discovery":inetsim_presence(),
        "root_rclone_config_metadata":root_crypt_config_status(),
        "source_master_capacity":None,
        "guest_started_or_reverted":False,
        "files_or_systemd_services_modified":False,
        "source_disk_or_TPM_file_contents_emitted":False,
        "secret_values_emitted":False,
    }
    try:
        result["source_master_capacity"]=capacity.plan(storage)
    except Exception as exc:
        result["source_master_capacity"]={
            "result":"SOURCE_MASTER_CAPACITY_BLOCKED",
            "error_type":type(exc).__name__,
            "manual_review_required":True,
            "master_modified":False,
        }
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--storage-root",type=Path,
                   default=Path("/var/backups"))
    args=p.parse_args()
    try:
        print(json.dumps(run(args.storage_root),sort_keys=True,indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"result":"SSL55_DEEP_REFERENCE_FINGERPRINT_BLOCKED",
                          "error_type":type(exc).__name__,
                          "no_host_or_VM_changes":True},
                         sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
