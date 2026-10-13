#!/usr/bin/env python3
"""Read-only SSL-55 source-provenance report for CAPE/INetSim portability.

Collects only allowlisted package versions, CAPE Git commit, unit loaded/
active status, exact master metadata, disk/RAM facts and mounted tmpfs type.
Never reads the contents of CAPE .conf, OAuth tokens, SQL passwords, TPM
blobs or Windows disks. Output JSON stdout; no host changes.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import command123_readonly_machine_report as common

CAPE=Path("/opt/CAPEv2")
PACKAGES=("python3","python3-venv","python3-pip","git","qemu-system-x86",
          "qemu-utils","libvirt-clients","libvirt-daemon-system","ovmf",
          "swtpm","swtpm-tools","virt-manager","virtinst","inetsim",
          "suricata","postgresql","mongodb-org","mongodb","poetry")
SERVICES=("cape.service","cape-processor.service","cape-rooter.service",
          "cape-web.service","suricata.service","inetsim.service",
          "postgresql.service","mongodb.service","mongod.service")
CONF=("api.conf","auxiliary.conf","cuckoo.conf","kvm.conf",
      "mitmdump.conf","routing.conf")

def query(*args):
    # Whitelist FULL read-only argument patterns, not just program names.
    # Otherwise a caller could accidentally perform mutating service operations,
    # git checkout or a mutable mount operation under this blueprint.
    approved = (
        len(args) == 4 and args[:3] ==
            ("dpkg-query","-W","-f=$"+"{Status}|$"+"{Version}")
            and args[3] in PACKAGES,
        len(args) == 5 and args[:3] ==
            ("systemctl","show","--no-pager") and
            args[3] == "--property=LoadState,ActiveState,UnitFileState"
            and args[4] in SERVICES,
        len(args) == 6 and args[:3] ==
            ("git","-C",str(CAPE)) and
            args[3:] == ("rev-parse","--verify","HEAD"),
        len(args) == 6 and args[:3] ==
            ("git","-C",str(CAPE)) and
            args[3:] == ("status","--porcelain","--untracked-files=no"),
        args == ("findmnt","--mountpoint","/mnt/tmpfs","-n","-o",
                 "FSTYPE"),
    )
    if not any(approved):
        return None
    try:
        p=subprocess.run(args,capture_output=True,text=True,check=False,
                         timeout=12)
        return p.stdout.strip() if p.returncode==0 and len(
            p.stdout)<128*1024 else None
    except (OSError,subprocess.TimeoutExpired,UnicodeError):
        return None

def packages():
    out={}
    for name in PACKAGES:
        val=query("dpkg-query","-W","-f=$"+"{Status}|$"+"{Version}",name)
        if val and val.startswith("install ok installed|"):
            version=val.split("|",1)[1]
            out[name]=(version if re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}",
                                              version) else "PRESENT")
        else:out[name]="NOT_INSTALLED_OR_UNKNOWN"
    return out

def repository():
    facts={"CAPE_checkout_present":CAPE.is_dir() and not CAPE.is_symlink(),
           "CAPE_commit_SHA40":None,"uncommitted_changes_present":None}
    if not facts["CAPE_checkout_present"]:return facts
    sha=query("git","-C",str(CAPE),"rev-parse","--verify","HEAD")
    if sha and re.fullmatch(r"[a-f0-9]{40}",sha):
        facts["CAPE_commit_SHA40"]=sha
    dirty=query("git","-C",str(CAPE),"status","--porcelain",
                "--untracked-files=no")
    if dirty is not None:
        facts["uncommitted_changes_present"]=bool(dirty)
    return facts

def services():
    out={}
    for name in SERVICES:
        val=query("systemctl","show","--no-pager",
                  "--property=LoadState,ActiveState,UnitFileState",name)
        data={}
        if val:
            for line in val.splitlines():
                if "=" not in line:continue
                key,value=line.split("=",1)
                if key in ("LoadState","ActiveState","UnitFileState"):
                    data[key]=value if re.fullmatch(
                        r"[a-z_-]{1,35}",value) else "UNKNOWN"
        out[name]=data or {"status":"UNAVAILABLE"}
    return out

def mounted_tmpfs():
    val=query("findmnt","--mountpoint","/mnt/tmpfs","-n","-o","FSTYPE")
    return {"exact_mnt_tmpfs":val=="tmpfs",
            "filesystem":val if val in ("tmpfs","ext4","xfs") else "UNKNOWN"}

def run():
    base=common.run("source",Path("/var/lib/libvirt/images"))
    return {"result":"CAPE_REFERENCE_SOURCE_PROVENANCE_READ_ONLY",
            "host_os":base["OS"],"arch":base["arch"],
            "cpu_count":base["CPU_count"],"memory":base["memory"],
            "storage":base["storage"],
            "master":base["exact_master"],
            "package_versions":packages(),
            "CAPE_checkout":repository(),
            "systemd":services(),
            "CAPE_conf_presence":{
                name:((CAPE/"conf"/name).is_file() and
                      not (CAPE/"conf"/name).is_symlink())
                for name in CONF},
            "tmpfs":mounted_tmpfs(),
            "secrets_included":False,
            "source_win11_unchanged":True,
            "VMs_not_booted_or_reverted":True,
            "host_or_service_modified":False,
            "full_fresh_host_installer_proven":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("report",),default="report")
    p.parse_args()
    try:
        print(json.dumps(run(),indent=2,sort_keys=True))
        return 0
    except (ValueError,OSError,TypeError) as exc:
        print(json.dumps({"result":"REFERENCE_REPORT_BLOCKED",
                          "error_type":type(exc).__name__,
                          "host_modified":False}),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
