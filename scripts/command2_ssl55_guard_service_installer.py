#!/usr/bin/env python3
"""SSL-55: guarded create-only CAPE-only systemd replay installer.

PLAN (default) makes no host changes. INSTALL creates only a small
root-owned CAPE script bundle, its private authorization record, and
cape-analysis-guard.service, then enables that unit WITHOUT starting it.
Requires exact current shut-off VMs, no-NIC clone/trial, inactive lab,
historical guard, disabled nftables.service, active libvirt daemon,
verified pinned sources and direct typed approval. NO VM or network
activation, no firewall rule writes, and NO edits to /etc/nftables.conf.

Systemd replay on boot still needs an actual reboot test. The unit is
not proof of IPv4/IPv6 egress isolation or permission to attach a NIC.
"""
from __future__ import annotations
import argparse
import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import command2_ssl55_guard_scoped_replay as replay
import command2_ssl55_guard_systemd_unit_plan as unitplan
import command2_ssl55_boot_persistence_readonly as boot
import command2_ssl55_existing_guard_readonly as existing

INSTALL_DIR=Path("/usr/local/libexec/cape-command2")
AUTH_DIR=Path("/etc/cape-command2")
AUTH_FILE=AUTH_DIR/"ssl55-guard-replay-approved.json"
UNIT_FILE=Path("/etc/systemd/system/cape-analysis-guard.service")
LOCK=Path("/run/lock/cape-ssl55-guard-installer.lock")
# Pinned Git blob IDs from development. Never fetch "latest" at install time.
SOURCE_BLOBS={
 "command2_ssl55_guard_scoped_replay.py":"c5c7a816efc87df6b57935585722714fcf212369",
 "command2_ssl55_existing_guard_readonly.py":"aa3b37ebcc9c6a2231ebd7864bb43400bae6aa6d",
 "command2_ssl55_boot_persistence_readonly.py":"b7dd0fc6c859b86fa565eef8845221907294691d",
 "command2_ssl55_guard_systemd_unit_plan.py":"809cc747341113eb93563017006d819316748e61",
 "dryrun_cape_lab_guard_nft.py":"1a33563be0987cc386b49d7007bfe5cced475d75",
}
AUTH_PHRASE="INSTALL-ENABLE-ONLY-CAPE-GUARD-SSL55"


class InstallerBlocked(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise InstallerBlocked(message)


def command(*argv,timeout=30):
    try:
        result=subprocess.run(argv,capture_output=True,text=True,
                              check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise InstallerBlocked("Host command unavailable: "+argv[0]) from exc
    require(result.returncode==0,
            "Host command failed: "+argv[0]+" rc="+str(result.returncode))
    return result.stdout.strip()


def git_blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def inspect_sources(staging):
    path=Path(staging)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(),
            "Absolute trusted staging folder required")
    s=path.stat()
    require(not s.st_mode & 0o022, "Source folder is writable by others")
    result={}
    for name,sha in SOURCE_BLOBS.items():
        file=path/name
        require(not file.is_symlink() and file.is_file(),
                "Missing/symlinked pinned source: "+name)
        meta=file.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and
                not meta.st_mode & 0o022 and meta.st_size<131072,
                "Unsafe staged source metadata: "+name)
        data=file.read_bytes()
        require(git_blob(data)==sha,
                "Git blob SHA mismatch: "+name)
        try:
            ast.parse(data,filename=name)
        except (SyntaxError,ValueError) as exc:
            raise InstallerBlocked("Invalid Python source: "+name) from exc
        result[name]=data
    return result


def service_observations():
    names=("libvirtd.service","virtqemud.service")
    statuses={}
    for name in names:
        raw=boot.read("systemctl","show","--no-pager",
                      "--property=LoadState,UnitFileState,ActiveState",name)
        statuses[name]=boot.parse_show(raw,name)
    active=[name for name in names
            if statuses[name]["load_state"]=="loaded" and
            statuses[name]["active_state"]=="active"]
    require(len(active)==1,
            "Expected exactly one ACTIVE supported libvirt daemon; "
            "inspect host before installing guard")
    return active[0],statuses


def no_existing_installation():
    for p in (INSTALL_DIR,AUTH_DIR,AUTH_FILE,UNIT_FILE):
        require(not p.exists() and not p.is_symlink(),
                "Existing CAPE install artifact; refuse overwrite: "+str(p))
    existing_state=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "cape-analysis-guard.service"),"cape-analysis-guard.service")
    require(existing_state.get("query_succeeded") and
            existing_state.get("load_state")=="not-found",
            "Systemd already has a CAPE guard unit or state unavailable")


def plan(staging):
    require(os.geteuid()==0,"Root required for protected SSL55 preflight")
    details=replay.plan()
    require(details["existing_guard_state"]=="present_verified",
            "Existing CAPE nft guard not present with expected structure")
    obs=boot.perform()
    require(obs["analysis_network_and_clones_autostart_disabled"] is True and
            obs["safe_to_attach_win11_1_nic"] is False and
            obs["service_show_observations"]["nftables.service"]
               ["unit_file_state"]=="disabled" and
            obs["service_show_observations"]["cape-analysis-guard.service"]
               ["load_state"]=="not-found",
            "Protected host service/guest baseline differs")
    source=inspect_sources(staging)
    libvirt_service,status=service_observations()
    proposal=unitplan.build_unit(libvirt_service)
    no_existing_installation()
    return {
        "result":"SSL55_CAPE_ONLY_SERVICE_INSTALL_PLAN",
        "service_name":"cape-analysis-guard.service",
        "libvirt_service":libvirt_service,
        "original_guard_sha256":replay.POLICY_SHA256,
        "expected_sources":{k:git_blob(v) for k,v in source.items()},
        "unit_sha256":proposal["unit_sha256"],
        "unit_text":proposal["unit_text"],
        "install_dir":str(INSTALL_DIR),
        "approval_path":str(AUTH_FILE),
        "base_nftables_service_touched":False,
        "nft_rules_modified":False,"analysis_network_started":False,
        "guest_changed":False,"systemd_unit_installed":False,
        "systemd_unit_enabled":False,
        "reboot_persistence_verified":False,
        "production_network_approved":False,
        "host_modified":False,
    }


def write_exclusive(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,"wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(path,mode)


def fsync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def verify_after(libvirt_service):
    source=command("systemctl","show","--no-pager",
                   "--property=LoadState,UnitFileState,ActiveState",
                   "cape-analysis-guard.service")
    status=boot.parse_show(source,"cape-analysis-guard.service")
    require(status["load_state"]=="loaded" and
            status["unit_file_state"] in ("enabled", "enabled-runtime") and
            status["active_state"]=="inactive",
            "Dedicated guard unit must be enabled but NOT started")
    nft_state=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "nftables.service"),"nftables.service")
    require(nft_state.get("unit_file_state")=="disabled" and
            nft_state.get("active_state")=="inactive",
            "Unexpected base nftables service change")
    require(replay.strict_state()=="present_verified",
            "Existing nft guard/VM/network definition changed; STOP")
    return status


def apply(staging, approved_plan_sha):
    require(sys.stdin.isatty(),
            "Run installer directly with an interactive controlling TTY")
    require(re.fullmatch(r"[0-9a-f]{64}",approved_plan_sha or "") is not None,
            "Reviewed plan checksum required")
    require(os.geteuid()==0,"Root required")
    snapshot=plan(staging)
    encoded=json.dumps(snapshot,sort_keys=True,
                       separators=(",",":")).encode("utf-8")
    found=hashlib.sha256(encoded).hexdigest()
    require(found==approved_plan_sha,
            "Reviewed install plan fingerprint STALE. No install.")
    require(input("Type "+AUTH_PHRASE+" to create+ENABLE CAPE-only unit: ")==
            AUTH_PHRASE,"Operator declined exact CAPE-only service install")
    require(not LOCK.is_symlink(),"Unsafe CAPE installer lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        metadata=os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0 and
                stat.S_IMODE(metadata.st_mode)==0o600 and metadata.st_nlink==1,
                "Unsafe root installation lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        checked=plan(staging)
        require(hashlib.sha256(json.dumps(checked,sort_keys=True,
              separators=(",",":")).encode()).hexdigest()==approved_plan_sha,
              "Host state changed under installation lock")
        source=inspect_sources(staging)
        # Ubuntu may not pre-create /usr/local/libexec. Ensure its parent
        # is trusted root-owned before create-only installation there.
        rootlocal=Path("/usr/local")
        local_info=rootlocal.lstat()
        require(stat.S_ISDIR(local_info.st_mode) and
                local_info.st_uid==0 and not local_info.st_mode & 0o022,
                "Cannot trust /usr/local for root-only helper installation")
        parent=INSTALL_DIR.parent
        require(parent==Path("/usr/local/libexec"),
                "Unreviewed helper installation parent")
        if parent.exists() or parent.is_symlink():
            entry=parent.lstat()
            require(stat.S_ISDIR(entry.st_mode) and entry.st_uid==0 and
                    not entry.st_mode & 0o022,
                    "Untrusted /usr/local/libexec parent")
        else:
            parent.mkdir(mode=0o755)
            fsync_directory(rootlocal)
        INSTALL_DIR.mkdir(mode=0o700)
        AUTH_DIR.mkdir(mode=0o700)
        for name,data in source.items():
            write_exclusive(INSTALL_DIR/name,data,0o600)
        fsync_directory(INSTALL_DIR)
        approval={"kind":replay.AUTH_KIND,
                  "policy_sha256":replay.POLICY_SHA256,
                  "protected_master_uuid":existing.MASTER_UUID,
                  "protected_clone_uuid":existing.CLONE_UUID,
                  "approved_single_table_replay":True,
                  "approved_no_global_flush":True,
                  "approved_no_guest_or_network_changes":True,
                  "approved_host_name":socket.gethostname().split(".",1)[0].lower(),
                  "operator":os.environ.get("SUDO_USER","authorized_operator"),
                  "install_plan_sha256":approved_plan_sha}
        write_exclusive(AUTH_FILE,(json.dumps(approval,indent=2,sort_keys=True)+"\n").encode(),0o600)
        fsync_directory(AUTH_DIR)
        write_exclusive(UNIT_FILE,checked["unit_text"].encode(),0o644)
        fsync_directory(UNIT_FILE.parent)
        # Syntax/ExecStart validation before enabling a new systemd unit.
        # Unlike systemctl start, systemd-analyze verify does not run it.
        command("systemd-analyze","verify",str(UNIT_FILE))
        # Do not use --now: enabling schedules the dedicated unit at
        # subsequent boot without immediately starting lab or service.
        command("systemctl","daemon-reload")
        command("systemctl","enable","cape-analysis-guard.service")
        verify_after(checked["libvirt_service"])
        return {
            "result":"SSL55_CAPE_ONLY_GUARD_UNIT_INSTALLED_ENABLED_NOT_STARTED",
            "service_name":"cape-analysis-guard.service",
            "systemd_unit_enabled":True,"systemd_unit_active":False,
            "helper_bundle_root_owned":True,
            "reboot_persistence_verified":False,
            "nftables_service_remains_disabled":True,
            "vm_or_network_changed":False,
            "ipv4_ipv6_negative_egress_verified":False,
            "snapshot_ready":False,
            "manual_reboot_test_required":True,
        }
    except Exception as exc:
        raise InstallerBlocked(
            "Partial install possible: preserve installed files; "
            "DO NOT rerun, delete, reboot or enable unrelated services. "
            "Review the TXT report. Detail: "+str(exc)) from exc
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","install"),default="plan")
    parser.add_argument("--staging-dir",type=Path,required=True)
    parser.add_argument("--plan-sha256")
    args=parser.parse_args()
    try:
        if args.mode=="plan":
            out=plan(args.staging_dir)
            out["plan_sha256"]=hashlib.sha256(
                json.dumps(out,sort_keys=True,separators=(",",":")).encode()
            ).hexdigest()
        else:
            out=apply(args.staging_dir,args.plan_sha256)
        print(json.dumps(out,indent=2,sort_keys=True))
        return 0
    except (InstallerBlocked,replay.ReplayBlocked,boot.BootBlocked,
            existing.AuditBlocked,OSError,ValueError,TypeError) as err:
        print("BLOCKED: "+str(err),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
