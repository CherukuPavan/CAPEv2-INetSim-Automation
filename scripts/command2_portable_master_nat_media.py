#!/usr/bin/env python3
"""OTHER-HOST guarded build of per-VM master-NAT Windows configuration ISOs.

After actual Command2 all-N persistent NAT DHCP + stopped one-NIC staging,
build one immutable optical image (CAPE_NAT2) for each exact win11_1..N.
Contains only nat-config.json + pinned nat-config.sha256 and separate
benign-only command2_guest_master_nat.ps1. Does NOT attach media,
start guests, invoke Windows, configure CAPE, touch snapshots or TPM.
Guest execution requires reviewed bootstrap/operator on the destination
Windows VM; this artifact does not magically configure Windows.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

import command2_portable_master_nat_attach as nat
import command2_master_nat_windows_profile as windows

class NatMediaBlocked(RuntimeError):pass
LOCK=".command2-master-nat-media.lock"
GIB=1024**3

def need(ok,reason):
    if not ok:raise NatMediaBlocked(reason)
def config_paths(folder,n):
    return [folder/f"win11_{i}.master-nat.iso" for i in range(1,n+1)]
def safe_dir(dest):
    p=Path(dest)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Existing absolute root-private ISO output directory required")
    for part in (p,*p.parents):
        need(not part.is_symlink(),"Media directory ancestor is symlink")
    st=p.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "Existing ISO output dir must be root-owned 0700")
    return p

def script_source():
    path=Path(__file__).resolve().with_name("command2_guest_master_nat.ps1")
    need(path.is_file() and not path.is_symlink(),
         "Reviewed Windows NAT bootstrap script missing")
    st=path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         st.st_size<64*1024 and st.st_size>128 and
         not (stat.S_IMODE(st.st_mode)&0o022),
         "Untrusted local Windows guest script")
    payload=path.read_bytes()
    need(payload.startswith(b"#Requires -Version 5.1") and
         b"COMMAND2_MASTER_NAT_WINDOWS_V1" in payload and
         b"malware_public_internet_authorized" in payload,
         "Unexpected Windows NAT source content")
    return payload

def plan(host,journal,dest):
    folder=safe_dir(dest)
    hoststate=nat.build(host,journal,True)
    profiles=windows.make(hoststate)
    script=script_source()
    names=config_paths(folder,len(profiles))
    need(all(not p.exists() and not p.is_symlink() for p in names),
         "Master NAT ISO already exists. Never overwrite/rebuild blindly")
    fs=os.statvfs(folder)
    free=fs.f_bavail*fs.f_frsize
    need(free>=40*GIB+len(profiles)*8*1024*1024,
         "Shared ISO storage below 40GiB safety reserve")
    output=[]
    for p,config in zip(names,profiles):
        one=windows.render_one(config)
        output.append({
           "vm":config["guest_name"],"iso_dest":str(p),
           "guest_json_sha256":one["sha256"],
           "nat_ipv4":config["ipv4"],
           "nat_mac":config["nic_mac"],
           "windows_smbios_uuid":config["expected_machine_uuid"],
           "approval_required_before_windows_guest_change":True})
    return {
        "result":"COMMAND2_ALL_N_WINDOWS_NAT_OPTICAL_PLAN_ONLY",
        "approved_host":host,"journal":str(journal),
        "count":len(profiles),"entries":output,
        "window_script_sha256":hashlib.sha256(script).hexdigest(),
        "source_guests_shut_off":True,
        "one_nat_guest_nic_and_dhcp_active_persistent_verified":True,
        "existing_outputs_absent":True,
        "guest_media_created":False,
        "attached_to_libvirt":False,
        "Windows_bootstrap_execution_and_reboot_tested":False,
        "CAPE_READY":False,"TPM_restoration_proven":False,
        "malware_analysis_authorized":False
    }

def build(host,journal,dest):
    need(sys.stdin.isatty(),"Direct terminal authorization required")
    before=plan(host,journal,dest)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    phrase=f"BUILD-{before['count']}-IMMUTABLE-MASTER-NAT-WINDOWS-ISOS"
    need(input("Type "+phrase+" to create N opt-in Windows media: ")==phrase,
         "Operator denied exact NAT guest config media generation")
    output=safe_dir(dest)
    lock=output/LOCK
    need(not lock.is_symlink(),"Unsafe symlinked ISO build lock")
    fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    created=[]
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "ISO build lock is not root-private")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NatMediaBlocked("Another guarded NAT media build active") from exc
        need(plan(host,journal,dest)==before,
             "Guest UUID/NAT/DHCP/media directory changed after approval")
        profiles=windows.make(nat.build(host,journal,True))
        script=script_source()
        with tempfile.TemporaryDirectory(prefix=".cape-nat-iso-",
                                         dir=str(output)) as td:
            staging=Path(td)
            for c in profiles:
                contents=staging/("contents-"+c["guest_name"])
                contents.mkdir(mode=0o700)
                config=windows.render_one(c)
                (contents/"nat-config.json").write_bytes(config["json_bytes"])
                (contents/"nat-config.sha256").write_text(config["sha256"]+"\n",
                                                         encoding="ascii")
                (contents/"command2_guest_master_nat.ps1").write_bytes(script)
                path=output/(c["guest_name"]+".master-nat.iso")
                tmp=staging/(c["guest_name"]+".iso")
                try:
                    x=subprocess.run(
                        ["genisoimage","-quiet","-J","-R","-V","CAPE_NAT2",
                         "-o",str(tmp),str(contents)],
                        capture_output=True,text=True,timeout=120,
                        check=False)
                except (OSError,subprocess.TimeoutExpired) as exc:
                    raise NatMediaBlocked("genisoimage not installed or timed out") from exc
                need(x.returncode==0 and tmp.is_file() and
                     2048<=tmp.stat().st_size<=8*1024*1024,
                     "Per-VM immutable NAT optical image build failed")
                # Exclusive publish: never replace other user files or
                # previously created VM media. Partial N requires review.
                os.link(tmp,path,follow_symlinks=False)
                created.append(str(path))
        dirfd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        return {**before,
            "result":"COMMAND2_ALL_N_WINDOWS_NAT_ISOS_BUILT_NOT_ATTACHED",
            "guest_media_created":True,
            "created_paths":created,
            "per_vm_iso_sha256":{
                Path(p).name:hashlib.sha256(Path(p).read_bytes()).hexdigest()
                for p in created},
            "guest_windows_executed":False}
    except Exception as exc:
        if created:
            raise NatMediaBlocked(
                "NAT_MEDIA_PARTIAL_OUTPUTS_PRESENT_DO_NOT_REBUILD_OR_DELETE: "+
                ", ".join(created)+". "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","build"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        value=(plan(a.approved_host,a.journal,a.output_dir)
              if a.mode=="plan" else
              build(a.approved_host,a.journal,a.output_dir))
        print(json.dumps(value,indent=2,sort_keys=True),flush=True)
        return 0
    except (NatMediaBlocked,nat.NatAttachBlocked,
            nat.profile.PortableNatBlocked,windows.NatGuestBlocked,
            nat.workflow.WorkflowBlocked,ValueError,TypeError,OSError,
            KeyError) as exc:
        print(json.dumps({
            "result":"COMMAND2_WINDOWS_MASTER_NAT_MEDIA_BLOCKED",
            "reason":str(exc),"do_not_auto_retry_on_partial_iso_set":True,
            "guest_booted_or_cape_snapshot_changed":False},
            sort_keys=True),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
