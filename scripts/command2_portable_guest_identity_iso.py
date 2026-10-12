#!/usr/bin/env python3
"""Portable zero-NIC Windows identity-only ISO media (OTHER hosts only).

Consumes the actual immutable Command 2 reservation journal and a matching
per-VM config from the verified zero-NIC staging step. Builds one immutable
read-only optical image, label CAPE_CMD2, containing guest-config.json and
guest-config.sha256, as expected by command2_guest_startup_autoconfig.ps1.

Never changes VM/host settings, starts a guest, mounts/attaches an ISO,
issues network approval or changes the Windows master. Building media
does NOT prove the Windows bootstrap was installed in Command 1.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_windows_guest_config as guestconfig

REF_HOSTS={"cse-ssl-55","ssl-55"}
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
GUEST_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
MAX_JSON=128*1024
GIB=1024**3
MIN_FREE=40*GIB
LOCK_NAME=".command2-identity-iso.lock"

class MediaBlocked(RuntimeError):pass

def need(ok,why):
    if not ok:raise MediaBlocked(why)

def host_guard(host):
    actual=socket.gethostname().split(".",1)[0].lower()
    need(actual not in REF_HOSTS and not SENTINEL.exists() and
         not SENTINEL.is_symlink(),
         "SSL55 protected master: no portable media operations")
    need(type(host) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",host)
         and host==actual,"Exact approved other-host identity required")
    need(os.geteuid()==0,"Root required for private staging journal")

def guarded_regular(path, max_bytes):
    p=Path(path)
    need(p.is_absolute() and not p.is_symlink() and p.is_file(),
         "Expected private regular file missing or symlinked")
    st=p.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
         st.st_uid==0 and st.st_size<=max_bytes and
         (st.st_mode & 0o077)==0,
         "Private file identity/permissions/size unexpected")
    return st

def guarded_dir(path):
    p=Path(path)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Existing root-owned output folder required")
    for part in (p,*p.parents):
        need(not part.is_symlink(),"Symlink ancestor in media output")
    st=p.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "Identity ISO output directory must be root-private 0700")
    return p

def digest(payload):
    return hashlib.sha256(payload).hexdigest()

def render_config(config):
    return (json.dumps(config,sort_keys=True,separators=(",",":"))+"\n").encode()

def read_json(path):
    guarded_regular(path,MAX_JSON)
    return json.loads(Path(path).read_text(encoding="utf-8"))

def read_cmd(*args):
    p=subprocess.run(args,text=True,capture_output=True,timeout=40)
    need(p.returncode==0,"Read-only libvirt status unavailable: "+args[-1])
    return p.stdout.strip()

def vm_guard(vm,uuid):
    need(read_cmd("virsh","-c","qemu:///system","domuuid",vm).lower()==uuid
         and read_cmd("virsh","-c","qemu:///system","domstate",vm).lower()
         =="shut off", "Expected shut-off staged clone UUID changed")
    root=ET.fromstring(read_cmd("virsh","-c","qemu:///system","dumpxml",
                                 "--inactive",vm))
    need(root.findtext("name")==vm and root.findtext("uuid")==uuid and
         len(root.findall("./devices/interface"))==0,
         "Expected staged identity-only clone with zero NICs")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Expected one standalone staged QCOW2 guest system disk")

def plan(*,host,vm,journal,config,dest):
    host_guard(host)
    match=GUEST_RE.fullmatch(vm or "")
    need(match is not None,"Only current 1..16 guest stager names supported")
    journal=Path(journal);config=Path(config);dest=Path(dest)
    if dest.exists() or dest.is_symlink():
        raise MediaBlocked("Refuse to replace or reuse existing ISO")
    need(journal.name=="command2-identity-reservation.json" and
         config==journal.parent/("command2-guest-config-"+vm+".json") and
         dest==journal.parent/(vm+".command2_identity.iso"),
         "Media paths must match immutable journal staging folder")
    outdir=guarded_dir(dest.parent)
    reservation=read_json(journal)
    need(reservation.get("format")=="CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION"
         and reservation.get("version")==1 and reservation.get("host")==host
         and reservation.get("host_network_modified") is False,
         "Reservation journal not canonical or host mismatch")
    rows=reservation.get("entries")
    count=reservation.get("guest_count")
    index=int(match.group(1))-1
    need(type(rows) is list and type(count) is int and
         1<=count<=16 and len(rows)==count and
         index<count and type(rows[index]) is dict and
         rows[index].get("libvirt_name")==vm,
         "VM absent from ordered recorded reservation")
    row=rows[index]
    expected=guestconfig.make_guest_config(row,
                            ip_prefix_from_config(read_json(config)))
    raw=Path(config).read_bytes()
    need(raw==render_config(expected),
         "Prepared guest config differs from independently validated identity")
    need(expected["default_gateway"] is None and
         expected["auto_apply_network"] is False and
         expected["guest_network_interface_attached"] is False,
         "Identity-only media must never approve guest networking")
    vm_guard(vm,expected["expected_machine_uuid"])
    need(shutil.which("genisoimage") is not None,
         "genisoimage unavailable on target host")
    fs=os.statvfs(outdir)
    need(fs.f_bavail*fs.f_frsize>=MIN_FREE+8*1024**2,
         "Insufficient reserve for even tiny identity media")
    return {"result":"COMMAND2_IDENTITY_OPTICAL_PLAN_ONLY",
            "host":host,"vm":vm,
            "expected_vm_uuid":expected["expected_machine_uuid"],
            "guest_hostname":expected["hostname"],
            "guest_static_ip_future_only":expected["ipv4"],
            "expected_mac_future_only":expected["nic_mac"],
            "config_sha256":digest(raw),
            "path":str(dest),
            "media_label":"CAPE_CMD2",
            "contains_host_network_approval":False,
            "guest_network_changed":False,
            "iso_created":False,
            "optical_media_attached":False,
            "windows_startup_bootstrap_installed_verified":False}

def ip_prefix_from_config(config):
    need(type(config) is dict and
         type(config.get("subnet")) is str,
         "Invalid per-VM config subnet")
    return config["subnet"]

def build(*,host,vm,journal,config,dest):
    need(sys.stdin.isatty(),"Typed approval requires local terminal")
    one=plan(host=host,vm=vm,journal=journal,config=config,dest=dest)
    print(json.dumps(one,indent=2,sort_keys=True),flush=True)
    phrase="BUILD-IDENTITY-ISO-"+vm.upper()
    need(input("Type "+phrase+" to create only immutable guest identity ISO: ")
         ==phrase,"Not approved")
    directory=guarded_dir(Path(dest).parent)
    lock=directory/LOCK_NAME
    need(not lock.is_symlink(),"Media lock symlink blocked")
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe identity media lock")
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MediaBlocked("Another identity ISO job active") from exc
        need(plan(host=host,vm=vm,journal=journal,config=config,dest=dest)==one,
             "Staged guest/identity/resources changed since operator approval")
        with tempfile.TemporaryDirectory(prefix=".idiso-",dir=str(directory)) as tmp:
            staging=Path(tmp)
            files=staging/"contents"
            files.mkdir(mode=0o700)
            payload=Path(config).read_bytes()
            (files/"guest-config.json").write_bytes(payload)
            (files/"guest-config.sha256").write_text(digest(payload)+"\n",
                                                    encoding="ascii")
            rendered=staging/"candidate.iso"
            proc=subprocess.run(["genisoimage","-quiet","-J","-R",
                                 "-V","CAPE_CMD2","-o",str(rendered),
                                 str(files)],capture_output=True,text=True,
                                timeout=120)
            need(proc.returncode==0 and rendered.is_file()
                 and 2048<=rendered.stat().st_size<4*1024**2,
                 "Immutable optical image generation failed")
            source=rendered.open("rb")
            try:
                with tempfile.NamedTemporaryFile(prefix=".pending-identity-",
                      dir=str(directory),delete=False) as out:
                    tempdest=Path(out.name)
                    os.fchmod(out.fileno(),0o600)
                    shutil.copyfileobj(source,out)
                    out.flush()
                    os.fsync(out.fileno())
                try:
                    # Link is exclusive: an interrupted or concurrent run
                    # never replaces an existing independently created ISO.
                    os.link(tempdest,dest,follow_symlinks=False)
                finally:
                    tempdest.unlink(missing_ok=True)
                rootfd=os.open(directory,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
                try:os.fsync(rootfd)
                finally:os.close(rootfd)
            finally:
                source.close()
        return {"result":"COMMAND2_IDENTITY_OPTICAL_CREATED_NOT_ATTACHED",
                "vm":vm,"iso":str(dest),
                "sha256":digest(Path(dest).read_bytes()),
                "config_sha256":one["config_sha256"],
                "network_approval_present":False,
                "nic_attached":False,
                "guest_booted":False,
                "windows_personalized":False,
                "verified_on_real_windows":False}
    finally:
        os.close(fd)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("plan","build"),default="plan")
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--vm",required=True)
    ap.add_argument("--journal",type=Path,required=True)
    ap.add_argument("--config",type=Path,required=True)
    ap.add_argument("--dest",type=Path,required=True)
    a=ap.parse_args()
    try:
        result=plan(host=a.approved_host,vm=a.vm,journal=a.journal,
                    config=a.config,dest=a.dest) if a.mode=="plan" else build(
            host=a.approved_host,vm=a.vm,journal=a.journal,
            config=a.config,dest=a.dest)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (MediaBlocked,guestconfig.GuestConfigBlocked,ValueError,TypeError,
            OSError,subprocess.TimeoutExpired,ET.ParseError,IndexError) as exc:
        print(json.dumps({"result":"COMMAND2_IDENTITY_OPTICAL_BLOCKED",
                          "reason":str(exc),
                          "guest_or_network_modified":False},indent=2),
              file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
