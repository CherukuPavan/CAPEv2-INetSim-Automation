#!/usr/bin/env python3
"""Read-only Windows SYSTEM hive inventory from a trusted shut-off QCOW2 template.

Uses only a free Linux NBD device, QEMU read-only export, and an NTFS
read-only/no-recovery mount. Reads an allowlisted set of Windows TCP/IP
registry fields through the existing hivex inspector; never changes the
template, creates clones, or publishes TPM/BitLocker/Registry secrets.

Never run this on an untrusted malware-submitted disk image: disk/NTFS
parsers are a kernel and userspace attack surface. Only a known clean
golden-template disk is appropriate.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import inspect_standalone_windows_hive as inspector

TEMPLATE=Path("/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2")
OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
LOCK=Path("/run/lock/cape-cold-export.lock")
DEV_PATTERN=re.compile(r"nbd[0-9]+\Z")

class ReadError(RuntimeError): pass

def require(ok,message):
    if not ok: raise ReadError(message)

def call(*args,timeout=120):
    try:
        return subprocess.run(args,check=True,capture_output=True,text=True,
                              timeout=timeout).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise ReadError(f"Unable to run {args[0]}: stop and review local host") from e

def virsh(*args):
    return call("virsh","-c","qemu:///system",*args)

def validate():
    require(os.geteuid()==0,"Requires sudo")
    require(virsh("domstate","win11")=="shut off",
            "Original Windows master must be shut off")
    require(virsh("snapshot-current","win11","--name")=="finalshutoffversion",
            "Cold master snapshot changed")
    root=ET.fromstring(virsh("dumpxml","--inactive","win11"))
    disks=root.findall("./devices/disk[@device='disk']")
    require(len(disks)==1 and disks[0].find("source") is not None and
            disks[0].find("source").get("file")==OVERLAY,
            "Unexpected original maintenance domain disk")
    require(TEMPLATE.is_file() and not TEMPLATE.is_symlink(),
            "Expected exported standalone template is missing")
    qinfo=json.loads(call("qemu-img","info","--output=json",str(TEMPLATE)))
    require(qinfo.get("format")=="qcow2" and
            qinfo.get("virtual-size")==64*1024**3 and
            not qinfo.get("backing-filename") and
            not qinfo.get("full-backing-filename"),
            "Template is not an independent 64 GiB QCOW2 image")
    disk=TEMPLATE.stat()
    require(disk.st_uid==0 and not disk.st_mode & 0o077,
            "Plaintext Windows template is not root-private")

def choose_free_nbd()->str:
    for path in sorted(Path("/sys/block").glob("nbd*")):
        if not DEV_PATTERN.fullmatch(path.name):
            continue
        device=Path("/dev")/path.name
        if not device.exists() or (path/"pid").exists():
            continue
        children=list(path.glob(path.name+"p*"))
        if children:
            continue
        return str(device)
    raise ReadError("No idle, unmounted NBD device found; do not steal active NBD")

def inventory():
    validate()
    require(not LOCK.is_symlink(),"Unsafe shared NBD/export lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    device=None
    mountdir=None
    mounted=False
    connected=False
    try:
        st=os.fstat(fd)
        require(st.st_uid==0 and not st.st_mode & 0o077,
                "Shared NBD/export lock permissions unsafe")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        validate()
        device=choose_free_nbd()
        require(call("blockdev","--getro",device) in ("0","1"),
                "Unexpected kernel block device")
        call("qemu-nbd","-r","-f","qcow2","-c",device,str(TEMPLATE))
        connected=True
        require(call("blockdev","--getro",device)=="1",
                "NBD is not read-only")
        part=device+"p3"
        for _ in range(15):
            if Path(part).exists(): break
            time.sleep(1)
        require(Path(part).exists(),"Windows NTFS partition device unavailable")
        require(call("blockdev","--getro",part)=="1",
                "Windows partition NBD is not read-only")
        with tempfile.TemporaryDirectory(prefix="cape-win11-registry-") as temp:
            root=Path(temp)
            mountdir=root/"mnt"
            mountdir.mkdir(mode=0o700)
            call("mount","-t","ntfs-3g","-o",
                 "ro,norecover,nosuid,nodev,noexec",part,str(mountdir))
            mounted=True
            options=call("findmnt","-n","-o","OPTIONS","--target",str(mountdir))
            require("ro" in options.split(","),
                    "NTFS was not mounted read-only")
            hive=mountdir/"Windows"/"System32"/"config"/"SYSTEM"
            require(hive.is_file() and not hive.is_symlink(),
                    "Windows SYSTEM hive absent or symlinked")
            require(4096<=hive.stat().st_size<=inspector.MAX_BYTES,
                    "Windows SYSTEM hive size out of expected range")
            local=root/"SYSTEM"
            shutil.copyfile(hive,local)
            local.chmod(0o600)
            result=inspector.inspect_file(local,expected_ip=None)
            require(result["mode"]=="READ_ONLY","Hive inspection changed mode")
            # Never report private registry bytes, TPM or BitLocker state.
            result["template"]=str(TEMPLATE)
            result["source_part"]=3
            result["template_modified"]=False
            result["nbd_read_only"]=True
            result["ntfs_mount_read_only"]=True
            result["guest_booted"]=False
            call("umount",str(mountdir))
            mounted=False
            mountdir=None
        return result
    finally:
        if mounted and mountdir:
            try: call("umount",str(mountdir))
            except ReadError:
                print("CRITICAL: readonly mount still active; "
                      "do not disconnect its NBD",file=sys.stderr)
                connected=False
        if connected and device:
            try: call("qemu-nbd","-d",device)
            except ReadError:
                print("CRITICAL: NBD disconnect failed; "
                      "do not reuse its device",file=sys.stderr)
        os.close(fd)

def main():
    os.umask(0o077)
    try:
        print(json.dumps(inventory(),sort_keys=True,indent=2))
        return 0
    except (OSError,ReadError,ValueError,inspector.HiveReadError,
            ET.ParseError) as e:
        print(f"BLOCKED: {type(e).__name__}: {e}",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
