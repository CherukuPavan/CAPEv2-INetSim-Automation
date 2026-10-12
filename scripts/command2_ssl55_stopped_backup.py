#!/usr/bin/env python3
"""Clone-only cold backup from an ALREADY STOPPED SSL55 win11_1.

Never stops, starts, restores or redefines a VM. Refuses live disks.
Captures QCOW2, OVMF VARS, swtpm state and domain XML together.
"""
import argparse
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
import uuid
import xml.etree.ElementTree as ET

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
VARS=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TPM=Path("/var/lib/libvirt/swtpm")/UID/"tpm2"
OUT=DISK.parent/"cape-win11_1-cold-recovery"
LOCK=Path("/run/lock/cape-command2-stopped-backup.lock")
GIB=1024**3
class Stop(Exception): pass
def must(ok,msg):
    if not ok:raise Stop(msg)
def cmd(*args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=600)
    must(p.returncode==0,"Host command failed: "+args[0])
    return p.stdout.strip()
def virsh(*a):return cmd("virsh","-c","qemu:///system",*a)
def stamp(p):
    must(p.is_file() and not p.is_symlink(),"Missing/linked file: "+str(p))
    s=p.stat()
    must(stat.S_ISREG(s.st_mode) and s.st_nlink==1,"Unsafe file: "+str(p))
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def state():
    must(os.geteuid()==0,"Root required")
    must(socket.gethostname().split(".")[0].lower()=="cse-ssl-55","Wrong host")
    must(virsh("domuuid",VM).lower()==UID,"Unexpected clone UUID")
    for name,identity in (MASTER,TRIAL):
        must(virsh("domuuid",name).lower()==identity and
             virsh("domstate",name).lower()=="shut off","Protected VM altered")
    must(not virsh("snapshot-list",VM,"--name").strip(),"Snapshot already exists")
    root=ET.fromstring(virsh("dumpxml","--inactive",VM))
    must(root.findtext("name")==VM and root.findtext("uuid")==UID,
         "XML identity mismatch")
    disk=root.find("./devices/disk[@device='disk']")
    must(disk is not None and disk.find("source") is not None and
         disk.find("source").get("file")==str(DISK),"Unexpected disk")
    backing=disk.find("backingStore")
    must(backing is None or (backing.find("source") is None and
         backing.find("backingStore") is None),"Nonempty backing chain")
    must(root.findtext("./os/nvram")==str(VARS),"Unexpected VARS")
    tpm=root.find("./devices/tpm/backend")
    must(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0","Unexpected swtpm")
    nics=root.findall("./devices/interface")
    must(len(nics)==1 and nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="cape-analysis-isolated",
         "Unexpected network")
    return (virsh("domstate",VM).lower(),ET.tostring(root,encoding="unicode"))
def items():
    stamp(DISK);stamp(VARS)
    must(TPM.is_dir() and not TPM.is_symlink(),"Missing TPM state")
    files=[(DISK,"disk.qcow2"),(VARS,"uefi-vars.fd")]
    for file in sorted(TPM.iterdir()):
        must(file.is_file() and not file.is_symlink(),"TPM file invalid")
        if file.name==".lock":continue
        must(re.fullmatch("[A-Za-z0-9_.-]+",file.name) is not None,
             "Unexpected TPM filename")
        must(0 < stamp(file)[2] < 20*1024*1024,"TPM file size invalid")
        files.append((file,"tpm-"+file.name))
    must(any(n.endswith(".permall") for _,n in files),
         "TPM permanent state missing")
    return files
def free():
    v=os.statvfs(DISK.parent)
    return v.f_frsize*v.f_bavail
def plan():
    mode,xml=state()
    must(mode in ("running","shut off"),"Unexpected clone state")
    files=items()
    size=stamp(DISK)[2]
    need=size+45*GIB
    must(free()>=need,"Full copy cannot preserve 40 GiB reserve")
    must(not OUT.is_symlink() and (not OUT.exists() or
         (OUT.is_dir() and OUT.stat().st_uid==0 and
          not OUT.stat().st_mode & 0o077)),"Unsafe backup root")
    return {"result":"STOPPED_BACKUP_PLAN_PASS","vm_state":mode,
            "file_count":len(files),"apparent_disk_gib":round(size/GIB,2),
            "free_gib":round(free()/GIB,2),
            "conservative_gate_gib":round(need/GIB,2),
            "requires_stopped_vm":True,"backup_created":False}
def sha(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        while True:
            b=f.read(4*1024*1024)
            if not b:return h.hexdigest()
            h.update(b)
def capture():
    must(sys.stdin.isatty(),"Interactive terminal required")
    before=plan()
    must(before["vm_state"]=="shut off","Only already shut-off clone permitted")
    word="CAPTURE-STOPPED-WIN11_1"
    must(input("Type "+word+" to copy ONLY the stopped clone data: ")==word,
         "Operator approval missing")
    must(plan()==before,"Preflight changed")
    must(not LOCK.is_symlink(),"Unsafe lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fs=os.fstat(fd)
        must(fs.st_uid==0 and stat.S_IMODE(fs.st_mode)==0o600,"Unsafe lock metadata")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        must(plan()==before,"Preflight changed after locking")
        # No backup of active QEMU or swtpm data. Assert no running guests.
        must(not virsh("list","--name").strip(),"Other guest running")
        cmd("qemu-img","check","-q","-f","qcow2",str(DISK))
        OUT.mkdir(mode=0o700,exist_ok=True)
        folder=OUT/(".incomplete-"+uuid.uuid4().hex)
        folder.mkdir(mode=0o700)
        print("INCOMPLETE_CAPTURE: "+str(folder),flush=True)
        records=[]
        for source,name in items():
            initial=stamp(source)
            target=folder/name
            with source.open("rb") as reader:
                outfd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(outfd,"wb") as writer:
                    while True:
                        block=reader.read(4*1024*1024)
                        if not block:break
                        must(free()>=40*GIB+len(block),"Reserve reached")
                        writer.write(block)
                    writer.flush();os.fsync(writer.fileno())
            must(stamp(source)==initial,"Source changed during backup")
            digest=sha(source)
            must(digest==sha(target),"Backup checksum mismatch")
            records.append({"name":name,"size":target.stat().st_size,
                            "sha256":digest})
            print("COPIED_AND_VERIFIED: "+name,flush=True)
        cmd("qemu-img","check","-q","-f","qcow2",str(folder/"disk.qcow2"))
        mode,xml=state()
        must(mode=="shut off","VM became active during backup")
        p=folder/"domain.xml";p.write_text(xml);p.chmod(0o600)
        data={"format":"cape-ssl55-cold-v1","vm":VM,"uuid":UID,
              "files":records,"restore_tested":False}
        p=folder/"manifest.json";p.write_text(json.dumps(data,indent=2));p.chmod(0o600)
        must(free()>=40*GIB,"Reserve consumed by backup")
        final=OUT/("cold-"+uuid.uuid4().hex)
        folder.rename(final)
        return {"result":"STOPPED_CLONE_BACKUP_CAPTURED_UNRESTORED",
                "checkpoint":str(final),"files_verified":len(records),
                "clone_still_shut_off":True,"restart_performed":False,
                "restore_tested":False}
    finally:os.close(fd)
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("plan","capture"),default="plan")
    args=ap.parse_args()
    try:
        print(json.dumps(plan() if args.mode=="plan" else capture(),
                         indent=2,sort_keys=True))
    except (Stop,OSError,subprocess.TimeoutExpired,ET.ParseError) as e:
        print("BLOCKED: "+str(e),file=sys.stderr);return 2
    return 0
if __name__=="__main__":sys.exit(main())
