#!/usr/bin/env python3
"""Guarded full cold clone bundle: QCOW2, OVMF VARS and swtpm2 (OTHER host).

Modes: plan (no writes), capture (new exclusive checkpoint), verify
(read-only SHA256), restore (DESTRUCTIVE, shut-off disposable VM only).
Preserves old target files and a durable intent on restore; never
silently deletes/retries/rolls back, boots a guest or attaches a NIC.

Full restore/boot acceptance on a real separate host is STILL REQUIRED.
No action may be performed on the protected SSL-55 reference host.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

GIB=1024**3
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-command2-cold-bundle.lock")
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
FNAME=re.compile(r"[a-zA-Z0-9_.-]{1,200}\Z")
BUNDLE_NAME="command2-cold-bundle.json"
INTENT_NAME="restore-intent.json"
DONE_NAME="restore-complete.json"
MIN_RESERVE=30*GIB
MAX_MANIFEST=128*1024


class ColdBlocked(RuntimeError):
    pass


def need(ok,why):
    if not ok:
        raise ColdBlocked(why)


def read_command(*argv,timeout=120):
    try:
        proc=subprocess.run(argv,capture_output=True,text=True,
                            timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ColdBlocked("Host command unavailable or timed out: "+argv[0]) from exc
    need(proc.returncode==0,"Host command failed: "+argv[0])
    return proc.stdout.strip()


def virsh(*args):
    return read_command("virsh","-c","qemu:///system",*args)


def host_guard(approved_host):
    actual=socket.gethostname().split(".",1)[0].lower()
    need(actual not in ("cse-ssl-55","ssl-55") and
         not SENTINEL.exists() and not SENTINEL.is_symlink(),
         "SSL55_REFERENCE_ONLY: cold bundle writes prohibited")
    need(re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",approved_host or "") and
         actual==approved_host,"Wrong separately approved target host")


def safe_regular(path):
    p=Path(path)
    need(p.is_absolute() and not p.is_symlink() and p.is_file(),
         "Missing, linked or nonregular clone file")
    st=p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size>=0 and
         not (st.st_mode & 0o022),"Unsafe clone metadata")
    return st


def safe_folder(path):
    p=Path(path)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Expected existing private directory")
    st=p.stat()
    need(st.st_uid==0 and not st.st_mode & 0o022,
         "Bundle parent must be root-controlled and not writable by others")
    for item in (p,*p.parents):
        need(not item.is_symlink(),"Symlink ancestor in bundle destination")
    return p


def free_bytes(p):
    fs=os.statvfs(str(p))
    return fs.f_bavail*fs.f_frsize


def state(vm, uid):
    need(type(vm) is str and VM_RE.fullmatch(vm) is not None,
         "Only Command2 guests win11_1..16 allowed")
    need(virsh("domuuid",vm).lower()==uid and
         virsh("domstate",vm).strip()=="shut off",
         "Exact guest UUID mismatch or VM not shut off")
    root=ET.fromstring(virsh("dumpxml","--inactive",vm))
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==vm and root.findtext("uuid")==uid,
         "Unexpected clone definition")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2" and
         disks[0].find("source") is not None,
         "Expected one independent file-backed QCOW2")
    disk=Path(disks[0].find("source").get("file",""))
    nvram=Path(root.findtext("./os/nvram",""))
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0" and tpm.find("source") is None,
         "TPM 2.0 emulator backend with independent state required")
    tpm_dir=Path("/var/lib/libvirt/swtpm")/uid/"tpm2"
    need(disk.name==vm+".command2.qcow2" and
         nvram.name==vm+".command2_VARS.fd" and
         str(disk)!=str(nvram) and
         disk.is_absolute() and nvram.is_absolute(),
         "Unexpected independently named clone disk/UEFI path")
    ds=safe_regular(disk)
    vs=safe_regular(nvram)
    need(tpm_dir.is_dir() and not tpm_dir.is_symlink(),
         "Per-guest swtpm state directory missing")
    files=[]
    for item in sorted(tpm_dir.iterdir()):
        need(FNAME.fullmatch(item.name) is not None,"Invalid swtpm file name")
        st=safe_regular(item)
        files.append((item,st))
    need(any(item.name.endswith(".permall") for item,_ in files),
         "No permanent guest swtpm2 state found")
    info=json.loads(read_command("qemu-img","info","--output=json",str(disk)))
    need(info.get("format")=="qcow2" and
         not info.get("backing-filename") and
         not info.get("full-backing-filename"),
         "Guest disk has non-independent QCOW2 chain")
    return {"vm":vm,"uuid":uid,"disk":disk,"nvram":nvram,
            "swtpm_dir":tpm_dir,"tpm_files":files,
            "stamps":{str(p):(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,
                                  st.st_ctime_ns) for p,st in
                      [(disk,ds),(nvram,vs)]+files},
            "image_virtual_bytes":info.get("virtual-size")}


def sha(path):
    digest=hashlib.sha256()
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_safe(source, dest, *, identity=None):
    st=safe_regular(source)
    fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb") as out, open(source,"rb") as inp:
            shutil.copyfileobj(inp,out,4*1024*1024)
            out.flush()
            os.fsync(out.fileno())
        if identity is not None:
            os.chown(dest,identity["uid"],identity["gid"])
            os.chmod(dest,identity["mode"])
        need(safe_regular(source).st_size==st.st_size and
             os.stat(source).st_mtime_ns==st.st_mtime_ns and
             os.stat(source).st_ctime_ns==st.st_ctime_ns,
             "Source file changed during checkpoint copy")
        return {"sha256":sha(dest),"bytes":st.st_size,
                "uid":st.st_uid,"gid":st.st_gid,
                "mode":stat.S_IMODE(st.st_mode)}
    except Exception:
        # Incomplete file is retained for operator recovery (no auto delete).
        raise


def record_json_exclusive(dest,obj):
    content=(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode()
    need(len(content)<MAX_MANIFEST,"Oversized cold bundle manifest")
    fd=os.open(dest,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(content)
        out.flush()
        os.fsync(out.fileno())


def bundle_paths(guest):
    result=[("disk.qcow2",guest["disk"]),
            ("UEFI_VARS.fd",guest["nvram"])]
    for item,_ in guest["tpm_files"]:
        result.append(("swtpm/"+item.name,item))
    return result


def capture(vm,uid,host,dest):
    host_guard(host)
    need(os.geteuid()==0,"Root required for cold checkpoint")
    guest=state(vm,uid)
    parent=safe_folder(Path(dest).parent)
    need(not Path(dest).exists() and not Path(dest).is_symlink(),
         "Checkpoint already exists: no overwrite")
    need(free_bytes(parent)>=guest["image_virtual_bytes"]+MIN_RESERVE,
         "Insufficient conservative free disk for full cold checkpoint")
    temporary=parent/(".pending-command2-cold-"+vm+"-"+secrets.token_hex(6))
    temporary.mkdir(mode=0o700)
    try:
        manifest={"kind":"COMMAND2_FULL_COLD_BUNDLE_V1",
                  "vm":vm,"uuid":uid,
                  "disk":str(guest["disk"]),"nvram":str(guest["nvram"]),
                  "swtpm_dir":str(guest["swtpm_dir"]),
                  "entries":{},"source_vm_shutoff":True,
                  "capture_complete":False}
        (temporary/"swtpm").mkdir(mode=0o700)
        for rel,src in bundle_paths(guest):
            manifest["entries"][rel]=copy_safe(src,temporary/rel)
        fresh=state(vm,uid)
        need(fresh["stamps"]==guest["stamps"],
             "Guest sources changed during cold capture")
        manifest["capture_complete"]=True
        record_json_exclusive(temporary/BUNDLE_NAME,manifest)
        dfd=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        os.rename(temporary,dest)
        dfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)
        return {"result":"COMMAND2_FULL_COLD_BUNDLE_CAPTURED",
                "vm":vm,"files_captured":len(manifest["entries"]),
                "bundle":str(dest),"guest_remains_shut_off":True,
                "restore_tested":False,
                "guest_boot_after_restore_tested":False}
    except Exception as exc:
        raise ColdBlocked("Incomplete checkpoint retained at "+str(temporary)+
                          "; do not blindly retry: "+str(exc)) from exc


def verify_bundle(vm,uid,host,dest):
    host_guard(host)
    folder=Path(dest)
    safe_folder(folder)
    manifest_file=folder/BUNDLE_NAME
    safe_regular(manifest_file)
    raw=manifest_file.read_bytes()
    need(len(raw)<MAX_MANIFEST,"Manifest size unreasonable")
    manifest=json.loads(raw)
    guest=state(vm,uid)
    need(manifest.get("kind")=="COMMAND2_FULL_COLD_BUNDLE_V1" and
         manifest.get("capture_complete") is True and
         manifest.get("vm")==vm and manifest.get("uuid")==uid and
         manifest.get("disk")==str(guest["disk"]) and
         manifest.get("nvram")==str(guest["nvram"]) and
         manifest.get("swtpm_dir")==str(guest["swtpm_dir"]),
         "Full cold bundle differs from exact VM/paths")
    wanted={rel for rel,_ in bundle_paths(guest)}
    records=manifest.get("entries")
    need(type(records) is dict and set(records)==wanted,
         "Full disk+UEFI+swtpm inventory does not match")
    for rel,info in records.items():
        need(rel in wanted and type(info) is dict,
             "Unrecognized checkpoint entry")
        file=folder/rel
        st=safe_regular(file)
        need(st.st_size==info.get("bytes") and
             sha(file)==info.get("sha256"),
             "Cold checkpoint SHA256 or file length differs")
    return manifest,hashlib.sha256(raw).hexdigest()


def restore(vm,uid,host,dest,expected_manifest_sha):
    host_guard(host)
    need(os.geteuid()==0,"Root required for guarded destructive restore")
    need(sys.stdin.isatty(),"Interactive terminal required for cold restore")
    manifest,actual=verify_bundle(vm,uid,host,dest)
    need(actual==expected_manifest_sha,
         "Provided reviewed cold manifest SHA256 mismatch")
    phrase="RESTORE-COLD-DISPOSABLE-"+vm.upper()
    need(input("Type "+phrase+" to restore this approved shut-off VM: ")==phrase,
         "Operator did not approve destructive restore")
    need(not LOCK.is_symlink(),"Unsafe cold checkpoint lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe cold checkpoint lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        previous=state(vm,uid)
        manifest,again=verify_bundle(vm,uid,host,dest)
        need(again==expected_manifest_sha,"Bundle changed under lock")
        marker=Path(dest)/INTENT_NAME
        need(not marker.exists() and
             not (Path(dest)/DONE_NAME).exists(),
             "Prior restore activity requires manual review")
        nonce=secrets.token_hex(8)
        # Preflight all target artifact paths before ANY original is moved.
        targets=[(manifest["disk"],"disk.qcow2"),
                 (manifest["nvram"],"UEFI_VARS.fd"),
                 (manifest["swtpm_dir"],"swtpm")]
        for original,rel in targets:
            path=Path(original)
            need(path.exists() and not path.is_symlink(),
                 "Original disposable guest path changed")
            need(not Path(str(path)+".pre-restore-"+nonce).exists() and
                 not Path(str(path)+".restore-new-"+nonce).exists(),
                 "A pending restore artifact already exists")
        required=sum(v["bytes"] for v in manifest["entries"].values())
        need(free_bytes(previous["disk"].parent)>=required+MIN_RESERVE,
             "Not enough disk to preserve prior clone during restore")
        # Materialize all NEW candidate replacements with private metadata
        # before moving any old active guest artifact.
        disk_target=Path(manifest["disk"])
        nvram_target=Path(manifest["nvram"])
        tpm_target=Path(manifest["swtpm_dir"])
        for target,src in ((disk_target,"disk.qcow2"),
                           (nvram_target,"UEFI_VARS.fd")):
            meta=manifest["entries"][src]
            new=Path(str(target)+".restore-new-"+nonce)
            detail=copy_safe(Path(dest)/src,new,identity=meta)
            need(detail["sha256"]==meta["sha256"],
                 "Restored candidate file SHA mismatch")
        tpm_new=Path(str(tpm_target)+".restore-new-"+nonce)
        tpm_new.mkdir(mode=0o700)
        tpm_new.chown(tpm_target.stat().st_uid,tpm_target.stat().st_gid)
        for rel,meta in manifest["entries"].items():
            if rel.startswith("swtpm/"):
                info=copy_safe(Path(dest)/rel,tpm_new/rel.split("/",1)[1],identity=meta)
                need(info["sha256"]==meta["sha256"],
                     "Restored TPM candidate SHA mismatch")
        need(virsh("domstate",vm).strip()=="shut off",
             "Guest started while preparing cold restore")
        # CRASH-AWARE: any interruption preserves journal and old artifacts.
        record_json_exclusive(marker,{
            "kind":"COMMAND2_COLD_RESTORE_INTENT",
            "vm":vm,"uuid":uid,"nonce":nonce,
            "manifest_sha256":actual,
            "paths":[{"target":t,"source":s} for t,s in targets],
            "operator_review_required_on_failure":True})
        for original,_ in targets:
            original_path=Path(original)
            backup=Path(str(original_path)+".pre-restore-"+nonce)
            prepared=Path(str(original_path)+".restore-new-"+nonce)
            os.rename(original_path,backup)
            os.rename(prepared,original_path)
            dfd=os.open(original_path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(dfd)
            finally:os.close(dfd)
        record_json_exclusive(Path(dest)/DONE_NAME,{
            "kind":"COMMAND2_COLD_RESTORE_COMPLETED_AWAITING_BOOT",
            "vm":vm,"uuid":uid,"nonce":nonce,
            "retained_previous_artifacts":True,
            "boot_and_tpm_uefi_validation_needed":True})
        return {"result":"COMMAND2_COLD_GUEST_FILES_RESTORED_NOT_BOOT_VERIFIED",
                "vm":vm,"previous_files_preserved":True,
                "guest_still_shut_off":True,
                "full_boot_tpm_uefi_cape_validation":False}
    except Exception as exc:
        raise ColdBlocked("Cold restore may be PARTIAL; retained all "
                          "pre-restore assets, do not retry automatically: "+
                          str(exc)) from exc
    finally:os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","capture","verify","restore"),
                    default="plan")
    ap.add_argument("--vm",required=True)
    ap.add_argument("--uuid",required=True)
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--bundle",required=True,type=Path)
    ap.add_argument("--manifest-sha256")
    args=ap.parse_args()
    try:
        host_guard(args.approved_host)
        if args.mode=="plan":
            guest=state(args.vm,args.uuid)
            result={"result":"COMMAND2_COLD_BUNDLE_PLAN_ONLY","vm":args.vm,
                    "source_paths":[str(x) for _,x in bundle_paths(guest)],
                    "guest_shut_off":True,"host_modified":False}
        elif args.mode=="capture":
            result=capture(args.vm,args.uuid,args.approved_host,args.bundle)
        elif args.mode=="verify":
            _,dig=verify_bundle(args.vm,args.uuid,args.approved_host,args.bundle)
            result={"result":"COMMAND2_COLD_BUNDLE_SHA256_VERIFIED",
                    "manifest_sha256":dig,
                    "restore_tested":False}
        else:
            need(args.manifest_sha256 is not None,
                 "Reviewed manifest SHA256 required before restore")
            result=restore(args.vm,args.uuid,args.approved_host,args.bundle,
                           args.manifest_sha256)
        print(json.dumps(result,sort_keys=True,indent=2))
        return 0
    except (ColdBlocked,OSError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
