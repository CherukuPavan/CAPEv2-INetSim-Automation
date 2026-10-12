#!/usr/bin/env python3
"""Guarded RAW -> QCOW2 OVMF variables sidecar on OTHER disposable host.

Strictly never changes VM definition/power, originals, swtpm, disk, network,
snapshot metadata or CAPE. Produces ONLY an exclusive, separately reviewed
QCOW2 sidecar alongside RAW NVRAM; operator-approved --mode prepare.

The sidecar is NOT active automatically, and DOES NOT prove TPM snapshots.
A separately approved configuration transition is required only after a
physical full cold-backup restore has been demonstrated on disposable VM.
"""
from __future__ import annotations
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
import xml.etree.ElementTree as ET

import command2_snapshot_recovery_preflight as cold

GIB=1024**3
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
HOST_EXCLUDED={"cse-ssl-55","ssl-55"}
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-command2-nvram-conversion.lock")
RESERVE_BYTES=40*GIB

class ConversionBlocked(RuntimeError): pass
def need(ok,msg):
    if not ok:raise ConversionBlocked(msg)
def execute(*args,timeout=60):
    try:
        r=subprocess.run(args,check=False,capture_output=True,
                         text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise ConversionBlocked("Command unavailable/timed out: "+args[0]) from e
    need(r.returncode==0,"Command exited nonzero: "+args[0])
    return r.stdout.strip()
def virsh(*args):
    return execute("virsh","-c","qemu:///system",*args)
def hostname_guard(host):
    current=socket.gethostname().split(".",1)[0].lower()
    need(current not in HOST_EXCLUDED and
         not SENTINEL.exists() and not SENTINEL.is_symlink(),
         "SSL55 protected host: firmware preparation forbidden")
    need(type(host) is str and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}",host) and
         host==current,"Approved separate-host identity differs")
    need(os.geteuid()==0,"Root permission required")

def filemeta(p):
    p=Path(p)
    need(p.is_absolute() and p.is_file() and not p.is_symlink(),
         "Expected regular non-symlinked NVRAM source missing")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size>0,
         "Unexpected shared/empty NVRAM source")
    return s

def sha256(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as fd:
        for chunk in iter(lambda:fd.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def plan(host,vm,uuid,bundle,manifest_sha):
    hostname_guard(host)
    need(type(vm) is str and VM_RE.fullmatch(vm) is not None,
         "Expected disposable Command2 VM name")
    need(type(uuid) is str and cold.UUID.fullmatch(uuid) is not None,
         "VM UUID is invalid")
    need(virsh("domuuid",vm).lower()==uuid and
         virsh("domstate",vm).lower()=="shut off",
         "Disposable VM must be shut off with exact UUID")
    need(not virsh("snapshot-list",vm,"--name").strip(),
         "Unexpected existing libvirt snapshot")
    saved=ET.fromstring(virsh("dumpxml","--inactive",vm))
    need(saved.tag=="domain" and saved.findtext("name")==vm and
         saved.findtext("uuid")==uuid,"Saved VM XML identity changed")
    fw=saved.find("./os/loader")
    nv=saved.find("./os/nvram")
    need(fw is not None and fw.get("type")=="pflash" and
         nv is not None and nv.text is not None and
         nv.get("format","raw")=="raw",
         "Only existing raw pflash variables can be staged")
    t=saved.find("./devices/tpm/backend")
    need(t is not None and t.get("type")=="emulator" and
         t.get("version")=="2.0","Windows TPM2 not present")
    disk=saved.findall("./devices/disk[@device='disk']")
    need(len(disk)==1 and disk[0].find("source") is not None and
         disk[0].find("source").get("file","").endswith(
             "/"+vm+".command2.qcow2"),"Unexpected independent OS disk")
    original=Path(nv.text)
    need(original.name==vm+".command2_VARS.fd",
         "Expected exact independent guest OVMF file name")
    metadata=filemeta(original)
    need(metadata.st_size<16*1024*1024,"Unexpected NVRAM source size")
    dest=Path(str(original)+".qcow2")
    need(not dest.exists() and not dest.is_symlink(),
         "Preexisting destination: no overwrite or retry")
    need(original.parent.is_dir() and not original.parent.is_symlink(),
         "Unexpected NVRAM directory")
    sourceinfo=json.loads(execute("qemu-img","info","--output=json",str(original)))
    need(sourceinfo.get("format")=="raw","Existing NVRAM is not RAW on disk")
    proof=cold.inspect(vm,uuid,bundle,manifest_sha)
    free=os.statvfs(original.parent)
    need(free.f_bavail*free.f_frsize >
         RESERVE_BYTES+2*GIB,"Host cannot maintain shared-space reserve")
    return {
      "result":"COMMAND2_OVMF_QCOW2_SIDECAR_PLAN_ONLY",
      "vm":vm,"uuid":uuid,"approved_host":host,
      "original_nvram":str(original),"original_nvram_sha256":sha256(original),
      "original_nvram_bytes":metadata.st_size,
      "proposed_sidecar":str(dest),
      "recovery_manifest_sha256":proof["manifest_sha256"],
      "recovery_bundle_sha256_all_members_verified":True,
      "cold_restore_physically_witnessed":False,
      "original_nvram_modified":False,
      "guest_vm_xml_modified":False,
      "guest_booted":False,"running_snapshot_created":False,
      "swtpm_restoration_tested":False,
    }

def prepare(host,vm,uuid,bundle,manifest_sha):
    need(sys.stdin.isatty(),"Direct operator terminal required")
    baseline=plan(host,vm,uuid,bundle,manifest_sha)
    print(json.dumps(baseline,indent=2,sort_keys=True),flush=True)
    phrase="PREPARE-DISPOSABLE-QCOW2-NVRAM-"+vm.upper()
    need(input("Type "+phrase+" to create *only* an additional QCOW2 file: ")==phrase,
         "Operator approval absent")
    need(not LOCK.is_symlink(),"Unsafe existing serialization lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(st.st_uid==0 and stat.S_ISREG(st.st_mode) and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe NVRAM staging lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(plan(host,vm,uuid,bundle,manifest_sha)==baseline,
             "VM identity, recovery bundle or NVRAM changed before staging")
        dest=Path(baseline["proposed_sidecar"])
        original=Path(baseline["original_nvram"])
        try:
            # Temporary file name ends in qcow2 and remains PRIVATE.
            candidate=dest.with_name(dest.name+".pending")
            need(not candidate.exists() and not candidate.is_symlink(),
                 "Unreviewed pending firmware file exists")
            # qemu-img convert -n requires destination pre-created, which
            # is unnecessary. -O writes an entirely distinct new sidecar.
            execute("qemu-img","convert","-f","raw","-O","qcow2",
                    str(original),str(candidate),timeout=180)
            need(candidate.is_file() and not candidate.is_symlink(),
                 "Converted firmware sidecar missing")
            os.chown(candidate,original.stat().st_uid,original.stat().st_gid)
            os.chmod(candidate,0o600)
            execute("qemu-img","check","-f","qcow2",str(candidate))
            execute("qemu-img","compare","-f","raw","-F","qcow2",
                    str(original),str(candidate),timeout=180)
            meta=json.loads(execute("qemu-img","info","--output=json",
                                    str(candidate)))
            need(meta.get("format")=="qcow2" and
                 meta.get("virtual-size")==baseline["original_nvram_bytes"],
                 "QCOW2 conversion size mismatch")
            need(sha256(original)==baseline["original_nvram_sha256"],
                 "Original guest NVRAM changed during conversion")
            os.link(candidate,dest,follow_symlinks=False)
            candidate.unlink()
        except (OSError,ConversionBlocked):
            raise ConversionBlocked(
                "Conversion did not complete; examine any .pending file, "
                "no automatic cleanup or retry, VM left shut off")
        return {"result":"COMMAND2_DISPOSABLE_OVMF_QCOW2_SIDECAR_CREATED_NOT_ACTIVE",
                "vm":vm,"original_nvram_unchanged":True,
                "sidecar":str(dest),"sidecar_sha256":sha256(dest),
                "sidecar_active_in_vm_xml":False,
                "guest_power_modified":False,
                "firmware_tpm_rollback_verified":False}
    finally:
        os.close(fd)
        # Deliberately keep lock filename as evidence; subsequent operator
        # work must inspect both outputs rather than blindly re-run.

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("plan","prepare"),default="plan")
    parser.add_argument("--approved-host",required=True)
    parser.add_argument("--vm",required=True)
    parser.add_argument("--uuid",required=True)
    parser.add_argument("--recovery-bundle",type=Path,required=True)
    parser.add_argument("--reviewed-manifest-sha",required=True)
    args=parser.parse_args()
    try:
        result=plan(args.approved_host,args.vm,args.uuid,
                    args.recovery_bundle,args.reviewed_manifest_sha) if args.mode=="plan" else prepare(
                    args.approved_host,args.vm,args.uuid,
                    args.recovery_bundle,args.reviewed_manifest_sha)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (ConversionBlocked,cold.RecoveryBlocked,ValueError,
            OSError,TypeError,ET.ParseError) as e:
        print(json.dumps({"result":"COMMAND2_OVMF_SIDE_CAR_BLOCKED",
                          "reason":str(e),
                          "vm_definition_or_power_not_changed":True},indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
