#!/usr/bin/env python3
"""Guarded, narrow per-clone swtpm socket AppArmor rule (Ubuntu/libvirt).

Never disables AppArmor, changes the parent profile or scans arbitrary VMs.
This follows the verified SSL-55 workaround for the master win11 swtpm socket.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

import guard_vm_backing_access as guard

LOCK = Path("/run/lock/cape-swtpm-socket-guard.lock")

class PolicyError(RuntimeError):
    pass


def expected(name: str, identifier: str) -> tuple[Path, str]:
    if not guard.SAFE_VM.fullmatch(name) or not name.startswith("win11_"):
        raise PolicyError("Guard accepts only an explicit win11_N clone name")
    suffix = name.split("win11_",1)[1]
    if not suffix.isdigit() or int(suffix) < 1 or str(int(suffix)) != suffix:
        raise PolicyError("Clone name suffix must be a positive canonical integer")
    try:
        realuuid=str(uuid.UUID(identifier))
    except (ValueError, AttributeError, TypeError) as exc:
        raise PolicyError("Malformed libvirt UUID") from exc
    path=guard.RULEDIR / ("98-cape-swtpm-"+realuuid)
    # Wildcard is permitted only for libvirt's unpredictable socket prefix.
    rule=f'  /run/libvirt/qemu/swtpm/*-{name}-swtpm.sock rw,\n'
    return path,rule


def ensure_shutdown(name: str, identifier: str) -> None:
    try:
        vm_uuid=guard.run("virsh","-c","qemu:///system","domuuid",name)
        state=guard.run("virsh","-c","qemu:///system","domstate",name)
    except guard.GuardError as exc:
        raise PolicyError(str(exc)) from exc
    if vm_uuid.lower()!=identifier.lower() or state!="shut off":
        raise PolicyError("Clone domain UUID differs or VM is not shut off")


def prepare(name: str, identifier: str, apply: bool=False) -> dict:
    path,rule=expected(name,identifier)
    ensure_shutdown(name,identifier)
    try:
        guard.ensure_supported()
    except guard.GuardError as exc:
        raise PolicyError(str(exc)) from exc
    if path.is_symlink():
        raise PolicyError("Existing policy symlink is unsafe")
    current=path.read_text() if path.exists() else None
    result={"vm":name,"policy_file":str(path),"rule":rule.strip(),
            "mode":"apply" if apply else "plan","changed":False}
    if current is not None and current != rule:
        raise PolicyError("Unexpected existing TPM policy; refusing overwrite")
    if not apply:
        result["status"]="PRESENT" if current==rule else "WOULD_CREATE"
        return result
    if os.geteuid()!=0:
        raise PolicyError("TPM policy installation requires root")
    if LOCK.is_symlink():
        raise PolicyError("Unsafe lock file symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    tmpname=None
    created=False
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        ensure_shutdown(name,identifier)
        if path.is_symlink():
            raise PolicyError("TPM policy path changed to symlink")
        if path.exists():
            if path.read_text()!=rule:
                raise PolicyError("Conflicting TPM policy appeared")
            result["status"]="ALREADY_PRESENT"
        else:
            guard.RULEDIR.mkdir(mode=0o755,parents=False,exist_ok=True)
            policy_fd,tmpname=tempfile.mkstemp(prefix=".cape-swtpm-",dir=str(guard.RULEDIR))
            os.fchmod(policy_fd,0o644)
            with os.fdopen(policy_fd,"w") as writer:
                writer.write(rule)
                writer.flush()
                os.fsync(writer.fileno())
            os.link(tmpname,path)
            created=True
            os.unlink(tmpname)
            tmpname=None
            result["status"]="INSTALLED"
            result["changed"]=True
        try:
            guard.parse_profile(identifier)
        except guard.GuardError as exc:
            if created and path.read_text()==rule:
                path.unlink()
                try:
                    guard.parse_profile(identifier)
                except guard.GuardError:
                    raise PolicyError("Policy reverted but AppArmor reload also failed") from exc
            raise PolicyError(f"AppArmor policy validation failed: {exc}") from exc
        return result
    finally:
        if tmpname is not None:
            Path(tmpname).unlink(missing_ok=True)
        os.close(fd)


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm",required=True)
    parser.add_argument("--uuid",required=True)
    parser.add_argument("--mode",choices=("plan","apply"),default="plan")
    a=parser.parse_args(argv)
    try:
        res=prepare(a.vm,a.uuid,a.mode=="apply")
        for key,value in res.items():
            print(f"{key}: {value}")
        return 0
    except (PolicyError,guard.GuardError,OSError) as exc:
        print(f"BLOCKED: {exc}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
