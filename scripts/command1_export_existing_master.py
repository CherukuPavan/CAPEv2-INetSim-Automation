#!/usr/bin/env python3
"""Command 1: preserve the ACTUAL manually configured Windows master.

Unlike recreating Windows apps/registry from notes, this captures a
portable COLD, FLATTENED image of the existing master win11's disk plus
a copy of its exact libvirt XML, UEFI NVRAM and independent swtpm state.

Plan: no writes, no lock, never boots/shuts down or reverts source.
Capture: typed approval, exclusive root-only destination, fsynced intent,
QEMU flatten from an OFFLINE source, SHA-256 all resulting artifacts.
Verify: re-hash all bundle files, no VM operations or modifications.

Bundle includes Windows software/data and TPM keys. Treat it as a
SENSITIVE PRIVATE SYSTEM BACKUP: never upload to GitHub or the chat.
This does not prove clean Windows clone boot, BitLocker portability,
licensed Windows activation on new hardware, Windows identity separation,
or CAPE-ready running snapshot/TPM rollback on a different host.
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
import xml.etree.ElementTree as ET

ROOT=Path("/run/lock/cape-command1-master-export.lock")
VM="win11"
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
MANIFEST="cape-command1-master-bundle.json"
FILES={"disk":"master-image.qcow2","xml":"master-domain.xml",
       "nvram":"master-uefi-vars.fd"}
MAX_TPM_FILES=8
MIN_AVAILABLE=30*1024**3
MAX_BUNDLE_MANIFEST=128*1024
APPROVE="EXPORT-MY-EXACT-WIN11-MASTER-COLD-PRIVATE-BUNDLE"
class MasterExportBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise MasterExportBlocked(why)

def run(*args,timeout=60):
    try:
        x=subprocess.run(args,capture_output=True,text=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise MasterExportBlocked("Read-only/export command unavailable: "+args[0]) from exc
    need(x.returncode==0 and len(x.stdout)<=512*1024,
         "Host process failed: "+args[0])
    return x.stdout.strip()

def virsh(*args):
    return run("virsh","-c","qemu:///system",*args)

def regular(path,*,owner_root=False):
    p=Path(path)
    need(p.is_absolute() and ".." not in p.parts and p.is_file() and
         not p.is_symlink(),
         "Required exact source file absent, symlinked or untrusted")
    st=p.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size>0,
         "Source artifact is not an independent nonempty regular file")
    if owner_root:
        need(st.st_uid==0 and not(st.st_mode&0o022),
             "Source must be root-owned and not writable by others")
    return st

def safe_parent(path):
    dest=Path(path)
    need(dest.is_absolute() and dest.name not in ("",".","..") and
         ".." not in dest.parts and not dest.exists() and
         not dest.is_symlink() and dest.name.startswith("cape-master-"),
         "Destination must be NEW absolute cape-master-* folder; never overwrite")
    parent=dest.parent
    need(parent.is_dir() and not parent.is_symlink(),
         "Master export destination parent missing")
    for p in (parent,*parent.parents):
        need(not p.is_symlink(),"Destination directory has symlink ancestor")
    st=parent.stat()
    need(st.st_uid==0 and not(st.st_mode&0o022),
         "Destination parent must be root-owned non-group/world-writable")
    return dest

def backing_chain(disk):
    """Admit every resolved master backing layer, not just active top."""
    rows=json.loads(run("qemu-img","info","--backing-chain",
                        "--output=json",str(disk),timeout=90))
    need(type(rows) is list and 1<=len(rows)<=16,
         "Missing/overlong master QCOW2 backing chain")
    paths=[]
    for i,row in enumerate(rows):
        need(type(row) is dict and row.get("format")=="qcow2" and
             type(row.get("filename")) is str,
             "Backing chain has unexpected non-QCOW2 layer")
        path=Path(row["filename"])
        regular(path)
        paths.append(path)
        if i<len(rows)-1:
            back=row.get("full-backing-filename")
            need(type(back) is str and Path(back)==Path(rows[i+1]["filename"]),
                 "Backing chain links do not identify the next checked layer")
    need(paths[0]==disk and len({str(x) for x in paths})==len(paths),
         "Original master disk top/chain mismatch or cycle")
    cap=rows[0].get("virtual-size")
    need(type(cap) is int and 8*1024**3<=cap<=512*1024**3,
         "Master virtual disk capacity implausible")
    return paths,cap

def source():
    need(os.geteuid()==0,"Root required for master source and TPM checks")
    need(virsh("domstate",VM).strip().lower()=="shut off",
         "Protected source win11 must be SHUT OFF (no automatic shutdown)")
    master_uuid=virsh("domuuid",VM).strip().lower()
    need(re.fullmatch(r"[a-f0-9-]{36}",master_uuid) is not None,
         "Master libvirt UUID missing")
    # SSL55 is permitted to EXPORT only the approved master. Existing
    # win11_1, trial, snapshots, libvirt networks and power are untouched.
    if socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55":
        need(master_uuid=="289d89be-68ec-4c62-90e1-ea930849266f",
             "SSL55 protected master identity mismatch")
    raw=virsh("dumpxml","--inactive",VM)
    root=ET.fromstring(raw)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and
         root.findtext("uuid")==master_uuid,
         "Source domain identity changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2" and
         disks[0].find("source") is not None,
         "Master requires exactly one file-backed QCOW2 Windows OS disk")
    disk=Path(disks[0].find("source").get("file",""))
    regular(disk)
    chain,virtual_size=backing_chain(disk)
    firmware=root.find("./os/nvram")
    need(firmware is not None and (firmware.text or "").strip(),
         "Exact UEFI NVRAM missing")
    nv=Path((firmware.text or "").strip())
    regular(nv)
    backend=root.find("./devices/tpm/backend")
    need(backend is not None and backend.get("type")=="emulator" and
         backend.get("version")=="2.0",
         "Actual master TPM2 emulator missing: cannot promise full state copy")
    state=Path("/var/lib/libvirt/swtpm")/master_uuid/"tpm2"
    need(state.is_dir() and not state.is_symlink() and
         not (state.stat().st_mode&0o002),
         "Original swtpm private state dir missing/untrusted")
    entries=sorted(state.iterdir())
    need(1<=len(entries)<=MAX_TPM_FILES and
         "tpm2-00.permall" in {p.name for p in entries},
         "Expected bounded TPM state members and permanent blob")
    for e in entries:
        need(re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}",e.name) is not None,
             "Unexpected TPM state file name")
        regular(e)
        need(e.stat().st_size<=32*1024*1024,
             "Unexpected large TPM state blob")
    # Refuse live domain using the exact current master disk/NVRAM.
    live=[n.strip() for n in virsh("list","--name").splitlines() if n.strip()]
    need(VM not in live,"Master unexpectedly running")
    for name in live:
        other=ET.fromstring(virsh("dumpxml",name))
        other_disk=[x.get("file") for x in
                    other.findall("./devices/disk/source") if x.get("file")]
        other_nv=other.findtext("./os/nvram")
        need(str(disk) not in other_disk and str(nv)!=other_nv,
             "Another RUNNING VM shares the master's exact source disk/NVRAM")
    return {"vm":VM,"uuid":master_uuid,"domain_xml":raw,
            "source_disk":disk,"source_nvram":nv,
            "tpm_members":entries,"tpm_dir":state,
            "backing_chain":chain,"virtual_size":virtual_size,
            "master_shut_off":True,
            "active_source_snapshot_revert_performed":False}

def stamp(items):
    return {str(p):(p.stat().st_dev,p.stat().st_ino,p.stat().st_size,
                    p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in items}

def sha(path):
    h=hashlib.sha256()
    with open(path,"rb",buffering=1024*1024) as f:
        while piece:=f.read(4*1024*1024):
            h.update(piece)
    return h.hexdigest()

def write_exclusive(path,data):
    f=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(f,"wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def copy_exclusive(source_path,target):
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as out,open(source_path,"rb") as inp:
        shutil.copyfileobj(inp,out,4*1024*1024)
        out.flush()
        os.fsync(out.fileno())

def capture_intent_check(root, manifest):
    """Validate even the root-private transfer-intent metadata as a member.

    Older v1 exports lack the optional SHA binding. They remain readable
    but do NOT qualify for the new all-member-bytes-verified claim.
    """
    f = root / "capture-intent.json"
    regular(f, owner_root=True)
    need(f.stat().st_size <= 65536, "Oversized private capture intent")
    try:
        obj = json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MasterExportBlocked("Invalid cold-master capture intent") from exc
    need(type(obj) is dict and
         obj.get("schema") == "cape-command1-intent-v1" and
         obj.get("master_uuid") == manifest.get("master_uuid") and
         obj.get("state") == "COPY_IN_PROGRESS" and
         obj.get("never_auto_retry") is True and
         set(obj) == {"schema", "master_uuid", "state",
                      "never_auto_retry"},
         "Cold-master capture intent differs from exact source identity")
    expected = manifest.get("capture_intent_sha256")
    if expected is None:
        return False  # historic v1: structurally checked, not SHA bound
    need(type(expected) is str and
         re.fullmatch(r"[a-f0-9]{64}", expected) is not None and
         sha(f) == expected,
         "Master capture-intent metadata is not SHA256 verified")
    return True


def manifest_check(folder):
    root=Path(folder)
    need(root.is_dir() and not root.is_symlink(),
         "Exact private bundle folder missing")
    st=root.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "Sensitive Windows bundle directory must be root 0700")
    mf=root/MANIFEST
    regular(mf,owner_root=True)
    need(mf.stat().st_size<=MAX_BUNDLE_MANIFEST,
         "Bundle manifest oversized")
    obj=json.loads(mf.read_text(encoding="utf-8"))
    need(obj.get("schema")=="cape-command1-master-bundle-v1" and
         obj.get("master")=="win11" and
         obj.get("guest_was_shut_off") is True,
         "Unrecognized/master-not-cold manifest")
    table=obj.get("artifacts")
    need(type(table) is dict and
         set(table)=={"disk","xml","nvram","tpm"} and
         type(table["tpm"]) is dict and
         1<=len(table["tpm"])<=MAX_TPM_FILES,
         "Bundle artifact inventory inconsistent")
    members={"disk":(FILES["disk"],table["disk"]),
             "xml":(FILES["xml"],table["xml"]),
             "nvram":(FILES["nvram"],table["nvram"])}
    for name,row in table["tpm"].items():
        need(re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}",name) is not None,
             "Untrusted TPM path")
        members["tpm/"+name]=("tpm-"+name,row)
    for name,(leaf,entry) in members.items():
        need(type(entry) is dict and
             re.fullmatch(r"[0-9a-f]{64}",entry.get("sha256","")) is not None and
             type(entry.get("bytes")) is int and entry["bytes"]>0,
             "Manifest checksum or length missing: "+name)
        p=root/leaf
        regular(p,owner_root=True)
        need(p.stat().st_size==entry["bytes"] and
             sha(p)==entry["sha256"],
             "MASTER BUNDLE CORRUPTION or copy mismatch: "+name)
    expected=set(x[0] for x in members.values())|{MANIFEST,"capture-intent.json"}
    need({p.name for p in root.iterdir()}==expected,
         "Unexpected payload in master export folder")
    intent_sha_bound = capture_intent_check(root, obj)
    # Bundle verification is structural; guest contents are opaque bytes.
    return {"result":"COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED",
            "capture_intent_sha256_verified": intent_sha_bound,
            "all_member_files_sha256_verified": intent_sha_bound,
            "manifest_sha256":sha(mf),
            "master_uuid":obj["master_uuid"],
            "windows_volume_bytes":table["disk"]["bytes"],
            "artifact_count":len(members),
            "master_windows_customizations_copied_in_disk":True,
            "master_swtpm_secrets_in_private_bundle":True,
            "auto_windows_clone_identity_or_tpm_revert_proven":False,
            "one_command_fresh_host_install_proven":False,
            "ready_to_transfer_privately":True,
            "host_vm_or_network_modified":False}

def capture(dest):
    need(sys.stdin.isatty(),"Direct operator terminal required")
    initial=source()
    dest=safe_parent(dest)
    free=shutil.disk_usage(dest.parent).free
    need(free>=initial["virtual_size"]+MIN_AVAILABLE,
         "Insufficient storage for conservative Windows image export + reserve")
    printed={k:str(v) if isinstance(v,Path) else v for k,v in initial.items()
             if k in ("vm","uuid","source_disk","source_nvram",
                      "virtual_size","master_shut_off")}
    printed["private_destination"]=str(dest)
    printed["will_copy_sensitive_master_tpm_and_windows_state"]=True
    print(json.dumps(printed,indent=2,sort_keys=True),flush=True)
    need(input("Type "+APPROVE+" to export a PRIVATE cold master: ")==APPROVE,
         "Explicit cold master image export approval missing")
    need(not ROOT.is_symlink(),"Unsafe export lock")
    fd=os.open(ROOT,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        info=os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and
             stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
             "Untrusted source export lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MasterExportBlocked("Another master export in progress") from exc
        current=source()
        need(current["domain_xml"]==initial["domain_xml"] and
             current["uuid"]==initial["uuid"] and
             current["source_disk"]==initial["source_disk"] and
             current.get("backing_chain")==initial.get("backing_chain"),
             "Master storage chain changed after approved export plan")
        sources=[*current.get("backing_chain",[current["source_disk"]]),
                 current["source_nvram"],*current["tpm_members"]]
        before=stamp(sources)
        dest.mkdir(mode=0o700)
        attempted=True
        write_exclusive(dest/"capture-intent.json",
              (json.dumps({"schema":"cape-command1-intent-v1",
               "master_uuid":current["uuid"],"state":"COPY_IN_PROGRESS",
               "never_auto_retry":True},sort_keys=True)+"\n").encode())
        run("qemu-img","convert","-p","-f","qcow2","-O","qcow2",
            "-o","compat=1.1",str(current["source_disk"]),
            str(dest/FILES["disk"]),timeout=7200)
        os.chmod(dest/FILES["disk"],0o600)
        run("qemu-img","check","-q","-f","qcow2",
            str(dest/FILES["disk"]),timeout=3600)
        meta=json.loads(run("qemu-img","info","--output=json",
                           str(dest/FILES["disk"])))
        need(meta.get("format")=="qcow2" and
             meta.get("virtual-size")==current["virtual_size"] and
             not meta.get("backing-filename"),
             "Source disk export did not flatten into standalone QCOW2")
        write_exclusive(dest/FILES["xml"],current["domain_xml"].encode())
        copy_exclusive(current["source_nvram"],dest/FILES["nvram"])
        for state in current["tpm_members"]:
            copy_exclusive(state,dest/("tpm-"+state.name))
        need(source()["domain_xml"]==current["domain_xml"] and
             stamp(sources)==before,
             "Master changed during export; preserve incomplete output")
        table={}
        for key in ("disk","xml","nvram"):
            path=dest/FILES[key]
            table[key]={"bytes":path.stat().st_size,"sha256":sha(path)}
        table["tpm"]={}
        for member in current["tpm_members"]:
            path=dest/("tpm-"+member.name)
            table["tpm"][member.name]={
                "bytes":path.stat().st_size,"sha256":sha(path)}
        content={"schema":"cape-command1-master-bundle-v1",
                "master":VM,"master_uuid":current["uuid"],
                "guest_was_shut_off":True,
                "source_uefi_format":(
                  ET.fromstring(current["domain_xml"]).find(
                     "./os/nvram").get("format","raw")),
                "qcow2_flattened":True,
                "master_tpm_state_must_not_be_reused_across_clones":True,
                "source_master_boot_or_snapshot_revert_attempted":False,
                "guest_apps_registry_and_original_windows_files_preserved":True,
                "capture_intent_sha256":sha(dest/"capture-intent.json"),
                "artifacts":table}
        write_exclusive(dest/MANIFEST,
                 (json.dumps(content,sort_keys=True,indent=2)+"\n").encode())
        dirfd=os.open(dest,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        return manifest_check(dest)
    except Exception as exc:
        if attempted:
            raise MasterExportBlocked(
               "MASTER_COPY_STARTED_PRESERVE_INCOMPLETE_PRIVATE_EXPORT; "
               "never auto delete or retry: "+str(exc)) from exc
        raise
    finally:os.close(fd)

def plan(dest):
    info=source()
    path=safe_parent(dest)
    free=shutil.disk_usage(path.parent).free
    need(free>=info["virtual_size"]+MIN_AVAILABLE,
         "Insufficient shared storage for cold master export")
    return {"result":"COMMAND1_ACTUAL_MASTER_EXPORT_PLAN_ONLY",
            "master":"win11","master_uuid":info["uuid"],
            "source_disk":str(info["source_disk"]),
            "source_uefi":str(info["source_nvram"]),
            "master_source_disk_virtual_bytes":info["virtual_size"],
            "source_tpm_member_count":len(info["tpm_members"]),
            "destination":str(path),
            "available_bytes":free,
            "master_must_remain_shut_off":True,
            "installed_windows_apps_and_settings_come_from_image":True,
            "none_of_windows_settings_needs_to_be_relisted":True,
            "guest_machine_tpm_depersonalization_still_needed":True,
            "host_vm_files_or_services_modified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","capture","verify"),default="plan")
    p.add_argument("--destination",type=Path,required=True)
    a=p.parse_args()
    try:
        result=(manifest_check(a.destination) if a.mode=="verify" else
                capture(a.destination) if a.mode=="capture" else
                plan(a.destination))
        print(json.dumps(result,indent=2,sort_keys=True),flush=True)
        return 0
    except (MasterExportBlocked,OSError,ValueError,KeyError,TypeError,
            ET.ParseError,json.JSONDecodeError) as exc:
        print(json.dumps({"result":"COMMAND1_MASTER_BUNDLE_BLOCKED",
               "reason":str(exc),
               "master_vm_shutoff_revert_snapshot_or_network_not_requested":True,
               "private_output_may_need_manual_review_if_capture_started":True},
               sort_keys=True),file=sys.stderr,flush=True)
        return 2
if __name__=="__main__":raise SystemExit(main())
