#!/usr/bin/env python3
"""Command 1 OTHER-HOST golden-master import, preserving Windows customizations.

Consumes the private SHA-verified COLD bundle from the ACTUAL manually
configured win11 master. On a separately approved host, stages a
flattened OS disk (all files/apps/settings), separate OVMF vars and
the SAME MASTER's swtpm state. Never reuses master swtpm state for
additional cloned win11_N VMs. Does not install packages, start Windows,
run guest code, revert snapshots or make a CAPE-ready assertion.

Use plan before stage; stage requires typed consent. Master state is
SHUT OFF after definition; a real supported-host boot and guest TPM
acceptance test is still necessary. TPM owner is explicitly provided
and must match the target host's swtpm service user. Host CPU/OVMF,
license and BitLocker portability cannot be inferred from a QCOW2 hash.
"""
from __future__ import annotations
import argparse
import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command1_export_existing_master as golden

LOCK=Path("/run/lock/cape-command1-master-import.lock")
TPM_ROOT=Path("/var/lib/libvirt/swtpm")
INTENT="command1-master-import-intent.json"
MASTER="win11"
class ImportBlocked(RuntimeError):pass
def need(x,why):
    if not x:raise ImportBlocked(why)

def virsh(*args,timeout=90):
    try:
        p=subprocess.run(["virsh","-c","qemu:///system",*args],
            capture_output=True,text=True,check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ImportBlocked("libvirt query/define unavailable") from exc
    need(p.returncode==0 and len(p.stdout)<512*1024,
         "libvirt query/define refused: "+args[0])
    return p.stdout.strip()

def require_host(approved_host):
    hostname=socket.gethostname().split(".",1)[0].lower()
    need(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,62}",approved_host or "")
         is not None and hostname==approved_host and
         hostname not in ("cse-ssl-55","ssl-55") and
         not golden.SENTINEL.exists() and
         not golden.SENTINEL.is_symlink(),
         "Import only on explicitly approved NEW host, not SSL55 reference")
    need(os.geteuid()==0,"Root required to import original Windows/TPM")
    return hostname

def approved_target(path):
    x=Path(path)
    need(x.is_absolute() and ".." not in x.parts and
         x.parent.is_dir() and not x.parent.is_symlink() and
         not x.exists() and not x.is_symlink(),
         "Exact master image target must be NEW absolute non-symlink")
    for p in (x.parent,*x.parent.parents):
        need(not p.is_symlink(),"Master image directory has symlink ancestor")
    st=x.parent.stat()
    need(st.st_uid==0 and not(st.st_mode&0o022),
         "Master image parent must be root-owned, non-group/world writable")
    return x

def prepare_xml(bundle,os_disk,vars_path):
    data=(Path(bundle)/golden.FILES["xml"]).read_text(encoding="utf-8")
    root=ET.fromstring(data)
    source=ET.fromstring(data)
    manifest=json.loads((Path(bundle)/golden.MANIFEST).read_text())
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==MASTER and
         root.findtext("uuid")==manifest["master_uuid"],
         "Bundle master XML name/UUID changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file",
         "Exactly one master OS disk expected")
    source_disk=disks[0].find("source")
    driver=disks[0].find("driver")
    need(source_disk is not None and driver is not None and
         driver.get("type")=="qcow2",
         "Master QCOW2 reference not available")
    source_disk.set("file",str(os_disk))
    nvram=root.find("./os/nvram")
    need(nvram is not None and (nvram.text or "").strip() and
         nvram.get("format","raw")==manifest["source_uefi_format"],
         "Bundled UEFI format/XML changed")
    nvram.text=str(vars_path)
    loader=root.find("./os/loader")
    need(loader is not None and (loader.text or "").strip() and
         Path(loader.text.strip()).is_file(),
         "Target host lacks the exact OVMF CODE firmware path; install "
         "compatible firmware before import")
    back=root.find("./devices/tpm/backend")
    need(back is not None and back.get("type")=="emulator" and
         back.get("version")=="2.0",
         "Source TPM2 definition absent")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="default" and
         nics[0].find("model") is not None and
         nics[0].find("model").get("type")=="e1000e",
         "Master network must match default NAT e1000e reference")
    for tag in ("hostdev","filesystem","redirdev","shmem","vsock"):
        need(not root.findall("./devices/"+tag),
             "Unreviewed direct host passthrough device: "+tag)
    # Source XML is a template for same master identity. New win11_N
    # clones use distinct UUID/TPM and NIC via Command2, not this XML.
    return ET.tostring(root,encoding="unicode"),manifest

def check(host,bundle,os_disk,vars_path,tpm_user,*,staged=False):
    require_host(host)
    proof=golden.manifest_check(bundle)
    need(proof["result"]=="COMMAND1_COLD_MASTER_BUNDLE_BYTE_VERIFIED",
         "Original golden-master byte manifest cannot be verified")
    members=json.loads((Path(bundle)/golden.MANIFEST).read_text())
    uid=members["master_uuid"]
    need(re.fullmatch(r"[a-f0-9-]{36}",uid) is not None,
         "Master UUID not canonical")
    owned=approved_target if not staged else Path
    os_disk=owned(os_disk)
    vars_path=owned(vars_path)
    if staged:
        golden.regular(os_disk)
        golden.regular(vars_path)
        need(golden.sha(os_disk)==members["artifacts"]["disk"]["sha256"] and
             golden.sha(vars_path)==members["artifacts"]["nvram"]["sha256"],
             "Imported master disk or UEFI copy differs from original bundle")
    else:
        need(os_disk.parent!=vars_path.parent or os_disk!=vars_path,
             "Master disk/NVRAM destination overlaps")
    need(not os.path.samefile(bundle,os_disk.parent)
         if os.path.exists(os_disk.parent) else True,
         "Original master bundle must not be overwritten")
    tpm_root=TPM_ROOT
    need(tpm_root.is_dir() and not tpm_root.is_symlink(),
         "Target swtpm service state root missing")
    dest_tpm=tpm_root/uid/"tpm2"
    if not staged:
        need(not dest_tpm.exists() and not dest_tpm.is_symlink() and
             not dest_tpm.parent.exists(),
             "Target master TPM state already exists; cannot overwrite")
    else:
        need(dest_tpm.is_dir() and not dest_tpm.is_symlink() and
             sorted(p.name for p in dest_tpm.iterdir())==
             sorted(members["artifacts"]["tpm"]),
             "Imported master TPM state layout differs from manifest")
        for leaf,entry in members["artifacts"]["tpm"].items():
            path=dest_tpm/leaf
            golden.regular(path)
            need(path.stat().st_size==entry["bytes"] and
                 golden.sha(path)==entry["sha256"],
                 "Imported master TPM blob mismatches original master bundle")
    try:
        pw=pwd.getpwnam(tpm_user)
        owner=(pw.pw_uid,pw.pw_gid)
    except KeyError as exc:
        raise ImportBlocked("Explicit target swtpm user does not exist") from exc
    data,meta=prepare_xml(bundle,os_disk,vars_path)
    need(virsh("list","--all","--name").splitlines().count("win11")==
         (1 if staged else 0),
         "Existing win11 master domain collision or duplicate")
    if staged:
        need(virsh("domuuid",MASTER).lower()==uid and
             virsh("domstate",MASTER).lower()=="shut off",
             "Imported master UUID/state not correct")
        x=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
        d=x.find("./devices/disk[@device='disk']/source")
        nv=x.find("./os/nvram")
        need(d is not None and d.get("file")==str(os_disk) and
             nv is not None and nv.text==str(vars_path),
             "Installed domain XML disk/NVRAM not the reviewed bundle")
    else:
        # Source MAC may be in use by an existing OTHER domain.
        source=ET.fromstring(data)
        source_mac=source.find("./devices/interface/mac")
        need(source_mac is not None,
             "No master e1000e MAC in source XML")
        for vm in (x.strip() for x in
                   virsh("list","--all","--name").splitlines() if x.strip()):
            root=ET.fromstring(virsh("dumpxml","--inactive",vm))
            need(all((m.get("address") or "").lower()!=
                     source_mac.get("address","").lower()
                     for m in root.findall("./devices/interface/mac")),
                 "Existing domain reuses source master MAC")
        fs=os.statvfs(os_disk.parent)
        need(fs.f_bavail*fs.f_frsize>=
             meta["artifacts"]["disk"]["bytes"]+40*1024**3,
             "Not enough target storage for exact master +40GiB reserve")
    return {"result":("COMMAND1_IMPORTED_EXACT_MASTER_SHUTOFF_VERIFIED"
                       if staged else "COMMAND1_EXACT_MASTER_IMPORT_PLAN_ONLY"),
        "host":host,"master":"win11","master_uuid":uid,
        "from_verified_actual_master_bundle":True,
        "source_windows_apps_and_registry_preserved":True,
        "disk_target":str(os_disk),"uefi_target":str(vars_path),
        "tpm_state_target":str(dest_tpm),
        "tpm_service_account":tpm_user,
        "target_tpm_service_uid_gid":list(owner),
        "guest_imported_and_off":staged,
        "guest_boot_verified":False,
        "license_bitlocker_ovmf_compatibility_proven":False,
        "final_running_master_snapshot_created":False,
        "not_a_copy_of_swtpm_state_for_clones":True,
        "CAPE_READY":False,"Command1_finished":False}

def apply(host,bundle,os_disk,vars_path,tpm_user):
    need(sys.stdin.isatty(),"Direct operator TTY required")
    before=check(host,bundle,os_disk,vars_path,tpm_user)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    phrase="IMPORT-EXACT-COLD-WIN11-MASTER-ON-NEW-HOST-ONLY"
    need(input("Type "+phrase+" to stage original master: ")==phrase,
         "Operator did not authorize sensitive full master import")
    need(not LOCK.is_symlink(),"Untrusted master import lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    mutated=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Untrusted master import root lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ImportBlocked("Other master import running") from exc
        need(check(host,bundle,os_disk,vars_path,tpm_user)==before,
             "Import bundle/NVRAM/target state changed after approval")
        os_disk=Path(os_disk)
        vars_path=Path(vars_path)
        private=TPM_ROOT/before["master_uuid"]
        tpm=private/"tpm2"
        mutated=True
        # Intent is a non-overwritten witness. No automatic undo/retry.
        intent=os_disk.parent/(".command1-import-"+before["master_uuid"]+".json")
        golden.write_exclusive(intent,
              (json.dumps({"intent":"COMMAND1_IMPORT_STARTED",
               "bundle":str(bundle),"master":before["master_uuid"],
               "never_autoretry":True},sort_keys=True)+"\n").encode())
        with tempfile.NamedTemporaryFile(dir=os_disk.parent,
             prefix=".command1-master-unfinished-",delete=False) as temp:
            temporary=Path(temp.name)
        os.chmod(temporary,0o600)
        # The golden source image is ALREADY independently flattened.
        # Re-encoding QCOW2 with qemu-img convert would change its byte
        # SHA despite preserving virtual sectors. Copy exact verified
        # bytes instead, then check QCOW2 structural integrity.
        with open(Path(bundle)/golden.FILES["disk"],"rb") as inp,\
             open(temporary,"wb") as out:
            shutil.copyfileobj(inp,out,4*1024*1024)
            out.flush()
            os.fsync(out.fileno())
        golden.run("qemu-img","check","-q","-f","qcow2",
                   str(temporary),timeout=3600)
        need(golden.sha(temporary)==
             json.loads((Path(bundle)/golden.MANIFEST).read_text())
                ["artifacts"]["disk"]["sha256"],
             "Master disk import content differs after QEMU conversion")
        os.link(temporary,os_disk)
        os.unlink(temporary)
        golden.copy_exclusive(Path(bundle)/golden.FILES["nvram"],vars_path)
        private.mkdir(mode=0o700)
        tpm.mkdir(mode=0o700)
        user=pwd.getpwnam(tpm_user)
        os.chown(private,user.pw_uid,user.pw_gid)
        os.chown(tpm,user.pw_uid,user.pw_gid)
        for member in json.loads((Path(bundle)/golden.MANIFEST).read_text()
                  )["artifacts"]["tpm"]:
            target=tpm/member
            golden.copy_exclusive(Path(bundle)/("tpm-"+member),target)
            os.chown(target,user.pw_uid,user.pw_gid)
            os.chmod(target,0o600)
        xml,_=prepare_xml(bundle,os_disk,vars_path)
        with tempfile.TemporaryDirectory(prefix=".command1-libvirt-",
                                          dir="/run") as temporary_xml:
            path=Path(temporary_xml)/"master.xml"
            golden.write_exclusive(path,xml.encode())
            virsh("define",str(path),"--validate",timeout=120)
        return {**check(host,bundle,os_disk,vars_path,tpm_user,staged=True),
                "result":"COMMAND1_ACTUAL_MASTER_IMPORT_STAGED_VERIFIED",
                "master_auto_started":False,
                "master_tpm_restore_proven_after_boot":False}
    except Exception as exc:
        if mutated:
            raise ImportBlocked(
               "MASTER_IMPORT_POSSIBLY_PARTIAL_PRESERVE_EVIDENCE: "
               "STOP; no blind retry, delete, reboot or guest start. "+str(exc)) from exc
        raise
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","stage","verify"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--bundle",type=Path,required=True)
    p.add_argument("--os-disk",type=Path,required=True)
    p.add_argument("--uefi-vars",type=Path,required=True)
    p.add_argument("--swtpm-user",required=True)
    a=p.parse_args()
    try:
        result=(apply(a.approved_host,a.bundle,a.os_disk,a.uefi_vars,
                      a.swtpm_user) if a.mode=="stage" else
                check(a.approved_host,a.bundle,a.os_disk,a.uefi_vars,
                      a.swtpm_user,staged=a.mode=="verify"))
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except (ImportBlocked,golden.MasterExportBlocked,ValueError,
            TypeError,KeyError,OSError,ET.ParseError) as exc:
        print(json.dumps({"result":"COMMAND1_MASTER_IMPORT_BLOCKED",
           "reason":str(exc),"never_auto_retry_partial_import":True,
           "existing_ssl55_vm_not_modified":True},sort_keys=True),
           file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
