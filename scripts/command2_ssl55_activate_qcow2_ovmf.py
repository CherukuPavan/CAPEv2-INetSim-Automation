#!/usr/bin/env python3
"""SSL-55 exact win11_1 saved-libvirt XML OVMF sidecar activation.

Plan and verify are READ ONLY; apply requires root, direct operator typed
approval and existing cold recovery byte verification. This changes ONLY
the SHUT-OFF win11_1 saved domain NVRAM format/path from RAW to the already
prepared distinct QCOW2 file. Original XML, disk, VARS and swtpm preserved.

No VM boot, snapshot, TPM reset, capture, malware or source-master change.
No blind rollback if virsh define partly changes the domain.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_ssl55_scoped_nvram_sidecar as prep
import command2_ssl55_running_snapshot_readonly as ref

VM=ref.VM
UID=ref.UID
RAW=ref.VARS
SIDE=Path(str(RAW)+".qcow2")
LOCK=Path("/run/lock/cape-command2-ssl55-win11-1-ovmf-activate.lock")
XML_SHA="f83f6e12644d56c093f304e3bf747c6b8496f73397ce93dbd91b796addca235c"
RAW_SHA="0ee94bcaf1347cfd5369261ea2c51cafd6e1945a6a8f2cdc1ff530f689fb2037"
SIDE_SHA="40f51f51b42763346b54bcaa125b0dc5af4620264c20762c1011ea3932c10f57"
MANIFEST_SHA="78aa8fb7dea53bd9284eb067cd30d06b168270511325aa3b2f6b498b4fd747b1"
BACKUP_FILE="win11_1.pre-qcow2-nvram-activation.xml"

class TransitionBlocked(RuntimeError): pass
def need(ok,msg):
    if not ok:raise TransitionBlocked(msg)

def cmd(*args,timeout=120):
    try:
        p=subprocess.run(args,capture_output=True,text=True,
                         timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise TransitionBlocked("Host utility missing or timed out: "+args[0]) from e
    need(p.returncode==0,"Host utility returned nonzero result: "+args[0])
    need(len(p.stdout)<2_000_000,"Unexpected oversized host utility response")
    return p.stdout.strip()

def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def guarded_existing_files():
    # Protect all three established VM identities and stopped state before
    # reading original firmware, sidecar, backup and saved libvirt XML.
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Exact protected SSL55 local root context required")
    need(virsh("domuuid",VM).lower()==UID and
         virsh("domstate",VM).lower()=="shut off",
         "Existing SSL55 clone must remain SHUT OFF")
    for name,uuid in (ref.MASTER,ref.TRIAL):
        need(virsh("domuuid",name).lower()==uuid and
             virsh("domstate",name).lower()=="shut off",
             "Protected master/trial changed identity or was powered on")
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Unexpected snapshot already exists; refuse firmware transition")
    raw=prep.regular(RAW)
    side=prep.regular(SIDE)
    need(raw.st_size==540672 and raw.st_nlink==1 and
         side.st_nlink==1 and side.st_uid==raw.st_uid and
         side.st_gid==raw.st_gid and
         stat.S_IMODE(side.st_mode)==0o600,
         "Original firmware or distinct staged QCOW2 metadata differs")
    need(prep.sha256(RAW)==RAW_SHA and
         prep.sha256(SIDE)==SIDE_SHA,
         "Source RAW or approved QCOW2 sidecar bytes changed")
    data=json.loads(cmd("qemu-img","info","--output=json",str(SIDE)))
    need(data.get("format")=="qcow2" and
         data.get("virtual-size")==raw.st_size and
         not data.get("backing-filename"),
         "QCOW2 UEFI sidecar size/format/backing not as approved")
    cmd("qemu-img","check","-f","qcow2",str(SIDE),timeout=90)
    cmd("qemu-img","compare","-f","raw","-F","qcow2",str(RAW),str(SIDE),
        timeout=180)
    cold=prep.verify_existing_bundle()
    need(cold["manifest_sha256"]==MANIFEST_SHA and
         cold["byte_verified_member_count"]==3,
         "Pinned full disk/OVMF/swtpm stopped recovery bundle differs")
    # The SHA of a recovery bundle doesn't establish that restoration
    # was physically performed. We never mark TPM revert proof as success.
    return {"cold_manifest_sha256":cold["manifest_sha256"],
            "sidecar_sha256":SIDE_SHA,"raw_sha256":RAW_SHA}

def transform_saved(raw_xml):
    root=ET.fromstring(raw_xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UID,
         "Unexpected libvirt guest identity/type")
    loader=root.find("./os/loader")
    need(loader is not None and loader.get("type")=="pflash" and
         loader.get("readonly")=="yes",
         "Unexpected UEFI loader type or writable loader")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(ref.DISK),
         "Clone system QCOW2 differs")
    backing=disks[0].find("backingStore")
    need(backing is None or
         (backing.find("source") is None and backing.find("backingStore") is None),
         "OS disk has unexpected master backing chain")
    nv=root.find("./os/nvram")
    need(nv is not None and nv.text==str(RAW) and
         nv.get("format","raw")=="raw",
         "Only original RAW UEFI path may be transitioned")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Unexpected swtpm2")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
         "Unreviewed network NIC")
    for dev in ("hostdev","filesystem","redirdev","shmem","vsock"):
        need(not root.findall("./devices/"+dev),
             "Unexpected passthrough device")
    nv.set("format","qcow2")
    nv.text=str(SIDE)
    return ET.tostring(root,encoding="utf-8")

def location(directory):
    folder=Path(directory)
    need(folder.is_absolute() and folder.is_dir() and not folder.is_symlink(),
         "Existing absolute private XML backup directory required")
    st=folder.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "XML backup directory must be root owned mode 0700")
    # Refuse user-controlled child symlinks/hardlinks or previous runs.
    return folder/BACKUP_FILE

def verify_after(active_xml):
    root=ET.fromstring(active_xml)
    nv=root.find("./os/nvram")
    need(nv is not None and nv.text==str(SIDE) and
         nv.get("format")=="qcow2",
         "Libvirt did not preserve intended QCOW2 NVRAM path/format")
    # Verify every other XML element is semantically identical. The
    # equality comparison ignores harmless libvirt formatting only.
    original=root.find("./os/nvram")
    original.text=str(RAW)
    original.set("format","raw")
    return root

def plan(backup_dir,*,mode="plan"):
    need(mode in ("plan","verify"),
         "Unexpected firmware transition action")
    witness=guarded_existing_files()
    backup=location(backup_dir)
    stored=virsh("dumpxml","--inactive",VM)
    xml_before=sha(stored.encode())
    if mode=="plan":
        need(not backup.exists() and not backup.is_symlink(),
             "Prior XML backup already exists: no blind reactivation")
        need(xml_before==XML_SHA,
             "Stored guest XML changed since stopped recovery evidence")
        proposed=transform_saved(stored)
        return {"result":"SSL55_WIN11_1_SAVED_OVMF_QCOW2_TRANSITION_PLAN_ONLY",
                "vm":VM,"uuid":UID,"state":"shut off",
                "prior_saved_xml_sha256":xml_before,
                "proposed_xml_sha256":sha(proposed),
                "planned_xml_backup":str(backup),
                **witness,
                "full_disk_tpm_ovmf_cold_restore_tested":False,
                "risk_acknowledgement_required_for_apply":True,
                "source_master_or_trial_touched":False,
                "domain_xml_changed":False,"snapshot_created":False}
    # Verify-only expects the unique original saved backup and active config.
    need(backup.is_file() and not backup.is_symlink() and
         backup.stat().st_uid==0 and
         stat.S_IMODE(backup.stat().st_mode)==0o600 and
         backup.stat().st_nlink==1 and
         sha(backup.read_bytes())==XML_SHA,
         "Prior original libvirt XML backup missing or modified")
    before=ET.fromstring(backup.read_bytes())
    expect=ET.fromstring(transform_saved(ET.tostring(before,encoding="unicode")))
    now=ET.fromstring(stored)
    nv_now=now.find("./os/nvram")
    need(nv_now is not None and nv_now.text==str(SIDE) and
         nv_now.get("format")=="qcow2",
         "Saved libvirt XML does not select distinct QCOW2 UEFI")
    # Strong exact device-field verification: libvirt may add harmless
    # defaults to XML after define; compare the dangerous elements.
    for xpath in ("./devices/disk[@device='disk']/source",
                  "./devices/disk[@device='disk']/driver",
                  "./devices/interface/source","./devices/interface/mac",
                  "./devices/tpm/backend","./os/loader"):
        a=expect.find(xpath)
        b=now.find(xpath)
        need(a is not None and b is not None and
             a.attrib==b.attrib and (a.text or "").strip()==(b.text or "").strip(),
             "Unexpected device drift after saved OVMF transition: "+xpath)
    need(now.findtext("uuid")==UID and
         virsh("domstate",VM).lower()=="shut off",
         "Guest started unexpectedly after firmware activation")
    return {"result":"SSL55_WIN11_1_QCOW2_OVMF_SAVED_XML_VERIFIED_OFF",
            "vm":VM,"uuid":UID,"state":"shut off",
            "verified_saved_nvram":str(SIDE),
            "backup_original_xml_sha256":XML_SHA,
            "sidecar_sha256":SIDE_SHA,
            "raw_original_preserved":True,
            "source_master_or_trial_touched":False,
            "swtpm_memory_snapshot_or_revert_verified":False,
            "guest_booted":False,"snapshot_created":False}

def apply(backup_dir):
    need(sys.stdin.isatty(),"Interactive operator authorization required")
    pre=plan(backup_dir)
    print(json.dumps(pre,sort_keys=True,indent=2),flush=True)
    phrase="ACTIVATE-SSL55-WIN11_1-QCOW2-OVMF-ONLY"
    need(input("Type "+phrase+" to switch ONLY this stopped clone's saved OVMF XML: ")==phrase,
         "No explicit clone-only activation authorization")
    backup=location(backup_dir)
    need(not LOCK.is_symlink(),"Untrusted transition serialization lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Transition lock not root-private")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise TransitionBlocked("Concurrent transition") from e
        need(plan(backup_dir)==pre,
             "Guest/OVMF/backup source changed since approval")
        before=virsh("dumpxml","--inactive",VM)
        need(sha(before.encode())==XML_SHA,
             "Saved XML changed after final approval")
        after=transform_saved(before)
        # Write and fsync the exact original libvirt domain XML backup
        # BEFORE attempting any guest definition change.
        fd_backup=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd_backup,"wb") as out:
            out.write(before.encode())
            out.flush()
            os.fsync(out.fileno())
        dirfd=os.open(backup.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
        # Use a temp XML file with mode 0600. Libvirt read and define may
        # canonicalize formatting. Never start a VM in this step.
        tmp=None
        try:
            with tempfile.NamedTemporaryFile(prefix="cape-ssl55-ovmf-",
                suffix=".xml",dir="/run",delete=False) as out:
                tmp=Path(out.name)
                os.fchmod(out.fileno(),0o600)
                out.write(after)
                out.flush();os.fsync(out.fileno())
            need(virsh("domstate",VM).lower()=="shut off",
                 "Guest unexpectedly powered on before XML define")
            virsh("define",str(tmp),"--validate")
        finally:
            if tmp is not None:tmp.unlink(missing_ok=True)
        # Re-read the exact VM state; refusal leaves backup and original RAW
        # untouched and does not perform blind XML rollback/redefine.
        return plan(backup_dir,mode="verify")
    finally:
        os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","apply","verify"),default="plan")
    p.add_argument("--xml-backup-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        out=(plan(a.xml_backup_dir,mode="plan") if a.mode=="plan" else
             plan(a.xml_backup_dir,mode="verify") if a.mode=="verify" else
             apply(a.xml_backup_dir))
        print(json.dumps(out,sort_keys=True,indent=2))
        return 0
    except (TransitionBlocked,prep.SSL55PrepareBlocked,OSError,
            ValueError,TypeError,KeyError,ET.ParseError,
            subprocess.TimeoutExpired) as e:
        print(json.dumps({"result":"SSL55_WIN11_1_FIRMWARE_TRANSITION_BLOCKED",
            "reason":str(e),
            "post_define_state_unknown_if_activation_attempted":True,
            "automatic_rollback_or_guest_start_attempted":False},
            sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
