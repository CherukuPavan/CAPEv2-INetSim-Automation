#!/usr/bin/env python3
"""Explicit OTHER-host disposal-only saved XML switch to staged QCOW2 OVMF.

No guest start/stop, running snapshot, TPM change or CAPE registration.
Retains RAW OVMF input, matching sidecar, byte-verified complete recovery
bundle and independently recorded prior *actual* cold restore witness.

If activation partially fails, preserves the original saved XML backup and
both NVRAM files and refuses automatic rollback/retry. Always test clean
Windows/TPM/Secure Boot in disposable VM after separately approved boot.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import command2_disposable_nvram_qcow2_prepare as prep

LOCK=Path("/run/lock/cape-command2-disposable-nvram-activate.lock")
class ActivateBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise ActivateBlocked(why)
def run(*args,timeout=50):
    try:
        p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise ActivateBlocked("Host utility missing or timed out: "+args[0]) from e
    need(p.returncode==0,"Host utility rejected operation: "+args[0])
    return p.stdout.strip()
def virsh(*args):return run("virsh","-c","qemu:///system",*args)
def read_private_json(path):
    file=Path(path)
    need(file.is_absolute() and file.is_file() and not file.is_symlink(),
         "Required separate-host operator witness missing")
    st=file.stat()
    need(st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)&0o077==0 and st.st_size<128*1024,
         "Witness must be root-private regular file")
    return json.loads(file.read_text(encoding="utf-8"))
def inspect_witness(file,host,vm,uuid,manifestsha):
    data=read_private_json(file)
    need(type(data) is dict and
         data.get("format")=="COMMAND2_FULL_COLD_RESTORE_WITNESS_V1" and
         data.get("approved_host")==host and data.get("vm")==vm and
         data.get("uuid")==uuid and
         data.get("recovery_manifest_sha256")==manifestsha and
         all(data.get(k) is True for k in (
            "cold_disk_restored_on_disposable_vm",
            "cold_nvram_restored_on_disposable_vm",
            "cold_swtpm2_restored_on_disposable_vm",
            "windows_agent_verified_after_restore",
            "windows_tpm_uefi_boot_verified_after_restore",
            "master_unmodified_verified")) and
         type(data.get("operator")) is str and
         len(data["operator"].strip())>=3 and
         type(data.get("details")) is str and
         len(data["details"].strip())>=25,
         "Independent full disk/OVMF/TPM restore witness incomplete")
    return hashlib.sha256(Path(file).read_bytes()).hexdigest()

def plan(host,vm,uuid,bundle,manifest_sha,witness,backup_dir):
    try:prep.hostname_guard(host)
    except prep.ConversionBlocked as e:raise ActivateBlocked(str(e)) from e
    need(type(vm) is str and prep.VM_RE.fullmatch(vm) is not None,
         "Only disposable Command2 guest accepted")
    cold=prep.cold.inspect(vm,uuid,bundle,manifest_sha)
    witnessed_sha=inspect_witness(witness,host,vm,uuid,cold["manifest_sha256"])
    need(virsh("domuuid",vm).lower()==uuid and
         virsh("domstate",vm).lower()=="shut off" and
         not virsh("snapshot-list",vm,"--name").strip(),
         "Exact disposable VM must be off and snapshot-free")
    raw_xml=virsh("dumpxml","--inactive",vm)
    root=ET.fromstring(raw_xml)
    need(root.tag=="domain" and root.findtext("name")==vm and
         root.findtext("uuid")==uuid and root.get("type")=="kvm",
         "Unexpected VM definition")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file","").endswith(
             "/"+vm+".command2.qcow2"),"Not a standalone clone disk")
    nv=root.find("./os/nvram")
    loader=root.find("./os/loader")
    need(loader is not None and loader.get("type")=="pflash" and
         nv is not None and nv.get("format","raw")=="raw" and
         nv.text is not None,"Unexpected old firmware XML")
    original=Path(nv.text)
    need(original.name==vm+".command2_VARS.fd",
         "Original NVRAM path differs")
    originalstat=prep.filemeta(original)
    originalsha=prep.sha256(original)
    sidecar=Path(str(original)+".qcow2")
    need(sidecar.is_file() and not sidecar.is_symlink() and
         sidecar.stat().st_uid==originalstat.st_uid and
         sidecar.stat().st_gid==originalstat.st_gid and
         sidecar.stat().st_nlink==1 and
         stat.S_IMODE(sidecar.stat().st_mode)&0o077==0,
         "Prepared firmware sidecar missing or unsafe")
    sidecar_info=json.loads(run("qemu-img","info","--output=json",str(sidecar)))
    need(sidecar_info.get("format")=="qcow2" and
         sidecar_info.get("virtual-size")==originalstat.st_size and
         not sidecar_info.get("backing-filename"),
         "Firmware sidecar format/dependency mismatch")
    run("qemu-img","compare","-f","raw","-F","qcow2",
        str(original),str(sidecar),timeout=180)
    need(prep.sha256(original)==originalsha,
         "Source NVRAM changed during sidecar validation")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "TPM2 unexpectedly changed")
    nic=root.findall("./devices/interface")
    need(len(nic)==1 and nic[0].find("source") is not None and
         nic[0].find("source").get("network")=="cape-analysis-isolated",
         "Expected isolated NIC missing")
    need(not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem"),
         "Unexpected passthrough guest devices")
    d=Path(backup_dir)
    need(d.is_absolute() and d.is_dir() and not d.is_symlink(),
         "Explicit private XML backup directory required")
    st=d.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,
         "XML backup folder must be root 0700")
    target=d/(vm+".raw-nvram-before-transition.xml")
    need(not target.exists() and not target.is_symlink(),
         "Backup XML already exists; prior transition needs review")
    # Preserve all other VM elements. Only <nvram format,path> changes.
    nv.set("format","qcow2")
    nv.text=str(sidecar)
    proposed=ET.tostring(root,encoding="unicode")
    need(proposed.count(str(sidecar))==1,
         "Unanticipated XML transition format")
    return {"result":"COMMAND2_DISPOSABLE_QCOW2_NVRAM_XML_PLAN_ONLY",
            "vm":vm,"uuid":uuid,
            "before_xml_sha256":hashlib.sha256(raw_xml.encode()).hexdigest(),
            "proposed_xml_sha256":hashlib.sha256(proposed.encode()).hexdigest(),
            "original_nvram_sha256":originalsha,
            "sidecar_sha256":prep.sha256(sidecar),
            "old_nvram_path":str(original),"new_nvram_path":str(sidecar),
            "xml_backup":str(target),
            "cold_manifest_sha256":cold["manifest_sha256"],
            "prior_real_cold_restore_witness_sha256":witnessed_sha,
            "vm_shutdown_verified":True,
            "snapshot_created":False,
            "xml_changed":False,
            "tpm_state_changed":False,
            "boot_after_switch_verified":False}

def apply(host,vm,uuid,bundle,manifest_sha,witness,backup_dir):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root and direct interactive operator approval required")
    pre=plan(host,vm,uuid,bundle,manifest_sha,witness,backup_dir)
    print(json.dumps(pre,indent=2,sort_keys=True),flush=True)
    phrase="ACTIVATE-QCOW2-OVMF-ON-DISPOSABLE-"+vm.upper()
    need(input("Type "+phrase+" to change ONLY saved OVMF XML: ")==phrase,
         "Operator did not authorize XML transition")
    need(not LOCK.is_symlink(),"Unsafe transition lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(st.st_uid==0 and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and
             stat.S_ISREG(st.st_mode),"Invalid root serialization lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:raise ActivateBlocked("Another transition running") from e
        need(plan(host,vm,uuid,bundle,manifest_sha,witness,backup_dir)==pre,
             "VM/firmware/backup/evidence changed after approval")
        original_xml=virsh("dumpxml","--inactive",vm)
        need(hashlib.sha256(original_xml.encode()).hexdigest()==pre["before_xml_sha256"],
             "Saved XML changed before commit")
        root=ET.fromstring(original_xml)
        nv=root.find("./os/nvram")
        need(nv is not None,"OVMF disappeared before approval")
        nv.set("format","qcow2")
        nv.text=pre["new_nvram_path"]
        rendered=ET.tostring(root,encoding="utf-8")
        need(hashlib.sha256(rendered).hexdigest()==pre["proposed_xml_sha256"],
             "Prepared XML byte hash mismatch")
        backup=Path(pre["xml_backup"])
        fd_backup=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd_backup,"wb") as stream:
            stream.write(original_xml.encode())
            stream.flush();os.fsync(stream.fileno())
        # Durably persist the recovery XML directory entry BEFORE changing libvirt.
        backup_dir_fd=os.open(backup.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(backup_dir_fd)
        finally:os.close(backup_dir_fd)
        with tempfile.NamedTemporaryFile(mode="wb",dir="/run",prefix="cape-disposable-nvram-",
                                         suffix=".xml",delete=False) as out:
            fname=Path(out.name)
            os.fchmod(out.fileno(),0o600)
            out.write(rendered);out.flush();os.fsync(out.fileno())
        try:
            # Saved DOMAIN CONFIG only. VM must stay off. No TPM/device/OS changes.
            virsh("define",str(fname),"--validate")
        except ActivateBlocked as e:
            raise ActivateBlocked("Saved XML backup preserved; libvirt rejected "
                                  "transition. Inspect before any retry") from e
        finally:fname.unlink(missing_ok=True)
        updated=ET.fromstring(virsh("dumpxml","--inactive",vm))
        currentnv=updated.find("./os/nvram")
        nics=updated.findall("./devices/interface")
        disks=updated.findall("./devices/disk[@device='disk']")
        tpm=updated.find("./devices/tpm/backend")
        need(currentnv is not None and currentnv.text==pre["new_nvram_path"] and
             currentnv.get("format")=="qcow2" and
             updated.findtext("uuid")==uuid and
             len(nics)==1 and nics[0].find("source") is not None and
             nics[0].find("source").get("network")=="cape-analysis-isolated" and
             len(disks)==1 and disks[0].find("source") is not None and
             disks[0].find("source").get("file","").endswith(
                "/"+vm+".command2.qcow2") and
             tpm is not None and tpm.get("type")=="emulator" and
             tpm.get("version")=="2.0" and
             not virsh("snapshot-list",vm,"--name").strip() and
             virsh("domstate",vm).lower()=="shut off",
             "Saved XML post-transition changed protected NIC/disk/TPM or VM started")
        need(prep.sha256(Path(pre["old_nvram_path"]))==
             pre["original_nvram_sha256"],
             "Original RAW NVRAM changed after switching saved XML")
        return {"result":"COMMAND2_DISPOSABLE_QCOW2_NVRAM_XML_UPDATED_VM_OFF",
                "vm":vm,"prior_xml_backed_up":str(backup),
                "original_raw_nvram_preserved":True,
                "new_firmware_path":pre["new_nvram_path"],
                "vm_booted":False,"snapshot_created":False,
                "real_tpm_uefi_revert_verified":False,
                "next_step":"Approve disposable guest boot and benign Windows TPM/UEFI/Agent check"}
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","apply"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--uuid",required=True)
    p.add_argument("--recovery-bundle",type=Path,required=True)
    p.add_argument("--reviewed-manifest-sha",required=True)
    p.add_argument("--witness",type=Path,required=True)
    p.add_argument("--xml-backup-dir",type=Path,required=True)
    a=p.parse_args()
    try:
        out=plan(a.approved_host,a.vm,a.uuid,a.recovery_bundle,
                 a.reviewed_manifest_sha,a.witness,a.xml_backup_dir) if a.mode=="plan" else apply(
                 a.approved_host,a.vm,a.uuid,a.recovery_bundle,
                 a.reviewed_manifest_sha,a.witness,a.xml_backup_dir)
        print(json.dumps(out,indent=2,sort_keys=True))
        return 0
    except (ActivateBlocked,prep.ConversionBlocked,
            prep.cold.RecoveryBlocked,OSError,ValueError,TypeError,
            ET.ParseError) as e:
        print(json.dumps({"result":"COMMAND2_DISPOSABLE_QCOW2_TRANSITION_BLOCKED",
                          "reason":str(e),
                          "automatic_revert_not_attempted":True},indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
