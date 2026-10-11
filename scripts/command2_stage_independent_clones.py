#!/usr/bin/env python3
"""Command 2A: independently STAGE N cold Windows 11 clones, zero NICs.

Consumes the VERIFIED standalone, decrypted 64-GiB CAPE Windows template,
not the original BitLocker-encrypted snapshot chain. Registers each clone
SHUT OFF, with its own flat QCOW2, UEFI NVRAM, libvirt UUID, generation ID,
and fresh TPM emulator state on first boot. Does NOT start the clone,
connect a NIC, change the Windows hostname/IP, edit CAPE, or run malware.

On any partial failure, retain artifacts and emit a journal for review;
NEVER delete anything, rollback snapshots or modify the master.
This SSL-55 staging adapter is not yet a portable fresh-host bootstrap.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
import stage_first_no_nic_windows_clone as verified
import probe_cold_windows_volume_crypto as crypto

BASE=Path("/var/lib/libvirt/images/cape-clones-staging")
NVBASE=Path("/var/lib/libvirt/qemu/nvram")
SOURCE=verified.TEMPLATE
ORIGINAL_VARS=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
GUARD_LOCK=verified.LOCK
TOTAL_RESERVE=30*1024**3
VIRTUAL_SIZE=64*1024**3
MAX_COUNT=16

class MultiStageError(RuntimeError):pass

def check(ok,why):
    if not ok:raise MultiStageError(why)

def run_command(*args,timeout=90):
    try:
        return subprocess.run(args,text=True,capture_output=True,
                              check=True,timeout=timeout).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        # No disk contents, libvirt XML or credentials in output.
        raise MultiStageError("Host command failed: "+args[0]+
                              " (manual review; no automatic rollback)") from e

def virsh(*args):
    return run_command("virsh","-c","qemu:///system",*args)

def names(count):
    check(isinstance(count,int) and 1<=count<=MAX_COUNT,
          "Count must be between 1 and "+str(MAX_COUNT))
    return [f"win11_{i}" for i in range(1,count+1)]

def planned(count):
    return [{"name":name,"windows_hostname":f"WIN11-{i}",
             "future_ipv4":f"192.168.240.{100+i}",
             # Reserved names distinguish Command 2 artifacts from
             # existing SSL-55 recovery disks, including win11_1.qcow2.
             "disk":str(BASE/(name+".command2.qcow2")),
             "nvram":str(NVBASE/(name+".command2_VARS.fd"))}
            for i,name in enumerate(names(count),1)]

def stamp(path):
    check(not path.is_symlink() and path.is_file(),
          "Source/template file missing or symlinked")
    state=path.stat()
    check(stat.S_ISREG(state.st_mode),"Source is not regular file")
    return (state.st_dev,state.st_ino,state.st_size,
            state.st_mtime_ns,state.st_ctime_ns)

def check_root_dir(path):
    check(path.is_dir() and not path.is_symlink(),
          "Clone directory missing or symlinked")
    st=path.stat()
    check(st.st_uid==0 and not(st.st_mode&0o022),
          "Clone directory is not protected from non-root changes")

def inspect_master():
    check(virsh("domstate",verified.VM)=="shut off",
          "Original master unexpectedly running")
    check(virsh("snapshot-current",verified.VM,"--name")==verified.SNAP,
          "Original master snapshot state changed")
    check_root_dir(BASE)
    check_root_dir(NVBASE)
    check(verified.BACKUP.is_dir() and not verified.BACKUP.is_symlink(),
          "Original preservation backup missing")
    check(not verified.BACKUP.stat().st_mode&0o077 and
          verified.BACKUP.stat().st_uid==0,
          "Original preservation backup not root-private")
    saved=(verified.BACKUP/"metadata/domain.xml").read_text(encoding="utf-8")
    orig=ET.fromstring(saved)
    live=ET.fromstring(virsh("dumpxml","--inactive",verified.VM))
    check(orig.findtext("uuid")==live.findtext("uuid"),
          "Preserved original UUID differs")
    disks=live.findall("./devices/disk[@device='disk']")
    check(len(disks)==1 and disks[0].find("source") is not None and
          disks[0].find("source").get("file")==verified.OVERLAY,
          "Preserved master inactive disk path differs")
    cold=(verified.BACKUP/("metadata/snapshot-"+verified.SNAP+".xml"))
    check(virsh("snapshot-dumpxml",verified.VM,verified.SNAP)==
          cold.read_text(encoding="utf-8").strip(),
          "Master snapshot metadata changed")
    check(orig.find("./os/nvram") is not None,
          "Preserved master firmware XML absent")
    return saved

def verify_source():
    check(SOURCE.parent==BASE,"Plaintext template is in an unexpected directory")
    check(not SOURCE.is_symlink(),"Template is symlinked")
    st=SOURCE.stat()
    check(st.st_uid==0 and not st.st_mode&0o077,
          "Source plaintext template not root-private")
    meta=json.loads(run_command("qemu-img","info","--output=json",str(SOURCE)))
    check(meta.get("format")=="qcow2" and
          meta.get("virtual-size")==VIRTUAL_SIZE and
          not meta.get("backing-filename") and
          not meta.get("full-backing-filename"),
          "Template is not independent flat 64-GiB QCOW2")
    try:
        crypto.require_cleartext_candidate(SOURCE)
    except crypto.VolumeProbeError as err:
        raise MultiStageError("Source Windows OS volume not verified plaintext") from err
    return stamp(SOURCE)

def check_resources(count):
    free=shutil.disk_usage(BASE).free
    needed=count*VIRTUAL_SIZE+TOTAL_RESERVE
    check(free>=needed,
          "Insufficient conservative disk capacity for "+str(count)+
          " clones: need "+str(needed//(1024**3))+
          " GiB free; have "+str(free//(1024**3))+
          " GiB. No changes made.")
    return {"host_free_gib":free//(1024**3),
            "conservative_required_gib":needed//(1024**3)}

def preflight(count):
    check(os.geteuid()==0,"Run with sudo/root privileges")
    entries=planned(count)
    saved=inspect_master()
    existing=set(virsh("list","--all","--name").splitlines())
    for entry in entries:
        check(entry["name"] not in existing,
              "Target domain already defined: "+entry["name"])
        for value in (entry["disk"],entry["nvram"]):
            path=Path(value)
            check(not path.exists() and not path.is_symlink(),
                  "Target disk/NVRAM already exists: "+path.name)
    source_stamp=verify_source()
    vars_stamp=stamp(ORIGINAL_VARS)
    check(vars_stamp[2] in (540672,131072,262144,1048576),
          "Master NVRAM size unexpectedly changed")
    resources=check_resources(count)
    for entry in entries:
        identifier=str(uuid.uuid4())
        # Validate exact same proven no-NIC renderer as working trial.
        verified.render(saved,identifier=identifier,name=entry["name"],
                        disk=Path(entry["disk"]),nvram=Path(entry["nvram"]))
    check(virsh("domstate",verified.NAME)=="running",
          "Proven no-NIC trial is no longer running")
    trial=ET.fromstring(virsh("dumpxml",verified.NAME))
    check(trial.findtext("name")==verified.NAME and
          trial.findtext("uuid")=="e75f6fef-347d-462f-9738-4de3df6bfa74",
          "Proven trial identity changed")
    check(not trial.findall("./devices/interface"),
          "Proven trial acquired a guest NIC")
    return entries,saved,source_stamp,vars_stamp,resources

def new_identity():
    return str(uuid.uuid4())

def guest_mac():
    # Reserved for future NIC attachment. Do not add NIC in this command.
    return "02:"+":".join(secrets.token_hex(1) for _ in range(5))

def verify_definition(entry,identifier):
    check(virsh("domstate",entry["name"])=="shut off",
          "New domain unexpectedly started")
    root=ET.fromstring(virsh("dumpxml","--inactive",entry["name"]))
    disk=root.find("./devices/disk[@device='disk']/source")
    backend=root.find("./devices/tpm/backend")
    expected_genid=str(uuid.uuid5(uuid.UUID(identifier),"new-windows-genid"))
    check(root.findtext("name")==entry["name"] and
          root.findtext("uuid")==identifier and
          (root.findtext("genid") in (None,expected_genid)) and
          root.findtext("./os/nvram")==entry["nvram"] and
          disk is not None and disk.get("file")==entry["disk"] and
          backend is not None and backend.get("type")=="emulator" and
          backend.find("source") is None and
          not root.findall("./devices/interface") and
          not root.findall("./devices/hostdev") and
          not root.findall("./devices/filesystem") and
          not root.findall("./devices/redirdev") and
          not root.findall("./devices/channel"),
          "Unexpected libvirt clone identity or host-connected device")
    image=json.loads(run_command("qemu-img","info","--output=json",entry["disk"]))
    check(image.get("format")=="qcow2" and
          image.get("virtual-size")==VIRTUAL_SIZE and
          not image.get("backing-filename") and
          not image.get("full-backing-filename"),
          "Clone image has a backing chain")

def provision(entry,saved,base_stamp,vars_stamp,existing_macs):
    name=entry["name"]
    check(virsh("domstate",verified.VM)=="shut off",
          "Master state changed before clone operation")
    check(stamp(SOURCE)==base_stamp and stamp(ORIGINAL_VARS)==vars_stamp,
          "Source files changed during staging")
    identifier=new_identity()
    mac=guest_mac()
    check(mac not in existing_macs,"Generated duplicate planned MAC")
    existing_macs.add(mac)
    xml=verified.render(saved,identifier=identifier,name=name,
                        disk=Path(entry["disk"]),nvram=Path(entry["nvram"]))
    disk=Path(entry["disk"])
    firmware=Path(entry["nvram"])
    temp_path=None
    stage="ALLOCATE"
    try:
        with tempfile.NamedTemporaryFile(prefix=".cape-multi-",
                suffix=".qcow2",dir=str(BASE),delete=False) as tf:
            temp_path=Path(tf.name)
        temp_path.unlink()
        stage="COPY_DISK"
        run_command("qemu-img","convert","-f","qcow2","-O","qcow2",
                    "-o","compat=1.1",str(SOURCE),str(temp_path),timeout=7200)
        temp_path.chmod(0o600)
        stage="VALIDATE_DISK"
        run_command("qemu-img","check","-q","-f","qcow2",str(temp_path),
                    timeout=3600)
        info=json.loads(run_command("qemu-img","info","--output=json",
                                    str(temp_path)))
        check(info.get("format")=="qcow2" and
              info.get("virtual-size")==VIRTUAL_SIZE and
              not info.get("backing-filename") and
              not info.get("full-backing-filename"),
              "Copied disk is not standalone QCOW2")
        stage="VERIFY_PLAINTEXT_OS"
        try:
            crypto.require_cleartext_candidate(temp_path)
        except crypto.VolumeProbeError as error:
            raise MultiStageError("Copied clone lacks readable plaintext Windows volume") from error
        check(stamp(SOURCE)==base_stamp and
              stamp(ORIGINAL_VARS)==vars_stamp,
              "Source template or original firmware changed mid-copy")
        check(not disk.exists() and not disk.is_symlink() and
              not firmware.exists() and not firmware.is_symlink(),
              "Target appeared during copy; do not overwrite it")
        check(shutil.disk_usage(BASE).free>=TOTAL_RESERVE,
              "Disk reserve lost during conversion")
        stage="COPY_NVRAM"
        st=ORIGINAL_VARS.stat()
        fd=os.open(firmware,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as out:
            os.fchown(out.fileno(),st.st_uid,st.st_gid)
            with ORIGINAL_VARS.open("rb") as source:
                shutil.copyfileobj(source,out)
            out.flush()
            os.fsync(out.fileno())
        stage="PUBLISH_DISK"
        os.link(temp_path,disk)
        temp_path.unlink()
        temp_path=None
        stage="DEFINE"
        with tempfile.TemporaryDirectory(prefix="cape-multi-define-",
                                         dir="/run") as d:
            path=Path(d)/"vm.xml"
            path.write_text(xml,encoding="utf-8")
            path.chmod(0o600)
            virsh("define",str(path),"--validate")
        stage="READBACK"
        verify_definition(entry,identifier)
        check(stamp(SOURCE)==base_stamp and stamp(ORIGINAL_VARS)==vars_stamp,
              "Source or original firmware changed after clone registration")
        return dict(entry,uuid=identifier,planned_mac=mac,
                    result="STAGED_SHUT_OFF_ZERO_NICS",
                    planned_mac_not_attached=True,
                    independent_tpm="new libvirt swtpm state on first boot",
                    guest_personalized=False,ip_assigned=False,
                    network_attached=False,guest_started=False,
                    snapshot_created=False,
                    master_disk_modified=False)
    except Exception as err:
        raise MultiStageError(name+" interrupted at "+stage+
              "; preserve any registered domain, disk and NVRAM; "+
              "no blind retry or deletion. Reason: "+str(err)) from err
    finally:
        # Temporary conversion file may be incomplete and unregistered.
        # To avoid deleting any unexamined artifacts, retain it for review.
        if temp_path is not None and temp_path.exists():
            print("INCOMPLETE_EXPORT_RETAINED: "+temp_path.name,file=sys.stderr)

def prohibit_reference_host_staging():
    """Do not create ANY additional VMs on the SSL-55 reference machine.

    This SSL-55-specific staging adapter is retained for historical tests.
    Production deployment on different hosts requires the portable Command 2
    entrypoint, not bypassing this guard.
    """
    hostname=socket.gethostname().split(".",1)[0].casefold()
    check(hostname not in ("cse-ssl-55","ssl-55"),
          "SSL-55 is REFERENCE-ONLY: additional VM staging prohibited")


def deploy(count,mode):
    os.umask(0o077)
    check(mode in ("plan","stage"),"Invalid staging mode")
    journal={"result":"IN_PROGRESS","mode":mode,
             "requested_clones":count,"created":[],
             "windows_personalized":False,
             "analysis_network_connected":False,
             "runtime_egress_isolation_verified":False,
             "malware_execution_authorized":False}
    if mode=="stage":
        # Enforce before opening even the staging lock file.
        try:
            prohibit_reference_host_staging()
        except MultiStageError as exc:
            journal["result"]="BLOCKED_OR_PARTIAL_REVIEW_REQUIRED"
            journal["reason"]=str(exc)
            return journal
    check(not GUARD_LOCK.is_symlink(),"Unsafe shared staging lock")
    lock=os.open(GUARD_LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(lock)
        check(info.st_uid==0 and not(info.st_mode&0o077),
              "Unsafe staging lock permissions")
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        entries,saved,base,vars,space=preflight(count)
        journal["resources"]=space
        journal["planned"]=entries
        if mode=="plan":
            journal["result"]="MULTI_CLONE_ZERO_NIC_PLAN_ONLY"
            return journal
        macs=set()
        for entry in entries:
            journal["current_clone"]=entry["name"]
            record=provision(entry,saved,base,vars,macs)
            journal["created"].append(record)
        journal.pop("current_clone",None)
        journal["result"]="INDEPENDENT_ZERO_NIC_CLONES_STAGED"
        return journal
    except Exception as exc:
        journal["result"]="BLOCKED_OR_PARTIAL_REVIEW_REQUIRED"
        journal["reason"]=str(exc)
        return journal
    finally:os.close(lock)

def main():
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--mode",choices=["plan","stage"],default="plan")
    cli.add_argument("--count",type=int)
    args=cli.parse_args()
    number=args.count
    if number is None:
        if not sys.stdin.isatty():
            print("BLOCKED: --count N needed for noninteractive usage",
                  file=sys.stderr)
            return 2
        try: number=int(input("Number of independent Windows clones [1-16]: "))
        except ValueError:
            print("BLOCKED: Invalid number",file=sys.stderr)
            return 2
    result=deploy(number,args.mode)
    print(json.dumps(result,indent=2,sort_keys=True),flush=True)
    return 0 if result["result"] in ("MULTI_CLONE_ZERO_NIC_PLAN_ONLY",
                                    "INDEPENDENT_ZERO_NIC_CLONES_STAGED") else 2

if __name__=="__main__":
    sys.exit(main())
