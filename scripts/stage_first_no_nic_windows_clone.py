#!/usr/bin/env python3
"""First no-network disposable Windows clone staging from a cold plaintext template.

Source: the proven standalone decrypted template ONLY. Never uses encrypted
original cold snapshots as the clone disk. Produces independent clone disk,
new libvirt UUID and guest GenID, separate UEFI NVRAM file, and a NEW libvirt
TPM emulator backend identity (state generated on first start). Domain is
registered SHUT OFF with ZERO NICs; no Windows guest boot, no sample analysis,
no guest IP address/hostname customization yet.

A staged no-NIC guest allows benign boot/driver/package verification
before attaching a separately tested isolated analysis network.

Do not run this source against untrusted/malware-submitted disk images.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
import probe_cold_windows_volume_crypto as crypto

VM="win11"
SNAP="finalshutoffversion"
NAME="win11_trial_1"
MASTER="/var/lib/libvirt/images/win11.finalshutoffversion"
OVERLAY="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
TEMPLATE=Path("/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2")
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_trial_1.qcow2")
NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_trial_1_VARS.fd")
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
LOCK=Path("/run/lock/cape-cold-export.lock")
RESERVE=30*1024**3
SIZE=64*1024**3

class StageError(RuntimeError): pass

def ensure(ok,reason):
    if not ok:raise StageError(reason)

def call(*args,timeout=120):
    try:
        return subprocess.run(args,capture_output=True,text=True,
                              check=True,timeout=timeout).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise StageError(f"{args[0]} operation failed; do not retry or delete files") from e

def virsh(*args):
    return call("virsh","-c","qemu:///system",*args)

def render(saved_xml,*,identifier,name=NAME,disk=DISK,nvram=NVRAM):
    # The zero-NIC renderer is reusable by Command 2 for arbitrary VM counts.
    # All safety checks on the saved source domain remain enforced.
    import re
    ensure(re.fullmatch(r"win11_[1-9][0-9]{0,2}",name) is not None or name==NAME,
           "Invalid Windows clone name")
    disk=Path(disk)
    nvram=Path(nvram)
    ensure(disk.is_absolute() and nvram.is_absolute() and
           not any(".."==part for part in disk.parts+nvram.parts) and
           disk!=nvram, "Unsafe independent clone file paths")
    ensure(disk.parent==DISK.parent and nvram.parent==NVRAM.parent and
           disk.name==name+".qcow2" and
           nvram.name==name+"_VARS.fd",
           "Clone disk/NVRAM must remain in protected staging directories")
    identifier=str(uuid.UUID(identifier))
    root=ET.fromstring(saved_xml)
    ensure(root.tag=="domain" and root.get("type")=="kvm",
           "Source must be KVM domain")
    ensure(root.findtext("name")==VM and
           root.findtext("uuid")!=identifier,"Source domain identity changed")
    require_disk=root.findall("./devices/disk[@device='disk']")
    ensure(len(require_disk)==1,"Unexpected source disk count")
    src=require_disk[0].find("source")
    ensure(src is not None and src.get("file")==MASTER,
           "Saved master XML references unexpected disk")
    require_nic=root.findall("./devices/interface")
    ensure(len(require_nic)==1 and require_nic[0].get("type")=="network",
           "Unexpected original network configuration")
    interface_src=require_nic[0].find("source")
    ensure(interface_src is not None and interface_src.get("network")=="default",
           "Unexpected original network attachment")
    tpm=root.findall("./devices/tpm")
    ensure(len(tpm)==1 and tpm[0].get("model") in ("tpm-tis","tpm-crb"),
           "Unsupported original TPM model")
    backend=tpm[0].find("backend")
    ensure(backend is not None and backend.get("type")=="emulator" and
           backend.get("version")=="2.0" and backend.find("source") is None,
           "Original TPM state path is explicit/unsafe")
    osnode=root.find("os")
    vars=osnode.find("nvram") if osnode is not None else None
    ensure(vars is not None and
           (vars.text or "").strip()=="/var/lib/libvirt/qemu/nvram/win11_VARS.fd",
           "Unexpected original UEFI variable store")
    devices=root.find("devices")
    ensure(devices is not None,"No source device list")
    for tag in ("hostdev","filesystem","smartcard","shmem","vsock","crypto"):
        ensure(not devices.findall(tag),"Unreviewed host-connected device: "+tag)
    ensure(not any(node.tag.endswith("}commandline") for node in root.iter()),
           "Unreviewed QEMU extension")
    graphics=root.findall("./devices/graphics")
    ensure(len(graphics)==1 and graphics[0].get("type") in ("spice","vnc"),
           "Unexpected guest graphics configuration")
    for node in graphics:
        node.set("autoport","yes")
        node.set("port","-1")
        node.attrib.pop("tlsPort",None)
        node.attrib.pop("websocket",None)
        node.set("listen","127.0.0.1")
        for listen in node.findall("listen"):
            ensure(listen.get("type") in ("address",None),
                   "Unexpected graphics remote listening mode")
            listen.set("type","address")
            listen.set("address","127.0.0.1")
    for tag in ("interface","redirdev","redirfilter","channel"):
        for element in list(devices.findall(tag)):
            devices.remove(element)
    for label in list(root.findall("./seclabel")):
        root.remove(label)
    root.find("name").text=name
    root.find("uuid").text=identifier
    genid=root.find("genid")
    if genid is not None:
        genid.text=str(uuid.uuid5(uuid.UUID(identifier),"new-windows-genid"))
    src.set("file",str(disk))
    vars.text=str(nvram)
    # Do not inherit unattached Windows installer media from SSL-55.
    for optical in devices.findall("./disk[@device='cdrom']"):
        medium=optical.find("source")
        if medium is not None:optical.remove(medium)
    out=ET.tostring(root,encoding="unicode")
    check=ET.fromstring(out)
    ensure(not check.findall("./devices/interface") and
           not check.findall("./devices/redirdev") and
           not check.findall("./devices/channel") and
           len(check.findall("./devices/tpm"))==1,
           "Detached clone still contains a host-connected device")
    return out

def file_stamp(path):
    ensure(not path.is_symlink() and path.is_file(),
           "Template or firmware file unavailable")
    x=path.stat()
    ensure(stat.S_ISREG(x.st_mode),"Template path not a regular file")
    return (x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)

def preflight():
    ensure(os.geteuid()==0,"Requires sudo on SSL-55")
    ensure(virsh("domstate",VM)=="shut off","Original Windows VM must be shut off")
    ensure(virsh("snapshot-current",VM,"--name")==SNAP,
           "Original cold snapshot changed")
    ensure(NAME not in virsh("list","--all","--name").splitlines(),
           "Disposable clone name is already registered")
    ensure(BACKUP.is_dir() and not BACKUP.is_symlink() and
           BACKUP.stat().st_uid==0 and not BACKUP.stat().st_mode & 0o077,
           "Original preservation backup unavailable")
    saved=(BACKUP/"metadata/domain.xml").read_text()
    current=ET.fromstring(virsh("dumpxml","--inactive",VM))
    ensure(current.findtext("./uuid")==ET.fromstring(saved).findtext("./uuid"),
           "Original VM UUID changed")
    disks=current.findall("./devices/disk[@device='disk']")
    ensure(len(disks)==1 and disks[0].find("source") is not None and
           disks[0].find("source").get("file")==OVERLAY,
           "Maintenance domain is not using known original-TPM overlay")
    snapshot=(BACKUP/("metadata/snapshot-"+SNAP+".xml")).read_text().strip()
    ensure(virsh("snapshot-dumpxml",VM,SNAP)==snapshot,
           "Original snapshot metadata changed")
    ensure(not TEMPLATE.is_symlink() and TEMPLATE.is_file(),
           "Expected plaintext standalone template missing")
    info=json.loads(call("qemu-img","info","--output=json",str(TEMPLATE)))
    ensure(info.get("format")=="qcow2" and
           info.get("virtual-size")==SIZE and
           not info.get("backing-filename") and
           not info.get("full-backing-filename"),
           "Template is not independent 64 GiB QCOW2")
    ensure(TEMPLATE.stat().st_uid==0 and
           not TEMPLATE.stat().st_mode & 0o077,
           "Standalone decrypted template must be root-private")
    try:crypto.require_cleartext_candidate(TEMPLATE)
    except crypto.VolumeProbeError as e:
        raise StageError("Template is not verified plaintext NTFS") from e
    ensure(not DISK.exists() and not DISK.is_symlink() and
           not NVRAM.exists() and not NVRAM.is_symlink(),
           "Trial clone destination already exists; will not overwrite")
    for p in (DISK.parent,NVRAM.parent):
        ensure(p.is_dir() and not p.is_symlink() and
               p.stat().st_uid==0 and not p.stat().st_mode & 0o022,
               "Clone destination folder not root-controlled")
    original_vars=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
    vstat=file_stamp(original_vars)
    ensure(vstat[2] in (540672,131072,262144,1048576),
           "Firmware variables size unexpected")
    ensure(shutil.disk_usage(DISK.parent).free>=SIZE+RESERVE,
           "Less than 94 GiB free; stop before staging clone")
    return saved,original_vars

def stage():
    ensure(not LOCK.is_symlink(),"Unsafe clone/export lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    temporary=None
    published=False
    try:
        st=os.fstat(fd)
        ensure(st.st_uid==0 and not st.st_mode & 0o077,"Unsafe shared lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        saved,original_vars=preflight()
        before=(file_stamp(TEMPLATE),file_stamp(original_vars))
        identifier=str(uuid.uuid4())
        xml=render(saved,identifier=identifier)
        print("PASS: Verified cold standalone plaintext Windows source",flush=True)
        print("PASS: New guest UUID and zero-NIC isolated XML generated",flush=True)
        tmpfd,temporary=tempfile.mkstemp(
            prefix=".cape-win11-trial-",suffix=".qcow2",dir=str(DISK.parent))
        os.close(tmpfd)
        os.unlink(temporary)
        print("Exporting standalone disposable clone disk; may take time...",
              flush=True)
        call("qemu-img","convert","-f","qcow2","-O","qcow2",
             "-o","compat=1.1",str(TEMPLATE),temporary,timeout=7200)
        os.chmod(temporary,0o600)
        call("qemu-img","check","-q","-f","qcow2",temporary,timeout=3600)
        cinfo=json.loads(call("qemu-img","info","--output=json",temporary))
        ensure(cinfo.get("format")=="qcow2" and
               cinfo.get("virtual-size")==SIZE and
               not cinfo.get("backing-filename") and
               not cinfo.get("full-backing-filename"),
               "Disposable clone QCOW2 not independent")
        try:crypto.require_cleartext_candidate(Path(temporary))
        except crypto.VolumeProbeError as e:
            raise StageError("Disposable clone does not have plaintext NTFS") from e
        ensure(virsh("domstate",VM)=="shut off" and
               file_stamp(TEMPLATE)==before[0] and
               file_stamp(original_vars)==before[1],
               "Source or firmware changed during disk copy")
        ensure(not DISK.exists() and not DISK.is_symlink() and
               not NVRAM.exists() and not NVRAM.is_symlink(),
               "Clone destination appeared; abort")
        ensure(shutil.disk_usage(DISK.parent).free>=RESERVE,
               "Host storage reserve too low")
        # Source UEFI boot entries are copied into a distinct file.
        # No original TPM state is ever copied.
        source_info=original_vars.stat()
        destfd=os.open(NVRAM,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        try:
            os.fchown(destfd,source_info.st_uid,source_info.st_gid)
            with os.fdopen(destfd,"wb") as f:
                with original_vars.open("rb") as src:
                    shutil.copyfileobj(src,f)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            NVRAM.unlink(missing_ok=True)
            raise
        os.link(temporary,DISK)
        os.unlink(temporary)
        temporary=None
        published=True
        with tempfile.TemporaryDirectory(prefix="cape-clone-xml-",dir="/run") as tmp:
            definition=Path(tmp)/"trial.xml"
            definition.write_text(xml)
            definition.chmod(0o600)
            print("Registering shut-off zero-NIC disposable clone...",flush=True)
            virsh("define",str(definition),"--validate")
        ensure(virsh("domstate",NAME)=="shut off",
               "Trial clone unexpectedly started; operator review needed")
        parsed=ET.fromstring(virsh("dumpxml","--inactive",NAME))
        ensure(parsed.findtext("uuid")==identifier and
               parsed.findtext("name")==NAME and
               not parsed.findall("./devices/interface") and
               not parsed.findall("./devices/redirdev") and
               not parsed.findall("./devices/channel") and
               len(parsed.findall("./devices/tpm"))==1 and
               parsed.find("./devices/disk[@device='disk']/source") is not None and
               parsed.find("./devices/disk[@device='disk']/source").get("file")==str(DISK) and
               parsed.findtext("./os/nvram")==str(NVRAM),
               "Libvirt clone definition differs from expected, DO NOT BOOT")
        return {"result":"DISPOSABLE_CLONE_STAGED_NOT_BOOTED",
                "vm":NAME,"uuid":identifier,"qcow2":str(DISK),
                "nvram_file":str(NVRAM),"guest_nics":0,
                "guest_tpm_backend":"fresh independent libvirt emulator at first boot",
                "guest_started":False,"ip_personalized":False,
                "agent_verified":False,"master_disk_modified":False,
                "original_tpm_state_copied":False,
                "warning":"Do not boot until pre-start AppArmor and firmware checks"}
    finally:
        if temporary is not None:
            try:Path(temporary).unlink()
            except FileNotFoundError:pass
        if not published:
            # A failed publish may leave a valid clone disk and/or cloned
            # firmware file. Never delete automatically without confirming
            # libvirt did not register or consume them; retain for review.
            pass
        os.close(fd)

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","stage"),default="plan")
    args=parser.parse_args()
    try:
        if args.mode=="plan":
            saved,_=preflight()
            xml=render(saved,identifier=str(uuid.uuid4()))
            print(json.dumps({"mode":"READ_ONLY_PLAN",
                "trial_vm":NAME,"clone_disk":str(DISK),
                "independent_nvram":str(NVRAM),"zero_network_interfaces":True,
                "template_plaintext":True,"copy_performed":False,
                "guest_started":False,"xml_validated_offline":bool(xml)}))
        else:
            print(json.dumps(stage(),sort_keys=True,indent=2))
        return 0
    except (StageError,OSError,ValueError,ET.ParseError) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
