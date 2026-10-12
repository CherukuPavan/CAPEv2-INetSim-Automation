#!/usr/bin/env python3
"""OTHER-host Command2 network-APPROVED replacement ISO for shut-off guest.

After separate verified host isolated-network + NIC approval and Windows
zero-NIC identity initialization, constructs CONFIG-ONLY CAPE_CMD2 optical
media with exact guest-config + SHA256 and network-approved + SHA256.
One existing CD-ROM (currently identity ISO) is updated in SAVED XML only.
No VM start/stop, IP change, NIC attachment, firewall action or sample.
Receipt is recorded operator evidence, NOT independently authenticated.
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
import tempfile
import xml.etree.ElementTree as ET

import command2_portable_guest_identity_iso as identity
import command2_portable_guest_identity_attach as attachment
import command2_guarded_isolated_nic as nic

LOCK=Path("/run/lock/cape-command2-network-approved-media.lock")
VM_RE=re.compile(r"win11_([1-9]|1[0-6])\Z")
GIB=1024**3

class ApprovalBlocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise ApprovalBlocked(msg)

def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def sha(data):return hashlib.sha256(data).hexdigest()
def command(*args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=45)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ApprovalBlocked("Read-only libvirt command failed: "+args[0]) from exc
    need(p.returncode==0,"libvirt read-only command exited nonzero")
    return p.stdout.strip()
def virsh(*args):return command("virsh","-c","qemu:///system",*args)

def trusted_cape_iso(iso,conf):
    media,digest=attachment.media_contents(iso)
    need(media==conf and digest.strip().decode("ascii","replace")==sha(conf),
         "Existing identity ISO does not match exact guest config")

def network_xml(raw,name,uuid,mac,osdisk,old_media):
    root=ET.fromstring(raw)
    need(root.findtext("name")==name and root.findtext("uuid")==uuid,
         "Different saved guest identity")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network")=="cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()==mac,
         "Host-approved NIC changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(osdisk),
         "Guest OS disk no longer independently staged")
    back=disks[0].find("backingStore")
    need(back is None or (back.find("source") is None and
         back.find("backingStore") is None),"Unexpected master backing chain")
    t=root.find("./devices/tpm/backend")
    need(t is not None and t.get("type")=="emulator" and
         t.get("version")=="2.0","Expected swtpm2 missing")
    vars=root.find("./os/nvram")
    need(vars is not None and vars.text and vars.text!=str(osdisk),
         "Expected separate private OVMF NVRAM missing")
    need(not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem") and
         not root.findall("./devices/redirdev"),
         "Unexpected host-connected device")
    cd=root.findall("./devices/disk[@device='cdrom']")
    need(len(cd)==1 and cd[0].find("source") is not None and
         cd[0].find("source").get("file")==str(old_media) and
         cd[0].find("readonly") is not None,
         "Optical media differs from original approved identity ISO")
    target=cd[0].find("target")
    need(target is not None and re.fullmatch(
         r"(?:sd[a-z]|hd[a-d]|vd[a-z])",target.get("dev","")),
         "Unexpected optical target")
    return target.get("dev")

def checked_inputs(host,vm,journal,receipt):
    try: identity.host_guard(host)
    except identity.MediaBlocked as exc:raise ApprovalBlocked(str(exc)) from exc
    need(VM_RE.fullmatch(vm or "") is not None,
         "Only approved Command2 names win11_1..16 supported")
    folder=identity.guarded_dir(Path(journal).parent)
    need(Path(journal).name=="command2-identity-reservation.json",
         "Untrusted reservation path")
    reservation=identity.read_json(journal)
    idx=int(VM_RE.fullmatch(vm).group(1))-1
    rows=reservation.get("entries")
    need(reservation.get("format")=="CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION"
         and reservation.get("version")==1 and reservation.get("host")==host
         and type(rows) is list and type(reservation.get("guest_count")) is int
         and len(rows)==reservation["guest_count"] and idx<len(rows) and
         type(rows[idx]) is dict and rows[idx].get("libvirt_name")==vm,
         "Unknown per-VM reservation for this host")
    row=rows[idx]
    original=folder/("command2-guest-config-"+vm+".json")
    attachment.safe_root_file(original,128*1024)
    config=original.read_bytes()
    data=json.loads(config)
    expected=identity.guestconfig.make_guest_config(
        row,identity.ip_prefix_from_config(data))
    need(config==identity.render_config(expected) and
         expected["auto_apply_network"] is False and
         expected["default_gateway"] is None and
         expected["guest_network_interface_attached"] is False,
         "Unreviewed guest config or network auto-approval")
    uid=row["libvirt_uuid_candidate"];mac=row["mac_candidate"]
    try:
        accepted=nic.read_acceptance_receipt(
            str(receipt),vm,uid,mac,row["guest_static_ipv4_target"],host)
    except (nic.NicBlocked,OSError,ValueError) as exc:
        raise ApprovalBlocked("Exact separate-host isolation acceptance missing") from exc
    need(accepted is True,"Guest network acceptance proof missing")
    disk=Path(row["disk_target"])
    need(disk.is_file() and not disk.is_symlink() and
         disk.name==vm+".command2.qcow2",
         "Independent staged system disk missing")
    oldiso=disk.parent/(vm+".command2_identity.iso")
    output=disk.parent/(vm+".command2_network_approved.iso")
    need(oldiso.is_file() and not oldiso.is_symlink() and
         not output.exists() and not output.is_symlink(),
         "Existing identity optical media missing, or approved media already exists")
    trusted_cape_iso(oldiso,config)
    need(virsh("domuuid",vm).lower()==uid and
         virsh("domstate",vm).lower()=="shut off",
         "Exact candidate VM must be shut off")
    optical=network_xml(virsh("dumpxml","--inactive",vm),vm,uid,mac,disk,oldiso)
    need(shutil.which("genisoimage") and shutil.which("isoinfo"),
         "ISO builder/inspection dependencies missing")
    statv=os.statvfs(disk.parent)
    need(statv.f_bavail*statv.f_frsize>=40*GIB+8*1024**2,
         "Cannot maintain shared-host storage reserve")
    approval={"format":"COMMAND2_HOST_NETWORK_APPROVAL_V1",
              "guest_uuid":uid,"guest_name":vm,"guest_mac":mac,
              "host_ipv4_negative_egress_verified":True,
              "host_ipv6_negative_egress_verified":True,
              "reboot_persistence_verified":True,
              "guest_l2_separation_verified":True}
    return {"result":"COMMAND2_NETWORK_APPROVAL_MEDIA_PLAN_ONLY",
            "vm":vm,"uid":uid,"host":host,
            "original_iso":str(oldiso),"approved_iso":str(output),
            "cdrom_target":optical,"config_sha256":sha(config),
            "approval_bytes_sha256":sha(canonical(approval)),
            "future_ip":row["guest_static_ipv4_target"],
            "prior_isolation_acceptance_receipt_recorded":True,
            "guest_config_network_autoapply":False,
            "guest_running":False,"approved_media_created":False,
            "network_or_guest_modified":False}

def apply(host,vm,journal,receipt):
    need(sys.stdin.isatty(),"Operator terminal required")
    before=checked_inputs(host,vm,journal,receipt)
    print(json.dumps(before,sort_keys=True,indent=2),flush=True)
    phrase="INSERT-APPROVED-NETWORK-CONFIG-"+vm.upper()
    need(input("Type "+phrase+" to update ONLY saved guest optical media: ")==phrase,
         "Operator did not approve")
    need(not LOCK.is_symlink(),"Unsafe lock symlink")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe root-only lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise ApprovalBlocked("Another media operation active") from exc
        need(checked_inputs(host,vm,journal,receipt)==before,
             "Guest/receipt/media changed before approved apply")
        folder=Path(journal).parent
        config=(folder/("command2-guest-config-"+vm+".json")).read_bytes()
        data=json.loads(config)
        approval={"format":"COMMAND2_HOST_NETWORK_APPROVAL_V1",
                  "guest_uuid":before["uid"],"guest_name":vm,
                  "guest_mac":data["nic_mac"],
                  "host_ipv4_negative_egress_verified":True,
                  "host_ipv6_negative_egress_verified":True,
                  "reboot_persistence_verified":True,
                  "guest_l2_separation_verified":True}
        payload=canonical(approval)
        need(sha(payload)==before["approval_bytes_sha256"],
             "Network approval fields differ")
        disk=Path(json.loads(Path(journal).read_text())["entries"][
                  int(VM_RE.fullmatch(vm).group(1))-1]["disk_target"])
        dest=Path(before["approved_iso"])
        with tempfile.TemporaryDirectory(prefix=".cape-net-iso-",dir=str(disk.parent)) as td:
            work=Path(td);src=work/"contents"
            src.mkdir(mode=0o700)
            (src/"guest-config.json").write_bytes(config)
            (src/"guest-config.sha256").write_text(sha(config)+"\n")
            (src/"network-approved.json").write_bytes(payload)
            (src/"network-approved.sha256").write_text(sha(payload)+"\n")
            temp=work/"optical.iso"
            p=subprocess.run(["genisoimage","-quiet","-J","-R","-V",
                              "CAPE_CMD2","-o",str(temp),str(src)],
                             capture_output=True,timeout=120)
            need(p.returncode==0 and temp.is_file() and
                 2048<=temp.stat().st_size<4*1024**2,
                 "Failed to build bounded network approval media")
            with temp.open("rb") as inp:
                dfd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
                with os.fdopen(dfd,"wb") as out:
                    shutil.copyfileobj(inp,out)
                    out.flush();os.fsync(out.fileno())
                    st=disk.stat()
                    os.fchown(out.fileno(),st.st_uid,st.st_gid)
        need(virsh("domstate",vm).lower()=="shut off",
             "VM started during ISO build; preserve status")
        need(virsh("domuuid",vm).lower()==before["uid"],
             "VM identity changed during ISO build")
        # ONLY saved CD-ROM change; no guest/network state changes.
        try:
            virsh("change-media",vm,before["cdrom_target"],str(dest),
                  "--update","--config")
        except ApprovalBlocked as exc:
            raise ApprovalBlocked("ISO created but libvirt media update failed; inspect, do not retry") from exc
        root=ET.fromstring(virsh("dumpxml","--inactive",vm))
        optical=root.findall("./devices/disk[@device='cdrom']/source")
        need(len(optical)==1 and optical[0].get("file")==str(dest) and
             virsh("domstate",vm).lower()=="shut off",
             "Saved CD-ROM media update not verified")
        return {"result":"COMMAND2_APPROVED_NETWORK_MEDIA_SAVED_NOT_BOOTED",
                "vm":vm,"iso":str(dest),"iso_sha256":sha(dest.read_bytes()),
                "guest_booted":False,"windows_static_ip_applied":False,
                "host_network_modified":False,"master_modified":False,
                "requires_next_guest_personalization_verification":True}
    finally:os.close(fd)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--mode",choices=("plan","apply"),default="plan")
    ap.add_argument("--approved-host",required=True)
    ap.add_argument("--vm",required=True)
    ap.add_argument("--journal",type=Path,required=True)
    ap.add_argument("--receipt",type=Path,required=True)
    a=ap.parse_args()
    try:
        data=checked_inputs(a.approved_host,a.vm,a.journal,a.receipt) if a.mode=="plan" else apply(
            a.approved_host,a.vm,a.journal,a.receipt)
        print(json.dumps(data,indent=2,sort_keys=True))
        return 0
    except (ApprovalBlocked,identity.MediaBlocked,attachment.AttachBlocked,
            ValueError,TypeError,OSError,ET.ParseError,subprocess.TimeoutExpired) as exc:
        print(json.dumps({"result":"COMMAND2_APPROVED_NETWORK_MEDIA_BLOCKED",
                          "reason":str(exc),"guest_network_changed":False},indent=2),file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
