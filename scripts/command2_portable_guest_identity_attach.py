#!/usr/bin/env python3
"""Approved OTHER-host identity ISO placement + CONFIG-ONLY CD-ROM insertion.

Exactly one staged, shut-off, ZERO-NIC guest. This component cannot boot,
attach network, change firewall or give Windows network approval.
A trusted Windows startup bootstrap must already exist in the master.
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

import command2_guest_identity_blueprint as unused_blueprint  # schema imported from reservation helper
import command2_portable_guest_identity_iso as identity

GIB=1024**3
LOCK=Path("/run/lock/cape-command2-identity-attach.lock")
SAFE_VM=re.compile(r"win11_([1-9]|1[0-6])\Z")
class AttachBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise AttachBlocked(why)

def sha(data):
    return hashlib.sha256(data).hexdigest()
def cmd(*args):
    try:
        p=subprocess.run(args,capture_output=True,timeout=45,check=False)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise AttachBlocked("Host utility failed: "+args[0]) from exc
    need(p.returncode==0,"Host utility returned failure: "+args[0])
    return p.stdout.decode("utf-8","replace").strip()
def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)

def safe_root_file(path,limit):
    p=Path(path)
    need(p.is_absolute() and not p.is_symlink() and p.is_file(),
         "Input file missing or symlinked")
    s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and
         s.st_nlink==1 and 0<s.st_size<=limit and
         stat.S_IMODE(s.st_mode)&0o077==0,
         "Input file ownership/size/permissions unexpected")
    return s

def media_contents(iso):
    # ISO data must agree with the already-staged exact guest JSON, not only
    # with a hash of an arbitrarily substituted ISO image.
    def extract(name):
        try:
            p=subprocess.run(["isoinfo","-R","-i",str(iso),"-x",name],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                check=False)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise AttachBlocked("Cannot inspect prepared identity ISO") from exc
        need(p.returncode==0 and len(p.stdout)<128*1024,
             "Unreadable or oversized ISO content: "+name)
        return p.stdout
    return extract("/guest-config.json"),extract("/guest-config.sha256")

def xml_gate(raw,vm,uid,disk):
    r=ET.fromstring(raw)
    need(r.tag=="domain" and r.findtext("name")==vm and
         r.findtext("uuid")==uid,"Different/unknown libvirt guest")
    need(not r.findall("./devices/interface") and
         not r.findall("./devices/hostdev") and
         not r.findall("./devices/filesystem"),
         "Unexpected guest NIC or host passthrough")
    disks=r.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(disk),
         "Guest OS disk is not reserved private clone")
    b=disks[0].find("backingStore")
    need(b is None or (b.find("source") is None and
         b.find("backingStore") is None),"Guest disk has master backing chain")
    optical=r.findall("./devices/disk[@device='cdrom']")
    need(len(optical)==1 and optical[0].find("source") is None and
         optical[0].find("readonly") is not None,
         "Exactly one empty read-only optical drive required")
    target=optical[0].find("target")
    need(target is not None and
         re.fullmatch(r"(?:sd[a-z]|hd[a-d]|vd[a-z])",target.get("dev","")),
         "Unrecognized optical target")
    return target.get("dev")

def plan(host,vm,journal):
    try: identity.host_guard(host)
    except identity.MediaBlocked as exc: raise AttachBlocked(str(exc)) from exc
    need(type(vm) is str and SAFE_VM.fullmatch(vm) is not None,
         "Only current portable Command2 win11_1..16 allowed")
    journal=Path(journal)
    need(journal.is_absolute() and
         journal.name=="command2-identity-reservation.json",
         "Exact reservation journal required")
    identity.guarded_dir(journal.parent)
    reservation=identity.read_json(journal)
    need(reservation.get("format")=="CAPE_COMMAND2_GUEST_IDENTITY_RESERVATION"
         and reservation.get("version")==1 and reservation.get("host")==host
         and reservation.get("host_network_modified") is False,
         "Identity reservation journal differs from host")
    rows=reservation.get("entries")
    idx=int(SAFE_VM.fullmatch(vm).group(1))-1
    need(type(rows) is list and type(reservation.get("guest_count")) is int
         and len(rows)==reservation["guest_count"] and
         idx<len(rows) and type(rows[idx]) is dict and
         rows[idx].get("libvirt_name")==vm,
         "Exact VM not in ordered journal")
    row=rows[idx]
    uid=row.get("libvirt_uuid_candidate")
    disk=Path(row.get("disk_target",""))
    iso=journal.parent/(vm+".command2_identity.iso")
    config=journal.parent/("command2-guest-config-"+vm+".json")
    safe_root_file(iso,4*1024**2)
    safe_root_file(config,128*1024)
    content=config.read_bytes()
    archived,checksum=media_contents(iso)
    need(archived==content and checksum.strip().decode("ascii","replace")==
         sha(content),"Guest optical ISO content differs from reserved JSON")
    expected=identity.guestconfig.make_guest_config(
        row,identity.ip_prefix_from_config(json.loads(content)))
    need(content==identity.render_config(expected) and
         expected["expected_machine_uuid"]==uid and
         expected["guest_network_interface_attached"] is False and
         expected["auto_apply_network"] is False,
         "ISO does not contain canonical zero-NIC guest configuration")
    need(virsh("domuuid",vm).lower()==uid and
         virsh("domstate",vm).lower()=="shut off",
         "Unexpected VM UUID or running VM")
    optical=xml_gate(virsh("dumpxml","--inactive",vm),vm,uid,disk)
    need(disk.is_absolute() and disk.name==vm+".command2.qcow2"
         and disk.is_file() and not disk.is_symlink(),
         "Missing independent clone disk")
    target=disk.parent/(vm+".command2_identity.iso")
    need(not target.exists() and not target.is_symlink(),
         "Previously inserted/media artifact exists: do not overwrite")
    st=disk.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1,
         "Unexpected staged guest disk file")
    storage=disk.parent
    need(storage.is_dir() and not storage.is_symlink() and
         os.statvfs(storage).f_bavail*os.statvfs(storage).f_frsize>
         40*GIB+4*1024**2,"Not enough shared-host reserve for identity ISO")
    need(iso.resolve()!=target.resolve(),
         "Refuse source=destination optical media")
    return {"result":"COMMAND2_IDENTITY_ATTACH_PLAN_ONLY",
            "vm":vm,"uid":uid,"guest_disk":str(disk),
            "journal_iso":str(iso),"config_sha256":sha(content),
            "journal_iso_sha256":sha(iso.read_bytes()),
            "libvirt_iso_target":str(target),"cdrom_target":optical,
            "source_vm_shut_off":True,"clone_zero_nic":True,
            "guest_running":False,"iso_inserted":False,
            "guest_network_authorized":False}

def apply(host,vm,journal):
    need(sys.stdin.isatty(),"Interactive operator TTY required")
    initial=plan(host,vm,journal)
    phrase="ATTACH-IDENTITY-ISO-"+vm.upper()
    need(input("Type "+phrase+" for CONFIG-only ISO attach to shut-off "+vm+": ")
         ==phrase,"Operator did not approve optical-only update")
    need(not LOCK.is_symlink(),"Unsafe serialization lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "Unsafe operation lock")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AttachBlocked("Another identity-ISO operation active") from exc
        need(plan(host,vm,journal)==initial,
             "Host/VM/ISO changed after operator approval")
        disk=Path(initial["guest_disk"])
        iso=Path(initial["journal_iso"])
        target=Path(initial["libvirt_iso_target"])
        ds=disk.stat()
        src=iso.read_bytes()
        destfd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                       0o600)
        with os.fdopen(destfd,"wb") as out:
            out.write(src)
            out.flush();os.fsync(out.fileno())
            os.fchown(out.fileno(),ds.st_uid,ds.st_gid)
            os.fchmod(out.fileno(),0o640)
        need(sha(target.read_bytes())==initial["journal_iso_sha256"],
             "Libvirt media copy differs; preserve file for inspection")
        need(virsh("domuuid",vm).lower()==initial["uid"] and
             virsh("domstate",vm).lower()=="shut off",
             "Guest state changed since media staging")
        xml_gate(virsh("dumpxml","--inactive",vm),vm,initial["uid"],disk)
        # Existing empty CD-ROM ONLY. --config modifies saved XML, never runs guest.
        try:
            virsh("change-media",vm,initial["cdrom_target"],str(target),
                  "--insert","--config")
        except AttachBlocked as exc:
            raise AttachBlocked("Media copied, but CD-ROM change failed/partial. "
                                "Preserve new ISO and inspect; no blind retry") from exc
        root=ET.fromstring(virsh("dumpxml","--inactive",vm))
        cd=root.findall("./devices/disk[@device='cdrom']")
        need(len(cd)==1 and cd[0].find("source") is not None and
             cd[0].find("source").get("file")==str(target) and
             len(root.findall("./devices/interface"))==0,
             "Guest saved optical/media definition did not match")
        need(virsh("domstate",vm).lower()=="shut off",
             "Guest unexpectedly started during optical attach")
        return {"result":"COMMAND2_IDENTITY_ISO_ATTACHED_SHUTOFF_ZERO_NIC",
                "vm":vm,"iso":str(target),"iso_sha256":sha(src),
                "guest_booted":False,"windows_personalized":False,
                "network_configured":False,"tpm_snapshot_created":False,
                "requires_verified_template_bootstrap":True}
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","attach"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--vm",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        answer=plan(a.approved_host,a.vm,a.journal) if a.mode=="plan" else apply(
            a.approved_host,a.vm,a.journal)
        print(json.dumps(answer,indent=2,sort_keys=True))
        return 0
    except (AttachBlocked,identity.MediaBlocked,identity.guestconfig.GuestConfigBlocked,
            ValueError,TypeError,OSError,ET.ParseError,IndexError) as exc:
        print(json.dumps({"result":"COMMAND2_IDENTITY_ATTACH_BLOCKED",
                          "reason":str(exc),
                          "no_guest_start_or_network_mutation":True},
                         indent=2),file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
