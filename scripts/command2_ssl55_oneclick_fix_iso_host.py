#!/usr/bin/env python3
"""SSL55 install ONLY a reviewed one-click Windows guest-fix optical ISO.

Existing win11_1 stays running. No network changes, VM boot, malware,
new VMs/disks or guest commands. Replaces only existing sdb DIAG ISO
with exact one-click Windows FIX ISO after inspecting protected host.
Windows user explicitly approves benign-IP changes separately.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
MAC="02:0a:30:6a:3f:50"
MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
ROOT=Path("/var/lib/libvirt/images/cape-clones-staging")
OLD=ROOT/"win11_1.command2_diagnostics.iso"
NEW=ROOT/"win11_1.command2_safe_fix.iso"
EXPECTED_DISK=ROOT/"win11_1.command2.qcow2"
EXPECTED_NVRAM="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
SOURCES={
    "command2_ssl55_win11_1_oneclick_guest_fix.ps1":
    "a1827b96f4f1c5d2a42a9153ba6cfa00131b49a7",
    "command2_ssl55_win11_1_oneclick_SETUP.cmd":
    "844bb9926bf9c8c2052e9267accec3ed2e40542a",
}
PHRASE="INSTALL-ONECLICK-WIN11-1-ISO"


class OpticalBlocked(RuntimeError):
    pass


def need(test,why):
    if not test:raise OpticalBlocked(why)


def command(*args,timeout=30):
    try:
        p=subprocess.run(args,capture_output=True,text=True,
                         check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise OpticalBlocked("Host command unavailable: "+args[0]) from exc
    need(p.returncode==0,"Host command failed: "+args[0])
    return p.stdout.strip()


def virsh(*args):
    return command("virsh","-c","qemu:///system",*args)


def git_blob(data):
    return hashlib.sha1(
        b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def checked_source(path):
    p=Path(path)
    need(p.is_absolute() and p.is_dir() and not p.is_symlink(),
         "Missing trusted source folder")
    need(not p.stat().st_mode & 0o022,
         "Staging folder writable by other users")
    blobs={}
    for filename,want in SOURCES.items():
        file=p/filename
        need(file.is_file() and not file.is_symlink(),"Missing approved source "+filename)
        st=file.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             not st.st_mode & 0o022 and st.st_size<65536,
             "Source unsafe ownership/mode or size: "+filename)
        buf=file.read_bytes()
        need(git_blob(buf)==want,
             "Pinned Git source checksum mismatch: "+filename)
        blobs[filename]=buf
    return blobs


def vm_xml(xml,current_vm):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==current_vm,
         "Wrong libvirt guest domain")
    if current_vm!=VM:
        uid=MASTER_UUID if current_vm=="win11" else TRIAL_UUID
        need(root.findtext("uuid")==uid and
             len(root.findall("./devices/interface"))==(
                 1 if current_vm=="win11" else 0),
             "Protected master/trial NIC or UUID differs")
        return True
    need(root.findtext("uuid")==UUID,"Wrong clone UUID")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network",
         "Clone must have exactly one network NIC")
    nic=nics[0]
    src=nic.find("source");mac=nic.find("mac");model=nic.find("model")
    need(src is not None and src.get("network")=="cape-analysis-isolated" and
         mac is not None and mac.get("address","").lower()==MAC and
         model is not None and model.get("type")=="e1000e",
         "Guest MAC, model or attached network changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(EXPECTED_DISK) and
         root.findtext("./os/nvram")==EXPECTED_NVRAM and
         root.find("./devices/tpm/backend") is not None,
         "Unexpected original independent disk/UEFI/TPM configuration")
    optical=root.findall("./devices/disk[@device='cdrom']")
    need(len(optical)==1 and optical[0].find("target") is not None and
         optical[0].find("target").get("dev")=="sdb" and
         optical[0].find("source") is not None and
         optical[0].find("source").get("file")==str(OLD),
         "CD-ROM not currently displaying the expected diag ISO")
    return True


def preflight(staging):
    need(os.geteuid()==0,"Run protected inspection with sudo")
    host=socket.gethostname().split(".",1)[0].lower()
    need(host in ("ssl-55","cse-ssl-55") and
         SENTINEL.is_dir() and not SENTINEL.is_symlink(),
         "Not protected SSL55 reference host")
    blobs=checked_source(staging)
    need(ROOT.is_dir() and not ROOT.is_symlink() and
         OLD.is_file() and not OLD.is_symlink() and
         not NEW.exists() and not NEW.is_symlink(),
         "Expected pre-existing diagnostic ISO or empty destination missing")
    need(virsh("domuuid",VM)==UUID and
         virsh("domstate",VM).strip()=="running",
         "Expected protected running win11_1")
    need(virsh("list","--name").splitlines()==[VM],
         "Unexpected extra running libvirt VM")
    for guest in ("win11","win11_trial_1"):
        need(virsh("domstate",guest).strip()=="shut off",
             "Protected original/trial running unexpectedly")
        vm_xml(virsh("dumpxml","--inactive",guest),guest)
    for mode in ("--inactive",None):
        args=("dumpxml","--inactive",VM) if mode else ("dumpxml",VM)
        vm_xml(virsh(*args),VM)
    net=ET.fromstring(virsh("net-dumpxml","cape-analysis-isolated"))
    port=net.find("port")
    bridge=net.find("bridge")
    dns=net.find("dns")
    ips=net.findall("ip")
    need(net.findtext("name")=="cape-analysis-isolated" and
         bridge is not None and bridge.get("name")=="cape-lab0" and
         port is not None and port.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         net.find("forward") is None and
         not net.findall(".//dhcp") and
         len(ips)==1 and ips[0].get("address")=="192.168.240.1" and
         ips[0].get("netmask")=="255.255.255.0",
         "Unexpected CAPE libvirt isolation network")
    info=virsh("net-info","cape-analysis-isolated").lower()
    need("active:     yes" in info or
         any(x.strip()=="active: yes" for x in info.splitlines()),
         "Isolated network unexpectedly inactive")
    need(command("systemctl","is-active","cape-analysis-guard.service")=="active" and
         command("systemctl","is-enabled","nftables.service")=="disabled",
         "CAPE guard or host general nftables baseline changed")
    command("nft","list","table","inet","cape_analysis_guard")
    need(shutil.which("genisoimage") is not None,
         "Host ISO generator missing")
    return {"result":"SSL55_WIN11_1_ONECLICK_ISO_PLAN_ONLY",
            "source_git_blobs":{k:git_blob(v) for k,v in blobs.items()},
            "clone_uuid":UUID,"mac":MAC,
            "current_media":str(OLD),"candidate_media":str(NEW),
            "windows_previous_ipv4_observed":"192.168.122.125/24",
            "expected_ipv4":"192.168.240.101/24",
            "running_vm":VM,"host_changes":False,
            "windows_changed":False,"malware_authorized":False}


def apply(staging):
    need(sys.stdin.isatty(),"Direct interactive terminal required")
    initial=preflight(staging)
    need(input("Type "+PHRASE+" to replace ONLY win11_1 CD-ROM: ")==PHRASE,
         "Operator declined benign optical insertion")
    need(preflight(staging)==initial,
         "Host changed since reviewed preflight")
    sources=checked_source(staging)
    with tempfile.TemporaryDirectory(prefix="cape-ssl55-iso-",dir="/run") as temp:
        t=Path(temp)
        ps=sources["command2_ssl55_win11_1_oneclick_guest_fix.ps1"]
        batch=sources["command2_ssl55_win11_1_oneclick_SETUP.cmd"]
        expected=hashlib.sha256(ps).hexdigest().upper().encode()
        need(batch.count(b"__PS_SHA256__")==1,
             "Windows launcher expected checksum placeholder missing")
        (t/"FIX.PS1").write_bytes(ps)
        (t/"SETUP.CMD").write_bytes(batch.replace(b"__PS_SHA256__",expected))
        command("genisoimage","-quiet","-J","-R","-V","CAPE_FIX",
                "-o",str(t/"candidate.iso"),str(t))
        candidate=t/"candidate.iso"
        need(candidate.is_file() and candidate.stat().st_size<10485760,
             "Candidate ISO missing or unexpectedly large")
        fd=os.open(NEW,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        try:
            with os.fdopen(fd,"wb") as output,candidate.open("rb") as inp:
                shutil.copyfileobj(inp,output,1024*1024)
                output.flush();os.fsync(output.fileno())
            os.chmod(NEW,0o644)
        except Exception as exc:
            raise OpticalBlocked("Partial new ISO may exist: STOP: "+str(exc)) from exc
        # The single VM media update is not Windows code execution.
        virsh("change-media",VM,"sdb",str(NEW),
              "--update","--live","--config")
    for mode in ("live","saved"):
        xml=virsh("dumpxml",VM) if mode=="live" else virsh(
            "dumpxml","--inactive",VM)
        root=ET.fromstring(xml)
        need(root.findtext("uuid")==UUID and
             len(root.findall("./devices/interface"))==1 and
             root.find("./devices/disk[@device='cdrom']/source") is not None and
             root.find("./devices/disk[@device='cdrom']/source").get("file")==str(NEW),
             "CD-ROM postcondition FAILED; do not rerun")
    need(virsh("domstate",VM).strip()=="running" and
         virsh("domstate","win11").strip()=="shut off" and
         virsh("domstate","win11_trial_1").strip()=="shut off",
         "VM state unexpectedly changed")
    return {"result":"SSL55_WIN11_1_ONECLICK_FIX_ISO_INSERTED",
            "guest_running":True,"media":str(NEW),
            "original_cd_iso_preserved":True,
            "windows_configuration_applied":False,
            "analysis_authorized":False,
            "next":"In win11_1 Explorer, open CAPE_FIX CD and double-click SETUP.CMD; if asked approve UAC and type YES. Screenshot Notepad."}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","apply"),default="plan")
    ap.add_argument("--staging-dir",type=Path,required=True)
    args=ap.parse_args()
    try:
        result=preflight(args.staging_dir) if args.mode=="plan" else apply(args.staging_dir)
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (OpticalBlocked,OSError,ValueError,TypeError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
