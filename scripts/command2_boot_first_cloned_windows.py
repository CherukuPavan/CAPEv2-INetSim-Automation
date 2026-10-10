#!/usr/bin/env python3
"""Guarded first BENIGN boot of host-staged win11_1, with ZERO NICs.

Strictly SSL-55 acceptance: expects the UUID and independent paths from the
operator's actual Command2A clone report. Performs plan or apply, never
modifies the original master, its qcow2 chain, CAPE, nftables or networking.
Apply may install a narrow clone-only AppArmor swtpm socket rule, then starts
win11_1 paused, validates the live XML, and resumes it for Windows boot.
OS desktop/agent status must subsequently be checked INSIDE Windows.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

import guard_vm_tpm_socket as tpm

NAME="win11_1"
IDENT="732b2256-ee99-41fa-881d-fbf5c476d960"
DISK=Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd")
TEMPLATE=Path("/var/lib/libvirt/images/cape-clones-staging/win11_decrypted_template.qcow2")
ORIGINAL_NVRAM=Path("/var/lib/libvirt/qemu/nvram/win11_VARS.fd")
MASTER="win11"
MASTER_UUID="289d89be-68ec-4c62-90e1-ea930849266f"
MASTER_DISK="/var/lib/libvirt/images/win11.cape-bitlocker-maintenance.qcow2"
MASTER_SNAP="finalshutoffversion"
BACKUP=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")
TRIAL="win11_trial_1"
TRIAL_UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
NETWORK="cape-analysis-isolated"
FORBIDDEN=("interface","redirdev","redirfilter","channel","hostdev",
           "filesystem","smartcard","shmem","vsock","crypto")
RESERVE_KIB=3*1024*1024

class BootBlocked(RuntimeError):pass

def need(ok,msg):
    if not ok:raise BootBlocked(msg)

def execute(*args,timeout=120):
    try:
        proc=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BootBlocked("Host command could not execute: "+args[0]) from exc
    need(proc.returncode==0,"Host command failed: "+args[0]+
         " (exit="+str(proc.returncode)+")")
    return proc.stdout.strip()

def virsh(*args):
    return execute("virsh","-c","qemu:///system",*args)

def safe_file(path):
    need(path.is_file() and not path.is_symlink(),
         "Missing or symlinked file: "+path.name)
    st=path.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
         not st.st_mode&0o077,"File not root-private: "+path.name)
    return st

def check_disk():
    for p in (DISK,TEMPLATE):
        safe_file(p)
    nv=safe_file(NVRAM)
    orig=safe_file(ORIGINAL_NVRAM)
    for other in (TEMPLATE,ORIGINAL_NVRAM):
        st=other.stat()
        target=DISK.stat() if other==TEMPLATE else nv
        need((st.st_dev,st.st_ino)!=(target.st_dev,target.st_ino),
             "Clone disk or NVRAM aliases protected original")
    need(nv.st_size==orig.st_size,
         "Clone NVRAM size differs from master")
    image=json.loads(execute("qemu-img","info","--output=json",str(DISK)))
    need(image.get("format")=="qcow2" and
         image.get("virtual-size")==64*1024**3 and
         not image.get("backing-filename") and
         not image.get("full-backing-filename"),
         "Clone is not an independent 64-GiB QCOW2")
    execute("qemu-img","check","-q","-f","qcow2",str(DISK),timeout=3600)
    return True

def check_xml(content,live=False):
    root=ET.fromstring(content)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==NAME and root.findtext("uuid")==IDENT,
         "Clone UUID/name or hypervisor changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and
         disks[0].get("type")=="file" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==str(DISK) and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Clone disk path or format changed")
    need(root.findtext("./os/nvram")==str(NVRAM),
         "Clone firmware path changed")
    tpms=root.findall("./devices/tpm")
    need(len(tpms)==1,"Exactly one cloned TPM expected")
    be=tpms[0].find("backend")
    need(be is not None and be.get("type")=="emulator" and
         be.get("version")=="2.0",
         "Clone TPM backend differs from expected emulator v2")
    source=be.find("source")
    if source is not None:
        sock=source.get("path","")
        need(sock.startswith("/run/libvirt/qemu/swtpm/") and
             "-win11_1-swtpm.sock" in sock and
             "-win11-swtpm.sock" not in sock,
             "Clone TPM socket aliases unrelated libvirt instance")
    for tag in FORBIDDEN:
        need(not root.findall("./devices/"+tag),
             "Clone acquired forbidden host/network device: "+tag)
    need(not any(x.tag.endswith("}commandline") for x in root.iter()),
         "Unreviewed QEMU command-line extensions")
    graphics=root.findall("./devices/graphics")
    need(len(graphics)==1 and
         graphics[0].get("type") in ("spice","vnc") and
         graphics[0].get("listen") in ("127.0.0.1","::1"),
         "Guest display not bound to loopback")
    for listener in graphics[0].findall("listen"):
        need(listener.get("type")=="address" and
             listener.get("address") in ("127.0.0.1","::1"),
             "Guest display listener is not loopback-only")
    if live:
        need(root.find("./devices/emulator") is not None,
             "Live QEMU emulator path missing")
    return root

def check_master_and_trial():
    need(virsh("domstate",MASTER)=="shut off",
         "Original master started")
    need(virsh("domuuid",MASTER)==MASTER_UUID,
         "Original master UUID changed")
    need(virsh("snapshot-current",MASTER,"--name")==MASTER_SNAP,
         "Original master snapshot pointer changed")
    need(BACKUP.is_dir() and not BACKUP.is_symlink() and
         BACKUP.stat().st_uid==0 and
         not BACKUP.stat().st_mode&0o077,
         "Original backup is not protected")
    old=ET.fromstring((BACKUP/"metadata/domain.xml").read_text())
    master=ET.fromstring(virsh("dumpxml","--inactive",MASTER))
    need(master.findtext("uuid")==old.findtext("uuid")==MASTER_UUID,
         "Master XML identity changed")
    source=master.find("./devices/disk[@device='disk']/source")
    need(source is not None and source.get("file")==MASTER_DISK,
         "Original Windows domain disk changed")
    need(virsh("snapshot-dumpxml",MASTER,MASTER_SNAP)==
         (BACKUP/("metadata/snapshot-"+MASTER_SNAP+".xml")).read_text().strip(),
         "Original snapshot metadata changed")
    need(virsh("domstate",TRIAL)=="running" and
         virsh("domuuid",TRIAL)==TRIAL_UUID,
         "Previously verified no-NIC trial changed state/identity")
    for args in (("dumpxml",TRIAL),("dumpxml","--inactive",TRIAL)):
        trial=ET.fromstring(virsh(*args))
        need(not trial.findall("./devices/interface"),
             "Trial clone unexpectedly connected to network")
    state=virsh("net-info",NETWORK)
    need(re.search(r"^Active:\s+no\s*$",state,re.M|re.I) is not None and
         re.search(r"^Autostart:\s+no\s*$",state,re.M|re.I) is not None,
         "Analysis network became active or autostarted")

def memory_ready(inactive):
    memory=inactive.find("./memory")
    need(memory is not None and memory.get("unit","KiB")=="KiB" and
         memory.text and memory.text.isdecimal(),
         "Unexpected clone memory allocation")
    available=Path("/proc/meminfo").read_text()
    match=re.search(r"^MemAvailable:\s+(\d+)\s+kB",available,re.M)
    need(match is not None and
         int(match.group(1))>=int(memory.text)+RESERVE_KIB,
         "Insufficient host RAM to boot an additional Windows VM")

def preflight():
    need(os.geteuid()==0,"Run as root with sudo")
    check_master_and_trial()
    need(virsh("domstate",NAME)=="shut off" and
         virsh("domuuid",NAME)==IDENT,
         "New Command 2A clone must be registered and shut off")
    inactive=check_xml(virsh("dumpxml","--inactive",NAME))
    check_disk()
    memory_ready(inactive)
    status=tpm.prepare(NAME,IDENT,apply=False)
    need(status["status"] in ("PRESENT","WOULD_CREATE"),
         "Unexpected per-clone AppArmor policy")
    return {"result":"COMMAND2A_FIRST_BOOT_PREFLIGHT_PASSED",
            "clone":NAME,"uuid":IDENT,"guest_nics":0,
            "master_unchanged":True,"trial_untouched":True,
            "analysis_network_inactive":True,
            "tpm_rule_plan":status["status"],
            "windows_boot_verified":False}

def boot():
    report=preflight()
    # This changes ONLY the named clone's swtpm socket AppArmor include.
    guard=tpm.prepare(NAME,IDENT,apply=True)
    need(guard["status"] in ("INSTALLED","ALREADY_PRESENT"),
         "Clone TPM AppArmor preparation did not pass")
    # The newly changed policy is on a shutoff clone, and its XML still
    # cannot carry traffic due to zero NICs. Re-run all gates before start.
    preflight()
    print("PASS: master preserved, trial online but zero NIC, new clone independent",
          flush=True)
    print("PASS: exact per-clone TPM AppArmor rule validated",flush=True)
    virsh("start",NAME,"--paused")
    # Do not proceed to Windows CPU resume until the paused identity is
    # checked against the plan, including zero NICs and security isolation.
    paused=virsh("domstate",NAME).lower()
    need(paused in ("paused","paused (user)"),
         "Clone did not remain paused; DO NOT RESUME")
    check_xml(virsh("dumpxml",NAME),live=True)
    check_master_and_trial()
    print("PASS: named clone started PAUSED; live XML has zero NICs",flush=True)
    virsh("resume",NAME)
    try:
        need(virsh("domstate",NAME)=="running",
             "Clone failed to enter running state")
        check_xml(virsh("dumpxml",NAME),live=True)
        check_master_and_trial()
    except Exception:
        # Pause ONLY the exact newly registered VM. Do not stop/delete
        # the master, running trial, domain definition, TPM or disk.
        try:
            if virsh("domuuid",NAME)==IDENT and
               virsh("domstate",NAME)=="running":
                virsh("suspend",NAME)
                print("SAFETY_PAUSE: newly started win11_1 only",flush=True)
        except Exception:
            print("CRITICAL: could not confirm safety pause; inspect manually",
                  file=sys.stderr)
        raise
    report.update({
        "result":"COMMAND2A_NEW_CLONE_BOOTED_ZERO_NICS",
        "state":"RUNNING","guest_cpus_resumed":True,
        "tpm_rule":guard["status"],
        "master_unchanged":True,"trial_untouched":True,
        "network_changed":False,"guest_nics":0,
        "windows_login_verified":False,"cape_agent_verified_in_new_guest":False,
        "windows_hostname_personalized":False,"windows_static_ip_assigned":False,
        "malware_execution_authorized":False})
    return report

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=("plan","boot"),default="plan")
    args=parser.parse_args(argv)
    try:
        result=preflight() if args.mode=="plan" else boot()
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (BootBlocked,tpm.PolicyError,OSError,ValueError,
            ET.ParseError,json.JSONDecodeError) as e:
        print("BLOCKED: "+str(e),file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
