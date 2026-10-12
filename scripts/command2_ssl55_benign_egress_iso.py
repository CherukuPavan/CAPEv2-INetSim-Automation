#!/usr/bin/env python3
"""SSL55 only: one-click BENIGN Windows egress-test ISO on existing sdb.

PLAN reads only. APPLY needs local typed approval, root and exact running
guest/isolated network; changes existing CD-ROM media ONLY (no new NIC,
VM/disk, network, firewall, guest scripts run or samples submitted).
"""
from __future__ import annotations
import argparse
import fcntl
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
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
DIR=Path("/var/lib/libvirt/images/cape-clones-staging")
OLD=DIR/"win11_1.command2_safe_fix.iso"
NEW=DIR/"win11_1.command2_benign_egress.iso"
DISK=str(DIR/"win11_1.command2.qcow2")
LOCK=Path("/run/lock/cape-command2-egress-iso.lock")
NET="cape-analysis-isolated"
# Git blob IDs are checked again by operator shell wrapper at download time.
class Blocked(RuntimeError):pass
def need(ok,msg):
    if not ok:raise Blocked(msg)
def command(*args,timeout=50):
    try:
        p=subprocess.run(args,check=False,capture_output=True,
                         text=True,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise Blocked("Tool failed or timed out: "+args[0]) from e
    need(p.returncode==0,"Tool returned nonzero: "+args[0])
    return p.stdout.strip()
def virsh(*args):return command("virsh","-c","qemu:///system",*args)

def parse_network_info(raw):
    """Parse libvirt net-info key/value lines, allowing alignment whitespace."""
    need(isinstance(raw,str),"Unexpected libvirt net-info response")
    props={}
    for line in raw.splitlines():
        key,sep,value=line.partition(":")
        if not sep:continue
        key=key.strip().lower()
        need(key not in props,"Duplicate libvirt net-info key: "+key)
        props[key]=value.strip().lower()
    for key in ("active","persistent","autostart","bridge"):
        need(key in props,"Missing required libvirt net-info field: "+key)
    need(props["active"] in ("yes","no") and
         props["persistent"] in ("yes","no") and
         props["autostart"] in ("yes","no"),
         "Malformed libvirt net-info status")
    return props


def domxml(raw):
    root=ET.fromstring(raw)
    need(root.findtext("name")==VM and root.findtext("uuid")==UUID,
         "Unexpected analysis guest identity")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file")==DISK,"Unexpected primary disk")
    back=disks[0].find("backingStore")
    need(back is None or (back.find("source") is None and
         back.find("backingStore") is None),"Primary disk has backing dependency")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].find("source") is not None and
         nics[0].find("source").get("network")==NET and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address","").lower()=="02:0a:30:6a:3f:50",
         "Unexpected analysis NIC")
    need(root.findtext("./os/nvram")=="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd",
         "Unexpected VM UEFI NVRAM")
    tpm=root.find("./devices/tpm/backend")
    need(tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0","Unexpected TPM2 state")
    cds=root.findall("./devices/disk[@device='cdrom']")
    need(len(cds)==1,"Expected exactly one optical device")
    cd=cds[0]
    target=cd.find("target");source=cd.find("source")
    need(target is not None and target.get("dev")=="sdb" and
         cd.get("type")=="file" and cd.find("readonly") is not None,
         "Optical media device definition changed")
    present=source.get("file") if source is not None else None
    need(present==str(OLD),
         "CD-ROM no longer has the exact original reviewable optical ISO")
    return {"target":"sdb","old_media":present}

def plan(powershell,launcher):
    need(os.geteuid()==0,"sudo/root required")
    need(socket.gethostname().split(".")[0].lower()=="cse-ssl-55",
         "Only SSL55 pilot host is authorized")
    for name,uid,state in ((VM,UUID,"running"),
                           (MASTER[0],MASTER[1],"shut off"),
                           (TRIAL[0],TRIAL[1],"shut off")):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()==state,
             "VM identity or current state changed: "+name)
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Unknown snapshot state")
    old_live=domxml(virsh("dumpxml",VM))
    old_saved=domxml(virsh("dumpxml","--inactive",VM))
    need(old_live==old_saved,"Live/persistent optical media differ")
    net=virsh("net-info",NET)
    props=parse_network_info(net)
    need(props.get("active")=="yes" and
         props.get("persistent")=="yes" and
         props.get("autostart")=="no" and
         props.get("bridge")=="cape-lab0",
         "Analysis network inactive or configuration unexpectedly changed")
    network=ET.fromstring(virsh("net-dumpxml",NET))
    port=network.find("port");bridge=network.find("bridge")
    dns=network.find("dns")
    ips=network.findall("ip")
    need(network.find("forward") is None and
         port is not None and port.get("isolated")=="yes" and
         bridge is not None and bridge.get("name")=="cape-lab0" and
         dns is not None and dns.get("enable")=="no" and
         not network.findall(".//dhcp") and not network.findall(".//route") and
         len(ips)==1 and ips[0].get("address")=="192.168.240.1" and
         ips[0].get("netmask")=="255.255.255.0",
         "Network may forward, serve DHCP or lacks expected isolation")
    need(command("systemctl","is-active","cape-analysis-guard.service")=="active",
         "CAPE host containment guard inactive")
    sys.path.insert(0,"/usr/local/libexec/cape-command2")
    try:
        import command2_ssl55_existing_guard_readonly as guard
    except ImportError as exc:
        raise Blocked("Installed CAPE firewall verifier unavailable") from exc
    guard.guard_policy_structure(
        command("nft","-j","list","table","inet","cape_analysis_guard"),
        command("nft","list","table","inet","cape_analysis_guard"))
    need(DIR.is_dir() and not DIR.is_symlink() and
         not NEW.exists() and not NEW.is_symlink() and
         OLD.is_file() and not OLD.is_symlink(),
         "Unexpected existing/missing optical media")
    need(shutil.which("genisoimage") is not None,
         "ISO authoring utility unavailable")
    paths=[Path(powershell),Path(launcher)]
    for p in paths:
        need(p.is_file() and not p.is_symlink() and
             0<p.stat().st_size<100000,"Expected bounded local guest script")
    return {"result":"BENIGN_EGRESS_ISO_PLAN_ONLY","vm":VM,
            "network":NET,"cd_target":"sdb",
            "previous_media":str(OLD),"proposed_media":str(NEW),
            "powershell_sha256":hashlib.sha256(paths[0].read_bytes()).hexdigest(),
            "launcher_sha256":hashlib.sha256(paths[1].read_bytes()).hexdigest(),
            "no_host_guest_changes":True,
            "guests_not_executed_by_host":True}

def apply(powershell,launcher):
    need(sys.stdin.isatty(),"Approval requires local terminal")
    before=plan(powershell,launcher)
    print(json.dumps(before,indent=2,sort_keys=True),flush=True)
    phrase="INSERT-BENIGN-EGRESS-ISO-WIN11_1"
    need(input("Type "+phrase+" to insert ONLY the benign optical ISO: ")==phrase,
         "Operator did not approve")
    need(not LOCK.is_symlink(),"Unsafe optical operation lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600,
             "Root-owned optical lock required")
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise Blocked("Another optical operation active") from e
        need(plan(powershell,launcher)==before,
             "VM/network/sources changed before optical update")
        with tempfile.TemporaryDirectory(prefix="cape-egress-",dir="/run") as temp:
            tmp=Path(temp);content=tmp/"contents"
            content.mkdir(mode=0o700)
            (content/"CAPE_BenignEgressProbe.ps1").write_bytes(Path(powershell).read_bytes())
            (content/"RUN_EGRESS_CHECK.cmd").write_bytes(Path(launcher).read_bytes())
            image=tmp/"probe.iso"
            command("genisoimage","-quiet","-J","-R","-V","CAPE_EGRESS",
                    "-o",str(image),str(content),timeout=180)
            need(image.is_file() and 2048<image.stat().st_size<10*1024*1024,
                 "Generated optical ISO size invalid")
            # Exclusive creation; never replace or delete an older ISO.
            with image.open("rb") as source:
                destfd=os.open(NEW,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,
                               0o644)
                try:
                    with os.fdopen(destfd,"wb") as dest:
                        shutil.copyfileobj(source,dest)
                        dest.flush();os.fsync(dest.fileno())
                except Exception:raise
        # No --force, --destroy, NIC operations or host firewall changes.
        try:
            virsh("change-media",VM,"sdb",str(NEW),"--update","--live","--config")
        except Blocked:
            raise Blocked("ISO exists but media change failed/partial. "
                          "Inspect running/persistent CD-ROM XML before retry")
        for args in (("dumpxml",VM),("dumpxml","--inactive",VM)):
            root=ET.fromstring(virsh(*args))
            media=root.find("./devices/disk[@device='cdrom']/source")
            need(media is not None and media.get("file")==str(NEW),
                 "Media change not verified both live and persistent")
        need(virsh("domstate",VM).lower()=="running",
             "Guest no longer running after ISO update")
        return {"result":"BENIGN_EGRESS_ISO_INSERTED_NO_GUEST_EXECUTION",
                "iso":str(NEW),"vm_running":True,
                "original_iso_untouched":True,
                "guest_egress_negative_tested":False,
                "operator_action":"Open Windows CD drive and double-click RUN_EGRESS_CHECK.cmd"}

    finally:
        os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","apply"),default="plan")
    p.add_argument("--powershell",type=Path,required=True)
    p.add_argument("--launcher",type=Path,required=True)
    a=p.parse_args()
    try:
        res=plan(a.powershell,a.launcher) if a.mode=="plan" else apply(a.powershell,a.launcher)
        print(json.dumps(res,indent=2,sort_keys=True))
        return 0
    except (Blocked,OSError,ValueError,ET.ParseError) as e:
        print(json.dumps({"result":"BLOCKED_EGRESS_ISO",
                          "reason":str(e),"no_guest_execution_performed":True},indent=2),
              file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
