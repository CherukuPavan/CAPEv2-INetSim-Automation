#!/usr/bin/env python3
"""OTHER-host-only create-only systemd guard replay installer.

Requires already-active independently verified CAPE no-NAT libvirt network
and dedicated nft table. Creates ONLY root-owned dedicated policy, boot
helper and systemd unit, then ENABLES (does not START) the unit. Does not
change nftables.service, /etc/nftables.conf, Docker, unrelated nft rules,
libvirt network autostart, guest NICs, VM power or run malware.
Reboot/negative-traffic behavior remains untested until a real host reboot.
"""
from __future__ import annotations
import argparse
import ast
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import command2_portable_workflow as flow
import command2_guarded_isolated_nic as nic
import command2_cape_egress_guard_plan as nftplan

ETC=Path("/etc/cape-command2")
HELPERS=Path("/usr/local/libexec/cape-command2")
POLICY=ETC/"nft-cape-cmd2-only.nft"
BOOT=HELPERS/"nft-cape-cmd2-replay.py"
UNIT=Path("/etc/systemd/system/cape-command2-nft-guard.service")
LOCK=Path("/run/lock/cape-command2-guard-persistence.lock")
class ServiceBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise ServiceBlocked(why)

def run(*argv):
    try:r=subprocess.run(argv,capture_output=True,text=True,
                         timeout=45,check=False)
    except (OSError,subprocess.TimeoutExpired) as e:
        raise ServiceBlocked("System utility unavailable: "+argv[0]) from e
    need(r.returncode==0,"System utility failed: "+argv[0])
    return r.stdout.strip()

# No dependencies on the working-tree code after installation.
_BOOT=r'''#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
POLICY=Path("/etc/cape-command2/nft-cape-cmd2-only.nft")
SHA=__GUARD_SHA__
TABLE="cape_analysis_cmd2_guard"
BRIDGE="cape-lab0"
BRIDGE_IP=__BRIDGE_IP__
def cmd(*args):
    p=subprocess.run(args,capture_output=True,text=True,check=False,timeout=40)
    if p.returncode:raise RuntimeError("guard nft command failed")
    return p.stdout
def inspect():
    raw=cmd("nft","-a","list","table","inet",TABLE)
    patterns=[
      r"chain cape_guest_forward",
      r"chain cape_guest_input",
      r"hook forward priority -150; policy accept;",
      r"hook input priority -150; policy accept;",
      r'iifname "cape-lab0".*drop',
      r'iifname "cape-lab0" meta nfproto ipv6.*drop',
      r'iifname "cape-lab0" ip daddr != '+re.escape(BRIDGE_IP)+r'.*drop',
    ]
    return all(re.search(p,raw) for p in patterns)
def main():
    if POLICY.is_symlink() or not POLICY.is_file() or POLICY.stat().st_uid!=0:
        raise RuntimeError("Root-owned CAPE guard policy missing")
    if POLICY.stat().st_mode & 0o022:
        raise RuntimeError("CAPE guard policy writable by others")
    data=POLICY.read_bytes()
    if hashlib.sha256(data).hexdigest()!=SHA:
        raise RuntimeError("Pinned CAPE nft policy digest differs")
    tables=json.loads(cmd("nft","-j","list","tables")).get("nftables")
    if type(tables) is not list:raise RuntimeError("Cannot inspect nft tables")
    exists=any(isinstance(x.get("table"),dict) and
               x["table"].get("family")=="inet" and
               x["table"].get("name")==TABLE
               for x in tables if isinstance(x,dict))
    if exists:
        if not inspect():raise RuntimeError("Foreign CAPE nft table present")
        return 0
    cmd("nft","--check","-f",str(POLICY))
    cmd("nft","-f",str(POLICY))
    if not inspect():raise RuntimeError("CAPE guard not present after install")
    return 0
if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print("BLOCKED_CAPE_GUARD_REPLAY: "+str(exc),file=sys.stderr)
        sys.exit(2)
'''

_UNIT="""[Unit]
Description=Dedicated CAPE Command2 analysis nft guard replay (no global flush)
After=local-fs.target nftables.service
ConditionPathExists=/etc/cape-command2/nft-cape-cmd2-only.nft

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 /usr/local/libexec/cape-command2/nft-cape-cmd2-replay.py
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
"""

def boot_source(sha,bridge_ip):
    need(re.fullmatch(r"[0-9a-f]{64}",sha or "") and
         type(bridge_ip) is str and
         re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",bridge_ip),
         "Unexpected boot replay policy digest/bridge IPv4")
    src=_BOOT.replace("__GUARD_SHA__",repr(sha)).replace(
                   "__BRIDGE_IP__",repr(bridge_ip))
    ast.parse(src)
    return src

def systemd_state(unit):
    values={}
    for line in run("systemctl","show","--no-pager",
                    "--property=LoadState,UnitFileState,ActiveState",unit).splitlines():
        if "=" in line:
            key,value=line.split("=",1)
            values[key]=value
    need(all(k in values for k in ("LoadState","UnitFileState","ActiveState")),
         "Systemd state inventory unavailable")
    return values

def plan(host,journal):
    try:flow.canonical_host(host)
    except flow.WorkflowBlocked as e:raise ServiceBlocked(str(e)) from e
    need(os.geteuid()==0,"Root required for secure guard replay preflight")
    rows=flow.snapshotgate.reservation_rows(journal,host)
    need(rows,"Approved guest reservation missing")
    _,subnet,_=flow.load_guest(journal,host,"win11_1")
    for row in rows:
        _,other,_=flow.load_guest(journal,host,row["libvirt_name"])
        need(other==subnet,"Mixed guest subnet")
    need(not run("virsh","-c","qemu:///system","list","--name").strip(),
         "No running VM allowed while staging CAPE guard boot replay")
    for row in rows:
        vm=row["libvirt_name"]
        status=run("virsh","-c","qemu:///system","domstate",vm).lower()
        need(status=="shut off","Guard replay install requires all clones shut off")
        info=run("virsh","-c","qemu:///system","dominfo",vm)
        need(re.search(r"(?mi)^Autostart:\\s+disable\\s*$",info) is not None,
             "Clone autostart enabled; safe guard replay requires guest autostart off")
    bridge_ip=str(ipaddress.IPv4Address(
                  int(ipaddress.IPv4Network(subnet).network_address)+1))
    try:nic.verify_network_live(subnet,bridge_ip)
    except nic.NicBlocked as e:raise ServiceBlocked("Existing nft/libvirt guard differs") from e
    details=run("virsh","-c","qemu:///system","net-info","cape-analysis-isolated")
    need(re.search(r"(?mi)^Autostart:\s+no\s*$",details) is not None,
         "CAPE lab must NOT automatically start before guard boot acceptance")
    base=systemd_state("nftables.service")
    need(base["ActiveState"] in ("inactive","failed") and
         base["UnitFileState"] in ("disabled","masked","static","not-found"),
         "Active/enabled nftables.service may flush dedicated CAPE table at reboot")
    own=systemd_state("cape-command2-nft-guard.service")
    need(own["LoadState"]=="not-found",
         "Existing CAPE guard unit requires independent review; no overwrite")
    for f in (POLICY,BOOT,UNIT,ETC,HELPERS):
        need(not f.exists() and not f.is_symlink(),
             "Existing CAPE guard install path requires separate review")
    for parent in (Path("/etc"),Path("/usr/local"),
                   Path("/etc/systemd/system")):
        st=parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
             st.st_mode & 0o022==0,
             "Unsafe/missing root-owned systemd/helper parent directory")
    helper_parent=HELPERS.parent
    if helper_parent.exists() or helper_parent.is_symlink():
        st=helper_parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
             st.st_mode&0o022==0,
             "Untrusted /usr/local/libexec parent")
    guard=nftplan.render_cape_egress_guard(subnet)
    payload=guard["ruleset_text"]
    helper=boot_source(guard["ruleset_sha256"],bridge_ip)
    return {"result":"COMMAND2_NFT_REBOOT_UNIT_CREATE_ONLY_PLAN",
            "approved_host":host,"subnet":subnet,
            "bridge_ip":bridge_ip,
            "unit_file":str(UNIT),"policy_file":str(POLICY),
            "helper_file":str(BOOT),
            "guard_policy_sha256":guard["ruleset_sha256"],
            "boot_helper_sha256":hashlib.sha256(helper.encode()).hexdigest(),
            "unit_sha256":hashlib.sha256(_UNIT.encode()).hexdigest(),
            "unit_enabled":False,"unit_started":False,
            "reboot_persistence_verified":False,
            "nft_or_libvirt_changed":False,"vm_changed":False,
            "unrelated_firewall_changed":False}

def write_exclusive(file,data,mode):
    f=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(f,"wb") as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())

def fsync_dir(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def install(host,journal):
    need(sys.stdin.isatty(),"Direct operator terminal approval required")
    before=plan(host,journal)
    print(json.dumps(before,indent=2,sort_keys=True),flush=True)
    phrase="INSTALL-CAPE-ONLY-REBOOT-GUARD"
    need(input("Type "+phrase+" to create/enable ONLY the dedicated systemd unit: ")==
         phrase,"Operator did not approve CAPE-only unit")
    need(not LOCK.is_symlink(),"Unsafe CAPE guard install lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "CAPE guard install serialization lock unsafe")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(plan(host,journal)==before,
             "Host nft/libvirt/systemd state changed before approval")
        guard=nftplan.render_cape_egress_guard(before["subnet"])
        if not HELPERS.parent.exists():
            HELPERS.parent.mkdir(mode=0o755)
            fsync_dir(HELPERS.parent.parent)
        ETC.mkdir(mode=0o700)
        HELPERS.mkdir(mode=0o700)
        write_exclusive(POLICY,guard["ruleset_text"].encode(),0o600)
        write_exclusive(BOOT,boot_source(guard["ruleset_sha256"],
                        before["bridge_ip"]).encode(),0o700)
        fsync_dir(ETC);fsync_dir(HELPERS)
        write_exclusive(UNIT,_UNIT.encode(),0o644)
        fsync_dir(UNIT.parent)
        run("systemctl","daemon-reload")
        run("systemctl","enable","cape-command2-nft-guard.service")
        after=systemd_state("cape-command2-nft-guard.service")
        need(after["LoadState"]=="loaded" and
             after["UnitFileState"] in ("enabled","enabled-runtime") and
             after["ActiveState"]=="inactive",
             "Dedicated CAPE unit must be enabled but NOT started")
        return {"result":"COMMAND2_CAPE_NFT_REBOOT_UNIT_ENABLED_NOT_STARTED",
                "unit":"cape-command2-nft-guard.service",
                "no_base_nftables_service_changed":True,
                "no_guest_network_autostart_enabled":True,
                "reboot_test_performed":False,
                "guest_ipv4_ipv6_l2_packet_testing_done":False,
                "production_network_approved":False}
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","install"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--journal",type=Path,required=True)
    a=p.parse_args()
    try:
        report=plan(a.approved_host,a.journal) if a.mode=="plan" else install(
            a.approved_host,a.journal)
        print(json.dumps(report,indent=2,sort_keys=True))
        return 0
    except (ServiceBlocked,flow.WorkflowBlocked,
            flow.snapshotgate.GateBlocked,
            nftplan.GuardPlanBlocked,OSError,TypeError,
            ValueError,SyntaxError) as e:
        print(json.dumps({"result":"COMMAND2_CAPE_GUARD_UNIT_BLOCKED",
             "reason":str(e),"no_automatic_retry_or_rollback":True},indent=2),
             file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
