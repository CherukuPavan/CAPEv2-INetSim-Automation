#!/usr/bin/env python3
"""SSL55 only: guarded, TIME-LIMITED LIVE-ONLY NAT for BENIGN Windows setup.

Session uses an existing ACTIVE libvirt default NAT+DHCP network; NEVER
modifies that network, the dedicated analysis bridge, nft, persistent
domain XML, Windows settings, snapshots, swtpm, or protected master VMs.

Attach second e1000e NIC to RUNNING win11_1 using --live ONLY, verify it
appears, allow one interactive trusted setup window, and ALWAYS request
its live detachment in finally. Stops after a hard finite timeout or an
operator Enter, interrupt, SIGHUP or SIGTERM; no attempts to start/stop
a VM, revert/delete/capture snapshot or run malware. If virsh detach
fails, clearly mark the guest as UNSAFE/ONLINE, not analysis ready.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

HOST="cse-ssl-55"
VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
MAIN=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
SNAP="cape_candidate_win11_1"
SAVED_MAC="02:0a:30:6a:3f:50"
SETUP_MAC="02:ca:55:11:01:01"
ANALYSIS="cape-analysis-isolated"
ONLINE="default"
BRIDGE="cape-lab0"
LOCK=Path("/run/lock/cape-ssl55-win11-1-trusted-setup-internet.lock")
MAX_MINUTES=180
class SessionBlocked(RuntimeError):pass
class SessionInterrupted(Exception):pass
def need(test,reason):
    if not test:raise SessionBlocked(reason)

def command(*args,timeout=35):
    try:
        p=subprocess.run(args,check=False,capture_output=True,text=True,
                         timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise SessionBlocked("Host tool not available/timed out: "+args[0]) from exc
    need(p.returncode==0,
         "Host command failed: "+args[0]+" (returncode="+str(p.returncode)+")")
    need(len(p.stdout)<=500000,"Unexpected oversized host response")
    return p.stdout.strip()
def virsh(*args,timeout=35):
    return command("virsh","-c","qemu:///system",*args,timeout=timeout)

def nics_of(xml):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UID,
         "Unexpected source/clone domain identity")
    items=[]
    for nic in root.findall("./devices/interface"):
        mac=nic.find("mac")
        source=nic.find("source")
        model=nic.find("model")
        need(nic.get("type")=="network" and mac is not None and
             source is not None and model is not None,
             "Unexpected passthrough/host-connected guest NIC")
        items.append({"network":source.get("network"),
                      "mac":(mac.get("address") or "").lower(),
                      "model":model.get("type")})
    return items

def check_domain_views(expect_online):
    need(virsh("domuuid",VM).lower()==UID and
         virsh("domstate",VM).lower()=="running",
         "Approved win11_1 not RUNNING")
    saved=virsh("dumpxml","--inactive",VM)
    live=virsh("dumpxml",VM)
    original={"network":ANALYSIS,"mac":SAVED_MAC,"model":"e1000e"}
    proposed={"network":ONLINE,"mac":SETUP_MAC,"model":"e1000e"}
    need(nics_of(saved)==[original],
         "PERSISTENT VM NIC CHANGED: no automatic cleanup/guest restart")
    wanted=([original,proposed] if expect_online else [original])
    actual=nics_of(live)
    # Libvirt can reorder live device elements after attach; NICs
    # remain uniquely identified by exact MAC and network.
    need(len(actual)==len(wanted) and
         sorted(actual,key=lambda x:x["mac"])==
         sorted(wanted,key=lambda x:x["mac"]),
         "LIVE VM NICs unexpected (possibly partial hotplug/unplug)")
    return {"saved_has_only_isolated_nic":True,
            "live_nics":actual,"temporary_online_nic":expect_online}

def check_isolated_network():
    root=ET.fromstring(virsh("net-dumpxml",ANALYSIS))
    port=root.find("port")
    bridge=root.find("bridge")
    dns=root.find("dns")
    need(root.tag=="network" and root.findtext("name")==ANALYSIS and
         root.find("forward") is None and
         not root.findall(".//dhcp") and
         not root.findall(".//route") and
         port is not None and port.get("isolated")=="yes" and
         bridge is not None and bridge.get("name")==BRIDGE and
         dns is not None and dns.get("enable")=="no",
         "CAPEv2 isolated network no longer matches offline guard")
    return True

def check_nat_network():
    root=ET.fromstring(virsh("net-dumpxml",ONLINE))
    forward=root.find("forward")
    dns=root.find("dns")
    dhcp=root.findall(".//dhcp")
    bridge=root.find("bridge")
    need(root.tag=="network" and root.findtext("name")==ONLINE and
         forward is not None and forward.get("mode","nat")=="nat" and
         len(dhcp)==1 and bridge is not None and bridge.get("name")!=BRIDGE,
         "The existing libvirt default is NOT a separate NAT+DHCP bridge")
    details={}
    for line in virsh("net-info",ONLINE).splitlines():
        key,sep,value=line.partition(":")
        if sep:details[key.strip().lower()]=value.strip().lower()
    need(details.get("active")=="yes" and details.get("bridge"),
         "Existing NAT network not ACTIVE")
    return {"existing_nat_network":ONLINE,
            "bridge":details["bridge"],"dhcp_defined":True,
            "dns_explicitly_disabled":dns is not None and
                                     dns.get("enable")=="no",
            "internet_from_inside_windows_physically_verified":False}

def check_snapshot():
    names=[x.strip() for x in virsh("snapshot-list",VM,"--name").splitlines()
           if x.strip()]
    need(names==[SNAP],
         "Protected running candidate snapshot missing, renamed or duplicated")
    root=ET.fromstring(virsh("snapshot-dumpxml",VM,SNAP))
    mem=root.find("memory")
    need(root.tag=="domainsnapshot" and
         root.findtext("name")==SNAP and
         root.findtext("state")=="running" and
         mem is not None and mem.get("snapshot")=="internal" and
         sum(d.get("name")=="sda" and d.get("snapshot")=="internal"
             for d in root.findall("./disks/disk"))==1,
         "Existing RAM+Windows OS disk snapshot changed")
    return True

def guard_exact():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()==HOST,
         "Operation restricted to exact SSL55 root")
    for name,uid in (MAIN,TRIAL):
        need(virsh("domuuid",name).lower()==uid and
             virsh("domstate",name).lower()=="shut off",
             "Protected master/trial unexpectedly changed")
    need(virsh("list","--name").splitlines()==[VM],
         "Another running guest detected")
    check_snapshot()
    need(check_isolated_network(),"Isolated bridge missing")
    guard=command("nft","-j","list","table","inet","cape_analysis_guard")
    rows=json.loads(guard).get("nftables",[])
    chains={r["chain"].get("name") for r in rows
            if type(r) is dict and type(r.get("chain")) is dict}
    need({"cape_forward","cape_input","cape_output"}.issubset(chains),
         "Persistent analysis egress nft guard missing")
    return True

def ensure_mac_unique():
    names=[v.strip() for v in virsh("list","--all","--name").splitlines()
           if v.strip()]
    for name in names:
        for mode in (("dumpxml","--inactive",name),("dumpxml",name)):
            if mode[0]=="dumpxml" and len(mode)==2 and mode[1]==name:
                if virsh("domstate",name).lower()!="running":continue
            xml=ET.fromstring(virsh(*mode))
            for iface in xml.findall("./devices/interface"):
                mac=iface.find("mac")
                need(mac is None or
                     (mac.get("address") or "").lower()!=SETUP_MAC,
                     "Temporary setup MAC already used by another guest")
    return True

def before():
    guard_exact()
    existing=check_domain_views(False)
    nat=check_nat_network()
    ensure_mac_unique()
    return {"result":"SSL55_TRUSTED_WINDOWS_SETUP_INTERNET_PLAN_ONLY",
            "vm":VM,"uuid":UID,"snapshot_preserved":SNAP,
            "analysis_network_unchanged":True,
            "protected_master_trial_off":True,
            "approved_temporary_nat":nat,
            "live_only_setup_mac":SETUP_MAC,
            "saved_domain_unchanged":existing["saved_has_only_isolated_nic"],
            "guest_windows_internet_confirmed":False,
            "samples_or_malware_execution_authorized":False,
            "host_or_guest_modified":False}

def monitor(minutes,*,clock=time.monotonic,wait=select.select):
    expires=clock()+minutes*60
    print("TEMPORARY INTERNET ATTACHED. In Windows, verify DHCP, DNS and HTTPS.",
          flush=True)
    print("Press ENTER here when Windows setup is finished; "
          "otherwise auto-disconnect by deadline.",flush=True)
    while True:
        remaining=expires-clock()
        if remaining<=0:return "time_limit_reached"
        readable,_,_=wait([sys.stdin],[],[],min(10,remaining))
        if readable:
            sys.stdin.readline()
            return "operator_finished"
        need(virsh("domstate",VM).lower()=="running",
             "Guest stopped while setup NIC active")
        need(nics_of(virsh("dumpxml","--inactive",VM))==
             [{"network":ANALYSIS,"mac":SAVED_MAC,"model":"e1000e"}],
             "Persistent domain altered while temporary setup Internet active")
        check_snapshot()

def detach_live():
    # Do NOT detach ANY device by index or assume a libvirt 'success'
    # reply means the NIC vanished. Match exact temporary MAC and poll.
    live=virsh("dumpxml",VM)
    present=[n for n in nics_of(live) if n["mac"]==SETUP_MAC]
    need(len(present)<=1,
         "Multiple temporary NIC matches; refuse arbitrary detachment")
    if not present:
        check_domain_views(False)
        return {"temporary_nic_disconnected":True,
                "detach_request_not_needed":True}
    need(present==[{"network":ONLINE,"mac":SETUP_MAC,"model":"e1000e"}],
         "Unexpected device at temporary MAC: no arbitrary detach")
    virsh("detach-interface",VM,"network","--mac",SETUP_MAC,"--live",
          timeout=90)
    deadline=time.monotonic()+35
    while time.monotonic()<deadline:
        try:
            check_domain_views(False)
            return {"temporary_nic_disconnected":True,
                    "detach_request_sent":True,
                    "actual_live_xml_verified_after_detach":True}
        except SessionBlocked:
            time.sleep(2)
    raise SessionBlocked("DETACH MAY BE INCOMPLETE: live-only NAT NIC not "
                         "confirmed removed. NO snapshot/revert/start/stop allowed.")

def setup_session(minutes):
    need(type(minutes) is int and 10<=minutes<=MAX_MINUTES,
         "Temporary Internet duration must be 10..180 minutes")
    need(sys.stdin.isatty(),"Operator's direct terminal required")
    baseline=before()
    print(json.dumps(baseline,indent=2,sort_keys=True),flush=True)
    approval="TRUSTED-WINDOWS-SETUP-ONLY-NO-MALWARE"
    need(input("Type "+approval+" to connect temporary NAT only: ")==approval,
         "Operator did not approve benign-only live Internet access")
    need(not LOCK.is_symlink(),"Untrusted setup lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    need(stat.S_ISREG(os.fstat(fd).st_mode) and
         os.fstat(fd).st_uid==0 and os.fstat(fd).st_nlink==1 and
         stat.S_IMODE(os.fstat(fd).st_mode)==0o600,
         "Setup lock not root-private")
    started=False
    ended="unknown"
    detach_error=None
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise SessionBlocked("Another temporary setup session active") from e
        # Repeat the exact admission immediately before any mutation.
        need(before()==baseline,
             "Network, VM, original snapshot or guard changed after approval")
        # Use --live ONLY: persistent domain stays isolated and is not
        # modified by Windows setup or a later guest reboot.
        started=True
        virsh("attach-interface",VM,"network",ONLINE,
              "--mac",SETUP_MAC,"--model","e1000e","--live",timeout=120)
        active=check_domain_views(True)
        print(json.dumps({"result":"SSL55_TEMPORARY_WINDOWS_INTERNET_NIC_ATTACHED",
            "live_only":True,"network":ONLINE,"mac":SETUP_MAC,
            "verified_live_nics":active["live_nics"],
            "operator_must_verify_actual_windows_https":True,
            "never_run_analysis_samples":True},sort_keys=True),flush=True)
        ended=monitor(minutes)
    except (SessionBlocked,KeyboardInterrupt,SessionInterrupted) as exc:
        ended="session_interrupted_or_blocked"
        print("TRUSTED_SETUP_SESSION_INTERRUPTED: "+str(exc),
              file=sys.stderr,flush=True)
    finally:
        if started:
            try:
                # If Windows rebooted, the LIVE-only NIC is naturally gone.
                if virsh("domstate",VM).lower()=="running":
                    check_isolated_network()
                    detached=detach_live()
                    print(json.dumps({"result":"SSL55_TRUSTED_SETUP_NAT_DETACH",
                        **detached},sort_keys=True),flush=True)
                else:
                    # Cannot claim NAT is detached from an unexpected
                    # paused/migrating state: operator review required.
                    raise SessionBlocked("VM not running during cleanup; "
                                         "inspect persistent vs live NICs")
            except (SessionBlocked,OSError,ET.ParseError) as exc:
                detach_error=str(exc)
                print(json.dumps({"result":"SSL55_TRUSTED_SETUP_DETACH_UNVERIFIED",
                      "reason":detach_error,
                      "analysis_or_new_snapshot_must_not_run":True,
                      "do_not_force_shutdown_or_revert":True},
                      sort_keys=True),file=sys.stderr,flush=True)
        os.close(fd)
    if detach_error:
        raise SessionBlocked("TRUSTED INTERNET NIC NOT VERIFIED REMOVED: "+
                             detach_error)
    if ended=="session_interrupted_or_blocked":
        raise SessionBlocked("Temporary NAT was cleaned up but the setup "
                             "session failed/interrupted; confirm manually "
                             "that Windows is offline before any snapshot")
    return {"result":"SSL55_TRUSTED_WINDOWS_SETUP_FINISHED_OFFLINE",
            "reason_session_ended":ended,
            "guest_real_internet_witness_required":True,
            "windows_gateway_dns_routes_checked_by_script":False,
            "temporary_nat_nic_absent_from_live_and_saved_domain":True,
            "candidate_snapshot_preserved":SNAP,
            "TPM_restore_proven":False,
            "CAPE_READY":False,
            "final_snapshot_taken":False}

def cleanup_abandoned():
    """Idempotent manual recovery after lost terminal/SIGKILL.

    ONLY detaches the pinned temporary network adapter from the exact
    clone, verifying preserved snapshot, original protected VMs and
    isolated analysis bridge. Refuses if another active session owns
    the exclusive file lock. Never touches the original CAPE NIC.
    """
    need(not LOCK.is_symlink(),"Unsafe setup cleanup lock")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Root-only cleanup lock metadata differs")
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SessionBlocked("Live Internet setup session still owns lock") from exc
        guard_exact()
        expected_saved={"network":ANALYSIS,"mac":SAVED_MAC,"model":"e1000e"}
        need(nics_of(virsh("dumpxml","--inactive",VM))==[expected_saved],
             "Persistent offline NIC configuration drift; refuse cleanup")
        found=detach_live()
        guard_exact()
        check_domain_views(False)
        return {"result":"SSL55_TRUSTED_SETUP_NAT_CLEANUP_VERIFIED",
                **found,"snapshot_preserved":SNAP,
                "guest_windows_ip_config_reviewed":False,
                "new_final_snapshot_created":False,
                "safe_for_malware_analysis_proven":False}
    finally:
        os.close(fd)

def handle_signal(_signum,_frame):
    raise SessionInterrupted("Operator terminal closed/termination requested")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("plan","session","cleanup"),default="plan")
    p.add_argument("--minutes",type=int,default=90)
    a=p.parse_args()
    try:
        if a.mode=="session":
            signal.signal(signal.SIGTERM,handle_signal)
            signal.signal(signal.SIGHUP,handle_signal)
        report=(before() if a.mode=="plan" else
                cleanup_abandoned() if a.mode=="cleanup" else
                setup_session(a.minutes))
        print(json.dumps(report,indent=2,sort_keys=True),flush=True)
        return 0
    except (SessionBlocked,OSError,ValueError,TypeError,ET.ParseError,
            json.JSONDecodeError) as exc:
        print(json.dumps({"result":"SSL55_TRUSTED_INTERNET_SETUP_BLOCKED",
              "reason":str(exc),"existing_snapshot_not_reverted":True,
              "never_proceed_to_analysis_snapshot_on_failure":True},
              sort_keys=True),file=sys.stderr,flush=True)
        return 2

if __name__=="__main__":raise SystemExit(main())
