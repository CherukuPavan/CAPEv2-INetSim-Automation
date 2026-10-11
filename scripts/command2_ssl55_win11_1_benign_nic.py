#!/usr/bin/env python3
"""Guarded SSL55 EXISTING win11_1 saved-NIC-only attachment for BENIGN tests.

--mode plan: READ-ONLY. --mode attach-benign: interactive, one config
only NIC on existing SHUT OFF win11_1; never boots VMs, creates clones,
changes Windows IP, starts/stops bridges, modifies firewall or snapshots.
A successful NIC attachment is NOT malware/CAPE-analysis permission.
"""
from __future__ import annotations
import argparse
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
import xml.etree.ElementTree as ET

sys.path.insert(0,"/usr/local/libexec/cape-command2")
import command2_ssl55_existing_guard_readonly as guard
import command2_ssl55_boot_persistence_readonly as boot

VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
MAC="02:0a:30:6a:3f:50"
IP="192.168.240.101"
NET="cape-analysis-isolated"
BRIDGE="cape-lab0"
BRIDGE_IP="192.168.240.1"
SUBNET=ipaddress.IPv4Network("192.168.240.0/24")
LOCK=Path("/run/lock/cape-ssl55-benign-nic-one.lock")
CONFIRM="ATTACH-ONE-BENIGN-NIC-WIN11_1-SSL55"
EXPECTED_DISK="/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
EXPECTED_NVRAM="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"


class BenignBlocked(RuntimeError):pass


def need(ok,why):
    if not ok:raise BenignBlocked(why)


def cmd(*argv):
    try:
        p=subprocess.run(argv,check=False,capture_output=True,
                         text=True,timeout=30)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BenignBlocked("Cannot inspect host: "+argv[0]) from exc
    need(p.returncode==0,"Host command failed: "+argv[0])
    return p.stdout.strip()


def virsh(*args):
    return cmd("virsh","-c","qemu:///system",*args)


def read_json(*args):
    try: obj=json.loads(cmd(*args))
    except (ValueError,TypeError) as exc:
        raise BenignBlocked("Unreadable host JSON: "+args[0]) from exc
    need(type(obj) is list,"Expected host JSON array")
    return obj


def xml_clone_without_nic():
    need(virsh("domuuid",VM).lower()==UUID and
         virsh("domstate",VM).strip()=="shut off",
         "Wrong/running win11_1 clone")
    xml=virsh("dumpxml","--inactive",VM)
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UUID and
         len(root.findall("./devices/interface"))==0,
         "Clone already has a NIC or identity changed")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].get("type")=="file" and
         disks[0].find("source") is not None and
         disks[0].find("source").get("file")==EXPECTED_DISK and
         disks[0].find("driver") is not None and
         disks[0].find("driver").get("type")=="qcow2",
         "Unexpected independent clone disk XML")
    tpm=root.find("./devices/tpm/backend")
    need(root.findtext("./os/nvram")==EXPECTED_NVRAM and
         tpm is not None and tpm.get("type")=="emulator" and
         tpm.get("version")=="2.0",
         "Unexpected independent clone UEFI/TPM definition")
    return xml


def checked_network():
    props={}
    for line in virsh("net-info",NET).splitlines():
        k,sep,v=line.partition(":")
        if sep:props[k.strip().lower()]=v.strip().lower()
    need(props.get("active")=="yes" and
         props.get("autostart")=="no" and
         props.get("persistent")=="yes" and
         props.get("bridge")==BRIDGE,
         "Existing CAPE network not active, manual-only and persistent")
    root=ET.fromstring(virsh("net-dumpxml",NET))
    bridge=root.find("bridge")
    port=root.find("port")
    dns=root.find("dns")
    ips=root.findall("ip")
    need(root.tag=="network" and root.findtext("name")==NET and
         root.find("forward") is None and
         not root.findall(".//dhcp") and not root.findall(".//route") and
         bridge is not None and bridge.get("name")==BRIDGE and
         port is not None and port.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         len(ips)==1 and ips[0].get("address")==BRIDGE_IP and
         ips[0].get("netmask")=="255.255.255.0" and
         ips[0].get("family") in (None,"ipv4"),
         "Network XML differs: refuses NAT, DHCP, IPv6 and nonisolated ports")
    links=read_json("ip","-j","link","show")
    need(sum(1 for x in links if x.get("ifname")==BRIDGE)==1,
         "Exactly one CAPE bridge must exist")
    ip4=read_json("ip","-j","-4","addr","show")
    need(any(link.get("ifname")==BRIDGE and
             any(addr.get("family")=="inet" and
                 addr.get("local")==BRIDGE_IP and
                 addr.get("prefixlen")==24
                 for addr in link.get("addr_info",()))
             for link in ip4),
         "Wrong CAPE bridge IPv4 address/prefix")
    for link in ip4:
        if link.get("ifname")==BRIDGE:continue
        for addr in link.get("addr_info",()):
            if type(addr) is not dict or addr.get("family")!="inet":continue
            try:
                net=ipaddress.IPv4Network(
                    str(addr["local"])+"/"+str(addr["prefixlen"]),
                    strict=False)
            except (KeyError,TypeError,ValueError) as exc:
                raise BenignBlocked("Malformed host IPv4 interface inventory") from exc
            need(not net.overlaps(SUBNET),
                 "Host interface overlaps isolated CAPE subnet")
    for entry in read_json("ip","-j","-4","route","show","table","all"):
        if not isinstance(entry,dict):raise BenignBlocked("Malformed route")
        dest=entry.get("dst","default")
        if dest in ("default",None):continue
        try: network=ipaddress.IPv4Network(dest,strict=False)
        except (ValueError,TypeError):continue
        if network.overlaps(SUBNET):
            need(entry.get("dev")==BRIDGE,
                 "Unexpected CAPE subnet route on non-CAPE device")
    link6=read_json("ip","-j","-6","addr","show","dev",BRIDGE)
    need(not any(x.get("scope") in ("global","site")
                 for row in link6 for x in row.get("addr_info",())),
         "Globally scoped IPv6 address found on CAPE bridge")
    # Do not attach to an already occupied bridge (unknown TAP/link).
    member_ports=read_json("bridge","-j","link","show","master",BRIDGE)
    need(member_ports==[],
         "CAPE bridge already has ports, review guest/L2 isolation first")
    return True


def guard_and_guests():
    host=socket.gethostname().split(".",1)[0].lower()
    need(host in ("cse-ssl-55","ssl-55") and
         guard.SENTINEL.is_dir() and not guard.SENTINEL.is_symlink(),
         "Wrong SSL55 host or protected master marker missing")
    need(os.geteuid()==0,"Root required for protected host inspection")
    states=guard.protected_domains()
    need(all(states[x]["power_state"]=="shut off"
             for x in ("win11","win11_1","win11_trial_1")),
         "Protected VM unexpectedly active")
    need(not virsh("list","--name").strip(),
         "Another libvirt VM is running")
    need(states["win11"]["nic_counts"]["inactive"]==1 and
         states["win11_1"]["nic_counts"]["inactive"]==0 and
         states["win11_trial_1"]["nic_counts"]["inactive"]==0,
         "Protected master/clone/trial NIC baseline changed")
    need(all(boot.domain_autostart(v) is False
             for v in ("win11","win11_1","win11_trial_1")),
         "Unexpected Windows VM autostart")
    service=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "cape-analysis-guard.service"),"cape-analysis-guard.service")
    need(service.get("load_state")=="loaded" and
         service.get("unit_file_state")=="enabled" and
         service.get("active_state")=="active",
         "Dedicated guard replay service not running/available")
    general=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "nftables.service"),"nftables.service")
    need(general.get("load_state")=="loaded" and
         general.get("unit_file_state")=="disabled" and
         general.get("active_state")=="inactive",
         "General nftables service state unexpectedly changed")
    guard.guard_policy_structure(
        cmd("nft","-j","list","table","inet",guard.TABLE),
        cmd("nft","list","table","inet",guard.TABLE))
    mac=guard.proposed_analysis_mac()
    need(mac.get("proposed_mac")==MAC and
         mac.get("host_or_libvirt_mac_collision") is False and
         mac.get("mac_inventory_complete") is True,
         "Candidate MAC collision or unexpected planned address")
    checked_network()
    return True


def plan():
    guard_and_guests()
    xml=xml_clone_without_nic()
    snapshots=virsh("snapshot-list",VM,"--name").splitlines()
    need(not snapshots,"Unexpected clone snapshots: refuse NIC mutation")
    return {
        "result":"SSL55_WIN11_1_BENIGN_NIC_CONFIG_PLAN_ONLY",
        "vm":VM,"uuid":UUID,"mac":MAC,
        "expected_windows_ipv4":IP,
        "network":NET,"bridge":BRIDGE,
        "clone_saved_xml_sha256":hashlib.sha256(xml.encode()).hexdigest(),
        "clone_snapshot_names":snapshots,
        "nic_connected":False,"guest_started":False,
        "windows_static_ip_changed":False,
        "firewall_or_network_changed":False,
        "analysis_authorized":False,
        "snapshot_authorized":False,
        "host_changed":False,
    }


def attach():
    need(sys.stdin.isatty(),"Interactive controlling terminal required")
    initial=plan()
    need(input("Type "+CONFIRM+" to attach NIC to SHUT-OFF clone only: ")==CONFIRM,
         "Benign NIC operation not authorized")
    need(not LOCK.is_symlink(),"Unsafe lock symlink")
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    wrote=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1,
             "Unsafe root NIC lock")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        need(plan()==initial,"Host/guest/network changed while waiting")
        before_other={x:virsh("dumpxml","--inactive",x) for x in
                      ("win11","win11_trial_1")}
        virsh("attach-interface","--domain",VM,"--type","network",
              "--source",NET,"--model","e1000e","--mac",MAC,"--config")
        wrote=True
        root=ET.fromstring(virsh("dumpxml","--inactive",VM))
        interfaces=root.findall("./devices/interface")
        need(root.findtext("uuid")==UUID and
             len(interfaces)==1 and interfaces[0].get("type")=="network" and
             interfaces[0].find("source") is not None and
             interfaces[0].find("source").get("network")==NET and
             interfaces[0].find("mac") is not None and
             interfaces[0].find("mac").get("address","").lower()==MAC and
             interfaces[0].find("model") is not None and
             interfaces[0].find("model").get("type")=="e1000e",
             "Post-attach saved NIC identity differs: STOP")
        need(root.findtext("./os/nvram")==EXPECTED_NVRAM and
             len(root.findall("./devices/disk[@device='disk']"))==1 and
             root.find("./devices/disk[@device='disk']/source").get("file")==EXPECTED_DISK,
             "Unexpected clone disk/UEFI XML changed")
        need(virsh("domstate",VM).strip()=="shut off" and
             not virsh("list","--name").strip(),
             "A guest was started unexpectedly: STOP")
        need(all(virsh("dumpxml","--inactive",x)==v
                 for x,v in before_other.items()),
             "Protected master/trial saved definition changed: STOP")
        need(not virsh("snapshot-list",VM,"--name").strip(),
             "Unexpected snapshot during NIC operation: STOP")
        need(boot.domain_autostart(VM) is False,
             "VM autostart unexpectedly enabled")
        return {
            "result":"SSL55_WIN11_1_BENIGN_ONLY_NIC_SAVED_SHUTOFF",
            "vm":VM,"uuid":UUID,"mac":MAC,"network":NET,
            "guest_still_shutoff":True,
            "guest_ipv4_static_applied":False,
            "ipv4_egress_negative_tested":False,
            "ipv6_egress_negative_tested":False,
            "snapshot_created":False,
            "malware_analysis_authorized":False,
        }
    except Exception as exc:
        raise BenignBlocked(
            ("PARTIAL: saved NIC may be attached; DO NOT RETRY or boot VM. "
             if wrote else "BLOCKED before NIC attachment: ")+str(exc)) from exc
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","attach-benign"),default="plan")
    args=p.parse_args()
    try:
        print(json.dumps(plan() if args.mode=="plan" else attach(),
                         indent=2,sort_keys=True))
        return 0
    except (BenignBlocked,guard.AuditBlocked,boot.BootBlocked,
            OSError,TypeError,ValueError,ET.ParseError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
