#!/usr/bin/env python3
"""SSL55 exact-VM DHCP reservation: 192.168.122.131 on MASTER default NAT.

Scope: Existing Windows clone win11_1, already running with exact two
verified guest NICs; existing NAT MAC 02:ca:55:11:01:02 and live lease
192.168.122.131. The user verified real Windows HTTPS 2026-10-12.

PLAN and VERIFY never modify host. APPLY requests an EXACT typed approval
and only adds one <host mac name ip> to the EXISTING default libvirt NAT
network via virsh net-update default add ip-dhcp-host ... --live --config.
Does not run ipconfig /renew, restart dnsmasq/libvirtd, change Windows,
snapshot/revert VM, switch CAPE machine/IP/INetSim or touch the master.
Partial libvirt failures require manual inspection (no auto-retry).
CAPE malware egress remains forbidden while NAT is unrestricted.

Libvirt docs: https://wiki.libvirt.org/Networking.html
"""
from __future__ import annotations
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import xml.etree.ElementTree as ET

import command2_ssl55_dual_nic_agent_readonly as dual

NET="default"
BRIDGE="virbr0"
GUEST="win11_1"
MAC="02:ca:55:11:01:02"
ADDR="192.168.122.131"
NAME="WIN11-1"
LOCK=Path("/run/lock/cape-ssl55-win11-1-permanent-dhcp-reservation.lock")
APPROVE="RESERVE-SSL55-WIN11_1-DHCP-192.168.122.131-ONLY"

class ReservationBlocked(RuntimeError):pass
def need(condition,why):
    if not condition:
        raise ReservationBlocked(why)

def network_xml(inactive):
    return ET.fromstring(dual.virsh("net-dumpxml",NET,
                          *(("--inactive",) if inactive else ())))

def examine_network(root,label):
    forward=root.find("forward")
    bridge=root.find("bridge")
    ips=[x for x in root.findall("ip") if ":" not in x.get("address","")]
    need(root.tag=="network" and root.findtext("name")==NET and
         forward is not None and forward.get("mode","nat")=="nat" and
         bridge is not None and bridge.get("name")==BRIDGE and len(ips)==1,
         "Unexpected default NAT network definition: "+label)
    ip=ips[0]
    prefix=ip.get("prefix")
    mask=ip.get("netmask")
    need(bool(prefix)!=bool(mask) and ip.get("address")=="192.168.122.1",
         "Expected exact default NAT subnet gateway: "+label)
    subnet=ipaddress.IPv4Network("192.168.122.1/"+(prefix or mask),strict=False)
    need(str(subnet)=="192.168.122.0/24",
         "Default NAT subnet changed: "+label)
    dhcp=ip.find("dhcp")
    need(dhcp is not None and len(dhcp.findall("range"))>=1,
         "Expected original default NAT DHCP pools")
    pool=[]
    for r in dhcp.findall("range"):
        first=ipaddress.IPv4Address(r.get("start"))
        last=ipaddress.IPv4Address(r.get("end"))
        need(first<=last and first in subnet and last in subnet,
             "Malformed default NAT DHCP range: "+label)
        pool.append((first,last))
    wanted=ipaddress.IPv4Address(ADDR)
    need(any(lo<=wanted<=hi for lo,hi in pool),
         "Working Windows address is outside original default DHCP range")
    reservations=[]
    for host in dhcp.findall("host"):
        mac=(host.get("mac") or "").lower()
        address=host.get("ip") or ""
        name=host.get("name") or ""
        need(mac and address and name,
             "Unreviewed/incomplete static DHCP host on default NAT")
        reservations.append({"mac":mac,"ip":address,"name":name})
    for row in reservations:
        need(row["mac"]!=MAC or
             (row["ip"]==ADDR and row["name"]==NAME),
             "MAC is already reserved to another IP/name in "+label)
        need(row["ip"]!=ADDR or
             (row["mac"]==MAC and row["name"]==NAME),
             "IP is already reserved for a different MAC/name in "+label)
        need(row["name"].lower()!=NAME.lower() or
             (row["mac"]==MAC and row["ip"]==ADDR and row["name"]==NAME),
             "Hostname already reserved to a different guest")
    exact=sum(row=={"mac":MAC,"ip":ADDR,"name":NAME} for row in reservations)
    need(exact<=1,"Duplicate exact host reservations in "+label)
    return {"view":label,"root_network":"default","bridge":BRIDGE,
            "reservation_count":len(reservations),
            "exact_guest_host_reservation_count":exact,
            "other_host_reservations_unchanged":True}

def inspect():
    need(os.geteuid()==0 and
         socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Only root on protected CSE-SSL-55 can manage this reservation")
    # This performs the complete earlier verified saved/live MAC, UUID,
    # master/trial, snapshot, networking, two exact CAPE Agent probes.
    verified=dual.assess()
    need(verified["vm"]==GUEST and
         verified["snapshot"]==dual.SNAP and
         verified["original_agent_still_reachable"] is True and
         verified["nat_agent_reachable"] is True and
         verified["old_adapter_detached"] is False,
         "Both CAPE Agent routes and original adapter must work")
    lease=verified["nat_lease_observation"]
    need(lease["observed_nat_mac_lease_count"]==1 and
         lease["observed_nat_ips_for_mac"]==[ADDR],
         "NAT lease is not uniquely assigned to exact guest MAC/IP")
    rows=[]
    for line in dual.virsh("net-dhcp-leases",NET).splitlines():
        macmatch=re.search(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b",line)
        ipmatch=re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",line)
        if macmatch and ipmatch:
            mac=macmatch.group(0).lower()
            ip=ipmatch.group(0).split("/")[0]
            need(ip!=ADDR or mac==MAC,
                 "Different MAC has conflicting live DHCP lease for "+ADDR)
            need(mac!=MAC or ip==ADDR,
                 "MAC has conflicting DHCP lease")
            rows.append((mac,ip))
    need(sum(mac==MAC and ip==ADDR for mac,ip in rows)==1,
         "Did not independently find exact Windows active lease")
    live=examine_network(network_xml(False),"live")
    saved=examine_network(network_xml(True),"persistent")
    need(live["exact_guest_host_reservation_count"]==
         saved["exact_guest_host_reservation_count"],
         "Live/config reservation inconsistent, STOP for manual recovery")
    present=live["exact_guest_host_reservation_count"]==1
    return {"result":("SSL55_WIN11_1_NAT_DHCP_RESERVATION_VERIFIED"
                      if present else "SSL55_WIN11_1_NAT_DHCP_RESERVATION_PLAN_ONLY"),
            "vm":GUEST,"nat_mac":MAC,"nat_ipv4":ADDR,
            "hostname":NAME,"gateway_dns":"192.168.122.1",
            "existing_dhcp_guest_lease_confirmed":True,
            "host_cape_agent_at_nat_ip_verified":True,
            "host_cape_agent_at_isolated_ip_verified":True,
            "live_network":live,"persistent_network":saved,
            "reservation_present_in_live_and_config":present,
            "static_windows_ip_changed":False,
            "cape_machine_registration_changed":False,
            "original_nic_removed":False,
            "original_snapshot_preserved":True,
            "final_snapshot_created":False,
            "swtpm_revert_tested":False,
            "malware_analysis_allowed":False}

def apply():
    need(sys.stdin.isatty(),"Direct operator terminal approval required")
    baseline=inspect()
    print(json.dumps(baseline,sort_keys=True,indent=2),flush=True)
    if baseline["reservation_present_in_live_and_config"]:
        return {**baseline,"result":"SSL55_NAT_RESERVATION_ALREADY_PRESENT_NO_WRITE"}
    need(input("Type "+APPROVE+" to reserve only this MAC/IP: ")==APPROVE,
         "Operator did not authorize exact DHCP host reservation")
    need(not LOCK.is_symlink(),"Unsafe DHCP lock symlink")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    attempted=False
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600,
             "Nonprivate DHCP lock metadata")
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReservationBlocked("Another exact DHCP reservation operation is running") from exc
        need(inspect()==baseline,
             "Guest/network/lease/CAPE proof changed after approval")
        xml=f"<host mac='{MAC}' name='{NAME}' ip='{ADDR}'/>"
        attempted=True
        dual.virsh("net-update",NET,"add","ip-dhcp-host",xml,
                   "--live","--config")
        completed=inspect()
        need(completed["reservation_present_in_live_and_config"] is True,
             "Reservation was not independently verified in BOTH network views")
        return {**completed,
                "result":"SSL55_NAT_IP_MAC_DHCP_RESERVATION_APPLIED_AND_VERIFIED",
                "libvirt_network_restart_performed":False,
                "guest_dhcp_renewal_or_restart_requested":False}
    except Exception as exc:
        if attempted:
            raise ReservationBlocked(
                "DHCP_NET_UPDATE_ATTEMPTED_POSSIBLE_PARTIAL_CONFIGURATION: "
                "DO NOT RETRY; inspect live/config reservation and guest lease; "+
                str(exc)) from exc
        raise
    finally:
        os.close(fd)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--mode",choices=("plan","apply","verify"),
                        default="plan")
    args=parser.parse_args()
    try:
        result=apply() if args.mode=="apply" else inspect()
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        if args.mode=="verify":
            need(result["reservation_present_in_live_and_config"] is True,
                 "Required exact MAC/IP reservation missing")
        return 0
    except (ReservationBlocked,dual.ReaddressBlocked,ValueError,
            TypeError,KeyError,OSError,ET.ParseError) as exc:
        print(json.dumps({"result":"SSL55_NAT_DHCP_RESERVATION_BLOCKED",
            "reason":str(exc),"guest_power_or_snapshot_changed":False,
            "manual_review_if_net_update_attempted":True},
            sort_keys=True),file=sys.stderr,flush=True)
        return 2
if __name__=="__main__":raise SystemExit(main())
