#!/usr/bin/env python3
"""SSL55 read-only CAPE bridge runtime L2-configuration audit.

Inspects exact running clone, libvirt no-forward network, kernel bridge
membership + actual TAP isolation bit, IPv6 bridge addresses, and CAPE
nft firewall chain structure. Does NOT transmit guest-to-guest packets.
Never mutates VM, guest, disk, firewall, network or routes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_1"
UID="732b2256-ee99-41fa-881d-fbf5c476d960"
NIC_MAC="02:0a:30:6a:3f:50"
MASTER=("win11","289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL=("win11_trial_1","e75f6fef-347d-462f-9738-4de3df6bfa74")
NETWORK="cape-analysis-isolated"
BRIDGE="cape-lab0"
GATEWAY="192.168.240.1"
GUEST_IP="192.168.240.101"
DISK="/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
VARS="/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
KERNEL_NET=Path("/sys/class/net")
GIB=1024**3

class Blocked(RuntimeError):
    pass

def need(ok,reason):
    if not ok:
        raise Blocked(reason)

def read(*args,timeout=30):
    try:
        cp=subprocess.run(args,text=True,capture_output=True,check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired) as ex:
        raise Blocked("Read-only command failed/timed out: "+args[0]) from ex
    need(cp.returncode==0,"Read-only host utility nonzero: "+args[0])
    need(len(cp.stdout)<2_000_000,"Unexpectedly oversized read-only output")
    return cp.stdout.strip()

def virsh(*args):
    return read("virsh","-c","qemu:///system",*args)

def props(raw):
    values={}
    for line in raw.splitlines():
        k,sep,v=line.partition(":")
        if not sep:continue
        key=k.strip().lower()
        need(key not in values,"Duplicate libvirt status: "+key)
        values[key]=v.strip().lower()
    return values

def xml_check(xml,is_live):
    root=ET.fromstring(xml)
    need(root.tag=="domain" and root.findtext("name")==VM and
         root.findtext("uuid")==UID,"Unexpected pilot identity")
    disks=root.findall("./devices/disk[@device='disk']")
    need(len(disks)==1,"Unexpected number of guest disks")
    primary=disks[0]
    drv=primary.find("driver"); src=primary.find("source")
    need(drv is not None and drv.get("type")=="qcow2" and
         src is not None and src.get("file")==DISK,
         "Unexpected guest disk")
    chain=primary.find("backingStore")
    need(chain is None or
         (chain.find("source") is None and chain.find("backingStore") is None),
         "Guest disk backing chain unexpectedly returned")
    need(root.findtext("./os/nvram")==VARS,"Unexpected UEFI NVRAM")
    t=root.findall("./devices/tpm/backend")
    need(len(t)==1 and t[0].get("type")=="emulator" and
         t[0].get("version")=="2.0","Unexpected TPM2 emulator")
    nics=root.findall("./devices/interface")
    need(len(nics)==1 and nics[0].get("type")=="network",
         "Unexpected NIC count/type")
    n=nics[0]
    mac=n.find("mac");source=n.find("source");target=n.find("target")
    need(mac is not None and mac.get("address","").lower()==NIC_MAC and
         source is not None and source.get("network")==NETWORK,
         "NIC MAC/isolated network differs")
    if not is_live:
        return None
    need(target is not None and
         bool(re.fullmatch(r"(?:vnet|tap)[0-9]{1,5}",target.get("dev",""))),
         "Live guest TAP interface name unexpectedly missing/different")
    return target.get("dev")

def domain_preflight():
    need(os.geteuid()==0,"sudo required to inspect bridge and firewall")
    need(socket.gethostname().split(".",1)[0].lower()=="cse-ssl-55",
         "Only canonical CSE-SSL-55 pilot host supported")
    for name,uuid,state in ((VM,UID,"running"),
                            (MASTER[0],MASTER[1],"shut off"),
                            (TRIAL[0],TRIAL[1],"shut off")):
        need(virsh("domuuid",name).lower()==uuid and
             virsh("domstate",name).lower()==state,
             "Protected VM identity/state unexpectedly changed: "+name)
    need(virsh("list","--name").splitlines()==[VM],
         "Unexpected other guest actively running on shared host")
    need(not virsh("snapshot-list",VM,"--name").strip(),
         "Unexpected clone snapshot exists")
    xml_check(virsh("dumpxml","--inactive",VM),False)
    return xml_check(virsh("dumpxml",VM),True)

def network_preflight():
    values=props(virsh("net-info",NETWORK))
    need(values.get("active")=="yes" and
         values.get("persistent")=="yes" and
         values.get("autostart")=="no" and
         values.get("bridge")==BRIDGE,"Unexpected analysis network status")
    net=ET.fromstring(virsh("net-dumpxml",NETWORK))
    bridge=net.find("bridge")
    port=net.find("port")
    dns=net.find("dns")
    ip=net.findall("ip")
    need(net.tag=="network" and net.findtext("name")==NETWORK and
         bridge is not None and bridge.get("name")==BRIDGE and
         port is not None and port.get("isolated")=="yes" and
         dns is not None and dns.get("enable")=="no" and
         net.find("forward") is None and
         not net.findall(".//dhcp") and not net.findall(".//route") and
         len(ip)==1 and ip[0].get("address")==GATEWAY and
         ip[0].get("netmask")=="255.255.255.0",
         "Analysis network XML no longer port-isolated/no-forward")
    return True

def bridge_config(tap,sysfs_root=KERNEL_NET):
    br=sysfs_root/BRIDGE
    port=br/"brif"/tap
    need(br.is_dir() and (br/"bridge").is_dir(),
         "CAPE Linux bridge missing")
    need(port.exists(),"Clone TAP is not member of CAPE bridge")
    members=sorted(x.name for x in (br/"brif").iterdir())
    need(members==[tap],
         "Unexpected other port on CAPE bridge; peer/campus exposure unreviewed")
    member_dir=sysfs_root/tap
    master=member_dir/"master"
    need(master.is_symlink() and master.resolve()==br.resolve(),
         "TAP is not enslaved to expected CAPE bridge")
    isolation=member_dir/"brport"/"isolated"
    need(isolation.is_file(),"Linux bridge per-port isolation flag unreadable")
    bit=isolation.read_text().strip()
    need(bit=="1","Linux kernel bridge per-port isolation flag is NOT enabled")
    return {"bridge":BRIDGE,
            "live_clone_tap":tap,
            "bridge_member_ports":members,
            "tap_kernel_isolated_flag":1,
            "bridge_tap_membership_verified":True,
            "no_other_bridge_ports_at_inspection":True}

def bridge_ipv6():
    """ip -j -6 addr can legitimately return [] with no IPv6 addresses.

    Confirm the named Linux link independently before allowing that empty
    address inventory. Malformed/foreign interfaces or routable addresses
    remain a hard refusal; this checks bridge metadata, not guest egress.
    """
    try:
        link=json.loads(read("ip","-j","link","show","dev",BRIDGE))
        data=json.loads(read("ip","-j","-6","addr","show","dev",BRIDGE))
    except (TypeError,ValueError) as exc:
        raise Blocked("Cannot parse CAPE bridge link/IPv6 inventory") from exc
    need(type(link) is list and len(link)==1 and type(link[0]) is dict and
         link[0].get("ifname")==BRIDGE,
         "Expected CAPE bridge kernel link missing")
    need(type(data) is list and len(data)<=1,
         "Unexpected CAPE bridge IPv6 interface inventory")
    if not data:
        return {"no_global_ipv6_address_on_bridge":True,
                "ipv6_inventory_empty":True,
                "kernel_bridge_link_present":True}
    need(type(data[0]) is dict and data[0].get("ifname")==BRIDGE,
         "Unexpected CAPE bridge IPv6 interface identity")
    addr=data[0].get("addr_info")
    need(type(addr) is list and all(type(z) is dict for z in addr),
         "Unexpected CAPE bridge IPv6 address list")
    need(not any(z.get("scope") not in ("link","host") for z in addr),
         "Non-link-local IPv6 CAPE bridge address unexpectedly present")
    return {"no_global_ipv6_address_on_bridge":True,
            "ipv6_inventory_empty":False,
            "kernel_bridge_link_present":True}

def firewall_shape():
    need(read("systemctl","is-active","cape-analysis-guard.service")=="active",
         "CAPE host firewall guard service not active")
    sys.path.insert(0,"/usr/local/libexec/cape-command2")
    try:
        import command2_ssl55_existing_guard_readonly as guard
    except ImportError as exc:
        raise Blocked("Installed reviewed nft guard checker unavailable") from exc
    json_text=read("nft","-j","list","table","inet","cape_analysis_guard")
    plain=read("nft","list","table","inet","cape_analysis_guard")
    try:
        result=guard.guard_policy_structure(json_text,plain)
    except guard.AuditBlocked as exc:
        raise Blocked("CAPE nft guard structural mismatch: "+str(exc)) from exc
    need(result.get("expected_chain_hooks_and_order") is True and
         result.get("bridge_addr_agent_port_tokens_present") is True,
         "Incomplete CAPE nftables guard evidence")
    return {"nftables_cape_guard_policy_shape_verified":True,
            "dedicated_firewall_service_active":True,
            "guest_firewall_packet_path_negative_tested":False}

def perform():
    tap=domain_preflight()
    network_preflight()
    bridge=bridge_config(tap)
    v6=bridge_ipv6()
    guard=firewall_shape()
    folder=Path(DISK).parent
    v=os.statvfs(folder)
    free=v.f_bavail*v.f_frsize
    return {"result":"SSL55_RUNTIME_ISOLATED_BRIDGE_POLICY_OBSERVED",
            "vm":VM,"vm_running":True,
            "guest_tap":bridge,
            "bridge_ipv6":v6,
            "network_no_forward_no_dhcp_l2_isolated_xml":True,
            "firewall":guard,
            "storage_free_gib":round(free/GIB,2),
            "cold_backup_preserved_not_restored":True,
            "real_guest_to_guest_l2_negative_probe":False,
            "host_firewall_external_packet_negative_test":False,
            "running_snapshot_revert_verified":False,
            "safe_for_malware_execution":False,
            "host_or_guest_changes":False}

if __name__=="__main__":
    try:
        print(json.dumps(perform(),indent=2,sort_keys=True))
    except (Blocked,OSError,TypeError,ValueError,ET.ParseError) as exc:
        print(json.dumps({"result":"BLOCKED_ISOLATION_RUNTIME_INSPECTION",
                          "reason":str(exc),
                          "no_host_guest_mutation_performed":True},indent=2),
              file=sys.stderr)
        raise SystemExit(2)
