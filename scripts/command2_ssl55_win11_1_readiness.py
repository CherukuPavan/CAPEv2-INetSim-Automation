#!/usr/bin/env python3
"""READ ONLY: SSL-55 existing win11_1 network + CAPE snapshot readiness.

This examines the ALREADY EXISTING single analysis clone. No VM creation,
shutdown, boot, guest changes, disk copies, NAT, NIC attach, libvirt
network activation, firewall edits, CAPE service changes or snapshot
capture. Not a release certificate or isolation/eagress proof.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VM="win11_1"
UUID="732b2256-ee99-41fa-881d-fbf5c476d960"
NET="cape-analysis-isolated"
BRIDGE="cape-lab0"
SENTINEL=Path("/var/backups/cape-win11-preservation/win11-state-92POdfNc")

class ReadinessBlocked(RuntimeError):
    pass

def command(*args):
    try:
        result=subprocess.run(args,check=False,capture_output=True,
                              text=True,timeout=25)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise ReadinessBlocked("Read-only command unavailable: "+args[0]) from exc
    return result.returncode,result.stdout.strip()

def virsh(*args):
    return command("virsh","-c","qemu:///system",*args)

def need(ok,msg):
    if not ok:
        raise ReadinessBlocked(msg)

def xml_parts(raw,view):
    try:
        root=ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ReadinessBlocked("Unreadable "+view+" domain XML") from exc
    need(root.tag=="domain" and root.get("type")=="kvm" and
         root.findtext("name")==VM and root.findtext("uuid")==UUID,
         "Existing win11_1 identity differs: "+view)
    nics=[]
    for child in root.findall("./devices/interface"):
        source=child.find("source")
        mac=child.find("mac")
        model=child.find("model")
        nics.append({
            "type":child.get("type"),
            "network":source.get("network") if source is not None else None,
            "bridge":source.get("bridge") if source is not None else None,
            "mac":mac.get("address") if mac is not None else None,
            "model":model.get("type") if model is not None else None,
        })
    disks=[]
    for child in root.findall("./devices/disk[@device='disk']"):
        source=child.find("source")
        driver=child.find("driver")
        path=source.get("file") if source is not None else None
        disks.append({
            "path":path,"format":driver.get("type") if driver is not None else None,
            "independent_clone_filename":
                bool(path and path.endswith("/win11_1.command2.qcow2")),
        })
    tpm=root.find("./devices/tpm/backend")
    return {
        "nics":nics, "disks":disks,
        "uefi_nvram":root.findtext("./os/nvram"),
        "tpm_emulator_v2":bool(tpm is not None and
                                 tpm.get("type")=="emulator" and
                                 tpm.get("version")=="2.0"),
        "snapshots_not_inferred_from_xml":True,
    }

def check_ipv4_subnet_overlap(cidr="192.168.240.0/24"):
    """Summarize kernel routes/addresses that overlap candidate CAPE CIDR."""
    intended=ipaddress.IPv4Network(cidr,strict=True)
    commands=(("ip","-j","-4","route","show","table","all"),
              ("ip","-j","-4","addr","show"))
    parsed=[]
    for args in commands:
        result,payload=command(*args)
        if result!=0:
            return {"inventory_available":False,
                    "nonbridge_overlaps":None,
                    "no_nonbridge_collision_proven":False}
        try:
            entries=json.loads(payload)
        except (json.JSONDecodeError,ValueError) as exc:
            raise ReadinessBlocked("Malformed host IPv4 inventory") from exc
        need(type(entries) is list,"Unexpected host IP JSON shape")
        parsed.append(entries)
    matches=set()
    for entry in parsed[0]:
        if type(entry) is not dict:
            continue
        dev=entry.get("dev","unknown")
        dst=entry.get("dst","default")
        if dst in ("default",None):
            continue
        try:
            network=ipaddress.IPv4Network(dst,strict=False)
        except (ValueError,TypeError):
            continue
        if network.overlaps(intended) and dev!=BRIDGE:
            matches.add(("route",str(dev),str(network)))
    for device in parsed[1]:
        if type(device) is not dict:
            continue
        name=device.get("ifname","unknown")
        for address in device.get("addr_info",[]):
            if type(address) is not dict or address.get("family")!="inet":
                continue
            try:
                net=ipaddress.IPv4Network(
                    str(address["local"])+"/"+str(address["prefixlen"]),
                    strict=False)
            except (ValueError,TypeError,KeyError):
                continue
            if net.overlaps(intended) and name!=BRIDGE:
                matches.add(("interface",str(name),str(net)))
    conflicts=[{"source":src,"device":dev,"subnet":net}
               for src,dev,net in sorted(matches)]
    return {"inventory_available":True,
            "nonbridge_overlaps":conflicts,
            "no_nonbridge_collision_proven":len(conflicts)==0}


def check():
    actual=socket.gethostname().split(".",1)[0].lower()
    need(actual in ("ssl-55","cse-ssl-55"),
         "This inventory is restricted to reference SSL-55")
    need(SENTINEL.is_dir() and not SENTINEL.is_symlink(),
         "Protected original-master preservation marker not present")
    code,uid=virsh("domuuid",VM)
    need(code==0 and uid.lower()==UUID, "Existing clone UUID changed")
    code,state=virsh("domstate",VM)
    need(code==0 and state in ("running","shut off","paused"),
         "Existing clone state unexpected")
    views={}
    for view,args in (("inactive",("dumpxml","--inactive",VM)),
                      ("live",("dumpxml",VM))):
        if view=="live" and state=="shut off":
            continue
        code,out=virsh(*args)
        need(code==0,"Failed to read "+view+" win11_1 libvirt XML")
        views[view]=xml_parts(out,view)
    code,nets=virsh("net-info",NET)
    if code==0:
        fields={}
        for line in nets.splitlines():
            key,sep,val=line.partition(":")
            if sep and key.strip().lower() in ("name","active","autostart","bridge","persistent"):
                fields[key.strip().lower()]=val.strip().lower()
        network={
            "defined":True,
            "active":fields.get("active"),
            "autostart":fields.get("autostart"),
            "bridge":fields.get("bridge"),
            "persistent":fields.get("persistent")
        }
    else:
        network={"defined":False,"active":None,"autostart":None,
                 "bridge":None,"persistent":None}
    code,net_xml=virsh("net-dumpxml",NET)
    if code==0:
        try:
            nr=ET.fromstring(net_xml)
        except ET.ParseError as exc:
            raise ReadinessBlocked("Analysis network XML malformed") from exc
        network["no_forward_element"]=nr.find("forward") is None
        network["no_dhcp_element"]=not nr.findall(".//dhcp")
        network["bridge_matches_plan"]=bool(
            nr.find("bridge") is not None and
            nr.find("bridge").get("name")==BRIDGE)
        network["ipv4_bridge_address"]=[
            n.get("address") for n in nr.findall("./ip")
            if n.get("family") in (None,"ipv4")]
        network["ipv6_element_present"]=any(
            n.get("family")=="ipv6" for n in nr.findall("./ip"))
    else:
        network["network_xml_available"]=False
    nft_tables={}
    for family,table in (("inet","cape_analysis_guard"),
                         ("inet","cape_analysis_cmd2_guard")):
        code,out=command("nft","-a","list","table",family,table)
        nft_tables[table]={
            "present":code==0,
            "contains_forward_hook":bool(code==0 and "hook forward" in out),
            "contains_input_hook":bool(code==0 and "hook input" in out),
            "rules_unchanged_by_inventory":True
        }
    code,snapshots=virsh("snapshot-list",VM,"--name")
    snapshot_result={
        "inventory_available":code==0,
        "names":snapshots.splitlines() if code==0 else [],
        "running_cape_snapshot_found":
            code==0 and "cape_ready_win11_1" in snapshots.splitlines(),
        "memory_disk_snapshot_validated":False,
        "snapshot_revert_tested":False
    }
    subnet_conflicts=check_ipv4_subnet_overlap()
    code,space=command("df","-Pk","/var/lib/libvirt/images")
    disk_free_kib=None
    if code==0 and len(space.splitlines())>=2:
        parts=space.splitlines()[-1].split()
        if len(parts)>=4 and parts[3].isdigit():
            disk_free_kib=int(parts[3])
    return {
        "result":"SSL55_WIN11_1_COMMAND2_READINESS_READ_ONLY",
        "host":actual,"vm":VM,"uuid":UUID,"power_state":state,
        "domain_views":views,
        "analysis_network":network,
        "analysis_ipv4_subnet_overlap":subnet_conflicts,
        "nft_guard_presence_not_proof_of_effectiveness":nft_tables,
        "snapshots":snapshot_result,
        "images_fs_free_gib":round(disk_free_kib/1048576,2)
                             if disk_free_kib is not None else None,
        "planned_first_analysis_guest_static_ipv4":"192.168.240.101",
        "guest_windows_static_ipv4_verified":False,
        "host_ipv4_egress_isolation_proved":False,
        "host_ipv6_egress_isolation_proved":False,
        "firewall_reboot_persistence_proved":False,
        "guest_cape_agent_http_port_8000_verified":False,
        "guest_running_snapshot_restore_proved":False,
        "master_modified":False,"clone_modified":False,
        "host_network_modified":False,
        "next":"Review the read-only report before any isolated NIC or snapshot action."
    }

def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(check(),indent=2,sort_keys=True))
        return 0
    except (ReadinessBlocked,OSError,ValueError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
