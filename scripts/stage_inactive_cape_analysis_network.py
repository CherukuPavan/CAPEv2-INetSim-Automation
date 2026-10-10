#!/usr/bin/env python3
"""Define, but never START, a disposable libvirt analysis-network candidate.

Local-only route/subnet checks cannot identify site-private distant routes.
The network remains INACTIVE, without any guest NICs, even on success.
Not an isolation approval or authorization for malware execution.
"""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

NAME="cape-analysis-isolated"
BRIDGE="cape-lab0"
NET=ipaddress.IPv4Network("192.168.240.0/24")
ADDRESS="192.168.240.1"
TRIAL="win11_trial_1"
UUID="e75f6fef-347d-462f-9738-4de3df6bfa74"
LOCK=Path("/run/lock/cape-cold-export.lock")

class Blocked(RuntimeError): pass
def need(value,message):
    if not value: raise Blocked(message)
def command(*args):
    try:
        return subprocess.run(args,capture_output=True,text=True,
                              check=True,timeout=90).stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as e:
        raise Blocked("Host command failed: "+args[0]) from e
def virsh(*args):
    return command("virsh","-c","qemu:///system",*args)
def network_xml():
    root=ET.Element("network")
    ET.SubElement(root,"name").text=NAME
    ET.SubElement(root,"bridge",{"name":BRIDGE,"stp":"on","delay":"0"})
    ET.SubElement(root,"port",{"isolated":"yes"})
    ET.SubElement(root,"dns",{"enable":"no"})
    ET.SubElement(root,"ip",{"address":ADDRESS,"netmask":str(NET.netmask)})
    return ET.tostring(root,encoding="unicode")
def validate_xml(xml):
    root=ET.fromstring(xml)
    need(root.tag=="network" and root.findtext("name")==NAME,"Wrong network")
    need(root.find("forward") is None,"Network forwarding is enabled")
    bridge=root.find("bridge")
    need(bridge is not None and bridge.get("name")==BRIDGE,"Wrong bridge")
    port=root.find("port")
    need(port is not None and port.get("isolated")=="yes","No port isolation")
    dns=root.find("dns")
    need(dns is not None and dns.get("enable")=="no","DNS unexpectedly enabled")
    ips=root.findall("ip")
    need(len(ips)==1 and ips[0].get("address")==ADDRESS and
         ips[0].get("netmask")==str(NET.netmask) and
         ips[0].find("dhcp") is None,"Unexpected IP address or DHCP")
    need(not root.findall("route") and not root.findall("virtualport") and
         not root.findall("portgroup"),"Unreviewed virtual network features")

def ip_json(*args):
    result=json.loads(command("ip","-j",*args))
    need(isinstance(result,list) and len(result)<=4096,
         "Unexpected host network inventory size")
    return result

def preflight():
    need(os.geteuid()==0,"Root privileges required")
    need(virsh("domstate","win11")=="shut off","Master not shut off")
    need(virsh("domstate",TRIAL)=="running","Trial must be running")
    for args in (("dumpxml",TRIAL),("dumpxml","--inactive",TRIAL)):
        guest=ET.fromstring(virsh(*args))
        need(guest.findtext("name")==TRIAL and guest.findtext("uuid")==UUID and
             not guest.findall("./devices/interface"),
             "Trial VM changed or has a network adapter")
    validate_xml(network_xml())
    need(NAME not in virsh("net-list","--all","--name").splitlines(),
         "Network already exists; refusing redefinition")
    links=ip_json("link","show")
    need(not any(x.get("ifname")==BRIDGE for x in links),
         "Bridge name already allocated")
    routes=ip_json("-4","route","show","table","all")
    addresses=ip_json("-4","address","show")
    networks=[]
    for entry in routes:
        cidr=entry.get("dst","default")
        if cidr=="default": continue
        try: networks.append(ipaddress.ip_network(cidr,strict=False))
        except (ValueError,TypeError): raise Blocked("Unparseable host IPv4 route")
    for link in addresses:
        for addr in link.get("addr_info",[]):
            if addr.get("family")!="inet":continue
            try: networks.append(ipaddress.IPv4Interface(
                str(addr["local"])+"/"+str(addr["prefixlen"])).network)
            except (KeyError,ValueError,TypeError):
                raise Blocked("Unparseable host IPv4 address")
    need(not any(n.version==4 and NET.overlaps(n) for n in networks),
         "Candidate lab subnet overlaps local host network")
    return {"network":NAME,"bridge":BRIDGE,"subnet":str(NET),
            "host_guest_ip":ADDRESS,
            "guest_ports_isolated":True,
            "forwarding_enabled":False,"dns_enabled":False,"dhcp_enabled":False,
            "local_overlap":False,
            "remote_organizational_overlap_checked":False,
            "guest_network_connected":False,
            "guest_egress_containment_verified":False}

def perform(mode):
    if mode=="plan":
        r=preflight()
        return dict(r,result="READ_ONLY_INACTIVE_NETWORK_PLAN",
                    definition_created=False)
    need(not LOCK.is_symlink(),"Unsafe disk/network coordination lock")
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        stat=os.fstat(fd)
        need(stat.st_uid==0 and not stat.st_mode & 0o077,
             "Unsafe coordination lock ownership")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        report=preflight()
        with tempfile.TemporaryDirectory(prefix="cape-net-define-",dir="/run") as d:
            xml_path=Path(d)/"inactive-lab.xml"
            xml_path.write_text(network_xml())
            xml_path.chmod(0o600)
            command("virsh","-c","qemu:///system",
                    "net-define",str(xml_path),"--validate")
        # Deliberately NO net-start or net-autostart.
        info=virsh("net-info",NAME)
        need(re.search(r"^Active:\s+no\s*$",info,re.M|re.I) is not None,
             "Network unexpectedly active; do not connect VMs")
        need(re.search(r"^Autostart:\s+no\s*$",info,re.M|re.I) is not None,
             "Autostart unexpectedly enabled")
        validate_xml(virsh("net-dumpxml",NAME))
        need(virsh("domstate","win11")=="shut off",
             "Original master unexpectedly running")
        report.update(result="INACTIVE_ISOLATED_NETWORK_DEFINED",
                      definition_created=True,network_active=False,
                      autostart=False)
        return report
    finally:os.close(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","define"),default="plan")
    try:
        opts=p.parse_args()
        print(json.dumps(perform(opts.mode),indent=2,sort_keys=True))
    except (Blocked,OSError,ValueError,ET.ParseError) as e:
        print("BLOCKED:",str(e),file=sys.stderr)
        return 2
    return 0
if __name__=="__main__":sys.exit(main())
