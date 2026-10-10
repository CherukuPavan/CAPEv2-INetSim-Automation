#!/usr/bin/env python3
"""Prototype: personalize a COPY of a powered-off clone's Windows SYSTEM hive.

NEVER accepts a live Windows disk, a QCOW2, or the protected Windows master.
Reads an extracted Windows SYSTEM hive and writes a separate, new hive file.
Uses libhivex on a scratch copy and validates the new file before publication.

Network policy is not modified. Windows can allocate a new NIC GUID when
hardware MAC changes, so results need a benign guest boot with no egress.
Do not inject this hive into any clone without a separate restore/boot test.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

import inspect_standalone_windows_hive as hiveins

HOSTNAME=re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,14}\Z")
OLD_IP="192.168.122.125"
NETWORK=ipaddress.IPv4Network("192.168.240.0/24")
MASK="255.255.255.0"
GATEWAY="192.168.240.1"

class HivePatchBlocked(RuntimeError):pass

def require(ok,msg):
    if not ok:raise HivePatchBlocked(msg)

def reg_multisz(strings):
    require(isinstance(strings,(list,tuple)) and all(isinstance(x,str) for x in strings),
            "Malformed Registry MULTI_SZ values")
    return ("\x00".join(strings)+"\x00\x00").encode("utf-16-le")

def reg_sz(text):
    require(isinstance(text,str) and "\x00" not in text,
            "Malformed Windows REG_SZ")
    return (text+"\x00").encode("utf-16-le")

def resolve_nodes(hive,controlset):
    root=hive.root()
    ctrl=hiveins.require_child(hive,root,f"ControlSet{controlset:03d}")
    control=hiveins.require_child(hive,ctrl,"Control")
    names=hiveins.require_child(hive,control,"ComputerName")
    pending=hiveins.require_child(hive,names,"ComputerName")
    active=hiveins.require_child(hive,names,"ActiveComputerName")
    svc=hiveins.require_child(hive,ctrl,"Services")
    tcpip=hiveins.require_child(hive,svc,"Tcpip")
    params=hiveins.require_child(hive,tcpip,"Parameters")
    interfaces=hiveins.require_child(hive,params,"Interfaces")
    return params,interfaces,pending,active

def safely_patch(hive,old_ip,new_ip,hostname):
    try:
        addr=ipaddress.IPv4Address(new_ip)
        require(addr in NETWORK and addr not in (
                NETWORK.network_address,NETWORK.broadcast_address,
                ipaddress.IPv4Address(GATEWAY)),
                "New guest IP conflicts with bridge or subnet")
        require(new_ip!=old_ip and old_ip==OLD_IP,
                "Unexpected previously configured NIC address")
        require(HOSTNAME.fullmatch(hostname) is not None,
                "Invalid NetBIOS hostname")
        details=hiveins.inspect(hive,expected_ip=old_ip)
        matches=details["matched_static_interfaces"]
        require(len(matches)==1,"Ambiguous Windows original NIC")
        guid=matches[0]["interface_guid"]
        controlset=details["controlset"]
        params,interfaces,pending,active=resolve_nodes(hive,controlset)
        nic=hiveins.require_child(hive,interfaces,guid)
        def write(node,name,typ,value):
            hive.node_set_value(node,{"key":name,"t":typ,"value":value})
        write(nic,"EnableDHCP",hiveins.REG_DWORD,(0).to_bytes(4,"little"))
        write(nic,"IPAddress",hiveins.REG_MULTI_SZ,reg_multisz([new_ip]))
        write(nic,"SubnetMask",hiveins.REG_MULTI_SZ,reg_multisz([MASK]))
        # The isolated host bridge serves as a non-forwarding local gateway;
        # guard policy must DROP all undesired guest forwarding.
        write(nic,"DefaultGateway",hiveins.REG_MULTI_SZ,reg_multisz([GATEWAY]))
        # INetSim DNS not yet installed; avoid real resolvers in clone.
        write(nic,"NameServer",hiveins.REG_SZ,reg_sz(""))
        write(pending,"ComputerName",hiveins.REG_SZ,reg_sz(hostname))
        write(active,"ComputerName",hiveins.REG_SZ,reg_sz(hostname))
        write(params,"Hostname",hiveins.REG_SZ,reg_sz(hostname))
        write(params,"NV Hostname",hiveins.REG_SZ,reg_sz(hostname))
        return {"result":"OFFLINE_SYSTEM_HIVE_PATCHED_IN_MEMORY",
                "new_ip":new_ip,"hostname":hostname,
                "original_interface_guid":guid,
                "active_controlset":controlset,
                "network_subnet":str(NETWORK),
                "guest_nic_hardware_mapping_verified":False,
                "guest_boot_verified":False}
    except HivePatchBlocked:
        raise
    except (ValueError,hiveins.HiveReadError) as exc:
        raise HivePatchBlocked(str(exc)) from exc
    except Exception as exc:
        raise HivePatchBlocked("Hivex write failed: "+
                               type(exc).__name__) from exc

def verify_source(path):
    require(path.is_absolute() and not path.is_symlink() and path.is_file(),
            "Extracted SYSTEM input must be an absolute, non-symlink regular file")
    require(path.name=="SYSTEM",
            "Refusing arbitrary master file or other Windows hive name")
    st=path.stat()
    require(stat.S_ISREG(st.st_mode) and
            4096<=st.st_size<=hiveins.MAX_BYTES and
            not (st.st_mode&0o022),
            "Extracted hive permissions, type or size unsafe")
    require(path.open("rb").read(4)==b"regf","Input is not an NT registry hive")

def patch_copy(input_path,output_path,new_ip,hostname):
    require(os.geteuid()==0,"Root required for protected hive experiments")
    verify_source(input_path)
    require(output_path.is_absolute() and
            not output_path.exists() and not output_path.is_symlink() and
            output_path.parent.is_dir() and
            output_path.parent==input_path.parent and
            output_path.name.startswith("SYSTEM."+hostname+"."),
            "Refusing unsafe output path or potential overwrite")
    source_hash=hashlib.sha256(input_path.read_bytes()).hexdigest()
    # Verify old cloned NIC before any writable Hivex open.
    hiveins.inspect_file(input_path,expected_ip=OLD_IP)
    try:
        import hivex
    except ImportError as exc:
        raise HivePatchBlocked("python3-hivex unavailable") from exc
    with tempfile.TemporaryDirectory(prefix="cape-hive-",dir=str(input_path.parent)) as td:
        scratch=Path(td)/"scratch-SYSTEM"
        committed=Path(td)/"committed-SYSTEM"
        shutil.copyfile(input_path,scratch)
        scratch.chmod(0o600)
        writer=hivex.Hivex(str(scratch),write=True)
        result=safely_patch(writer,OLD_IP,new_ip,hostname)
        writer.commit(str(committed))
        del writer
        committed.chmod(0o600)
        post=hiveins.inspect_file(committed,expected_ip=new_ip)
        require(len(post["matched_static_interfaces"])==1 and
                post["matched_static_interfaces"][0]["static_ipv4"]==new_ip,
                "Written copy does not contain expected unique static IPv4")
        import hashlib as _h
        require(_h.sha256(input_path.read_bytes()).hexdigest()==source_hash,
                "Extracted source hive changed unexpectedly")
        # Hardlink publish O_EXCL semantics without overwriting any
        # user-controlled or existing file; scratch directory same FS.
        os.link(committed,output_path,follow_symlinks=False)
    result.update(
        result="INDEPENDENT_CLONE_SYSTEM_HIVE_COPY_PERSONALIZED",
        source_hive_unchanged=True,
        output_path=str(output_path),
        output_is_clone_only=True,
        injected_into_vm=False,
        boot_verified=False)
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--ip",required=True)
    p.add_argument("--hostname",required=True)
    a=p.parse_args()
    try:
        print(json.dumps(patch_copy(a.input,a.output,a.ip,a.hostname),
                         indent=2,sort_keys=True))
        return 0
    except (HivePatchBlocked,OSError,ValueError) as exc:
        print("BLOCKED: "+str(exc),file=sys.stderr)
        return 2
if __name__=="__main__":sys.exit(main())
