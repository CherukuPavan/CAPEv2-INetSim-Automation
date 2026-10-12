#!/usr/bin/env python3
"""Guarded read-only native RUNNING internal snapshot admission (OTHER host).

Never modifies libvirt or firmware. A PASS authorizes only an explicitly
approved *experimental* snapshot capture on a disposable separate-host VM
with a pinned full disk+OVMF+swtpm recovery bundle; it does NOT prove that
libvirt snapshots restore TPM state. A real benign revert remains mandatory.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import xml.etree.ElementTree as ET

GIB=1024**3
RESERVE=40*GIB
MIN_LIBVIRT=(10,10,0)
MIN_QEMU=(9,0,0)

class NativeBlocked(RuntimeError):
    pass

def need(test,why):
    if not test:raise NativeBlocked(why)

def parse_versions(raw):
    def version(line):
        m=re.search(r"(?m)^"+re.escape(line)+r":\s*(?:QEMU\s+)?(\d+)\.(\d+)\.(\d+)\s*$",raw)
        if m is None:raise NativeBlocked("Cannot read "+line+" version from virsh")
        return tuple(int(x) for x in m.groups())
    daemon=version("Running against daemon")
    qemu=version("Running hypervisor")
    need(daemon>=MIN_LIBVIRT,
         "Libvirt daemon older than 10.10: UEFI QCOW2 snapshot revert compatibility not accepted")
    need(qemu>=MIN_QEMU,
         "QEMU older than 9.0: experimental internal snapshot stack not accepted")
    return {"libvirt_daemon_version":".".join(map(str,daemon)),
            "qemu_hypervisor_version":".".join(map(str,qemu)),
            "versions_meet_conservative_snapshot_lab_floor":True}

def command(*args):
    try: p=subprocess.run(args,capture_output=True,text=True,
                          check=False,timeout=60)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise NativeBlocked("Read-only tool unavailable: "+args[0]) from exc
    need(p.returncode==0 and len(p.stdout)<2_000_000,
         "Read-only tool returned error or excessive output: "+args[0])
    return p.stdout.strip()

def inspect(vm):
    """Require firmware QCOW2 on disk and modern libvirt, before risky capture."""
    need(type(vm) is str and re.fullmatch(r"win11_([1-9]|1[0-6])",vm),
         "Only approved disposable Command2 clone identity allowed")
    versions=parse_versions(command("virsh","-c","qemu:///system",
                                    "version","--daemon"))
    raw=command("virsh","-c","qemu:///system","dumpxml",vm)
    domain=ET.fromstring(raw)
    need(domain.findtext("name")==vm and
         domain.get("type")=="kvm","Expected KVM clone missing")
    loader=domain.find("./os/loader")
    nvram=domain.find("./os/nvram")
    need(loader is not None and loader.get("type")=="pflash" and
         nvram is not None and nvram.get("format")=="qcow2" and nvram.text,
         "QEMU internal running pflash snapshot requires QCOW2 NVRAM and matching XML")
    path=Path(nvram.text)
    need(path.is_absolute() and path.name==vm+".command2_VARS.fd" and
         not path.is_symlink() and path.is_file(),
         "NVRAM filename or type not independently reviewed")
    nv_info=json.loads(command("qemu-img","info","-U","--output=json",str(path)))
    need(nv_info.get("format")=="qcow2" and
         not nv_info.get("backing-filename"),
         "Actual UEFI variable store is not standalone QCOW2 despite libvirt XML")
    # Firmware correctness is not enough: swtpm persistent state must be
    # independently recovered by a repeated real revert test.
    t=domain.find("./devices/tpm/backend")
    need(t is not None and t.get("type")=="emulator" and
         t.get("version")=="2.0",
         "Unexpected TPM2 model")
    mem=domain.find("memory")
    need(mem is not None and mem.text and
         mem.get("unit") in ("KiB","MiB","GiB"),
         "Guest memory capacity unknown for snapshot reserve")
    memory=int(mem.text)*{"KiB":1024,"MiB":1024**2,"GiB":GIB}[mem.get("unit")]
    need(0<memory<=128*GIB,"Unexpected snapshot guest memory size")
    disks=domain.findall("./devices/disk[@device='disk']")
    need(len(disks)==1 and disks[0].find("source") is not None and
         disks[0].find("source").get("file","").endswith(
             "/"+vm+".command2.qcow2"),
         "Unreviewed clone OS disk")
    disk=Path(disks[0].find("source").get("file"))
    need(not disk.is_symlink() and disk.is_file(),"Clone disk missing")
    free=os.statvfs(disk.parent)
    available=free.f_bavail*free.f_frsize
    need(available>RESERVE+memory*2+2*GIB,
         "Insufficient headroom for 40GiB host reserve and running-memory snapshot")
    return {"result":"COMMAND2_NATIVE_SNAPSHOT_EXPERIMENT_STACK_ADMITTED",
            "vm":vm,**versions,
            "uefi_variable_store_real_format":"qcow2",
            "uefi_variable_store_is_independent":True,
            "swtpm2_present":True,
            "guest_ram_bytes":memory,
            "available_storage_gib":round(available/GIB,2),
            "snapshot_created":False,
            "real_swtpm_rollback_tested":False,
            "physical_cape_ready":False,
            "no_host_changes":True}
