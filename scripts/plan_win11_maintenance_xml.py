#!/usr/bin/env python3
"""Plan an offline Windows maintenance XML change; no libvirt writes or VM boot.

Retain original guest name, UUID, firmware NVRAM, and TPM. Use the already
prepared QCOW2 maintenance overlay in place of the active disk, and omit
temporary network/USB/SPICE-agent integration devices. The original XML
must be retained separately for eventual recovery.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET

class MaintenancePlanError(ValueError):
    pass

def require(condition, why):
    if not condition:
        raise MaintenancePlanError(why)

def plan(original_xml: str, original_disk: str, overlay_disk: str) -> tuple[str,dict]:
    doc=ET.fromstring(original_xml)
    require(doc.findtext("./name")=="win11","Unexpected VM name")
    require(bool(doc.findtext("./uuid")),"Missing guest UUID")
    nvram=doc.find("./os/nvram")
    require(nvram is not None and bool((nvram.text or "").strip()),
            "Expected original UEFI NVRAM")
    devices=doc.find("./devices")
    require(devices is not None,"Missing devices section")
    tpms=devices.findall("./tpm")
    require(len(tpms)==1 and tpms[0].find("backend") is not None and
            tpms[0].find("backend").get("type")=="emulator",
            "Expected original emulator TPM")
    disks=devices.findall("./disk[@device='disk']")
    require(len(disks)==1,"Expected exactly one system disk")
    source=disks[0].find("source")
    driver=disks[0].find("driver")
    require(source is not None and source.get("file")==original_disk
            and driver is not None and driver.get("type")=="qcow2",
            "Unexpected master disk definition")
    interfaces=devices.findall("./interface")
    require(len(interfaces)==1,"Expected exactly one master interface")
    nic_source=interfaces[0].find("source")
    require(interfaces[0].get("type")=="network" and
            nic_source is not None and nic_source.get("network")=="default",
            "Original NIC differs from expected NAT source")
    for tag in ("hostdev","filesystem","smartcard","shmem","vsock","crypto"):
        require(not devices.findall("./"+tag),
                "Additional host-connected device requires review: "+tag)
    require(not any(e.tag.endswith("}commandline") for e in doc.iter()),
            "Custom QEMU command line requires review")
    for item in devices.findall("./redirdev"):
        require(item.get("type")=="spicevmc" and item.get("bus")=="usb",
                "Unexpected USB redirection type requires review")
    for item in devices.findall("./serial")+devices.findall("./parallel"):
        require(item.get("type") in ("pty","null","file"),
                "External serial/parallel transport requires review")
    graphics=devices.findall("./graphics")
    require(len(graphics)<=1,"Unexpected multiple graphical consoles")
    for g in graphics:
        require(g.get("type") in ("spice","vnc"),
                "Unexpected graphics type")
        # A remote graphics listener must not silently survive maintenance.
        for listen in g.findall("./listen"):
            require(listen.get("type") in ("address","socket"),
                    "Unexpected graphics listen transport")
            if listen.get("type")=="address":
                require(listen.get("address") in (None,"127.0.0.1","::1"),
                        "External graphics listener requires review")
        require(g.get("listen") in (None,"127.0.0.1","::1"),
                "External graphics listener requires review")
    removed={}
    for tag in ("interface","redirdev","redirfilter","channel"):
        entries=list(devices.findall("./"+tag))
        removed[tag]=len(entries)
        for node in entries:
            devices.remove(node)
    source.set("file",overlay_disk)
    out=ET.tostring(doc,encoding="unicode")
    check=ET.fromstring(out)
    require(check.findtext("./uuid")==ET.fromstring(original_xml).findtext("./uuid"),
            "Guest UUID changed")
    require((check.find("./os/nvram").text or "").strip()==nvram.text.strip(),
            "Original NVRAM changed")
    require(len(check.findall("./devices/tpm"))==1,
            "Original TPM device changed")
    require(check.find("./devices/disk[@device='disk']/source").get("file")==
            overlay_disk,"Maintenance overlay not selected")
    for tag in removed:
        require(not check.findall("./devices/"+tag),
                "Host integration survived sanitization: "+tag)
    return out,{
        "guest_identity_retained":True,
        "original_nvram_path_retained":True,
        "original_tpm_device_retained":True,
        "guest_nic_count":0,
        "usb_redirection_count":0,
        "guest_channel_count":0,
        "temporary_removals":removed,
        "maintenance_overlay_selected":True,
        "writes_performed":False,
    }
