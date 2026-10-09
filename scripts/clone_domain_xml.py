#!/usr/bin/env python3
"""Render a guarded clone libvirt XML from the configured Windows master.

Rendering is offline and pure (no host changes). The caller must allocate a
unique disk, NVRAM copy, UUID, MAC and approved no-forward network first.
"""
from __future__ import annotations

import copy
import ipaddress
import os
from pathlib import Path
import re
import uuid
import xml.etree.ElementTree as ET

class UnsafeDefinition(ValueError):
    pass

NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,99}\Z")
SAFE_FILE = re.compile(r"/[a-zA-Z0-9_./+@-]{1,4095}\Z")
MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise UnsafeDefinition(message)


def render(master_xml: str, *, name: str, uuid_value: str, mac: str,
           clone_disk: str, clone_nvram: str, isolated_network: str) -> str:
    """Return XML text but do not define the guest."""
    try:
        parsed_uuid = str(uuid.UUID(uuid_value))
        root = ET.fromstring(master_xml)
    except (ValueError, ET.ParseError) as exc:
        raise UnsafeDefinition(f"Malformed libvirt XML/UUID: {exc}") from exc
    _require(root.tag == "domain" and root.get("type") == "kvm",
             "Only KVM domain templates are supported")
    for value, description in ((name,"name"), (isolated_network,"network")):
        _require(bool(NAME.fullmatch(value)), "Unsafe clone "+description)
    for value in (clone_disk, clone_nvram):
        _require(bool(SAFE_FILE.fullmatch(value)) and ".." not in Path(value).parts,
                 "Unsafe clone destination path")
    _require(clone_disk != clone_nvram, "Clone disk and NVRAM paths overlap")
    _require(bool(MAC.fullmatch(mac)), "Malformed unique MAC")
    first_octet=int(mac[:2],16)
    _require(not first_octet & 1, "Multicast MAC is not allowed")
    _require(name != root.findtext("./name"), "Clone name matches original")
    _require(parsed_uuid != root.findtext("./uuid"), "Clone UUID matches master")
    _require(not root.findall("./devices/hostdev"), "Host passthrough devices require review")
    _require(not root.findall("./devices/filesystem"), "Host directory shares are forbidden")
    # Remove inherited USB redirection channels: they bridge host USB into guests.
    # This is an intentional containment exception to otherwise cloned hardware.
    devices = root.find("devices")
    if devices is not None:
        for redirect in list(devices.findall("redirdev")):
            devices.remove(redirect)
    _require(not root.findall("./devices/interface[@type='direct']"), "Direct NIC unsupported")
    _require(not root.findall("./devices/interface[@type='bridge']"), "Host bridge must be inventoried as isolated network")
    _require(not root.findall("./sysinfo"), "Source contains SMBIOS serial settings that might identify duplicate hardware")
    guest_disk=root.findall("./devices/disk[@device='disk']")
    nics=root.findall("./devices/interface")
    _require(len(guest_disk)==1 and len(nics)==1, "Expected one guest disk and one NIC")
    disk=guest_disk[0]
    src=disk.find("source")
    drv=disk.find("driver")
    _require(disk.get("type")=="file" and src is not None and drv is not None and
             drv.get("type")=="qcow2" and src.get("file"), "Source must be file QCOW2")
    _require(src.get("file") != clone_disk, "Refusing master disk as clone disk")
    _require(nics[0].get("type") == "network", "Expected libvirt network NIC")
    nic_source=nics[0].find("source")
    _require(nic_source is not None, "Missing NIC source")
    osnode=root.find("os")
    nvram=osnode.find("nvram") if osnode is not None else None
    _require(nvram is not None and nvram.text is not None and nvram.text.strip(),
             "Master has no inspectable UEFI NVRAM")
    _require(nvram.text.strip()!=clone_nvram,"Clone NVRAM would alias master NVRAM")
    tpms=root.findall("./devices/tpm")
    _require(len(tpms)==1, "Expected exactly one emulated TPM")
    backend=tpms[0].find("backend")
    _require(backend is not None and backend.get("type")=="emulator",
             "Source TPM backend is unsupported")
    _require(backend.find("source") is None,
             "Explicit TPM state paths would be shared")
    # Only a fresh per-UUID libvirt swtpm state is acceptable; no TPM master clone.
    for node in root.findall("./seclabel"):
        root.remove(node)
    for child in ("name", "uuid"):
        node=root.find(child)
        _require(node is not None, "Missing domain "+child)
        node.text=name if child=="name" else parsed_uuid
    genid=root.find("genid")
    if genid is not None:
        genid.text=str(uuid.uuid5(uuid.UUID(parsed_uuid),"windows-genid"))
    src.set("file",clone_disk)
    # Do not depend on the master host's Windows installer ISO path.
    # Leave the CD-ROM hardware present but eject its installation media.
    for optical in root.findall("./devices/disk[@device='cdrom']"):
        medium = optical.find("source")
        if medium is not None:
            optical.remove(medium)
    nvram.text=clone_nvram
    nic_source.attrib.clear()
    nic_source.set("network",isolated_network)
    macnode=nics[0].find("mac")
    if macnode is None:
        macnode=ET.SubElement(nics[0],"mac")
    macnode.set("address",mac.lower())
    # Source may have a fixed port (e.g. 5900) that prevents parallel starts.
    for graphics in root.findall("./devices/graphics"):
        if graphics.get("type") in ("spice","vnc"):
            graphics.set("autoport","yes")
            graphics.set("port","-1")
            graphics.attrib.pop("websocket", None)
        else:
            raise UnsafeDefinition("Unexpected graphics service requiring review")
    # Preserve CPU, RAM, controllers, machine, UEFI, disk bus and guest software.
    return ET.tostring(root, encoding="unicode")


def analyze_static(xml: str) -> dict:
    root=ET.fromstring(xml)
    return {"name":root.findtext("name"),"uuid":root.findtext("uuid"),
            "network":root.find("./devices/interface/source").get("network"),
            "disk":root.find("./devices/disk[@device='disk']/source").get("file"),
            "nvram":root.find("./os/nvram").text,
            "mac":root.find("./devices/interface/mac").get("address")}


def validate_no_forward_network(xml: str) -> None:
    root=ET.fromstring(xml)
    if root.tag != "network" or root.find("forward") is not None:
        raise UnsafeDefinition("Network XML has forwarding enabled or malformed root")
    if root.findall("virtualport") or root.findall("portgroup"):
        raise UnsafeDefinition("Unknown network passthrough configuration")
    if root.find("./bridge") is None:
        raise UnsafeDefinition("Expected a local, nonforwarded libvirt bridge")
    # This checks XML only. Full firewall/routing/IPv6 isolation requires tests.
