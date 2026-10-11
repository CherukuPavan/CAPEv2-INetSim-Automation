#!/usr/bin/env python3
"""Pure portable Windows clone libvirt XML renderer — ZERO NIC, NO WRITES.

It consumes an EXACT reviewed Windows master domain XML and one approved
candidate identity. It never accesses disk, libvirt, VM or guest state.
Not an installation/deployment authorizer. The actual portable apply
must separately validate paths, live inventory, device isolation,
permissions, firmware compatibility and running host state.
"""
from __future__ import annotations

import copy
from pathlib import PurePosixPath
import re
import uuid
import xml.etree.ElementTree as ET


class XMLBlocked(ValueError):
    pass


FORBIDDEN_DEVICES = (
    "hostdev", "filesystem", "redirdev", "redirfilter", "channel",
    "shmem", "vsock", "smartcard", "crypto", "interface", "watchdog",
)
HOSTNAME_RE = re.compile(r"^win11_([1-9][0-9]*)$")


def need(condition, reason):
    if not condition:
        raise XMLBlocked(reason)


def checked_path(value):
    need(type(value) is str and value.startswith("/") and "\x00" not in value
         and ".." not in PurePosixPath(value).parts,
         "Expected absolute, non-traversing file path")
    return value


def checked_uuid(value):
    try:
        normalized = str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise XMLBlocked("Missing or malformed candidate UUID") from exc
    need(normalized == value, "UUID must be canonical")
    return normalized


def render_no_nic(source_xml, candidate, *,
                  expected_master_name="win11",
                  expected_master_disk,
                  expected_master_nvram):
    """Return validated XML for a non-executable, SHUT-OFF zero-NIC domain.

    This function intentionally strips all source NICs and rejects
    other host-connected devices. No source XML is mutated in-place.
    """
    need(type(source_xml) is str and len(source_xml) < 512 * 1024,
         "Unexpected source domain XML size")
    need(type(candidate) is dict, "Missing guest candidate")
    target = candidate.get("libvirt_name")
    match = HOSTNAME_RE.fullmatch(target) if type(target) is str else None
    need(match is not None and candidate.get("windows_hostname_target") ==
         "WIN11-" + match.group(1), "Unexpected clone identity")
    guid = checked_uuid(candidate.get("libvirt_uuid_candidate"))
    generated_id = checked_uuid(candidate.get("smbios_generation_id_candidate"))
    disk_path = checked_path(candidate.get("disk_target"))
    vars_path = checked_path(candidate.get("uefi_nvram_target"))
    checked_path(expected_master_disk)
    checked_path(expected_master_nvram)
    need(disk_path != vars_path and disk_path not in
         (expected_master_disk, expected_master_nvram) and
         vars_path not in (expected_master_disk, expected_master_nvram),
         "Clone artifacts may not reuse master paths")
    need(candidate.get("nic_attached") is False and
         candidate.get("static_ipv4_applied") is False and
         candidate.get("per_vm_tpm_state_must_be_fresh") is True,
         "Candidate is not in pre-deployment zero-NIC state")

    try:
        root = ET.fromstring(source_xml)
    except ET.ParseError as exc:
        raise XMLBlocked("Malformed source libvirt XML") from exc
    need(root.tag == "domain" and root.get("type") == "kvm" and
         root.findtext("name") == expected_master_name,
         "Expected approved KVM master XML")
    source_guid = root.findtext("uuid")
    checked_uuid(source_guid)
    need(source_guid != guid, "Clone UUID equals source UUID")
    need(not any(node.tag.endswith("}commandline") for node in root.iter()),
         "Unexpected QEMU commandline override")
    need(root.find("./launchSecurity") is None and
         root.find("./keywrap") is None, "Unsupported encrypted guest profile")
    osnode = root.find("os")
    devices = root.find("devices")
    need(osnode is not None and devices is not None, "Missing OS/devices")
    nvram = osnode.find("nvram")
    need(nvram is not None and (nvram.text or "").strip() == expected_master_nvram
         and nvram.get("template") is not None,
         "Master UEFI NVRAM or firmware template not reviewed")
    disks = devices.findall("./disk[@device='disk']")
    need(len(disks) == 1 and disks[0].get("type") == "file",
         "Source must have exactly one file-backed OS disk")
    driver = disks[0].find("driver")
    source = disks[0].find("source")
    need(driver is not None and driver.get("type") == "qcow2" and
         source is not None and source.get("file") == expected_master_disk,
         "Unexpected source OS disk")
    need(not disks[0].findall("backingStore"), "Source XML has explicit backing chain")
    tpm = devices.findall("tpm")
    need(len(tpm) == 1 and tpm[0].get("model") in ("tpm-tis", "tpm-crb"),
         "Expected emulated TPM2 device")
    backend = tpm[0].find("backend")
    need(backend is not None and backend.get("type") == "emulator" and
         backend.get("version") == "2.0" and
         backend.find("source") is None and
         backend.find("encryption") is None,
         "Unexpected TPM backend or explicit shared state")
    for node in list(devices):
        if node.tag == "interface":
            need(node.get("type") in ("network", "bridge"),
                 "Refuse source direct/passthrough network interface")
            devices.remove(node)
        elif node.tag in FORBIDDEN_DEVICES:
            raise XMLBlocked("Unreviewed host-connected device: " + node.tag)
        elif node.tag == "disk":
            need(node.get("device") in ("disk", "cdrom"),
                 "Unexpected extra block device")
            if node.get("device") == "cdrom":
                # Leave media-less virtual CDROM only, no ISO/USB access.
                for media in list(node.findall("source")):
                    node.remove(media)
    for child in list(root.findall("seclabel")):
        root.remove(child)
    for child in list(root.findall("metadata")):
        root.remove(child)
    # Avoid inherited device alias/PCI addresses that conflict with
    # future NIC slot assignment; libvirt allocates new ephemeral aliases.
    for child in devices.iter():
        for alias in list(child.findall("alias")):
            child.remove(alias)

    graphics = devices.findall("graphics")
    need(len(graphics) == 1 and graphics[0].get("type") in ("spice", "vnc"),
         "Unexpected/absent local graphics")
    for gr in graphics:
        gr.set("autoport", "yes")
        gr.set("port", "-1")
        gr.set("listen", "127.0.0.1")
        for unsafe in ("tlsPort", "websocket", "passwd", "passwdValidTo"):
            gr.attrib.pop(unsafe, None)
        for l in list(gr.findall("listen")):
            need(l.get("type") in ("address", None),
                 "Unexpected libvirt graphics listening mode")
            l.set("type", "address")
            l.set("address", "127.0.0.1")

    root.find("name").text = target
    root.find("uuid").text = guid
    source.set("file", disk_path)
    nvram.text = vars_path
    genid = root.find("genid")
    if genid is None:
        genid = ET.SubElement(root, "genid")
    genid.text = generated_id

    xml = ET.tostring(root, encoding="unicode")
    result = ET.fromstring(xml)
    need(result.findtext("uuid") == guid and result.findtext("name") == target
         and result.findtext("genid") == generated_id and
         result.findtext("./os/nvram") == vars_path and
         result.find("./devices/disk[@device='disk']/source").get("file") == disk_path
         and not result.findall("./devices/interface") and
         not any(result.findall("./devices/" + tag)
                 for tag in FORBIDDEN_DEVICES),
         "Generated XML is not exact independent zero-NIC clone")
    return xml
