#!/usr/bin/env python3
"""Offline-only Windows static IPv4 and hostname personalization (clone disks).

Requires libguestfs virt-win-reg and ONE unregistered, shut-off, independent
QCOW2 clone. This does not mount live images, define/start guests or touch master.
Unsafe/ambiguous configurations fail closed rather than rewriting wrong NIC.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

HEADER = "Windows Registry Editor Version 5.00"
GUID = re.compile(r"^\{[0-9A-Fa-f-]{36}\}$")
SECTION = re.compile(r"^\[HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet\d{3}\\Services\\Tcpip\\Parameters\\Interfaces\\(\{[0-9A-Fa-f-]{36}\})\]$", re.I)
HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,14}\Z")
VM = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
DWORD = re.compile(r'"(Current|Default)"=dword:([0-9a-fA-F]{8})', re.I)
VALUERE = re.compile(r'^"([^"]+)"=(.*)$')


class Stop(RuntimeError):
    pass


def execute(*args: str, timeout: int = 180) -> str:
    try:
        p = subprocess.run(args, capture_output=True, check=True,
                           text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        # Do not copy complete potentially sensitive guest registry output.
        raise Stop(f"{args[0]} failed (exit or timeout): {str(exc)[:400]}") from exc


def validate_addresses(old_ip: str, new_ip: str, mask: str, gateway: str | None) -> None:
    try:
        previous = ipaddress.IPv4Address(old_ip)
        current = ipaddress.IPv4Address(new_ip)
        mask_int = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        net = ipaddress.IPv4Network(f"{current}/{mask_int}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise Stop(f"Invalid IPv4 addressing: {exc}") from exc
    if old_ip == new_ip:
        raise Stop("Proposed IP equals master IP")
    if current in (net.network_address, net.broadcast_address) or current.is_loopback or current.is_multicast:
        raise Stop("New guest address is not a usable unicast IP")
    if gateway:
        gw = ipaddress.IPv4Address(gateway)
        if gw not in net or gw == current:
            raise Stop("Requested guest gateway must be a distinct address on the subnet")
    # Traffic egress is controlled by the libvirt network; this does not certify isolation.


def registry_multisz(data: str) -> list[str]:
    """REG_MULTI_SZ export expected as hex(7): UTF-16LE bytes with NULs."""
    if not data.lower().startswith("hex(7):"):
        raise Stop("Expected exported REG_MULTI_SZ hex(7)")
    raw = re.sub(r"\s+", "", data[7:].replace("\\", ""))
    if not re.fullmatch(r"[0-9a-fA-F,]*", raw):
        raise Stop("Malformed exported REG_MULTI_SZ")
    try:
        buf = bytes(int(b, 16) for b in raw.split(",") if b)
        decoded = buf.decode("utf-16le")
    except (ValueError, UnicodeDecodeError) as exc:
        raise Stop("Cannot decode Windows multi-string") from exc
    return [x for x in decoded.split("\x00") if x]


def multi_literal(items: list[str]) -> str:
    data = ("\x00".join(items) + "\x00\x00").encode("utf-16le")
    return "hex(7):" + ",".join(f"{b:02x}" for b in data)


def parse_sections(text: str) -> dict[str, dict[str, str]]:
    # Merge line continuations, but reject duplicate section keys.
    lines = text.replace("\\\n", "").splitlines()
    data: dict[str, dict[str, str]] = {}
    current = None
    for line in lines:
        line = line.strip()
        match = SECTION.match(line)
        if match:
            current = match.group(1).upper()
            if current in data:
                raise Stop("Duplicate interface keys in registry export")
            data[current] = {}
            continue
        if line.startswith("["):
            current = None
        if current:
            value = VALUERE.match(line)
            if value:
                data[current][value.group(1).lower()] = value.group(2)
    return data


def parse_select(text: str) -> int:
    matches = [int(v, 16) for k, v in DWORD.findall(text) if k.lower() == "current"]
    if len(matches) != 1 or not 1 <= matches[0] <= 999:
        raise Stop("Windows SYSTEM Select\\Current control set is ambiguous")
    return matches[0]


def find_interface(exported: str, expected_old: str) -> tuple[str, dict]:
    entries = parse_sections(exported)
    matching = []
    for guid, values in entries.items():
        ip_value = values.get("ipaddress")
        if not ip_value:
            continue
        ips = registry_multisz(ip_value)
        if expected_old in ips:
            matching.append((guid, values, ips))
    if len(matching) != 1:
        raise Stop(f"Expected exactly one Windows NIC with original IP; found {len(matching)}")
    guid, values, ips = matching[0]
    if len(ips) != 1:
        raise Stop("NIC has multiple static IP addresses; refusing implicit overwrite")
    if values.get("enabledhcp", "").lower() != "dword:00000000":
        raise Stop("Interface does not have confirmed static DHCP-disabled IPv4")
    mask_values = registry_multisz(values.get("subnetmask", ""))
    if len(mask_values) != 1:
        raise Stop("Interface subnet mask is not a single static IPv4 value")
    return guid, {"original_mask": mask_values[0]}


def patch_contents(controlset: int, guid: str, hostname: str, ip: str, mask: str,
                   gateway: str | None) -> str:
    if not GUID.fullmatch(guid) or not HOSTNAME.fullmatch(hostname):
        raise Stop("Unsafe Windows interface GUID or hostname")
    path = f"HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet{controlset:03d}"
    lines = [
        HEADER, "",
        f"[{path}\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}]",
        '"EnableDHCP"=dword:00000000',
        f'"IPAddress"={multi_literal([ip])}',
        f'"SubnetMask"={multi_literal([mask])}',
    ]
    if gateway is not None:
        lines.append(f'"DefaultGateway"={multi_literal([gateway])}')
    lines.extend([
        "",
        f"[{path}\\Control\\ComputerName\\ComputerName]",
        f'"ComputerName"="{hostname}"',
        "",
        f"[{path}\\Control\\ComputerName\\ActiveComputerName]",
        f'"ComputerName"="{hostname}"',
        "",
        f"[{path}\\Services\\Tcpip\\Parameters]",
        f'"Hostname"="{hostname}"',
        f'"NV Hostname"="{hostname}"',
        "",
    ])
    return "\n".join(lines)


def disk_guard(disk: Path) -> None:
    if not disk.is_absolute() or disk.is_symlink() or not disk.is_file():
        raise Stop("Disk must be a regular, absolute, non-symlink clone image")
    if disk.suffix.lower() != ".qcow2":
        raise Stop("Windows personalization requires a QCOW2 clone")
    qinfo = json.loads(execute("qemu-img", "info", "--output=json", str(disk)))
    if qinfo.get("format") != "qcow2" or qinfo.get("backing-filename"):
        raise Stop("Clone disk must be a flattened QCOW2 image without any backing")
    names = execute("virsh", "-c", "qemu:///system", "list", "--all", "--name").splitlines()
    for name in names:
        if not VM.fullmatch(name):
            raise Stop("Invalid libvirt domain name in host inventory")
        xml = ET.fromstring(execute("virsh", "-c", "qemu:///system", "dumpxml", "--inactive", name))
        for src in xml.findall("./devices/disk/source"):
            if src.get("file") == str(disk):
                raise Stop(f"Clone image already attached to libvirt domain {name}")
    # Remaining limitation: a running QEMU process or unlisted externally
    # attached image can hold the file; guestfs locking must not be bypassed.


def prepare(disk: Path, old_ip: str, new_ip: str, hostname: str,
            mask: str, gateway: str | None, mode: str) -> dict:
    if not HOSTNAME.fullmatch(hostname):
        raise Stop("Windows hostname must be 1-15 letters/digits/hyphens")
    validate_addresses(old_ip, new_ip, mask, gateway)
    disk_guard(disk)
    if mode == "apply" and not shutil.which("virt-win-reg"):
        raise Stop("virt-win-reg is required for offline registry modification")
    select = execute("virt-win-reg", str(disk), r"HKLM\SYSTEM\Select")
    index = parse_select(select)
    key = rf"HKLM\SYSTEM\ControlSet{index:03d}\Services\Tcpip\Parameters\Interfaces"
    interfaces = execute("virt-win-reg", str(disk), key)
    guid, entry = find_interface(interfaces, old_ip)
    if entry["original_mask"] != mask:
        raise Stop("Proposed subnet mask differs from master; review network relocation")
    content = patch_contents(index, guid, hostname, new_ip, mask, gateway)
    result = {"status": "PLAN_ONLY", "disk": str(disk), "hostname": hostname,
              "old_ip": old_ip, "new_ip": new_ip, "prefix_controlset": index,
              "interface_guid": guid, "changes": ["IPv4", "hostname"],
              "source_master_untouched": True}
    if mode == "apply":
        # Atomicity: the caller must provide a disposable, exclusively-owned clone
        # disk; a failed edit is not rollback-safe. Never use on a master disk.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="cape-reg-", dir="/tmp") as dirname:
            regfile = Path(dirname) / "network.reg"
            regfile.write_text(content, encoding="utf-8")
            execute("virt-win-reg", "--merge", str(disk), str(regfile), timeout=600)
        # Verify registry values after writing, not merely process success.
        current = execute("virt-win-reg", str(disk), key)
        new_guid, _ = find_interface(current, new_ip)
        if new_guid != guid:
            raise Stop("Post-write interface verification differs from original NIC")
        result["status"] = "OFFLINE_REGISTRY_UPDATED_GUEST_BOOT_NOT_VERIFIED"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", type=Path, required=True)
    parser.add_argument("--old-ip", required=True)
    parser.add_argument("--new-ip", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--mask", required=True)
    parser.add_argument("--gateway")
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    args = parser.parse_args(argv)
    try:
        info = prepare(args.disk, args.old_ip, args.new_ip, args.hostname,
                       args.mask, args.gateway, args.mode)
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    except (Stop, ValueError, OSError, ET.ParseError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
