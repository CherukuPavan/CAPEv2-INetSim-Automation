#!/usr/bin/env python3
"""Fixed-command benign Windows disk-marker check through an ISOLATED CAPE Agent.

Only reads/creates C:/Users/Public/Documents/CAPE_Command2_BenignSnapshotMutation.marker.
Never accepts a command from input, changes Windows security, downloads a
binary, touches samples or claims swtpm/UEFI state consistency.
Caller MUST first prove isolated host libvirt/nft network and exact guest.
"""
from __future__ import annotations
import base64
import binascii
import ipaddress
from urllib.parse import urlencode

import command2_portable_nat_agent_setup_transport as transport

MARKER = "CAPE_Command2_BenignSnapshotMutation.marker"
BASE = "$p=Join-Path (Join-Path $env:PUBLIC 'Documents') '" + MARKER + "';"
PREFIX = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
READ_SCRIPT = (BASE +
               "if(Test-Path -LiteralPath $p -PathType Leaf){"
               "Write-Output CAPE_DISK_MARKER_PRESENT"
               "}else{Write-Output CAPE_DISK_MARKER_ABSENT}")
WRITE_SCRIPT = (BASE +
                "if(Test-Path -LiteralPath $p){throw 'PREEXISTING_MARKER'};"
                "$fs=[IO.File]::Open($p,[IO.FileMode]::CreateNew,"
                "[IO.FileAccess]::Write,[IO.FileShare]::None);"
                "try{$b=[Text.Encoding]::UTF8.GetBytes("
                "'Harmless CAPE disposable snapshot revert marker.');"
                "$fs.Write($b,0,$b.Length);$fs.Flush($true)"
                "}finally{$fs.Dispose()};"
                "Write-Output CAPE_DISK_MARKER_CREATED")


class MarkerBlocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise MarkerBlocked(reason)


def checked_ips(ip, source):
    try:
        dst = ipaddress.IPv4Address(ip)
        src = ipaddress.IPv4Address(source)
        subnet = ipaddress.IPv4Network(str(src) + "/24", strict=False)
    except (ipaddress.AddressValueError, TypeError, ValueError) as error:
        raise MarkerBlocked("Invalid isolated IPv4 guest/bridge") from error
    need(dst in subnet and src == subnet.network_address + 1 and
         dst != src and not src.is_loopback and src.is_private and
         not src.is_link_local and not dst.is_multicast,
         "Guest marker request must target the reviewed isolated lab /24")
    return str(dst), str(src)


def execute_fixed(ip, source, script, *, modifying=False):
    need(script in (READ_SCRIPT, WRITE_SCRIPT),
         "Only reviewed marker commands are permitted")
    need((script == WRITE_SCRIPT) == modifying,
         "Request mode does not match reviewed benign command")
    dst, src = checked_ips(ip, source)
    # Constant reviewed script. No shell/remote paths supplied by caller.
    command = PREFIX + '"' + script.replace('"', '\\"') + '"'
    body = urlencode({"command": command, "encoding": "base64"}).encode("ascii")
    try:
        result = transport.agent_post(dst, src, "/execute", body,
                                      "application/x-www-form-urlencoded")
    except transport.TransportBlocked as error:
        raise MarkerBlocked("Isolated CAPE Agent marker operation failed") from error
    need(type(result) is dict and
         result.get("message") == "Successfully executed command" and
         type(result.get("stdout")) is str and
         len(result["stdout"]) <= 2048,
         "Guest did not return trusted benign marker response")
    try:
        stdout = base64.b64decode(result["stdout"], validate=True)
        need(len(stdout) <= 1024, "Oversized decoded marker witness")
        lines = stdout.decode("utf-8-sig").strip().splitlines()
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise MarkerBlocked("Invalid CAPE Agent marker text") from error
    need(len(lines) == 1, "Unexpected Windows marker output")
    answer = lines[0].strip()
    expected = ({"CAPE_DISK_MARKER_CREATED"} if modifying else
                {"CAPE_DISK_MARKER_PRESENT", "CAPE_DISK_MARKER_ABSENT"})
    need(answer in expected, "Unexpected or failed marker command result")
    return answer


def read_marker(ip, source):
    result = execute_fixed(ip, source, READ_SCRIPT, modifying=False)
    return result == "CAPE_DISK_MARKER_PRESENT"


def create_marker(ip, source):
    # Only CreateNew, refusing pre-existing files. Caller checks first.
    answer = execute_fixed(ip, source, WRITE_SCRIPT, modifying=True)
    need(answer == "CAPE_DISK_MARKER_CREATED",
         "Windows marker creation not witnessed")
    return True
