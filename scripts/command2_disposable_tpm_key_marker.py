#!/usr/bin/env python3
"""Optional fixed TPM-backed Windows CNG-key restore probe on disposable clones.

A named key is created *after* a running snapshot using Windows' Microsoft
Platform Crypto Provider (not the software provider). After each approved
snapshot revert the original Windows identity must report the key absent.
No private/public key bytes, certificates or secret TPM NV contents leave
the guest; no TPM clear, key deletion, BitLocker changes, arbitrary command,
remote download or Windows Defender changes are permitted.

LIMITATION: An absent CNG key may reflect an OS key-file rollback even if
swtpm NV state itself did not revert. This is a useful NEGATIVE test for an
unsound snapshot, not sufficient standalone proof of synchronized TPM/UEFI.
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import urlencode

import command2_disposable_guest_marker as disk
import command2_portable_nat_agent_setup_transport as transport

KEY_PREFIX = "CAPE_BENIGN_DISPOSABLE_TPM_REVERT_WIN11_"
VM = re.compile(r"win11_([1-9]|1[0-6])\Z")


class TPMKeyBlocked(RuntimeError):
    pass


def need(ok, message):
    if not ok:
        raise TPMKeyBlocked(message)


def approved_name(vm):
    need(type(vm) is str and VM.fullmatch(vm) is not None,
         "Only reviewed disposable Windows clone names accepted")
    return KEY_PREFIX + vm.rsplit("_", 1)[1]


def script_for(vm, mode):
    need(mode in ("read", "create"), "Unknown TPM CNG operation")
    key = approved_name(vm)
    # The key name is fixed-derived and cannot contain quotes, backslashes,
    # PowerShell metacharacters or a user-supplied command.
    intro = (
        "$ErrorActionPreference='Stop';"
        "$p=New-Object System.Security.Cryptography.CngProvider("
        "'Microsoft Platform Crypto Provider');"
        "$n='" + key + "';"
        "$present=[System.Security.Cryptography.CngKey]::Exists($n,$p);"
    )
    if mode == "read":
        return intro + (
            "if($present){[Console]::WriteLine('CAPE_TPM_KEY_PRESENT')}"
            "else{[Console]::WriteLine('CAPE_TPM_KEY_ABSENT')}"
        )
    return intro + (
        "if($present){throw 'TPM_MARKER_ALREADY_EXISTS'};"
        "$options=New-Object "
        "System.Security.Cryptography.CngKeyCreationParameters;"
        "$options.Provider=$p;"
        "$options.KeyUsage=[System.Security.Cryptography.CngKeyUsages]::Signing;"
        "$options.ExportPolicy="
        "[System.Security.Cryptography.CngExportPolicies]::None;"
        "$key=[System.Security.Cryptography.CngKey]::Create("
        "[System.Security.Cryptography.CngAlgorithm]::Rsa,$n,$options);"
        "try{if(-not [System.Security.Cryptography.CngKey]::Exists($n,$p))"
        "{throw 'TPM_MARKER_CREATE_NOT_PERSISTED'};"
        "[Console]::WriteLine('CAPE_TPM_KEY_CREATED')}"
        "finally{$key.Dispose()}"
    )


def execute(ip, bridge, vm, mode):
    need(mode in ("read", "create"), "Invalid CNG TPM marker action")
    try:
        dst, src = disk.checked_ips(ip, bridge)
    except disk.MarkerBlocked as error:
        raise TPMKeyBlocked("Isolated Windows TPM probe destination rejected") from error
    code = script_for(vm, mode)
    # Windows PowerShell's -EncodedCommand uses UTF-16-LE, and *only* our
    # fixed, reviewable command is encoded. Avoid ExecutionPolicy bypass.
    encoded = base64.b64encode(code.encode("utf-16-le")).decode("ascii")
    command = ("powershell.exe -NoProfile -NonInteractive -EncodedCommand " +
               encoded)
    body = urlencode({"command": command, "encoding": "base64"}).encode("ascii")
    try:
        reply = transport.agent_post(dst, src, "/execute", body,
                                     "application/x-www-form-urlencoded")
    except transport.TransportBlocked as error:
        raise TPMKeyBlocked("Isolated Agent TPM marker probe failed") from error
    need(type(reply) is dict and
         reply.get("message") == "Successfully executed command" and
         type(reply.get("stdout")) is str and
         len(reply["stdout"]) < 1024,
         "Untrusted CAPE Agent TPM operation response")
    try:
        stdout = base64.b64decode(reply["stdout"], validate=True)
        need(len(stdout) < 512, "TPM witness text oversized")
        lines = stdout.decode("utf-8-sig").strip().splitlines()
    except (binascii.Error, UnicodeError, ValueError) as error:
        raise TPMKeyBlocked("Invalid encoded Windows CNG response") from error
    permitted = ({"CAPE_TPM_KEY_PRESENT", "CAPE_TPM_KEY_ABSENT"}
                 if mode == "read" else {"CAPE_TPM_KEY_CREATED"})
    need(len(lines) == 1 and lines[0].strip() in permitted,
         "TPM CNG operation incomplete or unexpected")
    return lines[0].strip()


def key_exists(ip, bridge, vm):
    return execute(ip, bridge, vm, "read") == "CAPE_TPM_KEY_PRESENT"


def create_key(ip, bridge, vm):
    need(execute(ip, bridge, vm, "create") == "CAPE_TPM_KEY_CREATED",
         "TPM persistent benign challenge key creation failed")
    return True
