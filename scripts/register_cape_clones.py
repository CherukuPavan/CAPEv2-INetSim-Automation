#!/usr/bin/env python3
"""Guarded CAPE KVM machinery registration for verified clone VMs.

Render a minimal textual patch while preserving unrelated configuration,
then atomically replace with rollback backup under an explicit apply mode.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile

SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*$", re.M)
MACHINES = re.compile(r"^(\s*machines\s*=\s*)([^#;\n]*)(.*)$", re.M | re.I)
SIMPLE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,90}\Z")


class CapeConfigError(RuntimeError):
    pass


def new_entry(name: str, ip: str, snapshot: str, interface: str) -> str:
    for field in (name, snapshot, interface):
        if not SIMPLE.fullmatch(field):
            raise CapeConfigError("Unsafe CAPE machine/snapshot/interface name")
    try:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError("Not IPv4")
    except ValueError as exc:
        raise CapeConfigError("Invalid guest static IPv4 address") from exc
    return (f"\n[{name}]\nlabel = {name}\nplatform = windows\n"
            f"ip = {ip}\narch = x64\ntags = win11\n"
            f"snapshot = {snapshot}\ninterface = {interface}\n")


def render_config(original: str, clones: list[dict], *,
                  libvirt_existing: set[str], snapshot: str, interface: str) -> str:
    section_names = SECTION.findall(original)
    if len(section_names) != len(set(section_names)):
        raise CapeConfigError("CAPE config has duplicated sections")
    if section_names.count("kvm") != 1:
        raise CapeConfigError("Expected exactly one [kvm] section")
    sections = SECTION.split(original)
    # Section split: [prefix, section_name, contents, ...]
    kvm_index = next((i for i in range(1,len(sections),2) if sections[i]=="kvm"),None)
    if kvm_index is None:
        raise CapeConfigError("Missing KVM stanza")
    body = sections[kvm_index+1]
    matches = list(MACHINES.finditer(body))
    if len(matches)!=1:
        raise CapeConfigError("Expected exactly one machines setting under [kvm]")
    old_names=[n.strip() for n in matches[0].group(2).split(",") if n.strip()]
    if len(old_names)!=len(set(old_names)):
        raise CapeConfigError("Duplicate names already configured in CAPE machines")
    for old in old_names:
        if old not in section_names:
            raise CapeConfigError(f"CAPE machine listed without a section: {old}")
    names=[]
    for entry in clones:
        name=entry["name"]
        if name in section_names or name in old_names:
            raise CapeConfigError(f"Clone already configured in CAPE: {name}")
        if name not in libvirt_existing:
            raise CapeConfigError(f"Clone missing from libvirt: {name}")
        if name in names:
            raise CapeConfigError("Duplicate clone name")
        names.append(name)
    if not names:
        raise CapeConfigError("No validated clones to register")
    # Remove old CAPE references ONLY when the libvirt domain no longer exists.
    # Keep all preexisting section bodies unchanged, including stale template
    # sections (not listed in the new machines list).
    kept=[name for name in old_names if name in libvirt_existing]
    aggregate=kept+names
    new_values=",".join(aggregate)
    start,end=matches[0].span(2)
    sections[kvm_index+1]=body[:start]+new_values+body[end:]
    rebuilt=sections[0]
    for i in range(1,len(sections),2):
        rebuilt+="["+sections[i]+"]"+sections[i+1]
    for entry in clones:
        # Per-VM snapshots are mandatory for Command 2; do not reuse one\n        # global snapshot for all clones when individual names are provided.\n        snap=entry.get("snapshot",snapshot)\n        rebuilt+=new_entry(entry["name"],entry["ip"],snap,interface)
    return rebuilt


def apply_config(path: Path, content: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise CapeConfigError("CAPE config missing or symlinked")
    st=path.stat()
    if st.st_mode & 0o002:
        raise CapeConfigError("CAPE config is world-writable")
    if "\x00" in content:
        raise CapeConfigError("Invalid NUL in new config")
    backup=path.with_name(path.name+".before-clone-"+str(os.getpid()))
    if backup.exists():
        raise CapeConfigError("Backup path already exists")
    with open(path,"rb") as original:
        source=original.read()
    # Backup has same owner/mode but is root-only while operation is pending.
    fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as out:
        out.write(source)
        out.flush()
        os.fsync(out.fileno())
    fd,tmp=tempfile.mkstemp(prefix=".cape-machines-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(content.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.chown(tmp,st.st_uid,st.st_gid)
        os.chmod(tmp,stat.S_IMODE(st.st_mode))
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return backup
