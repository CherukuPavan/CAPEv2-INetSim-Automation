#!/usr/bin/env python3
"""Read-only SSL-55 Command 2 live QEMU block graph and TPM/UEFI metadata audit.

Only allowlisted QMP *queries*. No guest code, snapshot, libvirt definition
change, disk repair/rebase/copy, firewall adjustment or TPM-secret reads.
"""
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

VM = "win11_1"
UID = "732b2256-ee99-41fa-881d-fbf5c476d960"
PROTECTED = (("win11", "289d89be-68ec-4c62-90e1-ea930849266f"),
             ("win11_trial_1", "e75f6fef-347d-462f-9738-4de3df6bfa74"))
DISK = "/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
VARS = "/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
SOURCES = ("/var/lib/libvirt/images/win11.Afterfull",
           "/var/lib/libvirt/images/win11.basicinstallwinsnapshot",
           "/var/lib/libvirt/images/win11.qcow2")

class Blocked(Exception):
    pass

def need(ok, why):
    if not ok:
        raise Blocked(why)

def read(*argv):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=50, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Command missing or timed out: " + argv[0]) from exc
    need(p.returncode == 0, "Read-only command failed: " + argv[0] +
         " (exit " + str(p.returncode) + ")")
    need(len(p.stdout) <= 1000000, "Oversize command response")
    return p.stdout.decode("utf-8", "replace").strip()

def virsh(*args):
    return read("virsh", "-c", "qemu:///system", *args)

def domain_summary(raw):
    doc = ET.fromstring(raw)
    need(doc.tag == "domain" and doc.findtext("name") == VM and
         doc.findtext("uuid") == UID, "Unexpected domain XML identity")
    disks = doc.findall("./devices/disk[@device='disk']")
    need(len(disks) == 1, "Expected exactly one primary disk")
    disk = disks[0]
    src, driver = disk.find("source"), disk.find("driver")
    need(src is not None and src.get("file") == DISK and driver is not None
         and driver.get("type") == "qcow2", "Unexpected disk path/format")
    loader, nvram = doc.find("./os/loader"), doc.find("./os/nvram")
    need(loader is not None and loader.get("type") == "pflash" and
         nvram is not None and nvram.text == VARS, "Unexpected OVMF VARS path")
    tpms = doc.findall("./devices/tpm")
    need(len(tpms) == 1 and tpms[0].find("backend") is not None and
         tpms[0].find("backend").get("type") == "emulator" and
         tpms[0].find("backend").get("version") == "2.0", "Unexpected TPM")
    nics = doc.findall("./devices/interface")
    need(len(nics) == 1 and nics[0].get("type") == "network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network") == "cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address", "").lower() == "02:0a:30:6a:3f:50",
         "Unexpected guest NIC")
    chain = []
    node = disk.find("backingStore")
    while node is not None:
        source = node.find("source")
        if source is None:
            break
        chain.append(source.get("file"))
        need(len(chain) <= 16, "Backing chain unusually deep")
        node = node.find("backingStore")
    return {"backing_paths_in_xml": chain,
            "loader_format": loader.get("format", "unspecified"),
            "nvram_format": nvram.get("format", "unspecified"),
            "tpm": "emulator-2.0", "disk": DISK}

def qmp_query(name):
    need(name in ("query-block", "query-named-block-nodes"),
         "Refused non-query QMP operation")
    result = json.loads(virsh("qemu-monitor-command", VM, "--pretty",
                              json.dumps({"execute": name})))
    need(type(result) is dict and type(result.get("return")) is list,
         "QMP response failed: " + name)
    return result["return"]

def referenced_paths(value):
    paths = set()
    def walk(obj, key=None):
        if type(obj) is dict:
            for k, v in obj.items():
                walk(v, k)
        elif type(obj) is list:
            for v in obj:
                walk(v, key)
        elif type(obj) is str and key in (
                "filename", "backing-filename", "full-backing-filename",
                "backing_file", "file"):
            paths.add(obj)
    walk(value)
    return sorted(paths)

def meta(path):
    file = Path(path)
    need(file.is_file() and not file.is_symlink(), "Missing/linked: " + path)
    st = file.stat()
    need(stat.S_ISREG(st.st_mode), "Nonregular file: " + path)
    return {"bytes": st.st_size, "allocated_bytes": st.st_blocks * 512}

def tpm_metadata():
    folder = Path("/var/lib/libvirt/swtpm") / UID / "tpm2"
    need(folder.is_dir() and not folder.is_symlink(), "TPM directory missing/linked")
    files = []
    for item in sorted(folder.iterdir()):
        need(not item.is_symlink(), "Linked TPM state file")
        st = item.lstat()
        need(stat.S_ISREG(st.st_mode), "Unexpected TPM state object")
        files.append({"basename": item.name, "bytes": st.st_size,
                      "permissions": oct(stat.S_IMODE(st.st_mode))})
    need(any(f["basename"].endswith(".permall") for f in files),
         "TPM permanent state not found")
    return {"metadata_only": files, "secret_contents_read": False}

def perform():
    need(os.geteuid() == 0, "sudo required for QMP query access")
    need(socket.gethostname().split(".")[0].lower() in
         ("cse-ssl-55", "ssl-55"), "Only CSE-SSL-55 allowed")
    need(virsh("domuuid", VM).lower() == UID and
         virsh("domstate", VM).lower() == "running",
         "Pilot VM UUID/state changed")
    for name, uuid in PROTECTED:
        need(virsh("domuuid", name).lower() == uuid and
             virsh("domstate", name).lower() == "shut off",
             "Protected VM UUID/state changed: " + name)
    live = domain_summary(virsh("dumpxml", VM))
    inactive = domain_summary(virsh("dumpxml", "--inactive", VM))
    need(not virsh("snapshot-list", VM, "--name").strip(),
         "Unexpected pre-existing snapshots")
    # QMP queries are the source of truth for LIVE disk graph observations.
    block = qmp_query("query-block")
    nodes = qmp_query("query-named-block-nodes")
    # -U deliberately bypasses active-image lock: ADVISORY metadata only.
    # No qemu-img check, convert, rebase, or write against a live image.
    img = json.loads(read("qemu-img", "info", "-U", "--output=json",
                          "--backing-chain", DISK))
    need(type(img) is list and bool(img) and img[0].get("format") == "qcow2",
         "Unexpected qemu-img info")
    qmp_paths = referenced_paths(block) + referenced_paths(nodes)
    img_paths = referenced_paths(img)
    fs = os.statvfs(str(Path(DISK).parent))
    return {"result": "SSL55_COMMAND2_LIVE_GRAPH_READONLY",
            "vm": VM, "uuid": UID, "master_and_trial_shut_off": True,
            "live_xml": live, "inactive_xml": inactive,
            "QMP_query_block": block, "QMP_query_named_block_nodes": nodes,
            "qemu_img_info_U_advisory_only": img,
            "master_paths_in_XML": [p for p in SOURCES if p in live["backing_paths_in_xml"]],
            "master_paths_in_QMP": [p for p in SOURCES if p in qmp_paths],
            "master_paths_in_qemu_img": [p for p in SOURCES if p in img_paths],
            "QMP_all_paths": sorted(set(qmp_paths)),
            "disk_metadata": meta(DISK), "nvram_metadata": meta(VARS),
            "TPM": tpm_metadata(),
            "free_gib": round(fs.f_bavail * fs.f_frsize / 1024 ** 3, 2),
            "snapshot_created": False, "restore_proven": False,
            "guest_egress_negative_proven": False,
            "TPM_UEFI_restore_proven": False,
            "approved_to_snapshot": False,
            "warning": "Do not infer backing independence from -U while QEMU is running",
            "no_mutations_requested": True}

def main():
    try:
        print(json.dumps(perform(), indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, TypeError, ET.ParseError) as exc:
        print(json.dumps({"result": "BLOCKED_READ_ONLY_AUDIT",
                          "reason": str(exc), "no_mutations_requested": True},
                         indent=2))
        return 2

if __name__ == "__main__":
    sys.exit(main())
