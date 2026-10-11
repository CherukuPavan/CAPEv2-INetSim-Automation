#!/usr/bin/env python3
"""Read-only SSL-55 Command 2: inspect active QEMU file handles and XML.

NO QMP / qemu-monitor-command: even harmless queries can taint libvirt
domain metadata. NO snapshots, guest actions, disk writes, or state changes.
Inspect /proc file descriptors + advisory qemu-img -U info ONLY.
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
WATCHED = (DISK, VARS) + SOURCES

class Blocked(Exception):
    pass

def need(ok, why):
    if not ok:
        raise Blocked(why)

def read(*argv):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=50, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Read-only utility unavailable/timed out: " + argv[0]) from exc
    need(p.returncode == 0, "Read-only command failed: " + argv[0] +
         " (exit " + str(p.returncode) + ")")
    need(len(p.stdout) <= 1000000, "Oversized command output")
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

def qemu_pid(proc_root=Path("/proc")):
    """Find a single exact guest process without printing its full command line."""
    hits = []
    for p in proc_root.iterdir():
        if not p.name.isdigit():
            continue
        try:
            name = (p / "comm").read_text().strip()
            if not (name.startswith("qemu-system") or name.startswith("qemu-kvm")):
                continue
            parts = (p / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        args = [s.decode("utf-8", "replace").lower() for s in parts if s]
        if UID in args and any(x == VM or x.startswith("guest=" + VM + ",")
                              or x == "guest=" + VM for x in args):
            hits.append(int(p.name))
    need(len(hits) == 1, "Could not uniquely identify exact QEMU PID")
    return hits[0]

def open_disk_fds(pid, proc_root=Path("/proc")):
    """An open inode is evidence of a QEMU-held file, not proof of chain order."""
    # Snapshot watched path inodes; allow missing sources, never follow links
    # supplied from other host directories into mutation operations.
    wanted = {}
    for path in WATCHED:
        try:
            s = os.stat(path)
            wanted[path] = (s.st_dev, s.st_ino)
        except (FileNotFoundError, PermissionError, OSError):
            wanted[path] = None
    refs = {path: [] for path in WATCHED}
    unusual_images = []
    root = proc_root / str(pid) / "fd"
    need(root.is_dir(), "Exact QEMU fd table disappeared")
    for fd in sorted(root.iterdir(), key=lambda p: p.name):
        try:
            link = os.readlink(fd)
            s = fd.stat()   # follows the open descriptor, works if name changed
        except (FileNotFoundError, ProcessLookupError):
            continue      # concurrent harmless descriptor closure
        except PermissionError as exc:
            raise Blocked("Cannot inspect QEMU file handles") from exc
        if not stat.S_ISREG(s.st_mode):
            continue
        inode = (s.st_dev, s.st_ino)
        matches = [path for path, ident in wanted.items() if ident == inode and ident is not None]
        if not matches and link.startswith("/var/lib/libvirt/images/"):
            unusual_images.append(link)
        for path in matches:
            refs[path].append({"fd": fd.name,
                               "link_matches_path": link == path,
                               "open_file_reported_path": link})
    return {"matching_open_file_descriptors": refs,
            "other_libvirt_image_paths": sorted(set(unusual_images)),
            "warning": "FD/inode presence confirms open files, NOT backing edge order"}

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

def meta(path):
    file = Path(path)
    need(file.is_file() and not file.is_symlink(), "Missing/linked: " + path)
    st = file.stat()
    need(stat.S_ISREG(st.st_mode), "Nonregular file: " + path)
    return {"bytes": st.st_size, "allocated_bytes": st.st_blocks * 512}

def perform():
    need(os.geteuid() == 0, "sudo needed to inspect exact running QEMU file handles")
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
    pid = qemu_pid()
    fds = open_disk_fds(pid)
    need(bool(fds["matching_open_file_descriptors"][DISK]),
         "QEMU disk inode not found open; cannot draw dependency conclusions")
    # -U bypasses lock for metadata only; QEMU could update concurrently.
    img = json.loads(read("qemu-img", "info", "-U", "--output=json",
                          "--backing-chain", DISK))
    need(type(img) is list and bool(img) and img[0].get("format") == "qcow2",
         "Unexpected qemu-img info")
    fs = os.statvfs(str(Path(DISK).parent))
    return {"result": "SSL55_COMMAND2_ACTIVE_FILE_HANDLE_READONLY",
            "vm": VM, "uuid": UID, "master_and_trial_shut_off": True,
            "live_xml": live, "inactive_xml": inactive,
            "qemu_pid": pid, "qemu_open_files": fds,
            "master_paths_held_open_by_QEMU": [
                path for path in SOURCES
                if fds["matching_open_file_descriptors"][path]],
            "qemu_img_info_U_ADVISORY_RUNNING_IMAGE": img,
            "disk_metadata": meta(DISK), "nvram_metadata": meta(VARS),
            "TPM": tpm_metadata(),
            "free_gib": round(fs.f_bavail * fs.f_frsize / 1024 ** 3, 2),
            "live_QMP_block_graph_read": False,
            "qemu_monitor_used": False,
            "snapshot_created": False, "restore_proven": False,
            "guest_egress_negative_proven": False,
            "TPM_UEFI_restore_proven": False,
            "approved_to_snapshot": False,
            "warning": "Open QEMU handles show active file usage but not graph edges; no snapshot/revert permission",
            "no_host_guest_or_network_mutations_requested": True}

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
