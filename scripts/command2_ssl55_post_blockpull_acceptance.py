#!/usr/bin/env python3
"""Post-blockpull SSL55 read-only acceptance: live/saved chain + QEMU fds + agent.

No qemu-monitor-command, snapshots, shutoff, guest execution, or host changes.
A PASS means the current RUNNING clone has no inspected master dependencies;
it does NOT prove cold boot, TPM/NVRAM snapshot or malware containment.
"""
from __future__ import annotations
import http.client
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
MASTER = ("win11", "289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL = ("win11_trial_1", "e75f6fef-347d-462f-9738-4de3df6bfa74")
TOP = "/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2"
VARS = "/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
PROTECTED = (
    "/var/lib/libvirt/images/win11.Afterfull",
    "/var/lib/libvirt/images/win11.basicinstallwinsnapshot",
    "/var/lib/libvirt/images/win11.qcow2",
)
IP = "192.168.240.101"
HOST_IP = "192.168.240.1"

class Blocked(RuntimeError):
    pass

def require(ok, why):
    if not ok:
        raise Blocked(why)

def read(*argv, timeout=45):
    try:
        p = subprocess.run(argv, check=False, capture_output=True,
                           text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Blocked("Read-only host command failed or timed out: " + argv[0]) from e
    require(p.returncode == 0, "Read-only command exit failure: " + argv[0])
    require(len(p.stdout) <= 1048576, "Unexpected oversized host query output")
    return p.stdout.strip()

def virsh(*args):
    return read("virsh", "-c", "qemu:///system", *args)

def check_xml(raw):
    root = ET.fromstring(raw)
    require(root.tag == "domain" and root.findtext("name") == VM and
            root.findtext("uuid") == UID, "Unexpected guest identity in XML")
    disks = root.findall("./devices/disk[@device='disk']")
    require(len(disks) == 1, "Expected only one guest primary disk")
    disk = disks[0]
    src, drv, tgt = disk.find("source"), disk.find("driver"), disk.find("target")
    require(src is not None and src.get("file") == TOP and
            drv is not None and drv.get("type") == "qcow2" and
            tgt is not None and tgt.get("dev") == "sda",
            "Guest disk source or target differs")
    node = disk.find("backingStore")
    # Libvirt can represent an exhausted backing chain as <backingStore/>.
    require(node is None or (node.find("source") is None and
                            node.find("backingStore") is None),
            "Backing source still declared in guest disk XML")
    require(root.findtext("./os/nvram") == VARS, "Guest NVRAM differs")
    tpms = root.findall("./devices/tpm")
    require(len(tpms) == 1 and tpms[0].find("backend") is not None and
            tpms[0].find("backend").get("type") == "emulator" and
            tpms[0].find("backend").get("version") == "2.0",
            "Guest TPM2 model unexpectedly changed")
    nics = root.findall("./devices/interface")
    require(len(nics) == 1 and nics[0].get("type") == "network" and
            nics[0].find("source") is not None and
            nics[0].find("source").get("network") == "cape-analysis-isolated" and
            nics[0].find("mac") is not None and
            nics[0].find("mac").get("address", "").lower() ==
            "02:0a:30:6a:3f:50", "Unexpected guest NIC after blockpull")
    return {"disk_source": TOP, "disk_target": "sda",
            "backing_chain_empty": True, "isolated_nic_unchanged": True,
            "guest_nvram_path_unchanged": True, "tpm_model_unchanged": True}

def exact_qemu_pid(proc_root=Path("/proc")):
    matched = []
    for item in proc_root.iterdir():
        if not item.name.isdecimal():
            continue
        try:
            comm = (item / "comm").read_text().strip()
            if not comm.startswith(("qemu-system", "qemu-kvm")):
                continue
            parts = (item / "cmdline").read_bytes().split(b"\0")
            argv = [x.decode("utf-8", "replace").lower() for x in parts if x]
            if UID in argv and any(
                arg == VM or arg == "guest=" + VM or
                arg.startswith("guest=" + VM + ",") for arg in argv
            ):
                matched.append(int(item.name))
        except (OSError, PermissionError):
            continue
    require(len(matched) == 1, "Cannot uniquely identify running pilot QEMU process")
    return matched[0]

def open_watched_fds(pid, proc_root=Path("/proc"), paths=None):
    watched = (TOP, VARS) + PROTECTED if paths is None else tuple(paths)
    stamps = {}
    for path in watched:
        p = Path(path)
        require(p.is_file() and not p.is_symlink(),
                "Watched disk/firmware path missing or symlinked: " + path)
        statinfo = p.stat()
        require(stat.S_ISREG(statinfo.st_mode),
                "Unexpected disk/firmware type")
        stamps[path] = (statinfo.st_dev, statinfo.st_ino)
    open_files = {x: [] for x in watched}
    fdroot = proc_root / str(pid) / "fd"
    require(fdroot.is_dir(), "QEMU FD directory missing")
    for fd in fdroot.iterdir():
        try:
            st = fd.stat()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as e:
            raise Blocked("Permission denied reading QEMU file descriptors") from e
        if not stat.S_ISREG(st.st_mode):
            continue
        for path, identity in stamps.items():
            if (st.st_dev, st.st_ino) == identity:
                open_files[path].append(fd.name)
    return {k: sorted(v) for k, v in open_files.items()}

def validate_handles(handles):
    require(bool(handles[TOP]),
            "QEMU top disk is no longer open; cannot certify live clone")
    require(bool(handles[VARS]),
            "QEMU NVRAM is no longer open; VM firmware configuration differs")
    still = [p for p in PROTECTED if handles[p]]
    require(not still, "Protected master source images still held open: " +
            ", ".join(still))
    return {"clone_qcow2_open": True, "clone_nvram_open": True,
            "original_master_images_open": [],
            "runtime_master_file_dependency_not_observed": True}

def check_agent():
    # Exactly one GET / with no credentials and no forwarding or payload.
    c = http.client.HTTPConnection(IP, 8000, timeout=5,
                                   source_address=(HOST_IP, 0))
    try:
        c.request("GET", "/", headers={"Accept": "application/json"})
        res = c.getresponse()
        data = res.read(8193)
        require(res.status == 200 and len(data) <= 8192,
                "CAPE Agent HTTP response invalid")
        obj = json.loads(data.decode("utf-8"))
        require(type(obj) is dict and obj.get("message") == "CAPE Agent!" and
                isinstance(obj.get("version"), str) and
                obj.get("is_user_admin") is True,
                "CAPE Agent identity/admin check failed")
        return {"agent_http_positive": True, "version": obj["version"],
                "administrator": True}
    except (OSError, UnicodeError, ValueError, http.client.HTTPException) as e:
        raise Blocked("CAPE Agent benign GET failed: " + type(e).__name__) from e
    finally:
        c.close()

def perform():
    require(os.geteuid() == 0, "sudo/root required for process file-handle inspection")
    require(socket.gethostname().split(".")[0].lower() == "cse-ssl-55",
            "Only CSE-SSL-55 reference host permitted")
    for name, uuid, state in ((VM, UID, "running"),
                              (MASTER[0], MASTER[1], "shut off"),
                              (TRIAL[0], TRIAL[1], "shut off")):
        require(virsh("domuuid", name).lower() == uuid and
                virsh("domstate", name).lower() == state,
                "Protected VM UUID/state changed: " + name)
    require(not virsh("snapshot-list", VM, "--name").strip(),
            "Unreviewed clone snapshot exists")
    live = check_xml(virsh("dumpxml", VM))
    saved = check_xml(virsh("dumpxml", "--inactive", VM))
    pid = exact_qemu_pid()
    handles = open_watched_fds(pid)
    held = validate_handles(handles)
    info = json.loads(read("qemu-img", "info", "-U", "--output=json", TOP))
    require(info.get("format") == "qcow2" and
            info.get("virtual-size") == 64*1024**3 and
            not info.get("backing-filename") and
            not info.get("full-backing-filename"),
            "QCOW2 top header unexpectedly contains backing dependency")
    fs = os.statvfs(str(Path(TOP).parent))
    agent = check_agent()
    return {"result": "SSL55_POST_BLOCKPULL_READONLY_ACCEPTED",
            "guest_running": True, "master_and_trial_shutoff": True,
            "live_xml": live, "saved_xml": saved,
            "qemu_open_handles": held, "qemu_pid": pid,
            "qemu_image_format": "qcow2",
            "qemu_img_live_U_metadata_advisory": True,
            "free_gib": round(fs.f_bavail*fs.f_frsize/1024**3, 2),
            "allocated_clone_disk_gib": round(
                Path(TOP).stat().st_blocks*512/1024**3, 2),
            "cape_agent": agent,
            "running_disk_independence_current_state_supported": True,
            "independent_cold_boot_tested": False,
            "UEFI_TPM_restore_tested": False,
            "running_snapshot_revert_tested": False,
            "negative_guest_egress_tested": False,
            "safe_for_malware": False,
            "no_host_vm_or_guest_mutations_requested": True}

def main():
    try:
        print(json.dumps(perform(), indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, TypeError, ET.ParseError) as e:
        print(json.dumps({"result": "BLOCKED_POST_BLOCKPULL_AUDIT",
                          "reason": str(e),
                          "snapshot_or_guest_changes_requested": False},
                         indent=2))
        return 2

if __name__ == "__main__":
    sys.exit(main())
