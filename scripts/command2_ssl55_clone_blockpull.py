#!/usr/bin/env python3
"""SSL55 exact-clone blockpull: read-only plan, opt-in live flatten and verify.

A blockpull copies guest-visible backing data *into* the current clone top.
It does not blockcommit into protected master source disks. The clone image
CAN grow substantially. Never run --apply before reviewing a PASS plan.
No VM shutdown, restart, snapshot, network changes, or master file writes.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

VM = "win11_1"
UUID = "732b2256-ee99-41fa-881d-fbf5c476d960"
MASTER = ("win11", "289d89be-68ec-4c62-90e1-ea930849266f")
TRIAL = ("win11_trial_1", "e75f6fef-347d-462f-9738-4de3df6bfa74")
DISK = Path("/var/lib/libvirt/images/cape-clones-staging/win11_1.command2.qcow2")
NVRAM = "/var/lib/libvirt/qemu/nvram/win11_1.command2_VARS.fd"
BACKING = (
    "/var/lib/libvirt/images/win11.Afterfull",
    "/var/lib/libvirt/images/win11.basicinstallwinsnapshot",
    "/var/lib/libvirt/images/win11.qcow2",
)
GIB = 1024 ** 3
RESERVE = 40 * GIB
OVERHEAD = 4 * GIB
LOCK = Path("/run/lock/cape-command2-ssl55-blockpull.lock")

class Blocked(RuntimeError):
    pass

def need(ok, message):
    if not ok:
        raise Blocked(message)

def cmd(*argv, timeout=45):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True,
                           check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Unavailable/timed out host utility: " + argv[0]) from exc
    need(p.returncode == 0, "Read-only command failed: " + argv[0] +
         " return=" + str(p.returncode) +
         " (no changes requested by audit)")
    need(len(p.stdout) < 2_000_000, "Unexpected oversized response")
    return p.stdout.strip()

def virsh(*args):
    return cmd("virsh", "-c", "qemu:///system", *args)

def meta(p):
    path = Path(p)
    need(path.is_file() and not path.is_symlink(),
         "Required disk missing or symlinked: " + str(path))
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
         "Unexpected hardlinked/nonregular disk: " + str(path))
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def xml_chain(raw):
    root = ET.fromstring(raw)
    need(root.tag == "domain" and root.findtext("name") == VM and
         root.findtext("uuid") == UUID,
         "VM identity changed")
    ds = root.findall("./devices/disk[@device='disk']")
    need(len(ds) == 1, "Exactly one clone primary disk expected")
    disk = ds[0]
    driver = disk.find("driver")
    source = disk.find("source")
    target = disk.find("target")
    need(driver is not None and driver.get("type") == "qcow2" and
         source is not None and source.get("file") == str(DISK) and
         target is not None and target.get("dev") in ("vda", "sda"),
         "Disk/target differs from reviewed pilot")
    nics = root.findall("./devices/interface")
    need(len(nics) == 1 and nics[0].get("type") == "network" and
         nics[0].find("source") is not None and
         nics[0].find("source").get("network") == "cape-analysis-isolated" and
         nics[0].find("mac") is not None and
         nics[0].find("mac").get("address", "").lower() ==
         "02:0a:30:6a:3f:50", "Unexpected VM NIC")
    need(root.findtext("./os/nvram") == NVRAM,
         "Unexpected clone NVRAM path")
    tpms = root.findall("./devices/tpm")
    need(len(tpms) == 1 and tpms[0].find("backend") is not None and
         tpms[0].find("backend").get("type") == "emulator" and
         tpms[0].find("backend").get("version") == "2.0",
         "Unexpected TPM config")
    need(not root.findall("./devices/hostdev") and
         not root.findall("./devices/filesystem") and
         not root.findall("./devices/redirdev"),
         "Unexpected host-connected devices")
    chain = []
    node = disk.find("backingStore")
    while node is not None:
        src = node.find("source")
        if src is None:
            break
        chain.append(src.get("file"))
        need(len(chain) <= 8, "Unexpected deep backing chain")
        node = node.find("backingStore")
    return {"target": target.get("dev"), "chain": chain}

def preflight():
    need(os.geteuid() == 0, "sudo/root required")
    need(socket.gethostname().split(".")[0].lower() == "cse-ssl-55",
         "Only reference host CSE-SSL-55 approved for this exact pilot")
    for name, uid, state in ((VM, UUID, "running"),
                             (MASTER[0], MASTER[1], "shut off"),
                             (TRIAL[0], TRIAL[1], "shut off")):
        need(virsh("domuuid", name).lower() == uid and
             virsh("domstate", name).lower() == state,
             "Protected domain identity/state changed: " + name)
    # FAIL CLOSED: all 3 protected images are verified before any write.
    stamps = {p: meta(p) for p in BACKING}
    need(not virsh("snapshot-list", VM, "--name"),
         "Clone snapshot metadata unexpectedly exists")
    live = xml_chain(virsh("dumpxml", VM))
    saved = xml_chain(virsh("dumpxml", "--inactive", VM))
    need(live["target"] == saved["target"],
         "Live/saved target mismatch")
    # The inactive XML has historically omitted the final .qcow2 entry.
    need(live["chain"] == list(BACKING) and
         saved["chain"] in (list(BACKING), list(BACKING[:2])),
         "Actual clone backing chain differs; do not start blockpull")
    need(meta(DISK)[2] > 0, "Clone top disk empty")
    info = json.loads(cmd("qemu-img", "info", "-U",
                          "--output=json", str(DISK)))
    need(info.get("format") == "qcow2" and
         info.get("virtual-size") == 64 * GIB,
         "Clone top is not the expected 64 GiB QCOW2")
    # Upper-bound before conversion; guest writes could consume reserve,
    # so recheck immediately before apply as well. This is an estimate,
    # never a guarantee of 40GiB free after a live operation.
    fs = os.statvfs(str(DISK.parent))
    available = fs.f_bavail * fs.f_frsize
    allocated = DISK.stat().st_blocks * 512
    extra = max(0, 64 * GIB - allocated) + OVERHEAD
    need(available >= extra + RESERVE,
         "Insufficient free disk space for worst-case disk expansion " +
         "plus 40 GiB shared-host reserve")
    return {"result": "BLOCKPULL_PREFLIGHT_PASS_NO_WRITES",
            "vm": VM, "target": live["target"],
            "live_backing_chain": live["chain"],
            "saved_backing_chain": saved["chain"],
            "virtual_disk_gib": 64,
            "top_allocated_gib": round(allocated/GIB, 2),
            "free_gib": round(available/GIB, 2),
            "estimated_max_extra_gib": round(extra/GIB, 2),
            "shared_host_reserve_gib": 40,
            "source_master_stamps": stamps,
            "no_changes": True}

def apply():
    need(sys.stdin.isatty(), "Interactive local terminal required")
    need(not LOCK.is_symlink(), "Unsafe blockpull lock symlink")
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
             "Unsafe blockpull lock metadata")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Blocked("Another clone blockpull operation has the lock") from exc
        first = preflight()
        print(json.dumps({k:v for k,v in first.items()
                          if k != "source_master_stamps"}, indent=2, sort_keys=True),
              flush=True)
        phrase = "FLATTEN-WIN11_1-CLONE-ONLY"
        need(input("Type " + phrase + " to APPROVE LIVE writes to win11_1 QCOW2 only: ") ==
             phrase, "Explicit live disk operation approval missing")
        second = preflight()
        need(first["source_master_stamps"] == second["source_master_stamps"] and
             first["live_backing_chain"] == second["live_backing_chain"],
             "Preflight backing inputs changed before operation")
        # ONLY this single guarded guest and its existing disk-target. Do not
        # include --base, --shallow, blockcommit, blockcopy, --pivot or --delete.
        argv = ["virsh", "-c", "qemu:///system",
                "blockpull", VM, second["target"], "--wait", "--verbose"]
        print("BEGIN CLONE-ONLY LIVE BLOCKPULL; never interrupt by reboot/shutdown",
              flush=True)
        result = subprocess.run(argv, check=False)
        need(result.returncode == 0,
             "Blockpull failed/interrupted. Preserve VM and disks; inspect blockjob "
             "status before any retry")
        need(virsh("domstate", VM).lower() == "running",
             "VM state changed during blockpull; preserve all files")
        for name, uid in (MASTER, TRIAL):
            need(virsh("domuuid", name).lower() == uid and
                 virsh("domstate", name).lower() == "shut off",
                 "Protected domain changed during blockpull")
        for path, old in first["source_master_stamps"].items():
            need(meta(path) == old,
                 "PROTECTED MASTER FILE CHANGED: immediately stop and inspect")
        after_live = xml_chain(virsh("dumpxml", VM))
        after_saved = xml_chain(virsh("dumpxml", "--inactive", VM))
        need(not after_live["chain"] and not after_saved["chain"],
             "Blockpull returned but live/saved backing XML not both empty. "
             "Do not reboot; inspect manual reconciliation")
        need(virsh("domblklist", VM, "--details").find(str(DISK)) >= 0,
             "Clone disk source disappeared")
        return {"result": "CLONE_LIVE_BLOCKPULL_COMPLETED_XML_CHAIN_EMPTY",
                "master_disk_metadata_unchanged": True,
                "guest_running": True,
                "live_chain_empty": True, "saved_chain_empty": True,
                "independent_cold_boot_verified": False,
                "running_snapshot_restore_verified": False,
                "negative_egress_verified": False,
                "full_cold_recovery_verified": False}
    finally:
        os.close(fd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    args = parser.parse_args()
    try:
        if args.mode == "plan":
            out = preflight()
            out.pop("source_master_stamps")
        else:
            out = apply()
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, ET.ParseError) as exc:
        print(json.dumps({"result": "BLOCKED_OR_REVIEW_REQUIRED",
                          "reason": str(exc),
                          "no_automatic_recovery_or_retry": True}, indent=2))
        return 2

if __name__ == "__main__":
    sys.exit(main())
