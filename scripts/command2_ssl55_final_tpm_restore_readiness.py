#!/usr/bin/env python3
"""SSL55 final one-NAT checkpoint TPM restore readiness (READ-ONLY).

No swtpm control commands, TPM state export, Windows changes, sample
execution, libvirt mutation, snapshot revert, guest stop, restart, or
host config write. THIS SCRIPT CAN NEVER DECLARE TPM-SAFE RESTORATION.

Uses physically verified 3 internal RUNNING checkpoints (including one
permanent NAT NIC) and checks exact current QEMU OS disk + UEFI images,
preserved legacy source/trial state, unique running swtpm process and
independent persistent TPM state-file metadata. State bytes are not
read or disclosed. We cannot infer checkpoint-era TPM state from a
present-day TPM state file: the QEMU+OVMF snapshot did not establish
matching swtpm permanent/volatile state at the moment of capture.

Upstream swtpm_ioctl documents separate permanent, volatile, savestate
blobs; 'save' cannot be retroactively synchronized to an earlier image
snapshot. A second disposable guest with explicitly matched TPM blobs
and two benign restore cycles is required before CAPE analysis release.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import time
import xml.etree.ElementTree as ET

import command2_ssl55_one_nat_running_snapshot as one
import command2_ssl55_swtpm_sync_audit as legacy

HOST="cse-ssl-55"
VM=one.VM
SNAP=one.SNAP
UUID=one.dual.UID
TPM=one.post.TPM

class TPMReadinessBlocked(RuntimeError):pass
def need(ok,why):
    if not ok:raise TPMReadinessBlocked(why)

def state_inventory(epoch):
    """Metadata only: never open swtpm persistent or volatile state blobs."""
    need(TPM.is_dir() and not TPM.is_symlink(),
         "Original VM swtpm state directory missing")
    base=TPM.stat()
    need(stat.S_ISDIR(base.st_mode) and
         not (stat.S_IMODE(base.st_mode)&0o002),
         "TPM state directory is world-writable or not a directory")
    state=[]
    names=set()
    for path in sorted(TPM.iterdir()):
        need(path.is_file() and not path.is_symlink(),
             "Nonregular/symlink TPM state entry; HOLD")
        st=path.stat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             0<st.st_size<=32*1024*1024 and path.name not in names,
             "TPM state blob file metadata violates guarded bounds")
        need("/" not in path.name and "\x00" not in path.name,
             "Untrusted TPM blob entry name")
        names.add(path.name)
        # Do NOT publish digest/byte contents; files can include keys.
        state.append({"filename":path.name,"byte_length":st.st_size,
                      "mtime_after_final_snapshot":st.st_mtime>epoch,
                      "mtime_epoch_is_not_tpm_checkpoint_proof":True})
    need("tpm2-00.permall" in names,"Original TPM2 permanent blob missing")
    return {"files":state,"file_names":sorted(names),
            "nonzero_persistent_blob_present":True,
            "old_snapshot_epoch_tpm_blob_available":False,
            "exact_checkpoint_epoch_volatile_blob_available":False,
            "active_tpm_contents_read_or_exported":False}

def metadata():
    pre=one.check(True)
    need(pre["captured"] is True and pre["name"]==SNAP and
         pre["guest_network"]["saved_and_live_one_exact_default_nat_nic"]
         is True and pre["guest_network"]["nat_agent_verified"] is True and
         pre["guest_network"]["dhcp_reservation_both_active_persistent"]
         is True,
         "One-NAT final checkpoint not independently verified")
    snapshots=pre["libvirt_snapshot_metadata"]
    need(set(snapshots)==set((one.post.OLD,one.post.NEW,SNAP)),
         "Expected all three snapshots")
    epoch=snapshots[SNAP]["snapshot_epoch"]
    need(isinstance(epoch,int) and 0<epoch<=int(time.time())+300,
         "Latest snapshot timestamp implausible")
    state=state_inventory(epoch)
    proc=legacy.find_swtpm_process()
    need(proc["unique_swtpm_process_bound_to_clone"] is True,
         "Expected exactly one bound swtpm process")
    # No socket connect, ioctl or TPM register reads.
    ctl=shutil.which("swtpm_ioctl")
    return {
        "result":"SSL55_ONE_NAT_TPM_RESTORE_READINESS_READONLY_HOLD",
        "vm":VM,"libvirt_uuid":UUID,
        "latest_running_snapshot":SNAP,
        "snapshot_epoch":epoch,
        "protected_prior_snapshots":[one.post.OLD,one.post.NEW],
        "new_snapshot_in_both_standalone_qcow2_images":True,
        "guest_has_only_one_persistent_default_nat_nic":True,
        "known_good_nat_agent_ip":"192.168.122.131",
        "existing_snapshots_not_reverted_or_deleted":True,
        "latest_guest_snapshot_uefi_os_ram_verified":True,
        "swtpm_state_file_metadata":state,
        "live_swtpm_process":proc,
        "swtpm_ioctl_utility_installed":ctl is not None,
        "swtpm_ioctl_live_socket_queried":False,
        "tpm_checkpoint_blob_exported_at_exact_snapshot_epoch":False,
        "libvirt_native_snapshot_captured_live_tpm_state_proven":False,
        "independent_tpm_state_backup_restored_on_disposable_clone":False,
        "bitlocker_secureboot_tpm_guest_after_restore_verified":False,
        "two_disposable_benign_revert_cycles_verified":False,
        "safe_to_use_snapshot_with_cape_auto_revert":False,
        "malware_analysis_authorized":False,
        "original_guest_mutated":False,
        "recommendation":"HOLD existing three checkpoints unchanged; "
          "design paired OS+UEFI+TPM disposable capture/restore with "
          "approved guest power transition and two benign revert tests. "
          "Do not retroactively treat current swtpm state as a past checkpoint."
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("audit",),default="audit")
    p.parse_args()
    try:
        need(os.geteuid()==0 and
             socket.gethostname().split(".",1)[0].lower()==HOST,
             "Read-only TPM readiness requires exact SSL55 root")
        print(json.dumps(metadata(),sort_keys=True,indent=2),flush=True)
        return 0
    except (TPMReadinessBlocked,one.OneNatCaptureBlocked,
            one.retired.RetireBlocked,one.post.CaptureBlocked,
            one.dual.ReaddressBlocked,legacy.AuditBlocked,
            ValueError,OSError,TypeError,KeyError,ET.ParseError,
            json.JSONDecodeError) as exc:
        print(json.dumps({
            "result":"SSL55_FINAL_TPM_READINESS_READONLY_BLOCKED",
            "reason":str(exc),
            "guest_or_snapshot_modified":False,
            "do_not_revert_or_reboot":True,
            "do_not_claim_cape_ready":True},sort_keys=True),
            file=sys.stderr,flush=True)
        return 2

if __name__=="__main__":raise SystemExit(main())
