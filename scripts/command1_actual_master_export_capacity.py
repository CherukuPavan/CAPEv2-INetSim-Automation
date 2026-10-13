#!/usr/bin/env python3
"""READ-ONLY exact SSL55 Windows master disk size and cold export space gate.

Wraps the existing strictly checked real win11 source() preflight:
shut-off/UUID/QCOW2 backing chain, independent NVRAM and swtpm2 files.
NO Windows or TPM bytes are read into the report. A snapshot-dumpxml
metadata probe checks whether Afterfull is recorded as running.

The exporter conservatively requires virtual OS image bytes + 30 GiB
free on the EXISTING root-owned storage parent. No directory created.
Plan/report only. No export, VM boot, snapshot restore, Google transfer,
service restart, secret reads or device changes.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import xml.etree.ElementTree as ET
import command1_export_existing_master as master

GIB=1024**3

class CapacityBlocked(RuntimeError):
    pass

def need(ok,why):
    if not ok:raise CapacityBlocked(why)

def safe_storage(path):
    path=Path(path)
    need(path.is_absolute() and path.is_dir() and
         not path.is_symlink() and not any(
             x.is_symlink() for x in path.parents),
         "Storage parent must be an existing nonsymlink absolute directory")
    meta=path.stat()
    need(meta.st_uid==0 and not meta.st_mode & 0o022,
         "Storage parent requires root ownership and no group/world write")
    return path

def snapshot_metadata():
    try:
        xml=master.virsh("snapshot-dumpxml","win11","Afterfull")
        root=ET.fromstring(xml)
    except (master.MasterExportBlocked,ET.ParseError,OSError):
        return {
            "afterfull_snapshot_metadata_available":False,
            "running_state_in_snapshot_verified":False,
        }
    state=(root.findtext("state") or "").strip().lower()
    memory=root.find("memory")
    mode=(memory.get("snapshot") if memory is not None else None)
    return {
        "afterfull_snapshot_metadata_available":True,
        "recorded_state":state,
        "memory_snapshot_mode":mode if mode in (
            "internal","external","no","manual") else "unknown",
        "running_state_in_snapshot_verified":state=="running" and
             mode in ("internal","external"),
        "restore_with_matching_swtpm_state_proven":False,
        "cold_flattened_QCOW2_preserves_afterfull_RAM":False,
    }

def plan(storage):
    need(os.geteuid()==0,"Real master and swtpm metadata require root")
    parent=safe_storage(storage)
    actual=master.source()
    bytes_count=actual["virtual_size"]
    need(type(bytes_count) is int and
         8*GIB<=bytes_count<=512*GIB,
         "Actual master image virtual size invalid")
    free=shutil.disk_usage(parent).free
    required=bytes_count+master.MIN_AVAILABLE
    snapshots=snapshot_metadata()
    return {
        "result":"COMMAND1_EXACT_MASTER_EXPORT_CAPACITY_READ_ONLY",
        "reference_vm":"win11",
        "actual_source_master_shut_off":actual["master_shut_off"],
        "source_QCOW2_backing_layers":len(actual["backing_chain"]),
        "original_TPM2_member_count":len(actual["tpm_members"]),
        "original_UEFI_nvram_present":bool(actual["source_nvram"]),
        "virtual_disk_size_gib":round(bytes_count/GIB,2),
        "exporter_required_free_space_gib":round(required/GIB,2),
        "checked_storage":str(parent),
        "current_available_gib":round(free/GIB,2),
        "conservative_export_storage_sufficient":free>=required,
        "missing_capacity_gib":round(max(0,required-free)/GIB,2),
        "if_insufficient_use_separately_approved_root_owned_storage":free<required,
        "source_running_snapshot":snapshots,
        "private_drive_config_or_upload_verified":False,
        "original_master_disk_TPM_or_snapshots_modified":False,
        "source_bundle_exported":False,
        "new_host_import_ready":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan",),default="plan")
    p.add_argument("--storage-root",type=Path,default=Path("/var/backups"))
    args=p.parse_args()
    try:
        print(json.dumps(plan(args.storage_root),sort_keys=True,indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "result":"COMMAND1_EXACT_MASTER_SOURCE_SIZE_PROBE_BLOCKED",
            "error_type":type(exc).__name__,
            "no_guest_or_storage_mutations":True,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
