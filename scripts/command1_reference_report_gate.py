#!/usr/bin/env python3
"""Offline-only reconcile of the SSL55 exact installer-reference JSON.

Nothing here installs missing packages or asserts that Ubuntu's dpkg
database represents a custom/source-built QEMU/libvirt installation.
The report contains no disk virtual-size or verified CAPE checkout SHA;
such unknowns remain explicit gates rather than inferred success.

Input is a newly-created, non-symlink JSON file only; no shell, network,
Google OAuth, service modifications or VM actions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

REQUIRED_CONF = ("api.conf","auxiliary.conf","cuckoo.conf",
                 "kvm.conf","mitmdump.conf","routing.conf")
REQUIRED_UNITS = ("cape.service","cape-processor.service",
                  "cape-rooter.service","cape-web.service",
                  "suricata.service","postgresql.service",
                  "mongodb.service")
VIRT_PACKAGES = ("qemu-system-x86","qemu-utils","libvirt-clients",
                 "libvirt-daemon-system")
NOT_FOUND = "not_installed_or_unknown"
MAX_REPORT_BYTES = 64*1024

class ReferenceBlocked(RuntimeError):
    pass

def need(ok,why):
    if not ok:
        raise ReferenceBlocked(why)

def load(path):
    file=Path(path)
    need(file.is_absolute() and file.is_file() and
         not file.is_symlink(),"Report must be regular absolute file")
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             0<st.st_size<=MAX_REPORT_BYTES,
             "Incorrect report size or hardlink count")
        raw=os.read(fd,MAX_REPORT_BYTES+1)
        need(len(raw)==st.st_size,"Reference report changed during read")
    finally:
        os.close(fd)
    try:
        data=json.loads(raw.decode("utf-8"))
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise ReferenceBlocked("Invalid JSON reference report") from exc
    need(type(data) is dict and
         data.get("purpose")=="read_only_exact_ssl55_installer_reference"
         and data.get("host_modified") is False and
         data.get("secrets_collected") is False,
         "Unsupported source-report purpose or privacy metadata")
    need(data.get("hostname")=="CSE-SSL-55",
         "This evidence is only the named CSE-SSL-55 reference")
    return data

def package_status(value):
    if not isinstance(value,str):
        return "not_attested"
    if value==NOT_FOUND:
        return "not_in_selected_dpkg_packages"
    if re.fullmatch(r"[A-Za-z0-9.+~:_-]{1,140}",value):
        return "dpkg_version_attested"
    return "not_attested"

def service_ready(services,unit):
    state=services.get(unit)
    return (type(state) is dict and
            state.get("LoadState")=="loaded" and
            state.get("ActiveState")=="active")

def review(report):
    need(type(report) is dict and
         report.get("purpose")=="read_only_exact_ssl55_installer_reference",
         "Unsupported source report")
    system=report.get("os_release")
    need(type(system) is dict and system.get("ID")=="ubuntu" and
         system.get("VERSION_ID")=="24.04" and
         report.get("architecture")=="x86_64",
         "Expected SSL55 Ubuntu 24.04 x86_64 reference")
    pkgs=report.get("packages")
    services=report.get("services")
    configs=report.get("cape_configs_present")
    vm=report.get("master")
    need(all(type(x) is dict for x in (pkgs,services,configs,vm)),
         "Missing expected package/service/Windows source groups")
    attested=all(configs.get(k) is True for k in REQUIRED_CONF)
    systemd=all(service_ready(services,k) for k in REQUIRED_UNITS)
    both=vm.get("state")=="shut off" and type(vm.get(
         "snapshot_names")) is list and "Afterfull" in vm["snapshot_names"]
    git=report.get("cape_git_revision")
    revision=(git if type(git) is str and
              re.fullmatch(r"[0-9a-f]{40}",git) else None)
    inetsim_service=services.get("inetsim.service",{})
    inetsim_installed=(package_status(pkgs.get("inetsim"))==
                        "dpkg_version_attested")
    inetsim_loaded=(type(inetsim_service) is dict and
                    inetsim_service.get("LoadState")=="loaded")
    virt={k:package_status(pkgs.get(k)) for k in VIRT_PACKAGES}
    unknown_virt=[k for k in VIRT_PACKAGES if
                  virt[k]!="dpkg_version_attested"]
    free=report.get("vm_storage_free_gib")
    need(type(free) in (float,int) and 0<=free<10**6,
         "Unknown or invalid VM storage free space")
    observations={
        "ubuntu_24_04_x86_64":True,
        "all_six_CAPE_conf_files_present":attested,
        "required_services_loaded_and_active":systemd,
        "master_win11_shut_off_with_Afterfull_named_snapshot":both,
        "rclone_binary_seen":report.get("rclone_installed") is True,
        "rclone_root_crypt_OAuth_setup_verified":False,
        "original_CAPE_checkout_git_SHA40":revision,
        "virtualization_selected_dpkg_package_status":virt,
        "virtualization_software_absent_proven":False,
        "inetsim_dpkg_version_seen":inetsim_installed,
        "inetsim_systemd_unit_loaded":inetsim_loaded,
        "INetSim_operational_implementation_verified":False,
        "CAPE_QEMU_compatibility_proven_on_new_host":False,
        "source_master_virtual_size_gib":None,
        "source_master_export_space_free_gib":round(free,2),
        "source_export_storage_adequacy_proven":False,
        "source_running_snapshot_binary_export_included":False,
        "git_repo_or_machine_modified":False,
    }
    blockers=[]
    if not attested: blockers.append("MISSING_REFERENCE_CAPE_CONFIG")
    if not systemd: blockers.append("REFERENCE_REQUIRED_SERVICE_NOT_ACTIVE")
    if not both: blockers.append("REFERENCE_MASTER_OR_AFTERFULL_NOT_ATTESTED")
    if not revision: blockers.append("CAPE_GIT_COMMIT_NOT_IDENTIFIED")
    if not (inetsim_installed or inetsim_loaded):
        blockers.append("INETSIM_NOT_DISCOVERED_BY_PACKAGE_OR_SYSTEMD")
    else:
        blockers.append("INETSIM_OPERATION_NOT_VERIFIED")
    if unknown_virt:
        blockers.append("VIRTUALIZATION_PACKAGE_PROVENANCE_UNKNOWN")
    blockers.extend(("ORIGINAL_MASTER_VIRTUAL_SIZE_NOT_IN_REPORT",
                     "SOURCE_EXPORT_STORAGE_NOT_APPROVED",
                     "NEW_HOST_BOOT_TPM_RUNNING_SNAPSHOT_UNVERIFIED",
                     "NEW_HOST_CAPE_DEPENDENCY_INSTALL_NOT_ATTESTED"))
    return {
        "result":"SSL55_SOURCE_REFERENCE_GAPS_EXPLICIT_NO_MUTATIONS",
        "reference":report["hostname"],
        "source":observations,
        "blocking_evidence":blockers,
        "physical_new_host_accepted":False,
        "portable_Cape_INetSim_command1_complete":False,
        "golden_master_private_drive_uploaded":False,
        "may_begin_unattended_export_now":False,
        "may_infer_virtualization_missing_from_dpkg":False,
        "next_source_evidence_categories":[
           "actual_QEMU_and_virsh_binary_version_and_origin",
           "actual_CAPEv2_tree_commit_or_git_checkout_presence",
           "actual_INetSim_installation_path_or_absence",
           "master_QCOW2_virtual_size_and_backing_chain",
           "approved_temporary_storage_capacity",
        ],
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    try:
        print(json.dumps(review(load(a.report)),sort_keys=True,indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "result":"REFERENCE_REPORT_RECONCILIATION_BLOCKED",
            "error_type":type(exc).__name__,
            "no_software_or_VM_changes":True,
        },sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
