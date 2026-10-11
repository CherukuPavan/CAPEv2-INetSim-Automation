#!/usr/bin/env python3
"""GUARDED original-SSL55 CAPE nft table reconciliation (NOT INSTALLED).

Plan is READ ONLY. Reconcile can add only a missing, exact, historical
table under root-only operator approval. It never enables nftables.service,
edits /etc/nftables.conf, starts a VM/network, attaches NICs, or uses
'flush ruleset'. A dedicated systemd unit is NOT installed by this tool,
and no systemd/reboot-persistence proof is implied.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile

import command2_ssl55_existing_guard_readonly as observed
import command2_ssl55_boot_persistence_readonly as boot
import dryrun_cape_lab_guard_nft as legacy

POLICY_SHA256 = "58b84446ad74ac7ea8b14aa57d94c19945baa3db7330e54c7fb2312a9577ea14"
AUTH_KIND = "CAPE_SSL55_SINGLE_TABLE_REPLAY_AUTHORIZATION_V1"
AUTH_PATH = Path("/etc/cape-command2/ssl55-guard-replay-approved.json")
LOCK_PATH = Path("/run/lock/cape-ssl55-single-table-replay.lock")


class ReplayBlocked(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise ReplayBlocked(why)


def policy_text():
    text = legacy.policy_text()
    require(hashlib.sha256(text.encode("utf-8")).hexdigest() == POLICY_SHA256,
            "Historical CAPE guard policy differs from reviewed SHA256")
    require(text.startswith("table inet cape_analysis_guard {") and
            not any(x in text.lower() for x in
                    ("flush ruleset", "delete table", "add table", "systemctl")),
            "Unapproved modification in dedicated CAPE guard policy")
    return text


def command(*argv, timeout=40):
    try:
        out = subprocess.run(argv, text=True, capture_output=True,
                             check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as err:
        raise ReplayBlocked("Required host command missing or timed out: "+argv[0]) from err
    require(out.returncode == 0,
            "Required host command failed: "+argv[0])
    return out.stdout.strip()


def strict_state():
    """Preserve original, trial and clone; keep CAPE network off."""
    actual = socket.gethostname().split(".",1)[0].lower()
    require(actual in ("ssl-55","cse-ssl-55"),
            "Not the approved SSL55 reference host")
    require(observed.SENTINEL.is_dir() and
            not observed.SENTINEL.is_symlink(),
            "Original SSL55 master preservation marker missing")
    require(os.geteuid()==0,
            "Root required to inspect original nftables state")
    report = observed.audit()
    require(report.get("no_vm_or_network_changes") is True and
            report.get("analysis_network",{}).get("active") == "no" and
            report["analysis_network"].get("autostart") == "no" and
            report["analysis_network"].get("nonforward_no_dhcp_known_subnet") is True,
            "Lab network is not the original inactive isolated network")
    domains = report.get("protected_domains",{})
    for name in ("win11","win11_1","win11_trial_1"):
        item=domains.get(name,{})
        require(item.get("power_state")=="shut off",
                "Protected VM running or identity cannot be verified: "+name)
        require(item.get("nic_counts",{}).get("inactive")==(
                1 if name=="win11" else 0),
                "Protected saved NIC configuration changed: "+name)
        require(boot.domain_autostart(name) is False,
                "Protected VM unexpectedly autostarts: "+name)
    # Do not rely on a mere table name: inspect chain, verdicts and
    # exact expected bridge/agent rules through the strict baseline.
    if report.get("existing_lab_firewall",{}).get("guard_present"):
        require(report["existing_lab_firewall"].get("expected_guard_shape") is True,
                "CAPE guard table is present but differs from historical safe policy")
        status="present_verified"
    else:
        status="missing"
    sys_service=boot.parse_show(boot.read(
        "systemctl","show","--no-pager",
        "--property=LoadState,UnitFileState,ActiveState",
        "nftables.service"),"nftables.service")
    require(sys_service.get("query_succeeded") is True and
            sys_service.get("load_state")=="loaded" and
            sys_service.get("unit_file_state")=="disabled" and
            sys_service.get("boot_enabled_observed") is False,
            "Base nftables.service changed; unsafe to reconcile")
    baseconf=boot.nft_config_metadata()
    require(baseconf.get("root_controlled") is True and
            baseconf.get("file_safe_to_inspect") is True and
            baseconf.get("guard_reference_present") is False and
            baseconf.get("global_flush_present") is True,
            "Unexpected base firewall config; never touch it")
    return status


def plan():
    state=strict_state()
    return {"result":"CAPE_SSL55_SINGLE_GUARD_REPLAY_PLAN_ONLY",
            "existing_guard_state":state,
            "expected_policy_sha256":POLICY_SHA256,
            "eligible_to_consider_guard_only_reconcile":
                state in ("missing","present_verified"),
            "replay_approval_file_installed_by_this_tool":False,
            "systemd_unit_installed":False,
            "reboot_persistence_verified":False,
            "guest_ipv4_negative_tested":False,
            "guest_ipv6_negative_tested":False,
            "network_started":False,"guest_nic_attached":False,
            "no_host_changes":True}


def approval_ok(p=AUTH_PATH):
    require(p.is_absolute() and p.is_file() and
            not p.is_symlink(),"Signed-off host-only authorization missing")
    stat_info=p.lstat()
    require(stat.S_ISREG(stat_info.st_mode) and
            stat_info.st_uid==0 and stat_info.st_nlink==1 and
            stat.S_IMODE(stat_info.st_mode)==0o600 and
            stat_info.st_size <= 16384,
            "Untrusted root-only approval metadata")
    signed=json.loads(p.read_text(encoding="utf-8"))
    require(type(signed) is dict and
            signed.get("kind")==AUTH_KIND and
            signed.get("policy_sha256")==POLICY_SHA256 and
            signed.get("protected_master_uuid")==observed.MASTER_UUID and
            signed.get("protected_clone_uuid")==observed.CLONE_UUID and
            signed.get("approved_single_table_replay") is True and
            signed.get("approved_no_global_flush") is True and
            signed.get("approved_no_guest_or_network_changes") is True and
            type(signed.get("operator")) is str and
            len(signed["operator"])>=3,
            "Authorization does not approve exact CAPE-only replay")
    return True


def reconcile():
    require(os.geteuid()==0,"Root required for scoped nft replay")
    approval_ok()
    require(not LOCK_PATH.is_symlink(),"Guard-replay lock is symlink")
    fd=os.open(LOCK_PATH,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid==0 and
                stat.S_IMODE(meta.st_mode)==0o600 and meta.st_nlink==1,
                "Guard-replay lock metadata unsafe")
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=strict_state()
        if state=="present_verified":
            return {"result":"CAPE_SSL55_EXISTING_GUARD_VERIFIED_NO_CHANGE",
                    "guard_restored":False,"host_changed":False,
                    "network_started":False,"guest_nic_attached":False}
        require(state=="missing","Unexpected legacy guard state")
        source=policy_text()
        # No table deletion, no modifying other host chains: nft -f
        # creates only the absent dedicated inet CAPE table atomically.
        tmpfd,path=tempfile.mkstemp(prefix="cape-ssl55-guard-",
                                    suffix=".nft",dir="/run")
        try:
            with os.fdopen(tmpfd,"w",encoding="utf-8") as output:
                output.write(source)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(path,0o600)
            command("nft","--check","--file",path)
            # Recheck once more; if someone created a table we abort
            # rather than replace it or overwrite another firewall.
            require(strict_state()=="missing",
                    "Guard table appeared before atomic creation")
            command("nft","--file",path)
        finally:
            os.unlink(path)
        need= strict_state()
        require(need=="present_verified",
                "CAPE guard created but strict verification FAILED; stop, do not roll back blindly")
        return {"result":"CAPE_SSL55_SINGLE_GUARD_RESTORED_NEEDS_REBOOT_TEST",
                "table":"cape_analysis_guard","guard_restored":True,
                "unrelated_nft_tables_mutated_by_this_script":False,
                "network_started":False,"guest_nic_attached":False,
                "reboot_persistence_verified":False,
                "guest_ipv4_negative_tested":False,
                "guest_ipv6_negative_tested":False}
    finally:
        os.close(fd)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode",choices=("plan","reconcile"),
                    default="plan")
    args=ap.parse_args()
    try:
        result=plan() if args.mode=="plan" else reconcile()
        print(json.dumps(result,indent=2,sort_keys=True))
        return 0
    except (ReplayBlocked,observed.AuditBlocked,boot.BootBlocked,
            ValueError,TypeError,OSError) as err:
        print("BLOCKED: "+str(err),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
