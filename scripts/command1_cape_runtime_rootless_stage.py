#!/usr/bin/env python3
"""Guarded rootless, strictly OFFLINE CAPEv2 Python3.12 runtime substage.

A preverified Python distribution, uv binary, exact CAPE git source and
all SHA-approved wheel bytes MUST ALREADY be on disk. This module makes
NO downloads and performs NO root package installs, VM boots, or service
restarts. It runs the actual dependency installation as a dedicated,
existing unprivileged CAPE user and records the attempt BEFORE mutation
in the host-bound deployment transaction. This is a Command1 component,
NOT the finished three-command release or Windows snapshot acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import uuid

import command123_deployment_transaction as tx
import command1_tracked_cape_source as source
import command1_cape_runtime_offline_admission as wheels

ROOT = Path("/var/lib/cape-command1-runtime")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
APPROVAL = "INSTALL-ROOTLESS-HASHED-OFFLINE-CAPE-PY312"
RUNTIME_KIND = "cape_runtime"


class RuntimeBlocked(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise RuntimeBlocked(reason)


def sha_file(path):
    p = Path(path)
    need(p.is_absolute() and
         not any(x.is_symlink() for x in (p, *p.parents)),
         "Untrusted binary path/symlink")
    meta = p.stat()
    need(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and
         meta.st_uid == 0 and not meta.st_mode & 0o022 and
         1000 <= meta.st_size <= 200 * 1024 * 1024,
         "Invalid root-owned reviewed executable")
    digest = hashlib.sha256()
    with p.open("rb") as stream:
        while True:
            part = stream.read(1024 * 1024)
            if not part:
                break
            digest.update(part)
    return digest.hexdigest()


def stage_parent(create=False):
    need(ROOT.is_absolute() and ROOT.parent == Path("/var/lib") and
         ROOT.parent.is_dir() and ROOT.parent.stat().st_uid == 0 and
         not ROOT.parent.stat().st_mode & 0o022,
         "Invalid trusted runtime parent")
    if not ROOT.exists() and create:
        ROOT.mkdir(mode=0o755)
        tx.fsync_dir(ROOT.parent)
    if ROOT.exists():
        meta = ROOT.lstat()
        need(stat.S_ISDIR(meta.st_mode) and
             meta.st_uid == 0 and not meta.st_mode & 0o022,
             "Untrusted runtime root")
    return ROOT


def user_account(name):
    need(type(name) is str and USERNAME.fullmatch(name) and
         name not in ("root","nobody"),
         "Explicit non-privileged CAPE runtime account required")
    try:
        account = pwd.getpwnam(name)
    except KeyError as exc:
        raise RuntimeBlocked("CAPE unprivileged service user not provisioned") from exc
    need(account.pw_uid != 0 and account.pw_gid != 0,
         "Runtime cannot run as root")
    return account


def source_entry(doc):
    matches = [x for x in doc["entries"] if x.get("kind") == "cape_source"]
    need(len(matches) == 1 and matches[0].get("status") == "sealed",
         "Pinned upstream CAPE source must be sealed")
    return matches[0]


def plan(host, transaction, manifest, lock, wheelhouse, approved_manifest,
         uv, approved_uv_sha, python, approved_python_sha, user):
    tx.host_guard(host)
    need(type(transaction) is str and
         re.fullmatch(r"[0-9a-f]{32}",transaction),
         "Exact active deployment ID needed")
    receipt,doc=tx.load(transaction,host)
    need(doc["phase"] == "active" and
         not any(x.get("kind") == RUNTIME_KIND for x in doc["entries"]),
         "A runtime stage has already been attempted")
    entry=source_entry(doc)
    # The original, exact source import is verified with Git, without
    # executing upstream installers as root.
    original=Path(entry["target"])
    need(original.is_dir() and
         source.pristine(original,entry["revision"]) == entry["after"],
         "Source checkout provenance or content changed")
    need(type(approved_uv_sha) is str and
         SHA256.fullmatch(approved_uv_sha) and
         sha_file(uv) == approved_uv_sha,
         "uv binary does not match separately approved SHA256")
    need(type(approved_python_sha) is str and
         SHA256.fullmatch(approved_python_sha) and
         sha_file(python) == approved_python_sha,
         "Isolated Python binary does not match approved SHA256")
    packages=wheels.plan(manifest,lock,wheelhouse,approved_manifest)
    need(packages["source_sha"] == entry["revision"],
         "Approved wheel set is not for this CAPE source revision")
    account=user_account(user)
    stage_parent()
    target=ROOT/transaction
    need(not target.exists() and not target.is_symlink(),
         "Runtime target already exists or was partially created")
    return {
        "result":"CAPE_ROOTLESS_OFFLINE_INSTALL_PLAN_ONLY",
        "transaction":transaction,
        "runtime_target":str(target/"venv"),
        "runtime_owner":user,
        "runtime_uid":account.pw_uid,
        "cape_upstream_source":str(original),
        "source_commit":entry["revision"],
        "approved_manifest_sha256":approved_manifest,
        "reviewed_uv_sha256":approved_uv_sha,
        "reviewed_python_sha256":approved_python_sha,
        "packages_verified":packages["packages_verified"],
        "no_network_or_remote_package_builds":True,
        "upstream_install_scripts_not_used":True,
        "system_python_replaced":False,
        "no_host_changes":True,
        "production_CAPE_services_started":False,
        "Windows_running_snapshot_tested":False,
    }


def rootless_command(account, argv, home, *, seconds=1200):
    need(type(argv) is list and argv and
         all(type(a) is str and a for a in argv) and
         Path(argv[0]).is_absolute(),
         "Only reviewed executable argv allowed")
    env = {
        "PATH":"/usr/bin:/bin",
        "HOME":str(home),
        "UV_NO_CACHE":"1",
        "UV_OFFLINE":"1",
        "PIP_NO_INDEX":"1",
        "PYTHONNOUSERSITE":"1",
        "LC_ALL":"C.UTF-8",
        "XDG_CACHE_HOME":str(home/"cache"),
    }
    run = subprocess.run(
        ["/usr/sbin/runuser","-u",account.pw_name,"--",*argv],
        env=env,stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,timeout=seconds,check=False)
    need(run.returncode == 0 and len(run.stdout) <= 1024*1024 and
         len(run.stderr) <= 1024*1024,
         "Unprivileged CAPE Python step failed or returned excessive output")
    return run.stdout


def apply(host,transaction,manifest,lock,wheelhouse,approved_manifest,
          uv,approved_uv_sha,python,approved_python_sha,user):
    need(os.geteuid() == 0 and sys.stdin.isatty(),
         "Root TTY required to review and journal installer")
    args=(host,transaction,manifest,lock,wheelhouse,approved_manifest,
          uv,approved_uv_sha,python,approved_python_sha,user)
    proposed=plan(*args)
    print(json.dumps(proposed,indent=2,sort_keys=True),flush=True)
    phrase=APPROVAL+"-"+transaction
    need(input("Type "+phrase+": ").strip() == phrase,
         "Offline Python deployment declined")
    need(plan(*args) == proposed,
         "Reviewed Python or wheelhouse changed after consent")
    with tx.exclusive_transaction_lock(transaction):
        need(plan(*args) == proposed,
             "Source or wheelhouse drift under lock")
        account=user_account(user)
        receipt,doc=tx.load(transaction,host)
        identifier=uuid.uuid4().hex
        target=stage_parent()/transaction
        row={
            "id":identifier,"kind":RUNTIME_KIND,"stage":"command1",
            "status":"prepared","target":str(target),
            "before_present":False,"runtime_owner":user,
            "source_commit":proposed["source_commit"],
            "approved_manifest_sha256":approved_manifest,
            "uv_sha256":approved_uv_sha,
            "python_sha256":approved_python_sha,
            "installed_package_versions":None
        }
        doc["entries"].append(row)
        tx.atomic_receipt(receipt,doc)
        # The journal is durable BEFORE the user-controlled directory
        # is created or a downloaded executable receives CPU time.
        stage_parent(create=True)
        os.mkdir(target,0o700)
        os.chown(target,account.pw_uid,account.pw_gid)
        tx.fsync_dir(ROOT)
        venv=target/"venv"
        uvexe=str(uv)
        pythonexe=str(python)
        rootless_command(
            account,[uvexe,"venv","--offline","--python",pythonexe,str(venv)],
            target,seconds=180)
        rootless_command(
            account,[uvexe,"pip","install","--offline",
                     "--python",str(venv/"bin/python"),
                     "--no-index","--no-deps","--require-hashes",
                     "--find-links",str(wheelhouse),
                     "--requirement",str(lock)],
            target,seconds=1600)
        packages=json.loads(rootless_command(
            account,[uvexe,"pip","list","--offline",
                     "--python",str(venv/"bin/python"),
                     "--format","json"],target,seconds=90))
        want=json.loads(Path(manifest).read_text(encoding="utf-8"))["wheels"]
        got={x["name"].lower().replace("_","-"):x["version"]
             for x in packages}
        expected={k.lower().replace("_","-"):v["version"]
                  for k,v in want.items()}
        need(got == expected,
             "Offline Python environment differs from exact reviewed wheel set")
        source_path=proposed["cape_upstream_source"]
        output=rootless_command(
            account,[str(venv/"bin/python"),"-B",
                     str(Path(source_path)/"cuckoo.py"),"--help"],
            target,seconds=100)
        need("--help" in output,
             "Pinned CAPEv2 CLI cannot import and start with reviewed wheels")
        row["installed_package_versions"]=got
        row["status"]="sealed"
        tx.atomic_receipt(receipt,doc)
        return {
            "result":"CAPE_ROOTLESS_OFFLINE_PY312_RUNTIME_INSTALLED",
            "transaction":transaction,
            "runtime":str(venv),
            "packages":len(got),
            "unprivileged_user":user,
            "system_python_unchanged":True,
            "CAPE_full_services_started":False,
            "Windows_TPM_snapshot_revert_proven":False,
        }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan","apply"),default="plan")
    p.add_argument("--approved-host",required=True)
    p.add_argument("--transaction",required=True)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--wheelhouse",type=Path,required=True)
    p.add_argument("--approved-manifest-sha256",required=True)
    p.add_argument("--uv",type=Path,required=True)
    p.add_argument("--approved-uv-sha256",required=True)
    p.add_argument("--python",type=Path,required=True)
    p.add_argument("--approved-python-sha256",required=True)
    p.add_argument("--runtime-user",default="cape")
    args=p.parse_args()
    params=(args.approved_host,args.transaction,args.manifest,args.lock,
            args.wheelhouse,args.approved_manifest_sha256,args.uv,
            args.approved_uv_sha256,args.python,args.approved_python_sha256,
            args.runtime_user)
    try:
        report=plan(*params) if args.mode=="plan" else apply(*params)
        print(json.dumps(report,indent=2,sort_keys=True))
        return 0
    except (RuntimeBlocked,tx.TransactionBlocked,source.SourceBlocked,
            wheels.AdmissionBlocked,OSError,ValueError,TypeError,
            subprocess.TimeoutExpired,KeyError) as exc:
        print(json.dumps({
            "result":"CAPE_ROOTLESS_OFFLINE_RUNTIME_BLOCKED_OR_PARTIAL",
            "error_type":type(exc).__name__,
            "never_auto_delete_partial_runtime":True,
            "full_three_command_install":False
        }),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
