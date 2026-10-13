#!/usr/bin/env python3
"""Read-only verifier for an AUTHENTICATED private development checkout.

Never downloads source, changes Git config, displays remote credentials or
deploys CAPE/Windows. Exact GitHub owner/repo, branch development, full
pinned commit and CLEAN tree are mandatory before other-host install.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

OWNER="CherukuPavan"
REPO="CAPEv2-INetSim-Automation"
BRANCH="development"
GIT="git"
SHA40=re.compile(r"[a-f0-9]{40}\Z")
SAFE_SSH=re.compile(r"git@github\.com:"+OWNER+"/"+REPO+r"(?:\.git)?\Z",
                    re.IGNORECASE)

class PrivateCheckoutBlocked(RuntimeError):
    pass

def need(ok,why):
    if not ok:raise PrivateCheckoutBlocked(why)

def accepted_remote(value):
    """Refuse embedded usernames/passwords and any untrusted Git host."""
    if SAFE_SSH.fullmatch(value):
        return "github_authenticated_ssh"
    try:
        url=urlsplit(value)
    except ValueError:
        return None
    if (url.scheme == "https" and url.hostname == "github.com" and
        url.username is None and url.password is None and
        url.port is None and not url.query and not url.fragment and
        url.path.lower() in (
            "/"+OWNER.lower()+"/"+REPO.lower(),
            "/"+OWNER.lower()+"/"+REPO.lower()+".git")):
        return "github_authenticated_https"
    return None

def git(*args):
    try:
        process=subprocess.run([GIT,*args],capture_output=True,text=True,
                               check=False,timeout=15)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise PrivateCheckoutBlocked(
            "Git unavailable or timed out") from exc
    need(process.returncode==0 and len(process.stdout)<64*1024,
         "Git checkout inspection unavailable")
    return process.stdout.strip()

def inspect(checkout,expected_sha):
    root=Path(checkout)
    need(root.is_absolute() and root.is_dir() and
         not root.is_symlink(),
         "Checkout must be existing absolute non-symlink directory")
    need(type(expected_sha) is str and
         SHA40.fullmatch(expected_sha) is not None,
         "Pinned audited development commit SHA40 required")
    loc=git("-C",str(root),"rev-parse","--show-toplevel")
    need(Path(loc).resolve()==root.resolve(),
         "Selected path not root of intended Git checkout")
    branch=git("-C",str(root),"branch","--show-current")
    need(branch==BRANCH,
         "Selected checkout must be development, NOT main")
    origin=git("-C",str(root),"remote","get-url","origin")
    method=accepted_remote(origin)
    need(method is not None,
         "Remote is not exact authenticated github.com project path; "
         "embedded URL credentials are NOT permitted")
    sha=git("-C",str(root),"rev-parse","--verify","HEAD")
    need(sha==expected_sha and SHA40.fullmatch(sha) is not None,
         "Checkout commit differs from reviewed SHA")
    current=git("-C",str(root),"status","--porcelain",
                "--untracked-files=normal")
    need(current=="","Checkout has uncommitted or untracked files")
    return {
        "result":"PRIVATE_GITHUB_DEVELOPMENT_CHECKOUT_PINNED_READ_ONLY",
        "repository":OWNER+"/"+REPO,
        "branch":BRANCH,
        "commit":sha,
        "authenticated_git_remote_format":method,
        "working_tree_clean":True,
        "token_or_password_output":False,
        "host_modified":False,
        "ready_for_stage_planning":True,
        "fresh_host_installed":False,
        "windows_vm_started":False,
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout",type=Path,required=True)
    parser.add_argument("--expected-sha",required=True)
    a=parser.parse_args()
    try:
        print(json.dumps(inspect(a.checkout,a.expected_sha),
                         sort_keys=True,indent=2),flush=True)
        return 0
    except Exception as exc:
        # URLs, tokens and git stderr must not leak from failure.
        print(json.dumps({"result":"PRIVATE_DEVELOPMENT_CHECKOUT_BLOCKED",
                          "error_type":type(exc).__name__,
                          "raw_remote_not_disclosed":True,
                          "host_modified":False},sort_keys=True),
              file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
