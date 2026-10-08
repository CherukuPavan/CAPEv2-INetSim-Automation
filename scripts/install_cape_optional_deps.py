#!/usr/bin/env python3
"""CAPE optional-package reconciler: plan first; constrained explicit apply.

The actual CAPE interpreter is discovered via the cape service account, not
through the invoking user's Poetry. Apply uses pip dry-run resolution and
blocks changing versions pinned by /opt/CAPEv2/poetry.lock. No global pip.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

SAMPLES = ("ImageHash", "deepdiff", "binGraph", "HTTPReplay", "Socks5man", "pyattck")
SERVICES = ("cape.service", "cape-processor.service", "cape-web.service", "cape-rooter.service")
CAPE_ROOT = Path("/opt/CAPEv2")
REQ = CAPE_ROOT / "extra/optional_dependencies.txt"
LOCK = CAPE_ROOT / "poetry.lock"
POETRY = Path("/etc/poetry/bin/poetry")


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def call(args: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        p = subprocess.run(args, text=True, capture_output=True, errors="replace",
                           timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return 125, ""
    return p.returncode, p.stdout.strip()


def service_python() -> Path | None:
    if not POETRY.is_file():
        return None
    status, result = call(["sudo", "-n", "-u", "cape", "-H", str(POETRY),
                           "-C", str(CAPE_ROOT), "env", "info", "--executable"])
    if status != 0 or not result.startswith("/") or "\n" in result:
        return None
    status, _ = call(["sudo", "-n", "-u", "cape", "-H", "test", "-x", result])
    return Path(result) if status == 0 else None


def locked_versions(lock_path: Path) -> dict[str, str]:
    data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    return {normalized(x["name"]): x["version"] for x in data.get("package", [])
            if isinstance(x, dict) and isinstance(x.get("name"), str)
            and isinstance(x.get("version"), str)}


def conflicts(proposed: list[dict[str, str]], lock: dict[str, str]) -> list[str]:
    """Fail closed if any proposed name modifies a pinned core distribution."""
    trouble = []
    for pkg in proposed:
        name = normalized(pkg.get("name", ""))
        version = pkg.get("version", "")
        if name in lock and version != lock[name]:
            trouble.append(name + " proposed=" + version + " locked=" + lock[name])
    return sorted(trouble)


# Runs under cape's Python. Dry-run creates a temporary report, not installs.
# On success output JUST a list of proposed name/version; avoid printing pip
# logs (which may include VCS URLs or other secrets).
RESOLVE_CODE = r"""
import json, os, subprocess, sys, tempfile
req=sys.argv[1]
with tempfile.TemporaryDirectory(prefix='cape-pip-resolve-') as folder:
    report=os.path.join(folder,'proposal.json')
    cmd=[sys.executable,'-m','pip','install','--dry-run','--report',report,
         '--disable-pip-version-check','-r',req]
    r=subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=900, check=False)
    if r.returncode!=0:
        print(json.dumps({'error':'resolver-failed','code':r.returncode}))
        raise SystemExit(0)
    with open(report,encoding='utf-8') as fh:
        plan=json.load(fh)
    packages=[{'name':x.get('metadata',{}).get('name',''),
               'version':x.get('metadata',{}).get('version','')}
              for x in plan.get('install',[])]
    print(json.dumps({'proposed':packages}))
"""


def sample_versions(python: Path) -> dict[str, str | None] | None:
    code = ("import json, importlib.metadata as m\n"
            "names = " + repr(SAMPLES) + "\n"
            "out = {}\n"
            "for n in names:\n"
            "  try: out[n] = m.version(n)\n"
            "  except m.PackageNotFoundError: out[n] = None\n"
            "print(json.dumps(out))\n")
    status, output = call(["sudo", "-n", "-u", "cape", "-H", str(python), "-B", "-c", code])
    if status != 0:
        return None
    try:
        data = json.loads(output)
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def proposed_changes(python: Path, req: Path) -> dict:
    status, output = call(["sudo", "-n", "-u", "cape", "-H", str(python),
                           "-B", "-c", RESOLVE_CODE, str(req)], timeout=930)
    if status != 0:
        raise RuntimeError("Resolver could not execute as cape")
    try:
        result = json.loads(output)
    except ValueError:
        raise RuntimeError("Resolver did not return valid summary") from None
    if not isinstance(result, dict) or result.get("error"):
        raise RuntimeError("pip dependency dry-run failed; no package installation attempted")
    vals = result.get("proposed")
    if not isinstance(vals, list) or any(not isinstance(x, dict) for x in vals):
        raise RuntimeError("Resolver returned invalid plan")
    return result


def service_states() -> dict[str, str]:
    states = {}
    for unit in SERVICES:
        status, state = call(["systemctl", "show", unit, "--value", "-p", "ActiveState"])
        states[unit] = state if status == 0 else "unknown"
    return states


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--requirements", type=Path, default=REQ)
    parser.add_argument("--expected-sha256",
                        help="Required for apply; must match exact optional requirements content")
    parser.add_argument("--approve-live-change", action="store_true",
                        help="Acknowledges services may be active; no automatic restarts.")
    parser.add_argument("--report", type=Path, default=None,
                        help="Optional NEW private summary TXT; never overwrite")
    args = parser.parse_args(argv)
    req = args.requirements
    try:
        if not req.is_absolute() or not req.is_file():
            parser.error("Requirements must exist at an absolute path")
        # Only use deployment's checked-out optional dependency manifest;
        # arbitrary local paths could inject different VCS/package dependencies.
        if req.resolve() != REQ.resolve():
            parser.error("Only /opt/CAPEv2/extra/optional_dependencies.txt is supported")
        if not LOCK.is_file():
            parser.error("CAPE poetry.lock missing: cannot constrain core versions")
        sha = hashlib.sha256(req.read_bytes()).hexdigest()
        locks = locked_versions(LOCK)
        if not locks:
            parser.error("No parseable locked packages; refuse optional install")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        parser.error("Cannot validate CAPE files: " + type(exc).__name__)

    python = service_python()
    data: dict = {
        "mode": args.mode,
        "requirements_sha256": sha,
        "lock_package_count": len(locks),
        "service_python_resolved": python is not None,
        "sample_optional": {},
        "proposal": [],
        "pinned_conflicts": [],
        "applied": False,
        "status": "INCOMPLETE",
    }
    if python is None:
        data["status"] = "BLOCKED_CANNOT_ACCESS_CAPE_ENVIRONMENT"
    else:
        sample = sample_versions(python)
        if sample is None:
            data["status"] = "BLOCKED_CANNOT_READ_CAPE_PACKAGES"
        else:
            data["sample_optional"] = sample
            data["status"] = "PLAN_ONLY"
            if args.mode == "apply":
                if args.expected_sha256 != sha:
                    parser.error("Apply requires exact --expected-sha256 from previous plan")
                states = service_states()
                if any(s == "active" for s in states.values()) and not args.approve_live_change:
                    parser.error("CAPEv2 services active; use --approve-live-change only with maintenance coordination")
                plan = proposed_changes(python, req)
                proposed = plan["proposed"]
                data["proposal"] = proposed
                data["pinned_conflicts"] = conflicts(proposed, locks)
                if data["pinned_conflicts"]:
                    data["status"] = "BLOCKED_LOCKFILE_CONFLICT"
                else:
                    # Only the identified service-account interpreter is used.
                    # stdout is captured but never echoed (URLs/credentials).
                    rc, _ = call(["sudo", "-n", "-u", "cape", "-H",
                                  str(python), "-B", "-m", "pip", "install",
                                  "--disable-pip-version-check", "-r", str(req)], timeout=1800)
                    data["applied"] = rc == 0
                    data["status"] = "PIP_EXIT_SUCCESS_REVERIFY_NEEDED" if rc == 0 else "PIP_FAILED_PARTIAL_POSSIBLE"
                    data["sample_optional_after"] = sample_versions(python)

    output = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        dest = args.report.expanduser().absolute()
        if dest.is_symlink() or dest.exists():
            parser.error("Refusing to overwrite/symlink report")
        dest.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(output)
        print("Private report:", dest)
    else:
        print(output)
    return 0 if data["status"] in ("PLAN_ONLY", "PIP_EXIT_SUCCESS_REVERIFY_NEEDED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
