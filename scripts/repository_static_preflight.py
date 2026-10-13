#!/usr/bin/env python3
"""Repository-wide structural audit: parse all tracked source/docs on CI.

Read-only; no network, package install, VM start, recovery, guest, TPM or
machine modifications. Syntax checks can NOT prove real-host functionality.
"""
from __future__ import annotations

import ast
from collections import Counter
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
MAX_SOURCE = 512 * 1024
POWER_SHELL_PARSE = """
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $env:CAPE_PS1_PATH, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count -gt 0) { exit 2 }
"""


def tracked():
    p = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"],
                       capture_output=True, check=True, timeout=40)
    return sorted(Path(x.decode("utf-8")) for x in p.stdout.split(b"\0") if x)


def main():
    files = tracked()
    errors = []
    warnings = []
    counted = Counter()
    yaml_mod = None
    try:
        import yaml as yaml_mod
    except ImportError:
        warnings.append("PyYAML absent: workflow YAML cannot be parsed")
    for relative in files:
        path = ROOT / relative
        counted["tracked_entries"] += 1
        if not path.is_file() or path.is_symlink():
            errors.append(str(relative) + ": missing or symlink file")
            continue
        try:
            contents = path.read_bytes()
            if len(contents) > MAX_SOURCE and path.suffix in (
                ".py", ".sh", ".ps1", ".yml", ".yaml"):
                errors.append(str(relative) + ": source exceeds safe parse cap")
                continue
            if path.suffix == ".py":
                ast.parse(contents, filename=str(relative))
                counted["python_parsed"] += 1
            elif path.suffix == ".sh":
                p = subprocess.run(["bash", "-n", str(path)],
                                   capture_output=True, timeout=30)
                if p.returncode:
                    errors.append(str(relative) + ": bash parser rejected")
                counted["bash_checked"] += 1
            elif path.suffix in (".ps1", ".psm1"):
                if shutil.which("pwsh"):
                    import os
                    env = dict(os.environ)
                    env["CAPE_PS1_PATH"] = str(path)
                    p = subprocess.run([
                        "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
                        "-Command", POWER_SHELL_PARSE],
                        env=env, capture_output=True, timeout=45)
                    if p.returncode:
                        errors.append(str(relative) +
                                      ": PowerShell AST parser rejected")
                    counted["powershell_checked"] += 1
                else:
                    counted["powershell_unchecked"] += 1
            elif path.suffix in (".yaml", ".yml"):
                if yaml_mod:
                    yaml_mod.safe_load(contents.decode("utf-8"))
                    counted["yaml_parsed"] += 1
                else:
                    counted["yaml_unchecked"] += 1
            elif path.suffix == ".md":
                counted["markdown_checked"] += 1
                body = contents.decode("utf-8")
                for match in re.finditer(r"\]\(([^)\n]+)\)", body):
                    link = match.group(1).strip().split()[0]
                    if link.startswith(("#", "http:", "https:", "mailto:",
                                        "sandbox:", "data:", "<")):
                        continue
                    link = unquote(link.split("#", 1)[0].split("?", 1)[0])
                    if not link or link.startswith("/"):
                        continue
                    if not (path.parent / link).exists():
                        warnings.append(str(relative) + ": possible stale link "
                                        + link[:140])
        except Exception as exc:
            errors.append(str(relative) + ": " + type(exc).__name__)
    report = {
        "result": "REPOSITORY_STRUCTURAL_PREFLIGHT",
        "git_files_checked": counted["tracked_entries"],
        "counts": dict(counted),
        "fatal_errors": errors[:100],
        "fatal_count": len(errors),
        "potential_document_link_warnings": warnings[:100],
        "documentation_warning_count": len(warnings),
        "Windows_boot_or_TPM_snapshot_physically_verified": False,
        "fresh_host_installer_complete": False,
        "no_local_or_remote_machine_modified": True,
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
