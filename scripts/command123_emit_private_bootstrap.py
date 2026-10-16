#!/usr/bin/env python3
"""Emit a single shell command for pinned PRIVATE source checkout on Ubuntu.

Development operator UX component only. It fetches the exact private
checkout helper over authenticated GitHub REST (read-only token from local
TTY), checks its pinned Git blob hash, executes it in memory and downloads
the entire pinned repository with per-blob verification. The token never
appears in argv, environment, logs or shell history.

This command is ONLY private source acquisition; it does NOT deploy CAPE,
load Windows, start a VM, validate swtpm or replace the final Command1.
"""
from __future__ import annotations

import argparse
import re

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
TEMPLATE = r"""python3 - <<'CAPE_VERIFIED_PRIVATE_BOOTSTRAP'
import base64
import getpass
import hashlib
import json
import os
import sys
from urllib.request import Request, urlopen

REVISION = "__COMMIT_SHA__"
EXPECTED_HELPER_BLOB = "__BLOB_SHA__"
REPO = "CherukuPavan/CAPEv2-INetSim-Automation"
PATH = "scripts/command123_private_pinned_checkout.py"
if os.geteuid() == 0 or not sys.stdin.isatty():
    raise SystemExit("Use an interactive non-root terminal")
token = getpass.getpass("Private GitHub read-only token: ")
if not (8 <= len(token) <= 500) or "\n" in token or "\r" in token:
    raise SystemExit("Invalid token supplied")
try:
    url = ("https://api.github.com/repos/" + REPO +
           "/contents/" + PATH + "?ref=" + REVISION)
    req = Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "cape-verified-source-bootstrap",
    })
    with urlopen(req, timeout=30) as response:
        doc_bytes = response.read(131073)
    if len(doc_bytes) > 131072:
        raise ValueError("Oversized GitHub helper response")
    doc = json.loads(doc_bytes)
    if doc.get("encoding") != "base64" or doc.get("sha") != EXPECTED_HELPER_BLOB:
        raise ValueError("Pinned helper metadata mismatch")
    data = base64.b64decode(doc["content"], validate=True)
    if len(data) > 65536:
        raise ValueError("Pinned helper code too large")
    got = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()
    if got != EXPECTED_HELPER_BLOB:
        raise ValueError("Pinned Git object hash does not match")
    namespace = {"__name__": "cape_private_pinned_source"}
    exec(compile(data, "verified-private-source.py", "exec"), namespace)
    if namespace.get("REPO") != REPO or not callable(namespace.get("main")):
        raise ValueError("Unexpected helper interface")
    sys.argv = ["verified-private-source", "--revision", REVISION]
    raise SystemExit(namespace["main"](bootstrap_token=token))
except SystemExit:
    raise
except Exception as exc:
    # Never echo credentials or arbitrary remote exception bodies.
    raise SystemExit("Private source bootstrap blocked: " +
                     type(exc).__name__)
CAPE_VERIFIED_PRIVATE_BOOTSTRAP"""


def render(commit_sha: str, helper_blob_sha: str) -> str:
    if not SHA40.fullmatch(commit_sha) or not SHA40.fullmatch(helper_blob_sha):
        raise ValueError("Both source commit and helper blob must be pinned SHA40")
    if commit_sha == helper_blob_sha:
        # Not necessarily impossible in Git but almost always a copied
        # identifier error. Reject rather than generate misleading command.
        raise ValueError("A commit and its source blob are different objects")
    return (TEMPLATE.replace("__COMMIT_SHA__", commit_sha)
                    .replace("__BLOB_SHA__", helper_blob_sha))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pinned-commit", required=True)
    p.add_argument("--helper-blob", required=True)
    args = p.parse_args()
    try:
        print(render(args.pinned_commit, args.helper_blob))
        return 0
    except ValueError as error:
        p.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
