#!/usr/bin/env python3
"""Render one credential-free, immutably pinned GitHub source bootstrap.

This obtains and verifies PUBLIC source only. It neither installs CAPE nor
fetches the encrypted private Windows/TPM master, and is NOT Command 1.
"""
from __future__ import annotations

import argparse
import re

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
TEMPLATE = r"""python3 - <<'CAPE_VERIFIED_PUBLIC_BOOTSTRAP'
import base64
import hashlib
import json
import os
import sys
from urllib.request import Request, urlopen

REVISION = "__PINNED_COMMIT__"
EXPECTED_BLOB = "__PINNED_HELPER_BLOB__"
REPOSITORY = "CherukuPavan/CAPEv2-INetSim-Automation"
PATH = "scripts/command123_private_pinned_checkout.py"

def controlling_tty():
    try:
        fd = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        return os.isatty(fd)
    finally:
        os.close(fd)

if os.geteuid() == 0 or not controlling_tty():
    raise SystemExit("Use a local interactive non-root controlling terminal")
try:
    url = ("https://api.github.com/repos/" + REPOSITORY +
           "/contents/" + PATH + "?ref=" + REVISION)
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "cape-public-sha-pinned-bootstrap",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urlopen(request, timeout=30) as response:
        body = response.read(131073)
    if len(body) > 131072:
        raise ValueError("Oversized GitHub source response")
    source = json.loads(body)
    if not isinstance(source, dict) or source.get("encoding") != "base64" or (
            source.get("sha") != EXPECTED_BLOB):
        raise ValueError("Source Git blob does not match reviewed SHA")
    encoded = source.get("content")
    if not isinstance(encoded, str) or len(encoded) > 100000:
        raise ValueError("Invalid GitHub base64 source payload")
    # GitHub Contents API folds Base64 with CR/LF. Validate every remaining
    # character rather than accepting arbitrary whitespace or extra bytes.
    data = base64.b64decode("".join(encoded.splitlines()), validate=True)
    if len(data) > 65536:
        raise ValueError("Oversized GitHub helper")
    actual = hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()
    if actual != EXPECTED_BLOB:
        raise ValueError("Git source object hash mismatch")
    env = {"__name__": "verified_public_source", "__file__": "<verified>"}
    exec(compile(data, "verified-public-source.py", "exec"), env)
    if env.get("REPO") != REPOSITORY or not callable(env.get("main")):
        raise ValueError("Unexpected verified source entrypoint")
    sys.argv = ["verified-public-source", "--revision", REVISION, "--public"]
    raise SystemExit(env["main"]())
except SystemExit:
    raise
except Exception as exc:
    # Do not print remote-origin error strings, query parameters or credentials.
    raise SystemExit("Pinned public GitHub source blocked: " +
                     type(exc).__name__)
CAPE_VERIFIED_PUBLIC_BOOTSTRAP"""


def render(commit_sha: str, blob_sha: str) -> str:
    if not SHA40.fullmatch(commit_sha) or not SHA40.fullmatch(blob_sha):
        raise ValueError("Exact SHA40 commit and helper Git blob are required")
    if commit_sha == blob_sha:
        raise ValueError("Copied commit/blob identities refused")
    return TEMPLATE.replace("__PINNED_COMMIT__", commit_sha).replace(
        "__PINNED_HELPER_BLOB__", blob_sha)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pinned-commit", required=True)
    parser.add_argument("--helper-blob", required=True)
    args = parser.parse_args()
    try:
        print(render(args.pinned_commit, args.helper_blob))
        return 0
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
