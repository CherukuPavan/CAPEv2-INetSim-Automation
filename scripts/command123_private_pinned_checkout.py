#!/usr/bin/env python3
"""Verified private GitHub checkout without Git, public access or a fourth command.

Library component: the eventual Command 1 may call acquire() internally.
A successful checkout is NOT a CAPEv2 installation or snapshot release.
Credentials are read from a TTY and are never written to disk or argv.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import (
    HTTPRedirectHandler, Request, build_opener, urlopen,
)

REPO = "CherukuPavan/CAPEv2-INetSim-Automation"
API = "https://api.github.com/repos/" + REPO
SHA40 = re.compile(r"[0-9a-f]{40}")
MAX_JSON = 4 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXTRACTED = 128 * 1024 * 1024
MAX_FILES = 4000


class CheckoutBlocked(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise CheckoutBlocked(why)


def git_hash(content: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def api_json(path: str, token: str) -> dict:
    require(path.startswith("/git/") and "?" not in path or
            path.startswith("/git/trees/") and path.endswith("?recursive=1"),
            "Disallowed GitHub API endpoint")
    req = Request(API + path, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "cape-verified-checkout",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urlopen(req, timeout=30) as response:
        data = response.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, "GitHub API response too large")
    doc = json.loads(data)
    require(type(doc) is dict, "Invalid GitHub API response")
    return doc


def tree_entries(commit_sha: str, token: str) -> dict:
    require(SHA40.fullmatch(commit_sha), "A pinned 40-hex commit is required")
    commit = api_json("/git/commits/" + commit_sha, token)
    require(commit.get("sha") == commit_sha and
            isinstance(commit.get("tree"), dict) and
            SHA40.fullmatch(commit["tree"].get("sha", "")),
            "Pinned commit response does not match requested SHA")
    tree_sha = commit["tree"]["sha"]
    tree = api_json("/git/trees/" + tree_sha + "?recursive=1", token)
    require(tree.get("sha") == tree_sha and tree.get("truncated") is False,
            "GitHub tree is truncated or has wrong SHA")
    items = tree.get("tree")
    require(type(items) is list and 0 < len(items) <= MAX_FILES,
            "GitHub repository tree size is invalid")
    entries = {}
    total = 0
    for item in items:
        require(type(item) is dict, "Bad GitHub tree element")
        name = item.get("path")
        require(type(name) is str, "Bad GitHub tree filename")
        p = PurePosixPath(name)
        require(not p.is_absolute() and name == str(p) and
                all(part not in ("", ".", "..") for part in p.parts) and
                len(name) < 512, "Unsafe GitHub tree path")
        mode, kind = item.get("mode"), item.get("type")
        if kind == "tree":
            require(mode == "040000", "Unexpected GitHub tree mode")
            continue
        # Symlinks and submodules are deliberately unsupported in this first
        # release; a changing repository cannot smuggle filesystem redirects.
        require(kind == "blob" and mode in ("100644", "100755") and
                SHA40.fullmatch(item.get("sha", "")),
                "Unsupported link, submodule, or Git object type")
        size = item.get("size")
        require(type(size) is int and 0 <= size <= 16 * 1024 * 1024,
                "Unreasonable repository file size")
        require(name not in entries, "Duplicate GitHub tree file")
        entries[name] = (item["sha"], size, mode)
        total += size
    require(entries and total <= MAX_EXTRACTED,
            "Repository exceeds checkout size limit")
    return entries


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def archive_to_temp(commit_sha: str, token: str, directory: Path) -> Path:
    req = Request(API + "/tarball/" + commit_sha, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "cape-verified-checkout",
    })
    opener = build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=30):
            raise CheckoutBlocked("GitHub archive did not provide redirect")
    except HTTPError as error:
        try:
            require(error.code in (301, 302, 303, 307, 308),
                    "Unexpected GitHub archive response")
            url = error.headers.get("Location", "")
        finally:
            error.close()
    parsed = urlparse(url)
    require(parsed.scheme == "https" and
            parsed.hostname == "codeload.github.com" and
            parsed.username is None and parsed.password is None and
            parsed.port is None and not parsed.fragment and
            parsed.path.startswith("/" + REPO + "/") and
            parsed.path.endswith("/" + commit_sha),
            "Untrusted GitHub archive redirect")
    fd, tmp = tempfile.mkstemp(prefix=".cape-source-", dir=directory)
    size = 0
    try:
        with os.fdopen(fd, "wb") as dest:
            # Do not forward Authorization to the codeload origin.
            with urlopen(Request(url, headers={
                "User-Agent": "cape-verified-checkout",
            }), timeout=60) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= MAX_ARCHIVE, "Compressed archive too large")
                    dest.write(chunk)
            dest.flush()
            os.fsync(dest.fileno())
        return Path(tmp)
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise


def extract_verified(archive: Path, folder: Path, expected: dict) -> None:
    seen = set()
    root = None
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            require(member.name and len(member.name) < 1024,
                    "Unsafe archive member name")
            parts = PurePosixPath(member.name).parts
            require(len(parts) >= 1 and
                    member.name == str(PurePosixPath(member.name)) and
                    not PurePosixPath(member.name).is_absolute() and
                    all(p not in (".", "..", "") for p in parts),
                    "Archive path traversal")
            if root is None:
                root = parts[0]
            require(parts[0] == root, "Archive contains multiple roots")
            if len(parts) == 1:
                require(member.isdir(), "Unexpected archive root")
                continue
            relative = "/".join(parts[1:])
            destination = folder.joinpath(*parts[1:])
            if member.isdir():
                require(not destination.is_symlink(),
                        "Symlinked destination directory")
                destination.mkdir(parents=True, exist_ok=True)
                continue
            require(member.isfile() and relative in expected and
                    relative not in seen, "Unexpected or duplicate archive file")
            sha, expected_size, mode = expected[relative]
            require(member.size == expected_size and member.size <= 16 * 1024 * 1024,
                    "Archive size differs from pinned Git tree")
            total += member.size
            require(total <= MAX_EXTRACTED, "Too many extracted bytes")
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = tar.extractfile(member)
            require(stream is not None, "Cannot read archive file")
            content = stream.read(expected_size + 1)
            require(len(content) == expected_size and git_hash(content) == sha,
                    "Archive member hash differs from pinned Git object")
            with destination.open("xb") as out:
                out.write(content)
                out.flush()
                os.fsync(out.fileno())
            destination.chmod(0o755 if mode == "100755" else 0o644)
            seen.add(relative)
    require(seen == set(expected), "Incomplete pinned checkout")


def verified_parent(home: Path) -> Path:
    require(home.is_absolute() and home.is_dir() and not home.is_symlink(),
            "Expected absolute unsymlinked user home")
    require(home.stat().st_uid == os.geteuid(), "Home owner mismatch")
    root = home / ".local" / "share" / "cape-three-command"
    for part in (home / ".local", home / ".local" / "share", root):
        require(not part.is_symlink(), "Symlink in checkout destination")
        if not part.exists():
            part.mkdir(mode=0o700)
        require(part.is_dir() and part.stat().st_uid == os.geteuid(),
                "Checkout parent is not owned by the caller")
    os.chmod(root, 0o700)
    return root


def acquire(commit_sha: str, token: str, home: Path) -> Path:
    require(SHA40.fullmatch(commit_sha), "Unpinned Git revision")
    require(type(token) is str and 8 <= len(token) <= 500 and
            "\n" not in token and "\r" not in token,
            "Missing or invalid private GitHub access credential")
    entries = tree_entries(commit_sha, token)
    parent = verified_parent(home)
    target = parent / commit_sha
    require(not target.exists() and not target.is_symlink(),
            "Pinned checkout already exists; refuse to overwrite")
    workspace = Path(tempfile.mkdtemp(prefix=".checkout-", dir=parent))
    try:
        archive = archive_to_temp(commit_sha, token, workspace)
        extraction = workspace / "source"
        extraction.mkdir(mode=0o700)
        extract_verified(archive, extraction, entries)
        archive.unlink()
        # One filesystem and same parent: rename is atomic; no partial
        # checkout can become the final trusted directory.
        extraction.rename(target)
        os.rmdir(workspace)
        return target
    except Exception:
        shutil.rmtree(workspace)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    try:
        require(os.geteuid() != 0 and sys.stdin.isatty(),
                "Run on a local non-root interactive terminal")
        require(os.uname().machine == "x86_64",
                "Checkout only supported on x86_64")
        token = getpass.getpass("GitHub fine-grained read-only token: ")
        result = acquire(args.revision, token, Path.home())
        print(json.dumps({"result": "VERIFIED_PRIVATE_SOURCE_ONLY",
                          "path": str(result),
                          "sha": args.revision,
                          "CAPE_installed": False,
                          "VMs_modified": False}, sort_keys=True))
        return 0
    except (CheckoutBlocked, HTTPError, URLError, OSError, ValueError,
            tarfile.TarError, json.JSONDecodeError) as error:
        print(json.dumps({"result": "PRIVATE_CHECKOUT_BLOCKED",
                          "error_type": type(error).__name__,
                          "credentials_printed": False,
                          "no_installation_attempted": True}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
