#!/usr/bin/env python3
"""No-personal-OAuth, world-reachable private Drive reader for NEW hosts.

A separately obtained Google service-account JSON key must be placed on the
target as root:0600. Share ONLY the encrypted parent Drive folder with the
service account as Viewer. A root-owned reader config refers to that account,
and wraps its restricted Drive root with the same CRYPT passwords used to
upload the exact Windows golden-master bundle.

No public link, SSL55 LAN route, personal Google OAuth or copied personal
rclone.conf is required on the new target. This does NOT install CAPE,
import/start a VM, grant Drive permissions or certify snapshot rollback.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

DEFAULT_CONFIG = Path("/root/.config/rclone/cape_world_readonly.conf")
APPROVAL = "CREATE-PRIVATE-WORLDWIDE-CAPE-DRIVE-READER"
KEY_FILE_MAX_BYTES = 16 * 1024
FOLDER_ID = re.compile(r"[A-Za-z0-9_-]{10,128}\Z")


class ReaderBlocked(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise ReaderBlocked(message)


def secure_file(path, *, max_size=None):
    """Read a root-owned 0600 regular, singly linked, non-symlinked file."""
    path = Path(path)
    require(path.is_absolute(), "Absolute root-only path required")
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            "Symlinked credential path blocked")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and
                stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1,
                "Credential file must be root-owned regular 0600")
        require(max_size is None or 100 <= s.st_size <= max_size,
                "Unrecognized credential file size")
        data = os.read(fd, s.st_size + 1)
        require(len(data) == s.st_size, "Credential file changed during read")
    finally:
        os.close(fd)
    return data


def service_account_identity(path):
    try:
        key = json.loads(secure_file(path, max_size=KEY_FILE_MAX_BYTES))
    except (ValueError, UnicodeDecodeError) as e:
        raise ReaderBlocked("Invalid service account credential JSON") from e
    require(type(key) is dict and key.get("type") == "service_account" and
            type(key.get("client_email")) is str and
            re.fullmatch(
                r"[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com",
                key["client_email"]) is not None and
            type(key.get("private_key")) is str and
            key["private_key"].startswith("-----BEGIN PRIVATE KEY-----") and
            key.get("token_uri") == "https://oauth2.googleapis.com/token",
            "Expected a Google service-account JSON key")
    return key["client_email"]


def verify_inputs(args):
    require(os.geteuid() == 0, "Root required for private credentials")
    actual = socket.gethostname().split(".", 1)[0].lower()
    require(actual not in ("ssl-55", "cse-ssl-55") and
            actual == args.approved_host.lower().split(".", 1)[0],
            "Only an explicitly approved non-SSL55 target machine")
    require(FOLDER_ID.fullmatch(args.shared_parent_folder_id) is not None,
            "Expected Google Drive encrypted PARENT folder ID, not a URL")
    require(args.crypt_subfolder == "master-backups",
            "Only approved master-backups encrypted child folder allowed")
    # INI values must not be able to inject a new line/remote or escape the
    # protected root-only credential directory. Check BEFORE opening keys.
    for value in (str(args.service_account_file), str(args.config)):
        require(len(value) <= 256 and
                re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None and
                ".." not in Path(value).parts,
                "Unsafe credential/config path for rclone INI")
    key_parent = args.service_account_file.parent
    require(key_parent.is_dir() and key_parent.stat().st_uid == 0 and
            stat.S_IMODE(key_parent.stat().st_mode) == 0o700,
            "Service-account JSON parent must be root-owned 0700")
    email = service_account_identity(args.service_account_file)
    config = args.config
    require(config.is_absolute() and not any(
        p.is_symlink() for p in (config, *config.parents)),
        "Config file must have a non-symlink absolute path")
    require(not config.exists(), "Refusing to replace existing rclone config")
    parent = config.parent
    require(parent.is_dir() and parent.stat().st_uid == 0 and
            stat.S_IMODE(parent.stat().st_mode) == 0o700,
            "Existing config parent must be root-owned 0700")
    require(args.service_account_file.resolve() != config.resolve(),
            "Service account JSON must not be the rclone config")
    return {
        "result": "WORLDWIDE_PRIVATE_DRIVE_READER_PLAN_ONLY",
        "approved_target_host": actual,
        "service_account_email_to_share_with_as_viewer": email,
        "shared_encrypted_parent_folder_id": args.shared_parent_folder_id,
        "crypt_child_relative_path": args.crypt_subfolder,
        "config_to_create": str(config),
        "target_must_have_private_service_account_key": True,
        "operator_must_share_only_encrypted_parent_folder_as_viewer": True,
        "personal_google_login_on_target_required": False,
        "public_google_drive_link_required": False,
        "no_host_changes": True,
    }


def obscure(secret):
    require("\n" not in secret and "\r" not in secret and len(secret) >= 12,
            "Crypt secret must contain at least 12 characters, no newlines")
    try:
        p = subprocess.run(["rclone", "obscure", "-"], input=secret + "\n",
                           capture_output=True, text=True, timeout=15,
                           check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ReaderBlocked("Unable to invoke rclone obscure") from e
    encoded = p.stdout.strip()
    require(p.returncode == 0 and
            re.fullmatch(r"[A-Za-z0-9_-]{24,1000}", encoded),
            "rclone obscure failed; no config has been written")
    return encoded


def plan(args):
    return verify_inputs(args)


def setup(args):
    require(sys.stdin.isatty(), "Use a direct interactive root terminal")
    first = verify_inputs(args)
    print(json.dumps(first, sort_keys=True, indent=2), flush=True)
    require(input("Type " + APPROVAL + ": ").strip() == APPROVAL,
            "Operator did not approve new private reader")
    require(verify_inputs(args) == first,
            "Key, Drive scope or target path changed after approval")
    password = getpass.getpass(
        "Existing source rclone CRYPT password (not Google password): ")
    repeated = getpass.getpass("Repeat existing CRYPT password: ")
    require(password == repeated, "Crypt password confirmation mismatch")
    pw = obscure(password)
    # Salt is optional but MUST match the exact source configuration.
    salt = getpass.getpass(
        "Existing crypt salt password2 (Enter ONLY if source has none): ")
    pw2 = obscure(salt) if salt else None
    lines = [
        "[cape_drive]",
        "type = drive",
        "scope = drive.readonly",
        "service_account_file = " + str(args.service_account_file),
        "root_folder_id = " + args.shared_parent_folder_id,
        "team_drive =",
        "",
        "[cape_crypt]",
        "type = crypt",
        "remote = cape_drive:" + args.crypt_subfolder,
        "filename_encryption = standard",
        "directory_name_encryption = true",
        "password = " + pw,
    ]
    if pw2 is not None:
        lines.append("password2 = " + pw2)
    lines.append("")
    require(verify_inputs(args) == first,
            "Source or destination changed before creation")
    fd = os.open(args.config,
                 os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    # A failed write retains partial private state for inspection;
    # never blindly overwrite/delete root secrets.
    with os.fdopen(fd, "wb") as out:
        out.write(("\n".join(lines)).encode("utf-8"))
        out.flush()
        os.fchmod(out.fileno(), 0o600)
        os.fsync(out.fileno())
    parent_fd = os.open(args.config.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return {
        "result": "WORLDWIDE_PRIVATE_DRIVE_READER_CONFIG_CREATED",
        "read_only_service_account": True,
        "scope": "drive.readonly",
        "config": str(args.config),
        "no_personal_google_login_used_on_target": True,
        "folder_acl_not_independently_verified": True,
        "remote_decryption_not_yet_verified": True,
        "next": "Use --rclone-config with command1_private_drive_bundle plan-download",
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("plan", "setup"), default="plan")
    p.add_argument("--approved-host", required=True)
    p.add_argument("--service-account-file", type=Path, required=True)
    p.add_argument("--shared-parent-folder-id", required=True)
    p.add_argument("--crypt-subfolder", default="master-backups")
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = p.parse_args()
    try:
        result = plan(args) if args.mode == "plan" else setup(args)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except Exception as e:
        print(json.dumps({
            "result": "WORLDWIDE_READER_BLOCKED_OR_PARTIAL",
            "error_type": type(e).__name__,
            "never_share_credentials_or_config": True,
            "do_not_retry_over_existing_config": True,
        }), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
