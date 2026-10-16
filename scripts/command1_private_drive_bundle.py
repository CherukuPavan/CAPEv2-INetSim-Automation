#!/usr/bin/env python3
"""Private Google Drive transport of the EXACT cold Windows golden bundle.

Uses rclone's client-side CRYPT backend: no second encrypted archive or
duplicate 64-GiB plaintext staging copy required for uploading. Only a
root-private rclone config with one crypt remote wrapping ONE personal Drive
remote is accepted. Crypt encrypts file contents and filenames before
upload; raw personal Drive remotes are NEVER used directly by this program.

TRANSFER-UPLOAD: verify actual offline Windows bundle manifest/hashes,
copy --immutable to the private encrypted remote, then rclone check
--download --one-way to byte-check decrypted remote contents. Re-verify
local bundle afterwards. This may reread/download large data.
TRANSFER-DOWNLOAD: require a NEW root-private cape-master-* destination
under a trusted root-owned parent; inspect remote object count/size, check
host storage, copy remote crypt -> private local folder, and SHA-verify
the canonical exact source master manifest. Do not import/start any VM.
Failures leave partial folders for review rather than deleting/retrying.

Root and named-host approval mandatory for mutations. Auth/passwords are
never output or committed. User must separately configure personal Google
Drive OAuth + crypt passphrase (and back up the crypt config/password) on
each host. Password 'obscure' alone in rclone.conf is not encryption.
Network/Drive ownership or sharing permissions are not established here.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys

import command1_export_existing_master as master

DEFAULT_RCLONE_CONFIG = Path("/root/.config/rclone/rclone.conf")
MAX_CONFIG = 256 * 1024
MIN_RESERVE = 15 * 1024**3
APPROVE_UPLOAD = "UPLOAD-PRIVATE-ENCRYPTED-EXACT-WIN11-MASTER"
APPROVE_DOWNLOAD = "DOWNLOAD-PRIVATE-EXACT-WIN11-MASTER-NEW-HOST"

class TransferBlocked(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise TransferBlocked(why)

def verify_host(host, *, upload):
    requested = host.lower().split(".", 1)[0]
    actual = socket.gethostname().lower().split(".", 1)[0]
    need(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", requested or "") and
         requested == actual,
         "Explicit --approved-host must equal actual host name")
    if not upload:
        need(actual not in ("ssl-55", "cse-ssl-55") and
             not master.SENTINEL.exists(),
             "Never import/download master onto its protected SSL-55 source")
    return actual

def transfer_remote(remote, bundle_id):
    need(type(remote) is str and
         re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,48}", remote or "") and
         type(bundle_id) is str and
         re.fullmatch(r"cape-master-[A-Za-z0-9_-]{4,72}", bundle_id or ""),
         "Crypt remote and cape-master-* bundle id must have safe names")
    return remote + ":" + bundle_id

def read_crypt_settings(config_file, remote):
    """Inspect credentials metadata, never show rclone token/password."""
    p = Path(config_file)
    need(p.is_absolute(), "Rclone config path must be absolute")
    need(not any(x.is_symlink() for x in (p, *p.parents)),
         "Symlinked rclone.conf path denied")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
             stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
             50 <= st.st_size <= MAX_CONFIG,
             "Rclone config must be existing root-owned 0600 file")
        data = os.read(fd, MAX_CONFIG + 1)
        need(len(data) == st.st_size, "Rclone config changed while reading")
    finally:
        os.close(fd)
    try:
        data = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransferBlocked("Invalid UTF8 rclone configuration") from exc
    c = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        c.read_string(data)
    except configparser.Error as exc:
        raise TransferBlocked("Invalid rclone configuration structure") from exc
    need(remote in c and c[remote].get("type") == "crypt",
         "Remote MUST be an existing encrypted rclone crypt remote")
    crypt = c[remote]
    need(crypt.get("password") not in (None, "") and
         crypt.get("no_data_encryption", "false").lower() in ("false","no","0") and
         crypt.get("pass_bad_blocks", "false").lower() in ("false","no","0") and
         crypt.get("filename_encryption", "standard") == "standard" and
         crypt.get("directory_name_encryption", "true").lower() in
         ("true", "yes", "1"),
         "Crypt remote must encrypt data AND names; disable pass_bad_blocks")
    underlying = crypt.get("remote", "")
    match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]{1,48}):(.+)", underlying)
    need(match is not None and match.group(1) != remote and
         ".." not in Path(match.group(2)).parts and
         not match.group(2).startswith("/") and
         re.fullmatch(r"[A-Za-z0-9_./-]{4,200}", match.group(2)),
         "Crypt remote must wrap a dedicated named subfolder")
    base = match.group(1)
    need(base in c and c[base].get("type") == "drive" and
         not c[base].get("team_drive") and
         not c[base].get("shared_drive"),
         "Crypt must wrap a personal Google Drive remote (not team drive)")
    # This is a structural check, not a claim about Drive folder ACLs.
    return {
        # Bind operator approval to the exact OAuth+crypt config bytes
        # WITHOUT disclosing the token or obscured crypt passphrase.
        "rclone_config_sha256": hashlib.sha256(
            data.encode("utf-8")).hexdigest(),
        "crypt_remote": remote,
        "underlying_provider": "personal_google_drive",
        "crypt_content_and_names_enabled": True,
        "raw_drive_upload_prohibited": True,
        "oauth_and_passphrase_not_output": True,
        "drive_folder_privacy_not_verified": True,
    }

def execute_rclone(config, *cmd, download_limit_hours=12):
    """Suppress untrusted CLI output; no accidental token or TPM data logs."""
    argv=["rclone","--config",str(config),*cmd]
    try:
        result=subprocess.run(argv, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,check=False,
                              timeout=3600*download_limit_hours)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TransferBlocked("rclone transfer/check unavailable or timed out;"
                              " review root-private source/destination") from exc
    need(result.returncode == 0,
         "rclone transfer/check returned nonzero; review private transfer; "
         "never fall back to an unencrypted Drive remote")

def rclone_remote_size(config, target):
    try:
        p=subprocess.run(["rclone","--config",str(config),"size",target,
                          "--json"], capture_output=True,text=True,
                         check=False,timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TransferBlocked("Unable to inspect private encrypted Drive size") from exc
    need(p.returncode == 0 and len(p.stdout) < 65536,
         "Private encrypted Drive bundle does not exist or is unavailable")
    try:
        data=json.loads(p.stdout)
    except json.JSONDecodeError as exc:
        raise TransferBlocked("Unrecognized rclone size response") from exc
    need(type(data.get("count")) is int and
         type(data.get("bytes")) is int and
         5 <= data["count"] <= 30 and
         data["bytes"] > 4096,
         "Encrypted golden bundle file count/size not plausible")
    return data["count"], data["bytes"]

def checked_destination(dest, total_bytes):
    path=Path(dest)
    need(path.is_absolute() and
         re.fullmatch(r"cape-master-[A-Za-z0-9_-]{4,72}",path.name or "") and
         not path.exists() and not path.is_symlink(),
         "Destination must be NEW root-private cape-master-* folder")
    for item in (path.parent, *path.parent.parents):
        need(not item.is_symlink(), "Symlinked destination parent path")
    need(path.parent.is_dir(), "Existing trusted destination parent required")
    owner=path.parent.stat()
    need(owner.st_uid == 0 and not owner.st_mode & 0o022,
         "Destination parent must be root-owned not writable by others")
    available=os.statvfs(path.parent)
    free=available.f_bavail*available.f_frsize
    need(free > total_bytes + MIN_RESERVE,
         "Not enough disk space for exact downloaded master plus reserve")
    return path

def plan_upload(host, bundle, remote, config):
    verify_host(host,upload=True)
    directory=Path(bundle)
    need(directory.name.startswith("cape-master-"),
         "Only actual cape-master-* export directories allowed")
    secret=read_crypt_settings(config,remote)
    proof=master.manifest_check(directory)
    need(proof.get("all_member_files_sha256_verified") is True,
         "Exact master export predates SHA256-bound capture intent; "
         "do not claim full byte verification")
    return {
        "result":"COMMAND1_PRIVATE_CRYPT_GDRIVE_UPLOAD_PLAN_ONLY",
        "source_bundle":str(directory),
        "remote":transfer_remote(remote,directory.name),
        "bundle_proof":proof,
        "encryption":secret,
        "host_modified":False,"Drive_uploaded":False,
        "no_plaintext_public_access":True,
        "requires_private_Drive_OAuth_and_crypt_password_setup":True,
    }

def plan_download(host, dest, remote, bundle_id, config):
    verify_host(host,upload=False)
    secret=read_crypt_settings(config,remote)
    target=transfer_remote(remote,bundle_id)
    count,total=rclone_remote_size(config,target)
    local=checked_destination(dest,total)
    return {
        "result":"COMMAND1_PRIVATE_CRYPT_GDRIVE_DOWNLOAD_PLAN_ONLY",
        "download_path":str(local), "remote":target,
        "expected_file_count":count,"expected_plaintext_bytes":total,
        "encryption":secret, "host_modified":False,
        "bundle_decrypted_on_private_host":False,
        "manifest_must_be_verified_after_download":True,
    }

def apply_upload(host,bundle,remote,config):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root direct terminal and explicit consent required")
    first=plan_upload(host,bundle,remote,config)
    print(json.dumps(first,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVE_UPLOAD+" to transfer PRIVATE crypt bundle: ")
         == APPROVE_UPLOAD,"Operator declined private encrypted upload")
    need(plan_upload(host,bundle,remote,config)==first,
         "Source bundle/config changed after approval")
    # This uses the crypt remote, not the unencrypted personal Drive name.
    execute_rclone(config,"copy","--immutable","--transfers","1",
                   "--checkers","1",str(bundle),first["remote"])
    execute_rclone(config,"check","--download","--one-way",
                   str(bundle),first["remote"])
    after=plan_upload(host,bundle,remote,config)
    need(after==first, "Master bundle changed while uploading; STOP")
    return {
        "result":"COMMAND1_PRIVATE_CRYPT_GDRIVE_UPLOAD_CHECKED",
        "encrypted_in_remote":True,
        "client_side_file_content_and_names_encrypted":True,
        "download_compare_performed":True,
        "source_master_VM_untouched":True,
        "guest_swtpm_secrets_not_uploaded_plaintext":True,
        "physical_new_host_import_not_yet_verified":True,
        "remote":first["remote"],
    }

def apply_download(host,dest,remote,bundle_id,config,expected_manifest_sha256=None):
    need(os.geteuid()==0 and sys.stdin.isatty(),
         "Root direct terminal and explicit consent required")
    if expected_manifest_sha256 is not None:
        need(type(expected_manifest_sha256) is str and
             re.fullmatch(r"[0-9a-f]{64}",expected_manifest_sha256) is not None,
             "Expected independently attested manifest must be lowercase SHA256")
    first=plan_download(host,dest,remote,bundle_id,config)
    print(json.dumps(first,sort_keys=True,indent=2),flush=True)
    need(input("Type "+APPROVE_DOWNLOAD+" for private new-host download: ")
         == APPROVE_DOWNLOAD,"Operator declined private encrypted download")
    need(plan_download(host,dest,remote,bundle_id,config)==first,
         "Target/disk/Drive changed after approval")
    folder=Path(dest)
    folder.mkdir(mode=0o700)
    # Any interruption leaves an explicit private partial directory.
    # Do NOT delete or blindly retry an incomplete exact-master download.
    try:
        execute_rclone(config,"copy","--immutable","--transfers","1",
                       "--checkers","1",first["remote"],str(folder))
        proof=master.manifest_check(folder)
        need(proof.get("all_member_files_sha256_verified") is True,
             "Private golden bundle lacks all-member SHA256 manifest proof")
        need(expected_manifest_sha256 is None or
             proof.get("manifest_sha256") == expected_manifest_sha256,
             "Downloaded master manifest differs from independent SSL46 SHA256")
        need(len(list(folder.iterdir()))==first["expected_file_count"],
             "Downloaded bundle count differs from remote inventory")
    except Exception as exc:
        raise TransferBlocked(
            "PARTIAL_OR_UNKNOWN: encrypted download was started; "
            "preserve root-private destination for manual review; "
            "no automatic retry/overwrite: "+type(exc).__name__) from None
    return {
        "result":"COMMAND1_PRIVATE_MASTER_DOWNLOADED_SHA256_VERIFIED",
        "private_bundle_path":str(folder),
        "bundle_manifest_sha256":proof["manifest_sha256"],
        "independently_attested_manifest_pinned":
            expected_manifest_sha256 is not None,
        "all_member_files_sha256_verified":True,
        "master_windows_disk_and_tpm_verified":True,
        "master_VM_imported":False,"master_running_snapshot_created":False,
        "Drive_remote_encrypted":True,
        "host_VM_or_network_modified":False,
    }

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("plan-upload","upload",
                                     "plan-download","download"),required=True)
    p.add_argument("--approved-host",required=True)
    p.add_argument("--bundle",type=Path)
    p.add_argument("--destination",type=Path)
    p.add_argument("--crypt-remote",required=True)
    p.add_argument("--bundle-id")
    p.add_argument("--expected-manifest-sha256")
    p.add_argument("--rclone-config",type=Path,default=DEFAULT_RCLONE_CONFIG)
    a=p.parse_args()
    try:
        if a.mode.endswith("upload"):
            need(a.bundle is not None and a.destination is None and
                 a.bundle_id is None,"Upload needs bundle, not destination/id")
            result=(plan_upload(a.approved_host,a.bundle,a.crypt_remote,
                                a.rclone_config)
                    if a.mode=="plan-upload" else
                    apply_upload(a.approved_host,a.bundle,a.crypt_remote,
                                 a.rclone_config))
        else:
            need(a.destination is not None and a.bundle_id and
                 a.bundle is None,"Download needs new destination/bundle-id")
            result=(plan_download(a.approved_host,a.destination,a.crypt_remote,
                                  a.bundle_id,a.rclone_config)
                    if a.mode=="plan-download" else
                    apply_download(a.approved_host,a.destination,a.crypt_remote,
                                   a.bundle_id,a.rclone_config,
                                   a.expected_manifest_sha256))
        print(json.dumps(result,sort_keys=True,indent=2),flush=True)
        return 0
    except (TransferBlocked,master.MasterExportBlocked,ValueError,
            OSError,TypeError) as exc:
        print(json.dumps({"result":"COMMAND1_PRIVATE_CRYPT_TRANSFER_BLOCKED",
                          "error_type":type(exc).__name__,
                          "not_safe_to_auto_retry_partial_transfer":True,
                          "never_send_rclone_conf_to_GitHub_or_chat":True},
                         sort_keys=True),file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
