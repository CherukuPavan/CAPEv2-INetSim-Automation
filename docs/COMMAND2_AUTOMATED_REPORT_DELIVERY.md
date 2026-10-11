# CAPE — automatic approved TXT report delivery (development, 2026-10-11)

**Operator request:** stop manually uploading every TXT report. Keep SSL-55
reference-only. No additional VMs, backups, malware analysis or firewall changes.

## The two connections are different

ChatGPT's connected Google Drive can **read** files already in Drive, but
does not mount or read the operator's Ubuntu `$HOME` automatically.
A local Ubuntu uploader must independently authorize its own Google
Drive upload connection, once.

The Ubuntu-side option here is `rclone` with Google Drive's **drive.file**
limited OAuth scope. It creates its own folder `CAPE_SSL55_AutoReports`
in the connected Google account. This is intentionally NOT the already
user-created `CAPE_SSL55_Reports` folder: the preexisting folder may not
be accessible to a newly authorized `drive.file` client. ChatGPT's
scheduled CAPE report watch searches only the two named private folders,
checking for new reports hourly. The watch is not instantaneous and may
fail if Drive authorization or scheduled connector access changes.

## One-time operator setup — no sudo daemon or remote terminal

1. Confirm the university authorizes syncing **non-sensitive,
   approved synthetic test logs** to this Google account.
2. If `rclone` is missing, ask the system administrator or explicitly
   authorize a local package installation. Do not use curl|bash.
3. In the SSL-55 Ubuntu terminal, run `rclone config` to create a new
   Google Drive remote named **cape_reports**. Choose storage
   **Google Drive**, scope **drive.file (files created by this app only)**,
   browser-based OAuth, and the same Google account connected to ChatGPT.
   Do not post OAuth codes, tokens or `rclone.conf` in chat.
4. Download `scripts/command2_upload_approved_reports.sh` and
   `scripts/command2_setup_auto_report_sync.sh` from an exact
   reviewed `development` commit with SHA verification, then run
   the setup script as the **ordinary user** (never sudo).
   It asks for the confirmation phrase
   `ENABLE-CAPE-AUTO-REPORTS` once.
5. Setup creates private folder `~/CAPE_Approved_Reports`, copies only
   earlier allowlisted small offline test logs from $HOME, creates
   app-owned Drive folder `CAPE_SSL55_AutoReports` via rclone,
   installs a user-level systemd timer and user-only uploader, and
   starts the timer. It does **not** enable lingering or a root daemon.
6. New runs of the current `command2_target_host_preflight_offline_acceptance.sh`
   automatically use `~/CAPE_Approved_Reports` when it exists with
   the expected user owner and mode 700. The timer checks for eligible
   reports every roughly five minutes while the user manager is running.
   ChatGPT's scheduled watch checks new reports once per hour.
7. To stop automatically: `systemctl --user disable --now
   cape-approved-report-upload.timer`. Revoke the Ubuntu rclone OAuth
   grant in the Google account's third-party access settings if needed.
   This does not disconnect ChatGPT's separate Drive authorization.

## Fixed installer invocation block (2026-10-11)

Operator encountered `PASS: Setup scripts verified` followed by
`BLOCKED: run interactively` after pasting an outer `bash <<'BASH'`
wrapper. Root cause: shell heredocs are non-TTY stdin (`-t 0`
false), even when a human has an interactive controlling terminal.
Development installer now requires a real controlling terminal and
reads the explicit confirmation from `/dev/tty` rather than stdin.
Offline regression test asserts the distinction. This fixes the
launcher gate only: SSL-55 installation has NOT been performed,
and there is no automatic uploader/timer demonstrated running.

User explicitly requested that the assistant operate the Ubuntu CMD
without any further terminal copy/paste. In the current Chat
toolset only GitHub and connected Google Drive are directly
accessible; **no SSH/local Ubuntu terminal tool is connected**.
Do not claim a Google Drive connection confers local CLI control.
Do not suggest enabling passwordless sudo, exposing a host terminal
to the internet, or installing a self-hosted CI runner on SSL-55.
Only a separate explicitly authorized/supported computer-control
session or a one-time operator setup can change the user's host.

## Strict limitations

- Uploader only scans one user-owned mode-0700 local folder, without
  recursion. It transfers only
  `CAPE_Command2_OfflinePreflightTests_YYYYMMDD_HHMMSS_XXXXXXXX.txt`,
  where the final component is eight alphanumeric characters.
- Each TXT must be an owned regular file, not symlink, at most 256KiB,
  stable for more than one minute, and not contain obvious credential
  patterns (e.g. TPM OwnerAuth, recovery password, private key, token,
  API secret or password assignment).
- Uses `rclone copyto --immutable`: never delete local/Drive files or
  overwrite changed remote reports. The user-only uploader does NOT
  inspect VMs, invoke virsh/qemu-img, use sudo, install packages, add
  networks, or touch unrelated local folders. No source of malware,
  VM image, state blobs or Windows guest data is eligible.
- Only this approved OFFLINE test report family is automatically
  delivered initially. Host diagnostic reports containing topology,
  identities or TPM metadata must be reviewed and explicitly added to
  a sanitizer/allowlist first; do not auto-upload all *.txt files.
- `rclone` tokens are stored locally in the invoking user's config
  directory. Protect the local account and keep tokens out of GitHub,
  ChatGPT, TXT reports, screenshots and backups.
- User systemd timer runs only when the user service manager is active;
  full unattended operation across logouts is not configured.
- This setup AUTOMATES REPORT TRANSFER, not arbitrary ChatGPT command
  execution on Ubuntu. GitHub development remains on `development`.
  Do not claim the full three-command installer is complete.

## Offline tests and evidence

- `scripts/test_command2_upload_approved_reports.py` uses an in-memory
  fake rclone executable and synthetic TXT files to verify allowed
  transfer, secret rejection, symlink skip, missing remote refusal and
  Bash syntax; **no Google account and no actual host upload**.
- Actual uploader and scheduled Drive watch require separate first
  production acceptance: local timer state, a test TXT appearing in
  `CAPE_SSL55_AutoReports`, connector read success, hourly alert.
