#!/usr/bin/env bash
# ONE-TIME user-only installer for limited automatic CAPE report uploads.
# Needs an already authenticated cape_reports rclone Drive remote.
# Creates ~/.local/libexec/cape script and systemd --user timer only.
set -Eeuo pipefail
umask 077
[[ -t 0 ]] || { echo 'BLOCKED: run interactively' >&2; exit 2; }
[[ "$(id -u)" -ne 0 ]] || { echo 'BLOCKED: do not run as root' >&2; exit 2; }
command -v rclone >/dev/null || { echo 'BLOCKED: install rclone first'; exit 2; }
command -v systemctl >/dev/null || { echo 'BLOCKED: systemctl missing'; exit 2; }
rclone listremotes 2>/dev/null | grep -Fxq 'cape_reports:' || {
 echo 'BLOCKED: first configure rclone remote named cape_reports with Google Drive drive.file scope'
 exit 2
}
SOURCE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)/command2_upload_approved_reports.sh"
[[ -f "$SOURCE" && ! -L "$SOURCE" ]] || { echo 'BLOCKED: sibling uploader missing'; exit 2; }
read -r -p 'Type ENABLE-CAPE-AUTO-REPORTS to activate approved TXT-only uploads: ' ACK
[[ "$ACK" == 'ENABLE-CAPE-AUTO-REPORTS' ]] || {
  echo 'No changes made'; exit 2;
}
FOLDER="$HOME/CAPE_Approved_Reports"
if [[ -e "$FOLDER" || -L "$FOLDER" ]]; then
  [[ -d "$FOLDER" && ! -L "$FOLDER" ]] || { echo 'BLOCKED: report folder conflict'; exit 2; }
  [[ "$(stat -c '%u' "$FOLDER")" == "$(id -u)" ]] || { echo 'BLOCKED: wrong owner'; exit 2; }
else
  mkdir -m 700 "$FOLDER"
fi
chmod 700 "$FOLDER"
mkdir -p "$HOME/.local/libexec/cape" "$HOME/.config/systemd/user"
DEST="$HOME/.local/libexec/cape/command2_upload_approved_reports.sh"
UNIT="$HOME/.config/systemd/user/cape-approved-report-upload.service"
TIMER="$HOME/.config/systemd/user/cape-approved-report-upload.timer"
for target in "$DEST" "$UNIT" "$TIMER"; do
  [[ ! -L "$target" ]] || { echo 'BLOCKED: symlink in service destination'; exit 2; }
  [[ ! -e "$target" ]] || { echo "BLOCKED: existing service file: $target"; exit 2; }
done
# rclone creates this folder using limited drive.file OAuth.
# No complete Drive-wide access is needed for this app-created folder.
rclone mkdir cape_reports:CAPE_SSL55_AutoReports
# One-time limited backfill of existing approved offline test reports.
# The uploader performs the actual secret-content inspection before transfer.
for FILE in "$HOME"/CAPE_Command2_OfflinePreflightTests_*.txt; do
  [[ -f "$FILE" && ! -L "$FILE" ]] || continue
  NAME="${FILE##*/}"
  [[ "$NAME" =~ ^CAPE_Command2_OfflinePreflightTests_[0-9]{8}_[0-9]{6}_[A-Za-z0-9]{8}\.txt$ ]] || continue
  [[ "$(stat -c '%u' -- "$FILE")" == "$(id -u)" ]] || continue
  [[ "$(wc -c < "$FILE")" -le 262144 ]] || continue
  [[ -e "$FOLDER/$NAME" || -L "$FOLDER/$NAME" ]] && continue
  install -m 0600 "$FILE" "$FOLDER/$NAME"
done
install -m 0700 "$SOURCE" "$DEST"
cat > "$UNIT" <<'EOF'
[Unit]
Description=Upload only approved CAPE offline TXT reports (no sudo)

[Service]
Type=oneshot
ExecStart=/bin/bash %h/.local/libexec/cape/command2_upload_approved_reports.sh
Nice=10
NoNewPrivileges=yes
EOF
cat > "$TIMER" <<'EOF'
[Unit]
Description=Check for approved CAPE offline TXT reports every five minutes

[Timer]
OnStartupSec=2min
OnUnitInactiveSec=5min
Unit=cape-approved-report-upload.service

[Install]
WantedBy=timers.target
EOF
chmod 600 "$UNIT" "$TIMER"
systemctl --user daemon-reload
systemctl --user enable --now cape-approved-report-upload.timer
echo 'PASS: User-only auto-upload enabled. No VMs, firewall or root services changed.'
echo 'Allowed local folder: '"$FOLDER"
echo 'Drive destination: CAPE_SSL55_AutoReports (rclone drive.file scope)'
echo 'Check user timer: systemctl --user list-timers cape-approved-report-upload.timer'
