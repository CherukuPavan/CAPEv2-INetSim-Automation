#!/usr/bin/env bash
# Only allowlisted, small synthetic test reports. No sudo or VM access.
set -Eeuo pipefail
umask 077
export LC_ALL=C
TARGET='cape_reports:CAPE_SSL55_AutoReports'
INPUT="$HOME/CAPE_Approved_Reports"
[[ -d "$INPUT" && ! -L "$INPUT" ]] || { echo "BLOCKED: directory missing/linked"; exit 2; }
[[ "$(stat -c '%u' -- "$INPUT")" == "$(id -u)" ]] || { echo "BLOCKED: owner"; exit 2; }
[[ "$(stat -c '%a' -- "$INPUT")" == "700" ]] || { echo "BLOCKED: permissions"; exit 2; }
command -v rclone >/dev/null || { echo "BLOCKED: rclone missing"; exit 2; }
rclone listremotes 2>/dev/null | grep -Fxq 'cape_reports:' || {
  echo "BLOCKED: expected Drive rclone remote not configured"; exit 2;
}
FAILED=0
SENT=0
while IFS= read -r -d '' FILE; do
  NAME="${FILE##*/}"
  [[ "$NAME" =~ ^CAPE_Command2_OfflinePreflightTests_[0-9]{8}_[0-9]{6}_[A-Za-z0-9]{8}\.txt$ ]] || continue
  [[ -f "$FILE" && ! -L "$FILE" ]] || { FAILED=$((FAILED+1)); continue; }
  [[ "$(stat -c '%u' -- "$FILE")" == "$(id -u)" ]] || { FAILED=$((FAILED+1)); continue; }
  [[ "$(wc -c < "$FILE")" -le 262144 ]] || { FAILED=$((FAILED+1)); continue; }
  # Do not transmit known secret-bearing report patterns.
  if grep -aEqi '(OwnerAuth|BEGIN [A-Z ]*PRIVATE KEY|BitLocker Recovery Password|client_secret|api[_-]?key[[:space:]]*[:=]|password[[:space:]]*[:=]|access_token)' "$FILE"; then
    echo "SKIP_POSSIBLE_SECRET: $NAME"
    FAILED=$((FAILED+1))
    continue
  fi
  # No deletion, no overwriting differing existing Drive files.
  if rclone copyto "$FILE" "$TARGET/$NAME" --immutable \
       --checkers 1 --transfers 1 --retries 2 --log-level ERROR; then
    SENT=$((SENT+1))
  else
    echo "FAILED_UPLOAD: $NAME"
    FAILED=$((FAILED+1))
  fi
done < <(find "$INPUT" -maxdepth 1 -type f \
  -name 'CAPE_Command2_OfflinePreflightTests_*.txt' \
  -size -256k -mmin +1 -print0)
echo "CAPE_AUTO_REPORT_SYNC: checked=$((SENT+FAILED)) failures=$FAILED"
[[ "$FAILED" == 0 ]]
