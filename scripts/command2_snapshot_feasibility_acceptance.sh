#!/usr/bin/env bash
# SSL-55 guarded one-report snapshot feasibility inventory (NO snapshot).
# Does not touch VM power state, storage content, libvirt configuration,
# Windows guests, swtpm files, host firewall or networking.
set -Eeuo pipefail
umask 077
[[ -t 0 ]] || { echo 'BLOCKED: Interactive SSL-55 terminal required' >&2; exit 2; }
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT="$HERE/command2_snapshot_feasibility_audit.py"
[[ -f "$SCRIPT" && ! -L "$SCRIPT" ]] || { echo 'BLOCKED: Audit module missing/symlink' >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_SnapshotFeasibility_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
printf 'REPORT: %s\n' "$REPORT"
set +e
sudo -n /usr/bin/python3 "$SCRIPT" >"$REPORT" 2>&1
STATUS=$?
set -e
printf 'EXIT: %s\nREPORT: %s\n' "$STATUS" "$REPORT"
tail -n 65 "$REPORT" || true
if [[ "$STATUS" != 0 ]]; then
  echo 'BLOCKED: Leave guests, disks, swtpm and networks untouched until report review.'
else
  echo 'AUDIT ONLY: No snapshot, backup, clone or egress permission granted.'
fi
exit "$STATUS"
