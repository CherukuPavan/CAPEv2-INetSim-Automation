#!/usr/bin/env bash
# Command 2A: ONE TXT report for read-only cold-checkpoint feasibility.
# Never shuts down guest, reads live qcow2 content, or writes a checkpoint.
set -Eeuo pipefail
umask 077
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
AUDIT="$HERE/command2_cold_checkpoint.py"
[[ -f "$AUDIT" && ! -L "$AUDIT" ]] || { echo 'BLOCKED: checkpoint module missing/symlink' >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_ColdCheckpointPlan_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "REPORT: $REPORT"
set +e
sudo -n /usr/bin/python3 -B "$AUDIT" --mode plan >"$REPORT" 2>&1
RESULT=$?
set -e
tail -n 75 "$REPORT" || true
echo "EXIT: $RESULT"
echo "REPORT: $REPORT"
if [[ "$RESULT" == 0 ]]; then
  echo 'READ-ONLY PLAN: no VM shutdown, checkpoint, restore, IP or networking authorized.'
else
  echo 'BLOCKED: report requires engineering review; no retry or host changes.'
fi
exit "$RESULT"
