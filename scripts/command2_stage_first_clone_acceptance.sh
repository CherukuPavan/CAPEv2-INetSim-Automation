#!/usr/bin/env bash
# SSL-55 acceptance drill for ONE shut-off, zero-NIC independent Windows clone.
# This is a gated Command 2A TEST, not the final bulk/connected Command 2.
set -Eeuo pipefail
umask 077
HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT="$HERE/command2_stage_independent_clones.py"
[[ -f "$SCRIPT" ]] || { echo "BLOCKED: Command2A Python script missing" >&2; exit 2; }
[[ -t 0 ]] || { echo "BLOCKED: interactive terminal required" >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_FirstClone_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "Report: $REPORT"
printf '%s\n' 'Stage 1/2: verifying resources, original snapshot and no-NIC trial...'
if ! sudo /usr/bin/python3 "$SCRIPT" --mode plan --count 1 >"$REPORT" 2>&1; then
  echo 'BLOCKED: Safe preflight did not pass; no clone was staged.'
  tail -n 35 "$REPORT"
  exit 2
fi
echo 'PASS: one-clone preflight accepted.'
echo 'One new independent file-backed Windows VM win11_1 will be DEFINED SHUT OFF'
echo 'with ZERO NICs, a new UUID/NVRAM and fresh per-domain TPM on first boot.'
echo 'Existing win11 and win11_trial_1 will not be modified, shut down, or restarted.'
echo 'No Windows personalization, NAT, firewall, snapshot or CAPE config changes.'
read -r -p 'Type STAGE-WIN11-1 to continue, otherwise abort safely: ' ACK
if [[ "$ACK" != "STAGE-WIN11-1" ]]; then
  echo 'ABORT: operator declined clone staging; plan-only report retained.'
  exit 2
fi
{
  echo
  echo '=== STAGE REQUESTED AFTER SUCCESSFUL PREFLIGHT ==='
} >>"$REPORT"
echo 'Stage 2/2: copying decrypted template; this may take several minutes...'
set +e
sudo /usr/bin/python3 "$SCRIPT" --mode stage --count 1 >>"$REPORT" 2>&1
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
  echo 'CAPE Command 2A first independent zero-NIC clone staged.'
else
  echo 'BLOCKED/PARTIAL: do not retry, delete files or start new VMs.'
fi
echo "Exit: $RC"
echo "Report: $REPORT"
tail -n 55 "$REPORT"
exit "$RC"
