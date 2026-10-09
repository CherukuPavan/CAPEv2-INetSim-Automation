#!/usr/bin/env bash
# Narrow, guarded repair of the swtpm-localca directory ownership seen on SSL-55.
# No recursive chmod/chown; no deletion; no vm/service restart; no AppArmor edits.
# --plan is default. --apply requires exact observed initial metadata + EMPTY dir.
set -u
umask 077
MODE=plan
GUEST=win11
usage() {
  cat <<'HELP'
Usage: bash scripts/repair_swtpm_localca_owner.sh [--plan|--apply] [--vm NAME]
--plan: inspect current local CA directory state without changing it.
--apply: only if shutoff VM, directory is REAL/EMPTY and exact swtpm:root:750,
         chown --no-dereference tss:root /var/lib/swtpm-localca (NONRECURSIVE).
         Keeps current 750 mode. Does not execute swtpm_setup or boot VM.
If the directory is populated/has a symlink, refuse rather than modifying CA.
This narrow remedy is for a specific evidenced swtpm_localca failure:
"Need read/write rights on statedir /var/lib/swtpm-localca for user tss."
HELP
}
while (($#)); do
  case "$1" in
    --plan) MODE=plan; shift ;;
    --apply) MODE=apply; shift ;;
    --vm)
      (($#>=2)) || { usage >&2; exit 2; }
      GUEST=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
if [[ ! "$GUEST" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$GUEST" == .* ]]; then
  echo "Refusing invalid VM name." >&2
  exit 2
fi
DIR=/var/lib/swtpm-localca
REPORT=$(mktemp "${HOME:?}/SSL_swtpm_LocalCA_${MODE}_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1

(
  set -euo pipefail
  echo "========== SAFE SWTPM LOCAL CA OWNERSHIP CORRECTION =========="
  echo "Mode=$MODE, VM=$GUEST, directory=$DIR"
  echo "No recursive ownership change, no file deletion, no service restart."

  command -v sudo >/dev/null || { echo "BLOCKED: sudo unavailable"; exit 2; }
  sudo -v || { echo "BLOCKED: sudo unavailable to current user"; exit 2; }
  command -v virsh >/dev/null || { echo "BLOCKED: virsh unavailable"; exit 2; }
  getent passwd tss >/dev/null || { echo "BLOCKED: tss user missing"; exit 2; }
  getent passwd swtpm >/dev/null || { echo "BLOCKED: swtpm baseline user missing"; exit 2; }

  guest_state=$(virsh -c qemu:///system domstate "$GUEST")
  echo "VM state: $guest_state"
  [[ "$guest_state" == "shut off" ]] || {
    echo "BLOCKED: VM must be completely shut off."; exit 3;
  }

  if sudo test -L "$DIR" || ! sudo test -d "$DIR"; then
    echo "BLOCKED: CA statedir missing, symlinked, or not a directory."
    exit 3
  fi
  state=$(sudo stat -c '%U:%G:%a' -- "$DIR")
  echo "CA statedir: owner:group:mode=$state"
  contents=$(sudo find "$DIR" -mindepth 1 -maxdepth 1 -print -quit)
  [[ -z "$contents" ]] || {
    echo "BLOCKED: CA statedir contains data; protect existing CA and VMs."; exit 3;
  }
  echo "CA statedir: EMPTY (including hidden entries)"

  if [[ "$state" == "tss:root:750" ]]; then
    echo "Already corrected; no action needed."
  elif [[ "$state" == "swtpm:root:750" ]]; then
    if [[ "$MODE" == "apply" ]]; then
      echo "Applying exact, non-recursive ownership correction."
      sudo chown --no-dereference tss:root -- "$DIR"
    else
      echo "PLAN: would change only directory owner swtpm -> tss."
      echo "PLAN: would preserve group root and mode 750."
      echo "Run --apply only after reviewing the host-specific evidence."
      exit 0
    fi
  else
    echo "BLOCKED: ownership/mode differs from observed baseline. No changes."
    exit 3
  fi

  echo "Verify ownership and user access:"
  final=$(sudo stat -c '%U:%G:%a' -- "$DIR")
  echo "CA statedir after: $final"
  [[ "$final" == "tss:root:750" ]] || {
    echo "BLOCKED: unexpected postcondition"; exit 4;
  }
  for flag in r w x; do
    if sudo -n -u tss test "-$flag" "$DIR"; then
      echo "tss $flag: PASS"
    else
      echo "tss $flag: FAIL"
      exit 4
    fi
  done
  echo "PASS: expected service-account CA statedir access."
  echo "Not proof TPM starts; verify by supervised guest boot separately."
) > "$REPORT" 2>&1
status=$?
echo "Private report: $REPORT"
echo "Exit status: $status"
exit "$status"
