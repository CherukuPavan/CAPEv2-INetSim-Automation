#!/usr/bin/env bash
# Narrow reversible workaround for known libvirt virt-aa-helper /var/run -> /run
# generated AppArmor rule mismatch. On SSL-55 the static libvirt-qemu abstraction
# contains "include if exists <abstractions/libvirt-qemu.d>".
#
# --plan (default): no changes.
# --apply: add only an allow rule for the win11 swtpm socket under the verified
# included directory. No global disablement or service restart.
# This policy inclusion is shared across guest profiles, but the added rule
# matches only filenames ending in -win11-swtpm.sock. Only one VM is allowed.
set -euo pipefail
umask 077

MODE=plan
case "${1:---plan}" in
  --plan) MODE=plan ;;
  --apply) MODE=apply ;;
  -h|--help)
    printf 'Usage: bash %s [--plan|--apply]\n' "$0"
    exit 0 ;;
  *) echo "Invalid argument (use --plan or --apply)" >&2; exit 2 ;;
esac
(( $# <= 1 )) || { echo 'Too many arguments' >&2; exit 2; }
[[ $EUID -ne 0 ]] || { echo 'Run as regular user; sudo is scoped.' >&2; exit 2; }
sudo -v

DIR=/etc/apparmor.d/abstractions/libvirt-qemu.d
BASE=/etc/apparmor.d/abstractions/libvirt-qemu
POLICY=$DIR/90-cape-win11-swtpm
RULE='  /run/libvirt/qemu/swtpm/*-win11-swtpm.sock rw,'
REPORT=$(mktemp "${HOME:?}/SSL55_Step12P_AppArmor_${MODE}_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")

set +e
(
  set -euo pipefail
  echo "========== WIN11 SWTPM APPARMOR LOCAL RULE =========="
  echo "Mode: $MODE"
  echo "Virtual domain: win11"
  echo "Target: $POLICY"
  state=$(virsh -c qemu:///system domstate win11)
  echo "win11 state: $state"
  [[ "$state" == 'shut off' ]] || { echo 'BLOCKED: win11 must be shut off'; exit 3; }

  mapfile -t names < <(virsh -c qemu:///system list --all --name | sed '/^[[:space:]]*$/d')
  [[ ${#names[@]} -eq 1 && "${names[0]}" == win11 ]] || {
    echo "BLOCKED: Expected only win11 on this libvirt system."; exit 3;
  }
  sudo test -f "$BASE" && ! sudo test -L "$BASE" || {
    echo "BLOCKED: Original AppArmor abstraction missing or symlinked."; exit 3;
  }
  sudo grep -Eq '^[[:space:]]*include[[:space:]]+if[[:space:]]+exists[[:space:]]+<abstractions/libvirt-qemu\.d>[[:space:]]*$' "$BASE" || {
    echo "BLOCKED: Expected Step12O directory include not present."; exit 3;
  }
  if sudo test -L "$DIR"; then
    echo "BLOCKED: include path is a symlink."; exit 3
  fi
  if sudo test -e "$DIR" && ! sudo test -d "$DIR"; then
    echo "BLOCKED: include path is not a directory."; exit 3
  fi
  if sudo test -e "$POLICY" || sudo test -L "$POLICY"; then
    if sudo test -f "$POLICY" && [[ $(sudo cat "$POLICY") == "$RULE" ]]; then
      echo "RULE ALREADY PRESENT: idempotent, no change."
      exit 0
    fi
    echo "BLOCKED: existing local policy differs; no overwrite."
    exit 3
  fi

  echo "Proposed rule: $RULE"
  echo "Other system guest profiles would also include this file, but the path pattern is restricted to win11."
  [[ "$MODE" == apply ]] || { echo "PLAN ONLY: no change."; exit 0; }

  command -v apparmor_parser >/dev/null 2>&1 || {
    echo "BLOCKED: AppArmor parser unavailable."; exit 3;
  }
  created_dir=no
  if ! sudo test -d "$DIR"; then
    sudo install -d -o root -g root -m 0755 "$DIR"
    created_dir=yes
  fi
  tmp=$(mktemp)
  trap 'rm -f -- "$tmp"' EXIT
  printf '%s\n' "$RULE" > "$tmp"
  sudo install -o root -g root -m 0644 "$tmp" "$POLICY"

  echo "Validating policy syntax without loading AppArmor profiles..."
  if ! sudo apparmor_parser -Q -T -K /etc/apparmor.d/libvirt/TEMPLATE.qemu >/dev/null 2>&1; then
    echo "VALIDATION FAILED. Removing only the policy file just installed."
    sudo rm -f -- "$POLICY"
    if [[ "$created_dir" == yes ]]; then
      sudo rmdir -- "$DIR" 2>/dev/null || true
    fi
    exit 4
  fi
  echo "VALIDATION PASS: apparmor_parser skip-kernel-load."
  echo "Rule file installed: $POLICY"
  echo "No AppArmor disablement, no system-wide service restart, no VM start."
  echo "Next: attempt starting win11 once in virt-manager. If it still fails, report rather than broaden the policy."
) > "$REPORT" 2>&1
rc=$?
echo "Private report: $REPORT"
echo "Exit status: $rc"
exit "$rc"
