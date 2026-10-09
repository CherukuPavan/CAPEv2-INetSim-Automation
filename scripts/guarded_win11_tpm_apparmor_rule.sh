#!/usr/bin/env bash
# Narrow AppArmor workaround for one guest's swtpm Unix socket /run alias.
# Default --plan is read only. --apply appends ONE specific AppArmor allow rule
# to the existing local abstraction, preserving the standard /etc/apparmor.d
# policy and all other guest profiles; no AppArmor/global daemon restart.
#
# This is a diagnostic remediation for documented libvirt /var/run -> /run
# rule-generation mismatch, NOT proof that AppArmor is the only cause of EACCES.
set -euo pipefail
umask 077
MODE=plan
VM=win11
while (($#)); do
 case "$1" in
   --plan) MODE=plan; shift ;;
   --apply) MODE=apply; shift ;;
   --vm) (($#>=2)) || exit 2; VM=$2; shift 2 ;;
   -h|--help) echo "Usage: $0 [--plan|--apply] [--vm win11]"; exit 0 ;;
   *) echo "Unknown option $1" >&2; exit 2 ;;
 esac
done
# No broad wildcard guest names accepted: reviewed fix is for the user's win11 only.
[[ "$VM" == "win11" ]] || { echo "Only reviewed win11 guest is supported." >&2; exit 2; }
[[ $EUID -ne 0 ]] || { echo "Run from regular user; sudo will be scoped." >&2; exit 2; }
sudo -v
REPORT=$(mktemp "${HOME:?}/SSL55_TPMSocket_AA_${MODE}_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")
BASE=/etc/apparmor.d/abstractions/libvirt-qemu
LOCAL=/etc/apparmor.d/local/abstractions/libvirt-qemu
RULE='/run/libvirt/qemu/swtpm/*-win11-swtpm.sock rw,'
{
 echo "Mode=$MODE, guest=$VM"
 state=$(virsh -c qemu:///system domstate win11)
 echo "Guest state=$state"
 [[ "$state" == "shut off" ]] || { echo "STOP: VM must be shut off."; exit 3; }
 [[ $(sudo cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true) == Y ]] || { echo "STOP: AppArmor module not enabled."; exit 3; }
 [[ $(sudo awk '/^[[:space:]]*security_driver[[:space:]]*=/{gsub(/[ \t\"]/, "", $3); print $3}' /etc/libvirt/qemu.conf 2>/dev/null | tail -1) == apparmor ]] || {
  echo "STOP: explicit AppArmor libvirt driver not established."; exit 3;
 }
 sudo test -f "$BASE" || { echo "STOP: standard abstraction missing."; exit 3; }
 sudo grep -Eq '^[[:space:]]*(#include[[:space:]]+|include[[:space:]]+if[[:space:]]+exists[[:space:]]+)<local/abstractions/libvirt-qemu>' "$BASE" || {
  echo "STOP: static abstraction does not include local override."; exit 3;
 }
 sudo test -d /etc/apparmor.d/local/abstractions || { echo "STOP: local overrides directory absent."; exit 3; }
 if sudo test -L "$LOCAL"; then echo "STOP: local policy path is symlink."; exit 3; fi
 if sudo test -e "$LOCAL" && ! sudo test -f "$LOCAL"; then echo "STOP: local policy is not regular file."; exit 3; fi
 if sudo test -f "$LOCAL" && sudo grep -Fxq "  $RULE" "$LOCAL"; then
   echo "ALREADY PRESENT; no change needed."
   exit 0
 fi
 echo "Planned additional allow path: $RULE"
 echo "Only applies to the win11-named TPM socket, dynamic numeric prefix."
 echo "This AppArmor local abstraction is included by all guests: other guest-specific paths not allowed by this rule."
 if [[ "$MODE" == plan ]]; then echo "PLAN ONLY. No change."; exit 0; fi
 command -v apparmor_parser >/dev/null || { echo "STOP: apparmor_parser missing."; exit 3; }
 # Create private rollback copy of existing local override before changes.
 BACKUP=$(mktemp "${HOME}/SSL55_AA_LocalBackup_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")
 if sudo test -e "$LOCAL"; then
   sudo cat "$LOCAL" > "$BACKUP"
 else
   printf '' > "$BACKUP"
 fi
 chmod 600 "$BACKUP"
 echo "Previous local policy saved in private local backup $BACKUP"
 # Only one append, scoped exactly to this reviewed allow line.
 printf '\n# CAPEv2 win11 swtpm /run socket path allow (reviewed Step 12L)\n  %s\n' "$RULE" |
    sudo tee -a "$LOCAL" >/dev/null
 echo "Applied only reviewed win11 socket path rule to local AppArmor abstraction."
 # Deliberately NO broad apparmor daemon reload/restart: libvirt's next VM
 # start regenerates/loads win11-specific profile and includes local policies.
 echo "No AppArmor reload or libvirt restart attempted."
 echo "Retry win11 start once and capture any error. Existing policy backup retained."
} > "$REPORT" 2>&1
echo "Private report: $REPORT"
