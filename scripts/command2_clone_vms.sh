#!/usr/bin/env bash
# Command 2 guarded operator entrypoint; deliberately asks for a count.
set -Eeuo pipefail
HERE=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd -P)
PROFILE="/etc/cape-clone/command2.json"
if [[ -n "$CAPE_CLONE_PROFILE" ]]; then PROFILE="$CAPE_CLONE_PROFILE"; fi
MODE=apply
if [[ $# -ge 1 ]]; then
  case "$1" in
    --apply) MODE=apply ;;
    --plan) MODE=plan ;;
    -h|--help) echo "Usage: bash scripts/command2_clone_vms.sh [--plan|--apply]"; exit 0 ;;
    *) echo "Unknown mode" >&2; exit 2 ;;
  esac
fi
[[ $# -le 1 ]] || { echo "Too many arguments" >&2; exit 2; }
command -v python3 >/dev/null || { echo "Missing Python3" >&2; exit 2; }
[[ -f "$PROFILE" ]] || { echo "Missing reviewed profile: $PROFILE" >&2; exit 2; }
[[ -t 0 ]] || { echo "Interactive terminal required (Python also supports --count N)" >&2; exit 2; }
echo "CAPEv2 Command 2: $MODE"
echo "Deployment profile: $PROFILE"
echo "Master VM and snapshots will not be changed."
read -rp "How many additional Windows VMs should be created? " COUNT
[[ $COUNT =~ ^[1-9][0-9]*$ ]] || { echo "Invalid VM count" >&2; exit 2; }
echo "Only benign agent/ICMP startup checks. No malware samples will be executed."
sudo -v
exec sudo python3 "$HERE/command2_clone_vms.py" --profile "$PROFILE" --mode "$MODE" --count "$COUNT" --reportdir /var/log/cape-clone
