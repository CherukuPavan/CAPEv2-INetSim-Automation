#!/usr/bin/env bash
# SSL-55: only a small root-private TXT. Zero libvirt/network/VM changes.
set -Eeuo pipefail
umask 077
[[ -t 0 ]] || { echo "BLOCKED: Run in SSL-55 terminal" >&2; exit 2; }
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
SCRIPT="$HERE/command2_ssl55_network_readonly_audit.py"
[[ -f "$SCRIPT" && ! -L "$SCRIPT" ]] || {
  echo "BLOCKED: Auditing module missing or linked" >&2; exit 2;
}
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_SSL55_NetworkReadOnly_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
set +e
sudo -n /usr/bin/python3 -B "$SCRIPT" >"$REPORT" 2>&1
CODE=$?
set -e
echo "EXIT: $CODE"
echo "REPORT: $REPORT"
tail -n 95 "$REPORT" || true
echo "READ-ONLY: No master/clone/network/firewall changes, no NIC attach."
exit "$CODE"
