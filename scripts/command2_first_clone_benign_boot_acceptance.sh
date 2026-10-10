#!/usr/bin/env bash
# SSL-55 one-report first benign boot acceptance of exact Command 2A win11_1.
# Plan is read-only, apply requires terminal confirmation and may install a
# narrow AppArmor swtpm rule then start --paused / check / resume WITHOUT NICs.
# No analysis network, CAPE config, snapshots or malware.
set -Eeuo pipefail
umask 077
HERE="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PY="$HERE/command2_boot_first_cloned_windows.py"
[[ -f "$PY" ]] || { echo "BLOCKED: Missing Command 2A boot script" >&2; exit 2; }
[[ -t 0 ]] || { echo "BLOCKED: Interactive terminal required" >&2; exit 2; }
sudo -v || exit 2
REPORT="$(mktemp "$HOME/CAPE_Command2A_BenignBoot_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")"
echo "Report: $REPORT"
echo "[1/2] Running protected VM / UEFI / TPM / RAM / NIC preflight..."
if ! sudo /usr/bin/python3 "$PY" --mode plan >"$REPORT" 2>&1; then
    echo "BLOCKED: Preflight failed. New Windows clone remains shut off."
    tail -n 45 "$REPORT"
    exit 2
fi
echo "PASS: Exact independently created win11_1 preflight."
echo "WARNING: next stage will modify only clone's narrow AppArmor TPM policy"
echo "and BOOT win11_1 after starting it PAUSED and checking live zero NICs."
echo "No guest network or host Internet/firewall changes will be made."
read -r -p 'Type BOOT-NONET-WIN11-1 to authorize benign first boot: ' ACK
if [[ "$ACK" != "BOOT-NONET-WIN11-1" ]]; then
    echo "ABORT: No guest started; preflight report preserved."
    exit 2
fi
printf '\n=== BENIGN NO-NIC FIRST BOOT AFTER OPERATOR APPROVAL ===\n' >>"$REPORT"
echo "[2/2] Scoped clone-only TPM preparation, paused QEMU start and resume..."
set +e
sudo /usr/bin/python3 "$PY" --mode boot >>"$REPORT" 2>&1
STATUS=$?
set -e
echo "Exit status: $STATUS"
echo "Report: $REPORT"
tail -n 65 "$REPORT" || true
if [[ "$STATUS" -eq 0 ]]; then
  echo "PASS: win11_1 reports RUNNING with zero NICs."
  echo "Open ONLY the win11_1 display in virt-manager."
  echo "Check Windows desktop and agent LOCALHOST:8000/status inside guest."
else
  echo "BLOCKED: Do not retry, force-stop, attach NIC, or edit any VM."
fi
exit "$STATUS"
