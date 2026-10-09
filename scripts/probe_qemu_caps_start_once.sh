#!/usr/bin/env bash
# Step 12M: observe CAP_DAC_OVERRIDE and AppArmor on QEMU during one guest start.
# Captures only QEMU credentials/capability mask, never dumps process arguments.
# Does START the guest once; if success leaves it running. No policy mutations.
set -u
umask 077
VM=win11
sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL55_Step12M_QEMUCapabilities_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1
SAMPLE=$(mktemp "${HOME}/.SSL55_QEMUCapabilities_XXXXXXXX.txt") || exit 1
START=$(mktemp "${HOME}/.SSL55_VMStart_XXXXXXXX.txt") || exit 1
trap 'rm -f -- "$SAMPLE" "$START"' EXIT
STATE=$(virsh -c qemu:///system domstate "$VM" 2>/dev/null || true)
if [[ "$STATE" != "shut off" ]]; then
 echo "STOP: $VM must be shut off. Current state: $STATE"
 exit 2
fi
sudo -n bash -c '
found=0
for ((i=0; i<800; i++)); do
  for pid in $(ps -C qemu-system-x86 -o pid= 2>/dev/null); do
    [[ -r "/proc/$pid/status" ]] || continue
    if tr "\000" "\n" < "/proc/$pid/cmdline" 2>/dev/null | grep -q "guest=win11"; then
      echo "========== QEMU PROCESS =========="
      grep -E "^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|NoNewPrivs):" \
        "/proc/$pid/status" 2>/dev/null
      echo "========== APPARMOR =========="
      cat "/proc/$pid/attr/current" 2>/dev/null || true
      found=1
      break
    fi
  done
  ((found)) && break
  sleep 0.01
done
((found)) || echo "QEMU process was not captured."
' >"$SAMPLE" 2>&1 &
MON=$!
sleep 0.1
virsh -c qemu:///system start "$VM" >"$START" 2>&1
RC=$?
wait "$MON" || true
{
 echo "========== STEP 12M: QEMU PROCESS CAPABILITIES =========="
 cat "$SAMPLE"
 echo
 echo "========== CAP_DAC_OVERRIDE =========="
 CAP=$(awk '/^CapEff:/ {print $2; exit}' "$SAMPLE")
 if [[ "$CAP" =~ ^[[:xdigit:]]+$ ]]; then
   python3 - "$CAP" <<'PY'
import sys
caps=int(sys.argv[1],16)
print("CAP_DAC_OVERRIDE:", "YES" if caps&(1<<1) else "NO")
PY
 else
   echo "CAP_DAC_OVERRIDE: UNKNOWN (process not captured)"
 fi
 echo
 echo "========== START RESULT =========="
 echo "Exit status: $RC"
 tail -n 8 "$START"
 echo
 echo "========== GUEST STATE =========="
 virsh -c qemu:///system domstate "$VM" 2>&1 || true
 echo "READ ONLY host inspection; one user-requested VM start attempt."
} >"$REPORT" 2>&1
echo "Private report: $REPORT"
echo "Review for private details before uploading."
