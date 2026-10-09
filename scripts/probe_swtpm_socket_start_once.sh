#!/usr/bin/env bash
# STEP 12L: Explicit one-time attempt to start a trusted INSTALLER-only guest.
# Captures transient swtpm socket metadata and QEMU security identity.
# WARNING: This DOES start the named VM once; if it succeeds, it remains running.
# No permission changes, security changes, package installs, or forced shutdowns.
set -u
umask 077
VM=win11
sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL55_Step12L_TPMLiveSocket_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1
SAMPLE=$(mktemp "${HOME}/.SSL55_Step12L_Sample_XXXXXXXX.txt") || exit 1
START=$(mktemp "${HOME}/.SSL55_Step12L_Start_XXXXXXXX.txt") || exit 1
trap 'rm -f -- "$SAMPLE" "$START"' EXIT

STATE=$(virsh -c qemu:///system domstate "$VM" 2>/dev/null || true)
if [[ "$STATE" != "shut off" ]]; then
  echo "VM state is '$STATE', not shut off. Nothing started."
  exit 2
fi

# Root only observes kernel/process metadata; no actions in the sampler.
sudo -n bash -c '
seen_socket=0
seen_qemu=0
for ((i=0; i<300; i++)); do
  for sock in /run/libvirt/qemu/swtpm/*-win11-swtpm.sock; do
    [[ -S "$sock" ]] || continue
    if (( ! seen_socket )); then
      stat -c "SOCKET: owner=%U group=%G mode=%a type=%F" -- "$sock"
      seen_socket=1
    fi
  done
  if (( ! seen_qemu )); then
    ids=$(ps -C qemu-system-x86 -o pid=,euid=,egid=,comm= 2>/dev/null)
    if [[ -n "$ids" ]]; then
      printf "QEMU PID EUID EGID PROCESS:\n%s\n" "$ids"
      while read -r pid _; do
        [[ -n "$pid" ]] || continue
        printf "QEMU AppArmor profile: "
        cat "/proc/$pid/attr/current" 2>/dev/null || echo "unavailable"
      done <<< "$ids"
      seen_qemu=1
    fi
  fi
  ((seen_socket && seen_qemu)) && break
  sleep 0.02
done
((seen_socket)) || echo "Transient socket not captured during sample."
((seen_qemu)) || echo "Transient QEMU process not captured during sample."
' > "$SAMPLE" 2>&1 &
MON=$!
sleep 0.15
virsh -c qemu:///system start "$VM" > "$START" 2>&1
RC=$?
wait "$MON" || true

{
  echo "========== STEP 12L: TPM SOCKET AT START TIME =========="
  echo "One VM start attempt; no host configuration changes."
  echo "VM before attempt: $STATE"
  echo "========== TRANSIENT SOCKET AND PROCESS METADATA =========="
  cat "$SAMPLE"
  echo "========== VM START RESULT =========="
  echo "virsh start exit: $RC"
  tail -n 12 "$START"
  echo "========== VM CURRENT STATE =========="
  virsh -c qemu:///system domstate "$VM" 2>&1 || true
  echo "========== KERNEL APPARMOR DENIALS =========="
  sudo journalctl -k -b -n 250 --no-pager -o cat 2>/dev/null |
    grep -Ei 'apparmor="DENIED".*(qemu|swtpm|libvirt)|apparmor=.*(swtpm|chrtpm)' |
    tail -n 15 || true
  echo "========== END =========="
  echo "If the VM started, it remains running; continue only normal Windows Setup."
} > "$REPORT" 2>&1

echo "Private evidence report: $REPORT"
echo "VM start exit status: $RC"
echo "Review the report for private details before uploading."
exit 0
