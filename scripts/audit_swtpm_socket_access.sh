#!/usr/bin/env bash
# Read-only analysis of which system accounts can traverse libvirt's TPM socket dir.
# Does not weaken permissions, alter service accounts or start a VM.
set -u
umask 077
sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL_TPM_SocketAccess_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1
DIR="/run/libvirt/qemu/swtpm"
{
  echo "========== TPM SOCKET DIRECTORY ACCESS =========="
  echo "NO state changes or VM launches."
  echo
  echo "========== NONCOMMENTED QEMU PROCESS CONFIG =========="
  sudo awk '/^[[:space:]]*(user|group|swtpm_user|swtpm_group)[[:space:]]*=/ {print}' /etc/libvirt/qemu.conf 2>/dev/null || true
  echo
  echo "========== ACCOUNT IDENTITIES =========="
  for USER in libvirt-qemu qemu tss; do
    if id "$USER" >/dev/null 2>&1; then id "$USER"
    else echo "$USER: account not found"; fi
  done
  echo
  echo "========== DIRECTORY PATH =========="
  sudo stat -c '%A %U:%G %n' "$DIR" 2>&1 || true
  sudo namei -l "$DIR" 2>&1 || true
  echo
  echo "========== ACCESS AS CANDIDATE ACCOUNTS =========="
  for USER in libvirt-qemu qemu tss; do
    id "$USER" >/dev/null 2>&1 || continue
    echo "--- $USER ---"
    for FLAG in r w x; do
      if sudo -n -u "$USER" test "-$FLAG" "$DIR"; then
        echo "$FLAG: PASS"
      else
        echo "$FLAG: FAIL"
      fi
    done
  done
  echo
  echo "========== APPARMOR STATE (NO POLICY MODIFICATION) =========="
  if command -v aa-status >/dev/null 2>&1; then
    sudo aa-status 2>&1 | head -n 35
  else
    echo "aa-status unavailable"
  fi
  echo "========== COMPLETE =========="
} > "$REPORT" 2>&1
echo "Private report: $REPORT"
echo "Review for host-private details before sharing."
