#!/usr/bin/env bash
# Step 12K read-only verification of win11 TPM socket/AppArmor rules.
# No permissions, systemd units, VM settings, security profiles or TPM state changed.
set -u
umask 077
sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL55_Step12K_TPMSecurity_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1
URI="qemu:///system"
{
  echo "========== STEP 12K: TPM SOCKET SECURITY CHECK =========="
  echo "READ ONLY - no VM launch or security changes."
  echo
  echo "========== VM STATE =========="
  virsh -c "$URI" domstate win11 2>&1 || true
  UUID=$(virsh -c "$URI" domuuid win11 2>/dev/null || true)
  if [[ ! "$UUID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    echo "Cannot identify domain UUID."
  else
    echo "VM UUID identified."
    echo "========== GENERATED APPARMOR RULES =========="
    for FILE in "/etc/apparmor.d/libvirt/libvirt-$UUID" \
                "/etc/apparmor.d/libvirt/libvirt-$UUID.files"; do
      if sudo test -f "$FILE"; then
        echo "--- ${FILE##*/} ---"
        sudo grep -E 'swtpm|@\{run\}|/var/run/libvirt|/run/libvirt' "$FILE" 2>&1 || true
      else
        echo "${FILE##*/}: NOT PRESENT"
      fi
    done
  fi
  echo
  echo "========== /run vs /var/run =========="
  ls -ld /run /var/run
  echo
  echo "========== EXPLICIT QEMU CONFIG OVERRIDES =========="
  sudo awk '/^[[:space:]]*(security_driver|security_default_confined|user|group)[[:space:]]*=/ { print }' \
      /etc/libvirt/qemu.conf 2>/dev/null || true
  echo
  echo "========== RECENT VM STARTUP ERRORS =========="
  if sudo test -f /var/log/libvirt/qemu/win11.log; then
    sudo grep -Ei 'permission denied|swtpm|apparmor|security|failed to connect' \
      /var/log/libvirt/qemu/win11.log | tail -n 25 || true
  else
    echo "Guest startup log not found."
  fi
  echo
  echo "========== KERNEL SECURITY DENIALS =========="
  sudo journalctl -k -b --no-pager -o cat 2>/dev/null |
    grep -Ei 'apparmor|audit' |
    grep -Ei 'denied|swtpm|qemu|libvirt' |
    tail -n 30 || true
  echo
  echo "========== CHECK COMPLETE =========="
  echo "No permissions or policies changed. No VM started."
} >"$REPORT" 2>&1
echo "Private report: $REPORT"
echo "Review host-private details before uploading. Never commit raw logs."
