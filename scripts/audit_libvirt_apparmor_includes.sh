#!/usr/bin/env bash
# Step 12O: read-only discovery of libvirt-qemu AppArmor local include syntax.
# Does not run any VM, reload policy, change files or start services.
set -u
umask 077
sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL55_Step12O_AppArmorIncludes_XXXXXXXX.txt") || exit 1
{
  echo "========== STEP 12O: APPARMOR INCLUDE CHECK =========="
  for FILE in \
      /etc/apparmor.d/abstractions/libvirt-qemu \
      /etc/apparmor.d/libvirt/TEMPLATE.qemu
  do
    echo
    echo "========== $FILE =========="
    if sudo test -f "$FILE"; then
      sudo grep -nE 'include|libvirt-qemu.d|swtpm' "$FILE" | tail -n 50 || true
    else
      echo "File not found."
    fi
  done
  echo
  echo "========== LOCAL OVERRIDE LOCATIONS =========="
  for PATHNAME in \
      /etc/apparmor.d/abstractions/libvirt-qemu.d \
      /etc/apparmor.d/local/abstractions/libvirt-qemu
  do
    if sudo test -e "$PATHNAME"; then
      sudo stat -c '%F %A %U:%G %n' "$PATHNAME"
    else
      echo "NOT PRESENT: $PATHNAME"
    fi
  done
  echo
  echo "No files modified."
  echo "No AppArmor policies reloaded."
  echo "No VM started."
} > "$REPORT" 2>&1
echo "Private read-only report: $REPORT"
echo "Review for host-private information before uploading."
