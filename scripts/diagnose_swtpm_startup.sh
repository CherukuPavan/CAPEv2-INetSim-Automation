#!/usr/bin/env bash
# Read-only diagnostic for libvirt/QEMU emulated TPM initialization failures.
# Log may contain machine-private details. Never commit generated reports.
set -u
umask 077

VM="${1:-win11}"
if [[ ! "$VM" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$VM" == .* ]]; then
  echo "Invalid VM name." >&2
  exit 2
fi

command -v sudo >/dev/null 2>&1 || { echo "sudo missing" >&2; exit 2; }
sudo -v || exit 1

REPORT=$(mktemp "${HOME:?}/SSL_TPM_Diagnostic_${VM}_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1

{
  echo "========== TPM 2.0 STARTUP DIAGNOSIS =========="
  echo "Guest name: $VM"
  echo "READ ONLY - no packages, permissions, TPM state, services, VMs changed."

  echo
  echo "========== DOMAIN STATE =========="
  virsh -c qemu:///system domstate "$VM" 2>&1 || true

  echo
  echo "========== HOST SOFTWARE TPM PACKAGES =========="
  dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' \
      swtpm swtpm-tools libtpms0 2>&1 || true

  echo
  echo "========== SOFTWARE TPM EXECUTABLES =========="
  command -v swtpm || true
  command -v swtpm_setup || true
  swtpm --version 2>&1 || true
  swtpm_setup --version 2>&1 || true

  echo
  echo "========== GUEST TPM XML ONLY =========="
  virsh -c qemu:///system dumpxml "$VM" 2>/dev/null |
    python3 -c '
import sys
import xml.etree.ElementTree as ET
try:
    root = ET.fromstring(sys.stdin.read())
    devices = root.find("devices")
    tpms = [] if devices is None else devices.findall("tpm")
    if not tpms:
        print("No TPM device defined or not accessible.")
    for tpm in tpms:
        print(ET.tostring(tpm, encoding="unicode"))
except Exception as error:
    print("Could not parse TPM XML:", type(error).__name__)
' || true

  echo
  echo "========== SWTPM INITIALIZATION LOG =========="
  LOG="/var/log/swtpm/libvirt/qemu/${VM}-swtpm.log"
  if sudo test -f "$LOG"; then
    sudo stat -c 'Permissions: %A Owner: %U:%G Size: %s bytes' "$LOG"
    sudo tail -n 100 "$LOG"
  else
    echo "Expected swtpm initialization log absent."
  fi

  echo
  echo "========== SWTPM DIRECTORY METADATA =========="
  for DIR in \
      /var/log/swtpm \
      /var/log/swtpm/libvirt \
      /var/log/swtpm/libvirt/qemu \
      /var/lib/libvirt/swtpm \
      "/var/lib/libvirt/swtpm/$VM"
  do
    if sudo test -e "$DIR"; then
      sudo stat -c '%A %U:%G %n' "$DIR"
    else
      echo "Not found: $DIR"
    fi
  done

  echo
  echo "========== LIBVIRT SERVICE =========="
  systemctl show virtqemud.service -p LoadState -p ActiveState -p SubState \
      --no-pager 2>&1 || true

  echo
  echo "========== RECENT LIBVIRT JOURNAL (REVIEW BEFORE SHARING) =========="
  sudo journalctl -b -u virtqemud.service -n 50 --no-pager -o short-iso 2>&1 || true

  echo
  echo "========== FINISHED =========="
  echo "No changes performed."
} >"$REPORT" 2>&1

echo "Saved private read-only diagnostic to: $REPORT"
echo "Inspect file for private details before uploading or sharing."
