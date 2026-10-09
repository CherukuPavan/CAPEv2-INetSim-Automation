#!/usr/bin/env bash
# Hivex backend feasibility preflight for customized CAPE hosts.
# Observes only package cache, version ownership, Docker daemon availability,
# and kernel NBD support. Never installs packages or attaches disks.
set -Eeuo pipefail
umask 077

OUT="${1:-$HOME/CAPE_Minimal_Hivex_Backend_$(date +%Y%m%d_%H%M%S)_$$.txt}"
if [[ "$OUT" != /* || -e "$OUT" || -L "$OUT" ]]; then
  echo "Provide an unused absolute TXT report path" >&2
  exit 2
fi
for tool in apt-cache apt-get dpkg-query mktemp grep awk stat; do
  command -v "$tool" >/dev/null || { echo "Missing required audit tool: $tool" >&2; exit 2; }
done

SIM=$(mktemp)
trap 'rm -f -- "$SIM"' EXIT
SIM_EXIT=0
apt-get -s --no-install-recommends install python3-hivex libhivex-bin >"$SIM" 2>&1 || SIM_EXIT=$?

DECISION="REVIEW_REQUIRED"
if [[ "$SIM_EXIT" -ne 0 ]]; then DECISION="BLOCKED_APT_SIMULATION_FAILED"; fi
if grep -Eq '^(Inst|Remv|Purg) (qemu[^ ]*|libvirt[^ ]*|seabios)( |$)' "$SIM"; then
  DECISION="BLOCKED_TOUCHES_CUSTOM_VIRTUALIZATION_STACK"
fi
if grep -Eq '^(Remv|Purg) ' "$SIM"; then
  DECISION="BLOCKED_PACKAGE_REMOVALS"
fi
if grep -Eq '^Inst .*Ubuntu:20\.04/' "$SIM"; then
  DECISION="BLOCKED_FOCAL_PACKAGE_CANDIDATE"
fi

{
  echo "=== Minimal Hivex / Windows offline customization — READ ONLY ==="
  date -Is
  echo "No apt update, install, modprobe, qemu-nbd attach or mount performed."
  echo
  echo "=== Host OS ==="
  grep -E '^(PRETTY_NAME|VERSION_ID|ID)=' /etc/os-release || true
  echo
  echo "=== Existing tool paths ==="
  for binary in hivexregedit hivexsh virt-win-reg guestfish \
      qemu-nbd qemu-img qemu-system-x86_64 ntfs-3g docker; do
    if command -v "$binary" >/dev/null; then
      printf '%s: %s\n' "$binary" "$(command -v "$binary")"
    else
      printf '%s: MISSING\n' "$binary"
    fi
  done
  echo
  echo "=== Python hive binding import (no changes) ==="
  python3 -c 'import hivex; print("hivex Python binding: FOUND")' 2>/dev/null || \
      echo "hivex Python binding: NOT IMPORTABLE"
  echo
  echo "=== Package origin candidates (do not install) ==="
  apt-cache policy python3-hivex libhivex-bin libhivex0 \
     libvirt0 qemu-system-x86 qemu-utils 2>&1 || true
  echo
  echo "=== Host QEMU package ownership / held packages ==="
  dpkg-query -S /usr/bin/qemu-img /usr/bin/qemu-nbd /usr/bin/qemu-system-x86_64 2>&1 || true
  apt-mark showhold 2>&1 || true
  echo
  echo "=== Full minimal Hivex APT simulation ==="
  cat "$SIM"
  echo
  echo "=== Docker daemon access (read-only request) ==="
  if command -v docker >/dev/null; then
    timeout 10s sudo -n docker version --format \
      'Client={{.Client.Version}} Server={{.Server.Version}}' 2>&1 || true
  else
    echo "Docker unavailable"
  fi
  echo
  echo "=== NBD support (observation only) ==="
  lsmod 2>/dev/null | grep '^nbd ' || echo "nbd module not currently loaded / unavailable"
  ls -l /dev/nbd* 2>&1 || true
  if command -v modinfo >/dev/null; then
    modinfo -F filename nbd 2>&1 || true
  fi
  echo
  echo "=== APT decision ==="
  echo "SIMULATION_EXIT=$SIM_EXIT"
  echo "DECISION=$DECISION"
  echo "Even REVIEW_REQUIRED does NOT authorize package installation."
  echo "Offline Windows hive mutation is NOT validated or enabled."
} >"$OUT" 2>&1

echo "Read-only report: $OUT"
echo "Simulation decision: $DECISION"
if [[ "$DECISION" == BLOCKED_* ]]; then
  echo "No installation attempted; candidate backend needs further review." >&2
  exit 2
fi
echo "No packages, VM images, services or networks were changed."
