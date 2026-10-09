#!/usr/bin/env bash
# Read-only plan for libguestfs package dependencies on Ubuntu 24.04.
# No apt update, package install, removal, daemon restart or VM operation.
set -Eeuo pipefail
umask 077
OUT="${1:-$HOME/cape_guestfs_dependency_plan_$(date +%Y%m%d_%H%M%S)_$$.txt}"
if [[ "$OUT" != /* ]]; then
  echo "Output path must be absolute" >&2
  exit 2
fi
if [[ -e "$OUT" || -L "$OUT" ]]; then
  echo "Report already exists; refusing overwrite: $OUT" >&2
  exit 2
fi
if ! command -v apt-get >/dev/null || ! command -v dpkg-query >/dev/null; then
  echo "APT or dpkg-query unavailable; not an Ubuntu APT host" >&2
  exit 2
fi
exec 3>"$OUT"
chmod 0600 "$OUT"
{
  echo "=== CAPE guestfs dependency PREVIEW ONLY ==="
  date -Is
  echo
  echo "== OS =="
  grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release || true
  echo
  echo "== current guestfs tools =="
  for t in virt-win-reg guestfish qemu-img virsh; do
    if command -v "$t" >/dev/null; then
      echo "$t: $(command -v "$t")"
    else
      echo "$t: MISSING"
    fi
  done
  echo
  echo "== package candidates (local apt metadata only; no apt update) =="
  apt-cache policy guestfs-tools libguestfs-tools guestfish libguestfs0t64 || true
  echo
  echo "== simulated minimal dependency transaction =="
  # Apt simulation does not execute dpkg, download data, or update sources.
  set +e
  apt-get -s --no-install-recommends install guestfs-tools
  RESULT=$?
  set -e
  echo
  echo "APT_SIMULATION_EXIT_CODE=$RESULT"
  echo "== package transaction summary =="
  echo "Review all Inst/Remv/Conf lines before authorizing installation."
} >&3 2>&3
exec 3>&-
echo "Read-only dependency report: $OUT"
echo "No packages, VM disks, networks, or system settings were changed."
