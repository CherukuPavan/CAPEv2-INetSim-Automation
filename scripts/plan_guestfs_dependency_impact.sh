#!/usr/bin/env bash
# Read-only libguestfs dependency impact analysis. Never install packages.
# For CAPE hosts using custom QEMU/libvirt, any virtualization-stack
# transaction is a hard-stop rather than an automatic dependency repair.
set -Eeuo pipefail
umask 077

OUT="${1:-$HOME/cape_guestfs_dependency_plan_$(date +%Y%m%d_%H%M%S)_$$.txt}"
[[ "$OUT" == /* ]] || { echo "Absolute report path required" >&2; exit 2; }
[[ ! -e "$OUT" && ! -L "$OUT" ]] || {
  echo "Report exists; refusing overwrite: $OUT" >&2; exit 2;
}
for tool in apt-get apt-cache dpkg-query awk mktemp; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done

# Operate exclusively on local cached APT package metadata.
SIMLOG=$(mktemp)
trap 'rm -f -- "$SIMLOG"' EXIT
SIM_EXIT=0
apt-get -s --no-install-recommends install guestfs-tools >"$SIMLOG" 2>&1 || SIM_EXIT=$?

BLOCKED=0
if [[ "$SIM_EXIT" -ne 0 ]]; then BLOCKED=1; fi
# New QEMU/libvirt packages may overlap with custom /usr binaries or ABI,
# even when apt reports no removals. Filesystem conflicts may be unseen in -s.
if grep -Eq '^(Inst|Remv|Purg) (qemu[^ ]*|libvirt[^ ]*|libvirt0|seabios)( |$)' "$SIMLOG"; then
  BLOCKED=1
fi
if grep -Eq '^([0-9]+ upgraded, .* [1-9][0-9]* to remove|Remv |Purg )' "$SIMLOG"; then
  BLOCKED=1
fi

{
  echo "=== CAPE guestfs host dependency transaction — READ ONLY ==="
  date -Is
  echo "Operator action: NEVER run apt install from this preview."
  echo
  echo "=== OS ==="
  grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release || true
  echo
  echo "=== Guestfs/QEMU/libvirt binaries ==="
  for tool in virt-win-reg guestfish qemu-img qemu-system-x86_64 virsh swtpm; do
    command -v "$tool" || echo "$tool: MISSING"
  done
  echo
  echo "=== Package holds ==="
  apt-mark showhold 2>/dev/null || true
  echo
  echo "=== Package candidates (read-only) ==="
  apt-cache policy guestfs-tools libguestfs-tools libvirt0 qemu-system-x86 qemu-utils || true
  echo
  echo "=== Complete APT simulation ==="
  cat "$SIMLOG"
  echo
  echo "=== Potentially dangerous virtualization changes ==="
  grep -E '^(Inst|Remv|Purg) (qemu[^ ]*|libvirt[^ ]*|seabios)( |$)' "$SIMLOG" || true
  echo
  echo "APT_SIMULATION_EXIT_CODE=$SIM_EXIT"
  if [[ "$BLOCKED" -ne 0 ]]; then
    echo "DEPENDENCY_DECISION=BLOCKED"
    echo "Reason: failed simulation or host virtualization stack package transaction."
    echo "No installation authorized. Choose an isolated/verified customization method."
  else
    echo "DEPENDENCY_DECISION=REVIEW_REQUIRED"
    echo "Not automatic installation approval; inspect all packages and host ABI."
  fi
  echo "No software, network, VM or snapshot changes performed."
} >"$OUT"

echo "Read-only dependency report: $OUT"
if [[ "$BLOCKED" -ne 0 ]]; then
  echo "BLOCKED: dependency plan touches QEMU/libvirt/firmware or has errors." >&2
  exit 2
fi
echo "No automatic installation authorized; manual compatibility review required."
