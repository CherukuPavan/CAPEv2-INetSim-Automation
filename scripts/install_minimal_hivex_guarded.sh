#!/usr/bin/env bash
# Install ONLY reviewed Noble hivex packages, after exact APT simulation.
# Does not touch QEMU/libvirt images, host networks or Windows Registry.
# Default is read-only plan; --apply requires explicit root-authorized action.
set -Eeuo pipefail
umask 077

MODE="${1:---plan}"
case "$MODE" in --plan|--apply) ;; *) echo 'Use --plan or --apply' >&2; exit 2;; esac
[[ $# -le 1 ]] || { echo 'Too many arguments' >&2; exit 2; }

REPORT="$HOME/CAPE_Hivex_Guarded_${MODE#--}_$(date +%Y%m%d_%H%M%S)_$$.txt"
if [[ -e "$REPORT" || -L "$REPORT" ]]; then
  echo "Report exists: $REPORT" >&2; exit 2
fi

# Freeze dependency versions observed in the operator's Noble simulation.
PKGS=(
  'libhivex0=1.3.23-1build7'
  'libhivex-bin=1.3.23-1build7'
  'python3-hivex=1.3.23-1build7'
)

if [[ $MODE == --apply ]]; then sudo -v; fi
SIM=$(mktemp)
trap 'rm -f -- "$SIM"' EXIT
EXIT_CODE=0
LC_ALL=C apt-get -s --no-install-recommends --no-upgrade --no-remove \
  install "${PKGS[@]}" > "$SIM" 2>&1 || EXIT_CODE=$?

VERDICT=PASS
if [[ $EXIT_CODE -ne 0 ]]; then VERDICT=BLOCK_SIMULATION_ERROR; fi

# Every newly installed package must be one of exactly these three.
while read -r action package more; do
  case "$action" in
    Inst)
      case "$package" in
        libhivex0|libhivex-bin|python3-hivex) ;;
        *) VERDICT=BLOCK_UNEXPECTED_INSTALL ;;
      esac
      ;;
    Remv|Purg) VERDICT=BLOCK_REMOVAL ;;
  esac
done < <(grep -E '^(Inst|Remv|Purg) ' "$SIM" || true)

if grep -Eq '^Inst .*Ubuntu:20\.04/' "$SIM"; then
  VERDICT=BLOCK_FOCAL_SOURCE
fi

if [[ ${ID:-} != ubuntu ]]; then
  . /etc/os-release
fi
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  VERDICT=BLOCK_UNSUPPORTED_OS
fi
if ! apt-mark showhold | grep -qx 'qemu'; then
  VERDICT=BLOCK_CUSTOM_QEMU_NOT_HELD
fi

QEMU_BEFORE=$(sha256sum /usr/bin/qemu-img /usr/bin/qemu-nbd /usr/bin/qemu-system-x86_64 2>/dev/null || true)
{
  echo "=== Guarded minimal Hivex install: $MODE ==="
  date -Is
  echo "Host: $(hostname)"
  echo "OS: ${PRETTY_NAME:-unknown}"
  echo "Transaction: ${PKGS[*]}"
  echo "APT simulation exit: $EXIT_CODE"
  echo "Preflight verdict: $VERDICT"
  echo
  cat "$SIM"
  echo
  echo "=== QEMU executable checksums before ==="
  echo "$QEMU_BEFORE"
  echo
  echo "=== Package operation ==="
  if [[ "$VERDICT" != PASS ]]; then
    echo "BLOCKED: No packages installed"
  elif [[ $MODE == --plan ]]; then
    echo "PLAN ONLY: No packages installed"
  else
    echo "Applying the exact three-package Noble transaction"
    # Force no removals or upgrades and no recommended packages.
    sudo env DEBIAN_FRONTEND=noninteractive apt-get -y \
      --no-install-recommends --no-upgrade --no-remove \
      install "${PKGS[@]}"
    echo "=== Installed packages ==="
    dpkg-query -W -f='${Package} ${Version} ${Status}\n' \
      libhivex0 libhivex-bin python3-hivex
    echo "=== Hivex Python import ==="
    /usr/bin/python3 -c 'import hivex; print("HIVEX_IMPORT_OK")'
    echo "=== Existing QEMU versions, after ==="
    qemu-img --version | head -n 1
    virsh --version || true
    echo "=== QEMU executable checksums after ==="
    sha256sum /usr/bin/qemu-img /usr/bin/qemu-nbd /usr/bin/qemu-system-x86_64
    QEMU_AFTER=$(sha256sum /usr/bin/qemu-img /usr/bin/qemu-nbd /usr/bin/qemu-system-x86_64)
    if [[ "$QEMU_BEFORE" != "$QEMU_AFTER" ]]; then
      echo "WARNING: QEMU executables unexpectedly changed — review immediately"
      exit 4
    fi
    echo "INSTALL_OK: HIVEX_READY_FOR_CLONE_ONLY_TESTS"
  fi
} > "$REPORT" 2>&1 || {
  STATUS=$?
  echo "Stopped with status $STATUS. Review: $REPORT" >&2
  exit "$STATUS"
}

echo "Report: $REPORT"
echo "Preflight: $VERDICT"
if [[ "$VERDICT" != PASS ]]; then
  exit 2
fi
if [[ $MODE == --apply ]]; then
  echo "Minimal Hivex packages installed. No VM or image was modified."
else
  echo "Plan only: no packages changed."
fi
