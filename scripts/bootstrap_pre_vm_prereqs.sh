#!/usr/bin/env bash
# Controlled prerequisite component for the future three-command installer.
# Safe by default: --plan does not require sudo or change the host.
# --apply explicitly installs only missing base packages (Steps 2, 4, 5).
# Never runs CAPEv2 upstream installers, apt upgrade/autoremove, reboots or masks power targets.
set -Eeuo pipefail

usage() {
  cat <<'HELP'
Usage: bash scripts/bootstrap_pre_vm_prereqs.sh [--plan|--apply] [--report FILE]

--plan       Default. Inspect Ubuntu and list missing provisionable prerequisites.
--apply      Explicit opt-in to apt-get install missing cpu-checker, msr-tools,
             git, acpica-tools, python3, python3-venv and python3-pip.
--report     Store private TXT output at this new absolute path (never overwrite).

This does NOT install CAPEv2, libvirt/QEMU builds, guest VMs or INetSim.
Host package repositories and system power/network policy are not edited.
HELP
}

MODE=plan
REPORT=''
while (($#)); do
  case "$1" in
    --plan) MODE=plan; shift ;;
    --apply) MODE=apply; shift ;;
    --report)
      (($# >= 2)) || { echo 'Missing report path' >&2; exit 2; }
      REPORT=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $EUID -ne 0 ]] || { echo 'Run under intended non-root user; sudo is scoped to apt.' >&2; exit 2; }
[[ -r /etc/os-release ]] || { echo 'Cannot read OS release' >&2; exit 2; }
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo 'Only supported Ubuntu hosts are considered by this draft.' >&2; exit 2; }
[[ $(uname -m) == x86_64 ]] || { echo 'This draft supports x86_64 only.' >&2; exit 2; }
if [[ $MODE == apply && "${VERSION_ID:-}" != "24.04" ]]; then
  echo 'Apply is restricted to Ubuntu 24.04 x86_64 until other releases are validated.' >&2
  exit 2
fi
command -v dpkg-query >/dev/null || { echo 'dpkg-query unavailable' >&2; exit 2; }
command -v apt-get >/dev/null || { echo 'apt-get unavailable' >&2; exit 2; }

umask 077
if [[ -z $REPORT ]]; then
  REPORT=$(mktemp "${HOME:?}/CAPEv2_PreVM_Prereqs_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")
else
  [[ $REPORT == /* && ! -L $REPORT && ! -e $REPORT ]] || {
    echo 'Report must be a new absolute nonsymlink path.' >&2; exit 2;
  }
  ( set -C; : > "$REPORT" ) || exit 2
  chmod 600 "$REPORT"
fi

# The report is private. Check before sharing; never commit raw host reports.
exec > >(tee -a "$REPORT") 2>&1
trap 'printf "[ERROR] Aborted at line %s; partial APT installs are possible.\n" "$LINENO"' ERR

echo 'CAPEv2 pre-VM prerequisite bootstrap'
echo "Mode: $MODE"
echo "Ubuntu release: ${VERSION_ID:-unknown}"
echo 'Only the explicit --apply mode changes installed packages.'

PACKAGES=(python3 python3-venv python3-pip git cpu-checker msr-tools acpica-tools)
missing=()
for pkg in "${PACKAGES[@]}"; do
  if [[ $(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true) == 'install ok installed' ]]; then
    printf '[OK] %s installed\n' "$pkg"
  else
    missing+=("$pkg")
    printf '[MISSING] %s\n' "$pkg"
  fi
done

if (("${#missing[@]}" == 0)); then
  echo '[PASS] All currently defined safe prerequisite packages installed; no changes.'
  exit 0
fi
echo "Missing package count: ${#missing[@]}"
if [[ $MODE == plan ]]; then
  echo '[PLAN] No changes. Run --apply only when ready to install the named packages.'
  exit 0
fi

command -v sudo >/dev/null || { echo 'sudo unavailable; cannot apply.' >&2; exit 3; }
sudo -v || { echo 'sudo permission unavailable; no packages changed.' >&2; exit 3; }
echo '[APPLY] apt-get install ONLY listed missing packages, no upgrade/autoremove.'
# Fail visibly on broken/duplicate/mixed APT sources or locks; do not edit them.
sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "${missing[@]}"
echo '[VERIFY] Installed-package status after APT:'
for pkg in "${missing[@]}"; do
  status=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
  [[ $status == 'install ok installed' ]] || { echo "[FAIL] $pkg status: $status"; exit 4; }
  echo "[OK] $pkg installed"
done
echo '[PASS] Provisioned this stage only. KVM/virtualization and malware containment not proven.'
