#!/usr/bin/env bash
# Supported Ubuntu 24.04 distro virtualization bootstrap, NOT an exact replacement
# for CAPEv2's source-built QEMU/SeaBIOS/libvirt. The upstream "all" option was
# observed to purge/pin packages and mask sleep targets even on --help.
# This installer never invokes it, rewrites modprobe/sysctl/grub or reboots.
set -Eeuo pipefail
umask 077

MODE=plan
REPORT=''
usage() {
  cat <<'HELP'
Usage: bash scripts/bootstrap_virtualization_stack.sh [--plan|--apply] [--report ABSOLUTE_NEW_TXT]

--plan (default): read-only binary/package/apt simulation plan.
--apply: explicitly install only missing distro QEMU/libvirt/virt-manager
         packages IF no custom/source-managed binary is already present and
         APT simulation proposes no removals or upgrades.
Requires Ubuntu 24.04 x86_64 for apply; an independent CAPE compatibility and
VM/guest isolation acceptance test is still required. NO host-wide firmware,
power, GRUB, sysctl, network, KVM modprobe or package-purge changes are made
by this script beyond normal package-manager installation effects.
HELP
}
while (($#)); do
  case "$1" in
    --plan) MODE=plan; shift ;;
    --apply) MODE=apply; shift ;;
    --report)
      (($#>=2)) || { echo 'Missing report path' >&2; exit 2; }
      REPORT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $EUID -ne 0 ]] || { echo 'Run as regular Ubuntu account, not root.' >&2; exit 2; }
[[ -r /etc/os-release ]] || exit 2
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo 'Ubuntu only.' >&2; exit 2; }
if [[ $MODE == apply && ("${VERSION_ID:-}" != 24.04 || $(uname -m) != x86_64) ]]; then
  echo 'Apply currently supports only Ubuntu 24.04 x86_64.' >&2
  exit 2
fi
command -v apt-get >/dev/null || { echo 'APT missing' >&2; exit 2; }

if [[ -n "$REPORT" ]]; then
  [[ $REPORT == /* && ! -e $REPORT && ! -L $REPORT ]] || { echo 'Report path exists or is not absolute' >&2; exit 2; }
  (set -C; : > "$REPORT") || exit 2
else
  REPORT=$(mktemp "$HOME/CAPEv2_VirtualizationPlan_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt")
fi
chmod 600 "$REPORT"
exec > >(tee -a "$REPORT") 2>&1
trap 'echo "Bootstrap stopped at line $LINENO; no rollback of any partial APT transaction claimed."' ERR

echo "Virtualization stage: $MODE"
echo "Ubuntu ${VERSION_ID:-unknown}, architecture $(uname -m)"
echo 'This is NOT approval to connect an analysis guest to the default NAT network.'

# Package / binary mapping. Detect source installed QEMU, libvirt, GUI first;
# do not use APT on top of an existing manually installed custom build.
declare -A BIN=(
 [qemu-system-x86]=qemu-system-x86_64
 [qemu-utils]=qemu-img
 [libvirt-clients]=virsh
 [libvirt-daemon-system]=libvirtd
 [virt-manager]=virt-manager
 [virtinst]=virt-install
 [ovmf]=
 [swtpm]=swtpm
)
packages=(qemu-system-x86 qemu-utils libvirt-clients libvirt-daemon-system virt-manager virtinst ovmf swtpm)
missing=()
external=0

for pkg in "${packages[@]}"; do
  state=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
  if [[ "$state" == 'install ok installed' ]]; then
    echo "[PRESENT] $pkg (APT managed)"
    continue
  fi
  b="${BIN[$pkg]}"
  if [[ -n "$b" ]] && command -v "$b" >/dev/null 2>&1; then
    echo "[EXTERNAL] $pkg: $b already exists but is not packaged; preserve custom build."
    external=1
  else
    echo "[MISSING] $pkg"
    missing+=("$pkg")
  fi
done

if (( external )); then
  echo '[GATE] Custom/source-managed components detected; refusing to overlay Ubuntu packages.'
  echo 'Review QEMU/libvirt version and CAPE compatibility instead of reinstalling/upgrading.'
  exit 3
fi
if (("${#missing[@]}" == 0)); then
  echo '[PASS] All listed APT components installed; guest VM startup/isolation still untested.'
  exit 0
fi

echo "Proposed missing packages: ${missing[*]}"
echo 'APT simulation (no system changes):'
SIM=$(mktemp)
trap 'rm -f "$SIM"' EXIT
if ! apt-get -s install --no-install-recommends "${missing[@]}" >"$SIM" 2>&1; then
  sed -n '1,60p' "$SIM"
  echo '[BLOCKED] APT simulation failed; do not edit repositories automatically.'
  exit 4
fi
grep -E '^(Inst |Remv |Conf )' "$SIM" | sed -n '1,80p' || true
if grep -Eq '^Remv ' "$SIM"; then
  echo '[BLOCKED] APT simulation proposes removing installed packages.'
  exit 4
fi
# If simulated install tries to replace an ALREADY installed package, do not
# silently upgrade/downgrade existing student/shared-host dependencies.
while IFS= read -r name; do
  state=$(dpkg-query -W -f='${Status}' "$name" 2>/dev/null || true)
  if [[ "$state" == 'install ok installed' ]]; then
    echo "[BLOCKED] APT simulation would change already-installed package: $name"
    exit 4
  fi
done < <(awk '$1=="Inst" {print $2}' "$SIM")

if [[ "$MODE" == plan ]]; then
  echo '[PLAN ONLY] No packages installed. Use --apply explicitly if this plan is acceptable.'
  exit 0
fi

command -v sudo >/dev/null || { echo 'sudo missing.' >&2; exit 5; }
sudo -v
echo '[APPLY] Installing only missing listed distro virtualization packages.'
sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "${missing[@]}"
for pkg in "${missing[@]}"; do
  state=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
  [[ "$state" == 'install ok installed' ]] || { echo "[FAILED VERIFICATION] $pkg"; exit 6; }
done
echo '[PASS] Packages installed and verified. KVM/libvirt guest and isolation NOT YET verified.'
