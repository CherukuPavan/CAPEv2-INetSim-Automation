#!/usr/bin/env bash
# Partial Command-1 pre-VM implementation (SSL-55 verified manual Steps 1-11).
# Intentionally NOT the finished three-command installer: VM creation, complex
# hypervisor build, CAPE base install and INetSim are not safe to auto-apply yet.
set -Eeuo pipefail

HERE=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

usage() {
  cat <<'HELP'
Usage: bash scripts/command1_pre_vm.sh MODE [component options]

Modes:
  audit                   Consolidated read-only Steps 1-11 report.
  plan-prereqs            Read-only missing-package plan.
  apply-prereqs           Explicitly install only known-safe missing base packages.
  bootstrap-source        Fresh-host Git clone, or verify existing owned checkout.
  plan-virt               Read-only distro virtualization package preflight (Steps 6-9).
  apply-virt              Controlled distro QEMU/libvirt install (not custom build).
  audit-installers        Static risk audit of local upstream installer scripts.
  inspect-media FILE      Read-only completed Windows archive/ISO metadata and SHA256.
  preflight-windows       Read-only guest capacity, OVMF/TPM, libvirt NAT & ISO access report.
  plan-optionals          Inspect CAPE service-account optional dependencies.
  apply-optionals         Explicit, lockfile-gated optional dependency install.
  master-checkpoint       Read-only final Windows master/snapshot handoff (after guest setup).
  master-export           Plan/capture/verify exact cold win11 Windows disk + OVMF + TPM golden bundle.
  master-import           Plan/stage/verify a PRIVATE golden bundle on a separate approved host.
  host-acceptance         Consolidated read-only host + finished-master dependency report.
  reference-evidence      Review a supplied SSL-55 JSON reference (read-only).
  source-export-capacity  Read-only actual master disk + TPM metadata, export disk-space check (requires root).
  source-deep-fingerprint One consolidated root-only SSL55 CAPE revision/QEMU/INetSim/master-space report.
  safe-space-audit        READ-ONLY filesystem and candidate cache sizes, NEVER delete Win11/TPM/CAPE assets.
  ssl46-lan-stage         Plan/export/verify/upload exact cold master THROUGH approved SSHFS on SSL46.
  coverage                Show human-reviewed automation coverage/status documentation.

Examples:
  bash scripts/command1_pre_vm.sh audit
  bash scripts/command1_pre_vm.sh plan-prereqs
  bash scripts/command1_pre_vm.sh plan-virt
  bash scripts/command1_pre_vm.sh plan-optionals
  # Explicit application commands require user review:
  bash scripts/command1_pre_vm.sh apply-virt
  bash scripts/command1_pre_vm.sh apply-optionals --expected-sha256 <SHA>
  bash scripts/command1_pre_vm.sh apply-prereqs
  bash scripts/command1_pre_vm.sh bootstrap-source --revision <SHA40>

This PARTIAL command implements only verified, low-risk portions of Steps 1-11.
It WILL NOT silently run kvm-qemu.sh all, cape2.sh base, make ACPI changes,
edit sysctl/GRUB/modprobe, alter host networking, create VM guests, reset
services, start malware or silently install optional packages into the wrong account.
See docs/AUTOMATION_COVERAGE_STEPS_1_11.md for gaps and release gates.
HELP
}

MODE=${1:-}
if [[ -z $MODE || $MODE == -h || $MODE == --help ]]; then
  usage
  exit 0
fi
shift

case "$MODE" in
  audit)
    (($# == 0)) || { usage >&2; exit 2; }
    command -v python3 >/dev/null 2>&1 || {
      echo 'Python3 missing. Use plan-prereqs then apply-prereqs if authorized.' >&2
      exit 2
    }
    exec python3 "$HERE/audit_pre_vm_stages.py"
    ;;
  plan-prereqs)
    exec bash "$HERE/bootstrap_pre_vm_prereqs.sh" --plan "$@"
    ;;
  apply-prereqs)
    exec bash "$HERE/bootstrap_pre_vm_prereqs.sh" --apply "$@"
    ;;
  bootstrap-source)
    exec bash "$HERE/bootstrap_cape_source.sh" "$@"
    ;;
  plan-virt)
    exec bash "$HERE/bootstrap_virtualization_stack.sh" --plan "$@"
    ;;
  apply-virt)
    exec bash "$HERE/bootstrap_virtualization_stack.sh" --apply "$@"
    ;;
  audit-installers)
    (($# == 0)) || { usage >&2; exit 2; }
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    SOURCE="${HOME:?}/CAPEv2/installer"
    OUT=$(mktemp "${HOME}/CAPEv2_InstallerRisk_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.json")
    rm -f -- "$OUT"
    exec python3 "$HERE/audit_upstream_installers.py" \
      --kvm "$SOURCE/kvm-qemu.sh" \
      --cape "$SOURCE/cape2.sh" \
      --report "$OUT"
    ;;
  inspect-media)
    (($# == 1)) || { usage >&2; exit 2; }
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    exec python3 "$HERE/inspect_windows_media.py" "$1"
    ;;
  preflight-windows)
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    exec python3 "$HERE/audit_windows_vm_preflight.py" "$@"
    ;;
  plan-optionals)
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    REPORT="${HOME:?}/CAPEv2_OptionalPlan_$(date +%Y%m%d_%H%M%S)_$_R.json"
    exec python3 "$HERE/install_cape_optional_deps.py" --mode plan --report "$REPORT" "$@"
    ;;
  apply-optionals)
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    REPORT="${HOME:?}/CAPEv2_OptionalApply_$(date +%Y%m%d_%H%M%S)_$_R.json"
    exec python3 "$HERE/install_cape_optional_deps.py" --mode apply --report "$REPORT" "$@"
    ;;
  host-acceptance)
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    REPORT="${HOME:?}/cape_command12_acceptance_$(date +%Y%m%d_%H%M%S)_$.txt"
    exec python3 "$HERE/audit_command12_acceptance.py" --output "$REPORT" "$@"
    ;;
  master-checkpoint)
    command -v python3 >/dev/null 2>&1 || { echo 'Python3 missing' >&2; exit 2; }
    REPORT="${HOME:?}/cape_command1_master_checkpoint_$(date +%Y%m%d_%H%M%S)_$.json"
    exec python3 "$HERE/command1_master_checkpoint.py" --report "$REPORT" "$@"
    ;;
  reference-evidence)
    exec python3 -B "$HERE/command1_reference_report_gate.py" "$@"
    ;;
  source-export-capacity)
    exec python3 -B "$HERE/command1_actual_master_export_capacity.py" "$@"
    ;;
  source-deep-fingerprint)
    exec python3 -B "$HERE/command1_ssl55_deep_fingerprint.py" "$@"
    ;;
  safe-space-audit)
    exec python3 -B "$HERE/command1_ssl55_safe_space_audit.py" "$@"
    ;;
  ssl46-lan-stage)
    exec python3 -B "$HERE/command1_ssl46_sshfs_master_stage.py" "$@"
    ;;
  master-export)
    exec python3 -B "$HERE/command1_export_existing_master.py" "$@"
    ;;
  master-import)
    exec python3 -B "$HERE/command1_import_existing_master.py" "$@"
    ;;

  coverage)
    (($# == 0)) || { usage >&2; exit 2; }
    DOC="$HERE/../docs/AUTOMATION_COVERAGE_STEPS_1_11.md"
    [[ -r $DOC ]] || { echo 'Coverage document missing' >&2; exit 2; }
    exec cat "$DOC"
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
