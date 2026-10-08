#!/usr/bin/env bash
# Read-only early-stage host and KVM preflight for the CAPEv2/INetSim project.
# Derived from SSL-55 canonical manual Steps 1-3. Does not install or configure.
set -u
export LC_ALL=C

issues=0
warnings=0
fail() { printf 'FAIL: %s\n' "$*"; issues=$((issues + 1)); }
warn() { printf 'WARN: %s\n' "$*"; warnings=$((warnings + 1)); }
info() { printf 'INFO: %s\n' "$*"; }

printf '%s\n' '=== Host identification ==='
if command -v hostname >/dev/null 2>&1; then
  info "Hostname: $(hostname)"
else
  warn 'hostname utility not found'
fi
info "Kernel: $(uname -srmo)"

if [[ -r /etc/os-release ]]; then
  # /etc/os-release is the OS's standard metadata file; no OS modifications.
  # shellcheck disable=SC1091
  . /etc/os-release
  info "OS: ${PRETTY_NAME:-unknown}"
  if [[ "${ID:-}" != ubuntu ]]; then
    warn 'OS is not identified as Ubuntu; compatibility must be reviewed'
  fi
else
  warn '/etc/os-release is unavailable; distribution could not be identified'
fi

printf '\n%s\n' '=== Network interfaces (no IP addresses recorded) ==='
if command -v ip >/dev/null 2>&1; then
  if interfaces=$(ip -br link 2>/dev/null); then
    printf '%s\n' "$interfaces" | awk '{print "INFO: " $1 " " $2}'
  else
    warn 'Unable to enumerate network interfaces'
  fi
else
  warn 'ip utility not available'
fi

printf '\n%s\n' '=== CPU virtualization feature flags ==='
if [[ -r /proc/cpuinfo ]]; then
  flag_count=$(awk -F: '/^flags[[:space:]]*:/ {if ($2 ~ /(^|[[:space:]])(vmx|svm)([[:space:]]|$)/) n++} END {print n+0}' /proc/cpuinfo)
  info "Logical CPU records exposing vmx/svm: $flag_count (NOT physical core count)"
  if (( flag_count == 0 )); then
    fail 'No exposed Intel VMX or AMD SVM flags found in /proc/cpuinfo'
  fi
else
  fail 'Cannot read /proc/cpuinfo'
fi

printf '\n%s\n' '=== KVM kernel/device availability ==='
if command -v lsmod >/dev/null 2>&1; then
  info 'Loaded KVM-related modules (none listed may also mean built-in or not loaded):'
  if modules=$(lsmod 2>/dev/null); then
    printf '%s\n' "$modules" | awk '$1 == "kvm" || $1 == "kvm_intel" || $1 == "kvm_amd" {print "INFO: " $0}'
  else
    warn 'Unable to enumerate kernel modules'
  fi
else
  warn 'lsmod is unavailable; skipping module inventory'
fi
if [[ -c /dev/kvm ]]; then
  info '/dev/kvm character device exists'
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    info '/dev/kvm is readable and writable by this user'
  else
    warn '/dev/kvm exists but this user may lack access; investigate permissions'
  fi
else
  fail '/dev/kvm character device not present'
fi

printf '\n%s\n' '=== Optional cpu-checker result ==='
if command -v kvm-ok >/dev/null 2>&1; then
  if kvm-ok; then
    info 'kvm-ok confirms acceleration can be used'
  else
    fail 'kvm-ok did not confirm acceleration'
  fi
else
  warn 'kvm-ok unavailable (cpu-checker not installed); this check is optional'
fi

printf '\nSummary: %s failure(s), %s warning(s). No changes made.\n' "$issues" "$warnings"
if (( issues > 0 )); then
  exit 1
fi
exit 0
