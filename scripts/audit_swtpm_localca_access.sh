#!/usr/bin/env bash
# Read-only focused swtpm-localca CA statedir ownership/access inspection.
# Never execute swtpm_setup or alter VM, service, permissions or CA contents.
set -u
umask 077

sudo -v || exit 1
REPORT=$(mktemp "${HOME:?}/SSL55_Step12G_LocalCA_Access_$(date +%Y%m%d_%H%M%S)_XXXXXXXX.txt") || exit 1
CA="/var/lib/swtpm-localca"

{
  echo "========== SWTPM LOCAL CERTIFICATE AUTHORITY STATE DIRECTORY =========="
  echo "Read-only. No permission, package, TPM or VM modifications."

  echo
  echo "========== EXPECTED SERVICE ACCOUNT =========="
  if getent passwd tss >/dev/null && getent group tss >/dev/null; then
    echo "tss account/group: PRESENT"
  else
    echo "tss account/group: MISSING/UNRESOLVED"
  fi

  echo
  echo "========== PARENT PATH TRAVERSAL =========="
  sudo namei -l -- "$CA" 2>&1 || true

  echo
  echo "========== TARGET TYPE/OWNERSHIP/MODE =========="
  if sudo test -L "$CA"; then
    echo "TARGET IS A SYMLINK: STOP; NEVER REPLACE AUTOMATICALLY."
  elif sudo test -d "$CA"; then
    sudo stat -c 'Type=%F Owner=%U:%G Mode=%a Permissions=%A' -- "$CA"
    echo
    echo "========== EXACT USER tss ACCESS =========="
    for access in r w x; do
      case "$access" in
        r) desc=read ;;
        w) desc=write ;;
        x) desc=traverse ;;
      esac
      if sudo -n -u tss test "-$access" "$CA" 2>/dev/null; then
        echo "$desc: YES"
      else
        echo "$desc: NO"
      fi
    done
    echo
    echo "========== DIRECT CHILD METADATA ONLY =========="
    echo "Only names/owners/modes, NOT private CA contents."
    sudo find "$CA" -mindepth 1 -maxdepth 1 \
      -printf '%f | %y | owner=%u:%g | mode=%m\n' 2>&1 | head -n 40
    echo
    echo "========== DIRECT CHILD COUNT =========="
    count=$(sudo find "$CA" -mindepth 1 -maxdepth 1 -printf '.' 2>/dev/null | wc -c)
    echo "Direct children: $count"
  elif sudo test -e "$CA"; then
    echo "Target exists but is NOT a directory: STOP."
  else
    echo "Target directory MISSING."
  fi

  echo
  echo "========== END READ-ONLY INSPECTION =========="
} > "$REPORT" 2>&1

echo "Local CA access report saved to: $REPORT"
echo "Review it for sensitive details and upload the TXT report."
