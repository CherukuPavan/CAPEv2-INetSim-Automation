#!/usr/bin/env bash
# DRAFT: Manual SSL-55 Step 4 -> fresh-host Git prerequisite + CAPEv2 source clone.
# This is NOT one of the final three deployment entrypoints.
# Never run this during read-only preflight. It installs git if missing and
# clones CAPEv2 only when explicitly executed as an installer component.
set -Eeuo pipefail
export LC_ALL=C

SOURCE_URL='https://github.com/kevoreilly/CAPEv2.git'
DESTINATION="${HOME:?HOME must be set}/CAPEv2"
REVISION=''
TEMP_DIR=''

log()   { printf '[INFO] %s\n' "$*"; }
warn()  { printf '[WARN] %s\n' "$*" >&2; }
error() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
    rm -rf -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT
trap 'warn "Bootstrap failed near line $LINENO. Any existing CAPEv2 checkout was left unchanged."' ERR

usage() {
  cat <<'USAGE'
Usage: bash scripts/bootstrap_cape_source.sh [--destination DIR] [--source-url URL] [--revision FULL_COMMIT_SHA]

Draft module: check/install Git on Ubuntu, then clone the CAPEv2 source as the
current non-root user. Existing clone is verified and never overwritten.
Use --revision with a verified full (40-character) commit SHA for reproducible
installations. Without it, this draft follows the remote default branch.
USAGE
}

while (( $# )); do
  case "$1" in
    --destination|--source-url|--revision)
      (( $# >= 2 )) || error "Missing value for $1"
      case "$1" in
        --destination) DESTINATION=$2 ;;
        --source-url) SOURCE_URL=$2 ;;
        --revision) REVISION=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) error "Unknown argument: $1" ;;
  esac
done

[[ -n "$SOURCE_URL" ]] || error 'Source URL must not be empty'
[[ -n "$DESTINATION" && "$DESTINATION" = /* ]] || error 'Destination must be an absolute path'
[[ "$DESTINATION" != / ]] || error 'Destination cannot be root directory'
[[ ! -L "$DESTINATION" ]] || error 'Refusing symbolic-link destination'
if [[ -n "$REVISION" && ! "$REVISION" =~ ^[0-9a-fA-F]{40}$ ]]; then
  error 'Revision must be an exact full 40-hex-character Git commit SHA'
fi

if (( EUID == 0 )); then
  error 'Run as the intended non-root user. Only the missing-package installation uses sudo.'
fi

if [[ ! -r /etc/os-release ]]; then
  error 'Cannot determine host operating system'
fi
# /etc/os-release is trusted local OS metadata.
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || error 'This draft currently supports Ubuntu only'
log "Detected OS: ${PRETTY_NAME:-Ubuntu (release unknown)}"

if command -v git >/dev/null 2>&1; then
  git --version >/dev/null || error 'Git executable was found but does not work; refusing replacement'
  log "Using existing $(git --version)"
else
  log 'Git missing; preparing to install only the git package and required dependencies'
  command -v apt-get >/dev/null 2>&1 || error 'apt-get unavailable; cannot bootstrap Git'
  command -v sudo >/dev/null 2>&1 || error 'sudo unavailable; cannot install Git as non-root user'
  # Do not hide package source, signature, privilege, or APT lock failures.
  sudo -v || error 'sudo authentication/authorization failed'
  sudo apt-get update || error 'APT metadata refresh failed (sources/locks/network require attention)'
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends git || error 'Git installation failed'
  command -v git >/dev/null 2>&1 || error 'Git missing even after package installation'
  git --version >/dev/null || error 'Installed Git cannot run'
  log "Installed $(git --version)"
fi

# Normalize parent to avoid accidentally writing outside the intended user tree.
PARENT=$(dirname -- "$DESTINATION")
BASENAME=$(basename -- "$DESTINATION")
[[ "$BASENAME" != . && "$BASENAME" != .. ]] || error 'Invalid destination'
[[ -d "$PARENT" ]] || error "Destination parent does not exist: $PARENT"
[[ -w "$PARENT" ]] || error "Destination parent is not writable: $PARENT"
CANONICAL_PARENT=$(cd -- "$PARENT" && pwd -P)
DESTINATION="$CANONICAL_PARENT/$BASENAME"

if [[ -e "$DESTINATION" ]]; then
  [[ -d "$DESTINATION" ]] || error "Destination exists and is not a directory: $DESTINATION"
  [[ -d "$DESTINATION/.git" || -f "$DESTINATION/.git" ]] || error 'Existing destination is not a Git checkout; refusing overwrite'
  [[ $(stat -c '%u' -- "$DESTINATION") == "$(id -u)" ]] || error 'Checkout belongs to another user (possibly from sudo git clone); refusing ownership change'
  CHECKOUT_ROOT=$(git -C "$DESTINATION" rev-parse --show-toplevel 2>/dev/null) || error 'Cannot inspect existing checkout'
  [[ "$CHECKOUT_ROOT" == "$DESTINATION" ]] || error 'Existing checkout location does not match its Git root'
  ORIGIN=$(git -C "$DESTINATION" remote get-url origin 2>/dev/null) || error 'Existing checkout has no origin remote'
  [[ "$ORIGIN" == "$SOURCE_URL" ]] || error "Existing checkout remote differs from expected source; refusing mutation"
  HEAD_SHA=$(git -C "$DESTINATION" rev-parse --verify HEAD^{commit}) || error 'No valid HEAD commit in existing checkout'
  if [[ -n "$REVISION" && "${HEAD_SHA,,}" != "${REVISION,,}" ]]; then
    error 'Existing checkout revision differs from requested pinned SHA; refusing automatic fetch/reset'
  fi
  log "Verified existing checkout; no changes: $DESTINATION"
  log "CAPEv2 HEAD: $HEAD_SHA"
  exit 0
fi

if [[ -z "$REVISION" ]]; then
  warn 'No revision pinned: the remote default branch may change. Pin a verified commit for production.'
fi

TEMP_DIR=$(mktemp -d -- "$CANONICAL_PARENT/.cape-source.XXXXXXXX") || error 'Cannot create temporary clone directory'
log "Cloning source to a temporary directory (as $(id -un)); no sudo for Git"
git clone -- "$SOURCE_URL" "$TEMP_DIR/repository" || error 'Git clone failed'
if [[ -n "$REVISION" ]]; then
  git -C "$TEMP_DIR/repository" cat-file -e "$REVISION^{commit}" || error 'Pinned Git commit is not present in the cloned repository'
  git -C "$TEMP_DIR/repository" checkout --detach "$REVISION" || error 'Could not check out the pinned revision'
fi
HEAD_SHA=$(git -C "$TEMP_DIR/repository" rev-parse --verify HEAD^{commit}) || error 'Cloned repository has no commit'
[[ ! -e "$DESTINATION" ]] || error 'Destination appeared during cloning; leaving it unchanged'
mv -T -- "$TEMP_DIR/repository" "$DESTINATION" || error 'Unable to place checkout at destination'
log "CAPEv2 checkout ready: $DESTINATION"
log "CAPEv2 HEAD: $HEAD_SHA"
log 'Source checkout is not CAPEv2 installation, service configuration, or VM validation.'
