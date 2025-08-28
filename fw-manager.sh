#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$PROJECT_ROOT/config.yaml"

# Default FMK root (สามารถอ่านจาก config.yaml จริง ๆ ได้ถ้าคุณ parse)
FMK_ROOT="$PROJECT_ROOT/external/firmware_mod_kit"

# -------------- Utilities -----------------
log() { printf "[FW-MGR] %s\n" "$*" >&2; }

die() { log "ERROR: $*"; exit 1; }

ensure_bin() {
  local b="$1"
  command -v "$b" >/dev/null 2>&1 || die "Required tool '$b' not found (install via apt/pip)."
}

sanitize_firmware_path() {
  local orig="$1"
  if [[ ! -f "$orig" ]]; then
    die "Firmware file not found: $orig"
  fi
  if [[ "$orig" =~ [[:space:]] ]]; then
    mkdir -p "$PROJECT_ROOT/input_sanitized"
    local base="$(basename "$orig")"
    local safe="$PROJECT_ROOT/input_sanitized/${base// /_}"
    if [ ! -f "$safe" ]; then
      cp -- "$orig" "$safe"
      log "Sanitized copy -> $safe"
    fi
    printf "%s" "$safe"
  else
    printf "%s" "$orig"
  fi
}

clone_or_update_fmk() {
  if [ -d "$FMK_ROOT/.git" ]; then
    log "Updating FMK..."
    git -C "$FMK_ROOT" pull --ff-only || log "FMK pull failed (ignore if offline)"
  else
    mkdir -p "$(dirname "$FMK_ROOT")"
    log "Cloning FMK..."
    git clone --depth=1 https://github.com/rampageX/firmware-mod-kit.git "$FMK_ROOT"
  fi
}

perform_extract_fmk() {
  local fw="$1"
  local ws="$2"
  mkdir -p "$ws"
  log "Attempt multi-squash via FMK -> $ws"
  if "$FMK_ROOT/extract-multisquashfs-firmware.sh" "$fw" "$ws"; then
    log "Multi-squash success"
    return 0
  fi
  log "Multi failed, try single..."
  if "$FMK_ROOT/extract-firmware.sh" "$fw" "$ws"; then
    log "Single extract success"
    return 0
  fi
  return 1
}

fallback_auto_carve() {
  local fw="$1" ws="$2"
  if [ -x "$PROJECT_ROOT/scripts/extract_multi_auto.sh" ]; then
    log "Fallback: scripts/extract_multi_auto.sh"
    "$PROJECT_ROOT/scripts/extract_multi_auto.sh" "$fw" "${ws}_carve" && return 0
  fi
  log "No fallback script available."
  return 1
}

do_extract() {
  local firmware="$1"
  [ -f "$firmware" ] || die "Input firmware not found: $firmware"
  ensure_bin binwalk
  ensure_bin unsquashfs

  local sanitized
  sanitized="$(sanitize_firmware_path "$firmware")"
  local ws="$PROJECT_ROOT/workspaces/ws_$(date +%Y%m%d_%H%M%S)"

  if perform_extract_fmk "$sanitized" "$ws"; then
    log "Extract finished with FMK."
    return 0
  fi
  log "FMK extraction failed -> fallback"
  if fallback_auto_carve "$sanitized" "$ws"; then
    log "Fallback carve completed."
    return 0
  fi
  die "All extraction methods failed."
}

usage() {
  cat <<EOF
Firmware Workbench Manager
Usage: $0 <command> [args]

Commands:
  install               Clone/update firmware-mod-kit
  extract <firmware>    Extract firmware (FMK -> fallback carve)
  update                Update FMK
  help                  Show this help
EOF
}

case "${1:-}" in
  install)
    clone_or_update_fmk
    ;;
  update)
    clone_or_update_fmk
    ;;
  extract)
    shift
    [ $# -ge 1 ] || die "extract requires <firmware_path>"
    clone_or_update_fmk
    do_extract "$1"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac