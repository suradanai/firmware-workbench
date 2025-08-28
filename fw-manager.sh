#!/usr/bin/env bash
#
# Firmware Workbench Manager (All-in-One)
# ---------------------------------------
# Subcommands:
#   install        สร้าง venv + ติดตั้ง deps + clone/build FMK
#   run            รัน GUI (activate venv อัตโนมัติ)
#   update         git pull ตัวโปรเจ็กต์ + FMK + pip upgrade
#   clean          ล้าง venv (ถามยืนยัน) และ build artifacts
#   envinfo        แสดงข้อมูลแวดล้อม (debug)
#
# Options (env หรือ export ก่อนเรียกก็ได้):
#   FW_VENV         ชื่อโฟลเดอร์ venv (default .venv)
#   FW_FMK_DIR      Path FMK (default external/firmware_mod_kit)
#   FW_NO_BINWALK   =1 เพื่อข้าม pip install binwalk
#   FW_PIP_MIRROR   ระบุ index-url (ถ้าต้องการ)
#
set -euo pipefail

# -------- Config Defaults --------
FW_VENV="${FW_VENV:-.venv}"
FW_FMK_DIR="${FW_FMK_DIR:-external/firmware_mod_kit}"
FW_PIP_MIRROR="${FW_PIP_MIRROR:-}"
FW_NO_BINWALK="${FW_NO_BINWALK:-0}"
REQ_FILE="requirements.txt"
CONFIG_FILE="config.yaml"

C_GREEN='\033[32m'; C_RED='\033[31m'; C_YELLOW='\033[33m'; C_RESET='\033[0m'
log(){ echo -e "${C_GREEN}[FW]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[FW] WARN:${C_RESET} $*"; }
err(){ echo -e "${C_RED}[FW] ERR:${C_RESET}  $*" >&2; }

command_exists(){ command -v "$1" >/dev/null 2>&1; }

ensure_requirements() {
  if [ ! -f "$REQ_FILE" ]; then
    warn "ไม่พบ $REQ_FILE สร้างใหม่พื้นฐาน"
    cat > "$REQ_FILE" <<EOF
PySide6>=6.4.0
passlib>=1.7.4
PyYAML>=6.0
EOF
  fi
}

create_or_replace_venv() {
  if [ -d "$FW_VENV" ]; then
    read -p "พบ venv เดิม ($FW_VENV) ต้องการลบทิ้งสร้างใหม่หรือไม่? [y/N]: " ans
    if [[ "${ans,,}" == "y" ]]; then
      rm -rf "$FW_VENV"
    else
      log "ใช้ venv เดิม"
      return
    fi
  fi
  python3 -m venv "$FW_VENV"
  log "สร้าง venv สำเร็จ: $FW_VENV"
}

activate_venv() {
  # shellcheck disable=SC1090
  source "$FW_VENV/bin/activate"
}

pip_install_project() {
  local extra=()
  if [ -n "$FW_PIP_MIRROR" ]; then
    extra+=( "--index-url" "$FW_PIP_MIRROR" )
  fi
  pip install --upgrade pip setuptools wheel
  pip install "${extra[@]}" -r "$REQ_FILE"
  if [ "$FW_NO_BINWALK" != "1" ]; then
    pip install "${extra[@]}" binwalk
  else
    warn "ข้ามการติดตั้ง binwalk (FW_NO_BINWALK=1)"
  fi
}

clone_or_update_fmk() {
  if [ -d "$FW_FMK_DIR/.git" ]; then
    log "อัปเดต FMK (git pull)"
    (cd "$FW_FMK_DIR" && git pull --ff-only || true)
  else
    log "Clone FMK → $FW_FMK_DIR"
    mkdir -p "$(dirname "$FW_FMK_DIR")"
    git clone https://github.com/rampageX/firmware-mod-kit.git "$FW_FMK_DIR"
  fi
}

build_fmk() {
  if [ ! -d "$FW_FMK_DIR/src" ]; then
    err "ไม่พบ $FW_FMK_DIR/src"
    exit 1
  fi
  log "Build FMK tools"
  (cd "$FW_FMK_DIR/src" && make -j1)
}

ensure_config() {
  if [ ! -f "$CONFIG_FILE" ]; then
    log "สร้าง $CONFIG_FILE"
    cat > "$CONFIG_FILE" <<EOF
fmk:
  root: ${FW_FMK_DIR#./}
  use_sudo_extract: auto
  use_sudo_build: auto
EOF
  else
    # update root ถ้าไม่ตรง
    if ! grep -q "root:" "$CONFIG_FILE"; then
      printf "\n# appended by fw-manager\nfmk:\n  root: %s\n  use_sudo_extract: auto\n  use_sudo_build: auto\n" "${FW_FMK_DIR#./}" >> "$CONFIG_FILE"
    fi
  fi
}

create_run_wrapper() {
  cat > run.sh <<EOF
#!/usr/bin/env bash
set -e
SCRIPT_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
if [ ! -d "\$SCRIPT_DIR/$FW_VENV" ]; then
  echo "ไม่พบ venv: $FW_VENV (รัน ./fw-manager.sh install ก่อน)" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "\$SCRIPT_DIR/$FW_VENV/bin/activate"
exec python app.py "\$@"
EOF
  chmod +x run.sh
  log "สร้าง run.sh แล้ว"
}

make_executable_self() {
  # ให้สิทธิ์รันตัวเองและ run.sh (ถ้ามี)
  chmod +x "$0" 2>/dev/null || true
  [ -f run.sh ] && chmod +x run.sh || true
}

sub_install() {
  if ! command_exists python3; then
    err "ไม่พบ python3 กรุณาติดตั้งก่อน"
    exit 1
  fi
  ensure_requirements
  create_or_replace_venv
  activate_venv
  pip_install_project
  clone_or_update_fmk
  build_fmk
  ensure_config
  create_run_wrapper
  make_executable_self
  log "ติดตั้งเสร็จ! ใช้: ./fw-manager.sh run  หรือ  ./run.sh"
}

sub_run() {
  if [ ! -d "$FW_VENV" ]; then
    err "ไม่พบ venv: $FW_VENV (รัน ./fw-manager.sh install ก่อน)"
    exit 1
  fi
  activate_venv
  if [ ! -f app.py ]; then
    err "ไม่พบ app.py ในไดเรกทอรีปัจจุบัน"
    exit 1
  fi
  python app.py "$@"
}

sub_update() {
  if [ ! -d "$FW_VENV" ]; then
    err "ไม่มี venv (install ก่อน)"
    exit 1
  fi
  activate_venv
  log "อัปเดต repo หลัก (ถ้าเป็น git)"
  if [ -d .git ]; then
    git pull --ff-only || warn "pull โปรเจ็กต์ล้มเหลว"
  fi
  log "อัปเดต FMK"
  clone_or_update_fmk
  build_fmk
  log "อัปเกรด Python deps"
  pip install --upgrade -r "$REQ_FILE"
  [ "$FW_NO_BINWALK" != "1" ] && pip install --upgrade binwalk || true
  log "อัปเดตเสร็จ"
}

sub_clean() {
  read -p "ยืนยันลบ venv ($FW_VENV) และไฟล์ build บางส่วน? [y/N]: " ans
  if [[ "${ans,,}" == "y" ]]; then
    rm -rf "$FW_VENV"
    find . -name "__pycache__" -type d -exec rm -rf {} +
    log "ล้างเสร็จ"
  else
    log "ยกเลิก"
  fi
}

sub_envinfo() {
  echo "Python: $(command -v python3 2>/dev/null || echo '-')"
  [ -d "$FW_VENV" ] && echo "Venv: $FW_VENV (yes)" || echo "Venv: missing"
  echo "FMK Dir: $FW_FMK_DIR"
  echo "Config: $CONFIG_FILE"
  echo "run.sh: $( [ -x run.sh ] && echo executable || echo missing )"
}

show_help() {
  cat <<EOF
Usage: $0 <command>

Commands:
  install       ติดตั้งทั้งหมด (venv, deps, FMK, run.sh)
  run [args]    รันโปรแกรม (GUI) (ผ่าน venv)
  update        อัปเดตโปรเจ็กต์ + FMK + deps
  clean         ลบ venv และไฟล์ pycache
  envinfo       แสดงข้อมูลสภาพแวดล้อม
  help          แสดงหน้านี้

Environment overrides:
  FW_VENV, FW_FMK_DIR, FW_NO_BINWALK, FW_PIP_MIRROR

ตัวอย่าง:
  $0 install
  $0 run
  FW_NO_BINWALK=1 $0 install
  $0 update
EOF
}

main() {
  cmd="${1:-help}"; shift || true
  case "$cmd" in
    install) sub_install "$@";;
    run) sub_run "$@";;
    update) sub_update "$@";;
    clean) sub_clean "$@";;
    envinfo) sub_envinfo ;;
    help|--help|-h) show_help ;;
    *) err "ไม่รู้จักคำสั่ง: $cmd"; show_help; exit 1;;
  esac
}

main "$@"