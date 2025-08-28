#!/usr/bin/env bash
#
# Advanced Automated Setup for Firmware Workbench
# ------------------------------------------------
# จุดเด่นเวอร์ชันนี้ (โฟกัสสร้างและตั้งค่า venv ตั้งแต่แรก):
#  1. ตรวจหา Python หลายชื่อ (python3.12, python3.11, python3 ฯลฯ)
#  2. สร้าง virtual environment (venv) ใหม่เสมอ (ค่าเริ่มต้น: .venv) เว้นแต่สั่ง --keep-venv
#  3. รองรับตัวเลือกติดตั้ง system dependencies (apt/dnf/yum/pacman/zypper)
#  4. Clone หรืออัปเดต Firmware Mod Kit (FMK) อัตโนมัติ
#  5. Build FMK tools
#  6. ติดตั้ง Python requirements + optional binwalk
#  7. สร้างไฟล์ run.sh (รัน GUI พร้อม activate venv)
#  8. สร้าง / อัปเดต config.yaml ให้ชี้ FMK root
#  9. มีโหมด offline (ข้าม network clone/pip) + ตรวจ cache
#
# ใช้งานเร็ว:
#   bash setup.sh
#
# ตัวเลือกสำคัญ:
#   --python <path|name>      ระบุ interpreter เอง
#   --venv <dir>              ตั้งชื่อโฟลเดอร์ venv (ค่าเริ่มต้น .venv)
#   --keep-venv               ไม่ลบ venv เดิม (ถ้ามี)
#   --no-system-deps          ไม่ติดตั้งแพ็กเกจระบบ
#   --no-binwalk              ไม่ติดตั้ง binwalk (ผ่าน pip)
#   --fmk-branch <branch>     Checkout branch/tag ของ FMK
#   --force-fmk-reclone       ลบ FMK เดิมก่อน clone ใหม่
#   --offline                 โหมด offline (ไม่ git clone / ไม่ pip install)
#   --requirements <file>     ใช้ไฟล์ requirements.txt อื่น
#   --extra-pip-args "<args>" ส่ง args เพิ่มให้ pip
#   --pip-mirror <url>        ตั้ง index-url ชั่วคราว
#   --skip-build-fmk          ไม่ make FMK (ถ้าสร้างไว้แล้ว)
#   --no-run-wrapper          ไม่สร้าง run.sh
#   --yes                     ไม่ถามยืนยัน (โหมด non-interactive)
#
# ------------------------------------------------

set -euo pipefail

# ---------------- Defaults ----------------
PYTHON_CANDIDATES=("python3.12" "python3.11" "python3.10" "python3.9" "python3")
PYTHON_EXPLICIT=""
VENV_DIR=".venv"
KEEP_VENV=0
INSTALL_SYSTEM_DEPS=1
INSTALL_BINWALK=1
FORCE_FMK_RECLONE=0
FMK_BRANCH=""
OFFLINE=0
REQ_FILE="requirements.txt"
EXTRA_PIP_ARGS=""
PIP_MIRROR=""
SKIP_BUILD_FMK=0
CREATE_RUN_WRAPPER=1
ASSUME_YES=0

ROOT_DIR="$(pwd)"
FMK_DIR="$ROOT_DIR/external/firmware_mod_kit"
CONFIG_FILE="$ROOT_DIR/config.yaml"

# ---------------- Colors ----------------
C_RESET='\033[0m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_BLUE='\033[34m'

log(){ echo -e "${C_GREEN}[SETUP]${C_RESET} $*"; }
info(){ echo -e "${C_BLUE}[INFO] ${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[WARN] ${C_RESET} $*"; }
err(){ echo -e "${C_RED}[ERR ] ${C_RESET} $*" >&2; }

confirm() {
  if [[ $ASSUME_YES -eq 1 ]]; then
    return 0
  fi
  read -r -p "$1 [y/N]: " ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

# ---------------- Parse Args ----------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --python) PYTHON_EXPLICIT="$2"; shift 2;;
    --venv) VENV_DIR="$2"; shift 2;;
    --keep-venv) KEEP_VENV=1; shift;;
    --no-system-deps) INSTALL_SYSTEM_DEPS=0; shift;;
    --no-binwalk) INSTALL_BINWALK=0; shift;;
    --fmk-branch) FMK_BRANCH="$2"; shift 2;;
    --force-fmk-reclone) FORCE_FMK_RECLONE=1; shift;;
    --offline) OFFLINE=1; shift;;
    --requirements) REQ_FILE="$2"; shift 2;;
    --extra-pip-args) EXTRA_PIP_ARGS="$2"; shift 2;;
    --pip-mirror) PIP_MIRROR="$2"; shift 2;;
    --skip-build-fmk) SKIP_BUILD_FMK=1; shift;;
    --no-run-wrapper) CREATE_RUN_WRAPPER=0; shift;;
    --yes|-y) ASSUME_YES=1; shift;;
    -h|--help)
      grep '^# ' "$0" | sed 's/^# //'
      exit 0;;
    *) warn "ไม่รู้จักออปชัน: $1"; shift;;
  esac
done

# ---------------- Detect Package Manager ----------------
PKG_MANAGER=""
if command -v apt-get >/dev/null 2>&1; then
  PKG_MANAGER="apt"
elif command -v dnf >/dev/null 2>&1; then
  PKG_MANAGER="dnf"
elif command -v yum >/dev/null 2>&1; then
  PKG_MANAGER="yum"
elif command -v pacman >/dev/null 2>&1; then
  PKG_MANAGER="pacman"
elif command -v zypper >/dev/null 2>&1; then
  PKG_MANAGER="zypper"
else
  warn "ไม่พบ package manager ที่รู้จัก จะข้ามการติดตั้ง system deps"
  INSTALL_SYSTEM_DEPS=0
fi

maybe_sudo(){
  if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      sudo "$@"
    else
      warn "ไม่มี sudo จะพยายามรันโดยตรง"
      "$@"
    fi
  else
    "$@"
  fi
}

install_system_deps(){
  case "$PKG_MANAGER" in
    apt)
      maybe_sudo apt-get update -y
      maybe_sudo apt-get install -y build-essential zlib1g-dev liblzma-dev liblzo2-dev \
        autoconf automake libtool pkg-config git file squashfs-tools python3-venv python3-dev
      ;;
    dnf)
      maybe_sudo dnf install -y @"Development Tools" zlib-devel xz-devel lzo-devel autoconf automake libtool \
        pkgconfig git file squashfs-tools python3-virtualenv python3-devel
      ;;
    yum)
      maybe_sudo yum groupinstall -y "Development Tools"
      maybe_sudo yum install -y zlib-devel xz-devel lzo-devel autoconf automake libtool \
        pkgconfig git file squashfs-tools python3-devel
      ;;
    pacman)
      maybe_sudo pacman -Sy --noconfirm base-devel zlib xz lzo autoconf automake libtool \
        git file squashfs-tools python python-virtualenv
      ;;
    zypper)
      maybe_sudo zypper --non-interactive install -t pattern devel_C_C++
      maybe_sudo zypper --non-interactive install zlib-devel xz-devel lzo-devel autoconf automake \
        libtool git file squashfs-tools python3-devel python3-virtualenv
      ;;
    *)
      warn "ไม่รองรับ auto install สำหรับ $PKG_MANAGER"
      ;;
  esac
}

# ---------------- Pick Python ----------------
PYTHON_BIN=""
if [[ -n "$PYTHON_EXPLICIT" ]]; then
  if command -v "$PYTHON_EXPLICIT" >/dev/null 2>&1; then
    PYTHON_BIN="$PYTHON_EXPLICIT"
  else
    err "ไม่พบ interpreter: $PYTHON_EXPLICIT"
    exit 1
  fi
else
  for c in "${PYTHON_CANDIDATES[@]}"; do
    if command -v "$c" >/dev/null 2>&1; then
      PYTHON_BIN="$c"; break
    fi
  done
  if [[ -z "$PYTHON_BIN" ]]; then
    err "ไม่พบ Python3 ใด ๆ (ลองติดตั้ง python3 ก่อน)"
    exit 1
  fi
fi
info "เลือกใช้ Python: $PYTHON_BIN ($( $PYTHON_BIN -V ))"

# ---------------- System deps ----------------
if [[ $INSTALL_SYSTEM_DEPS -eq 1 && $OFFLINE -eq 0 ]]; then
  log "ติดตั้ง system dependencies..."
  install_system_deps
else
  info "ข้ามการติดตั้ง system dependencies"
fi

# ---------------- Virtualenv ----------------
if [[ $KEEP_VENV -eq 0 && -d "$VENV_DIR" ]]; then
  if confirm "พบ venv เดิม ($VENV_DIR) ต้องการลบและสร้างใหม่หรือไม่?"; then
    rm -rf "$VENV_DIR"
  else
    warn "ผู้ใช้ยกเลิกการลบ venv แต่สั่ง --keep-venv=0 → จะใช้ venv เดิม"
  fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
  log "สร้าง virtual environment: $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  info "ใช้ venv เดิม: $VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

# ---------------- Upgrade pip ----------------
if [[ $OFFLINE -eq 0 ]]; then
  log "อัปเกรด pip"
  python -m pip install --upgrade pip setuptools wheel >/dev/null
else
  info "โหมด offline: ข้ามอัปเด pip"
fi

# ---------------- Requirements ----------------
if [[ ! -f "$REQ_FILE" ]]; then
  warn "ไม่พบ $REQ_FILE สร้างไฟล์ใหม่พื้นฐาน"
  cat > "$REQ_FILE" <<EOF
PySide6>=6.4.0
passlib>=1.7.4
PyYAML>=6.0
EOF
fi

PIP_INSTALL_EXTRA=()
if [[ -n "$PIP_MIRROR" ]]; then
  PIP_INSTALL_EXTRA+=( "--index-url" "$PIP_MIRROR" )
fi
if [[ -n "$EXTRA_PIP_ARGS" ]]; then
  # split on spaces (basic)
  # shellcheck disable=SC2206
  EXTRA_SPLIT=($EXTRA_PIP_ARGS)
  PIP_INSTALL_EXTRA+=( "${EXTRA_SPLIT[@]}" )
fi

if [[ $OFFLINE -eq 0 ]]; then
  log "ติดตั้ง Python dependencies จาก $REQ_FILE"
  pip install "${PIP_INSTALL_EXTRA[@]}" -r "$REQ_FILE"
  if [[ $INSTALL_BINWALK -eq 1 ]]; then
    log "ติดตั้ง binwalk (pip)"
    pip install "${PIP_INSTALL_EXTRA[@]}" binwalk
  else
    info "ข้ามการติดตั้ง binwalk"
  fi
else
  info "โหมด offline: ข้ามการติดตั้ง Python packages"
fi

# ---------------- Clone / Update FMK ----------------
if [[ $OFFLINE -eq 1 ]]; then
  info "โหมด offline: ข้ามการ clone/update FMK"
else
  if [[ -d "$FMK_DIR" && $FORCE_FMK_RECLONE -eq 1 ]]; then
    warn "ลบ FMK เดิม (force reclone)"
    rm -rf "$FMK_DIR"
  fi

  if [[ -d "$FMK_DIR/.git" ]]; then
    info "พบ FMK เดิม ทำการ git pull"
    (cd "$FMK_DIR" && git fetch --all --prune && git pull --ff-only || warn "pull ไม่สำเร็จ")
    if [[ -n "$FMK_BRANCH" ]]; then
      (cd "$FMK_DIR" && git checkout "$FMK_BRANCH")
    fi
  else
    log "Clone FMK → $FMK_DIR"
    mkdir -p "$(dirname "$FMK_DIR")"
    if [[ -n "$FMK_BRANCH" ]]; then
      git clone --depth 1 --branch "$FMK_BRANCH" https://github.com/rampageX/firmware-mod-kit.git "$FMK_DIR"
    else
      git clone https://github.com/rampageX/firmware-mod-kit.git "$FMK_DIR"
    fi
  fi
fi

# ---------------- Build FMK ----------------
if [[ $SKIP_BUILD_FMK -eq 1 ]]; then
  info "ข้ามการ build FMK ตาม --skip-build-fmk"
else
  if [[ -d "$FMK_DIR/src" ]]; then
    log "Build FMK tools"
    if [[ $OFFLINE -eq 1 ]]; then
      info "โหมด offline: assume source พร้อม build"
    fi
    ( cd "$FMK_DIR/src" && make -j1 ) || { err "make FMK ล้มเหลว"; exit 1; }
  else
    warn "ไม่พบ $FMK_DIR/src ข้าม"
  fi
fi

# ---------------- config.yaml ----------------
if [[ ! -f "$CONFIG_FILE" ]]; then
  log "สร้าง config.yaml"
  cat > "$CONFIG_FILE" <<EOF
fmk:
  root: external/firmware_mod_kit
  use_sudo_extract: auto
  use_sudo_build: auto
EOF
else
  if grep -q 'fmk:' "$CONFIG_FILE"; then
    info "มี section fmk อยู่แล้ว"
  else
    log "เพิ่ม section fmk ลง config.yaml"
    cat >> "$CONFIG_FILE" <<EOF

fmk:
  root: external/firmware_mod_kit
  use_sudo_extract: auto
  use_sudo_build: auto
EOF
  fi
fi

# ---------------- run.sh wrapper ----------------
if [[ $CREATE_RUN_WRAPPER -eq 1 ]]; then
  log "สร้าง run.sh เพื่อรัน GUI สะดวก"
  cat > run.sh <<EOF
#!/usr/bin/env bash
set -e
SCRIPT_DIR=\$(cd "\$(dirname "\$0")" && pwd)
if [[ ! -d "\$SCRIPT_DIR/$VENV_DIR" ]]; then
  echo "ไม่พบ venv โปรดรัน setup.sh ก่อน" >&2
  exit 1
fi
source "\$SCRIPT_DIR/$VENV_DIR/bin/activate"
python app.py "\$@"
EOF
  chmod +x run.sh
else
  info "ไม่สร้าง run.sh ตาม --no-run-wrapper"
fi

# ---------------- Sanity Checks ----------------
MKSQ="$(command -v mksquashfs || true)"
UNSQ="$(command -v unsquashfs || true)"
BINWALK_VER="$(python -c 'import binwalk,sys;print(binwalk.__version__)' 2>/dev/null || echo 'N/A')"

# ---------------- Summary ----------------
echo -e "\n${C_GREEN}============= SUMMARY =============${C_RESET}"
echo " Project Root       : $ROOT_DIR"
echo " Python Executable  : $(command -v python)"
echo " Python Version     : $(python -V 2>&1)"
echo " Virtualenv         : $VENV_DIR"
echo " FMK Directory      : $FMK_DIR"
echo " FMK Branch         : ${FMK_BRANCH:-(default)}"
echo " Binwalk Version    : $BINWALK_VER"
echo " mksquashfs (PATH)  : ${MKSQ:-Not found}"
echo " unsquashfs (PATH)  : ${UNSQ:-Not found}"
echo " Config File        : $CONFIG_FILE"
echo " Requirements File  : $REQ_FILE"
echo " Offline Mode       : $OFFLINE"
echo " Run App            : source $VENV_DIR/bin/activate && python app.py"
echo " หรือ (มี wrapper) : ./run.sh"
echo -e "${C_GREEN}====================================${C_RESET}\n"

log "Setup เสร็จสมบูรณ์ พร้อมใช้งาน!"

# หมายเหตุ: หาก run แล้ว font หรือ Qt plugin มีปัญหา ให้ติดตั้งแพ็กเกจเพิ่มเติมของระบบ (เช่น qtwayland, libxkbcommon)