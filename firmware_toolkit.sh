#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage:"
  echo "  $0 show-layout --input <firmware.bin>"
  echo "  $0 patch --input <firmware.bin> --output <patched.bin> [--bootdelay N]"
  echo "  $0 patch-rootfs0-services --input <firmware.bin> --output <patched.bin> [--ports ttyS1] [--enable-telnet --telnet-port 23] [--enable-ftp --ftp-port 21 --ftp-root /]"
  echo "  $0 verify-rootfs --input <firmware.bin> --index <0|1|2> [--port ttyS1]"
  exit 1
}

if [[ $# -eq 0 ]]; then usage; fi

CMD="$1"; shift

getopt_val() {
  local key="$1"
  shift
  for ((i=1;i<=$#;i++)); do
    if [[ "${!i}" == "$key" ]]; then
      local next=$((i+1))
      echo "${!next}"
      return 0
    fi
  done
  return 1
}

# Partition offsets (ปรับตามจริง)
declare -A PART_OFF=( ["boot"]=0x0000000 ["rootfs0"]=0x0240000 ["rootfs1"]=0x0610000 ["rootfs2"]=0x0BC0000 ["end"]=0x1000000 )

show_layout() {
  local fw="$1"
  echo "=== Partition layout ==="
  for part in boot rootfs0 rootfs1 rootfs2; do
    local off=${PART_OFF[$part]}
    local nextkey
    case $part in
      boot) nextkey="rootfs0";;
      rootfs0) nextkey="rootfs1";;
      rootfs1) nextkey="rootfs2";;
      rootfs2) nextkey="end";;
    esac
    local next=${PART_OFF[$nextkey]}
    local size=$((next - off))
    printf "%-8s Offset=0x%07X  Size=0x%X\n" "$part" "$off" "$size"
    dd if="$fw" bs=1 skip=$((off)) count=4 status=none | xxd
  done
  sha256sum "$fw"
}

copy_and_patch_bootdelay() {
  local in="$1"
  local out="$2"
  local delay="$3"
  cp "$in" "$out"
  # ตัวอย่าง: สมมุติ bootdelay อยู่ offset 0x100 (ต้องปรับตามจริง)
  printf "%1u" "$delay" | dd of="$out" bs=1 seek=256 count=1 conv=notrunc status=none
  echo "Patched bootdelay at offset 0x100 to $delay"
}

patch_rootfs0_services() {
  local in="$1"
  local out="$2"
  local ports="$3"
  local enable_telnet="$4"
  local telnet_port="$5"
  local enable_ftp="$6"
  local ftp_port="$7"
  local ftp_root="$8"
  cp "$in" "$out"
  # ตัวอย่าง: ใส่ shell ลง rootfs0 (สมมุติเป็น squashfs ที่ offset)
  # จริงควร unsquashfs, แก้ inittab, mksquashfs กลับ, dd ทับ rootfs0
  echo "[DEMO] Would patch shell ($ports), telnet=$enable_telnet, ftp=$enable_ftp" >> /dev/null
  # -- ในเวอร์ชั่นจริง เพิ่ม logic แก้ไข rootfs ตามที่คุณเคยใช้ toolkit เดิม
  echo "Patched shell/telnet/ftp (demo only)"
}

verify_rootfs() {
  local in="$1"
  local index="$2"
  local port="$3"
  # ตัวอย่าง: ตรวจ magic, ขนาด, SHA256
  echo "Verify rootfs$index in $in (port=$port)"
  # offset ตาม index
  local off
  case $index in
    0) off=${PART_OFF[rootfs0]} ;;
    1) off=${PART_OFF[rootfs1]} ;;
    2) off=${PART_OFF[rootfs2]} ;;
    *) echo "Invalid index"; exit 1;;
  esac
  dd if="$in" bs=1 skip=$((off)) count=4 status=none | xxd
  sha256sum "$in"
  echo "OK (demo)"
}

case "$CMD" in
  show-layout)
    while [[ $# -gt 0 ]]; do case "$1" in --input) INPUT="$2"; shift 2;; *) shift;; esac; done
    [ -z "${INPUT:-}" ] && usage
    show_layout "$INPUT"
    ;;
  patch)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --input) INPUT="$2"; shift 2;;
        --output) OUTPUT="$2"; shift 2;;
        --bootdelay) BOOTDELAY="$2"; shift 2;;
        *) shift;;
      esac
    done
    [ -z "${INPUT:-}" ] || [ -z "${OUTPUT:-}" ] || [ -z "${BOOTDELAY:-}" ] && usage
    copy_and_patch_bootdelay "$INPUT" "$OUTPUT" "$BOOTDELAY"
    ;;
  patch-rootfs0-services)
    # รองรับ option พื้นฐาน
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --input) INPUT="$2"; shift 2;;
        --output) OUTPUT="$2"; shift 2;;
        --ports) PORTS="$2"; shift 2;;
        --enable-telnet) ENABLE_TELNET="yes"; shift;;
        --telnet-port) TELNET_PORT="$2"; shift 2;;
        --enable-ftp) ENABLE_FTP="yes"; shift;;
        --ftp-port) FTP_PORT="$2"; shift 2;;
        --ftp-root) FTP_ROOT="$2"; shift 2;;
        *) shift;;
      esac
    done
    [ -z "${INPUT:-}" ] || [ -z "${OUTPUT:-}" ] && usage
    patch_rootfs0_services "$INPUT" "$OUTPUT" "${PORTS:-ttyS1}" "${ENABLE_TELNET:-no}" "${TELNET_PORT:-23}" "${ENABLE_FTP:-no}" "${FTP_PORT:-21}" "${FTP_ROOT:-/}"
    ;;
  verify-rootfs)
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --input) INPUT="$2"; shift 2;;
        --index) INDEX="$2"; shift 2;;
        --port) PORT="$2"; shift 2;;
        *) shift;;
      esac
    done
    [ -z "${INPUT:-}" ] || [ -z "${INDEX:-}" ] || [ -z "${PORT:-}" ] && usage
    verify_rootfs "$INPUT" "$INDEX" "$PORT"
    ;;
  *)
    usage
    ;;
esac