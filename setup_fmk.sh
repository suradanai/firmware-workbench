#!/usr/bin/env bash
set -e
FMK_DIR="external/firmware_mod_kit"
if [ -d "$FMK_DIR" ]; then
  echo "[+] FMK directory already exists: $FMK_DIR"
else
  echo "[*] Cloning Firmware Mod Kit..."
  mkdir -p external
  git clone https://github.com/rampageX/firmware-mod-kit.git "$FMK_DIR"
fi
echo "[*] Building FMK tools..."
cd "$FMK_DIR/src"
make -j1
cd -
echo "[*] Done. You can set FMK_PATH or edit config.yaml."