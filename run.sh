#!/usr/bin/env bash
# Wrapper สำหรับรัน GUI อย่างรวดเร็ว (สร้างอัตโนมัติจาก setup.sh ถ้ายังไม่มี)
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${VENV_DIR:-.venv}"

if [[ ! -d "$SCRIPT_DIR/$VENV_DIR" ]]; then
  echo "[run.sh] ไม่พบ virtualenv: $VENV_DIR (โปรดรัน: bash setup.sh)" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$SCRIPT_DIR/$VENV_DIR/bin/activate"
exec python app.py "$@"