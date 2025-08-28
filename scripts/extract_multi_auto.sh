#!/usr/bin/env bash
#
# Auto carve & extract multiple filesystems (SquashFS / JFFS2) from a firmware image.
# Fallback script when FMK extract fails or when you want deterministic carving based on binwalk.
#
# Usage:
#   scripts/extract_multi_auto.sh <firmware.bin> [OUTPUT_DIR]
#
# If OUTPUT_DIR is omitted it will create: workspaces/auto_ws_YYYYmmdd_HHMMSS
#
# Requirements:
#   - binwalk (system: apt install binwalk)
#   - unsquashfs (squashfs-tools)
#   - jefferson (optional, for JFFS2) -> pip install jefferson
#
# What it does:
#   1. Runs binwalk once and stores scan output.
#   2. Parses offsets of "Squashfs filesystem" and "JFFS2 filesystem".
#   3. For each filesystem:
#        - Carves region from its offset up to (next_offset OR EOF)
#        - Tries to extract:
#            * Squashfs -> unsquashfs -d <dir>
#            * JFFS2   -> jefferson -d <dir>  (if installed)
#   4. Saves carved filesystem blobs + extracted directories inside OUTPUT_DIR.
#
# Notes:
#   - Length estimation uses "next FS offset - current offset" heuristic; padding between
#     partitions is included. That is usually fine for read-only inspection.
#   - If unsquashfs fails due to special compression (LZMA patched), install 'sasquatch'.
#   - Adjust/extend TYPES pattern below if you want to support UBIFS, cramfs, etc.
#
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <firmware.bin> [output_dir]" >&2
  exit 1
fi

FW="$1"
if [ ! -f "$FW" ]; then
  echo "[ERR] Firmware file not found: $FW" >&2
  exit 2
fi

# Allow relative output path from current working dir
OUTDIR="${2:-workspaces/auto_ws_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

SCAN="$OUTDIR/binwalk_scan.txt"

echo "[*] Running binwalk scan..."
if ! command -v binwalk >/dev/null 2>&1; then
  echo "[ERR] binwalk not found. Install with: sudo apt install -y binwalk" >&2
  exit 3
fi
binwalk "$FW" > "$SCAN"

# Arrays to store filesystem offsets and types
declare -a OFFS TYPES

# Parse relevant lines
# Customize this grep if you want more FS types (e.g. "UBI image", "CramFS filesystem")
while read -r line; do
  # Match lines like: 2359296       0x240000        Squashfs filesystem, ...
  if [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]+0x[0-9A-Fa-f]+[[:space:]]+(Squashfs\ filesystem|JFFS2\ filesystem) ]]; then
    OFFS+=("${BASH_REMATCH[1]}")
    case "${BASH_REMATCH[2]}" in
      Squashfs\ filesystem) TYPES+=("Squashfs");;
      JFFS2\ filesystem)    TYPES+=("JFFS2");;
    esac
  fi
done < <(grep -E "Squashfs filesystem|JFFS2 filesystem" "$SCAN")

COUNT=${#OFFS[@]}
if [ "$COUNT" -eq 0 ]; then
  echo "[!] No SquashFS or JFFS2 signatures found. (See $SCAN)"
  exit 4
fi

SIZE=$(stat -c%s "$FW")
echo "[*] Found $COUNT filesystem signatures"
printf "%-10s %-12s %-8s\n" "INDEX" "OFFSET(dec)" "TYPE"
for i in "${!OFFS[@]}"; do
  printf "%-10s %-12s %-8s\n" "$i" "${OFFS[$i]}" "${TYPES[$i]}"
done

# Carve each filesystem using offset to next FS (or EOF for last)
for i in "${!OFFS[@]}"; do
  start=${OFFS[$i]}
  type=${TYPES[$i]}

  if [ $((i+1)) -lt "$COUNT" ]; then
    end=${OFFS[$((i+1))]}
  else
    end=$SIZE
  fi
  length=$(( end - start ))

  printf "\n[*] Carving %s index=%02d offset=0x%X (dec %d) length=%d (0x%X)\n" \
         "$type" "$i" "$start" "$start" "$length" "$length"

  case "$type" in
    Squashfs)
      outfs="$OUTDIR/rootfs_${i}.sqsh"
      dd if="$FW" of="$outfs" bs=1 skip="$start" count="$length" status=none
      # Try unsquashfs
      if command -v unsquashfs >/dev/null 2>&1; then
        if unsquashfs -d "$OUTDIR/rootfs_${i}" "$outfs" >/dev/null 2>&1; then
          echo "    -> unsquashfs OK (rootfs_${i})"
        else
          echo "    -> unsquashfs FAILED (maybe needs sasquatch or different compression)"
        fi
      else
        echo "    -> unsquashfs not found (sudo apt install -y squashfs-tools)"
      fi
      ;;
    JFFS2)
      outfs="$OUTDIR/jffs2_${i}.bin"
      dd if="$FW" of="$outfs" bs=1 skip="$start" count="$length" status=none
      if command -v jefferson >/dev/null 2>&1; then
        if jefferson -d "$OUTDIR/jffs2_${i}" "$outfs" >/dev/null 2>&1; then
          echo "    -> jefferson OK (jffs2_${i})"
        else
          echo "    -> jefferson FAILED (structure or ECC mismatch)"
        fi
      else
        echo "    -> jefferson not installed (pip install jefferson)"
      fi
      ;;
    *)
      echo "    -> Unknown type logic not implemented: $type"
      ;;
  esac
done

echo
echo "[*] Finished. Artifacts in: $OUTDIR"
echo "[*] Scan file saved at: $SCAN"
echo "[*] Tip: diff rootfs directories to identify differences."
