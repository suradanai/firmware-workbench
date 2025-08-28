#!/usr/bin/env bash
set -euo pipefail

FW="$1"
OUTDIR="${2:-auto_ws_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

echo "[*] Scanning firmware with binwalk..."
TMP_SCAN="$OUTDIR/binwalk_scan.txt"
binwalk "$FW" > "$TMP_SCAN"

# เก็บ offsets
declare -a OFFS TYPES
while read -r line; do
  [[ "$line" =~ ^[[:space:]]*([0-9]+)[[:space:]]+0x[0-9A-Fa-f]+[[:space:]]+(Squashfs|JFFS2) ]] || continue
  OFFS+=("${BASH_REMATCH[1]}")
  TYPES+=("${BASH_REMATCH[2]}")
done < <(grep -E "Squashfs filesystem|JFFS2 filesystem" "$TMP_SCAN")

if [ "${#OFFS[@]}" -eq 0 ]; then
  echo "[!] No FS signatures found."
  exit 2
fi

# คำนวณขอบเขตแต่ละ partition (offset pair ไปจน offset ถัดไป)
SIZE=$(stat -c%s "$FW")
for i in "${!OFFS[@]}"; do
  start=${OFFS[$i]}
  type=${TYPES[$i]}
  if [ $((i+1)) -lt ${#OFFS[@]} ]; then
    end=${OFFS[$((i+1))]}
  else
    end=$SIZE
  fi
  length=$(( end - start ))
  printf "[*] Carving %s at 0x%X (dec %d) length=%d (0x%X)\n" "$type" "$start" "$start" "$length" "$length"

  if [ "$type" = "Squashfs" ]; then
    outfile="$OUTDIR/$(printf 'rootfs_%02d.sqsh' "$i")"
    dd if="$FW" of="$outfile" bs=1 skip="$start" count="$length" status=none
    unsquashfs -d "$OUTDIR/rootfs_$i" "$outfile" >/dev/null 2>&1 || \
      echo "[!] unsquashfs failed on $outfile (maybe compression patch needed)"
  elif [ "$type" = "JFFS2" ]; then
    outfile="$OUTDIR/$(printf 'jffs2_%02d.bin' "$i")"
    dd if="$FW" of="$outfile" bs=1 skip="$start" count="$length" status=none
    if command -v jefferson >/dev/null; then
      jefferson -d "$OUTDIR/jffs2_$i" "$outfile" >/dev/null 2>&1 || echo "[!] jefferson failed"
    else
      echo "[!] jefferson not installed; install with: pip install jefferson"
    fi
  fi
done

echo "[*] Done. See $OUTDIR"