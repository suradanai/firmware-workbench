#!/usr/bin/env bash
set -e
echo "[*] Soft reset to remove first commit (keeping worktree)"
git reset --soft HEAD~1 || { echo "No previous commit? Skipping soft reset"; }

echo "[*] Unstage everything"
git reset

echo "[*] Remove unwanted directories/files"
rm -rf external/firmware_mod_kit docs/app\ py\ test
rm -f requirement.txt docs/requirement.txt all
find docs -maxdepth 1 -type f -name 'Copilot said*' -exec rm -f {} +

echo "[*] Writing .gitignore"
cat > .gitignore <<'EOF'
.venv/
venv/
workspaces/
output/
__pycache__/
*.py[cod]
*.bin
*.img
*.trx
*.chk
external/firmware_mod_kit/
*.log
.DS_Store
.idea/
.vscode/
EOF

echo "[*] Staging core files"
git add app.py fmk_integration.py patch_utils.py rebuild_squashfs.py \
  fw-manager.sh run.sh setup.sh setup_fmk.sh firmware_toolkit.sh \
  requirements.txt config.yaml README_FMK_INTEGRATION.md .gitignore 2>/dev/null || true
[ -d docs ] && git add docs || true

echo "[*] Set executable bits"
git update-index --chmod=+x fw-manager.sh run.sh setup.sh setup_fmk.sh firmware_toolkit.sh || true

echo "[*] Create new clean commit"
git commit -m "chore: initial clean commit (core scripts, ignore env/FM K binaries)"

echo "[*] Show result"
git show --name-status --oneline -n1