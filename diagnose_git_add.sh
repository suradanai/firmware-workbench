#!/usr/bin/env bash
set -e
echo "== Commit HEAD =="
git log --oneline -n1
echo "== Files in HEAD =="
git ls-tree -r --name-only HEAD | sort | head -20
echo "== Untracked =="
git ls-files --others --exclude-standard | head -20
echo "Total untracked: $(git ls-files --others --exclude-standard | wc -l)"
echo "== Configs =="
echo "alias:"; git config --get-regexp '^alias\.' 2>/dev/null || echo "(none)"
echo -n "status.showUntrackedFiles="; git config --get status.showUntrackedFiles || echo "(unset)"
echo -n "core.sparseCheckout="; git config --get core.sparseCheckout || echo "(unset)"
echo -n "core.excludesfile="; git config --get core.excludesfile || echo "(unset)"
echo "== Hooks =="
ls -1 .git/hooks | grep -v sample || echo "(no custom hooks)"
echo "== Attempt staged diff (pre) =="
git diff --cached --name-status || true
echo "== Try add -A =="
git add -A
git diff --cached --name-status || true
echo "== Probe file =="
echo "probe $(date)" > _probe_file.txt
git add _probe_file.txt
git diff --cached --name-status | grep _probe_file.txt || echo "(probe not staged!)"