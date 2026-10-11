#!/usr/bin/env bash
# lane-sync.sh — run by an hp2 lane (docs/plans/swap-poc/lanes/_hp2.md rule 4) after the
# orchestrator landed its work: puts the latest main under the lane's uncommitted edits.
# Lanes never commit, so the landed changes reappear identical in the stash and pop cleanly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git fetch -q origin main
if git diff --quiet HEAD && [[ -z "$(git ls-files --others --exclude-standard)" ]]; then
  git merge -q --ff-only origin/main
else
  git stash push -q --include-untracked -m lane-sync
  git merge -q --ff-only origin/main
  git stash pop -q || { echo "lane-sync: conflicts after stash pop — resolve them (git status), then 'git stash drop'"; exit 1; }
fi
git log --oneline -1
