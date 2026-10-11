#!/usr/bin/env bash
# hp2-land.sh <coin> — orchestrator (Mac) lands an hp2 lane's ready seam as a signed commit on
# main. Lanes never commit (signing needs 1Password on the Mac): this copies the lane's diff
# against its base, applies it to a clean main, commits with the subject from the lane's
# `- ready_to_land:` line, pushes GitHub and the hp2 mirror, and clears the line on hp2.
set -euo pipefail
coin="$1"
lane="swap-lanes/$coin"
ssh_=(ssh -o BatchMode=yes hp2)
root="$(git rev-parse --show-toplevel)"; cd "$root"
[[ -z "$(git status --porcelain)" ]] || { echo "hp2-land: working tree not clean"; exit 1; }
git pull -q --rebase origin main
subject="$("${ssh_[@]}" "grep -E '^- *ready_to_land:' ~/$lane/docs/plans/swap-poc/status/$coin.md | head -1 | sed -E 's/^- *ready_to_land: *//'")"
[[ -n "$subject" ]] || { echo "hp2-land: $coin has no ready_to_land line"; exit 1; }
patch="$(mktemp)"; trap 'rm -f "$patch"' EXIT
"${ssh_[@]}" "cd ~/$lane && git add -A -N . && git diff --binary HEAD" >"$patch"
base="$("${ssh_[@]}" "git -C ~/$lane rev-parse HEAD")"
if ! git apply --3way "$patch" 2>/dev/null; then
  # Usually only Cargo.lock collides between lanes: apply the rest, regenerate the lock below.
  git checkout -q -- . && git clean -qfd
  git apply --3way --exclude=Cargo.lock "$patch" \
    || { echo "hp2-land: patch from $coin (base $base) does not apply on main"; exit 1; }
fi
# The lane's own status file keeps its ready line in the commit; drop it there.
sed -i '' -E '/^- *ready_to_land:/d' "docs/plans/swap-poc/status/$coin.md" 2>/dev/null || true
cargo metadata --format-version 1 >/dev/null  # refresh Cargo.lock for any new deps
git add -A
git -c user.name="Bert Shuler" -c user.email=BertShuler@proton.me commit -q -m "$subject"
git push -q origin main
git push -q hp2:swap-lanes/IronDivi.git main:main
"${ssh_[@]}" "sed -i -E '/^- *ready_to_land:/d' ~/$lane/docs/plans/swap-poc/status/$coin.md"
git log --oneline -1
