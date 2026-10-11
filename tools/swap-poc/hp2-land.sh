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
# The line becomes the commit subject verbatim, so it must read like one ("swap(zec): …"),
# not a status answer ("yes — re-synced …").
[[ "$subject" =~ ^[a-z]+(\([a-z0-9-]+\))?:\  ]] || { echo "hp2-land: $coin ready_to_land is not a commit subject: $subject"; exit 1; }
unmerged="$("${ssh_[@]}" "git -C ~/$lane diff --name-only --diff-filter=U")"
[[ -z "$unmerged" ]] || { echo "hp2-land: $coin has unresolved conflicts: $unmerged"; exit 1; }
patch="$(mktemp)"; trap 'rm -f "$patch"' EXIT
# Intent-to-add makes new files show in the diff; reset afterwards, or the lane's next
# lane-sync.sh stash fails on the leftover index entries. Orchestrator notes never land.
"${ssh_[@]}" "cd ~/$lane && git add -A -N . && git diff --binary HEAD -- . ':(exclude)target' ':(exclude)ORCHESTRATOR-NOTE*'; rc=\$?; git reset -q; exit \$rc" >"$patch"
base="$("${ssh_[@]}" "git -C ~/$lane rev-parse HEAD")"
lock_excluded=0
if ! git apply --3way "$patch" 2>/dev/null; then
  # Usually only Cargo.lock collides between lanes: apply the rest, regenerate the lock below.
  git checkout -q -- . && git clean -qfd
  git apply --3way --exclude=Cargo.lock "$patch" \
    || { git reset -q --hard HEAD; git clean -qfd -e target
         echo "hp2-land: patch from $coin (base $base) does not apply on main; tree reset, lane must lane-sync"; exit 1; }
  lock_excluded=1
fi
# The lane's own status file keeps its ready line in the commit; drop it there.
sed -i '' -E '/^- *ready_to_land:/d' "docs/plans/swap-poc/status/$coin.md" 2>/dev/null || true
# Refresh Cargo.lock only when the lane's copy was dropped. Offline: the lane already fetched the
# deps on hp2, and an online metadata call can sit for ages on the shared package-cache lock.
if [[ $lock_excluded == 1 ]]; then
  cargo metadata --offline --format-version 1 >/dev/null \
    || { echo "hp2-land: Cargo.lock needs new crates; run cargo fetch, then land again"; exit 1; }
fi
git add -A
git -c user.name="Bert Shuler" -c user.email=BertShuler@proton.me commit -q -m "$subject"
git push -q origin HEAD:main
git push -q hp2:swap-lanes/IronDivi.git HEAD:main
"${ssh_[@]}" "sed -i -E '/^- *ready_to_land:/d' ~/$lane/docs/plans/swap-poc/status/$coin.md"
git log --oneline -1
