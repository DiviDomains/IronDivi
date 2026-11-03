#!/usr/bin/env bash
# hp2-land.sh <coin> — orchestrator (Mac) lands an hp2 lane's ready seam as a signed commit on
# signed/main of the PRIVATE repo (remote `private` = bshuler/IronDivi). Lanes never commit
# (signing needs 1Password on the Mac): this copies the lane's diff against its base, applies it
# to a clean signed/main, commits with the subject from the lane's `- ready_to_land:` line, pushes
# the private repo and the hp2 mirror, and clears the line on hp2. It never pushes to the public
# DiviDomains mirror and refuses to run if the push remote points there.
# For lanes already checkpointed as commits on the private repo use land-private.sh instead.
set -euo pipefail
coin="$1"
lane="swap-lanes/$coin"
remote=private
branch=signed/main
ssh_=(ssh -o BatchMode=yes hp2)
root="$(git rev-parse --show-toplevel)"; cd "$root"
push_url="$(git remote get-url --push "$remote" 2>/dev/null || true)"
[[ -n "$push_url" ]] || { echo "hp2-land: remote '$remote' is missing (git remote add $remote git@github.com:bshuler/IronDivi.git)"; exit 1; }
if grep -qi 'dividomains' <<<"$push_url"; then echo "hp2-land: refusing: '$remote' push URL is the PUBLIC repo ($push_url)"; exit 1; fi
[[ "$push_url" =~ ^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)bshuler/IronDivi(\.git)?/?$ ]] \
  || { echo "hp2-land: refusing: '$remote' push URL is not bshuler/IronDivi ($push_url)"; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "hp2-land: working tree not clean"; exit 1; }
git checkout -q "$branch"
git pull -q --rebase "$remote" "$branch"
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
git commit -q -m "$subject"
git verify-commit HEAD >/dev/null 2>&1 || { echo "hp2-land: git verify-commit failed on HEAD; not pushing"; exit 1; }
git push -q "$remote" "HEAD:refs/heads/$branch"
git push -q "$remote" "HEAD:refs/heads/signed/$coin"
git push -q hp2:swap-lanes/IronDivi.git HEAD:main
"${ssh_[@]}" "sed -i -E '/^- *ready_to_land:/d' ~/$lane/docs/plans/swap-poc/status/$coin.md"
git log --oneline -1
