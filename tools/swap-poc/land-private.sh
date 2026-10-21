#!/usr/bin/env bash
# land-private.sh <coin> [<sha>] — one-command signed landing of a lane seam to the PRIVATE repo.
#
# Fetches `lane/<coin>` (or the given sha) from the `private` remote (bshuler/IronDivi), squashes
# the lane's unlanded commits onto `signed/main` as ONE commit whose subject is the lane's
# `- ready_to_land:` line (docs/plans/swap-poc/status/<coin>.md), authored and SSH-signed as Bert,
# verifies the signature, pushes `signed/main` and `signed/<coin>` (= signed/main) to `private`,
# and prints the SHAs. Idempotent: a seam whose subject is already in signed/main history, or whose
# pick leaves no change, prints "nothing to land" and exits 0.
#
# Hard refusals (exit 1, nothing pushed): the `private` remote's push URL is not the bshuler repo
# or mentions DiviDomains (the public mirror is never a push target of this script; `origin` may
# stay public for fetching), the working tree is dirty, the pick conflicts, or `git verify-commit`
# fails on the new commit (the commit is then dropped so nothing unsigned is left on the branch).
set -euo pipefail

coin="${1:-}"
want="${2:-}"
[[ -n "$coin" ]] || { echo "usage: land-private.sh <coin> [<sha>]" >&2; exit 2; }

remote=private
branch=signed/main
status_file="docs/plans/swap-poc/status/$coin.md"
author_name="Bert Shuler"
author_email="BertShuler@proton.me"

die() { echo "land-private: $*" >&2; exit 1; }

root="$(git rev-parse --show-toplevel)"; cd "$root"

# --- refusals ------------------------------------------------------------------------------------
push_url="$(git remote get-url --push "$remote" 2>/dev/null || true)"
[[ -n "$push_url" ]] || die "remote '$remote' is missing; add it: git remote add $remote git@github.com:bshuler/IronDivi.git"
if grep -qi 'dividomains' <<<"$push_url"; then die "refusing: '$remote' push URL is the PUBLIC repo ($push_url)"; fi
[[ "$push_url" =~ ^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)bshuler/IronDivi(\.git)?/?$ ]] \
  || die "refusing: '$remote' push URL is not bshuler/IronDivi ($push_url)"
[[ -z "$(git status --porcelain)" ]] || die "refusing: working tree not clean"
if git rev-parse -q --verify CHERRY_PICK_HEAD >/dev/null 2>&1; then die "refusing: a cherry-pick is in progress"; fi

# --- sync signed/main --------------------------------------------------------------------------
git fetch -q "$remote" "+refs/heads/$branch:refs/remotes/$remote/$branch" 2>/dev/null \
  || echo "land-private: $remote has no $branch yet (first landing)"
if git rev-parse -q --verify "refs/heads/$branch" >/dev/null; then
  git checkout -q "$branch"
  if git rev-parse -q --verify "refs/remotes/$remote/$branch" >/dev/null; then
    git merge -q --ff-only "refs/remotes/$remote/$branch" \
      || die "local $branch and $remote/$branch have diverged; reconcile by hand (never force)"
  fi
else
  git rev-parse -q --verify "refs/remotes/$remote/$branch" >/dev/null \
    || die "no local $branch and $remote has none: create it first (git checkout -b $branch <public main>)"
  git checkout -q -b "$branch" "refs/remotes/$remote/$branch"
fi
before="$(git rev-parse HEAD)"

# --- lane tip ------------------------------------------------------------------------------------
if [[ -n "$want" ]]; then
  git fetch -q "$remote" "$want" 2>/dev/null || git rev-parse -q --verify "$want^{commit}" >/dev/null \
    || die "cannot fetch or find commit $want"
  tip="$(git rev-parse --verify "$want^{commit}")"
else
  git fetch -q "$remote" "refs/heads/lane/$coin" || die "cannot fetch lane/$coin from $remote"
  tip="$(git rev-parse FETCH_HEAD)"
fi

# Subject: the LAST `ready_to_land:` line of the lane's status file at the tip. Tolerates the
# marker being wrapped in backticks or bold. It becomes the commit subject verbatim, so it must
# read like one ("fix(swap-xmr): …"), not a status answer ("yes — re-synced …").
subject="$(git show "$tip:$status_file" 2>/dev/null | grep -E 'ready_to_land:' | tail -1 \
  | sed -E 's/^.*ready_to_land:[[:space:]]*//; s/[[:space:]`*]+$//' || true)"
[[ -n "$subject" ]] || die "$coin@${tip:0:7} has no ready_to_land line in $status_file"
[[ "$subject" =~ ^[a-z]+(\([a-z0-9_./-]+\))?!?:\  ]] || die "$coin ready_to_land is not a commit subject: $subject"

# --- already landed? -----------------------------------------------------------------------------
if git merge-base --is-ancestor "$tip" HEAD; then
  echo "nothing to land: $coin@${tip:0:7} is already in $branch"; exit 0
fi
landed="$(git log --format=%H --fixed-strings --grep="$subject" "$branch" | head -1)"
if [[ -n "$landed" ]]; then
  echo "nothing to land: '$subject' is already in $branch as ${landed:0:7}"; exit 0
fi

# --- pick ----------------------------------------------------------------------------------------
base="$(git merge-base HEAD "$tip")"
commits=()
while IFS= read -r c; do [[ -n "$c" ]] && commits+=("$c"); done < <(git rev-list --reverse "$base..$tip")
[[ ${#commits[@]} -gt 0 ]] || { echo "nothing to land: no commits in $base..$tip"; exit 0; }
echo "land-private: picking ${#commits[@]} commit(s) from $coin@${tip:0:7} onto $branch@${before:0:7}"
if ! git cherry-pick -n --allow-empty "${commits[@]}" >/dev/null 2>&1; then
  conflicts="$(git diff --name-only --diff-filter=U | tr '\n' ' ')"
  git cherry-pick --quit >/dev/null 2>&1 || true
  git reset -q --hard "$before"
  die "pick of $coin@${tip:0:7} conflicts on: ${conflicts:-?}; tree reset to ${before:0:7}, lane must rebase"
fi
# The marker line is for the lander, not for history: drop it from the landed status file.
if [[ -f "$status_file" ]]; then
  sed -i '' -E '/^[-*][[:space:]]*[`*]*ready_to_land:/d' "$status_file"
  git add -A -- "$status_file"
fi
if git diff --cached --quiet; then
  git reset -q --hard "$before"
  echo "nothing to land: $coin@${tip:0:7} adds no change to $branch"; exit 0
fi

# --- commit, sign, verify ------------------------------------------------------------------------
git -c user.name="$author_name" -c user.email="$author_email" commit -q \
  -m "$subject" -m "Landed-From: $tip"
new="$(git rev-parse HEAD)"
if ! git verify-commit "$new" >/dev/null 2>&1; then
  git reset -q --hard "$before"
  die "git verify-commit failed on $new; commit dropped, $branch back at ${before:0:7} (is signing configured? gpg.format/user.signingkey)"
fi
sig_email="$(git log -1 --format=%ae "$new")"
[[ "$sig_email" == "$author_email" ]] || { git reset -q --hard "$before"; die "author is $sig_email, not $author_email"; }

# --- push ----------------------------------------------------------------------------------------
git push -q "$remote" "$branch:refs/heads/$branch"
git push -q "$remote" "$branch:refs/heads/signed/$coin"
echo "landed $coin: $new  ($subject)"
echo "  $remote $branch        -> $new"
echo "  $remote signed/$coin   -> $new"
echo "  lane tip (Landed-From)   $tip"
