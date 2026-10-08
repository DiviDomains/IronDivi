#!/usr/bin/env bash
# Conditional Stop hook for a swap POC lane (context-budget.md §2.5 rule 15).
# Re-prompts only while tools/swap-poc/check-<lane>.sh fails, at most 15 times per worktree.
# Installed per worktree in .claude/settings.local.json by the orchestrator:
#   {"hooks":{"Stop":[{"hooks":[{"type":"command","command":"tools/swap-poc/stop-hook.sh <lane>","timeout":1800}]}]}}
set -uo pipefail
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"  # hooks and panes start without the rust toolchain on PATH
lane="$1"
cat >/dev/null # hook input JSON (unused)
root="$(git rev-parse --show-toplevel)"
count_file="$(git rev-parse --git-dir)/swap-stop-count-$lane"
n="$(cat "$count_file" 2>/dev/null || echo 0)"
# A lane that parked work behind a human turn may stop.
if grep -qiE '^- *parked:.*[a-z]' "$root/docs/plans/swap-poc/status/$lane.md" 2>/dev/null \
   && grep -qiE '^- *blocked-on-human: *yes' "$root/docs/plans/swap-poc/status/$lane.md"; then
  exit 0
fi
out="$("$root/tools/swap-poc/check-$lane.sh" 2>&1)" && exit 0
if (( n >= 15 )); then
  echo "stop-hook: $lane still failing after 15 re-prompts; letting it stop for the orchestrator." >&2
  exit 0
fi
echo $((n + 1)) >"$count_file"
fails="$(grep -E '^FAIL' <<<"$out" | head -20)"
jq -n --arg r "Lane $lane is not done: tools/swap-poc/check-$lane.sh fails (re-prompt $((n + 1))/15). Update docs/plans/swap-poc/status/$lane.md, then fix:
$fails" '{decision: "block", reason: $r}'
