#!/usr/bin/env bash
# Lane deploy acceptance. See docs/plans/swap-poc/lanes/deploy.md.
source "$(dirname "$0")/lib.sh"
D=deploy/divi-swapd
for f in divi-swapd.service nginx-swap.conf logrotate-divi-swapd deploy.sh divi-swapd.toml.example README.md; do
  [[ -f "$D/$f" ]] && pass "$f exists" || fail "missing $D/$f"
done
if [[ -f "$D/divi-swapd.service" ]]; then
  for k in 'User=divi-swapd' 'ProtectSystem=strict' 'NoNewPrivileges=yes' 'PrivateTmp=yes' \
           'LoadCredential=' 'StateDirectory=divi-swapd' 'Restart=on-failure'; do
    grep -q "^$k" "$D/divi-swapd.service" && pass "unit has $k" || fail "unit lacks $k"
  done
  command -v systemd-analyze >/dev/null && { systemd-analyze verify "$D/divi-swapd.service" >/dev/null 2>&1 && pass "systemd-analyze verify" || fail "systemd-analyze verify"; }
fi
grep -qs 'size 10M' "$D/logrotate-divi-swapd" && pass "logrotate 10M" || fail "logrotate lacks 'size 10M'"
grep -qs 'location /swap/' "$D/nginx-swap.conf" && pass "nginx location /swap/" || fail "nginx lacks 'location /swap/'"
if command -v shellcheck >/dev/null; then
  shellcheck "$D"/*.sh >/dev/null 2>&1 && pass "shellcheck" || fail "shellcheck $D/*.sh"
else fail "shellcheck not installed (brew install shellcheck)"; fi
if [[ -x "$D/deploy.sh" ]]; then
  out="$("$D/deploy.sh" --dry-run 2>&1)"; rc=$?
  (( rc == 0 )) && pass "deploy.sh --dry-run exits 0" || fail "deploy.sh --dry-run exit $rc"
  grep -q 'DRY RUN' <<<"$out" && pass "dry run prints plan" || fail "dry run output lacks 'DRY RUN'"
  grep -qiE 'ssh .*dnsdivi' <<<"$out" && pass "plan targets dnsdivi" || fail "dry run plan does not show the ssh dnsdivi steps"
fi
if grep -rnE '(PRIVATE KEY|op://[^ ]*password[^ ]*[[:space:]]*=|[0-9a-f]{64})' "$D" >/dev/null 2>&1; then
  fail "something that looks like a secret is in $D"; else pass "no secrets in $D"; fi
finish deploy
