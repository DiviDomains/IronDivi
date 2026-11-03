#!/usr/bin/env bash
# Lane deploy acceptance. See docs/plans/swap-poc/lanes/deploy.md.
source "$(dirname "$0")/lib.sh"
D=deploy/divi-swapd
# unit_verify <unit> — systemd-analyze verify. SKIP if the tool is absent; if the only complaint is that
# the ExecStart binary is not installed here, SKIP with that reason; any other complaint about the unit FAILs.
unit_verify() {
  local u="$1" out rc bin rest
  if ! command -v systemd-analyze >/dev/null 2>&1; then skip "systemd-analyze not installed" "systemd-analyze verify"; return; fi
  out="$(systemd-analyze verify "$u" 2>&1)"; rc=$?
  (( rc == 0 )) && { pass "systemd-analyze verify"; return; }
  rest="$(grep -F "$(basename "$u")" <<<"$out" | grep -v 'is not executable' || true)"
  if [[ -z "$rest" ]] && grep -qF "$(basename "$u")" <<<"$out" && grep -q 'is not executable' <<<"$out"; then
    bin="$(sed -n 's/^ExecStart=[-@:+!]*\([^ ]*\).*/\1/p' "$u" | head -1)"
    skip "ExecStart binary ${bin:-?} not installed" "systemd-analyze verify"
  else fail "systemd-analyze verify"; fi
}
for f in divi-swapd.service nginx-swap.conf logrotate-divi-swapd deploy.sh divi-swapd.toml.example README.md; do
  [[ -f "$D/$f" ]] && pass "$f exists" || fail "missing $D/$f"
done
if [[ -f "$D/divi-swapd.service" ]]; then
  for k in 'User=divi-swapd' 'ProtectSystem=strict' 'NoNewPrivileges=yes' 'PrivateTmp=yes' \
           'LoadCredential=' 'StateDirectory=divi-swapd' 'Restart=on-failure'; do
    grep -q "^$k" "$D/divi-swapd.service" && pass "unit has $k" || fail "unit lacks $k"
  done
  unit_verify "$D/divi-swapd.service"
fi
grep -qs 'size 10M' "$D/logrotate-divi-swapd" && pass "logrotate 10M" || fail "logrotate lacks 'size 10M'"
grep -qs 'location /swap/' "$D/nginx-swap.conf" && pass "nginx location /swap/" || fail "nginx lacks 'location /swap/'"
tool_check shellcheck "shellcheck" shellcheck "$D"/*.sh
if [[ -x "$D/deploy.sh" ]]; then
  out="$("$D/deploy.sh" --dry-run 2>&1)"; rc=$?
  (( rc == 0 )) && pass "deploy.sh --dry-run exits 0" || fail "deploy.sh --dry-run exit $rc"
  grep -q 'DRY RUN' <<<"$out" && pass "dry run prints plan" || fail "dry run output lacks 'DRY RUN'"
  grep -qiE 'ssh .*dnsdivi' <<<"$out" && pass "plan targets dnsdivi" || fail "dry run plan does not show the ssh dnsdivi steps"
fi
if grep -rnE '(PRIVATE KEY|op://[^ ]*password[^ ]*[[:space:]]*=|[0-9a-f]{64})' "$D" >/dev/null 2>&1; then
  fail "something that looks like a secret is in $D"; else pass "no secrets in $D"; fi
finish deploy
