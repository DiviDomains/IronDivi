#!/usr/bin/env bash
# Harness for the hermetic check scripts: network rows are opt-in (SWAP_CHECK_NETWORK=1) and a missing
# tool (shellcheck / forge / systemd-analyze) is a SKIP, never a FAIL. No network, no cargo, no real tools:
# each case runs the REAL check-*.sh from this tree inside a throwaway git repo, on a PATH that holds only
# core utilities plus stubs (curl, shellcheck, forge, systemd-analyze, cargo).
# Run: bash tools/swap-poc/test-check-hermetic.sh
set -uo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
FAILS=0; CASES=0
ok()  { CASES=$((CASES + 1)); echo "ok:   $*"; }
bad() { CASES=$((CASES + 1)); FAILS=$((FAILS + 1)); echo "FAIL: $*"; }

# --- minimal PATH: core utilities only, so an "absent" tool is really absent -------------------------
BIN="$T/bin"; STUBS="$T/stubs"; mkdir -p "$BIN" "$STUBS"
for c in bash env git grep sed awk tr head tail cat dirname basename mktemp rm mkdir timeout python3 sort \
         wc cut true false uname date ls chmod cp mv sleep find diff jq xargs readlink; do
  p="$(command -v "$c" 2>/dev/null)" && [[ -x "$p" ]] && ln -sf "$p" "$BIN/$c"
done
HOME_T="$T/home"; mkdir -p "$HOME_T"   # lib.sh prepends $HOME/.local/bin etc.: keep them empty

mkstub() { # mkstub <name> — stub whose behaviour comes from $STUB_<NAME>: ok | err | (absent => not created)
  local n="$1" up; up="$(tr a-z- A-Z_ <<<"$n")"
  cat > "$STUBS/$n" <<EOF
#!/usr/bin/env bash
echo "$n \$*" >> "\$CALL_LOG"
mode="\${STUB_$up:-ok}"
[[ "\$mode" == ok ]] && exit 0
[[ -n "\${STUB_${up}_OUT:-}" ]] && printf '%s\n' "\$STUB_${up}_OUT" >&2
exit 1
EOF
  chmod +x "$STUBS/$n"
}
mkstub shellcheck; mkstub forge
cat > "$STUBS/systemd-analyze" <<'EOF'
#!/usr/bin/env bash
echo "systemd-analyze $*" >> "$CALL_LOG"
[[ -n "${STUB_SDA_OUT:-}" ]] && printf '%s\n' "$STUB_SDA_OUT" >&2
exit "${STUB_SDA_RC:-0}"
EOF
cat > "$STUBS/curl" <<'EOF'
#!/usr/bin/env bash
echo "curl $*" >> "$CALL_LOG"
printf '{"confirmed":%s,"result":{"confirmations":%s}}' "${STUB_CURL_CONFIRMED:-true}" "${STUB_CURL_CONFS:-3}"
EOF
chmod +x "$STUBS"/*

# --- fixture repo ------------------------------------------------------------------------------------
R="$T/repo"; mkdir -p "$R/tools/swap-poc/chaos"
H64() { printf '%064d' "$1" | tr 0 a; }
(
  cd "$R" && git init -q . && git config user.email t@t && git config user.name t
  cp "$SRC"/lib.sh "$SRC"/check-*.sh tools/swap-poc/
  # btc / divi / e2e-local / chaos status files
  mkdir -p docs/plans/swap-poc/status crates/swap-chain-btc/src crates/swap-chain-divi/src crates/swap-chain-evm/src
  echo 'impl ChainBackend for BtcBackend {}' > crates/swap-chain-btc/src/lib.rs
  echo 'impl ChainBackend for DiviBackend {}' > crates/swap-chain-divi/src/lib.rs
  echo 'fn x() {}' > crates/swap-chain-evm/src/lib.rs
  for k in live_fund_txid live_claim_txid live_refund_txid; do
    echo "- $k: $(H64 1)" >> docs/plans/swap-poc/status/btc.md
    echo "- $k: $(H64 2)" >> docs/plans/swap-poc/status/divi.md
  done
  for k in happy_divi_lock happy_divi_claim casec_divi_lock casec_divi_refund cased_divi_claim \
           happy_btc_lock happy_btc_claim casec_btc_lock casec_btc_refund cased_btc_claim; do
    echo "- ${k}_txid: $(H64 3)" >> docs/plans/swap-poc/status/e2e-local.md
  done
  echo "- cased_claim_secs_before_timeout: 12" >> docs/plans/swap-poc/status/e2e-local.md
  for k in accepted taker_lock_seen taker_lock_confirmed maker_locked maker_lock_confirmed \
           taker_claimed maker_claimed maker_refundable maker_refunded rpc_outage esplora_429; do
    echo "- chaos_$k: \`$(H64 4)\`" >> docs/plans/swap-poc/status/chaos.md
  done
  # deploy
  D=deploy/divi-swapd; mkdir -p $D
  printf '%s\n' '[Service]' 'User=divi-swapd' 'ProtectSystem=strict' 'NoNewPrivileges=yes' 'PrivateTmp=yes' \
    'LoadCredential=k:/x' 'StateDirectory=divi-swapd' 'Restart=on-failure' \
    'ExecStart=/nonexistent/divi-swapd --config /x' > $D/divi-swapd.service
  echo 'size 10M' > $D/logrotate-divi-swapd; echo 'location /swap/ {}' > $D/nginx-swap.conf
  echo '# x' > $D/divi-swapd.toml.example; echo '# x' > $D/README.md
  printf '#!/usr/bin/env bash\necho "DRY RUN"; echo "ssh dnsdivi true"\n' > $D/deploy.sh; chmod +x $D/deploy.sh
  # e2e / rev-tools
  printf '#!/usr/bin/env bash\nexit 0\n' > tools/swap-poc/e2e.sh; chmod +x tools/swap-poc/e2e.sh
  printf 'import argparse\np = argparse.ArgumentParser()\np.add_argument("--offer")\np.parse_args()\n' > tools/swap-poc/chaos/driver.py
  # usdc
  mkdir -p contracts/htlc/src; touch contracts/htlc/foundry.toml contracts/htlc/src/Erc20Htlc.sol
  printf '## Recommendation\nx\n' > docs/plans/swap-poc/usdc-design.md
)
# cargo stub (always on PATH; lib.sh's rcargo/crate_green call it): succeeds; `--list` names every word the scripts mention
cat > "$BIN/cargo" <<STUBEOF
#!/usr/bin/env bash
if [[ "\$*" == *"--list"* ]]; then grep -ohE '[a-z][a-z0-9_]+' "$R"/tools/swap-poc/check-*.sh | sort -u | sed 's/\$/: test/'; fi
exit 0
STUBEOF
chmod +x "$BIN/cargo"

# --- case runner -------------------------------------------------------------------------------------
# run_case <name> <script> <want_rc> <want_regex|-> <forbid_regex|-> [VAR=val ...] — tools: absent unless listed in TOOLS
OUT=""; RC=0
run_script() { # run_script <script> [VAR=val ...]
  local s="$1"; shift
  : > "$T/calls.log"
  OUT="$(cd "$R" && env -i HOME="$HOME_T" PATH="$STUBS_ON:$BIN" CALL_LOG="$T/calls.log" R="$R" "$@" \
         bash "tools/swap-poc/$s" 2>&1)"; RC=$?
}
expect() { # expect <name> <want_rc> <want_regex|-> <forbid_regex|->
  local name="$1" wrc="$2" want="$3" forbid="$4" good=1
  [[ "$wrc" == - ]] || (( RC == wrc )) || { good=0; echo "      exit $RC, wanted $wrc"; }
  [[ "$want" == - ]] || grep -qE -- "$want" <<<"$OUT" || { good=0; echo "      output lacks /$want/"; }
  [[ "$forbid" == - ]] || ! grep -qE -- "$forbid" <<<"$OUT" || { good=0; echo "      output has /$forbid/"; }
  if (( good )); then ok "$name"; else bad "$name"; echo "$OUT" | tail -8 | sed 's/^/      | /'; fi
}
calls() { grep -c "^$1" "$T/calls.log" 2>/dev/null || true; }
with_tools() { # with_tools "<stub names>" — a PATH dir holding only those stubs
  rm -rf "$T/on"; mkdir -p "$T/on"; for n in $1; do ln -s "$STUBS/$n" "$T/on/$n"; done; STUBS_ON="$T/on"
}
absent_ok() { # lib.sh re-prepends fixed dirs; make sure the "absent" tool is really absent before trusting the case
  local t="$1"; if env -i HOME="$HOME_T" PATH="$STUBS_ON:$BIN" bash -c "source <(sed -n '/^export PATH=/p' '$SRC/lib.sh'); command -v $t" >/dev/null 2>&1; then
    echo "note: $t is on lib.sh's fixed PATH dirs here; absent-tool case for $t not meaningful on this host"; return 1; fi
}

# btc ---------------------------------------------------------------------------------------------------
with_tools "curl"
run_script check-btc.sh;                       expect "btc: no opt-in -> 3 SKIP naming the opt-in, exit 0" 0 'SKIP \(network row, set SWAP_CHECK_NETWORK=1 to run\): live_fund_txid' 'FAIL'
[[ "$(calls curl)" == 0 ]] && ok "btc: no opt-in -> curl never invoked" || bad "btc: no opt-in -> curl invoked $(calls curl)x"
[[ "$(grep -c '^SKIP' <<<"$OUT")" == 3 ]] && ok "btc: exactly the 3 live_*_txid rows skipped" || bad "btc: skip count $(grep -c '^SKIP' <<<"$OUT")"
run_script check-btc.sh SWAP_CHECK_NETWORK=1;  expect "btc: opt-in + confirmed -> PASS, exit 0" 0 'ok:   live_fund_txid .* confirmed' 'SKIP|FAIL'
[[ "$(calls curl)" == 3 ]] && ok "btc: opt-in -> curl invoked once per row (3)" || bad "btc: opt-in curl calls $(calls curl)"
run_script check-btc.sh SWAP_CHECK_NETWORK=1 STUB_CURL_CONFIRMED=false; expect "btc: opt-in + unconfirmed -> FAIL, exit 1" 1 'FAIL: live_fund_txid' -

# divi / e2e-local / chaos: same gate -------------------------------------------------------------------
run_script check-divi.sh;      expect "divi: no opt-in -> SKIP, exit 0" 0 'SKIP \(network row' 'FAIL'
[[ "$(calls curl)" == 0 ]] && ok "divi: no opt-in -> curl never invoked" || bad "divi: curl invoked"
run_script check-divi.sh SWAP_CHECK_NETWORK=1 STUB_CURL_CONFS=0; expect "divi: opt-in + 0 confs -> FAIL, exit 1" 1 'FAIL: live_fund_txid' -
run_script check-chaos.sh;     expect "chaos: no opt-in -> SKIP, exit 0" 0 'SKIP \(network row' 'FAIL: chaos_'
[[ "$(calls curl)" == 0 ]] && ok "chaos: no opt-in -> curl never invoked" || bad "chaos: curl invoked"
run_script check-chaos.sh SWAP_CHECK_NETWORK=1; expect "chaos: opt-in -> network rows run (curl called)" - - 'SKIP \(network row'
[[ "$(calls curl)" -ge 1 ]] && ok "chaos: opt-in -> curl invoked" || bad "chaos: opt-in did not reach curl"
with_tools "curl shellcheck"
run_script check-e2e-local.sh; expect "e2e-local: no opt-in -> network rows SKIP, exit 0" 0 'SKIP \(network row' 'FAIL'
[[ "$(calls curl)" == 0 ]] && ok "e2e-local: no opt-in -> curl never invoked" || bad "e2e-local: curl invoked"

# shellcheck: e2e-local, rev-tools, deploy ---------------------------------------------------------------
with_tools ""
if absent_ok shellcheck; then
  run_script check-e2e-local.sh;  expect "e2e-local: shellcheck absent -> SKIP (shellcheck not installed), exit 0" 0 'SKIP \(shellcheck not installed\): e2e.sh shellcheck' 'FAIL'
  run_script check-rev-tools.sh;  expect "rev-tools: shellcheck absent -> SKIP, exit 0" 0 'SKIP \(shellcheck not installed\): shellcheck tools/swap-poc/e2e.sh' 'FAIL'
  run_script check-deploy.sh;     expect "deploy: shellcheck absent -> SKIP, exit 0" 0 'SKIP \(shellcheck not installed\): shellcheck' 'FAIL: shellcheck'
fi
with_tools "shellcheck"
run_script check-e2e-local.sh STUB_SHELLCHECK=err; expect "e2e-local: shellcheck reports error -> FAIL, exit 1" 1 'FAIL: e2e.sh shellcheck' 'SKIP \(shellcheck'
run_script check-rev-tools.sh STUB_SHELLCHECK=err; expect "rev-tools: shellcheck reports error -> FAIL, exit 1" 1 'FAIL: shellcheck tools/swap-poc/e2e.sh' -
run_script check-deploy.sh STUB_SHELLCHECK=err;    expect "deploy: shellcheck reports error -> FAIL, exit 1" 1 'FAIL: shellcheck' -
run_script check-e2e-local.sh;  expect "e2e-local: shellcheck clean -> PASS row" 0 'ok:   e2e.sh shellcheck' 'FAIL: e2e.sh shellcheck'
run_script check-rev-tools.sh;  expect "rev-tools: shellcheck clean -> PASS, exit 0" 0 'PASS: rev-tools' 'FAIL'
run_script check-deploy.sh;     expect "deploy: shellcheck clean -> PASS row" 0 'ok:   shellcheck' 'FAIL: shellcheck'

# forge: usdc --------------------------------------------------------------------------------------------
with_tools ""
if absent_ok forge; then
  run_script check-usdc.sh;     expect "usdc: forge absent -> SKIP (forge not installed), exit 0" 0 'SKIP \(forge not installed\): forge test contracts/htlc' 'FAIL'
fi
with_tools "forge"
run_script check-usdc.sh STUB_FORGE=err; expect "usdc: forge test fails -> FAIL, exit 1" 1 'FAIL: forge test contracts/htlc' -
run_script check-usdc.sh;     expect "usdc: forge clean -> PASS, exit 0" 0 'PASS: usdc' 'FAIL'

# systemd-analyze: deploy --------------------------------------------------------------------------------
with_tools "shellcheck"
if absent_ok systemd-analyze; then
  run_script check-deploy.sh;   expect "deploy: systemd-analyze absent -> SKIP (systemd-analyze not installed), exit 0" 0 'SKIP \(systemd-analyze not installed\): systemd-analyze verify' 'FAIL'
fi
with_tools "shellcheck systemd-analyze"
run_script check-deploy.sh STUB_SDA_RC=1 STUB_SDA_OUT='divi-swapd.service: Command /nonexistent/divi-swapd is not executable: No such file or directory'
expect "deploy: ExecStart binary absent -> SKIP with the binary named, exit 0" 0 'SKIP \(ExecStart binary /nonexistent/divi-swapd not installed\): systemd-analyze verify' 'FAIL'
run_script check-deploy.sh STUB_SDA_RC=1 STUB_SDA_OUT='/lib/systemd/system/snapd.service:23: Unknown key name RestartMode
divi-swapd.service: Command /nonexistent/divi-swapd is not executable: No such file or directory'
expect "deploy: binary absent + unrelated noise about other units -> SKIP, exit 0" 0 'SKIP \(ExecStart binary' 'FAIL'
run_script check-deploy.sh STUB_SDA_RC=1 STUB_SDA_OUT='deploy/divi-swapd/divi-swapd.service:3: Unknown key name Bogus in section Service'
expect "deploy: unit syntax error -> FAIL, exit 1" 1 'FAIL: systemd-analyze verify' 'SKIP \(ExecStart'
run_script check-deploy.sh STUB_SDA_RC=1 STUB_SDA_OUT='deploy/divi-swapd/divi-swapd.service:3: Unknown key name Bogus in section Service
divi-swapd.service: Command /nonexistent/divi-swapd is not executable: No such file or directory'
expect "deploy: syntax error AND binary absent -> still FAIL, exit 1" 1 'FAIL: systemd-analyze verify' 'SKIP \(ExecStart'
run_script check-deploy.sh STUB_SDA_RC=1;  expect "deploy: verify fails with no output we can attribute -> FAIL, exit 1" 1 'FAIL: systemd-analyze verify' -
run_script check-deploy.sh;    expect "deploy: systemd-analyze clean -> PASS row, exit 0" 0 'ok:   systemd-analyze verify' 'FAIL'

# a SKIP is not a failure anywhere: exit code follows FAILS only ------------------------------------------
with_tools ""
run_script check-btc.sh; [[ $RC == 0 && "$OUT" == *"PASS: btc ("*" skipped)"* ]] && ok "finish: PASS line reports the skip count" || bad "finish: PASS line lacks skip count: $(tail -1 <<<"$OUT")"

echo "---"
if (( FAILS )); then echo "$FAILS of $CASES harness case(s) failed"; exit 1; fi
echo "PASS: test-check-hermetic ($CASES cases)"
