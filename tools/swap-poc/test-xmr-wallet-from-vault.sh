#!/usr/bin/env bash
# Self-test for xmr-wallet-from-vault.sh: a mock `secret` and a mock monero-wallet-rpc (a tiny local
# HTTP stub), no network, no real secret. Proves the fake seed never reaches argv, stdout, stderr or
# any file left behind, and that the trap wipes the wallet dir on success, failure, SIGINT and SIGTERM.
# Run: tools/swap-poc/test-xmr-wallet-from-vault.sh   (or xmr-wallet-from-vault.sh --self-test)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL="$HERE/xmr-wallet-from-vault.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/xmrvault-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/shm" "$T/fixture" "$T/out"
FAILS=0
ok() { echo "ok:   $*"; }
bad() { echo "FAIL: $*"; FAILS=$((FAILS + 1)); }

# Fixture: a recognisable fake 25-word seed. It lives only in $T/fixture, which is excluded from the
# leftover-file scan and removed with $T.
SEED="zephyr ocean lantern quartz meadow violin harbor tundra sphinx velvet ripple anchor bronze castle dagger ember falcon glacier hollow island jungle kettle lagoon marble nectar zephyr"
printf '%s\n' "$SEED" > "$T/fixture/seed"
export T

cat > "$T/bin/secret" <<'EOF'
#!/usr/bin/env bash
# mock `secret get --name N --op-ref R`
[ "$1" = get ] || exit 2
name=""; while [ $# -gt 0 ]; do [ "$1" = --name ] && name="$2"; shift; done
echo "$name" >> "$T/secret.calls"
[ -z "${MOCK_SECRET_FAIL:-}" ] || exit 1
case "$name" in
  taker-xmr-wallet-rpc-username) echo rpcuser;;
  taker-xmr-wallet-rpc-password) echo rpcpw-test;;
  *) cat "$T/fixture/seed";;
esac
EOF

cat > "$T/bin/monero-wallet-rpc" <<'EOF'
#!/usr/bin/env bash
# mock monero-wallet-rpc: parse the flags the tool passes, then run the HTTP stub
while [ $# -gt 0 ]; do
  case "$1" in
    --rpc-bind-port) port="$2"; shift 2;;
    --wallet-dir) wdir="$2"; shift 2;;
    --config-file) conf="$2"; shift 2;;
    *) shift;;
  esac
done
exec python3 -I "$T/stub.py" "$port" "$wdir" "$conf"
EOF

cat > "$T/stub.py" <<'EOF'
import hashlib, json, os, signal, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, wdir, conf = int(sys.argv[1]), sys.argv[2], sys.argv[3]
user = [l.split("=", 1)[1].split(":")[0] for l in open(conf) if l.startswith("rpc-login=")][0].strip()
want = hashlib.sha256(open(os.environ["T"] + "/fixture/seed", "rb").read().strip()).hexdigest()
log = open(os.environ["T"] + "/rpc.methods", "a")
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        auth = self.headers.get("Authorization", "")
        if not auth:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Digest realm="mock", nonce="n0", qop="auth"')
            self.send_header("Content-Length", "0"); self.end_headers(); return
        assert 'username="%s"' % user in auth
        m, p = body.get("method"), body.get("params", {})
        log.write(m + "\n"); log.flush()
        res = {}
        if m == "restore_deterministic_wallet":
            if os.environ.get("MOCK_FAIL"):
                out = {"error": {"code": -1, "message": "mock failure"}}
            else:
                seed_ok = hashlib.sha256(p["seed"].encode()).hexdigest() == want
                log.write("seed_matches=%s\n" % seed_ok); log.flush()
                open(wdir + "/swap.keys", "w").write("fake-keys\n")   # a stand-in for the wallet file
                open(wdir + "/swap", "w").write("fake-cache\n")
                out = {"result": {"address": "5MockAddress" + "x" * 83, "info": "ok"}}
        elif m == "get_address": out = {"result": {"address": "5MockAddress" + "x" * 83}}
        elif m == "get_height": out = {"result": {"height": 123456}}
        else: out = {"result": res}
        data = json.dumps(dict(out, id="0", jsonrpc="2.0")).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
HTTPServer(("127.0.0.1", port), H).serve_forever()
EOF
chmod +x "$T/bin/secret" "$T/bin/monero-wallet-rpc"

export PATH="$T/bin:$PATH" XMR_VAULT_SHM="$T/shm"
PORT=$((39500 + $$ % 400))
run() { "$TOOL" --network stagenet --restore-height 100 --port "$PORT" "$@"; }
shm_empty() { [ -z "$(ls -A "$T/shm")" ]; }
no_rpc() { ! pgrep -f "stub.py $PORT " >/dev/null; }
leak_scan() { # leak_scan <label>: the seed must be in no file under $T except the fixture
  if grep -rlF -e "ripple anchor" -e "zephyr ocean" "$T" 2>/dev/null | grep -v "^$T/fixture/" | grep -q .; then
    bad "$1: seed text found in a file"; else ok "$1: no file holds the seed"; fi
}

# 1. dry run: prints the plan, makes no secret call, starts nothing
run --dry-run > "$T/out/dry" 2>&1; rc=$?
if [ $rc = 0 ] && grep -q '^plan' "$T/out/dry" && [ ! -e "$T/secret.calls" ] && shm_empty; then
  ok "dry-run prints the plan, no secret call, no dir"; else bad "dry-run (rc=$rc)"; fi

# 2. success, --once: address and height only, nothing left behind
run --once > "$T/out/o1" 2> "$T/out/e1"; rc=$?
if [ $rc = 0 ] && grep -q '^address 5Mock' "$T/out/o1" && grep -q '^height 123456$' "$T/out/o1"; then
  ok "success: address and height printed"; else bad "success output (rc=$rc)"; fi
[ "$(wc -l < "$T/out/o1")" = 2 ] && ok "success: stdout is exactly two lines" || bad "stdout has extra lines"
grep -qx 'seed_matches=True' "$T/rpc.methods" && ok "success: the stub received the real seed in the POST body" || bad "stub did not get the seed"
grep -qx close_wallet "$T/rpc.methods" && ok "success: close_wallet was called" || bad "close_wallet not called"
shm_empty && ok "success: wallet dir wiped" || bad "success: dir left behind: $(ls "$T/shm")"
no_rpc && ok "success: wallet-rpc stopped" || bad "success: wallet-rpc still running"
grep -q -e zephyr -e ripple "$T/out/o1" "$T/out/e1" && bad "success: seed on stdout/stderr" || ok "success: seed not on stdout or stderr"
leak_scan success

# 3. failure: the restore is refused
: > "$T/rpc.methods"
MOCK_FAIL=1 run --once > "$T/out/o2" 2> "$T/out/e2"; rc=$?
[ $rc = 10 ] && ok "failure: exit 10" || bad "failure: exit $rc, wanted 10"
shm_empty && ok "failure: wallet dir wiped" || bad "failure: dir left behind"
no_rpc && ok "failure: wallet-rpc stopped" || bad "failure: wallet-rpc still running"
grep -q -e zephyr -e ripple "$T/out/o2" "$T/out/e2" && bad "failure: seed on stdout/stderr" || ok "failure: seed not on stdout or stderr"
leak_scan failure

# 3b. the vault is unavailable: exit 9, nothing left behind
MOCK_SECRET_FAIL=1 run --once > "$T/out/o3" 2> "$T/out/e3"; rc=$?
[ $rc = 9 ] && shm_empty && no_rpc && ok "secret down: exit 9, nothing left" || bad "secret down (rc=$rc)"

# 4/5. stays up, then SIGINT / SIGTERM. A background job of a non-interactive shell ignores SIGINT, so
# start it through perl, which restores the default disposition first.
for sig in INT TERM; do
  : > "$T/rpc.methods"
  perl -e '$SIG{INT}="DEFAULT"; $SIG{TERM}="DEFAULT"; exec @ARGV' -- "$TOOL" --network stagenet \
    --restore-height 100 --port "$PORT" > "$T/out/o_$sig" 2> "$T/out/e_$sig" &
  pid=$!
  for _ in $(seq 1 100); do grep -q '^height' "$T/out/o_$sig" 2>/dev/null && break; sleep 0.1; done
  grep -q '^height' "$T/out/o_$sig" || bad "$sig: tool never reached the open-wallet state"
  [ -n "$(ls -A "$T/shm")" ] && ok "$sig: wallet files exist while it is up" || bad "$sig: no wallet dir while up"
  if ps -axww -o args= | grep -v 'grep' | grep -q -e zephyr -e ripple -e 'rpcpw-test'; then
    bad "$sig: seed or rpc password visible in ps"; else ok "$sig: nothing secret in any process argv"; fi
  kill -$sig "$pid"; wait "$pid"; rc=$?
  want=$([ $sig = INT ] && echo 130 || echo 143)
  [ $rc = $want ] && ok "$sig: exit $rc" || bad "$sig: exit $rc, wanted $want"
  shm_empty && ok "$sig: wallet dir wiped" || bad "$sig: dir left behind"
  no_rpc && ok "$sig: wallet-rpc stopped" || bad "$sig: wallet-rpc still running"
  grep -q -e zephyr -e ripple "$T/out/o_$sig" "$T/out/e_$sig" && bad "$sig: seed on stdout/stderr" || ok "$sig: seed not on stdout or stderr"
  leak_scan "$sig"
done

# 6. mainnet is refused without the opt-in
"$TOOL" --network mainnet --restore-height 1 --dry-run >/dev/null 2>&1 && bad "mainnet allowed without opt-in" || ok "mainnet refused without XMR_VAULT_ALLOW_MAINNET=1"

echo
if [ "$FAILS" = 0 ]; then echo "self-test: PASS"; else echo "self-test: $FAILS FAILED"; exit 1; fi
