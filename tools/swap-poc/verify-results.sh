#!/usr/bin/env bash
# Read-only verification: every full (64-hex-char) txid in docs/plans/swap-poc/RESULTS.md,
# checked against its own chain's public explorer/node API. No keys, no secrets, no cargo.
#
#   tools/swap-poc/verify-results.sh [--parse-only] [path-to-RESULTS.md]
#
# Chain attribution: for each txid, the nearest preceding label word *on its own line*
# (BTC/LTC/DIVI/ZEC/XMR/Sepolia/USDC) wins — not anywhere on the line, since a line can
# legitimately mention a different, later txid's own label after this one. If a line has
# none before this txid, the last label word stated on an earlier line since the last
# `##`/`###` heading is the fallback, then the heading's own label word (RESULTS.md's own
# convention — see its usage note — every multi-coin entry labels each txid inline; only a
# few early single-chain sections rely on the heading).
#
# A handful of txids are hardcoded exceptions, because no generic rule reads them correctly:
# CHAIN_OVERRIDES for one whose own label is a documented self-correction ("the driver logs
# it as X; it is actually Y"); EXCLUDED_TXIDS for ones RESULTS.md itself says were computed
# but never broadcast (a rejected probe — "txid would have been ..."), which would otherwise
# always, correctly, read as MISSING. Both are listed with their reason in the script body.
#
# DIVI needs `ssh dnsdivi` running `divi-cli` there (no public DIVI testnet explorer API);
# if that host is not reachable from wherever this runs (checked once, up front), every DIVI
# row is reported SKIPPED rather than MISSING and does not affect the exit code — this is
# expected on hp2, which has no route/host key for dnsdivi; it works from the Mac.
#
# --parse-only: print `<chain><TAB><txid>` per attributed txid and `excluded<TAB><txid><TAB>
# <reason>` per excluded one, then exit 0 — no network calls at all. Used by
# test-verify-results.sh to check attribution in isolation; also handy by hand to audit a
# RESULTS.md edit before spending real API calls on it.
#
# Prints one row per unique (chain, txid): chain, txid, confirmations, ok/missing/skipped.
# Exits nonzero if any row is MISSING (skipped and excluded rows do not count).
set -uo pipefail
die() { echo "verify-results: $*" >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repo"
cd "$ROOT" || die "cannot cd to $ROOT"
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

PARSE_ONLY=0
if [[ "${1:-}" == "--parse-only" ]]; then
  PARSE_ONLY=1
  shift
fi
RESULTS="${1:-docs/plans/swap-poc/RESULTS.md}"
[[ -f "$RESULTS" ]] || die "no such file: $RESULTS"

PYHELPER="$(mktemp)"
trap 'rm -f "$PYHELPER"' EXIT INT TERM
cat >"$PYHELPER" <<'PYEOF'
import json
import re
import subprocess
import sys
import tempfile
import urllib.request

# ---- RESULTS.md parsing --------------------------------------------------------------

TXID_CONTENT_RE = re.compile(r"^[0-9a-f]{64}$")
BACKTICK_RE = re.compile(r"`([^`]*)`")
HEADING_RE = re.compile(r"^#{1,6}\s+(.*)")

# Case-insensitive, word-bounded, with an optional leading testnet/stagenet-amount prefix
# letter ("tBTC", "tDIVI", "sBTC", "sXMR" all appear in this document): avoids both
# "individual"/"dividend" (substring "divi" with no real word boundary around it) and
# "height"/"together"/"method" (no bare "eth" keyword exists here at all — too
# collision-prone to be worth it; "sepolia"/"usdc" are the distinguishing words this
# document actually uses for the EVM chain).
KEYWORD_PATTERNS = [
    ("btc", re.compile(r"\b[st]?BTC\b", re.I)),
    ("ltc", re.compile(r"\b[st]?LTC\b", re.I)),
    ("divi", re.compile(r"\b[st]?divi\b", re.I)),
    ("zec", re.compile(r"\b[st]?ZEC\b", re.I)),
    ("xmr", re.compile(r"\b[st]?XMR\b", re.I)),
    ("sepolia", re.compile(r"\bsepolia\b", re.I)),
    ("usdc", re.compile(r"\bUSDC\b", re.I)),
]


def nearest_keyword(text):
    # The occurrence closest to the *end* of text wins, not the first one found: a line
    # (or a line prefix) can legitimately mention more than one chain — its own label, then
    # a later txid's label further along — and only the label closest to the position being
    # resolved actually describes it.
    best = None
    for name, pat in KEYWORD_PATTERNS:
        last = None
        for mm in pat.finditer(text):
            last = mm
        if last and (best is None or last.start() > best[1]):
            best = (name, last.start())
    return best[0] if best else None


def normalize_chain(chain):
    # USDC and plain Sepolia mentions both verify the same way (one EVM RPC check); keep
    # them as one chain for dispatch, Base Sepolia can be added the same way once there is
    # a real txid to verify against it.
    return "sepolia" if chain == "usdc" else chain


MATCHED_PAREN_RE = re.compile(r"\([^()]*\)")


def resolve_keyword(text):
    # Every tier searches *outside* any backtick span (quoted log lines and command output
    # like "`divi-swapd up`", file paths, other txids/truncated-ids all legitimately
    # contain other chains' names or hex-looking text as plain substrings) and *outside*
    # any fully-matched, already-closed parenthetical aside (e.g. "DIVI claim (maker,
    # preimage read from the LTC spend) `<hash>`" — the parenthetical is commentary about
    # a *different* chain's earlier transaction, not this hash's own label, and must not
    # beat the real "DIVI claim" label just for being closer). Repeated passes strip
    # nested parens too. A still-*open* paren (no matching close within this text) is a
    # hard boundary instead: the position being resolved sits inside that still-open
    # aside, so content from *before* it belongs to an outer clause and does not apply
    # (e.g. "DIVI RPC 502 ... (swap `<id>`, maker BTC claim " — only "BTC", stated inside
    # the same open parenthetical as the hash itself, should win).
    text = BACKTICK_RE.sub(" ", text)
    while True:
        new = MATCHED_PAREN_RE.sub(" ", text)
        if new == text:
            break
        text = new
    idx = text.rfind("(")
    if idx != -1:
        text = text[idx + 1 :]
    return nearest_keyword(text)


# The keyword heuristic reads what the surrounding prose *labels* a txid, which is right
# almost everywhere RESULTS.md labels consistently — except where the document itself
# flags its own label as wrong. The Wave 3 crash-recovery line for this one says in so many
# words: "the driver logs it as 'taker BTC refund'; it is the DIVI leg" — i.e. the line's
# own "BTC" keyword is a known-bad label for this specific txid. No generic heuristic can
# read that self-correction; hardcode it instead of trying to teach the parser English.
CHAIN_OVERRIDES = {
    "d1a45509a64dbbd88fa7e5bde370db0f0935bf674d058873d88c10365f404346": "divi",
}

# These are computed-but-never-broadcast identifiers: RESULTS.md itself documents each one
# as rejected before it could land on any chain. No explorer will ever show them, by
# design — checking them would always, correctly, report MISSING, which misreads "never
# sent" as "lost". Excluded entirely rather than checked; reason kept alongside for anyone
# auditing this list later.
EXCLUDED_TXIDS = {
    "1e184a6fdc4162ab9629e9b1da998cab48f22346400d27694b3158ffaee37f66": (
        "CLTV-violation probe deliberately rejected by the node "
        "(64: non-mandatory-script-verify-flag); RESULTS.md line 48: "
        "'txid would have been'"
    ),
}


def parse_results(path):
    section_default = None
    running_default = None  # last keyword seen on any line, within the current section
    items = []  # (chain, txid, line_no)
    excluded = []  # (txid, reason, line_no)
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            h = HEADING_RE.match(line)
            if h:
                section_default = resolve_keyword(h.group(1))
                running_default = None
                continue
            line_keyword = resolve_keyword(line)
            for m in BACKTICK_RE.finditer(line):
                content = m.group(1)
                if not TXID_CONTENT_RE.fullmatch(content):
                    continue
                if content in EXCLUDED_TXIDS:
                    excluded.append((content, EXCLUDED_TXIDS[content], lineno))
                    continue
                # Tier 1: the nearest label *before this txid, on its own line* — not
                # anywhere on the line (a line can state a different, later txid's label
                # after this one; e.g. "maker BTC refund `<hash>`, taker DIVI refund after
                # the 6 h locktime `<other hash>`" — "DIVI" must not win for the BTC hash).
                # Tier 2: the last label seen on an *earlier* line since the last heading —
                # a bullet's own label line, followed by indented continuation lines with
                # none of their own (e.g. "- Leftover tBTC swept ...:\n  taker ... ->
                # `<64 hex>`;\n  maker ... -> `<64 hex>`.").
                # Tier 3: the enclosing section heading.
                chain = CHAIN_OVERRIDES.get(content) or (
                    resolve_keyword(line[: m.start()])
                    or running_default
                    or section_default
                    or "unknown"
                )
                items.append((normalize_chain(chain), content, lineno))
            if line_keyword:
                running_default = line_keyword
    return items, excluded


# ---- BTC / LTC: Esplora REST ----------------------------------------------------------

# litecoinspace.org's Cloudflare front door 403s urllib's default "Python-urllib/x.y"
# User-Agent (curl's default UA passes); mempool.space does not care either way, so send
# this on every request for both.
USER_AGENT = "verify-results.sh/1.0 (+https://github.com)"


def http_get_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def http_get_text(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode().strip()


def esplora_confirmations(base, txid):
    try:
        tx = http_get_json(f"{base}/tx/{txid}")
    except Exception:
        return None
    status = tx.get("status", {})
    if not status.get("confirmed"):
        return None
    height = status.get("block_height")
    try:
        tip = int(http_get_text(f"{base}/blocks/tip/height"))
    except Exception:
        tip = None
    if height is None or tip is None:
        return None
    return tip - height + 1


def verify_btc(txid):
    return esplora_confirmations("https://mempool.space/testnet/api", txid)


def verify_ltc(txid):
    return esplora_confirmations("https://litecoinspace.org/testnet/api", txid)


# ---- DIVI: ssh dnsdivi + divi-cli (no public testnet explorer API) --------------------

def check_ssh_dnsdivi():
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", "dnsdivi", "true"],
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


def verify_divi(txid):
    try:
        r = subprocess.run(
            [
                "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "dnsdivi",
                "divi-cli", "-conf=/opt/divi-testnet/node5/divi.conf",
                "-datadir=/opt/divi-testnet/node5/data",
                "getrawtransaction", txid, "1",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if r.returncode != 0:
            return None
        return json.loads(r.stdout).get("confirmations")
    except Exception:
        return None


# ---- ZEC: hand-framed gRPC to lightwalletd (no public REST/JSON explorer exists) -----
# cash.z.wallet.sdk.rpc.CompactTxStreamer, same proto field numbers
# crates/swap-chain-zec/src/grpc.rs already hand-encodes against (no protoc, no protobuf
# package here either — just the same tiny varint/length-delimited scanner).

ZEC_HOST = "https://testnet.zec.rocks:443"
ZEC_PATH_GET_TX = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTransaction"
ZEC_PATH_LATEST = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock"


def read_varint(data, i):
    result, shift = 0, 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i


def parse_proto(data):
    i, n, out = 0, len(data), []
    while i < n:
        tag, i = read_varint(data, i)
        field_num, wire_type = tag >> 3, tag & 7
        if wire_type == 0:
            val, i = read_varint(data, i)
        elif wire_type == 2:
            length, i = read_varint(data, i)
            val = data[i : i + length]
            i += length
        elif wire_type == 1:
            val, i = data[i : i + 8], i + 8
        elif wire_type == 5:
            val, i = data[i : i + 4], i + 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire_type}")
        out.append((field_num, wire_type, val))
    return out


def grpc_unary(path, msg_bytes, timeout=20):
    frame = bytes([0]) + len(msg_bytes).to_bytes(4, "big") + msg_bytes
    with tempfile.NamedTemporaryFile() as reqf, tempfile.NamedTemporaryFile() as respf:
        reqf.write(frame)
        reqf.flush()
        try:
            rc = subprocess.run(
                [
                    "curl", "-fsS", "-m", str(timeout), "--http2", "-X", "POST",
                    f"{ZEC_HOST}{path}",
                    "-H", "content-type: application/grpc", "-H", "te: trailers",
                    "--data-binary", f"@{reqf.name}", "-o", respf.name,
                ],
                capture_output=True,
                timeout=timeout + 5,
            )
        except Exception:
            return None
        if rc.returncode != 0:
            return None
        with open(respf.name, "rb") as f:
            raw = f.read()
    i, msgs = 0, []
    while i + 5 <= len(raw):
        length = int.from_bytes(raw[i + 1 : i + 5], "big")
        msgs.append(raw[i + 5 : i + 5 + length])
        i += 5 + length
    return b"".join(msgs) if msgs else None


def verify_zec(txid):
    try:
        reversed_bytes = bytes.fromhex(txid)[::-1]
    except ValueError:
        return None
    req_msg = bytes([0x1A, len(reversed_bytes)]) + reversed_bytes  # TxFilter.hash, tag 3
    tx_resp = grpc_unary(ZEC_PATH_GET_TX, req_msg)
    if tx_resp is None:
        return None
    height = None
    for field_num, wire_type, val in parse_proto(tx_resp):
        if field_num == 2 and wire_type == 0:  # RawTransaction.height
            height = val
    if not height:
        return None
    tip_resp = grpc_unary(ZEC_PATH_LATEST, b"")  # ChainSpec {} is 0 bytes
    if tip_resp is None:
        return None
    tip = None
    for field_num, wire_type, val in parse_proto(tip_resp):
        if field_num == 1 and wire_type == 0:  # BlockID.height
            tip = val
    if tip is None:
        return None
    return tip - height + 1


# ---- XMR: Monero daemon's own get_transactions (plain REST+JSON, not JSON-RPC) --------

def http_post_json(url, payload, timeout=20):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def verify_xmr(txid):
    try:
        d = http_post_json(
            "http://node.monerodevs.org:38089/get_transactions",
            {"txs_hashes": [txid], "decode_as_json": False},
        )
    except Exception:
        return None
    txs = d.get("txs") or []
    if not txs:
        return None
    return txs[0].get("confirmations")


# ---- Sepolia: plain eth_getTransactionReceipt / eth_blockNumber JSON-RPC --------------

SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"


def verify_sepolia(txid):
    try:
        receipt = http_post_json(
            SEPOLIA_RPC,
            {
                "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt",
                "params": [f"0x{txid}"],
            },
        )
        result = receipt.get("result")
        if not result:
            return None
        height = int(result["blockNumber"], 16)
        tip_resp = http_post_json(
            SEPOLIA_RPC, {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}
        )
        tip = int(tip_resp["result"], 16)
        return tip - height + 1
    except Exception:
        return None


# ---- driver -----------------------------------------------------------------------

def main():
    results_path = sys.argv[1]
    parse_only = len(sys.argv) > 2 and sys.argv[2] == "1"
    items, excluded = parse_results(results_path)

    if parse_only:
        seen = set()
        for chain, txid, _lineno in items:
            if (chain, txid) in seen:
                continue
            seen.add((chain, txid))
            print(f"{chain}\t{txid}")
        for txid, reason, _lineno in excluded:
            print(f"excluded\t{txid}\t{reason}")
        return

    ssh_ok = check_ssh_dnsdivi()
    if any(chain == "divi" for chain, _, _ in items) and not ssh_ok:
        print(
            "verify-results: ssh dnsdivi is not reachable from here; "
            "every DIVI row below is skipped, not failed",
            file=sys.stderr,
        )
    for txid, reason, lineno in excluded:
        print(f"excluded {txid}      — {reason} (line {lineno})")

    verifiers = {
        "btc": verify_btc,
        "ltc": verify_ltc,
        "zec": verify_zec,
        "xmr": verify_xmr,
        "sepolia": verify_sepolia,
    }

    seen = set()
    missing = 0
    skipped = 0
    unknown = 0
    for chain, txid, _lineno in items:
        if (chain, txid) in seen:
            continue
        seen.add((chain, txid))

        if chain == "divi":
            if not ssh_ok:
                print(f"{chain:8} {txid} {'-':>6} skipped (ssh dnsdivi unavailable)")
                skipped += 1
                continue
            conf = verify_divi(txid)
        elif chain in verifiers:
            conf = verifiers[chain](txid)
        else:
            print(f"{chain:8} {txid} {'-':>6} UNKNOWN chain (not attributable — see script header)")
            unknown += 1
            continue

        if conf is not None and conf > 0:
            print(f"{chain:8} {txid} {conf:>6} ok")
        else:
            print(f"{chain:8} {txid} {'-':>6} MISSING")
            missing += 1

    total = len(seen)
    print(
        f"verify-results: {total} unique txid(s) checked, {missing} missing, "
        f"{skipped} skipped, {len(excluded)} excluded, {unknown} unattributed"
    )
    sys.exit(1 if missing > 0 else 0)


if __name__ == "__main__":
    main()
PYEOF

python3 "$PYHELPER" "$RESULTS" "$PARSE_ONLY"
