#!/usr/bin/env python3
"""Raw-transaction RPC replies of Divi Core divid and irondivid, compared field
by field.

Both nodes sit on one regtest chain that divid mines; irondivid's wallet comes
from divid's phrase, so both hold the same keys and coins and sign alike. The
same raw transactions, made once on divid, go to both nodes. Each row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit
code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
and the private keys given to signrawtransaction live only in memory and in RPC
messages; they are never printed or put on a command line or in a file.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("RAW_REPLIES_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("RAW_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true. "open:" rows are gaps not closed yet; "open: rpc-left" rows
# are being closed by fix/rpc-left (RPC-LEFT.md).
KNOWN = {
    "decoderawtransaction: fields divid lacks":
        "valueSat beside value on each output, as divid's getrawtransaction writes it (rpcrawtransaction.cpp:96-97); divid's decoderawtransaction writes value only (TxToJSON, JsonTxHelpers.cpp:66)",
    "decodescript: fields divid lacks":
        "hex, the script given (divid: rpcrawtransaction.cpp:556-563)",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "decoderawtransaction": {"valueSat"},
    "decodescript": {"hex"},
}
extra_seen = {}

fails = 0


def known(name):
    if name in KNOWN:
        return KNOWN[name]
    return KNOWN.get(name.split(": ", 1)[1]) if name.startswith("after restart: ") else None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0", "txindex=1",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (OSError, ValueError) as e:
            # No reply at all (the node stopped or closed the connection): a row
            # that differs, not the end of the run
            return ("err", "no reply", f"{type(e).__name__}: {e}"[:120])
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- how replies are compared ------------------------------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def kind(v):
    return {dict: "object", list: "array", str: "string", bool: "bool", int: "int", type(None): "null"}.get(type(v), "?")


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Reals are compared as divid writes
    them (the text of the number); a real and an integer are different types."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if type(a) is not type(b):
        return f"{path}: {kind(a)} {json.dumps(a)[:40]} vs {kind(b)} {json.dumps(b)[:40]}"
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:80]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, dict):
        return dict(v, injected=True)
    if isinstance(v, list):
        return v + ["injected"]
    if isinstance(v, int) and not isinstance(v, bool):
        return v + 1
    return "injected"


def compare(name, core, iron, drop=frozenset(), order=None):
    """Same outcome (a result, or an error with the same code and message); for a
    result the same fields, types and values (except `drop`), list items in
    divid's order unless `order` gives a sort key"""
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and usage_text(name, core[2]):
            # A wrong argument count: divid answers with the call's help text,
            # which is not compared (README.md); both must refuse with -1
            same = True
        if DUMP and not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        dump(name, ("ok", a), ("ok", b))
    row(name, short(core), d or short(iron), d is None)


def usage_text(name, message):
    """divid's reply to a wrong argument count: the help text, which starts with
    the call's name"""
    method = name.split(": ", 1)[1] if name.startswith("after restart: ") else name
    method = method.split(" ", 1)[0]
    return message.startswith(method + " ") or message.startswith(method + "\n")


def dump(name, core, iron):
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok":
        found = set(fields_in(iron[1])) & extra
        when = name.split(": ", 1)[0] if name.startswith("after restart: ") else ""
        extra_seen.setdefault(when, {}).setdefault(method, set()).update(found)
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)


def fields_in(v):
    """Every member name in a reply, at any depth"""
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from fields_in(x)
    elif isinstance(v, list):
        for x in v:
            yield from fields_in(x)


def extra_rows(when):
    p = f"{when}: " if when else ""
    for method in EXTRA:
        found = extra_seen.get(when, {}).get(method, set())
        row(f"{p}{method}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


def wait_for(fn, secs):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def setup_failed(kind_, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 90)


def seen_by(node, txid):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), 60)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def out_of(txid, addr):
    """(vout, scriptPubKey hex) of txid's output to addr"""
    tx = C.rpc("getrawtransaction", txid, 1)
    o = next(o for o in tx["vout"] if addr in o["scriptPubKey"].get("addresses", []))
    return o["n"], o["scriptPubKey"]["hex"]


# --- the nodes and the chain -----------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

C.rpc("setgenerate", 30)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# Keys of the wallet both nodes hold; N's key is used in multisig scripts only
A, B, N, Y, Z = (C.rpc("getnewaddress") for _ in range(5))
pub = {a: C.rpc("validateaddress", a)["pubkey"] for a in (A, B, N)}
# Two pay-to-script-hash multisig addresses: 1-of-2 and 2-of-2 of A's and B's keys
ms1 = C.rpc("createmultisig", 1, [pub[A], pub[B]])
ms2 = C.rpc("createmultisig", 2, [pub[A], pub[B]])
# A keyless address (regtest P2PKH version 139, random bytes)
W = b58check(bytes([139]) + secrets.token_bytes(20))

# The coins the raw transactions spend, in one block; each is locked on divid so
# no send of its wallet takes it
fund_a = C.rpc("sendtoaddress", A, 50)
fund_a2 = C.rpc("sendtoaddress", A, 30)
fund_p1 = C.rpc("sendtoaddress", ms1["address"], 20)
fund_p2 = C.rpc("sendtoaddress", ms2["address"], 20)
fund_low = C.rpc("sendtoaddress", B, 1)
fund_high = C.rpc("sendtoaddress", B, 150)
C.rpc("setgenerate", 1)
coin = {}
for name, txid, addr in (("a", fund_a, A), ("a2", fund_a2, A), ("p1", fund_p1, ms1["address"]),
                         ("p2", fund_p2, ms2["address"]), ("low", fund_low, B), ("high", fund_high, B)):
    n, spk = out_of(txid, addr)
    coin[name] = {"txid": txid, "vout": n, "scriptPubKey": spk}
C.rpc("lockunspent", False, [{"txid": c["txid"], "vout": c["vout"]} for c in coin.values()
                             if c["txid"] not in (fund_p1, fund_p2)])
if not synced():
    print("FAIL   setup: irondivid did not follow the block with the funding", flush=True)
    sys.exit(1)
coinbase = C.rpc("getblock", C.rpc("getblockhash", 3))["tx"][0]
unknown = "11" * 32
outpoint = lambda c: {"txid": c["txid"], "vout": c["vout"]}

# Private keys for the given-key forms: in memory and in RPC messages only
wif = {a: C.rpc("dumpprivkey", a) for a in (A, B)}

# Raw transactions, made on divid; outputs in name order (irondivid's RPC maps
# keep names sorted; see README.md)
LO, HI = sorted((Y, Z))
raw_a = C.rpc("createrawtransaction", [outpoint(coin["a"])], {Y: 49.99})
raw_a_two = C.rpc("createrawtransaction", [outpoint(coin["a2"])], {LO: 10, HI: 19.99})
raw_p1 = C.rpc("createrawtransaction", [outpoint(coin["p1"])], {Y: 19.99})
raw_p2 = C.rpc("createrawtransaction", [outpoint(coin["p2"])], {Y: 19.99})
raw_unknown = C.rpc("createrawtransaction", [{"txid": unknown, "vout": 0}], {Y: 1})
raw_low = C.rpc("createrawtransaction", [outpoint(coin["low"])], {Y: 0.999999})
raw_high = C.rpc("createrawtransaction", [outpoint(coin["high"])], {Y: 1})
prev_p1 = dict(coin["p1"], redeemScript=ms1["redeemScript"])
prev_p2 = dict(coin["p2"], redeemScript=ms2["redeemScript"])
signed_a = C.rpc("signrawtransaction", raw_a)["hex"]
half_p2 = C.rpc("signrawtransaction", raw_p2, [prev_p2], [wif[A]])["hex"]
signed_p1 = C.rpc("signrawtransaction", raw_p1, [prev_p1], [wif[A]])["hex"]
signed_low = C.rpc("signrawtransaction", raw_low)["hex"]
signed_high = C.rpc("signrawtransaction", raw_high)["hex"]
funding_hex = C.rpc("getrawtransaction", fund_a)

# One spend in both mempools: the signed spend of the P2SH 1-of-2 coin
pending = C.rpc("sendrawtransaction", signed_p1)
if not seen_by(I, pending):
    print("FAIL   setup: irondivid did not get the mempool transaction", flush=True)
    sys.exit(1)
print(f"# chain: {C.rpc('getblockcount')} blocks, mempool {pending[:16]}", flush=True)


# --- the replies -----------------------------------------------------------------------

def replies():
    # createrawtransaction
    for what, args in (
            ("one output", [[outpoint(coin["a"])], {Y: 49.99}]),
            ("two inputs, two outputs in name order", [[outpoint(coin["a"]), outpoint(coin["p1"])], {LO: 1, HI: 2}]),
            ("outputs as an array", [[outpoint(coin["a"])], [{HI: 1}, {LO: 2}]]),
            ("no inputs", [[], {Y: 1}]),
            ("no outputs", [[outpoint(coin["a"])], {}]),
            ("a script as the output key", [[], {"6a0568656c6c6f": 0}]),
            ("an amount with 8 decimals", [[], {Y: 0.12345678}]),
            ("an amount as text", [[], {Y: "1"}]),
            ("a negative amount", [[], {Y: -1}]),
            ("an amount of 21 million and more", [[], {Y: 21000001}]),
            ("a bad address", [[], {"notanaddress": 1}]),
            ("the same address twice in the array form", [[], [{Y: 1}, {Y: 2}]]),
            ("txid not hex", [[{"txid": "xyz", "vout": 0}], {Y: 1}]),
            ("txid too short", [[{"txid": "11", "vout": 0}], {Y: 1}]),
            ("missing vout", [[{"txid": unknown}], {Y: 1}]),
            ("negative vout", [[{"txid": unknown, "vout": -1}], {Y: 1}]),
            ("vout as text", [[{"txid": unknown, "vout": "0"}], {Y: 1}]),
            ("an input that is not an object", [["x"], {Y: 1}]),
            ("inputs not an array", [{"txid": unknown, "vout": 0}, {Y: 1}]),
            ("outputs a number", [[], 5]),
            ("one argument", [[]]),
            ("no arguments", []),
            ("three arguments", [[], {Y: 1}, 0])):
        both(f"createrawtransaction {what}", "createrawtransaction", *args)

    # decoderawtransaction
    for what, hexes in (("unsigned", raw_a), ("signed by the wallet", signed_a), ("two outputs", raw_a_two),
                        ("a P2SH spend", signed_p1), ("half-signed 2-of-2", half_p2),
                        ("a funding transaction", funding_hex), ("a coinbase", C.rpc("getrawtransaction", coinbase)),
                        ("no inputs", C.rpc("createrawtransaction", [], {Y: 1}))):
        both(f"decoderawtransaction {what}", "decoderawtransaction", hexes)
    for what, args in (("not hex", ["xyz"]), ("odd length", ["abc"]), ("not a transaction", ["0011"]),
                       ("empty", [""]), ("a number", [5]), ("no arguments", []), ("two arguments", [raw_a, 1])):
        both(f"decoderawtransaction {what}", "decoderawtransaction", *args)

    # decodescript
    for what, args in (("1-of-2 multisig redeemScript", [ms1["redeemScript"]]),
                       ("2-of-2 multisig redeemScript", [ms2["redeemScript"]]),
                       ("pay to script hash", [coin["p1"]["scriptPubKey"]]),
                       ("pay to key hash", [coin["a"]["scriptPubKey"]]),
                       ("pay to key", ["21" + pub[A] + "ac"]),
                       ("OP_META", ["6a0568656c6c6f"]), ("nonstandard", ["5193"]), ("empty", [""]),
                       ("truncated push", ["4c"]), ("not hex", ["xyz"]), ("a number", [5]), ("no arguments", []),
                       ("two arguments", ["", 1])):
        both(f"decodescript {what}", "decodescript", *args)

    # signrawtransaction
    for what, args in (
            ("with the wallet's keys", [raw_a]),
            ("given prevtxs and a private key", [raw_a, [coin["a"]], [wif[A]]]),
            ("given a private key, no prevtxs", [raw_a, None, [wif[A]]]),
            ("given the key of another address", [raw_a, None, [wif[B]]]),
            ("P2SH 1-of-2, redeemScript and key given", [raw_p1, [prev_p1], [wif[A]]]),
            ("P2SH 1-of-2, redeemScript given, wallet keys", [raw_p1, [prev_p1]]),
            ("P2SH 1-of-2 without the redeemScript", [raw_p1, [coin["p1"]], [wif[A]]]),
            ("P2SH 2-of-2 with one key", [raw_p2, [prev_p2], [wif[A]]]),
            ("P2SH 2-of-2, the second key on the half-signed", [half_p2, [prev_p2], [wif[B]]]),
            ("an unknown input", [raw_unknown]),
            ("a prevtx for an unknown input", [raw_unknown, [{"txid": unknown, "vout": 0,
                                                             "scriptPubKey": coin["a"]["scriptPubKey"]}]]),
            ("a prevtx whose script differs from the coin's", [raw_a, [dict(coin["a"], scriptPubKey=coin["p1"]["scriptPubKey"])]]),
            ("a prevtx without scriptPubKey", [raw_a, [outpoint(coin["a"])]]),
            ("a prevtx with a negative vout", [raw_a, [dict(coin["a"], vout=-1)]]),
            ("a prevtx with a txid not hex", [raw_a, [dict(coin["a"], txid="xyz")]]),
            ("a prevtx that is not an object", [raw_a, ["x"]]),
            ("prevtxs not an array", [raw_a, "x"]),
            ("a bad private key", [raw_a, None, ["notakey"]]),
            ("privkeys not an array", [raw_a, None, "x"]),
            ("sighash ALL", [raw_a_two, None, None, "ALL"]),
            ("sighash NONE", [raw_a_two, None, None, "NONE"]),
            ("sighash SINGLE", [raw_a_two, None, None, "SINGLE"]),
            ("sighash ALL|ANYONECANPAY", [raw_a_two, None, None, "ALL|ANYONECANPAY"]),
            ("sighash NONE|ANYONECANPAY", [raw_a_two, None, None, "NONE|ANYONECANPAY"]),
            ("sighash SINGLE|ANYONECANPAY", [raw_a_two, None, None, "SINGLE|ANYONECANPAY"]),
            ("sighash in lower case", [raw_a_two, None, None, "all"]),
            ("a bad sighash", [raw_a_two, None, None, "SOME"]),
            ("sighash a number", [raw_a_two, None, None, 1]),
            ("not hex", ["xyz"]), ("not a transaction", ["0011"]), ("a number", [5]), ("no arguments", []),
            ("five arguments", [raw_a, None, None, "ALL", 1])):
        both(f"signrawtransaction {what}", "signrawtransaction", *args)

    # sendrawtransaction (refusals; the good form below)
    for what, args in (("already in the chain", [funding_hex]), ("an unknown input", [raw_unknown]),
                       ("a fee below the relay fee", [signed_low]),
                       ("a fee above the maximum", [signed_high]),
                       ("a fee above the maximum, allowhighfees as text", [signed_high, "true"]),
                       ("not hex", ["xyz"]), ("not a transaction", ["0011"]), ("a number", [5]),
                       ("no arguments", []), ("three arguments", [signed_a, False, 1])):
        both(f"sendrawtransaction {what}", "sendrawtransaction", *args)

    # getrawtransaction
    for what, args in (("block 0", [fund_a, 0]), ("block 1", [fund_a, 1]), ("block default", [fund_a]),
                       ("mempool 0", [pending, 0]), ("mempool 1", [pending, 1]), ("coinbase 1", [coinbase, 1]),
                       ("P2SH funding 1", [fund_p1, 1]), ("verbose 2", [fund_a, 2]),
                       ("verbose as text", [fund_a, "1"]), ("unknown transaction", [unknown, 1]),
                       ("not hex", ["xyz", 1]), ("txid too short", ["11", 1]), ("a number", [5]),
                       ("no arguments", []), ("three arguments", [fund_a, 1, 1])):
        both(f"getrawtransaction {what}", "getrawtransaction", *args)

    # createmultisig and addmultisigaddress
    keyless = W
    forms = (("1 of 2 keys", [1, [pub[A], pub[B]]]),
             ("2 of 3 keys", [2, [pub[A], pub[B], pub[N]]]),
             ("an address and a key", [1, [A, pub[B]]]),
             ("an address without a key", [1, [keyless, pub[B]]]),
             ("a pay-to-script-hash address", [1, [ms1["address"], pub[B]]]),
             ("0 required", [0, [pub[A]]]),
             ("more required than keys", [3, [pub[A], pub[B]]]),
             ("17 keys", [1, [pub[A]] * 17]),
             ("a key that is not hex", [1, ["xyz"]]),
             ("a key that is no key", [1, ["02" + "00" * 32]]),
             ("nrequired as text", ["1", [pub[A]]]),
             ("keys not an array", [1, pub[A]]),
             ("one argument", [1]), ("no arguments", []))
    for what, args in forms + (("three arguments", [1, [pub[A]], "x"]),):
        both(f"createmultisig {what}", "createmultisig", *args)
    for what, args in forms + (("with an account", [1, [pub[A], pub[N]], "msig"]),
                               ("four arguments", [1, [pub[A]], "x", 1])):
        both(f"addmultisigaddress {what}", "addmultisigaddress", *args)
    both("getaddressesbyaccount msig", "getaddressesbyaccount", "msig")

    # the good sendrawtransaction last: divid's first, then the same on irondivid
    core = C.call("sendrawtransaction", signed_a)
    seen_by(I, signed_a_txid)
    compare("sendrawtransaction a good spend", core, I.call("sendrawtransaction", signed_a))
    both("getrawtransaction the sent spend 1", "getrawtransaction", signed_a_txid, 1)
    extra_rows("")


signed_a_txid = C.rpc("decoderawtransaction", signed_a)["txid"]
replies()

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
