#!/usr/bin/env python3
"""Blockchain and raw-transaction RPC replies of Divi Core divid and irondivid,
compared field by field.

Both nodes sit on one regtest chain that divid mines: sends, a vault, a
version-2 transaction, an OP_META output carrying value, and a reorganization
that leaves a stale block. Both wallets come from the same phrase, so signing
and wallet fields agree. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
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
INJECT = os.environ.get("CHAIN_REPLIES_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("CHAIN_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true. "open:" rows are gaps not closed yet; "open: rpc-left" rows
# are being closed by fix/rpc-left (RPC-LEFT.md). Rows after the restart take
# the entry of the same row before it.
KNOWN = {
    "getblockchaininfo: fields divid lacks":
        "pruning, block-expiry and snapshot state divid does not have (docs/divid-differences.md R3)",
    "getblock: fields divid lacks":
        "mediantime and nTx, as Bitcoin Core's getblock gives them (divid: blockToJSON, JsonBlockHelpers.cpp:38-77)",
    "getblockheader: fields divid lacks":
        "hash, confirmations, height, mediantime, difficulty, chainwork, nTx, as Bitcoin Core's getblockheader gives them (divid: blockHeaderToJSON, JsonBlockHelpers.cpp:80-91, has 6 fields)",
    "gettxout: fields divid lacks":
        "coinstake (divid: coinbase only, rpcblockchain.cpp:398-399)",
    "gettxoutsetinfo: fields divid lacks":
        "bogosize, the size of irondivid's own UTXO records (divid: rpcblockchain.cpp:319-325)",
    "decoderawtransaction: fields divid lacks":
        "valueSat beside value on each output, as divid's getrawtransaction writes it (rpcrawtransaction.cpp:96-97); divid's decoderawtransaction writes value only (TxToJSON, JsonTxHelpers.cpp:66)",
    "decodescript: fields divid lacks":
        "hex, the script given (divid: rpcrawtransaction.cpp:556-563)",
    "getinfo: fields divid lacks":
        "keypoololdest, keypoolsize, paytxfee (divid: rpcmisc.cpp:136-157)",
    "getblock tip 1":
        "verbosity 0, 1 or 2 as Bitcoin Core takes it (2: transactions decoded); divid reads a bool (rpcblockchain.cpp:216)",
    "createrawtransaction two outputs":
        "open: the outputs come out sorted by address, not in the order given: the RPC layer parses requests into serde_json maps, which keep names sorted (Cargo.toml, no preserve_order; docs/divid-differences.md R6); divid keeps the order (rpcrawtransaction.cpp:400-410). The array form of the outputs keeps the order on irondivid",
    "sendrawtransaction unsigned":
        "open: divid runs with acceptnonstandard=1 here, which skips its input standardness check, so the script check answers -26 \"16: mandatory-script-verify-flag-failed (...)\" (MempoolConsensus.cpp:274, :362-364); irondivid has no -acceptnonstandard and answers -25 \"\" as divid does without it (scripts/reject-replies, row unsigned)",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "getblockchaininfo": {"fullhistorypeers", "lastblockfetch", "mediantime", "pruned", "pruneheight",
                          "snapshotbase", "warnings", "winnersstripheight"},
    "getblock": {"mediantime", "nTx"},
    "getblockheader": {"chainwork", "confirmations", "difficulty", "hash", "height", "mediantime", "nTx"},
    "gettxout": {"coinstake"},
    "gettxoutsetinfo": {"bogosize"},
    "decoderawtransaction": {"valueSat"},
    "decodescript": {"hex"},
    "getinfo": {"keypoololdest", "keypoolsize", "paytxfee"},
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


def patched(raw, version=None, meta_value=None):
    """An unsigned transaction with one input and no scriptSig, with another
    version and/or one more output: `meta_value` satoshis to an OP_META script"""
    b = bytearray.fromhex(raw)
    assert b[4] == 1 and b[4 + 1 + 36] == 0
    if version is not None:
        b[0:4] = version.to_bytes(4, "little")
    if meta_value is not None:
        pos = 4 + 1 + 36 + 1 + 4
        end = len(b) - 4
        meta = meta_value.to_bytes(8, "little") + bytes([6, 0x6A, 4]) + b"burn"
        b = b[:pos] + bytes([b[pos] + 1]) + b[pos + 1:end] + meta + b[end:]
    return bytes(b).hex()


def vout_to(txid, addr):
    tx = C.rpc("getrawtransaction", txid, 1)
    return next(o["n"] for o in tx["vout"] if addr in o["scriptPubKey"].get("addresses", []))


# --- the nodes and the chain -----------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1", "acceptnonstandard=1"])
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

C.rpc("setgenerate", 40)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

X = C.rpc("getnewaddress")
Y = C.rpc("getnewaddress")
# An address nobody holds a key for (regtest P2PKH version 139, random bytes)
W = b58check(bytes([139]) + secrets.token_bytes(20))

# One block with: a send, a vault funding, and the funding of the version-2
# transaction and of the OP_META output, one paying the keyless address too
send1 = C.rpc("sendtoaddress", X, 10)
vault = C.rpc("fundvault", f"{C.rpc('getnewaddress')}:{C.rpc('getnewaddress')}", 250)["txhash"]
# The coin to the keyless address stays unspent, so `fund` always keeps an
# unspent output after the version-2 transaction spends its other one
fund = C.rpc("sendmany", "", {Y: 100, W: 5})
fund2 = C.rpc("sendtoaddress", Y, 100)
to_w = fund
C.rpc("setgenerate", 1)
raw = C.rpc("createrawtransaction", [{"txid": fund, "vout": vout_to(fund, Y)}], {X: 99.99})
v2 = C.rpc("sendrawtransaction", C.rpc("signrawtransaction", patched(raw, version=2))["hex"])
raw = C.rpc("createrawtransaction", [{"txid": fund2, "vout": vout_to(fund2, Y)}], {X: 98.99})
meta = C.rpc("sendrawtransaction", C.rpc("signrawtransaction", patched(raw, meta_value=100_000_000))["hex"])
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid did not follow the block with the sends", flush=True)
    sys.exit(1)
sends_block = C.rpc("getblockhash", C.rpc("getblockcount") - 1)
# send1's coin is the input of the raw transactions below: no later send of
# divid's wallet may take it
C.rpc("lockunspent", False, [{"txid": send1, "vout": vout_to(send1, X)}])

# A reorganization: a block with a send is replaced by two blocks; it stays
# known as a stale branch on both
send2 = C.rpc("sendtoaddress", X, 7)
seen_by(I, send2)
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid did not follow the block before the reorganization", flush=True)
    sys.exit(1)
stale = C.rpc("getbestblockhash")
C.rpc("invalidateblock", stale)
C.rpc("setgenerate", 2)
C.rpc("reconsiderblock", stale)
if not synced():
    print("FAIL   setup: irondivid did not follow the reorganization", flush=True)
    sys.exit(1)
if C.rpc("getrawtransaction", send2, 1).get("confirmations", 0) < 1:
    print("FAIL   setup: the send of the stale block was not mined again", flush=True)
    sys.exit(1)

# One send left in both mempools
pending = C.rpc("sendtoaddress", X, 3)
if not seen_by(I, pending):
    print("FAIL   setup: irondivid did not get the mempool transaction", flush=True)
    sys.exit(1)
pending_hex = C.rpc("getrawtransaction", pending)

tip_height = C.rpc("getblockcount")
tip = C.rpc("getbestblockhash")
genesis = C.rpc("getblockhash", 0)
coinbase = C.rpc("getblock", C.rpc("getblockhash", 5))["tx"][0]
spent_coin = (fund, vout_to(fund, Y))
send1_vout = vout_to(send1, X)
meta_vout = next(o["n"] for o in C.rpc("getrawtransaction", meta, 1)["vout"]
                 if o["scriptPubKey"]["hex"].startswith("6a"))
unknown = "11" * 32
print(f"# chain: {tip_height} blocks, stale block {stale[:16]}, mempool {pending[:16]}", flush=True)

# Raw transactions made on divid, used as arguments on both
created = C.rpc("createrawtransaction", [{"txid": send1, "vout": send1_vout}], {Y: 9.99})
created_two = C.rpc("createrawtransaction", [{"txid": send1, "vout": send1_vout}, {"txid": unknown, "vout": 0}],
                    {Y: 9.99})
created_w = C.rpc("createrawtransaction", [{"txid": to_w, "vout": vout_to(to_w, W)}], {Y: 4.99})
signed = C.rpc("signrawtransaction", created)["hex"]
# A signed spend of a coin already spent in the chain
fund_spk = C.rpc("getrawtransaction", fund, 1)["vout"][spent_coin[1]]["scriptPubKey"]["hex"]
respend = C.rpc("signrawtransaction",
                C.rpc("createrawtransaction", [{"txid": fund, "vout": spent_coin[1]}], {X: 99.9}),
                [{"txid": fund, "vout": spent_coin[1], "scriptPubKey": fund_spk}])["hex"]
# A signed spend of the coin the mempool transaction spends
pending_in = C.rpc("decoderawtransaction", pending_hex)["vin"][0]
in_tx = C.rpc("getrawtransaction", pending_in["txid"], 1)
in_out = in_tx["vout"][pending_in["vout"]]
conflict = C.rpc("signrawtransaction",
                 C.rpc("createrawtransaction", [{"txid": pending_in["txid"], "vout": pending_in["vout"]}],
                       {Y: float(in_out["value"]) - 0.01}))["hex"]
confirmed_hex = C.rpc("getrawtransaction", send1)
p2pkh_script = C.rpc("validateaddress", X)["scriptPubKey"] if "scriptPubKey" in C.rpc("validateaddress", X) \
    else C.rpc("getrawtransaction", send1, 1)["vout"][send1_vout]["scriptPubKey"]["hex"]
pub1 = C.rpc("validateaddress", X)["pubkey"]
pub2 = C.rpc("validateaddress", Y)["pubkey"]
multisig_script = "52" + "21" + pub1 + "21" + pub2 + "52ae"
LO, HI = sorted((X, Y))


# --- the replies -----------------------------------------------------------------------

def replies(when):
    p = f"{when}: " if when else ""
    both(f"{p}getblockchaininfo", "getblockchaininfo")
    both(f"{p}getblockcount", "getblockcount")
    both(f"{p}getbestblockhash", "getbestblockhash")
    both(f"{p}getdifficulty", "getdifficulty")
    both(f"{p}getchaintips", "getchaintips", order=lambda t: t.get("hash", ""))
    for args in ([0], [tip_height], [tip_height + 1], [-1], ["1"], [1.5], []):
        both(f"{p}getblockhash {json.dumps(args)}", "getblockhash", *args)
    for what, args in (("tip", [tip]), ("tip true", [tip, True]), ("tip false", [tip, False]),
                       ("genesis", [genesis]), ("block with the sends", [sends_block]),
                       ("stale block", [stale]), ("tip 1", [tip, 1]), ("unknown hash", [unknown]),
                       ("not a hash", ["xyz"]), ("no arguments", [])):
        both(f"{p}getblock {what}", "getblock", *args)
    for what, args in (("tip", [tip]), ("tip false", [tip, False]), ("stale block", [stale]),
                       ("unknown hash", [unknown]), ("no arguments", [])):
        both(f"{p}getblockheader {what}", "getblockheader", *args)
    for what, txid, n in (("unspent send", send1, send1_vout), ("spent", *spent_coin),
                          ("coinbase", coinbase, 0), ("version 2", v2, 0), ("OP_META output", meta, meta_vout),
                          ("vault", vault, 0), ("mempool", pending, 0), ("mempool", pending, 1),
                          ("past the last output", send1, 9), ("unknown transaction", unknown, 0)):
        for mempool in (True, False):
            both(f"{p}gettxout {what} {n} includemempool={json.dumps(mempool)}", "gettxout", txid, n, mempool)
    both(f"{p}gettxout send default", "gettxout", send1, send1_vout)
    both(f"{p}gettxout not a hash", "gettxout", "xyz", 0)
    both(f"{p}gettxout vout as text", "gettxout", send1, "0")
    both(f"{p}gettxout no arguments", "gettxout")
    both(f"{p}gettxoutsetinfo", "gettxoutsetinfo")
    for args in ([], [3, 10], [4, 0]):
        both(f"{p}verifychain {json.dumps(args)}", "verifychain", *args)
    for what, args in (("send 0", [send1, 0]), ("send 1", [send1, 1]), ("send default", [send1]),
                       ("version 2", [v2, 1]), ("OP_META", [meta, 1]), ("coinbase", [coinbase, 1]),
                       ("vault", [vault, 1]), ("mempool", [pending, 1]), ("send verbose true", [send1, True]),
                       ("unknown transaction", [unknown, 1]), ("not a hash", ["xyz", 1]), ("no arguments", [])):
        both(f"{p}getrawtransaction {what}", "getrawtransaction", *args)
    for what, args in (
            ("one output", [[{"txid": send1, "vout": send1_vout}], {Y: 9.99}]),
            # the outputs not in name order, so keeping the order given shows
            ("two outputs", [[{"txid": send1, "vout": send1_vout}], {HI: 1, LO: 8.5}]),
            ("two outputs as an array", [[{"txid": send1, "vout": send1_vout}], [{HI: 1}, {LO: 8.5}]]),
            ("no inputs", [[], {Y: 1}]),
            ("bad address", [[{"txid": send1, "vout": 0}], {"notanaddress": 1}]),
            ("txid not hex", [[{"txid": "xyz", "vout": 0}], {Y: 1}]),
            ("missing vout", [[{"txid": send1}], {Y: 1}]),
            ("negative vout", [[{"txid": send1, "vout": -1}], {Y: 1}]),
            ("negative amount", [[{"txid": send1, "vout": 0}], {Y: -1}]),
            ("inputs not an array", [{"txid": send1, "vout": 0}, {Y: 1}]),
            ("no arguments", [])):
        both(f"{p}createrawtransaction {what}", "createrawtransaction", *args)
    for what, args in (("created", [created]), ("signed", [signed]), ("version 2", [C.rpc("getrawtransaction", v2)]),
                       ("OP_META", [C.rpc("getrawtransaction", meta)]),
                       ("coinbase", [C.rpc("getrawtransaction", coinbase)]),
                       ("not hex", ["xyz"]), ("not a transaction", ["0011"]), ("no arguments", [])):
        both(f"{p}decoderawtransaction {what}", "decoderawtransaction", *args)
    for what, args in (("pay to key hash", [p2pkh_script]), ("2-of-2 multisig", [multisig_script]),
                       ("OP_META", ["6a046275726e"]), ("empty", [""]), ("not hex", ["xyz"]), ("no arguments", [])):
        both(f"{p}decodescript {what}", "decodescript", *args)
    for what, args in (("complete", [created]), ("one input unknown", [created_two]),
                       ("keyless address", [created_w]), ("sighash ALL", [created, [], None, "ALL"]),
                       ("bad sighash", [created, [], None, "SOME"]), ("not hex", ["xyz"]), ("no arguments", [])):
        both(f"{p}signrawtransaction {what}", "signrawtransaction", *args)
    for what, args in (("already in the chain", [confirmed_hex]), ("unsigned", [created]),
                       ("spent input", [respend]), ("mempool conflict", [conflict]),
                       ("already in the mempool", [pending_hex]), ("not hex", ["xyz"]),
                       ("not a transaction", ["0011"]), ("no arguments", [])):
        both(f"{p}sendrawtransaction {what}", "sendrawtransaction", *args)
    both(f"{p}getinfo", "getinfo")
    # One argument more than divid takes (its fHelp checks): divid answers -1 with the
    # help text; irondivid must refuse with -1 too
    for method, args in (
            ("getblockchaininfo", [1]), ("getblockcount", [1]), ("getbestblockhash", [1]),
            ("getdifficulty", [1]), ("getchaintips", [1]), ("gettxoutsetinfo", [1]), ("getinfo", [1]),
            ("getblockhash", [0, 1]), ("getblock", [tip, True, 1]), ("getblockheader", [tip, True, 1]),
            ("gettxout", [send1, send1_vout, True, 1]), ("verifychain", [3, 10, 1]),
            ("getrawtransaction", [send1, 1, 1]),
            ("createrawtransaction", [[{"txid": send1, "vout": send1_vout}], {Y: 1}, 0]),
            ("decoderawtransaction", [created, 1]), ("decodescript", ["", 1]),
            ("signrawtransaction", [created, [], None, "ALL", 1]), ("sendrawtransaction", [created, False, 1])):
        both(f"{p}{method} one argument too many", method, *args)
    extra_rows(when)


replies("")

# Restart both: the replies must come back the same from disk
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not synced():
    print("FAIL   restart: irondivid did not reconnect to divid", flush=True)
    sys.exit(1)
# The mempool transaction back in both mempools
for n in (C, I):
    if pending not in n.rpc("getrawmempool"):
        n.call("sendrawtransaction", pending_hex)
if not (seen_by(C, pending) and seen_by(I, pending)):
    print("FAIL   restart: the mempool transaction is not back in both mempools", flush=True)
    sys.exit(1)
replies("after restart")

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
