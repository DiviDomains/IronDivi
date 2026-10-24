#!/usr/bin/env python3
"""One set of addresses followed through the address and spent indexes of
Divi Core divid and irondivid, side by side on one regtest chain.

divid mines; irondivid follows it (connect=), so both indexes are built from the
same blocks. The addresses receive, send, get a multisig, coinbase, coinstake
and vault output, and keep one spend in the mempool; then the chain is taken
back with invalidateblock and given back with reconsiderblock, both nodes are
restarted, reindexed, started without the indexes and with them again. At each
step the same index calls go to both. Each row prints PASS (same as divid),
KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random and kept in each node's 0600 divi.conf.
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
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("ADDRESS_INDEX_INJECT", "")
HOST = os.environ.get("ADDRESS_INDEX_HOST", "127.0.0.2")
# A directory to write both replies of every differing row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("ADDRESS_INDEX_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 240

# Differences irondivid has on purpose, one per row name, each with the shape
# it must have: (reason, shape(divid's reply, irondivid's reply)). A KNOWN row
# that matches divid, or differs in another way, is a FAIL, so the list stays true.
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is None or shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


class Node:
    def __init__(self, name, binary, index, extra):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"ai{index}"
        self.password = secrets.token_hex(16)
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", "txindex=1",
        ] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = None
        self.runs = 0

    def start(self, *args):
        """The index settings go on the command line, so each start names its own"""
        self.runs += 1
        self.log = open(os.path.join(WORK, f"{self.name}.{self.runs}.out"), "w")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=WORK, stdout=self.log,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

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

    def call(self, method, *params):
        """('ok', result) or ('err', code, message); reals keep their text"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
        return out[1]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- how replies are compared ---------------------------------------------------------

def first_difference(a, b, path="$"):
    """Where two replies first differ, or None: field names and their order,
    JSON types and values, list items in order. Reals are compared as written."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        if list(a) != list(b):
            return f"{path} field order {','.join(a)} vs {','.join(b)}"
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if a != b or type(a) is not type(b):
        return f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"
    return None


def help_first_line(out):
    """divid's help text (a -1 error of several lines): its first line"""
    if out[0] == "err" and out[1] == -1 and "\n" in out[2].strip():
        return ("err", out[1], out[2].strip().split("\n")[0])
    return out


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\"".replace("\n", "\\n")
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:70]


def inject(v):
    if isinstance(v, list):
        return v + ["injected"]
    if isinstance(v, dict):
        return dict(v, injected=True)
    return "injected"


def by_height(v):
    """getaddressutxos in a fixed order: divid sorts by height alone with
    std::sort (rpcmisc.cpp:873-876, :980), which is not stable, so the order of
    one height's entries is whatever the sort leaves"""
    key = lambda u: (u.get("height", 0), u.get("txid", ""), u.get("outputIndex", 0))
    if isinstance(v, list):
        return sorted(v, key=key)
    if isinstance(v, dict) and isinstance(v.get("utxos"), list):
        return dict(v, utxos=sorted(v["utxos"], key=key))
    return v


def compare(name, core, iron, order=None):
    """Same outcome; an error: the same code and message (divid's help texts by
    their first line); a result: the same fields in the same order, types and
    values, list items in divid's order (or both put in `order`)"""
    core, iron = help_first_line(core), help_first_line(iron)
    if INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        row(name, short(core), short(iron), core == iron, (core, iron))
        return
    a, b = core[1], iron[1]
    if order:
        a, b = order(a), order(b)
    d = first_difference(a, b)
    if DUMP and d:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:100]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1)
    row(name, short(core), d or short(iron), d is None, (a, b))


def both(name, method, *params, order=None):
    compare(name, C.call(method, *params), I.call(method, *params), order)


def wait_for(fn, secs):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

ON = ("-addressindex=1", "-spentindex=1")
OFF = ("-addressindex=0", "-spentindex=0")
C = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect={HOST}:{PORT_BASE}"])


def start_both(*args):
    for n in (C, I):
        n.start(*args)
    for n in (C, I):
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not answer within {START_TIMEOUT} s (started with {' '.join(args)})")
    if not synced():
        raise RuntimeError(f"irondivid did not follow divid after a start with {' '.join(args)}")


def stop_both():
    for n in (I, C):
        n.stop()


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120)


def mine(n):
    """n blocks on divid, one call at a time: a proof-of-stake block can be refused
    until the clock passes the median time of the last blocks"""
    for _ in range(n):
        if not wait_for(lambda: C.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"divid could not mine block {C.rpc('getblockcount') + 1}")
    if not synced():
        raise RuntimeError("irondivid did not follow divid's chain")


def in_both_pools(txids):
    return wait_for(lambda: all(t in I.rpc("getrawmempool") for t in txids), 60)


def out_to(txid, address):
    for o in C.rpc("getrawtransaction", txid, 1)["vout"]:
        if o["scriptPubKey"].get("addresses") == [address]:
            return o["n"], o["value"]
    raise RuntimeError(f"no output to {address} in {txid}")


def spend(txid, n, value, to):
    """A raw transaction of divid's wallet spending one output to `to`"""
    raw = C.rpc("createrawtransaction", [{"txid": txid, "vout": n}], {to: round(float(value) - 0.01, 8)})
    return C.rpc("sendrawtransaction", C.rpc("signrawtransaction", raw)["hex"])


start_both(*ON)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
mine(40)

# --- the addresses ------------------------------------------------------------------------

A, B, A2, OWN, MGR = (C.rpc("getnewaddress") for _ in range(5))
MS = C.rpc("addmultisigaddress", 1, [C.rpc("validateaddress", A)["pubkey"], C.rpc("validateaddress", B)["pubkey"]])
# An address nobody pays (regtest P2PKH version 139, random bytes)
NONE = b58check(bytes([139]) + secrets.token_bytes(20))
# The coinbase of block 5 pays an address of divid's own
K = C.rpc("getblock", C.rpc("getblockhash", 5), True)["tx"][0]
K = next(o["scriptPubKey"]["addresses"][0] for o in C.rpc("getrawtransaction", K, 1)["vout"]
         if o["scriptPubKey"].get("addresses"))

# Block H1: receives (A twice, B, the multisig) and a vault fund
paid = [C.rpc("sendtoaddress", A, 10), C.rpc("sendtoaddress", B, 5), C.rpc("sendtoaddress", A, 3),
        C.rpc("sendtoaddress", MS, 7)]
pool_before = set(C.rpc("getrawmempool"))
C.rpc("fundvault", f"{OWN}:{MGR}", 20)
VAULT_TX = (set(C.rpc("getrawmempool")) - pool_before).pop()
in_both_pools(paid + [VAULT_TX])
mine(1)
H1 = C.rpc("getblockcount")

# Block H2: a send from A, and a coin made and spent in the block (X pays A2, Y
# spends that output before either is mined)
a_n, a_value = out_to(paid[0], A)
SEND = spend(paid[0], a_n, a_value, B)
X = C.rpc("sendtoaddress", A2, 4)
x_n, x_value = out_to(X, A2)
Y = spend(X, x_n, x_value, B)
in_both_pools([SEND, X, Y])
mine(1)
H2 = C.rpc("getblockcount")
HASH1, HASH2 = C.rpc("getblockhash", H1), C.rpc("getblockhash", H2)

# Past the last proof-of-work block (100): coinstakes from 101
mine(104 - H2)
TIP = C.rpc("getblockcount")
stake_tx = C.rpc("getblock", C.rpc("getblockhash", 103), True)["tx"][1]
S = next(o["scriptPubKey"]["addresses"][0] for o in C.rpc("getrawtransaction", stake_tx, 1)["vout"]
         if o["scriptPubKey"].get("addresses"))

# The mempool: B's 5 coin spent to A, and one more payment to A
b_n, b_value = out_to(paid[1], B)
POOL_SPEND = spend(paid[1], b_n, b_value, A)
POOL_PAY = C.rpc("sendtoaddress", A, 1)
if not in_both_pools([POOL_SPEND, POOL_PAY]):
    raise RuntimeError("irondivid did not see the mempool transactions")
print(f"# chain {TIP} blocks; receives and a vault fund in {H1}, sends in {H2}, coinstakes from 101; "
      f"one spend and one payment in the mempool", flush=True)

# Every spent outpoint of blocks H1..TIP, by where it is spent (stable names)
SPENT = []
for h in range(H1, TIP + 1):
    for k, txid in enumerate(C.rpc("getblock", C.rpc("getblockhash", h), True)["tx"]):
        tx = C.rpc("getrawtransaction", txid, 1)
        for j, vin in enumerate(tx["vin"]):
            if "txid" in vin:
                SPENT.append((f"block {h} tx {k} input {j}", vin["txid"], vin["vout"]))

# --- the views ----------------------------------------------------------------------------------

CALLS = ("getaddresstxids", "getaddressdeltas", "getaddressbalance", "getaddressutxos")


def forms():
    """(label, params) of each call: the addresses, the object form, ranges"""
    out = [
        ("A", (A,)), ("{A}", ({"addresses": [A]},)), ("[A, B]", ({"addresses": [A, B]},)),
        ("[B, A]", ({"addresses": [B, A]},)), ("[A, B, A] (a duplicate)", ({"addresses": [A, B, A]},)),
        ("A2 (coin made and spent in one block)", (A2,)), ("multisig", (MS,)), ("[A, multisig]", ({"addresses": [A, MS]},)),
        ("coinbase address", (K,)), ("coinstake address", (S,)),
        ("vault owner", (OWN,)), ("vault owner, only_vaults", (OWN, True)), ("vault manager, only_vaults", (MGR, True)),
        ("[A, owner], only_vaults", ({"addresses": [A, OWN]}, True)), ("A, only_vaults false", (A, False)),
        ("multisig, only_vaults", (MS, True)), ("unknown address", (NONE,)), ("bad address", ("notanaddress",)),
        ("[A, bad]", ({"addresses": [A, "notanaddress"]},)),
    ]
    q = lambda **kw: ({"addresses": [A, B], **kw},)
    out += [
        ("[A, B] start..end inside", q(start=H1, end=H2)),
        ("[A, B] start..end outside", q(start=TIP + 5, end=TIP + 10)),
        ("[A, B] start..end reversed", q(start=H2, end=H1)),
        ("[A, B] start = end", q(start=H2, end=H2)),
        ("[A, B] start as text", q(start=str(H1), end=H2)),
        ("[A, B] start negative", q(start=-1, end=H2)),
        ("[A, B] start 0", q(start=0, end=H2)),
        ("[A, B] start beyond int", q(start=2 ** 32 + H1, end=H2)),
        ("[A, B] start beyond int, negative as int", q(start=2 ** 31 + H1, end=H2)),
        ("[A, B] end beyond int", q(start=H1, end=2 ** 32 + H2)),
        ("[A, B] start alone", q(start=H1)),
        ("{A} start..end", ({"addresses": [A], "start": H1, "end": H1},)),
        ("[A, B] chainInfo", q(chainInfo=True)),
        ("[A, B] chainInfo false", q(chainInfo=False)),
        ("[A, B] chainInfo as text", q(chainInfo="true")),
        ("[A, B] start..end chainInfo", q(start=H1, end=H2, chainInfo=True)),
        ("[A, B] start..end past the tip chainInfo", q(start=H1, end=TIP + 5, chainInfo=True)),
        ("[A, B] start = end = tip chainInfo", q(start=TIP, end=TIP, chainInfo=True)),
    ]
    return out


def spentinfo(p):
    for label, txid, n in SPENT:
        both(f"{p}getspentinfo spent at {label}", "getspentinfo", {"txid": txid, "index": n})
    both(f"{p}getspentinfo spent in the mempool", "getspentinfo", {"txid": paid[1], "index": b_n})
    both(f"{p}getspentinfo unspent (the send's output to B)", "getspentinfo",
         {"txid": SEND, "index": 0})
    both(f"{p}getspentinfo unspent multisig output", "getspentinfo", {"txid": paid[3], "index": out_to(paid[3], MS)[0]})
    both(f"{p}getspentinfo unknown txid", "getspentinfo", {"txid": "11" * 32, "index": 0})
    both(f"{p}getspentinfo index past the outputs", "getspentinfo", {"txid": paid[0], "index": 99})
    both(f"{p}getspentinfo negative index", "getspentinfo", {"txid": paid[0], "index": -1})
    both(f"{p}getspentinfo index as text", "getspentinfo", {"txid": paid[0], "index": "0"})
    both(f"{p}getspentinfo index beyond int", "getspentinfo", {"txid": paid[0], "index": 2 ** 32 + a_n})


def view(when):
    p = f"{when}: "
    for m in CALLS:
        for label, params in forms():
            both(f"{p}{m} {label}", m, *params, order=by_height if m == "getaddressutxos" else None)
    spentinfo(p)
    both(f"{p}getblockcount", "getblockcount")


def pool_view(when):
    """Which of the run's transactions each mempool holds"""
    ours = {"receives": paid, "vault fund": [VAULT_TX], "send": [SEND], "X": [X], "Y": [Y],
            "mempool spend": [POOL_SPEND], "mempool payment": [POOL_PAY]}
    pools = (set(C.rpc("getrawmempool")), set(I.rpc("getrawmempool")))
    for label, txids in ours.items():
        held = [",".join("in" if t in pool else "out" for t in txids) for pool in pools]
        row(f"{when}: mempool holds {label}", held[0], held[1], held[0] == held[1])


view("indexed")
pool_view("indexed")

# --- invalidateblock and reconsiderblock -------------------------------------------------------


def on_both(method, label, block_hash):
    c, i = C.call(method, block_hash), I.call(method, block_hash)
    compare(f"{method} {label}", c, i)
    if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120):
        raise RuntimeError(f"divid and irondivid have other tips after {method}")


def settle(*txids):
    """Wait until both mempools hold the transactions a disconnect gives back"""
    wait_for(lambda: all(t in C.rpc("getrawmempool") and t in I.rpc("getrawmempool") for t in txids), 30)


on_both("invalidateblock", f"of {H2}", HASH2)
settle(SEND, X, Y)
view(f"after invalidateblock {H2}")
pool_view(f"after invalidateblock {H2}")
on_both("invalidateblock", f"of {H1}", HASH1)
settle(*paid, VAULT_TX)
view(f"after invalidateblock {H1}")
pool_view(f"after invalidateblock {H1}")
on_both("reconsiderblock", f"of {H1}", HASH1)
view("after reconsiderblock")
pool_view("after reconsiderblock")

# --- restarts -------------------------------------------------------------------------------------

stop_both()
start_both(*ON)
view("after a restart")
stop_both()
start_both("-reindex", *ON)
view("after -reindex")
# Started without the indexes, a node that has them goes on with them: divid
# follows the flags its block tree was made with (txdb.cpp:498-511)
stop_both()
start_both(*OFF)
view("started without the indexes")
stop_both()
start_both("-reindex", *OFF)
view("after -reindex without the indexes")
stop_both()
start_both(*ON)
view("started with the indexes, not reindexed")
stop_both()
start_both("-reindex", *ON)
view("after -reindex with the indexes")

stop_both()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
