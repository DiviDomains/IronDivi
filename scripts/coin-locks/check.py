#!/usr/bin/env python3
"""Coin locks, block reversal and wallet switching on Divi Core divid and
irondivid, compared reply by reply.

Both wallets come from the same phrase and sit on one regtest chain, so they own
the same coins under the same outpoints. lockunspent and listlockunspent are
compared for every kind of coin and every malformed list; listunspent,
getbalance, getcoinavailability, sendtoaddress, sendmany and fundvault with coins
locked; the locks across walletlock/walletpassphrase, invalidateblock/
reconsiderblock and a restart; reverseblocktransactions on several blocks; and
loadwallet with several files. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
and the wallet passphrase live only in memory, in RPC requests and replies and in
irondivid's environment; they are never printed or put on a command line.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("COIN_LOCKS_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120
# A port in the run's range nothing listens on: irondivid "connects" there once
# the two nodes must no longer share their transactions
DEAD_PORT = PORT_BASE + 4

# Differences irondivid has on purpose, one per row name, each listed in
# README.md with divid's source line. A KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
ORDER = ("irondivid writes the members of every reply object in name order (serde_json without "
         "preserve_order, all replies); the other rows compare members as sets, as the other reply scripts do")
STAKING_BALANCE = ("divid's lockedCoinBalance takes off the credit of the whole transaction once for each locked "
                   "output of it (wallet.cpp:2236-2252), so staking_balance falls below the coins left, even below "
                   "0, and HasAgedCoins (wallet.cpp:1468) and enoughcoins (rpcmisc.cpp:1066) follow it; irondivid "
                   "takes off each locked coin's own value")
LOADWALLET = ("irondivid keeps the wallet it started with (it is wired into the block, mempool and reorg "
              "callbacks and the staker at start) and refuses another; divid switches (init.cpp:260-279), "
              "creating a new empty wallet for a name with no file and opening a file outside its datadir")
KNOWN = {
    "member order: listunspent item": ORDER,
    "member order: gettxoutsetinfo": ORDER,
    "member order: getcoinavailability": ORDER,
    "one wallet coin locked: getstakingstatus": STAKING_BALANCE,
    "every coin locked: getstakingstatus": STAKING_BALANCE,
    "one coin free: getstakingstatus": STAKING_BALANCE,
    "loadwallet copy.dat (a backupwallet copy)": LOADWALLET,
    "after loadwallet copy.dat: getwalletinfo": LOADWALLET,
    "loadwallet missing.dat (no such file)": LOADWALLET,
    "after loadwallet missing.dat: getwalletinfo": LOADWALLET,
    "after loadwallet missing.dat: getbalance": LOADWALLET,
    "loadwallet a file outside the datadir": LOADWALLET,
    "after loadwallet outside the datadir: getwalletinfo": LOADWALLET,
    "after loadwallet outside the datadir: getbalance": LOADWALLET,
}

# Fields irondivid adds to a reply on purpose: compared without them
EXTRA = {
    "listunspent": {"ischange", "solvable"},
    "getcoinavailability": {"total_vaults", "vaults"},
    "gettxoutsetinfo": {"bogosize"},
}
# Fields that depend on the node's own files or on the moment, not on the chain
DROP = {"bytes_serialized", "hash_serialized", "time", "timereceived"}

fails = 0


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"locks{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=locks{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ]
        self.write_conf(extra_conf)
        self.log = None
        self.proc = None
        self.start()

    def write_conf(self, extra_conf):
        path = os.path.join(self.dir, "divi.conf")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra_conf)) + "\n")
        os.replace(tmp, path)

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def call(self, method, *params):
        """('ok', result), ('err', code, message), or ('down',) when the node
        does not answer"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "HTTP")
        except (OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1:]}"[:200])
        return out[1]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            if self.call("getblockcount")[0] == "ok":
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        if self.proc is None:
            return
        self.call("stop")
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None
        self.log.close()

    def restart(self, extra_conf):
        self.stop()
        self.write_conf(extra_conf)
        self.start()
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not come back after a restart")


# --- how replies are compared ------------------------------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Members are compared as sets, as
    in the other reply scripts; their order has rows of its own (order_row)"""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(a) + [k for k in b if k not in a]:
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
    if type(a) is not type(b) or a != b:
        return f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"
    return None


def short(out):
    if out[0] == "down":
        return "no answer (the node has stopped)"
    if out[0] == "err":
        text = out[2].replace("\n", "\\n")
        return f"error {out[1]} \"{text[:100]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items {json.dumps(v)[:120]}"
    if isinstance(v, dict):
        return json.dumps(v)[:160]
    return json.dumps(v)[:100]


# divid's help examples name sample addresses and hashes; irondivid's texts
# write them "diviaddress" and "hash" (no address or hash of anyone's wallet is
# written in the tree). Error texts are compared with that done, as in
# help-replies.
SAMPLE_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{40,}(?![0-9A-Za-z])")
SAMPLE_B58 = re.compile(r"(?<![0-9A-Za-z])(?=[1-9A-HJ-NP-Za-km-z]*\d)(?=[1-9A-HJ-NP-Za-km-z]*[A-Za-z])"
                        r"[1-9A-HJ-NP-Za-km-z]{26,35}(?![0-9A-Za-z])")


def samples(out):
    if out[0] != "err" or "\n" not in out[2]:
        return out
    return ("err", out[1], SAMPLE_B58.sub("diviaddress", SAMPLE_HEX.sub("hash", out[2])))


def compare(name, core, iron, order=None, view=None):
    """Same outcome; for a result the same value (keys in divid's order). `order`
    sorts list items first; `view` maps each result before the comparison"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", "injected")
    if core[0] != "ok" or iron[0] != "ok":
        core, iron = samples(core), samples(iron)
        detail = short(iron)
        if core[0] == iron[0] == "err" and core[1] == iron[1] and core[2] != iron[2]:
            n = next((i for i, (x, y) in enumerate(zip(core[2], iron[2])) if x != y), min(len(core[2]), len(iron[2])))
            esc = lambda t: t[max(0, n - 20):n + 40].replace("\n", "\\n")
            detail = f"message differs at character {n}: divid \"...{esc(core[2])}\" irondivid \"...{esc(iron[2])}\""
        row(name, short(core), detail, core == iron)
        return
    a, b = core[1], iron[1]
    if view:
        a, b = view(a), view(b)
    a, b = strip(a, DROP), strip(b, DROP)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    row(name, short(("ok", a)), d or short(("ok", b)), d is None)


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok":
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)
    return core, iron


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
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    print(f"FAILS {fails + 1}", flush=True)
    sys.exit(min(fails + 1, 254))


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 90)


def seen_by(node, txid):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), 90)


def outpoint(txid, vout):
    return {"txid": txid, "vout": vout}


# --- the nodes and the coins -----------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    raise RuntimeError(f"divid did not answer within {START_TIMEOUT} s")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I_LINK = ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"]
I_ALONE = ["listen=0", f"connect=127.0.0.1:{DEAD_PORT}"]
I = Node("irondivid", IRONDIVID, 1, I_LINK, env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    raise RuntimeError(f"irondivid did not answer within {START_TIMEOUT} s")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

C.rpc("setgenerate", 40)
if not synced():
    raise RuntimeError("irondivid did not follow divid's chain")

# Three wallet coins of their own amounts and one coin of nobody's wallet, in one
# transaction made on divid; irondivid sees it, so both own the same outpoints
A = [C.rpc("getnewaddress") for _ in range(3)]
for a in A:
    I.rpc("setaccount", a, "")
FOREIGN = b58check(bytes([139]) + secrets.token_bytes(20))
T = C.rpc("sendmany", "", {A[0]: 7, A[1]: 11, A[2]: 13, FOREIGN: 5})
if not seen_by(I, T):
    raise RuntimeError("irondivid did not see divid's sendmany")
C.rpc("setgenerate", 1)
if not synced():
    raise RuntimeError("irondivid did not follow the block with the sendmany")
B1 = C.rpc("getbestblockhash")
raw = C.rpc("getrawtransaction", T, 1)
by_value = {}
for o in raw["vout"]:
    by_value[str(o["value"])] = o["n"]
C7, C11, C13 = (outpoint(T, by_value[v]) for v in ("7.00000000", "11.00000000", "13.00000000"))
CF = outpoint(T, by_value["5.00000000"])
SPENT = outpoint(raw["vin"][0]["txid"], raw["vin"][0]["vout"])
UNKNOWN = outpoint(secrets.token_hex(32), 0)
OUT_OF_RANGE = outpoint(T, 99)


def key(o):
    """divid's std::set<COutPoint> order: the txid as a 256-bit number, then n"""
    return (int(o["txid"], 16), o["vout"])


def locks(name):
    both(f"{name}: listlockunspent", "listlockunspent")


def lock(name, *params):
    both(f"lockunspent {name}", "lockunspent", *params)
    locks(f"after lockunspent {name}")


# --- lockunspent and listlockunspent -------------------------------------------------

locks("at the start")
lock("false [wallet coin]", False, [C7])
lock("false [coin of another wallet]", False, [CF])
lock("false [spent coin]", False, [SPENT])
lock("false [unknown txid]", False, [UNKNOWN])
lock("false [vout out of range]", False, [OUT_OF_RANGE])
lock("false [the same coin again]", False, [C7])
lock("false [one coin twice]", False, [C11, C11])
for what, item in (
        ("missing txid", {"vout": 0}),
        ("missing vout", {"txid": T}),
        ("vout negative", {"txid": T, "vout": -1}),
        ("vout text", {"txid": T, "vout": "1"}),
        ("vout real", {"txid": T, "vout": 1.5}),
        ("vout null", {"txid": T, "vout": None}),
        ("txid number", {"txid": 5, "vout": 0}),
        ("txid not hex", {"txid": "zz" * 32, "vout": 0}),
        ("txid short hex", {"txid": "ab", "vout": 0}),
        ("txid odd hex", {"txid": "abc", "vout": 0}),
        ("txid empty", {"txid": "", "vout": 0}),
        ("txid upper case", {"txid": SPENT["txid"].upper(), "vout": 5}),
        ("extra member", {"txid": T, "vout": 98, "x": 1}),
        ("not an object", "text"),
        ("an array", [T, 0]),
):
    lock(f"false [{what}]", False, [item])
lock("false [good coin, then a bad object]", False, [C13, {"txid": T}])
lock("false []", False, [])
lock("false (no list)", False)
both("lockunspent \"false\"", "lockunspent", "false")
both("lockunspent false {object}", "lockunspent", False, C7)
both("lockunspent (no arguments)", "lockunspent")
both("lockunspent with three arguments", "lockunspent", False, [C7], 1)
both("listlockunspent with an argument", "listlockunspent", 1)

def order_row(name, method, *params, pick=lambda v: v):
    """The order of the members of one reply object"""
    core, iron = C.call(method, *params), I.call(method, *params)
    if core[0] != "ok" or iron[0] != "ok":
        row(name, short(core), short(iron), core == iron)
        return
    a, b = list(pick(core[1])), list(pick(iron[1]))
    b = [k for k in b if k not in EXTRA.get(method, ())]
    row(name, ",".join(a), ",".join(b), a == b)


# With coins locked: the coins and balances a wallet shows
both("locked: listunspent", "listunspent", order=key)
both("locked: listunspent 0", "listunspent", 0, order=key)
both("locked: getbalance", "getbalance")
both("locked: getbalance * 0", "getbalance", "*", 0)
both("locked: getcoinavailability", "getcoinavailability")
both("locked: getcoinavailability true", "getcoinavailability", True)
# (no getstakingstatus here: with (T, 99) locked divid reads past the end of
# T's outputs in lockedCoinBalance, wallet.cpp:2244, and stops; see README.md)
both("locked: getwalletinfo balances", "getwalletinfo",
     view=lambda v: {k: v.get(k) for k in ("balance", "spendable_balance", "unconfirmed_balance", "immature_balance")})
order_row("member order: listunspent item", "listunspent", pick=lambda v: v[0])
order_row("member order: gettxoutsetinfo", "gettxoutsetinfo")
order_row("member order: getcoinavailability", "getcoinavailability")
order_row("member order: listlockunspent item", "listlockunspent", pick=lambda v: v[0])

lock("true [unknown txid]", True, [UNKNOWN])
lock("true [wallet coin]", True, [C7])
lock("true [a coin not locked]", True, [C7])
lock("true (no list)", True)
lock("true []", True, [])

# --- locks across wallet encryption and unlocking ---------------------------------

lock("false [two wallet coins]", False, [C7, C11])
passphrase = secrets.token_hex(16)
both("encryptwallet", "encryptwallet", passphrase)
for n in (C, I):
    wait_for(lambda: n.call("getwalletinfo")[0] == "ok", 60)
locks("after encryptwallet")
lock("false [wallet coin] with the wallet locked", False, [C7])
both("walletlock", "walletlock")
locks("after walletlock")
both("walletpassphrase", "walletpassphrase", passphrase, 9999)
locks("after walletpassphrase")
both("walletpassphrase unlocked for staking only", "walletpassphrase", passphrase, 9999, True)
locks("after walletpassphrase for staking only")
both("walletpassphrase again", "walletpassphrase", passphrase, 9999)

# --- locks across the block holding the coins going and coming back ------------------

lock("false [the three wallet coins]", False, [C7, C11, C13])
both("invalidateblock of the coins' block", "invalidateblock", B1)
locks("after invalidateblock")
both("after invalidateblock: listunspent 0", "listunspent", 0, order=key)
both("after invalidateblock: getbalance", "getbalance")
both("after invalidateblock: getrawmempool", "getrawmempool", order=str)
both("reconsiderblock of the coins' block", "reconsiderblock", B1)
if not synced():
    raise RuntimeError("the nodes did not come back to one tip after reconsiderblock")
locks("after reconsiderblock")

# --- locks across a restart; from here on the nodes keep their transactions apart ------

C.restart(["listen=1"])
I.restart(I_ALONE)
locks("after a restart")
both("after a restart: walletpassphrase", "walletpassphrase", passphrase, 9999)


# --- reverseblocktransactions ---------------------------------------------------------

def chain_state(name):
    for method, kw in (("getblockcount", {}), ("getbestblockhash", {}), ("getbalance", {}),
                       ("getrawmempool", {"order": str}), ("gettxoutsetinfo", {})):
        both(f"{name}: {method}", method, **kw)


def restore(hash_):
    for n in (C, I):
        n.call("reconsiderblock", hash_)
    wait_for(lambda: C.rpc("getblockcount") == I.rpc("getblockcount") == 41, 60)


tip = C.rpc("getbestblockhash")
older = C.rpc("getblockhash", 30)
genesis = C.rpc("getblockhash", 0)
both("reverseblocktransactions the tip", "reverseblocktransactions", tip)
chain_state("after reversing the tip")
both("reconsiderblock after reversing the tip", "reconsiderblock", tip)
chain_state("after reconsiderblock of the reversed tip")
both("reverseblocktransactions an older block", "reverseblocktransactions", older)
chain_state("after reversing block 30")
restore(older)
chain_state("after reconsiderblock of block 30")
both("reverseblocktransactions an unknown hash", "reverseblocktransactions", secrets.token_hex(32))
both("reverseblocktransactions not a hash", "reverseblocktransactions", "xyz")
both("reverseblocktransactions 0x and the tip", "reverseblocktransactions", "0x" + tip)
chain_state("after reversing 0x and the tip")
restore(tip)
both("reverseblocktransactions a number", "reverseblocktransactions", 5)
both("reverseblocktransactions (no arguments)", "reverseblocktransactions")


# --- spending with coins locked -------------------------------------------------------

def spends_locked(node, txid, locked):
    tx = node.rpc("getrawtransaction", txid, 1)
    return any({"txid": i.get("txid"), "vout": i.get("vout")} in locked for i in tx["vin"])


def send(name, method, *params, locked=()):
    """Same outcome; a transaction made spends none of the locked coins"""
    core, iron = C.call(method, *params), I.call(method, *params)
    view = []
    for node, out in ((C, core), (I, iron)):
        if out[0] != "ok":
            view.append(out)
            continue
        txid = out[1]["txhash"] if isinstance(out[1], dict) else out[1]
        view.append(("ok", {"made": True, "spends a locked coin": spends_locked(node, txid, list(locked))}))
    compare(name, view[0], view[1])


spendable = [outpoint(u["txid"], u["vout"]) for u in C.rpc("listunspent") if u.get("spendable", True)]
OWNER, MANAGER = C.rpc("getnewaddress"), C.rpc("getnewaddress")
for a in (OWNER, MANAGER):
    I.rpc("setaccount", a, "")
STAKING = ("walletunlocked", "mintablecoins", "staking_balance", "enoughcoins")
lock("false [one wallet coin of the sendmany]", False, [C7])
both("one wallet coin locked: getstakingstatus", "getstakingstatus", view=lambda v: {k: v.get(k) for k in STAKING})
lock("true (no list) before locking every coin", True)
lock("false [every coin]", False, spendable)
both("every coin locked: getbalance", "getbalance")
both("every coin locked: getcoinavailability", "getcoinavailability")
both("every coin locked: getstakingstatus", "getstakingstatus", view=lambda v: {k: v.get(k) for k in STAKING})
send("every coin locked: sendtoaddress 1", "sendtoaddress", FOREIGN, 1)
send("every coin locked: sendmany 1", "sendmany", "", {FOREIGN: 1})
send("every coin locked: fundvault 1", "fundvault", f"{OWNER}:{MANAGER}", 1)
free = [o for o in spendable if o not in (C7, C11, C13)][0]
lock("true [one coinbase]", True, [free])
locked = [o for o in spendable if o != free]
free_value = [u["amount"] for u in C.rpc("listunspent") if outpoint(u["txid"], u["vout"]) == free][0]
both("one coin free: listunspent", "listunspent", order=key)
both("one coin free: getcoinavailability", "getcoinavailability")
both("one coin free: getstakingstatus", "getstakingstatus", view=lambda v: {k: v.get(k) for k in STAKING})
over = int(float(free_value)) + 100
send(f"one coin free: sendtoaddress {over} (only with locked coins)", "sendtoaddress", FOREIGN, over)
send(f"one coin free: sendmany {over} (only with locked coins)", "sendmany", "", {FOREIGN: over})
send(f"one coin free: fundvault {over} (only with locked coins)", "fundvault", f"{OWNER}:{MANAGER}", over)
send("one coin free: sendtoaddress 3", "sendtoaddress", FOREIGN, 3, locked=locked)
send("one coin free: sendmany 2", "sendmany", "", {FOREIGN: 2}, locked=locked)
send("one coin free: fundvault 4", "fundvault", f"{OWNER}:{MANAGER}", 4, locked=locked)
locks("after the sends")
lock("true (no list) after the sends", True)


# --- loadwallet ------------------------------------------------------------------------

def wallet_dir(node):
    """The folder holding the node's wallet: divid's wallet.dat file,
    irondivid's wallet folder"""
    for root, dirs, files in os.walk(node.dir):
        if "wallet.dat" in files or ("wallet" in dirs and os.path.isfile(os.path.join(root, "wallet", "CURRENT"))):
            return root
    raise RuntimeError(f"no wallet under {node.name}'s datadir")


def wallet_view(info):
    keep = ("walletversion", "balance", "unconfirmed_balance", "immature_balance", "txcount",
            "keypoolsize", "encryption_status")
    return {k: info[k] for k in keep if k in info}


def wallet_rows(name, new_address=False):
    both(f"{name}: getwalletinfo", "getwalletinfo", view=wallet_view)
    both(f"{name}: getbalance", "getbalance")
    if not new_address:
        return
    core, iron = C.call("getnewaddress"), I.call("getnewaddress")
    shape = lambda out: out if out[0] != "ok" else ("ok", "address" if isinstance(out[1], str) else out[1])
    compare(f"{name}: getnewaddress", shape(core), shape(iron))


both("loadwallet wallet.dat (the loaded file)", "loadwallet", "wallet.dat")
wallet_rows("after loadwallet wallet.dat", new_address=True)
for n in (C, I):
    n.rpc("backupwallet", os.path.join(wallet_dir(n), "copy.dat"))
both("loadwallet copy.dat (a backupwallet copy)", "loadwallet", "copy.dat")
wallet_rows("after loadwallet copy.dat")
both("loadwallet wallet.dat back", "loadwallet", "wallet.dat")
both("loadwallet missing.dat (no such file)", "loadwallet", "missing.dat")
wallet_rows("after loadwallet missing.dat")
outside = os.path.join(WORK, "outside")
os.makedirs(outside, exist_ok=True)
for n in (C, I):
    n.rpc("backupwallet", os.path.join(outside, n.name + ".dat"))
core, iron = C.call("loadwallet", os.path.join(outside, "divid.dat")), \
    I.call("loadwallet", os.path.join(outside, "irondivid.dat"))
compare("loadwallet a file outside the datadir", core, iron)
wallet_rows("after loadwallet outside the datadir")
both("loadwallet 5", "loadwallet", 5)
both("loadwallet (no arguments)", "loadwallet")
C.restart(["listen=1"])
I.restart(I_ALONE)
wallet_rows("after loadwallet and a restart")

# --- last: reversing the genesis block (divid may not survive it) --------------------

both("reverseblocktransactions the genesis block", "reverseblocktransactions", genesis)
for method in ("getblockcount", "getbestblockhash", "getbalance"):
    both(f"after reversing the genesis block: {method}", method)
row("after reversing the genesis block: node still answers",
    "yes" if C.call("getblockcount")[0] == "ok" else "no",
    "yes" if I.call("getblockcount")[0] == "ok" else "no",
    (C.call("getblockcount")[0] == "ok") == (I.call("getblockcount")[0] == "ok"))

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
