#!/usr/bin/env python3
"""A large wallet on Divi Core divid and on irondivid, compared: paging and
order of the list calls over thousands of entries, totals, coin selection over
many small coins, and a restart and a -rescan restart (with their wall time).

Both wallets come from the same phrase and sit on one regtest chain, with a
divid miner of its own: the miner pays the twins' addresses, each send is made
on divid first and then on irondivid once it has seen divid's (so each wallet
holds one copy it made and one it only saw), and divid stakes the twins' coins.
Every operation comes from one seeded list. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md), ORDER (the same items in
another order: a FAIL) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment at its
first start; it is never printed or put on a command line.
"""

import base64
import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import member_order  # noqa: E402  (scripts/lib: the order check the replies scripts share)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
SEED = int(os.environ.get("LARGE_WALLET_SEED", "11"))
ADDRESSES = int(os.environ.get("LARGE_WALLET_ADDRESSES", "500"))
RECEIVE_TXS = int(os.environ.get("LARGE_WALLET_RECEIVE_TXS", "300"))  # 10 outputs each
SEND_PAIRS = int(os.environ.get("LARGE_WALLET_SEND_PAIRS", "100"))
STAKES = int(os.environ.get("LARGE_WALLET_STAKES", "300"))
DUMP = os.environ.get("LARGE_WALLET_DUMP", "")
RPC_TIMEOUT = 300
START_TIMEOUT = 900
T0 = time.time()
rng = random.Random(SEED)


def note(text):
    print(f"# [{time.time() - T0:7.1f}s] {text}", flush=True)


# Differences irondivid has on purpose, one per row name (README.md, with divid's
# line); a KNOWN row that starts to match divid is a FAIL
KNOWN = {
    "getstakingstatus": (
        "with coins locked (lockunspent), divid's staking balance takes off, for each locked coin, the wallet's "
        "credit from the whole transaction (lockedCoinBalance adds getCredit(*walletTx), wallet.cpp:2236-2252), not "
        "the coin's value: locked coins of a transaction that paid the wallet several outputs take off too much, "
        "and the balance can go below 0, which makes enoughcoins and mintablecoins false (rpcmisc.cpp:1063-1066, "
        "wallet.cpp:1377-1385, :1466-1469). irondivid takes off the locked coins' values. divid is wrong here by "
        "accident; lockunspent is not kept across a restart, so the rows after it match"),
}
# Fields irondivid adds on purpose (as scripts/wallet-replies): compared without
# them, named once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "listreceivedbyaddress": {"label"},
    "listunspent": {"ischange", "solvable"},
    "getwalletinfo": {"walletname", "keypoololdest", "paytxfee", "hdmasterkeyid"},
    "getstakingstatus": {"staking status text"},
}
for m, why in (("listreceivedbyaddress", "label, kept as an extra field (divid ListReceived, rpcwallet.cpp:1793-1912)"),
               ("listunspent", "ischange, solvable, kept as extra fields (divid listunspent, "
                               "rpcrawtransaction.cpp:320-334)"),
               ("getwalletinfo", "walletname, keypoololdest, paytxfee, hdmasterkeyid "
                                 "(docs/divid-differences.md R4)"),
               ("getstakingstatus", "staking status text, the staker's state in words (also KNOWN in "
                                    "scripts/received, start-rescan, vault-records)")):
    KNOWN[f"{m}: fields divid lacks"] = why
extra_seen = {}
# Set from the moment a node saw a transaction, not from the chain (as
# scripts/wallet-replies): the two nodes see a relayed one apart
MOMENT = {"timereceived", "time"}
# A send's notes exist only on the node that made it (compared in "notes" rows)
NOTES = {"comment", "to", "FromAccount"}

fails = 0


def known(name):
    """A row's KNOWN reason; the extra-field rows after a restart share the
    entry of the row before it"""
    if name in KNOWN:
        return KNOWN[name]
    if ": " in name and name.split(": ", 1)[0] in WHENS and name.endswith("fields divid lacks"):
        return KNOWN.get(name.split(": ", 1)[1])
    return None


WHENS = {"after restart", "after -rescan"}


def row(name, core, iron, same, moved=None):
    global fails
    if moved:
        fails += 1
        print(f"ORDER  {name}  {moved}  divid={core}  irondivid={iron}"[:500], flush=True)
        return
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        why = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        why = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{why}"[:500], flush=True)


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_tb(tb)
    print(f"FAIL   setup: {kind.__name__}: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- nodes -----------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, extra_conf, env=None, template=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        if template:
            shutil.copytree(template, self.dir)
            os.remove(os.path.join(self.dir, "divi.conf"))
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"lw{index}:{password}".encode()).decode()
        os.makedirs(self.dir, exist_ok=True)
        self.conf = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=lw{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "txindex=1",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.conf) + "\n")
        self.log = None
        self.start()

    def start(self, args=()):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.started = time.time()
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "")
        except (OSError, ValueError) as e:
            return ("err", "no reply", f"{type(e).__name__}: {e}"[:120])
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:160]}")
        return out[1]

    def wait_ready(self):
        """Seconds until RPC answers getblockcount, or None"""
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return None
            if self.call("getblockcount")[0] == "ok":
                return time.time() - self.started
            time.sleep(0.05)
        return None

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


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


# --- how replies are compared (as scripts/wallet-replies) --------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
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
    if a != b:
        return f"{path}: {json.dumps(a)[:80]} vs {json.dumps(b)[:80]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{str(out[2])[:80]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def unordered(v):
    if isinstance(v, dict):
        return {k: sorted(x) if k == "txids" and isinstance(x, list) else unordered(x) for k, x in v.items()}
    if isinstance(v, list):
        return [unordered(x) for x in v]
    return v


def compare(name, core, iron, drop=MOMENT | NOTES, order=None):
    if core[0] == "err" or iron[0] == "err":
        row(name, short(core), short(iron), core[0] == iron[0] and core[1:] == iron[1:])
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    moved = member_order.difference(a, b) if order is None else None
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    a, b = unordered(a), unordered(b)
    d = first_difference(a, b)
    if DUMP and d:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1)
    row(name, short(core), d or short(iron), d is None, moved=moved)


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok":
        items = iron[1] if isinstance(iron[1], list) else [iron[1]]
        found = set()
        for item in items:
            if isinstance(item, dict):
                found |= extra & set(item)
        when = name.split(": ", 1)[0] if name.split(": ", 1)[0] in WHENS else ""
        extra_seen.setdefault(when, {}).setdefault(method, set()).update(found)
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)
    return core, iron


def extra_rows(when):
    p = f"{when}: " if when else ""
    for method in EXTRA:
        found = extra_seen.get(when, {}).get(method, set())
        row(f"{p}{method}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


# --- the nodes and the chain -------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if C.wait_ready() is None:
    raise RuntimeError("divid did not answer")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
M = Node("miner", DIVID, 2, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"])
for n in (I, M):
    if n.wait_ready() is None:
        raise RuntimeError(f"{n.name} did not answer")
if not wait_for(lambda: C.rpc("getconnectioncount") >= 2, 60):
    raise RuntimeError("irondivid and the miner did not connect to divid")
I.env = None  # later starts read the wallet irondivid made
note(f"divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}")


def synced(secs=300):
    """All three nodes on one tip"""
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in (C, I, M)}) == 1, secs)


def mine(node, n):
    """n blocks on `node`, one call at a time (a stake is not always found at once)"""
    for _ in range(n):
        if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok", 120):
            raise RuntimeError(f"{node.name} could not mine")


def seen_by(node, txid, secs=120):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), secs)


M.rpc("setgenerate", 101)
if not synced():
    raise RuntimeError("the twins did not follow the miner")

# The twins' addresses, the same on both, over six accounts
ACCOUNTS = ["", "alpha", "beta", "gamma", "small", "savings"]
addr_acct = {}
for k in range(ADDRESSES):
    acct = "small" if k % 5 == 4 else ACCOUNTS[k % 6] if k % 6 != 4 else "savings"
    a, b = C.rpc("getnewaddress", acct), I.rpc("getnewaddress", acct)
    if a != b:
        raise RuntimeError(f"the twins hand out different addresses ({k})")
    addr_acct[a] = acct
ADDRS = list(addr_acct)
SMALL = [a for a in ADDRS if addr_acct[a] == "small"]
OTHER = [a for a in ADDRS if addr_acct[a] != "small"]
note(f"{len(ADDRS)} addresses: " + ", ".join(f"{acct or chr(34) * 2} {sum(1 for x in ADDRS if addr_acct[x] == acct)}"
                                             for acct in ACCOUNTS))

# Receives: the miner pays ten addresses a transaction; small coins to "small"
# (0.01 to 0.99 DIVI), larger ones elsewhere; a block after every 30
received = 0
for t in range(RECEIVE_TXS):
    payees = {}
    for a in rng.sample(SMALL, 6):
        payees[a] = float(Decimal(rng.randint(1, 99)) / 100)
    for a in rng.sample(OTHER, 4):
        payees[a] = float(Decimal(rng.choice([1, 2, 5, 10, 20, 50])) + Decimal(rng.randint(0, 99)) / 100)
    txid = M.rpc("sendmany", "", payees)
    # Both twins have it before the next: a wallet lists what it learns in the
    # order it learns it, and relay could hand the two nodes a burst in two orders
    if not (seen_by(C, txid) and seen_by(I, txid)):
        raise RuntimeError(f"a receive did not reach both twins ({t})")
    received += len(payees)
    if t % 30 == 29:
        mine(M, 1)
mine(M, 21)  # every coin mature enough to stake and to spend
if not synced():
    raise RuntimeError("the twins did not follow the receives")
note(f"{received} receives in {RECEIVE_TXS} transactions")

# Sends: the same send on divid, then on irondivid once it has divid's; a third
# with comments; to the miner, or to the wallet's own addresses
own = []  # (divid's txid, irondivid's txid, what)
TO = [M.rpc("getnewaddress") for _ in range(20)]


def send_pair(what, method, *params):
    a = C.rpc(method, *params)
    if not seen_by(I, a):
        raise RuntimeError(f"irondivid did not see divid's {what}")
    b = I.rpc(method, *params)
    if not seen_by(C, b):
        raise RuntimeError(f"divid did not see irondivid's {what}")
    own.append((a, b, what))


for k in range(SEND_PAIRS):
    amount = float(Decimal(rng.randint(10, 500)) / 100)
    kind = k % 4
    if kind == 0:
        send_pair(f"send {k}", "sendtoaddress", rng.choice(TO), amount)
    elif kind == 1:
        send_pair(f"send {k} with a comment", "sendtoaddress", rng.choice(TO), amount, "metadata",
                  f"note {k}", f"to {k % 7}")
    elif kind == 2:
        # To the wallet's own address. Not sendfrom: which account a send debits is
        # a note of the node that made it, so each node's account lists would hold
        # only its own copy of the pair
        send_pair(f"send {k} to an own address with a comment", "sendtoaddress", rng.choice(OTHER), amount,
                  "metadata", f"move {k}", f"self {k % 5}")
    else:
        send_pair(f"sendmany {k}", "sendmany", "", {rng.choice(TO): amount, rng.choice(OTHER): amount / 2})
    if k % 10 == 9:
        mine(M, 1)
        if not synced():
            raise RuntimeError("the twins did not follow the sends")
note(f"{2 * SEND_PAIRS} sends ({SEND_PAIRS} on each)")

# Stakes: divid stakes the twins' coins
done = 0
while done < STAKES:
    mine(C, 1)
    done += 1
if not synced():
    raise RuntimeError("irondivid did not follow the stakes")
note(f"{STAKES} blocks staked by the twins' coins")

# The same lockunspent set on both
coins = C.rpc("listunspent", 1)
LOCKED = [{"txid": u["txid"], "vout": u["vout"]} for u in rng.sample(coins, min(60, len(coins)))]
for n in (C, I):
    n.rpc("lockunspent", False, LOCKED)
# One send pair left in the mempool
send_pair("unconfirmed send", "sendtoaddress", TO[0], 1.5)
HEIGHT = C.rpc("getblockcount")
note(f"chain {HEIGHT} blocks; divid's wallet {C.rpc('getwalletinfo').get('txcount')} transactions")


# --- the replies -----------------------------------------------------------------------

def entry_key(e):
    return (e.get("txid", ""), e.get("vout", 0), e.get("category", ""), e.get("address", ""), str(e.get("amount")))


def replies(when):
    p = f"{when}: " if when else ""
    full_c, full_i = both(f"{p}listtransactions * 100000 0 (the whole history)", "listtransactions", "*", 100000, 0)
    total = len(full_c[1]) if full_c[0] == "ok" else 0
    note(f"{p}listtransactions: {total} entries on divid, "
         f"{len(full_i[1]) if full_i[0] == 'ok' else full_i} on irondivid")
    # Pages over the whole history, and the edges
    for start in range(0, total + 1, 700):
        both(f"{p}listtransactions * 700 {start}", "listtransactions", "*", 700, start)
    for args in (["*", 10, total + 10], ["*", 10, total - 5], ["*", 0, 0], ["*", 0, 50], ["*", -1, 0],
                 ["*", 10, -1], ["*", 1, 0], ["", 500, 0], ["", 100000, 0], ["small", 100000, 0],
                 ["small", 50, 300], ["savings", 20, 0], ["nobody", 10, 0]):
        both(f"{p}listtransactions {json.dumps(args)}", "listtransactions", *args)
    # Each node's own copy of each send: its notes
    same_notes = sum(1 for a, b, _ in own if notes_of(C, a) == notes_of(I, b))
    row(f"{p}notes of each node's own sends (comment, to, FromAccount)", f"{len(own)} sends",
        f"{same_notes} the same", same_notes == len(own))
    order = lambda e: entry_key(e)
    for h in (0, HEIGHT // 2, HEIGHT - 60, HEIGHT - 5, HEIGHT):
        args = [C.rpc("getblockhash", h)] if h else []
        both(f"{p}listsinceblock {'(none)' if not h else 'height ' + str(h)}", "listsinceblock", *args, order=order)
    for args in ([], [0, True], [1, False], [6, True], [100, False]):
        both(f"{p}listreceivedbyaddress {json.dumps(args)}", "listreceivedbyaddress", *args,
             order=lambda e: e.get("address", ""))
        both(f"{p}listreceivedbyaccount {json.dumps(args)}", "listreceivedbyaccount", *args,
             order=lambda e: e.get("account", ""))
    ukey = lambda u: (u.get("txid", ""), u.get("vout", 0))
    for args in ([], [0], [1, 5], [10, 50], [200, 9999999], [1, 9999999, SMALL[:3]], [0, 9999999, [OTHER[0]]]):
        label = json.dumps(args) if len(json.dumps(args)) < 60 else f"[{args[0]}, {args[1]}, <{len(args[2])} addresses>]"
        both(f"{p}listunspent {label}", "listunspent", *args, order=ukey)
    both(f"{p}listlockunspent", "listlockunspent", order=ukey)
    for args in ([], ["*"], ["*", 0], ["*", 6]) + tuple([a] for a in ACCOUNTS) + tuple([a, 0] for a in ACCOUNTS):
        both(f"{p}getbalance {json.dumps(args)}", "getbalance", *args)
    both(f"{p}getunconfirmedbalance", "getunconfirmedbalance")
    both(f"{p}listaccounts", "listaccounts")
    both(f"{p}getwalletinfo", "getwalletinfo")
    # Not "staking status": whether the node itself tried to stake in the last
    # minutes (rpcmisc.cpp:1071-1072), and only divid stakes in this run
    both(f"{p}getstakingstatus", "getstakingstatus", drop=MOMENT | {"staking status"})
    extra_rows(when)


def notes_of(node, txid):
    out = node.call("gettransaction", txid)
    return {k: v for k, v in out[1].items() if k in NOTES} if out[0] == "ok" else out


replies("")


# --- coin selection over many small coins: fresh copies of both, no peers -----------------

def stop_all():
    for n in (C, I, M):
        n.stop()


stop_all()
TEMPLATES = (C.dir, I.dir)


def copies():
    for name in ("divid-copy", "irondivid-copy"):
        shutil.rmtree(os.path.join(WORK, name), ignore_errors=True)
    dead = f"connect=127.0.0.2:{PORT_BASE + 9}"
    c = Node("divid-copy", DIVID, 0, ["listen=0", dead], template=TEMPLATES[0])
    i = Node("irondivid-copy", IRONDIVID, 1, ["listen=0", dead], template=TEMPLATES[1])
    for n in (c, i):
        if n.wait_ready() is None:
            raise RuntimeError(f"{n.name} did not start")
    return c, i


def built(node, out):
    if out[0] != "ok":
        return out
    tx = node.rpc("getrawtransaction", out[1], 1)
    value_in = 0
    inputs = []
    for vin in tx["vin"]:
        prev = node.rpc("getrawtransaction", vin["txid"], 1)["vout"][vin["vout"]]
        value_in += int(Decimal(prev["value"]) * 100_000_000)
        inputs.append(f"{vin['txid']}:{vin['vout']}")
    fee = value_in - sum(int(Decimal(v["value"]) * 100_000_000) for v in tx["vout"])
    return ("ok", {"inputs": sorted(inputs), "input count": len(inputs), "fee": fee,
                   "outputs": sorted((str(v["value"]), v["scriptPubKey"].get("addresses", ["?"])[0] in TO)
                                     for v in tx["vout"])})


# The small account's coins, largest first (the order divid's selection takes
# them in when none covers the amount alone, MinimumFeeCoinSelectionAlgorithm.cpp:127-140):
# amounts that need about 300 and about 900 of them; 900 inputs are over divid's
# 100,000-byte transaction limit (:93, defaultValues.h:54)
c, i = copies()
small_coins = sorted((Decimal(u["amount"]) for u in c.rpc("listunspent", 1)
                      if addr_acct.get(u["address"]) == "small"), reverse=True)
for n in (c, i):
    n.stop()
note(f"the small account: {len(small_coins)} spendable coins, {sum(small_coins)} DIVI")
CASES = [("sendfrom small 5", ["small", TO[1], 5])]
for k in (300, 900):
    if len(small_coins) > k:
        CASES.append((f"sendfrom small, about {k} coins", ["small", TO[1], float(sum(small_coins[:k]) - Decimal("0.5"))]))
CASES.append(("sendtoaddress 2000 (the default account takes every coin)", None))
for name, params in CASES:
    c, i = copies()
    try:
        if params is None:
            core, iron = c.call("sendtoaddress", TO[1], 2000), i.call("sendtoaddress", TO[1], 2000)
        else:
            core, iron = c.call("sendfrom", *params), i.call("sendfrom", *params)
        compare(f"coin selection: {name}", built(c, core), built(i, iron), drop=set())
    finally:
        for n in (c, i):
            n.stop()


# --- restart and -rescan: wall time, then the same replies -----------------------------

TIMES = {}


def restart(label, args=()):
    for n in (C, M, I):
        n.start(args if n is not M else ())
    for n in (C, I):
        secs = n.wait_ready()
        if secs is None:
            raise RuntimeError(f"{n.name} did not answer after the {label}")
        TIMES[(label, n.name)] = secs
    M.wait_ready()
    if not synced(600):
        raise RuntimeError(f"the nodes are not on one tip after the {label}")
    for n in (C, I):
        TIMES[(label + " (on the tip)", n.name)] = time.time() - n.started
    row(f"{label}: height", C.rpc("getblockcount"), I.rpc("getblockcount"),
        C.rpc("getblockcount") == I.rpc("getblockcount") == HEIGHT)
    both(f"{label}: getbalance", "getbalance")
    count = lambda n: len(n.rpc("listtransactions", "*", 100000, 0))
    row(f"{label}: listtransactions entries", count(C), count(I), count(C) == count(I))


restart("after restart")
for n in (C, I):
    seen_by(n, own[-1][0], 60)
replies("after restart")
stop_all()
restart("after -rescan", ("-rescan",))
replies("after -rescan")
stop_all()

print("# wall time (seconds): start to the first RPC answer, and to the tip", flush=True)
for (label, name), secs in sorted(TIMES.items()):
    print(f"#   {label}: {name} {secs:.1f}", flush=True)
for label in ("after restart", "after -rescan"):
    c, i = TIMES[(label, "divid")], TIMES[(label, "irondivid")]
    print(f"#   {label}: irondivid/divid {i / c:.2f}" + ("  (over 3x)" if i > 3 * c else ""), flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
