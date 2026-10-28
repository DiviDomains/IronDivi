#!/usr/bin/env python3
"""The wallet's transaction history replies of Divi Core divid next to
irondivid on regtest, for each kind of wallet transaction: listtransactions,
gettransaction, listsinceblock, getwalletinfo and getbalance, compared field
by field after every step (README.md lists the steps).

S, a divid, mines and stakes and pays; C, a divid wallet (vault owner), and I,
an irondivid restored from C's phrase (WALLET_MNEMONIC); M, a divid vault
manager (vault=1), and N, an irondivid restored from M's phrase; X, a divid
that is cut off from the others to build the branch that orphans a stake.
Rows print PASS (same as divid), KNOWN (listed in README.md) or FAIL; exit
code = FAILs.

Phrases go into the irondivid environment only; RPC passwords are random and
written only to each node's 0600 divi.conf; none is printed or put on a
command line.
"""

import base64
import collections
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("TX_HISTORY_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
KNOWN = []

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v, cut=260):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if cut is None else text[:cut]


def first_difference(core, iron):
    """Where two long values first part, as the row is cut at 260 characters"""
    c, i = show(core, cut=None), show(iron, cut=None)
    if len(c) <= 260 and len(i) <= 260:
        return ""
    k = next((n for n, (x, y) in enumerate(zip(c, i)) if x != y), min(len(c), len(i)))
    return f"  [first difference at {k}: divid ...{c[max(0, k - 40):k + 60]}... irondivid ...{i[max(0, k - 40):k + 60]}...]"


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = known(name)
    if listed:
        reason, shape = listed
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
        note += first_difference(core, iron)
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


class Node:
    """A node on `datadir` (made with a divi.conf when new)"""

    def __init__(self, name, binary, index, extra_conf=(), env=None, datadir=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = datadir or os.path.join(WORK, name)
        self.starts = 0
        self.proc = None
        if not os.path.exists(os.path.join(self.dir, "divi.conf")):
            os.makedirs(self.dir, exist_ok=True)
            password = secrets.token_hex(16)
            user = "th" + secrets.token_hex(4)
            lines = [
                "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
                f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
                "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "dnsseed=0",
                "staking=0", "allowunencryptedwallet=1",
            ] + list(extra_conf)
            fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines) + "\n")
        self.read_conf()

    def read_conf(self):
        conf = dict(l.split("=", 1) for l in open(os.path.join(self.dir, "divi.conf")).read().split("\n") if "=" in l)
        self.rpcport = int(conf["rpcport"])
        self.auth = base64.b64encode(f"{conf['rpcuser']}:{conf['rpcpassword']}".encode()).decode()

    def set_conf(self, key, value):
        """Replace (or add) one line of divi.conf"""
        path = os.path.join(self.dir, "divi.conf")
        lines = [l for l in open(path).read().split("\n") if l and not l.startswith(key + "=")]
        lines.append(f"{key}={value}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.read_conf()

    def launch(self, *args):
        self.starts += 1
        self.out = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        env = dict(os.environ, **self.env) if self.env else None
        with open(self.out, "w") as o:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=o, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code)"""
        self.launch(*args)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code)
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.5)
        return ("exit", "none within %d s" % START_TIMEOUT)

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def logs(self):
        return [os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")]

    def tail(self, n=4):
        lines = []
        for path in [self.out] + self.logs() if self.starts else self.logs():
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]


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


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    for n in globals().get("NODES", ()):
        t = n.tail()
        if t:
            print(f"#      {n.name}: {t}"[:700], flush=True)
    if os.environ.get("TX_HISTORY_DEBUG"):
        import traceback
        traceback.print_tb(tb)
        for n in globals().get("NODES", ()):
            for p in n.logs():
                if os.path.exists(p):
                    shutil.copy(p, os.path.join(os.environ["TX_HISTORY_DEBUG"], n.name + ".log"))
    sys.exit(1)


sys.excepthook = setup_failed



def outcome(out, value=lambda v: v):
    if out[0] == "err":
        return {"error": out[1], "message": out[2]}
    return {"ok": value(out[1])}


def amount(v):
    return None if v is None else round(float(v), 8)



def both(name, fn):
    c, i = fn(C), fn(I)
    row(name, c, i)
    return c, i


# --- the nodes ---------------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
DIAL = ["listen=0", f"connect={HOST}:{S.p2p}"]
C = Node("divid-owner", DIVID, 1, DIAL)
M = Node("divid-manager", DIVID, 3, DIAL + ["vault=1"])
X = Node("divid-branch", DIVID, 5, DIAL)
for n in (C, M, X):
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-owner", IRONDIVID, 2, DIAL, env={"WALLET_MNEMONIC": phrase})
phrase = M.rpc("dumphdinfo")["mnemonic"]
N = Node("irondivid-manager", IRONDIVID, 4, DIAL + ["vault=1"], env={"WALLET_MNEMONIC": phrase})
del phrase
for n in (I, N):
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
NODES = [S, C, I, M, N, X]
JOINED = list(NODES)
PAIRS = [("owner", C, I), ("manager", M, N)]
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

LABELS = {}     # txid -> what the step made
# Sends made by one twin, which keeps the send's notes (mapValue: FromAccount,
# comment, to; wallet.cpp:1918-1921) that the other twin, which only saw it,
# has not: txid -> kind. The notes and the send entries' account are compared
# maker against maker (C's own record of its send against I's of the same
# kind of send), the rest of the record twin against twin.
MADE = {}
NOTES = ("FromAccount", "comment", "to")


def label(txid, what):
    LABELS.setdefault(txid, what)
    return txid


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in JOINED}) == 1, secs)


def block_by(node, tries=30):
    """One block from `node` with setgenerate; a stake needs the clock past the
    tip, and a wallet of few coins hashes few kernels a second"""
    out = None
    for _ in range(tries):
        tip = node.rpc("getblock", node.rpc("getbestblockhash"))
        wait_for(lambda: time.time() > tip["time"] + 1, 60)
        out = node.call("setgenerate", 1)
        if out[0] == "ok" and node.rpc("getblockcount") > tip["height"]:
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"{node.name} made no block: {out}")
    if node in JOINED and not synced():
        raise RuntimeError("the nodes did not follow the chain")
    return node.rpc("getblockcount")


def bare_block(extra=()):
    """S mines a block of its own coinstake and `extra` only, leaving the mempool"""
    out = None
    for _ in range(30):
        out = S.call("generateblock", {"extratx": list(extra), "ignoreMempool": True})
        if out[0] == "ok":
            break
        time.sleep(2)
    if out[0] != "ok":
        raise RuntimeError(f"S could not mine the block: {out}")
    if not synced():
        raise RuntimeError("the nodes did not follow S's block")
    return S.rpc("getblockcount")


def mine(n=1, by=None):
    for _ in range(n):
        block_by(by or S)


def special(h):
    """A lottery height (every 10th from 101) or a treasury height (every 50th
    from 102: 150, 200, ..., which wins over a lottery at the same height;
    chainparams.cpp:490-493, scripts/superblocks)"""
    return h >= 101 and h % 10 == 0


def ordinary_next():
    """S mines until the next block (and the one after) is at an ordinary height"""
    while special(S.rpc("getblockcount") + 1) or special(S.rpc("getblockcount") + 2):
        block_by(S)


ARRIVED = {}    # txid -> {node name: when its mempool first showed it}


def seen(txid, nodes=None):
    first = ARRIVED.setdefault(txid, {})

    def everywhere():
        for n in nodes or JOINED:
            if n.name not in first and txid in n.rpc("getrawmempool"):
                first[n.name] = time.time()
        return all(n.name in first for n in nodes or JOINED)

    if not wait_for(everywhere, 60):
        raise RuntimeError(f"{LABELS.get(txid, txid)} did not reach every mempool")
    return txid


def shared_address(node, twin, account=""):
    """A new address of `node` that its twin holds under the same account"""
    address = node.rpc("getnewaddress", account) if account else node.rpc("getnewaddress")
    twin.rpc("setaccount", address, account)
    return address


def with_coins(node, coins, fn):
    """fn() with only `coins` ((txid, vout)) of `node`'s unlocked"""
    node.rpc("lockunspent", True)
    others = [{"txid": u["txid"], "vout": u["vout"]} for u in node.rpc("listunspent", 0, 9999999)
              if (u["txid"], u["vout"]) not in coins]
    if others:
        node.rpc("lockunspent", False, others)
    try:
        return fn()
    finally:
        node.rpc("lockunspent", True)


def sparing(node, coins, fn):
    """fn() with `coins` ((txid, vout)) of `node`'s locked, so a send of the
    wallet's own choosing leaves them to a later step"""
    locked = [{"txid": t, "vout": v} for t, v in coins]
    if locked:
        node.rpc("lockunspent", False, locked)
    try:
        return fn()
    finally:
        if locked:
            node.rpc("lockunspent", True, locked)


def stake_only(node, coins):
    """`node` stakes one block with only `coins` ((txid, vout)) unlocked of
    the coins old enough to stake (10 blocks deep, SelectStakeCoins,
    wallet.cpp:1433-1462). divid takes a locked coin off the staking balance
    by the wallet credit of its whole transaction, once per locked output
    (lockedCoinBalance, wallet.cpp:2236-2252), so only coins whose transaction
    pays the wallet nothing else may be locked: sweep() first."""
    node.rpc("lockunspent", True)
    others = [{"txid": u["txid"], "vout": u["vout"]} for u in node.rpc("listunspent", 10, 9999999)
              if (u["txid"], u["vout"]) not in coins]
    if others:
        node.rpc("lockunspent", False, others)
    try:
        return block_by(node, 400)
    finally:
        node.rpc("lockunspent", True)


def sweep(node, keep, to):
    """All of `node`'s confirmed coins but `keep` into one new coin of `to`'s,
    mined: too young to stake for the next 9 blocks"""
    coins = [u for u in node.rpc("listunspent", 1, 9999999)
             if (u["txid"], u["vout"]) not in keep and u["scriptPubKey"].startswith("76a914")]
    total = sum(u["amount"] for u in coins)
    raw = node.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]} for u in coins],
                   {to: round(total - 0.1, 8)})
    txid = node.rpc("sendrawtransaction", node.rpc("signrawtransaction", raw)["hex"])
    seen(label(txid, f"sweep of {len(coins)} coins by C (sendrawtransaction)"))
    mine(1)
    return txid


def coins_at(node, address):
    return {(u["txid"], u["vout"]) for u in node.rpc("listunspent", 1, 9999999, [address])}


def coinstake_at(h, node=None):
    return (node or S).rpc("getblock", (node or S).rpc("getblockhash", h))["tx"][1]


# --- comparing the history ---------------------------------------------------------------
TOL = 3                       # seconds the twins' clocks may read apart, past the gap between their mempools
CLOCK = ("time", "timereceived")


def clean(v):
    """`v` without the clock fields, amounts rounded"""
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items() if k not in CLOCK}
    if isinstance(v, list):
        return [clean(x) for x in v]
    if isinstance(v, float):
        return round(v, 8)
    return v


def unmade(e, txid=None):
    """A history entry or gettransaction reply without what only the maker of
    a send has"""
    if (txid or e.get("txid")) not in MADE:
        return e
    e = {k: v for k, v in e.items() if k not in NOTES}
    if e.get("category") == "send":
        e.pop("account", None)
    return e


def made(node, txid, kind):
    MADE[txid] = kind
    return label(txid, f"{kind} by {'C' if node is C else 'I'}")


def ekey(e):
    return (e.get("txid", ""), e.get("category", ""), e.get("vout", -1), json.dumps(clean(e.get("amount"))),
            e.get("address", ""))


def name_of(txid):
    return LABELS.get(txid, txid[:12])


def entry_diffs(c_list, i_list):
    """What differs between two lists of history entries, item by item"""
    cs, is_ = collections.defaultdict(list), collections.defaultdict(list)
    for e in c_list:
        cs[ekey(e)].append(clean(unmade(e)))
    for e in i_list:
        is_[ekey(e)].append(clean(unmade(e)))
    out = []
    for k in sorted(set(cs) | set(is_)):
        a, b = cs.get(k, []), is_.get(k, [])
        tag = f"{name_of(k[0])} {k[1]} vout={k[2]} amount={k[3]}"
        if len(a) != len(b):
            out.append(f"{tag}: divid has {len(a)}, irondivid {len(b)}")
            continue
        for x, y in zip(sorted(a, key=json.dumps), sorted(b, key=json.dumps)):
            for f in sorted(set(x) | set(y)):
                if x.get(f, "<absent>") != y.get(f, "<absent>"):
                    out.append(f"{tag}: {f} divid={show(x.get(f, '<absent>'), 120)} "
                               f"irondivid={show(y.get(f, '<absent>'), 120)}")
    return out


def obj_diffs(c, i, prefix=""):
    out = []
    if isinstance(c, dict) and isinstance(i, dict):
        for f in sorted(set(c) | set(i)):
            out += obj_diffs(c.get(f, "<absent>"), i.get(f, "<absent>"), f"{prefix}{f}.")
    elif c != i:
        out.append(f"{prefix.rstrip('.')}: divid={show(c, 160)} irondivid={show(i, 160)}")
    return out


def diff_row(name, diffs):
    """One row: the differences found (none = PASS), each printed below it"""
    row(name, len(diffs) and diffs[0][:200] or "same", len(diffs) and "differs" or "same", not diffs)
    for d in diffs[1:12]:
        print(f"#        {d}"[:400], flush=True)
    if len(diffs) > 12:
        print(f"#        ... {len(diffs) - 12} more", flush=True)


def relay_gap(txid, c, i):
    """Seconds between the twins' mempools first showing `txid` (0 for one not followed by seen())"""
    first = ARRIVED.get(txid, {})
    if c.name in first and i.name in first:
        return abs(first[c.name] - first[i.name])
    return 0


def clock_diffs(c_list, i_list, c, i):
    """Entries of one transaction whose time or timereceived is more than TOL, past the relay gap, apart"""
    ct = {e.get("txid"): e for e in c_list}
    it = {e.get("txid"): e for e in i_list}
    out = []
    for t in sorted(set(ct) & set(it)):
        for f in CLOCK:
            a, b = ct[t].get(f), it[t].get(f)
            gap = relay_gap(t, c, i)
            if (a is None) != (b is None) or (a is not None and abs(a - b) > TOL + gap):
                out.append(f"{name_of(t)}: {f} divid={a} irondivid={b} (relay gap {gap:.1f} s)")
    return out


def wallet_txids(n):
    return {e.get("txid") for e in n.rpc("listtransactions", "*", 100000, 0, True) if e.get("txid")}


def snapshot(when, since=None, pairs=None):
    """Every history reply of each twin pair, compared"""
    time.sleep(1)
    for side, c, i in pairs or PAIRS:
        p = f"{when}: {side}: "
        for args in (("*", 100000, 0, True), ("*", 100000, 0, False), ("", 100000, 0, True)):
            a, b = c.rpc("listtransactions", *args), i.rpc("listtransactions", *args)
            if args[0] == "":
                # Whose account a send is listed under is the maker's (compared below)
                a, b = ([e for e in x if not (e.get("txid") in MADE and e.get("category") == "send")] for x in (a, b))
            q = f"{p}listtransactions {' '.join(json.dumps(x) for x in args)}"
            diff_row(q, entry_diffs(a, b))
            if args[3] and args[0] == "*":
                diff_row(f"{q}: time and timereceived (within {TOL} s past the relay gap)", clock_diffs(a, b, c, i))
                oa = [ekey(e)[:3] for e in a]
                ob = [ekey(e)[:3] for e in b]
                same_set = sorted(oa) == sorted(ob)
                diff_row(f"{q}: order", [] if not same_set or oa == ob else
                         [f"first apart at {k}: divid {name_of(oa[k][0])} {oa[k][1]}, irondivid "
                          f"{name_of(ob[k][0])} {ob[k][1]}"
                          for k in [next(k for k in range(len(oa)) if oa[k] != ob[k])]])
        # A short page, so the newest-first window is compared too
        diff_row(f"{p}listtransactions \"*\" 3 1 true",
                 obj_diffs(clean([unmade(e) for e in c.rpc("listtransactions", "*", 3, 1, True)]),
                           clean([unmade(e) for e in i.rpc("listtransactions", "*", 3, 1, True)])))
        txids = sorted(wallet_txids(c) | wallet_txids(i) | set(LABELS))
        for watch in (True, False):
            diffs = []
            for t in txids:
                x, y = c.call("gettransaction", t, watch), i.call("gettransaction", t, watch)
                x = clean(unmade(x[1], t)) if x[0] == "ok" else list(x[1:])
                y = clean(unmade(y[1], t)) if y[0] == "ok" else list(y[1:])
                if isinstance(x, dict) and isinstance(y, dict):
                    xd, yd = x.pop("details", []), y.pop("details", [])
                    diffs += [f"{name_of(t)}: {d}" for d in obj_diffs(x, y)]
                    diffs += [f"details of {d}" for d in entry_diffs(
                        [dict(e, txid=t) for e in xd], [dict(e, txid=t) for e in yd])]
                elif x != y:
                    diffs.append(f"{name_of(t)}: divid={show(x, 120)} irondivid={show(y, 120)}")
            diff_row(f"{p}gettransaction <each of {len(txids)}> {str(watch).lower()}", diffs)
        for args in ((), (since, 1, True) if since else None):
            if args is None:
                continue
            a, b = c.rpc("listsinceblock", *args), i.rpc("listsinceblock", *args)
            q = f"{p}listsinceblock" + (" <block before the step> 1 true" if args else "")
            diff_row(q, entry_diffs(a["transactions"], b["transactions"]) +
                     obj_diffs(a["lastblock"], b["lastblock"], "lastblock."))
        keep = ("balance", "unconfirmed_balance", "immature_balance", "spendable_balance", "vaulted_balance", "txcount")
        a, b = c.rpc("getwalletinfo"), i.rpc("getwalletinfo")
        diff_row(f"{p}getwalletinfo {','.join(keep)}",
                 obj_diffs(clean({k: a.get(k) for k in keep}), clean({k: b.get(k) for k in keep})))
        bal = {}
        for args in ((), ("*", 0), ("*", 1, True), ("*", 0, True), ("", 0), ("", 1, True), ("acct1",),
                     ("acct1", 0)):
            bal[f"getbalance {' '.join(json.dumps(x) for x in args)}"] = (
                outcome(c.call("getbalance", *args), amount), outcome(i.call("getbalance", *args), amount))
        bal["getunconfirmedbalance"] = (outcome(c.call("getunconfirmedbalance"), amount),
                                        outcome(i.call("getunconfirmedbalance"), amount))
        diff_row(f"{p}getbalance forms, getunconfirmedbalance",
                 [f"{k}: divid={show(x)} irondivid={show(y)}" for k, (x, y) in bal.items() if x != y])
    if pairs is None:
        makers(when)


def own_view(node, txid):
    """What the maker of a send keeps of it: the notes, each send entry's
    account, and the send entries listtransactions "" and "acct1" give"""
    g = node.rpc("gettransaction", txid, True)
    sends = lambda acct: len([e for e in node.rpc("listtransactions", acct, 100000, 0, True)
                              if e.get("txid") == txid and e.get("category") == "send"])
    return {"notes": {k: g[k] for k in NOTES if k in g},
            "send entries' account": sorted({d.get("account") for d in g.get("details", [])
                                             if d.get("category") == "send"}),
            "send entries in listtransactions \"\"": sends(""),
            "send entries in listtransactions \"acct1\"": sends("acct1")}


def makers(when):
    """Each kind of send as its maker keeps it: C's own against I's own"""
    for kind in sorted(set(MADE.values())):
        tc = next((t for t, k in MADE.items() if k == kind and LABELS[t].endswith("by C")), None)
        ti = next((t for t, k in MADE.items() if k == kind and LABELS[t].endswith("by I")), None)
        if tc and ti:
            diff_row(f"{when}: owner: {kind}, as its maker keeps it", obj_diffs(own_view(C, tc), own_view(I, ti)))


def shows(when, txid):
    """What each twin shows for one transaction (printed, not compared: the
    snapshot compares it)"""
    for n in (C, I):
        g = n.call("gettransaction", txid, True)
        if g[0] != "ok":
            v = list(g[1:])
        else:
            g = g[1]
            v = {"confirmations": g.get("confirmations"), "amount": g.get("amount"), "fee": g.get("fee"),
                 "generated": g.get("generated"), "blockhash": bool(g.get("blockhash")),
                 "walletconflicts": len(g.get("walletconflicts", [])),
                 "details": [[d.get("category"), d.get("amount"), d.get("vout")] for d in g.get("details", [])],
                 "in listtransactions": sorted({e.get("category") for e in n.rpc("listtransactions", "*", 100000, 0, True)
                                                if e.get("txid") == txid})}
        print(f"# shows, {when}: {name_of(txid)}: {'divid' if n is C else 'irondivid'} {show(v, 400)}", flush=True)


def tip():
    return S.rpc("getbestblockhash")


# --- coinbases ---------------------------------------------------------------------------
mine(2)
mine(3, by=C)
for h in (3, 4, 5):
    label(C.rpc("getblock", C.rpc("getblockhash", h))["tx"][0], f"C's coinbase {h}")
snapshot("C's coinbases, immature")
mine(95)
snapshot("C's coinbases, mature")

# --- addresses ---------------------------------------------------------------------------
RECV = shared_address(C, I)
ACCT = shared_address(C, I, "acct1")
SELF = shared_address(C, I)
SELF2 = shared_address(C, I)
STAKE1 = shared_address(C, I)
STAKE2 = shared_address(C, I)
STAKE3 = shared_address(C, I)
OWN = shared_address(C, I)
DEST = shared_address(C, I)
MGR = shared_address(M, N)
VAULT = f"{OWN}:{MGR}"
# The regtest treasury and charity payees (BlockIncentivesPopulator.cpp:27-36),
# watched by the twins: a treasury block pays them in S's coinstake
for n in (C, I):
    n.rpc("importaddress", "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd", "treasury", False)
    n.rpc("importaddress", "y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5", "charity", False)
OUT1, OUT2, OUT3 = (S.rpc("getnewaddress") for _ in range(3))

# --- receives ----------------------------------------------------------------------------
mark = tip()
for k in range(8):
    seen(label(S.rpc("sendtoaddress", RECV, 100), f"receive to RECV ({k + 1} of 8)"))
for k in range(4):
    seen(label(S.rpc("sendtoaddress", ACCT, 20), f"receive to acct1 ({k + 1} of 4)"))
seen(label(S.rpc("sendmany", "", {RECV: 7, ACCT: 8, OUT1: 9}), "receive by S's sendmany"))
snapshot("receives in the mempool", mark)
mine(1)
snapshot("receives mined", mark)

# --- sends -------------------------------------------------------------------------------
mark = tip()
# First: a send of another kind may spend acct1's coins, which takes them off its balance
# Each from a coin of its own of acct1's (the others locked), as a send's
# change is no coin of the account's
acct_coins = sorted(coins_at(C, ACCT))
for k, n in enumerate((C, I)):
    seen(made(n, with_coins(n, [acct_coins[2 * k]], lambda: n.rpc("sendfrom", "acct1", OUT3, 3)), "sendfrom acct1"))
    seen(made(n, with_coins(n, [acct_coins[2 * k + 1]], lambda: n.rpc("sendmany", "acct1", {OUT1: 0.5})),
              "sendmany from acct1"))
for n in (C, I):
    seen(made(n, n.rpc("sendtoaddress", OUT1, 10), "send"))
    seen(made(n, n.rpc("sendtoaddress", SELF, 5), "send to self"))
    seen(made(n, n.rpc("sendtoaddress", OUT2, 1.25, "metadata", "a comment", "a comment-to"), "send with comments"))
    seen(made(n, n.rpc("sendmany", "", {OUT2: 1, SELF2: 2}), "sendmany (one payee is C)"))
    seen(made(n, n.rpc("sendmany", "", {OUT2: 1.5, OUT3: 2.5}, "a comment"), "sendmany"))
snapshot("sends in the mempool", mark)
mine(1)
snapshot("sends mined", mark)

# --- coins to stake, and X's coins -----------------------------------------------------------
# Each reaches every mempool before the next is sent: a wallet lists its
# transactions in the order it first heard of them (nOrderPos), and relay
# hands transactions sent together to each node in an order of its own
seen(label(S.rpc("sendtoaddress", STAKE1, 21000), "receive to STAKE1 (one coin of 21000)"))
for k in range(3):
    seen(label(S.rpc("sendtoaddress", STAKE2, 1000), f"receive to STAKE2 ({k + 1} of 3 coins of 1000)"))
seen(label(S.rpc("sendtoaddress", STAKE3, 12000), "receive to STAKE3"))
seen(label(S.rpc("sendtoaddress", OWN, 5000), "receive to OWN"))
# X stakes four blocks in a row: a coin each, at addresses of their own, as
# coins of one address are staked together
for _ in range(5):
    S.rpc("sendtoaddress", X.rpc("getnewaddress"), 5000)
mine(25)

# --- stakes ------------------------------------------------------------------------------
# A coin over -stakesplitthreshold (20000) is split in two (PoSTransactionCreator.cpp:281-300)
SWEEP = shared_address(C, I)
ordinary_next()
sweep(C, coins_at(C, STAKE1) | coins_at(C, STAKE2) | coins_at(C, STAKE3) | coins_at(C, OWN), SWEEP)
ordinary_next()
mark = tip()
h = stake_only(C, coins_at(C, STAKE1))
label(coinstake_at(h), f"C's stake of the coin of 21000 (split), block {h}")
snapshot("C staked a coin of 21000", mark)
# Coins of one address under half of the threshold are combined
ordinary_next()
mark = tip()
h = stake_only(C, coins_at(C, STAKE2))
label(coinstake_at(h), f"C's stake of three coins of 1000 (combined), block {h}")
snapshot("C staked three coins of 1000", mark)

# --- a lottery block paying C ------------------------------------------------------------
# C staked in this cycle, so S's next lottery block pays it
while not (S.rpc("getblockcount") + 1 >= 101 and (S.rpc("getblockcount") + 1) % 10 == 0
           and (S.rpc("getblockcount") + 1) % 50 != 0):
    block_by(S)
mark = tip()
h = block_by(S)
label(coinstake_at(h), f"S's lottery block {h}")
snapshot(f"S's lottery block", mark)
# The stakes mature
mine(21)
snapshot("the stakes matured")

# --- a vault -----------------------------------------------------------------------------
mark = tip()
# C's coin of STAKE3 is kept for the orphaned stake: the sends of C's own choosing below leave it alone
reply = sparing(C, coins_at(C, STAKE3), lambda: C.rpc("fundvault", VAULT, 3000))
fund = label(reply["txhash"] if isinstance(reply, dict) else reply, "fundvault by C")
seen(fund)
snapshot("vault funded, in the mempool", mark)
mine(1)
for n in (M, N):
    n.rpc("addvault", VAULT, fund)
snapshot("vault funded, mined, added by the managers", mark)
mine(20)
ordinary_next()
mark = tip()
h = block_by(M)
label(coinstake_at(h), f"M's stake of the vault, block {h}")
snapshot("the manager staked the vault", mark)
# The vault's coin is now that coinstake's output: it matures first
mine(21)
snapshot("the vault's stake matured")
mark = tip()
r = C.rpc("reclaimvaultfunds", DEST, 500)
seen(label(r["txhash"] if isinstance(r, dict) else r, "reclaimvaultfunds by C"))
snapshot("vault reclaim in the mempool", mark)
mine(1)
snapshot("vault reclaim mined", mark)

# --- a treasury block --------------------------------------------------------------------
while not (S.rpc("getblockcount") + 1 >= 102 and (S.rpc("getblockcount") + 1) % 50 == 0):
    block_by(S)
mark = tip()
h = block_by(S)
label(coinstake_at(h), f"S's treasury block {h}")
cs = S.rpc("getrawtransaction", coinstake_at(h), 1)
print(f"# treasury block {h} pays: " + show([[v["value"], v["scriptPubKey"].get("addresses")] for v in cs["vout"]], 400),
      flush=True)
for n in (C, I):
    v = n.rpc("validateaddress", "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd")
    print(f"# {n.name} validateaddress <treasury>: " + show({k: v.get(k) for k in ("isvalid", "ismine", "iswatchonly",
                                                                                  "account")}), flush=True)
snapshot("S's treasury block", mark)

# --- a send conflicted by a double spend ---------------------------------------------------
mark = tip()
A = seen(made(C, sparing(C, coins_at(C, STAKE3), lambda: C.rpc("sendtoaddress", OUT1, 7)), "send, double-spent"))
raw = C.rpc("getrawtransaction", A, 1)
ins = [{"txid": v["txid"], "vout": v["vout"]} for v in raw["vin"]]
total = 0
for v in raw["vin"]:
    total += C.rpc("getrawtransaction", v["txid"], 1)["vout"][v["vout"]]["value"]
B_hex = C.rpc("signrawtransaction", C.rpc("createrawtransaction", ins, {SELF: round(total - 0.01, 8)}))["hex"]
B = label(C.rpc("decoderawtransaction", B_hex)["txid"], "the double spend (C to itself), mined")
bare_block([B_hex])
snapshot("a send conflicted by a double spend", mark)
shows("conflicted", A)
shows("conflicted", B)

# --- a stake orphaned by a reorganisation ------------------------------------------------
# X is cut off (its peers forgotten, no connect), stakes three blocks; C stakes
# one on the others' chain; X joins and its longer branch takes over
X.stop()
for f in ("peers.dat", "banlist.dat"):
    try:
        os.remove(os.path.join(X.dir, "regtest", f))
    except OSError:
        pass
X.set_conf("connect", "0")
JOINED = [S, C, I, M, N]
if X.start()[0] != "up":
    raise RuntimeError(f"X did not start again: {X.tail()}")
ordinary_next()
fork = S.rpc("getblockcount")
if X.rpc("getblockcount") != fork:
    raise RuntimeError(f"X is at {X.rpc('getblockcount')}, the others at {fork}")
for _ in range(3):
    block_by(X)
mark = tip()
sweep(C, coins_at(C, STAKE3), SWEEP)
h = stake_only(C, coins_at(C, STAKE3))
ORPHAN = label(coinstake_at(h), f"C's stake orphaned by the reorganisation, block {h}")
snapshot("C's stake before the reorganisation", mark)
X.rpc("addnode", f"{HOST}:{S.p2p}", "onetry")
JOINED = list(NODES)
if not synced():
    raise RuntimeError("the reorganisation did not happen")
snapshot("C's stake orphaned", mark)
shows("orphaned", ORPHAN)

# --- a send never mined ------------------------------------------------------------------
# From here S mines only blocks that leave the mempool alone
mark = tip()
T = seen(made(C, C.rpc("sendtoaddress", OUT2, 4), "send, never mined"))
snapshot("a send never mined, at once", mark)
bare_block()
bare_block()
snapshot("a send never mined, two blocks later", mark)
shows("two blocks later", T)
for n in (C, I):
    n.stop()
for n in (C, I):
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start again: {n.tail()}")
synced()
wait_for(lambda: all(T in n.rpc("getrawmempool") for n in (C, I)), 60)
snapshot("after a restart of the twins", mark)
shows("after a restart", T)
shows("after a restart", ORPHAN)
shows("after a restart", A)
for t in LABELS:
    shows("at the end", t)

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
