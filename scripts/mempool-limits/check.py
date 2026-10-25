#!/usr/bin/env python3
"""Mempool limits and what survives a restart, Divi Core divid and irondivid
side by side: both follow one divid miner on regtest, which relays them the
same transactions; the script reaches each limit on purpose and compares the
answers, the mempool contents and each node's next block.

Rows print PASS (same as divid), KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory and
stops the nodes.
"""

import base64
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from decimal import Decimal

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
START_TIMEOUT = 120
CHAIN = int(os.environ.get("MEMPOOL_LIMITS_CHAIN", "50"))
FANOUT = int(os.environ.get("MEMPOOL_LIMITS_FANOUT", "200"))
T0 = time.time()


def note(text):
    print(f"# [{time.time() - T0:6.1f}s] {text}", flush=True)


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


KNOWN = {
    "getmempoolinfo keys": (
        "irondivid adds usage, maxmempool and mempoolminfee (docs/divid-differences.md R13; KNOWN in "
        "scripts/net-counters too); divid gives size and bytes only (rpcblockchain.cpp:569-574)",
        pair(["bytes", "size"], ["bytes", "maxmempool", "mempoolminfee", "size", "usage"])),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def matches(shape, core, iron):
    try:
        return bool(shape(core, iron))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def row(name, core, iron):
    global fails
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, why = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif matches(shape, core, iron):
            word, why = "KNOWN", "  [known: " + reason + "]"
        else:
            word, why = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, why = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{why}"[:900], flush=True)


def both(name, fn):
    """A row of fn(node) on each follower"""
    row(name, fn(C), fn(I))


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_tb(tb)
    print(f"FAIL   setup: {kind.__name__}: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- nodes -----------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.password = secrets.token_hex(16)
        self.user = f"ml{index}"
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.dir = os.path.join(WORK, name)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra):
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
                 f"rpcpassword={self.password}", "rpcallowip=127.0.0.0/8", f"rpcbind={HOST}", f"bind={HOST}",
                 "server=1", "daemon=0", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
                 "printtoconsole=0"] + list(extra)
        os.makedirs(self.dir, exist_ok=True)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self, extra=()):
        self.write_conf(extra)
        self.starts += 1
        out = open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, stdout=out,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited with {self.proc.returncode} at start")
            if self.call("getblockcount", timeout=5)[0] == "ok":
                return
            time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s")

    def call(self, method, *params, timeout=120):
        """('ok', result), ('err', code, message) or ('down',)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                reply = json.loads(r.read(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=Decimal)
            except ValueError:
                return ("err", e.code, "")
        except (urllib.error.URLError, OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out}")
        return out[1]

    def stop(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        self.call("stop", timeout=30)
        try:
            self.proc.wait(120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def kill(self):
        if self.proc is not None and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()

    def mempool(self):
        return set(self.rpc("getrawmempool"))


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


def mine(node, n=1):
    for _ in range(n):
        if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"{node.name} could not mine")


def in_step(nodes, secs=120):
    """Every node at the miner's tip"""
    tip = M.rpc("getbestblockhash")
    return all(wait_for(lambda n=n: n.rpc("getbestblockhash") == tip, secs) for n in nodes)


def amount(x):
    return f"{Decimal(x):.8f}"


# --- transactions, made and signed by the miner -------------------------------------------

def coin_of(txid, address):
    raw = M.rpc("getrawtransaction", txid, 1)
    for o in raw["vout"]:
        if o["scriptPubKey"].get("addresses") == [address]:
            return {"txid": txid, "vout": o["n"], "value": Decimal(o["value"]),
                    "scriptPubKey": o["scriptPubKey"]["hex"]}
    raise RuntimeError(f"no output to {address} in {txid}")


def signed(inputs, outputs):
    """A raw transaction of the miner's coins, signed by the miner. `inputs`
    carry their scriptPubKey, so unconfirmed parents can be signed for."""
    raw = M.rpc("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]} for c in inputs],
                {a: float(v) for a, v in outputs.items()})
    prev = [{"txid": c["txid"], "vout": c["vout"], "scriptPubKey": c["scriptPubKey"]} for c in inputs]
    out = M.rpc("signrawtransaction", raw, prev)
    if not out.get("complete"):
        raise RuntimeError("signrawtransaction incomplete")
    return out["hex"]


def send_from_miner(hexes):
    """sendrawtransaction on the miner (relayed to both followers); the txids"""
    return [M.rpc("sendrawtransaction", h) for h in hexes]


def reach_both(txids, secs=120):
    want = set(txids)
    ok = all(wait_for(lambda n=n: want <= n.mempool(), secs) for n in (C, I))
    if not ok:
        note(f"not every transaction reached both: divid lacks {len(want - C.mempool())}, "
             f"irondivid lacks {len(want - I.mempool())}")
    return ok


# --- set-up ----------------------------------------------------------------------------

M = Node("miner", DIVID, 0)
C = Node("divid", DIVID, 1)
I = Node("irondivid", IRONDIVID, 2)
PEER = [f"connect={HOST}:{PORT_BASE}"]
ALONE = [f"connect={HOST}:{PORT_BASE + 49}"]  # nothing listens there

M.start(["listen=1"])
mine(M, 110)
for n in (C, I):
    n.start(PEER)
    # Coins of their own to stake and to send, old enough by the end of the set-up
    addresses = {n.rpc("getnewaddress"): 100 for _ in range(10)}
    M.rpc("sendmany", "", addresses)
OLD = []  # the miner's old coins, for transactions it signs
for _ in range(40):
    a = M.rpc("getnewaddress")
    OLD.append(coin_of(M.rpc("sendtoaddress", a, 100), a))
mine(M, 25)
if not in_step([C, I]):
    raise RuntimeError("the followers did not follow the miner")
SETUP_HEIGHT = M.rpc("getblockcount")
for n in (C, I):
    n.stop()
M.stop()
for n in (M, C, I):
    shutil.copytree(n.dir, n.dir + ".template", symlinks=True)
note(f"set-up: chain {SETUP_HEIGHT} blocks")


def fresh():
    for n in (M, C, I):
        n.stop()
        shutil.rmtree(n.dir)
        shutil.copytree(n.dir + ".template", n.dir, symlinks=True)
    M.start(["listen=1"])
    for n in (C, I):
        n.start(PEER)
    if not wait_for(lambda: all(n.rpc("getconnectioncount") >= 1 for n in (C, I)), 60):
        raise RuntimeError("the followers did not connect to the miner")
    if not in_step([C, I]):
        raise RuntimeError("the followers are not at the miner's tip")


def change_to():
    return M.rpc("getnewaddress")


# --- 1. what the mempool shows for a transaction -------------------------------------------

fresh()
coins = iter(OLD)
paying = next(coins)
t_pay_hex = signed([paying], {change_to(): paying["value"] - Decimal("0.001")})
free = next(coins)
t_free_hex = signed([free], {change_to(): free["value"]})
t_pay, t_free = send_from_miner([t_pay_hex, t_free_hex])
reach_both([t_pay, t_free])
child_addr = change_to()
pay_out = coin_of(t_pay, M.rpc("decoderawtransaction", t_pay_hex)["vout"][0]["scriptPubKey"]["addresses"][0])
t_child_hex = signed([pay_out], {child_addr: pay_out["value"] - Decimal("0.001")})
(t_child,) = send_from_miner([t_child_hex])
reach_both([t_child])

ROLE = {t_pay: "paying", t_free: "free (old coin)", t_child: "child of the paying one"}


def verbose(n):
    out = {}
    for txid, e in n.rpc("getrawmempool", True).items():
        if txid not in ROLE:
            continue
        e = dict(e)
        e["time within 60 s"] = abs(int(e.pop("time")) - time.time()) < 60
        e["fee"] = amount(e["fee"])
        for k in ("startingpriority", "currentpriority"):
            if k in e:
                e[k] = str(Decimal(e[k]).quantize(Decimal(1)))
        e["depends"] = [ROLE.get(d, d) for d in e.get("depends", [])]
        e["keys in order"] = list(e)
        out[ROLE[txid]] = e
    return out


core_v, iron_v = verbose(C), verbose(I)
for role in ROLE.values():
    c, i = core_v.get(role, {}), iron_v.get(role, {})
    for k in sorted(set(c) | set(i)):
        row(f"getrawmempool true: {role}: {k}", c.get(k, "<none>"), i.get(k, "<none>"))
both("getrawmempool: the three", lambda n: sorted(ROLE[t] for t in n.mempool() if t in ROLE))
both("getmempoolinfo size and bytes", lambda n: [n.rpc("getmempoolinfo")[k] for k in ("size", "bytes")])
both("getmempoolinfo keys", lambda n: sorted(n.rpc("getmempoolinfo")))

# sendrawtransaction of what the mempool holds: the txid again (divid relays it
# again, rpcrawtransaction.cpp:862-899), with and without allowhighfees
both("sendrawtransaction of a mempool transaction", lambda n: n.call("sendrawtransaction", t_pay_hex))
both("sendrawtransaction of a mempool transaction, allowhighfees", lambda n: n.call("sendrawtransaction",
                                                                                    t_pay_hex, True))
# The same coin spent again: -25 with no text (MempoolConsensus.cpp:304-314)
other = signed([paying], {change_to(): paying["value"] - Decimal("0.002")})
both("sendrawtransaction of a second spend of a mempool coin", lambda n: n.call("sendrawtransaction", other))

# The clock 15 days on: divid has no expiry (README), the transactions stay
for n in (C, I):
    n.rpc("setmocktime", int(time.time()) + 15 * 86400)
time.sleep(3)
both("15 days later (setmocktime): the three still in the mempool",
     lambda n: sorted(ROLE[t] for t in n.mempool() if t in ROLE))
for n in (C, I):
    n.rpc("setmocktime", 0)


# --- 2. a long chain and a wide fan-out of unconfirmed transactions ------------------------

prev = next(coins)
chain = []
for k in range(CHAIN):
    addr = change_to()
    h = signed([prev], {addr: prev["value"] - Decimal("0.001")})
    (txid,) = send_from_miner([h])
    chain.append(txid)
    prev = {"txid": txid, "vout": 0, "value": prev["value"] - Decimal("0.001"),
            "scriptPubKey": M.rpc("decoderawtransaction", h)["vout"][0]["scriptPubKey"]["hex"]}
reach_both(chain)
both(f"a chain of {CHAIN} unconfirmed transactions: how many are in the mempool",
     lambda n: len(set(chain) & n.mempool()))
both("the chain's last transaction: depends on the one before",
     lambda n: n.rpc("getrawmempool", True)[chain[-1]].get("depends") == [chain[-2]])

wide = next(coins)
outs = {change_to(): Decimal("0.2") for _ in range(FANOUT)}
fan_hex = signed([wide], dict(outs, **{change_to(): wide["value"] - Decimal("0.2") * FANOUT - Decimal("0.01")}))
(fan,) = send_from_miner([fan_hex])
fan_vouts = M.rpc("decoderawtransaction", fan_hex)["vout"]
kids = []
for o in fan_vouts:
    if Decimal(o["value"]) != Decimal("0.2"):
        continue
    c = {"txid": fan, "vout": o["n"], "value": Decimal("0.2"), "scriptPubKey": o["scriptPubKey"]["hex"]}
    kids.append(signed([c], {change_to(): Decimal("0.199")}))
kid_ids = send_from_miner(kids)
reach_both([fan] + kid_ids, 240)
both(f"a transaction of {FANOUT} outputs and {FANOUT} spends of them: how many are in the mempool",
     lambda n: len(set([fan] + kid_ids) & n.mempool()))
both("getmempoolinfo size and bytes, everything in", lambda n: [n.rpc("getmempoolinfo")[k] for k in ("size",
                                                                                                    "bytes")])

# --- 3. the next block: the miner goes, each follower mines from its own mempool -----------

M.stop()
pool = {n.name: n.mempool() for n in (C, I)}
row("the mempools are the same before each mines", sorted(pool["divid"]), sorted(pool["irondivid"]))


def next_block(n):
    before = n.mempool()
    mine(n, 1)
    block = n.rpc("getblock", n.rpc("getbestblockhash"))
    txs = set(block["tx"][1:])  # after the coinbase
    return {"taken from the mempool": len(txs & before), "left in the mempool": len(n.mempool()),
            "transactions not from the mempool": len(txs - before), "ids": txs & before}


results = {}


def run_next(n):
    results[n.name] = next_block(n)


threads = [threading.Thread(target=run_next, args=(n,)) for n in (C, I)]
for t in threads:
    t.start()
for t in threads:
    t.join()
c, i = results.get("divid", {}), results.get("irondivid", {})
for k in ("taken from the mempool", "left in the mempool"):
    row(f"next block: {k}", c.get(k), i.get(k))
row("next block: the same transactions", True, c.get("ids") == i.get("ids"))
note(f"next block: transactions not from the mempool (coinstake): divid {c.get('transactions not from the mempool')}, "
     f"irondivid {i.get('transactions not from the mempool')}")


# --- 4. a restart: clean stop, and kill ----------------------------------------------------

def restart_case(how):
    fresh()
    coin = OLD[-1 - (0 if how == "stop" else 1)]
    relayed_hex = signed([coin], {change_to(): coin["value"] - Decimal("0.001")})
    (relayed,) = send_from_miner([relayed_hex])
    own = {}
    for n in (C, I):
        own[n.name] = n.rpc("sendtoaddress", change_to(), 1)
    reach_both([relayed] + list(own.values()), 120)
    before = {n.name: n.mempool() for n in (C, I)}
    for n in (C, I):
        if how == "stop":
            n.stop()
        else:
            n.kill()
        n.start(ALONE)
    time.sleep(5)

    def kept(n):
        now = n.mempool()
        other = "irondivid" if n is C else "divid"
        roles = {relayed: "the miner's relayed transaction", own[n.name]: "its own wallet send",
                 own[other]: "the other follower's wallet send"}
        return sorted(roles[t] for t in now if t in roles) + [f"{len(now - set(roles))} others"]

    row(f"after a {'clean stop' if how == 'stop' else 'kill'} and start: what the mempool holds", kept(C), kept(I))
    row(f"after a {'clean stop' if how == 'stop' else 'kill'}: before, the mempools held the same",
        sorted(before["divid"]), sorted(before["irondivid"]))


restart_case("stop")
restart_case("kill")

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
for n in (C, I, M):
    n.stop()
sys.exit(min(fails, 254))
