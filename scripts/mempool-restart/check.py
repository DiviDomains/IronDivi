#!/usr/bin/env python3
"""A wallet's unconfirmed sends across a restart, Divi Core divid and
irondivid side by side: both follow one divid miner on regtest. Each sends a
chain of unconfirmed transactions, and a send whose coin the miner spends
while the node is down; then each is stopped cleanly or killed, started
again, and its mempool and wallet replies compared.

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
import time
import urllib.error
import urllib.request
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
START_TIMEOUT = 120
CHAIN = int(os.environ.get("MEMPOOL_RESTART_CHAIN", "3"))
T0 = time.time()


def note(text):
    print(f"# [{time.time() - T0:6.1f}s] {text}", flush=True)


# --- rows ------------------------------------------------------------------------------

# name -> (reason, shape(core, iron)); none so far
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def matches(shape, core, iron):
    try:
        return bool(shape(core, iron))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def row(name, core, iron):
    global fails
    if INJECT and name == INJECT:
        iron = ["changed by MEMPOOL_RESTART_INJECT", iron]
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
    print(f"{word:<5}  {name}  divid={json.dumps(core, default=str)}  "
          f"irondivid={json.dumps(iron, default=str)}{why}"[:900], flush=True)


INJECT = os.environ.get("MEMPOOL_RESTART_INJECT", "")


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
        self.user = f"mr{index}"
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
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, stdout=out,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                                     work=WORK)
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




# --- set-up ----------------------------------------------------------------------------

M = Node("miner", DIVID, 0)
C = Node("divid", DIVID, 1)
I = Node("irondivid", IRONDIVID, 2)
FOLLOWERS = (C, I)
PEER = [f"connect={HOST}:{PORT_BASE}"]
ALONE = [f"connect={HOST}:{PORT_BASE + 49}"]  # nothing listens there

M.start(["listen=1"])
mine(M, 110)
for n in FOLLOWERS:
    n.start(PEER)
    # Three coins of 100 each; old enough by the end of the set-up
    M.rpc("sendmany", "", {n.rpc("getnewaddress"): 100 for _ in range(3)})
mine(M, 25)
if not in_step(FOLLOWERS):
    raise RuntimeError("the followers did not follow the miner")
note(f"set-up: chain {M.rpc('getblockcount')} blocks")
for n in FOLLOWERS:
    n.stop()
M.stop()
for n in (M, C, I):
    shutil.copytree(n.dir, n.dir + ".template", symlinks=True)


def fresh(followers_extra):
    for n in (M, C, I):
        n.stop()
        shutil.rmtree(n.dir)
        shutil.copytree(n.dir + ".template", n.dir, symlinks=True)
    M.start(["listen=1"])
    for n in FOLLOWERS:
        n.start(followers_extra)
    if followers_extra == PEER:
        if not wait_for(lambda: all(n.rpc("getconnectioncount") >= 1 for n in FOLLOWERS), 60):
            raise RuntimeError("the followers did not connect to the miner")
        if not in_step(FOLLOWERS):
            raise RuntimeError("the followers are not at the miner's tip")


def one_coin(n):
    """Lock every coin of n's wallet but one, so its sends form a chain; that
    coin (txid, vout, address)"""
    coins = sorted(n.rpc("listunspent"), key=lambda c: (c["txid"], c["vout"]))
    keep = coins[0]
    n.rpc("lockunspent", False, [{"txid": c["txid"], "vout": c["vout"]} for c in coins[1:]])
    return keep


def sends(n, count):
    """`count` sends of 1 DIVI to the miner, each spending the change of the
    one before: the first by sendtoaddress, the others made raw, signed by the
    wallet and sent with sendrawtransaction (divid's coin selection does not
    take unconfirmed change)"""
    out = [n.rpc("sendtoaddress", M.rpc("getnewaddress"), 1)]
    for _ in range(count - 1):
        prev = n.rpc("getrawtransaction", out[-1], 1)
        change = next(o for o in prev["vout"]
                      if n.rpc("validateaddress", o["scriptPubKey"]["addresses"][0]).get("ismine"))
        rest = Decimal(str(change["value"])) - 1 - Decimal("0.01")
        raw = n.rpc("createrawtransaction", [{"txid": out[-1], "vout": change["n"]}],
                    {M.rpc("getnewaddress"): 1, n.rpc("getnewaddress"): float(rest)})
        signed = n.rpc("signrawtransaction", raw)
        if not signed.get("complete"):
            raise RuntimeError(f"{n.name} could not sign its chained send")
        out.append(n.rpc("sendrawtransaction", signed["hex"]))
    return out


def chained(n, txids):
    """Each send spends an output of the one before it"""
    for parent, child in zip(txids, txids[1:]):
        vin = n.rpc("getrawtransaction", child, 1)["vin"]
        if parent not in [i["txid"] for i in vin]:
            return False
    return True


def wallet_view(n, txids):
    """What the wallet says of each send, by position in the chain"""
    out = []
    for k, t in enumerate(txids):
        r = n.call("gettransaction", t)
        if r[0] != "ok":
            out.append({"send": k, "gettransaction": r[:2]})
            continue
        g = r[1]
        out.append({"send": k, "confirmations": g.get("confirmations"), "amount": str(g.get("amount")),
                    "fee": str(g.get("fee")), "in mempool": t in n.mempool()})
    return out


def listed(n, txids):
    """The listtransactions entries of the sends: (position, category, confirmations)"""
    entries = n.rpc("listtransactions", "*", 1000)
    pos = {t: k for k, t in enumerate(txids)}
    return sorted((pos[e["txid"]], e.get("category"), e.get("confirmations"))
                  for e in entries if e.get("txid") in pos)


def times(n, txids):
    return [{k: n.rpc("gettransaction", t).get(k) for k in ("time", "timereceived")} for t in txids]


def halt(n, how):
    if how == "stop":
        n.stop()
    else:
        n.kill()


# --- 1. a chain of unconfirmed sends across a clean stop and a kill --------------------------

def chain_case(how):
    word = "clean stop" if how == "stop" else "kill"
    fresh(PEER)
    own = {}
    for n in FOLLOWERS:
        one_coin(n)
        own[n.name] = sends(n, CHAIN)
    every = own["divid"] + own["irondivid"]
    if not all(wait_for(lambda n=n: set(every) <= n.mempool(), 120) for n in (M, C, I)):
        note("not every send reached every mempool")
    row(f"chain ({word}): the {CHAIN} sends spend each other's change", chained(C, own["divid"]),
        chained(I, own["irondivid"]))
    before = {n.name: (wallet_view(n, own[n.name]), listed(n, own[n.name]), times(n, own[n.name]),
                       str(n.rpc("getbalance"))) for n in FOLLOWERS}
    row(f"chain ({word}): before, gettransaction", before["divid"][0], before["irondivid"][0])
    row(f"chain ({word}): before, listtransactions", before["divid"][1], before["irondivid"][1])
    row(f"chain ({word}): before, getbalance", before["divid"][3], before["irondivid"][3])

    for n in FOLLOWERS:
        halt(n, how)
        n.start(ALONE)
    # Both put their wallet's sends back at start; give a moment to settle
    time.sleep(5)

    def pool(n):
        other = own["irondivid" if n is C else "divid"]
        now = n.mempool()
        return {"own sends": [k for k, t in enumerate(own[n.name]) if t in now],
                "the other follower's sends": [k for k, t in enumerate(other) if t in now],
                "others": len(now - set(every))}

    row(f"chain ({word}) and a start with no peer: the mempool", pool(C), pool(I))
    row(f"chain ({word}) and a start with no peer: gettransaction", wallet_view(C, own["divid"]),
        wallet_view(I, own["irondivid"]))
    row(f"chain ({word}) and a start with no peer: listtransactions", listed(C, own["divid"]),
        listed(I, own["irondivid"]))
    row(f"chain ({word}) and a start with no peer: time and timereceived as before",
        times(C, own["divid"]) == before["divid"][2], times(I, own["irondivid"]) == before["irondivid"][2])
    row(f"chain ({word}) and a start with no peer: getbalance as before",
        str(C.rpc("getbalance")) == before["divid"][3], str(I.rpc("getbalance")) == before["irondivid"][3])
    row(f"chain ({word}) and a start with no peer: getmempoolinfo size",
        C.rpc("getmempoolinfo")["size"], I.rpc("getmempoolinfo")["size"])

    # Back with the miner, which mines its own mempool (it holds every send)
    for n in FOLLOWERS:
        n.stop()
        n.start(PEER)
    if not wait_for(lambda: all(n.rpc("getconnectioncount") >= 1 for n in FOLLOWERS), 60):
        raise RuntimeError("the followers did not connect to the miner")
    mine(M, 1)
    in_step(FOLLOWERS)
    time.sleep(2)
    row(f"chain ({word}), then a block of the miner: gettransaction", wallet_view(C, own["divid"]),
        wallet_view(I, own["irondivid"]))
    row(f"chain ({word}), then a block of the miner: the mempool size",
        C.rpc("getmempoolinfo")["size"], I.rpc("getmempoolinfo")["size"])


chain_case("stop")
chain_case("kill")


# --- 2. a send whose coin is spent elsewhere while the node is down -------------------------

def conflict_case(how):
    word = "clean stop" if how == "stop" else "kill"
    # Alone, so the miner never hears of the sends
    fresh(ALONE)
    own, coin = {}, {}
    for n in FOLLOWERS:
        coin[n.name] = one_coin(n)
        # The miner gets the coin's key (a throwaway of this run), never printed
        M.rpc("importprivkey", n.rpc("dumpprivkey", coin[n.name]["address"]), "", False)
        own[n.name] = sends(n, 2)
    before = {n.name: str(n.rpc("getbalance")) for n in FOLLOWERS}
    row(f"conflict ({word}): before, the two sends in the mempool",
        [t in C.mempool() for t in own["divid"]], [t in I.mempool() for t in own["irondivid"]])
    for n in FOLLOWERS:
        halt(n, how)
    # The miner spends each coin to itself and mines it
    for n in FOLLOWERS:
        c = coin[n.name]
        raw = M.rpc("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]}],
                    {M.rpc("getnewaddress"): float(Decimal(str(c["amount"])) - Decimal("0.01"))})
        out = M.rpc("signrawtransaction", raw)
        if not out.get("complete"):
            raise RuntimeError("the miner could not sign the coin")
        M.rpc("sendrawtransaction", out["hex"])
    mine(M, 1)
    for n in FOLLOWERS:
        n.start(PEER)
    if not in_step(FOLLOWERS):
        raise RuntimeError("the followers did not follow the miner")
    time.sleep(3)
    row(f"conflict ({word}), then the miner's block: gettransaction", wallet_view(C, own["divid"]),
        wallet_view(I, own["irondivid"]))
    row(f"conflict ({word}), then the miner's block: listtransactions", listed(C, own["divid"]),
        listed(I, own["irondivid"]))
    row(f"conflict ({word}), then the miner's block: getbalance", str(C.rpc("getbalance")),
        str(I.rpc("getbalance")))
    row(f"conflict ({word}), then the miner's block: getbalance with the sends still unconfirmed, before the stop",
        before["divid"], before["irondivid"])
    row(f"conflict ({word}), then the miner's block: listunspent count",
        len(C.rpc("listunspent")), len(I.rpc("listunspent")))
    # Another start: the wallet offers the sends again, and the mempool refuses them
    for n in FOLLOWERS:
        n.stop()
        n.start(ALONE)
    time.sleep(5)
    row(f"conflict ({word}), and another start: gettransaction", wallet_view(C, own["divid"]),
        wallet_view(I, own["irondivid"]))
    row(f"conflict ({word}), and another start: the mempool size",
        C.rpc("getmempoolinfo")["size"], I.rpc("getmempoolinfo")["size"])


conflict_case("stop")
conflict_case("kill")

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
for n in (C, I, M):
    n.stop()
sys.exit(min(fails, 254))
