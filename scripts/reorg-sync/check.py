#!/usr/bin/env python3
"""Reorganisations across a split network of Divi Core divid and irondivid on
regtest. Two sides, each a divid bridge with a divid and an irondivid behind it
(dialling it); the sides are split by a restart (no node dials across) and
joined by `addnode onetry` from one bridge to the other. The divid and the
irondivid behind the same bridge see the network alike, so each is compared
with the other. Each scenario builds competing chains on the two sides,
joins them, and compares what every node then shows: the tip, getchaintips, the
mempool, and one wallet (divid's, restored into both irondivid) through
gettransaction, getbalance and listsinceblock; then invalidateblock and
reconsiderblock. Each row prints PASS (irondivid as divid), KNOWN (a difference
listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("REORG_SYNC_INJECT", "")
# For looking into a difference: both replies of every row that differs
DUMP = os.environ.get("REORG_SYNC_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 120
SYNC_TIMEOUT = 120
# A node that cannot bind its ports is started again on new ones, this often
BIND_RETRIES = 5

# Differences listed in README.md with divid's source line, one per row name:
# (reason, shape). shape takes the two raw outcomes and is true only for the
# difference described, so a KNOWN row that matches divid, or differs in another
# way, is a FAIL.
LAST_DIFF = set()


def only(*paths):
    """Both are results, and the fields that differ are some of `paths`"""
    return lambda c, i: c[0] == i[0] == "ok" and LAST_DIFF and LAST_DIFF <= set(paths)


KNOWN = {
}

fails = 0


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    if DUMP and not same and raw is not None:
        os.makedirs(DUMP, exist_ok=True)
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:90]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"row": name, "divid": raw[0], "irondivid": raw[1]}, f, indent=1, sort_keys=True)
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def free_port():
    """A port nothing listens on now (the system picks it)"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Node:
    def __init__(self, name, binary, index, extra):
        """extra: divi.conf lines; a callable is evaluated at each start, so a
        line naming another node's port follows that node to new ports"""
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"reorg{index}"
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.extra = list(extra)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0
        self.why = ""

    def write_conf(self):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + [line() if callable(line) else line for line in self.extra]
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".new", path)

    def launch(self, env):
        self.starts += 1
        self.write_conf()
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        full_env = dict(os.environ, **(env or {}))
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=full_env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def log_tail(self, n=15):
        """The last lines of the node's debug.log (divid keeps it in regtest/),
        or of its stderr when there is none"""
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log"), self.err):
            try:
                with open(path, errors="replace") as f:
                    lines = f.read().splitlines()
                if lines:
                    return lines[-n:]
            except OSError:
                pass
        return []

    def start(self, env=None):
        """True once RPC answers. A node that exits at once because a port is
        taken is started again on new ports; otherwise `why` says how it ended:
        its exit code and the last 15 lines of its debug.log"""
        retries = BIND_RETRIES
        self.launch(env)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                tail = self.log_tail()
                text = "\n".join(tail)
                if retries and ("Address already in use" in text or "Unable to bind" in text):
                    retries -= 1
                    old = (self.p2p, self.rpcport)
                    self.p2p, self.rpcport = free_port(), free_port()
                    print(f"# {self.name}: ports {old[0]}/{old[1]} in use, starting again on "
                          f"{self.p2p}/{self.rpcport}", flush=True)
                    self.launch(env)
                    continue
                self.why = f"exited with code {code}; last lines of its log:\n" + "\n".join(
                    "#     " + line for line in tail)
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        self.why = f"no RPC answer within {START_TIMEOUT} s; last lines of its log:\n" + "\n".join(
            "#     " + line for line in self.log_tail())
        return False

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:150]}")
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


# --- how replies are compared ------------------------------------------------------

def kind(v):
    if v is None:
        return "null"
    return {bool: "bool", int: "int", float: "number", str: "string", list: "array", dict: "object"}[type(v)]


def flatten(v, vary, path=""):
    out = {}
    if isinstance(v, dict):
        out[path or "."] = "object"
        for k, x in v.items():
            out.update(flatten(x, vary, f"{path}.{k}"))
    elif isinstance(v, list):
        out[path or "."] = f"array[{len(v)}]"
        for i, x in enumerate(v):
            out.update(flatten(x, vary, f"{path}[{i}]"))
    else:
        leaf = path.rsplit(".", 1)[-1]
        out[path or "."] = f"<{kind(v)}>" if leaf in vary else (kind(v), v)
    return out


def differences(a, b):
    return [(k, a.get(k, "absent"), b.get(k, "absent")) for k in sorted(set(a) | set(b))
            if a.get(k, "absent") != b.get(k, "absent")]


def leaf(x):
    return x if isinstance(x, str) else f"{x[1]!r}"[:70]


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{str(out[2]).splitlines()[0][:90] if out[2] else ''}\""
    return json.dumps(out[1], sort_keys=True)[:140]


def compare(name, c, i, vary=()):
    """Same outcome; for an error the same code and message; for a result
    every field's name, JSON type and value, except the values in `vary`"""
    LAST_DIFF.clear()
    if name == INJECT:
        i = ("ok", {"injected": True, "reply": i[1]}) if i[0] == "ok" else ("err", (i[1] or 0) + 1, i[2])
    if c[0] == "err" and i[0] == "err":
        row(name, show(c), show(i), c[1] == i[1] and c[2] == i[2], (c, i))
    elif c[0] == "ok" and i[0] == "ok":
        d = differences(flatten(c[1], set(vary)), flatten(i[1], set(vary)))
        LAST_DIFF.update(k for k, _, _ in d)
        if not d:
            row(name, show(c), "same", True, (c, i))
        else:
            row(name, "; ".join(f"{k}={leaf(x)}" for k, x, _ in d[:5]),
                "; ".join(f"{k}={leaf(y)}" for k, _, y in d[:5]) + (f" (+{len(d) - 5} more)" if len(d) > 5 else ""),
                False, (c, i))
    else:
        row(name, show(c), show(i), False, (c, i))


def pair(name, core_node, iron_node, method, *params, vary=(), fix=None):
    """The same call on a divid and an irondivid; `fix` normalises a result
    (e.g. sorts a list whose order is not part of the reply's meaning)"""
    c, i = core_node.call(method, *params), iron_node.call(method, *params)
    if fix is not None:
        c = ("ok", fix(c[1])) if c[0] == "ok" else c
        i = ("ok", fix(i[1])) if i[0] == "ok" else i
    compare(name, c, i, vary)
    return c, i


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


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind_, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

# --- the six nodes: side L (bridge C1; C3 and I1 behind it), side R (C2; C4, I2) -------

C1 = Node("bridge-L", DIVID, 0, ["listen=1"])
I1 = Node("irondivid-L", IRONDIVID, 1, ["listen=0", lambda: f"connect=127.0.0.1:{C1.p2p}"])
C2 = Node("bridge-R", DIVID, 2, ["listen=1"])
I2 = Node("irondivid-R", IRONDIVID, 3, ["listen=0", lambda: f"connect=127.0.0.1:{C2.p2p}"])
C3 = Node("divid-L", DIVID, 4, ["listen=0", lambda: f"connect=127.0.0.1:{C1.p2p}"])
C4 = Node("divid-R", DIVID, 5, ["listen=0", lambda: f"connect=127.0.0.1:{C2.p2p}"])
ALL = (C1, I1, C2, I2, C3, C4)
BRIDGES = (C1, C2)
# The divid and the irondivid behind each bridge
PAIRS = (("L", C3, I1), ("R", C4, I2))


def connected_within_sides():
    return (all(n.rpc("getconnectioncount") >= 1 for n in (I1, I2, C3, C4))
            and all(b.rpc("getconnectioncount") >= 2 for b in BRIDGES))


def join():
    """One link across the split: divid R dials divid L once"""
    C2.rpc("addnode", f"127.0.0.1:{C1.p2p}", "onetry")
    need(wait_for(lambda: C1.rpc("getconnectioncount") >= 3, 60), "the sides did not connect")


def split():
    """Restart all six: no node dials across, so the sides are apart"""
    for n in (I1, I2, C3, C4, C1, C2):
        n.stop()
    for n in (C1, C2, C3, C4, I1, I2):
        need(n.start(), f"{n.name} did not start again: {n.why}")
    need(wait_for(connected_within_sides, 60), "a side did not connect again")
    need(C1.rpc("getconnectioncount") == 2 and C2.rpc("getconnectioncount") == 2, "the sides are still joined")


def tip(n):
    return n.rpc("getbestblockhash")


def one_tip(secs=SYNC_TIMEOUT):
    return wait_for(lambda: len({tip(n) for n in ALL}) == 1, secs)


def mine(node, n):
    hashes = node.rpc("setgenerate", n)
    return hashes if isinstance(hashes, list) else []


def tips_sorted(v):
    return sorted(v, key=lambda t: (-t.get("height", 0), t.get("hash", ""))) if isinstance(v, list) else v


def chain_rows(label):
    """The tip on every node, and getchaintips of each side's two nodes"""
    hashes = {n.name: tip(n) for n in ALL}
    core = {hashes[n.name] for n in (C1, C2, C3, C4)}
    iron = {hashes[n.name] for n in (I1, I2)}
    row(f"{label}: one tip on all six nodes", f"{len(core)} tip(s)", f"{len(iron)} tip(s)",
        len(set(hashes.values())) == 1)
    for side, c, i in PAIRS:
        pair(f"{label}: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"{label}: getblockcount ({side})", c, i, "getblockcount")
        pair(f"{label}: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)


def mempool_rows(label):
    for side, c, i in PAIRS:
        pair(f"{label}: getrawmempool ({side})", c, i, "getrawmempool", fix=lambda v: sorted(v))


TX_VARY = {"time", "timereceived"}


def wallet_rows(label, txids, since):
    """The shared wallet on the divid and the irondivid behind bridge L"""
    for i in (I1,):
        for t, txid in txids:
            pair(f"{label}: gettransaction {t} (L)", C3, i, "gettransaction", txid, vary=TX_VARY)
        pair(f"{label}: getbalance (L)", C3, i, "getbalance")
        pair(f"{label}: listsinceblock <losing tip> (L)", C3, i, "listsinceblock", since,
             vary=TX_VARY, fix=lambda v: dict(v, transactions=sorted(
                 v.get("transactions", []), key=lambda x: (x.get("txid", ""), x.get("category", ""),
                                                           x.get("vout", 0)))) if isinstance(v, dict) else v)


def is_pos(node, block_hash):
    """A proof-of-stake block: its second transaction is a coinstake (first
    output empty)"""
    txs = node.rpc("getblock", block_hash).get("tx", [])
    if len(txs) < 2:
        return False
    raw = node.call("getrawtransaction", txs[1], 1)
    return raw[0] == "ok" and raw[1]["vout"][0].get("value") == 0


def spend(node, coin, dest, fee=0.001):
    amount = round(coin["amount"] - fee, 8)
    raw = node.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}], {dest: amount})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign")
    return node.rpc("sendrawtransaction", signed["hex"])


# --- start: one network, one wallet ---------------------------------------------------

for n in (C1, C2, C3, C4):
    need(n.start(), f"{n.name} did not start: {n.why}")
phrase = C3.rpc("dumphdinfo")["mnemonic"]
need(I1.start({"WALLET_MNEMONIC": phrase}), f"irondivid L did not start: {I1.why}")
need(I2.start({"WALLET_MNEMONIC": phrase}), f"irondivid R did not start: {I2.why}")
del phrase
print(f"# divid {C1.rpc('getinfo').get('version')}, irondivid {I1.rpc('getnetworkinfo').get('version')}", flush=True)
need(wait_for(connected_within_sides, 60), "a side did not connect")
join()
mine(C3, 25)
need(one_tip(), "the nodes did not follow divid L's first 25 blocks")
need(wait_for(lambda: I1.rpc("getbalance") == C3.rpc("getbalance") and I2.rpc("getbalance") > 0, 60),
     "the irondivid wallets did not find divid's coins")

# --- A. depth 1 (proof of work): side R, mined by irondivid, wins ------------------------

split()
mine(C3, 1)
lost_a = tip(C3)
mine(I2, 2)
need(wait_for(lambda: tip(C2) == tip(I2) == tip(C4), 60), "side R did not agree")
join()
one_tip()
chain_rows("A depth 1")
row("A depth 1: the longer side won", "", "", tip(C3) == tip(I2) and tip(C3) != lost_a)

# --- B. depth 6 with transactions: a double spend across the split ---------------------

coins = sorted(C3.rpc("listunspent"), key=lambda u: (u["txid"], u["vout"]))
need(len(coins) >= 3, "not enough coins in the wallet")
x_coin, y_coin = coins[0], coins[1]
split()
dest_l, dest_r, dest_y = C3.rpc("getnewaddress"), C3.rpc("getnewaddress"), C3.rpc("getnewaddress")
t_l = spend(C3, x_coin, dest_l)            # side L spends coin X ...
t_y = spend(C3, y_coin, dest_y)            # ... and coin Y, spent on side L only
need(wait_for(lambda: t_y in C1.rpc("getrawmempool"), 30), "bridge L did not take side L's spends")
mine(C1, 6)
lost_b = tip(C1)
need(wait_for(lambda: tip(C3) == lost_b and tip(I1) == lost_b, 60), "side L did not agree")
need(I2.call("listunspent")[0] == "ok", "irondivid R has no wallet")
t_r = spend(I2, x_coin, dest_r)            # side R spends coin X too
mine(I2, 7)
need(wait_for(lambda: tip(C2) == tip(I2) == tip(C4), 60), "side R did not agree")
join()
one_tip()
time.sleep(3)
chain_rows("B depth 6")
mempool_rows("B depth 6")
in_pool = {n.name: t_y in n.rpc("getrawmempool") for n in (C3, I1)}
row("B depth 6: side L's lone spend is back in the mempool (L)", in_pool[C3.name], in_pool[I1.name],
    in_pool[C3.name] == in_pool[I1.name])
wallet_rows("B depth 6", [("of the losing double spend", t_l), ("of the winning double spend", t_r),
                          ("of side L's lone spend", t_y)], lost_b)

# --- C. equal tips (first seen), then one more block on side R ---------------------------

split()
mine(C1, 2)
tip_l = tip(C1)
need(wait_for(lambda: tip(I1) == tip_l and tip(C3) == tip_l, 60), "side L did not agree")
mine(I2, 2)
tip_r = tip(I2)
need(wait_for(lambda: tip(C2) == tip_r and tip(C4) == tip_r, 60), "side R did not agree")
join()
time.sleep(8)
for side, c, i, own in (("L", C3, I1, tip_l), ("R", C4, I2, tip_r)):
    row(f"C equal tips: side {side} keeps the tip it saw first", tip(c) == own, tip(i) == own,
        (tip(c) == own) == (tip(i) == own))
    pair(f"C equal tips: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)
# Side R's longer chain arrives block by block: the first block tips it
for k in range(3):
    mine(C2, 1)
    one_tip(60)
    if k == 0:
        chain_rows("C one block more on side R")
    time.sleep(1)
chain_rows("C two blocks after that, one by one")

# --- D. depth 30: side L (mined by divid) wins; irondivid R restarted while it reorganises

split()
mine(I2, 30)
lost_d = tip(I2)
need(wait_for(lambda: tip(C2) == lost_d and tip(C4) == lost_d, 90), "side R did not agree")
mine(C1, 31)
need(wait_for(lambda: tip(I1) == tip(C1) == tip(C3), 90), "side L did not agree")
join()
time.sleep(1)
I2.stop()
need(I2.start(), f"irondivid R did not start again: {I2.why}")
one_tip(180)
chain_rows("D depth 30, restart")
row("D depth 30: the longer side won", "", "", tip(I2) == tip(C1) and tip(I2) != lost_d)

# --- E. proof of stake: depth 1 and 6 past the last PoW block ---------------------------

height = C1.rpc("getblockcount")
if height < 101:
    mine(C1, 101 - height)
    need(one_tip(), "the nodes did not follow to height 101")
for depth, winner in ((1, "R"), (6, "L"), (30, "R")):
    split()
    loser_miner, winner_miner = (C1, I2) if winner == "R" else (I2, C1)
    mine(loser_miner, depth)
    mine(winner_miner, depth + 1)
    need(wait_for(lambda: tip(I1) == tip(C1) == tip(C3) and tip(C2) == tip(I2) == tip(C4), 120),
         "a side did not agree")
    pos = is_pos(C1, tip(C1)) and is_pos(C2, tip(C2))
    print(f"# E depth {depth}: side {winner} wins, proof of stake on both sides: {pos}", flush=True)
    row(f"E PoS depth {depth}: both sides' tips are proof of stake", pos, pos, pos)
    win_tip = tip(winner_miner)
    own_l, own_r = tip(C1), tip(C2)
    join()
    if depth < 30:
        one_tip(180)
        chain_rows(f"E PoS depth {depth}")
        row(f"E PoS depth {depth}: the longer side won", "", "", tip(C3) == win_tip and tip(I1) == win_tip)
        continue
    # 30 blocks deep the other branch stakes coins made on that branch. Divi
    # Core looks the stake's input up in its own chain only (GetTransaction,
    # BlockProofVerifier.cpp:66-70) and refuses the block (:147), so each side
    # keeps its own tip; irondivid is to do the same
    time.sleep(20)
    core = (tip(C3) == own_l, tip(C4) == own_r)
    iron = (tip(I1) == own_l, tip(I2) == own_r)
    row(f"E PoS depth {depth}: each side keeps its own tip", core, iron, core == iron == (True, True))
    for side, c, i in PAIRS:
        pair(f"E PoS depth {depth}: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"E PoS depth {depth}: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)

# --- F. invalidateblock and reconsiderblock, on the divid and irondivid behind bridge L ---------------------

height = C3.rpc("getblockcount")
target = C3.rpc("getblockhash", height - 2)
pair("F invalidateblock <tip-2>", C3, I1, "invalidateblock", target)
time.sleep(3)
for method in ("getblockcount", "getbestblockhash"):
    pair(f"F after invalidateblock: {method}", C3, I1, method)
pair("F after invalidateblock: getchaintips", C3, I1, "getchaintips", fix=tips_sorted)
pair("F reconsiderblock <tip-2>", C3, I1, "reconsiderblock", target)
wait_for(lambda: C3.rpc("getblockcount") == height and I1.rpc("getblockcount") == height, 60)
for method in ("getblockcount", "getbestblockhash"):
    pair(f"F after reconsiderblock: {method}", C3, I1, method)
pair("F after reconsiderblock: getchaintips", C3, I1, "getchaintips", fix=tips_sorted)
pair("F invalidateblock of an unknown block", C3, I1, "invalidateblock", "00" * 32)
pair("F reconsiderblock of an unknown block", C3, I1, "reconsiderblock", "00" * 32)

for n in ALL:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
