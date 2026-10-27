#!/usr/bin/env python3
"""Wallet transaction times of Divi Core divid and irondivid: `time` (divid's
GetTxTime, the smart time) and `timereceived` (nTimeReceived).

Three nodes on one regtest chain: S, a divid wallet that mines and sends; C, a
divid wallet; and I, an irondivid restored from C's phrase, so C and I own the
same coins and see the same transactions. For each kind of wallet transaction
the two replies are compared: block times exactly, times read from a node's
clock within TOL seconds (the twins hear of a transaction moments apart), and
how time, timereceived and the block time relate. Each row prints PASS (same
as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. C's phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is
never printed or put on a command line.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("SMART_TIME_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
# Seconds two clock-read times may differ by: the twins hear of a transaction a
# moment apart (relay, then each one's own processing)
TOL = 3

KNOWN = {}

fails = 0


def row(name, core, iron, same):
    global fails
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    text = lambda v: json.dumps(v, sort_keys=True, default=str)[:220]
    print(f"{word:<5}  {name}  divid={text(core)}  irondivid={text(iron)}{note}", flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        password = secrets.token_hex(16)
        user = "times" + name.replace("-", "")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
            f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self, *args):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def raw_call(self, method, *params):
        """The reply text as sent, to see the members' order"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
            # json.loads keeps the members in the order they were sent
            return json.loads(r.read())

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

    def tail(self, n=4):
        lines = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "debug.log"),
                     os.path.join(self.dir, "regtest", "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def restart(self, *args):
        self.stop()
        self.start(*args)
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer after a restart: {self.tail()}")




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
    sys.exit(1)


sys.excepthook = setup_failed

S = Node("divid-sender", DIVID, 0, ["listen=1"])
if not S.wait_ready():
    print(f"FAIL   start: divid sender did not answer: {S.tail()}", flush=True)
    sys.exit(1)
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}"])
if not C.wait_ready():
    print(f"FAIL   start: divid wallet did not answer: {C.tail()}", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid wallet did not answer: {I.tail()}", flush=True)
    sys.exit(1)
NODES = (S, C, I)
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(node, n=1):
    for _ in range(n):
        out = node.call("setgenerate", 1)
        if out[0] != "ok":
            tip = node.rpc("getblock", node.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            node.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


def seen(txid):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in NODES), 60)


def shared_address():
    """A new address of C that its twin has in its address book too"""
    a = C.rpc("getnewaddress")
    I.rpc("setaccount", a, "")
    return a


def times(node, txid):
    """time, timereceived and blocktime of txid in node's gettransaction"""
    out = node.call("gettransaction", txid, True)
    if out[0] != "ok":
        return {"error": out[1:]}
    t = out[1]
    return {k: t.get(k) for k in ("time", "timereceived", "blocktime")}


def relation(t):
    """How the three times relate, which does not depend on when each node
    heard of the transaction"""
    if "error" in t:
        return t
    rel = lambda a, b: "absent" if a is None or b is None else ("=" if a == b else "<" if a < b else ">")
    return {"time vs blocktime": rel(t["time"], t["blocktime"]),
            "timereceived vs blocktime": rel(t["timereceived"], t["blocktime"]),
            "time vs timereceived": rel(t["time"], t["timereceived"])}


def close(a, b, tol=TOL):
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= tol


def compare_times(what, txid, extra=None):
    c, i = times(C, txid), times(I, txid)
    rc, ri = relation(c), relation(i)
    # A relation decided by a block time and a clock time may tip the other
    # way when the two are within TOL: compared only when they are further apart
    near = lambda t, a, b: t.get(a) is not None and t.get(b) is not None and abs(t[a] - t[b]) <= TOL
    for key, a, b in (("time vs blocktime", "time", "blocktime"),
                      ("timereceived vs blocktime", "timereceived", "blocktime"),
                      ("time vs timereceived", "time", "timereceived")):
        if "error" not in c and "error" not in i and (near(c, a, b) or near(i, a, b)):
            rc[key] = ri[key] = "within TOL"
    row(f"{what}: how time, timereceived and blocktime relate", rc, ri, rc == ri)
    same = ("error" in c) == ("error" in i) and all(close(c.get(k), i.get(k)) for k in ("time", "timereceived")) \
        and c.get("blocktime") == i.get("blocktime")
    row(f"{what}: time and timereceived (within {TOL} s)", c, i, same)
    if extra:
        extra(c, i)
    return c, i


def raw_to(address, amount):
    """A transaction from S's wallet paying `address`, signed and not sent"""
    utxo = max(S.rpc("listunspent", 1), key=lambda u: float(u["amount"]))
    change = S.rpc("getnewaddress")
    value = float(utxo["amount"])
    raw = S.rpc("createrawtransaction", [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                {address: amount, change: round(value - amount - 0.01, 8)})
    signed = S.rpc("signrawtransaction", raw)
    # Locked, so S's own stake in that block does not take the same coin
    S.rpc("lockunspent", False, [{"txid": utxo["txid"], "vout": utxo["vout"]}])
    return signed["hex"], S.rpc("decoderawtransaction", signed["hex"])["txid"]


def in_block_only(address, amount):
    """A receive the twins first hear of in a block: S mines it without
    relaying it first"""
    hex_, txid = raw_to(address, amount)
    for _ in range(30):
        out = S.call("generateblock", {"extratx": [hex_], "ignoreMempool": True})
        if out[0] == "ok":
            break
        # divid stakes from its clock back: let it pass the tip, then again
        time.sleep(2)
    if out[0] != "ok":
        raise RuntimeError(f"S could not mine the block: {out}")
    if not synced():
        raise RuntimeError("the twins did not follow S's block")
    return txid


log = {}   # what -> txid, for the restart and -rescan rows

# --- coins: S mines blocks 1-50, C mines 51-100 (coinbases of both twins) -----------
mine(S, 50)
mine(C, 50)
mine(S, 25)
coinbase = C.rpc("getblock", C.rpc("getblockhash", 60))["tx"][0]
log["a coinbase of the twins' wallet"] = coinbase
compare_times("a coinbase of the twins' wallet", coinbase)

# --- a receive seen in the mempool, then mined ------------------------------------------
X = shared_address()
txid = S.rpc("sendtoaddress", X, 100)
if not seen(txid):
    raise RuntimeError("the receive did not reach the twins' mempools")
compare_times("a receive in the mempool", txid)
# Mined well after it came, so the received time and the block time differ
time.sleep(10)
mine(S)
log["a receive seen in the mempool, then mined"] = txid
compare_times("a receive seen in the mempool, then mined", txid)

# --- a receive first seen in a block ----------------------------------------------------
txid = in_block_only(shared_address(), 50)
log["a receive first seen in a block"] = txid
compare_times("a receive first seen in a block", txid)

# --- a block dated behind the wallet's latest entry --------------------------------------
# Let the clock pass the tip well; then a receive in the mempool (the wallet's
# latest entry, dated now); then S, its clock set back, mines a block dated
# before that entry with another receive
tip_time = S.rpc("getblock", S.rpc("getbestblockhash"))["time"]
wait_for(lambda: time.time() > tip_time + 40, 180)
latest = S.rpc("sendtoaddress", shared_address(), 30)
seen(latest)
time.sleep(2)
mtp = S.rpc("getblock", S.rpc("getbestblockhash"))["time"]
S.rpc("setmocktime", max(int(time.time()) - 20, mtp + 2))
behind = in_block_only(shared_address(), 20)
S.rpc("setmocktime", 0)
bt = C.rpc("gettransaction", behind)["blocktime"]
lt = C.rpc("gettransaction", latest)["time"]
print(f"# block dated behind: blocktime {bt}, the wallet's latest entry {lt} ({bt - lt} s)", flush=True)
log["a receive in a block dated behind the wallet's latest entry"] = behind
compare_times("a receive in a block dated behind the wallet's latest entry", behind)
row("the receive behind the latest entry: time is not before that entry's time",
    times(C, behind)["time"] >= times(C, latest)["time"], times(I, behind)["time"] >= times(I, latest)["time"],
    (times(C, behind)["time"] >= times(C, latest)["time"]) == (times(I, behind)["time"] >= times(I, latest)["time"]))
mine(S)

# --- a send ------------------------------------------------------------------------------
txid = C.rpc("sendtoaddress", S.rpc("getnewaddress"), 5)
if not seen(txid):
    raise RuntimeError("the send did not reach every mempool")
compare_times("a send in the mempool", txid)
mine(S)
log["a send"] = txid
compare_times("a send, mined", txid)

# --- a coinstake of the twins' wallet ----------------------------------------------------
tip = C.rpc("getblock", C.rpc("getbestblockhash"))
wait_for(lambda: time.time() > tip["time"] + 2, 120)
before = C.rpc("getblockcount")
mine(C)
stake = C.rpc("getblock", C.rpc("getblockhash", before + 1))["tx"][1]
log["a coinstake of the twins' wallet"] = stake
compare_times("a coinstake of the twins' wallet", stake)


# --- a block dated ahead of the clock (last: S's next blocks would wait for the
# clock): S's clock set 90 s ahead for one block -------------------------------------------
S.rpc("setmocktime", int(time.time()) + 90)
txid = in_block_only(shared_address(), 40)
S.rpc("setmocktime", 0)
bt = C.rpc("gettransaction", txid)["blocktime"]
print(f"# block dated ahead: blocktime - now = {bt - int(time.time())} s", flush=True)
log["a receive in a block dated ahead of the clock"] = txid
compare_times("a receive in a block dated ahead of the clock", txid)

def lists(when):
    """listtransactions and listsinceblock: each entry's times, and the order of
    the entries"""
    p = f"{when}: " if when else ""
    for call, args in (("listtransactions", ["*", 1000, 0, True]), ("listsinceblock", [])):
        c_out, i_out = C.rpc(call, *args), I.rpc(call, *args)
        ce = c_out if call == "listtransactions" else c_out["transactions"]
        ie = i_out if call == "listtransactions" else i_out["transactions"]
        key = lambda e: (e.get("txid"), e.get("category"), e.get("vout", 0))
        cm, im = {key(e): e for e in ce}, {key(e): e for e in ie}
        far = [k for k in cm if k in im and not (close(cm[k].get("time"), im[k].get("time"))
                                                 and close(cm[k].get("timereceived"), im[k].get("timereceived")))]
        row(f"{p}{call}: every entry's time and timereceived (within {TOL} s)",
            f"{len(cm)} entries", f"{len(far)} differ: {far[:2]}" if far else f"{len(im)} entries", not far and cm.keys() == im.keys())
        if call == "listtransactions":
            order_c = [key(e) for e in ce]
            order_i = [key(e) for e in ie]
            row(f"{p}listtransactions: order of the entries", f"{len(order_c)} entries",
                "same order" if order_c == order_i else f"first difference at {next(n for n, (a, b) in enumerate(zip(order_c + [None] * 9, order_i + [None] * 9)) if a != b)}",
                order_c == order_i)


lists("")

# --- after a restart, after -rescan --------------------------------------------------------
before = {what: (times(C, t), times(I, t)) for what, t in log.items()}
for args, when in (((), "after a restart"), (("-rescan",), "after -rescan")):
    for n in TWINS:
        n.restart(*args)
    if not synced():
        raise RuntimeError(f"the twins did not reconnect {when}")
    time.sleep(2)
    for what, txid in log.items():
        c, i = times(C, txid), times(I, txid)
        bc, bi = before[what]
        row(f"{when}: {what}: times as before", c == bc, i == bi, (c == bc) == (i == bi))
    lists(when)

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
