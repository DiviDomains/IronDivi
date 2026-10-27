#!/usr/bin/env python3
"""What the wallet does with transactions that are not final yet, Divi Core
divid next to irondivid on one regtest network.

Three nodes: divid A (listens, mines, funds), divid B and irondivid I (both dial
A, both with -spendzeroconfchange). B and I get the same coins from A and then
do the same things, so their wallet replies can be compared value for value.
Each of B and I:

1. sends transactions locked above the next block (height and time): what
   sendrawtransaction says and whether the wallet keeps a record;
2. holds three transactions locked at the tip height (final for the next block,
   not at the tip): a payment from A, a payment to A and a payment to itself;
   the wallet replies in the mempool and after the block;
3. holds transactions time-locked behind its clock (setmocktime back): in the
   mempool, then mined;
4. with A stopped, invalidates the block at the lock height of two transactions
   that were mined above it, so they are back in its mempool and cannot go in
   the next block: the wallet replies, a send that needs their coins, then the
   two blocks it makes itself.

The wallet replies compared at each step: getbalance (each form),
getunconfirmedbalance, getwalletinfo's balances, listunspent 0 and 1,
getreceivedbyaddress, getreceivedbyaccount, listreceivedbyaddress,
gettransaction and listtransactions of each transaction. Transactions are named
by their role (txids differ between B and I).

Each row prints PASS (the same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs. Started by run.sh, which owns the work
directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
SEQ_NOT_FINAL = 0xFFFFFFFE

# Differences kept on purpose (README.md): row name -> reason
KNOWN = {
    "3 time lock behind the clock, mined: listunspent 0":
        "decided: a mined coin stays listed (divid hides it while its clock is behind the lock)",
    "3 time lock behind the clock, mined: listunspent 1":
        "decided: a mined coin stays listed (divid hides it while its clock is behind the lock)",
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


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
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"wf{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=wf{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                text = r.read()
        except urllib.error.HTTPError as e:
            text = e.read() or b"{}"
        reply = json.loads(text, parse_float=Decimal)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply["result"])

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
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
            self.proc.wait(timeout=90)
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


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_exception(kind, value, tb, file=sys.stdout)
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- transactions as bytes -----------------------------------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def read_compact(b, pos):
    n = b[pos]
    if n < 0xfd:
        return n, pos + 1
    if n == 0xfd:
        return struct.unpack_from("<H", b, pos + 1)[0], pos + 3
    return struct.unpack_from("<I", b, pos + 1)[0], pos + 5


def relock(hexstr, lock, seq=SEQ_NOT_FINAL):
    """The unsigned transaction with this lock time and every input's sequence"""
    b = bytes.fromhex(hexstr)
    out = bytearray(b[:4])
    n, pos = read_compact(b, 4)
    out += compact(n)
    for _ in range(n):
        out += b[pos:pos + 36]
        pos += 36
        size, pos2 = read_compact(b, pos)
        out += b[pos:pos2 + size]
        pos = pos2 + size + 4
        out += struct.pack("<I", seq)
    n, pos2 = read_compact(b, pos)
    end = pos2
    for _ in range(n):
        end += 8
        size, end = read_compact(b, end)
        end += size
    out += b[pos:end] + struct.pack("<I", lock)
    return out.hex()


# --- the network ---------------------------------------------------------------------------

def synced(nodes, secs=90):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in nodes}) == 1, secs)


def mine(node, n, followers=()):
    for _ in range(n):
        start = node.rpc("getblockcount")
        if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok" and node.rpc("getblockcount") > start, 120):
            raise RuntimeError(f"{node.name} could not make block {start + 1}")
    if followers and not synced([node] + list(followers)):
        raise RuntimeError(f"the nodes did not follow {node.name}")


def in_mempool(node, txids, secs=30):
    return wait_for(lambda: set(txids) <= set(node.rpc("getrawmempool")), secs)


def coin_of(node, txid, amount):
    """The outpoint of `txid` paying `amount` to `node`'s wallet"""
    tx = node.rpc("gettransaction", txid)
    raw = node.rpc("decoderawtransaction", tx["hex"])
    for out in raw["vout"]:
        if Decimal(out["value"]) == Decimal(amount):
            return {"txid": txid, "vout": out["n"]}
    raise RuntimeError(f"{node.name}: no output of {amount} in {txid}")


def build(node, inputs, outputs, lock, seq=SEQ_NOT_FINAL):
    """Signed hex of a transaction from `inputs` to `outputs` (address: amount)
    with this lock time and sequence; signed by `node`'s wallet"""
    raw = node.rpc("createrawtransaction", inputs, {a: float(v) for a, v in outputs.items()})
    signed = node.rpc("signrawtransaction", relock(raw, lock, seq))
    if not signed.get("complete"):
        raise RuntimeError(f"{node.name}: signing incomplete")
    return signed["hex"]


def txid_of(node, hexstr):
    return node.rpc("decoderawtransaction", hexstr)["txid"]


# --- the wallet replies, by role -----------------------------------------------------------

def amt(v):
    return str(Decimal(str(v)).normalize()) if v is not None else None


def result(out, f):
    if out[0] == "err":
        return f"error {out[1]}"
    return f(out[1])


def snapshot(node, w):
    """{reply name: comparable value} for wallet `w` of `node`"""
    roles = {txid: role for role, txid in w["txids"].items()}
    s = {}
    for label, params in [
        ("getbalance", []), ("getbalance \"*\" 0", ["*", 0]), ("getbalance \"*\" 1", ["*", 1]),
        ("getbalance \"\" 0", ["", 0]), ("getbalance \"\" 1", ["", 1]),
        ("getbalance \"fin\" 0", ["fin", 0]), ("getbalance \"fin\" 1", ["fin", 1]),
        ("getbalance \"self\" 0", ["self", 0]),
    ]:
        s[label] = result(node.call("getbalance", *params), amt)
    s["getunconfirmedbalance"] = result(node.call("getunconfirmedbalance"), amt)
    s["getwalletinfo"] = result(node.call("getwalletinfo"), lambda i: {
        k: amt(i.get(k)) for k in ("balance", "unconfirmed_balance", "immature_balance", "spendable_balance")})
    for minconf in (0, 1):
        s[f"listunspent {minconf}"] = result(node.call("listunspent", minconf), lambda us: sorted(
            (roles.get(u["txid"], "other"), amt(u["amount"]), u["confirmations"]) for u in us))
    for minconf in (0, 1):
        s[f"getreceivedbyaddress fin {minconf}"] = result(
            node.call("getreceivedbyaddress", w["fin"], minconf), amt)
        s[f"getreceivedbyaddress self {minconf}"] = result(
            node.call("getreceivedbyaddress", w["self"], minconf), amt)
        s[f"getreceivedbyaccount fin {minconf}"] = result(node.call("getreceivedbyaccount", "fin", minconf), amt)
        s[f"listreceivedbyaddress {minconf}"] = result(node.call("listreceivedbyaddress", minconf), lambda es: sorted(
            (e.get("account"), amt(e["amount"]), e["confirmations"],
             sorted(roles.get(t, "other") for t in e.get("txids", []))) for e in es))
    for role, txid in sorted(w["txids"].items()):
        s[f"gettransaction {role}"] = result(node.call("gettransaction", txid), lambda t: {
            "confirmations": t.get("confirmations"), "amount": amt(t.get("amount")), "fee": amt(t.get("fee")),
            "details": sorted((d.get("category"), d.get("account"), amt(d.get("amount"))) for d in t.get("details", []))})
    s["listtransactions"] = result(node.call("listtransactions", "*", 1000), lambda es: sorted(
        (roles[e["txid"]], e.get("category"), e.get("account"), amt(e.get("amount")), e.get("confirmations"))
        for e in es if e.get("txid") in roles))
    s["mempool"] = sorted(roles[t] for t in node.rpc("getrawmempool") if t in roles)
    return s


def compare_snapshots(step):
    sb, si = snapshot(B, WB), snapshot(I, WI)
    for key in sb:
        row(f"{step}: {key}", json.dumps(sb[key])[:300], json.dumps(si[key])[:300], sb[key] == si[key])


def compare(step, core, iron):
    row(step, json.dumps(core)[:200], json.dumps(iron)[:200], core == iron)


def send_out(node, hexstr):
    out = node.call("sendrawtransaction", hexstr)
    return ("ok",) if out[0] == "ok" else ("err", out[1], out[2])


# --- the run -------------------------------------------------------------------------------

common = ["listen=1"]
A = Node("A", DIVID, 0, common)
for n in (A,):
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start")
peer = [f"connect={HOST}:{A.p2p}", "listen=0", "spendzeroconfchange=1"]
B = Node("B", DIVID, 1, peer)
I = Node("I", IRONDIVID, 2, peer)
for n in (B, I):
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start")
if not wait_for(lambda: A.rpc("getconnectioncount") >= 2, 60):
    raise RuntimeError("B and I did not connect to A")

mine(A, 30, (B, I))
WB, WI = {"txids": {}}, {"txids": {}}
for node, w in ((B, WB), (I, WI)):
    w["fin"] = node.rpc("getnewaddress", "fin")
    w["self"] = node.rpc("getnewaddress", "self")
    w["plain"] = node.rpc("getnewaddress")
    for k in ("c1", "c2", "c3", "c4"):
        w["txids"][k] = A.rpc("sendtoaddress", w["plain"], 100)
a_addr = A.rpc("getnewaddress")
mine(A, 1, (B, I))
for node, w in ((B, WB), (I, WI)):
    w["coins"] = {k: coin_of(node, w["txids"][k], 100) for k in ("c1", "c2", "c3", "c4")}
a_coins = sorted((u for u in A.rpc("listunspent", 1) if Decimal(u["amount"]) >= 1000),
                 key=lambda u: (u["txid"], u["vout"]))
print(f"# start: height {A.rpc('getblockcount')}, A has {len(a_coins)} coins", flush=True)
compare_snapshots("0 funded")


def a_coin():
    u = a_coins.pop(0)
    return {"txid": u["txid"], "vout": u["vout"]}, Decimal(u["amount"])


# 1. locked above the next block: refused, no wallet record
tip = B.rpc("getblockcount")
now = int(time.time())
for label, lock in [("height lock tip+1", tip + 1), ("height lock tip+5", tip + 5),
                    ("time lock now+3600", now + 3600)]:
    outs = {}
    for node, w in ((B, WB), (I, WI)):
        hexstr = build(node, [w["coins"]["c1"]], {a_addr: 99.999}, lock)
        outs[node.name] = (send_out(node, hexstr), txid_of(node, hexstr))
    compare(f"1 {label}: sendrawtransaction", outs["B"][0], outs["I"][0])
    compare(f"1 {label}: gettransaction of it", result(B.call("gettransaction", outs["B"][1]), lambda t: "found"),
            result(I.call("gettransaction", outs["I"][1]), lambda t: "found"))
    compare(f"1 {label}: in the mempool", outs["B"][1] in B.rpc("getrawmempool"),
            outs["I"][1] in I.rpc("getrawmempool"))
compare_snapshots("1 after the refusals")

# 2. locked at the tip height: in the mempool, not final at the tip
tip = A.rpc("getblockcount")
for node, w in ((B, WB), (I, WI)):
    coin, value = a_coin()
    hexstr = build(A, [coin], {w["fin"]: 50, a_addr: float(value - Decimal("50.001"))}, tip)
    w["txids"]["in2"] = A.rpc("sendrawtransaction", hexstr)
    out = build(node, [w["coins"]["c1"]], {a_addr: 30, w["plain"]: 69.999}, tip)
    w["txids"]["out2"] = node.rpc("sendrawtransaction", out)
    own = build(node, [w["coins"]["c2"]], {w["self"]: 50, w["plain"]: 49.999}, tip)
    w["txids"]["self2"] = node.rpc("sendrawtransaction", own)
for node, w in ((B, WB), (I, WI)):
    if not in_mempool(node, [w["txids"][k] for k in ("in2", "out2", "self2")]):
        raise RuntimeError(f"{node.name}: step 2 transactions not in the mempool")
compare_snapshots("2 lock at the tip, mempool")
mine(A, 1, (B, I))
compare_snapshots("2 lock at the tip, mined")

# 3. time-locked behind the wallet's clock
now = int(time.time())
lock = now - 60
for node, w in ((B, WB), (I, WI)):
    coin, value = a_coin()
    hexstr = build(A, [coin], {w["fin"]: 20, a_addr: float(value - Decimal("20.001"))}, lock)
    w["txids"]["in3"] = A.rpc("sendrawtransaction", hexstr)
    own = build(node, [w["coins"]["c3"]], {w["self"]: 10, w["plain"]: 89.999}, lock)
    w["txids"]["self3"] = node.rpc("sendrawtransaction", own)
for node, w in ((B, WB), (I, WI)):
    if not in_mempool(node, [w["txids"][k] for k in ("in3", "self3")]):
        raise RuntimeError(f"{node.name}: step 3 transactions not in the mempool")
for node in (B, I):
    node.rpc("setmocktime", lock - 600)
compare_snapshots("3 time lock behind the clock, mempool")
for node in (B, I):
    node.rpc("setmocktime", 0)
mine(A, 1, (B, I))
for node in (B, I):
    node.rpc("setmocktime", lock - 600)
compare_snapshots("3 time lock behind the clock, mined")
for node in (B, I):
    node.rpc("setmocktime", 0)

# 4. a reorg below the lock height: back in the mempool, not final for the next block
lock_height = A.rpc("getblockcount")
lock_hash = A.rpc("getblockhash", lock_height)
for node, w in ((B, WB), (I, WI)):
    coin, value = a_coin()
    hexstr = build(A, [coin], {w["fin"]: 7, a_addr: float(value - Decimal("7.001"))}, lock_height)
    w["txids"]["in4"] = A.rpc("sendrawtransaction", hexstr)
    own = build(node, [w["coins"]["c4"]], {w["self"]: 60, w["plain"]: 39.999}, lock_height)
    w["txids"]["self4"] = node.rpc("sendrawtransaction", own)
for node, w in ((B, WB), (I, WI)):
    if not in_mempool(node, [w["txids"][k] for k in ("in4", "self4")]):
        raise RuntimeError(f"{node.name}: step 4 transactions not in the mempool")
mine(A, 3, (B, I))
for node, w in ((B, WB), (I, WI)):
    if node.rpc("gettransaction", w["txids"]["self4"])["confirmations"] != 3:
        raise RuntimeError(f"{node.name}: step 4 transactions not mined")
A.stop()
for node in (B, I):
    node.rpc("invalidateblock", lock_hash)
compare("4 after invalidateblock: height", B.rpc("getblockcount"), I.rpc("getblockcount"))
for node, w in ((B, WB), (I, WI)):
    in_mempool(node, [w["txids"][k] for k in ("in4", "self4")], 10)
compare_snapshots("4 lock above the tip after a reorg")

# A send that needs a coin of the transactions that cannot be mined next: more
# than every coin divid's AvailableCoins gives (B's listunspent 0; B and I list
# the same final coins, rows above)
available = sum(Decimal(str(u["amount"])) for u in B.rpc("listunspent", 0))
need = available + Decimal(10)
sent = {}
for node, w in ((B, WB), (I, WI)):
    out = node.call("sendtoaddress", w["plain"], float(need))
    if out[0] == "ok":
        w["txids"]["send4"] = out[1]
        raw = node.rpc("getrawtransaction", out[1], 1)
        spends = sorted({role for v in raw["vin"] for role, t in w["txids"].items() if t == v["txid"]})
        sent[node.name] = ("sent", spends)
    else:
        sent[node.name] = ("error", out[1])
compare("4 send needing a coin not final: sendtoaddress", sent["B"], sent["I"])

# The node makes the next two blocks alone: the first cannot hold them
for step in ("first", "second"):
    for node in (B, I):
        mine(node, 1)
    held = {}
    for node, w in ((B, WB), (I, WI)):
        block = node.rpc("getblock", node.rpc("getbestblockhash"))
        held[node.name] = sorted(r for r, t in w["txids"].items() if t in block["tx"])
    compare(f"4 {step} block after the reorg: holds", held["B"], held["I"])
    compare_snapshots(f"4 {step} block after the reorg")

for n in (B, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
sys.exit(min(fails, 254))
