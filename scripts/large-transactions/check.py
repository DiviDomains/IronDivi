#!/usr/bin/env python3
"""Large transactions, full blocks and long unconfirmed chains on Divi Core
divid and irondivid, compared row by row.

A divid miner funds two followers, a divid and an irondivid, with the same
coins, and keeps coins of its own for raw transactions it signs. Every part
starts from copies of that set-up:

1. raw size and sigops edges: transactions of 99,999, 100,000 and 100,001
   bytes, of 8,000 and 8,020 sigops, handed to each follower alone;
2. a block's sigops: a mempool of three 7,000-sigop transactions, then the
   block each follower makes;
3. full blocks: a mempool larger than a block, then blocks until it is empty;
4. unconfirmed chains: raw chains of 30, 60 and 120 steps, and a wallet send
   repeated 120 times on its own unconfirmed change;
5. wallet sends: sendmany fan-outs of 100, 500 and 1,000 outputs and up to the
   largest that fits; sends that need 100, 500 and 1,500 small coins.

Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL; the exit code is the number of FAILs. Started by run.sh, which owns the
work directory and stops the nodes. Every key is a throwaway of the run's own
wallets; none is printed.
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
START_TIMEOUT = 180
INJECT = os.environ.get("LARGE_TRANSACTIONS_INJECT", "")
SMALL = int(os.environ.get("LARGE_TRANSACTIONS_SMALL", "1500"))
# The parts to run (all by default), e.g. "3,4"
# A directory to write both values of every FAIL row to (nothing without it)
DUMP = os.environ.get("LARGE_TRANSACTIONS_DUMP", "")
PARTS = set(os.environ.get("LARGE_TRANSACTIONS_PARTS", "1,2,3,4,5").split(","))

# divid's limits (defaultValues.h:43-62)
MAX_STANDARD_TX_SIZE = 100_000
MAX_TX_SIGOPS = 8_000

# Differences irondivid has on purpose, by row name; each listed in README.md
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def note(text):
    print(f"# {text}", flush=True)


def row(name, core, iron):
    global fails
    if INJECT and INJECT == name:
        iron = ["injected", iron]
    same = core == iron
    reason = KNOWN.get(name)
    if reason:
        word, extra = ("FAIL", "  [listed as KNOWN but now matches divid: update README.md]") if same \
            else ("KNOWN", f"  [known: {reason}]")
    else:
        word, extra = ("PASS", "") if same else ("FAIL", "")
    counts[word] += 1
    if word == "FAIL":
        fails += 1
        if DUMP:
            safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:90]
            os.makedirs(DUMP, exist_ok=True)
            with open(os.path.join(DUMP, safe + ".json"), "w") as f:
                json.dump({"divid": core, "irondivid": iron}, f, indent=1, default=str)
    show = lambda v: json.dumps(v, default=str)[:150]
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{extra}", flush=True)


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_exception(kind, value, tb)
    print("FAIL   set-up or step: " + str(value)[:300], flush=True)
    print(f"FAILS {fails + 1}", flush=True)
    sys.exit(min(fails + 1, 254))


sys.excepthook = setup_failed


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.password = secrets.token_hex(16)
        self.user = f"lt{index}"
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

    def call(self, method, *params, timeout=600):
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
            raise RuntimeError(f"{self.name} {method}: {str(out)[:200]}")
        return out[1]

    def stop(self):
        if self.proc is None or self.proc.poll() is not None:
            return
        self.call("stop", timeout=30)
        try:
            self.proc.wait(180)
        except subprocess.TimeoutExpired:
            self.proc.kill()
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


def in_step(nodes, secs=180):
    tip = M.rpc("getbestblockhash")
    return all(wait_for(lambda n=n: n.rpc("getbestblockhash") == tip, secs) for n in nodes)


def outcome(out):
    """A reply as compared: an error by code and message, a result as ok"""
    if out[0] == "err":
        return ["error", out[1], str(out[2]).split("\n", 1)[0]]
    if out[0] == "down":
        return ["no reply"]
    return ["ok"]


# --- the miner's raw transactions ----------------------------------------------------------

def coin_of(txid, address):
    raw = M.rpc("getrawtransaction", txid, 1)
    for o in raw["vout"]:
        if o["scriptPubKey"].get("addresses") == [address]:
            return {"txid": txid, "vout": o["n"], "value": Decimal(o["value"]),
                    "scriptPubKey": o["scriptPubKey"]["hex"]}
    raise RuntimeError(f"no output to {address} in {txid}")


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def p2pkh_script(address):
    return bytes.fromhex(M.rpc("validateaddress", address)["scriptPubKey"])


def unsigned_tx(inputs, outputs):
    """A version-1 transaction: `inputs` [(txid, vout)], `outputs` [(sat, script)]"""
    t = (1).to_bytes(4, "little") + compact(len(inputs))
    for txid, vout in inputs:
        t += bytes.fromhex(txid)[::-1] + vout.to_bytes(4, "little") + b"\x00" + b"\xff\xff\xff\xff"
    t += compact(len(outputs))
    for sat, script in outputs:
        t += int(sat).to_bytes(8, "little") + compact(len(script)) + script
    return t + (0).to_bytes(4, "little")


def sign(coin, outputs):
    """The miner's signature over one coin paying `outputs`; the signed hex"""
    raw = unsigned_tx([(coin["txid"], coin["vout"])], outputs).hex()
    prev = [{"txid": coin["txid"], "vout": coin["vout"], "scriptPubKey": coin["scriptPubKey"]}]
    out = M.rpc("signrawtransaction", raw, prev)
    if not out.get("complete"):
        raise RuntimeError("signrawtransaction incomplete")
    return out["hex"]


SAT = 100_000_000
FEE = 20_000_000  # 0.2 DIVI, well over any relay fee for 100 kB


def sized(coin, target):
    """A transaction of exactly `target` bytes: one coin to outputs of 0.001
    DIVI, mostly P2SH (32 bytes, no legacy sigop) and a few P2PKH (34 bytes)
    to reach the size, and the rest back to the miner. A signature's length
    varies by a byte, so the change is moved a satoshi at a time until the
    signed size is exact. Few sigops, so a block of them is bound by its size,
    not by CheckBlock's legacy 20,000 sigops."""
    pay = p2pkh_script(M.rpc("getnewaddress"))
    p2sh = bytes([0xa9, 0x14]) + bytes(range(20)) + bytes([0x87])
    back = p2pkh_script(M.rpc("getnewaddress"))
    total = int(coin["value"] * SAT)
    base = len(unsigned_tx([(coin["txid"], coin["vout"])], [(0, back)])) + 107
    for k1 in range(0, 40):
        k2 = (target - base - 34 * k1) // 32
        outs = [(100_000, p2sh)] * k2 + [(100_000, pay)] * k1
        outs.append((total - 100_000 * (k1 + k2) - FEE, back))
        est = len(unsigned_tx([(coin["txid"], coin["vout"])], outs)) + 107
        if abs(est - target) > 1:
            continue
        for _ in range(40):
            hexed = sign(coin, outs)
            if len(hexed) // 2 == target:
                return hexed
            outs[-1] = (outs[-1][0] - 1, back)
    raise RuntimeError(f"could not make a transaction of {target} bytes")


def sigops_tx(coin, sigops, pubkey):
    """A transaction of exactly `sigops` legacy sigops: bare 1-of-1 multisig
    outputs of 20 each (CHECKMULTISIG counts 20, script.cpp GetSigOpCount),
    P2PKH outputs of 1 each, and the change back to the miner (1)"""
    ms = bytes([0x51, 33]) + bytes.fromhex(pubkey) + bytes([0x51, 0xae])
    back = p2pkh_script(M.rpc("getnewaddress"))
    n_ms, rest = divmod(sigops - 1, 20)
    outs = [(1_000_000, ms)] * n_ms + [(1_000_000, back)] * rest
    outs.append((int(coin["value"] * SAT) - 1_000_000 * (n_ms + rest) - FEE, back))
    return sign(coin, outs)


def to_both(name, hexed):
    """sendrawtransaction of the same transaction to each follower; its
    outcome and whether it is in each mempool"""
    c, i = C.call("sendrawtransaction", hexed), I.call("sendrawtransaction", hexed)
    row(name, outcome(c), outcome(i))
    txid = c[1] if c[0] == "ok" else (i[1] if i[0] == "ok" else None)
    if txid:
        row(f"{name}: in the mempool", txid in C.mempool(), txid in I.mempool())
    return txid


# --- set-up ----------------------------------------------------------------------------------

M = Node("miner", DIVID, 0)
C = Node("divid", DIVID, 1)
I = Node("irondivid", IRONDIVID, 2)
PEER = [f"connect={HOST}:{PORT_BASE}"]
ALONE = [f"connect={HOST}:{PORT_BASE + 49}"]  # nothing listens there

M.start(["listen=1"])
mine(M, 110)
for n in (C, I):
    n.start(PEER)
    # The same coins for each: ten of 100 DIVI, the small ones of 1 DIVI and
    # one of 50 DIVI
    M.rpc("sendmany", "", {n.rpc("getnewaddress"): 100 for _ in range(10)})
    small = {n.rpc("getnewaddress"): 1 for _ in range(SMALL)}
    keys = list(small)
    for k in range(0, len(keys), 750):
        M.rpc("sendmany", "", {a: 1 for a in keys[k:k + 750]})
    M.rpc("sendtoaddress", n.rpc("getnewaddress"), 50)
OLD = []  # the miner's own coins for raw transactions
for _ in range(45):
    a = M.rpc("getnewaddress")
    OLD.append(coin_of(M.rpc("sendtoaddress", a, 100), a))
# Locked, so the miner does not stake them (AvailableUtxoCalculator.cpp:91)
M.rpc("lockunspent", False, [{"txid": c["txid"], "vout": c["vout"]} for c in OLD])
mine(M, 25)
if not in_step([C, I]):
    raise RuntimeError("the followers did not follow the miner")
PAYEES = [M.rpc("getnewaddress") for _ in range(3000)]
PUBKEY = M.rpc("validateaddress", M.rpc("getnewaddress"))["pubkey"]
note(f"set-up: height {M.rpc('getblockcount')}, {SMALL} small coins per follower")
for n in (C, I):
    n.stop()
M.stop()
for n in (M, C, I):
    shutil.copytree(n.dir, n.dir + ".template", symlinks=True)


def fresh(follower_conf=(), connected=True):
    for n in (M, C, I):
        n.stop()
        shutil.rmtree(n.dir)
        shutil.copytree(n.dir + ".template", n.dir, symlinks=True)
    M.start(["listen=1"])
    for n in (C, I):
        n.start(list(follower_conf) + (PEER if connected else ALONE))
    if connected:
        if not wait_for(lambda: all(n.rpc("getconnectioncount") >= 1 for n in (C, I)), 60):
            raise RuntimeError("the followers did not connect to the miner")
        if not in_step([C, I]):
            raise RuntimeError("the followers are not at the miner's tip")


coins = iter(OLD)


def next_block(n):
    """One block from the follower's own mempool: the mempool transactions it
    took, in the block's order"""
    before = n.mempool()
    mine(n, 1)
    block = n.rpc("getblock", n.rpc("getbestblockhash"))
    return [t for t in block["tx"] if t in before]


def blocks_until_empty(label, most=12, same_txids=True):
    """Each follower mines blocks from its mempool until it is empty; per block
    the transactions taken, in order, compared. Transactions each wallet signed
    itself have their own txids, and so their own order: then only how many"""
    for k in range(1, most + 1):
        pools = [len(C.mempool()), len(I.mempool())]
        if pools == [0, 0]:
            break
        c, i = next_block(C), next_block(I)
        if same_txids:
            row(f"{label}: block {k}: the transactions it takes, in order", c, i)
        else:
            row(f"{label}: block {k}: how many transactions it takes", len(c), len(i))
        row(f"{label}: block {k}: left in the mempool", len(C.mempool()), len(I.mempool()))


# --- 1. a transaction's size and sigops edges ---------------------------------------------------

if "1" in PARTS:

    fresh(connected=False)
    for size in (MAX_STANDARD_TX_SIZE - 1, MAX_STANDARD_TX_SIZE, MAX_STANDARD_TX_SIZE + 1):
        to_both(f"sendrawtransaction of {size} bytes", sized(next(coins), size))
    for sigops in (MAX_TX_SIGOPS, MAX_TX_SIGOPS + 1):
        to_both(f"sendrawtransaction of {sigops} sigops", sigops_tx(next(coins), sigops, PUBKEY))

# --- 2. a block's sigops: three 7,000-sigop transactions ------------------------------------------

if "2" in PARTS:

    fresh(connected=False)
    heavy = [to_both(f"7,000 sigops #{k}", sigops_tx(next(coins), 7000, PUBKEY)) for k in (1, 2, 3)]
    c, i = C.call("setgenerate", 1), I.call("setgenerate", 1)
    row("a mempool of 21,000 sigops: setgenerate 1", outcome(c), outcome(i))
    row("a mempool of 21,000 sigops: height after", C.rpc("getblockcount"), I.rpc("getblockcount"))
    row("a mempool of 21,000 sigops: left in the mempool", len(C.mempool()), len(I.mempool()))

# --- 3. full blocks: a mempool larger than a block ------------------------------------------------

if "3" in PARTS:

    fresh()
    big = []
    for k in range(12):
        big.append(M.rpc("sendrawtransaction", sized(next(coins), 90_000 + 500 * k)))
    if not wait_for(lambda: all(set(big) <= n.mempool() for n in (C, I)), 180):
        note("not every large transaction reached both followers")
    row("full blocks: the mempools are the same", sorted(C.mempool()), sorted(I.mempool()))
    M.stop()
    blocks_until_empty("full blocks")

# --- 4. unconfirmed chains ------------------------------------------------------------------------

if "4" in PARTS:

    fresh()
    for length in (30, 60, 120):
        coin = next(coins)
        back = p2pkh_script(M.rpc("getnewaddress"))
        txids, value, prev = [], int(coin["value"] * SAT), coin
        for _ in range(length):
            value -= 100_000
            hexed = sign(prev, [(value, back)])
            txid = M.rpc("sendrawtransaction", hexed)
            txids.append(txid)
            prev = {"txid": txid, "vout": 0, "value": Decimal(value) / SAT, "scriptPubKey": back.hex()}
        wait_for(lambda: all(set(txids) <= n.mempool() for n in (C, I)), 180)
        row(f"a raw chain of {length}: in the mempool", sum(t in C.mempool() for t in txids),
            sum(t in I.mempool() for t in txids))
        deps = [n.rpc("getrawmempool", True).get(txids[-1], {}).get("depends") for n in (C, I)]
        row(f"a raw chain of {length}: the last one depends on", deps[0] == [txids[-2]], deps[1] == [txids[-2]])
    M.stop()
    blocks_until_empty("raw chains")

    # A wallet send repeated on its own unconfirmed change (-spendzeroconfchange):
    # every coin but the 50 DIVI one locked
    # Each follower alone, so neither sees the other's sends
    fresh(follower_conf=["spendzeroconfchange=1"], connected=False)
    for n in (C, I):
        keep = [u for u in n.rpc("listunspent") if Decimal(u["amount"]) != 50]
        n.rpc("lockunspent", False, [{"txid": u["txid"], "vout": u["vout"]} for u in keep])
    first_failure = {}
    for n in (C, I):
        for step in range(1, 121):
            out = n.call("sendtoaddress", PAYEES[step], 0.01)
            if out[0] != "ok":
                first_failure[n.name] = [step] + outcome(out)
                break
        else:
            first_failure[n.name] = ["none in 120"]
    row("a wallet send on its own change, 120 times: the first that fails", first_failure["divid"],
        first_failure["irondivid"])
    row("a wallet send on its own change: in the mempool", len(C.mempool()), len(I.mempool()))
    # Locked coins do not stake (AvailableUtxoCalculator.cpp:91): unlock to mine
    for n in (C, I):
        n.rpc("lockunspent", True)
    M.stop()
    blocks_until_empty("the wallet chain", same_txids=False)

# --- 5. wallet sends: fan-outs and sends of many small coins --------------------------------------

if "5" in PARTS:

    def sent(n, out):
        """A wallet send's outcome and its transaction: inputs, outputs, the fee
        (set from coin selection's size estimate, not the signed size, which
        differs by the signatures' lengths: MinimumFeeCoinSelectionAlgorithm.cpp:58,
        :87-95, wallet.cpp:1595-1603), in the mempool"""
        if out[0] != "ok":
            return outcome(out), None
        raw = n.rpc("getrawtransaction", out[1], 1)
        fee = abs(Decimal(n.rpc("gettransaction", out[1])["fee"]))
        return ["ok", len(raw["vin"]), len(raw["vout"]), int(fee * SAT), out[1] in n.mempool()], fee

    def lock_all_but(n, keep):
        n.rpc("lockunspent", True)  # with no list: every coin unlocked
        others = [u for u in n.rpc("listunspent") if not keep(Decimal(u["amount"]))]
        if others:
            n.rpc("lockunspent", False, [{"txid": u["txid"], "vout": u["vout"]} for u in others])

    fees = {"divid": Decimal(0), "irondivid": Decimal(0)}

    def wallet_row(name, method, *params):
        res = []
        for n in (C, I):
            r, fee = sent(n, n.call(method, *params))
            if fee is not None:
                fees[n.name] += fee
            res.append(r)
        row(name, res[0], res[1])

    fresh(connected=False)
    for n in (C, I):
        lock_all_but(n, lambda v: v == 100)
    for count in (100, 500, 1000, 2700, 2900, 2935, 2936, 3000):
        wallet_row(f"sendmany \"\" of {count} outputs of 0.01", "sendmany", "",
                   {a: 0.01 for a in PAYEES[:count]})
    for n in (C, I):
        lock_all_but(n, lambda v: v == 1)
    # Sends that need about 1,500, 500 and 100 of the small coins (the largest
    # first, so a refused one leaves the coins for the next)
    for amount in (SMALL - 1, 499, 99):
        wallet_row(f"sendtoaddress {amount} DIVI of 1-DIVI coins", "sendtoaddress", PAYEES[0], amount)
    for n in (C, I):
        n.rpc("lockunspent", True)
    balances = [Decimal(n.rpc("getbalance")) + fees[n.name] for n in (C, I)]
    row("the balance after the sends, with the fees paid added back", str(balances[0]), str(balances[1]))
    row("the sends in the mempool", len(C.mempool()), len(I.mempool()))
    M.stop()
    blocks_until_empty("the wallet sends", same_txids=False)

for n in (C, I, M):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
