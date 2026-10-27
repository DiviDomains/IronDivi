#!/usr/bin/env python3
"""Random wallet and chain sequences on two Divi Core divid nodes and two
irondivid nodes, compared after every step.

Pair C is two divid nodes connected to each other; pair I is two irondivid nodes
connected to each other, restored from the phrases of their divid twins (I1 from
C1, I2 from C2). Each step is drawn from a list with a seeded random generator
and applied to node n of both pairs the same way. After every step each pair
settles, and node n of pair C is compared with node n of pair I on what does
not depend on keys or hashes: the step's outcome (success or error code), the
balances, the unspent coins' amounts, the locked coins, the mempool size and the
height. The first difference ends the run with one FAIL line naming the seed,
the step and both values. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases and the wallet passphrase live only in memory, in RPC requests and
replies and in irondivid's environment; they are never printed or put on a
command line.
"""

import base64
import hashlib
import json
import os
import random
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
SEED = int(os.environ.get("SEED") or secrets.randbelow(2**32))
STEPS = int(os.environ.get("STEPS") or 200)
# A file with a JSON list of steps, as the run prints them, to run instead of
# drawn ones (to shorten a difference)
REPLAY = os.environ.get("REPLAY", "")
# For the proof that a difference is caught: irondivid's outcome of this step
# number is changed before it is compared
INJECT = os.environ.get("RANDOM_SEQUENCES_INJECT", "")
# For looking into a difference: go on after a FAIL instead of ending the run
GO_ON = os.environ.get("RANDOM_SEQUENCES_GO_ON", "") == "1"
# For looking into a difference: a folder to copy the four debug.logs to on a FAIL
LOGS = os.environ.get("RANDOM_SEQUENCES_LOGS", "")
# For looking into a difference: irondivid logs at debug level
# For looking into a difference: irondivid logs at debug level, divid logs its
# mempool decisions
IRON_DEBUG = ["debug=1"] if os.environ.get("RANDOM_SEQUENCES_DEBUG", "") == "1" else []
CORE_DEBUG = ["debug=mempool"] if os.environ.get("RANDOM_SEQUENCES_DEBUG", "") == "1" else []
HOST = "127.0.0.2"
# RANDOM_SEQUENCES_TWIN=1: the second pair runs divid too (run.sh passes it in
# irondivid's place), to see the differences divid has with itself
TWIN = os.environ.get("RANDOM_SEQUENCES_TWIN", "") == "1"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
SETTLE_TIMEOUT = 45

# Step patterns where divid's behaviour is accidental and irondivid keeps its
# own: (kind, reason). A step of that kind is still run, but its comparison is
# skipped and the run goes on from the two states only if they agree again.
KNOWN = {}


def log(line):
    print(line, flush=True)


# --- nodes ----------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"seq{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=seq{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            # a small keypool, so a locked wallet runs out of keys within a few calls
            f"keypool={KEYPOOL}",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = None
        self.start()

    def start(self, *args):
        out = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        out.close()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s; "
                               f"exit {self.proc.poll()}; log ends: {self.log_tail()}")

    def log_tail(self, lines=6):
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(path):
                with open(path, errors="replace") as f:
                    return " | ".join(line.rstrip() for line in f.readlines()[-lines:])
        return "(no debug.log)"

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            if self.call("getblockcount")[0] == "ok":
                return True
            time.sleep(0.25)
        return False

    def call(self, method, *params):
        """('ok', result), ('err', code, message), or ('down',)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
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

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def kill(self):
        os.kill(self.proc.pid, signal.SIGKILL)
        self.proc.wait()


def wait_for(fn, secs, step=0.25):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


class Pair:
    """Two nodes of one kind connected to each other, and the per-pair memory
    of a run: addresses and txids by step number, the wallet passphrase"""

    def __init__(self, name, nodes):
        self.name, self.nodes = name, nodes
        self.addresses = {}  # step -> address handed out at that step
        self.vault_funded = {1: [], 2: []}
        self.lock_order = {1: [], 2: []}  # coins in the order the steps locked them
        self.last_tx = None  # (node, txid) of the step's wallet send
        self.note = None  # what the step needed besides itself
        self.restarted = set()  # nodes stopped and started again in this episode
        self.imported = {1: [], 2: []}  # addresses importprivkey steps brought in, per node
        self.pool_before = {}  # an invalidate's node: its mempool before, txid -> inputs
        self.stake = None  # a mine step's stake blocks: the coins staked, and whether divid's rule picks them
        self.reorg = None  # an invalidate: the height it left, the disconnected blocks' transactions, the mempool then

    def node(self, n):
        return self.nodes[n - 1]

    def other(self, n):
        return self.nodes[2 - n]

    def settle(self):
        """Both nodes connected to each other and on one tip, and each mempool
        still for a moment (or the two equal). A transaction made while the
        two are apart (just after a restart) reaches the other one only by the
        random mempool rebroadcast, so the next step waits for the link."""
        a, b = self.nodes
        deadline = time.time() + SETTLE_TIMEOUT
        last = None
        steady = 0
        while time.time() < deadline:
            try:
                if a.rpc("getconnectioncount") < 1 or b.rpc("getconnectioncount") < 1:
                    time.sleep(0.5)
                    continue
                tips = (a.rpc("getbestblockhash"), b.rpc("getbestblockhash"))
                pools = (sorted(a.rpc("getrawmempool")), sorted(b.rpc("getrawmempool")))
            except RuntimeError:
                time.sleep(0.5)
                continue
            if tips[0] == tips[1] and pools[0] == pools[1]:
                return True
            steady = steady + 1 if (tips, pools) == last else 0
            last = (tips, pools)
            # 8 s with nothing new: divid can take a few seconds to relay
            if tips[0] == tips[1] and steady >= 16:
                return True
            time.sleep(0.5)
        return False


def counted(out):
    return ("ok", len(out[1])) if out[0] == "ok" else out


def snapshot(node):
    """What is compared between the pairs, for one node"""
    def amounts(items):
        return sorted(str(u["amount"]) for u in items)
    unspent = node.call("listunspent", 0)
    locked = node.call("listlockunspent")
    info = node.call("getwalletinfo")
    wallet = info[1] if info[0] == "ok" else {}
    return {
        "immature balance": wallet.get("immature_balance"),
        "keypoolsize": wallet.get("keypoolsize"),
        "encryption status": wallet.get("encryption_status"),
        # unlocked_until is a time: compared as whether it is set and not past
        "unlocked_until set": None if "unlocked_until" not in wallet else bool(wallet["unlocked_until"]),
        "height": node.call("getblockcount"),
        "getbalance * 0": node.call("getbalance", "*", 0),
        "getbalance * 1": node.call("getbalance", "*", 1),
        "getunconfirmedbalance": node.call("getunconfirmedbalance"),
        "listunspent 0 amounts": ("ok", amounts(unspent[1])) if unspent[0] == "ok" else unspent,
        "locked coins": ("ok", len(locked[1])) if locked[0] == "ok" else locked,
        "mempool size": counted(node.call("getrawmempool")),
    }


def outcome(out):
    """A step's outcome without keys or hashes: ok, or the error code"""
    if out[0] == "ok":
        return "ok"
    if out[0] == "down":
        return "down"
    # the message goes along for the FAIL line; only the code is compared
    return f"error {out[1]}: {str(out[2])[:200]}"


def code_only(text):
    """An outcome as compared: the error codes without their messages"""
    import re
    return re.sub(r"(error -?\d+): [^/]*", r"\1", text)


# --- steps -------------------------------------------------------------------------------

AMOUNTS = ("dust", "tiny", "small", "large", "whole", "whole sweep_funds", "small receiver_pays")
PASSPHRASE = secrets.token_hex(16)
KEYPOOL = 5
# A salt made fresh for the run: the keys importprivkey steps import are
# derived from it and the step number, so both pairs import the same
# throwaway key; it is never printed
KEY_SALT = secrets.token_bytes(32)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def step_key(i):
    """The compressed regtest WIF (prefix 239, chainparams.cpp, testnet's) of
    the key a step imports"""
    secret = hashlib.sha256(KEY_SALT + i.to_bytes(4, "little")).digest()
    data = bytes([239]) + secret + b"\x01"
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return out


# The nodes (1, 2) whose encryptwallet step has run: a later episode encrypts
# them at its setup, so the wallet states go on as the steps left them. A
# replay takes the set its episode started with from RANDOM_SEQUENCES_ENCRYPTED
ENCRYPTED = {int(n) for n in os.environ.get("RANDOM_SEQUENCES_ENCRYPTED", "").split(",") if n}
episode_encrypted = set()  # ENCRYPTED when the current episode started


def amount_args(pair, n, kind, draw):
    """sendtoaddress amount (and fee mode) of a kind; draw is the step's
    random number for the amount"""
    node = pair.node(n)
    if kind == "dust":
        return ["0.00000100"]
    if kind == "tiny":
        return ["0.00010000"]
    if kind == "small":
        return [f"{0.1 + draw % 2000 / 100:.8f}"]
    if kind == "small receiver_pays":
        return [f"{0.1 + draw % 2000 / 100:.8f}", "receiver_pays"]
    if kind == "large":
        return [f"{100 + draw % 2500:.8f}"]
    whole = node.rpc("getbalance", "*", 1)
    if kind == "whole":
        return [whole]
    return [whole, "sweep_funds"]


def as_number(args):
    """The amount as JSON number text is what both read; json.dumps of a str
    would send a string, so amounts go as floats with 8 decimals"""
    out = [float(args[0])]
    return out + args[1:]


def coin_at(node, draw, minconf=1):
    coins = node.call("listunspent", minconf)
    if coins[0] != "ok":
        return None
    usable = sorted((u for u in coins[1] if u.get("spendable", True)),
                    key=lambda u: (str(u["amount"]).rjust(20, "0"), u["confirmations"]))
    if not usable:
        return None
    return usable[draw % len(usable)]


def sent(pair, node, out):
    """Remember the transaction a wallet send made, for the coin-choice check"""
    if out[0] == "ok":
        pair.last_tx = (node, out[1])
    return outcome(out)


def input_values(node, txid):
    """The values of the coins a wallet transaction spends, smallest first"""
    tx = node.rpc("decoderawtransaction", node.rpc("gettransaction", txid)["hex"])
    values = []
    for i in tx["vin"]:
        prev = node.rpc("decoderawtransaction", node.rpc("gettransaction", i["txid"])["hex"])
        values.append(str(prev["vout"][i["vout"]]["value"]))
    return sorted(values, key=float)


TRACE = os.environ.get("RANDOM_SEQUENCES_TRACE", "") == "1"
# The middle of an invalidate, for chasing a difference there:
# RANDOM_SEQUENCES_MID_TRACE=1 logs each side's mempool (txids) with a time,
# before the invalidate, when it returns, at the read and for 4 s after;
# RANDOM_SEQUENCES_MID_DELAY=<s> waits that long between the return and the
# read; RANDOM_SEQUENCES_MID_BARRIER=1 makes the two pairs read together
MID_TRACE = os.environ.get("RANDOM_SEQUENCES_MID_TRACE", "") == "1"
MID_DELAY = float(os.environ.get("RANDOM_SEQUENCES_MID_DELAY") or 0)
MID_BARRIER = threading.Barrier(2) if os.environ.get("RANDOM_SEQUENCES_MID_BARRIER", "") == "1" else None
T0 = time.monotonic()


def mid_trace(pair, node, when):
    if not MID_TRACE:
        return
    pool = node.call("getrawmempool")
    ids = sorted(t[:8] for t in pool[1]) if pool[0] == "ok" else pool
    log(f"#   mid {time.monotonic() - T0:9.3f} {pair.name} {node.name} {when}: "
        f"height {node.call('getblockcount')[1]} pool {ids}")


def trace_mempool(pair, node, when):
    """With RANDOM_SEQUENCES_TRACE=1: node's mempool, each transaction with its
    inputs (txid:vout, height of the block holding them, generated or not) and
    its outputs, logged"""
    if not TRACE:
        return
    pool = node.call("getrawmempool")
    log(f"#   trace {pair.name} {node.name} {when}: height {node.rpc('getblockcount')}, mempool {pool[1] if pool[0] == 'ok' else pool}")
    for txid in pool[1] if pool[0] == "ok" else []:
        tx = node.call("getrawtransaction", txid, 1)
        if tx[0] != "ok":
            continue
        ins = []
        for i in tx[1]["vin"]:
            prev = node.call("getrawtransaction", i.get("txid", ""), 1)
            where, kind = "?", "?"
            if prev[0] == "ok":
                p = prev[1]
                kind = "coinbase" if "coinbase" in p["vin"][0] else (
                    "coinstake" if len(p["vout"]) > 1 and p["vout"][0]["value"] in ("0.00000000", "0.0", 0) else "tx")
                # divid's getblockheader gives no height: from the confirmations
                where = node.rpc("getblockcount") - p["confirmations"] + 1 if p.get("confirmations") else "mempool"
            ins.append(f"{i.get('txid', '')[:12]}:{i.get('vout')}@{where}/{kind}")
        log(f"#     {txid[:12]} in {ins} out {[o['value'] for o in tx[1]['vout']]}")


def run_step(pair, step):
    """Apply one step to one pair; returns (outcome, extra) where extra holds
    what is compared besides the snapshots"""
    kind, n, draw = step["kind"], step["node"], step["draw"]
    node, other = pair.node(n), pair.other(n)
    i = step["i"]
    if kind == "getnewaddress":
        out = node.call("getnewaddress")
        if out[0] == "ok":
            pair.addresses[i] = out[1]
        return outcome(out), None
    if kind in ("send own", "send other"):
        target = (node if kind == "send own" else other).rpc("getnewaddress")
        args = as_number(amount_args(pair, n, step["amount"], draw))
        return sent(pair, node, node.call("sendtoaddress", target, *args)), None
    if kind == "sendmany":
        to_own, to_other = node.rpc("getnewaddress"), other.rpc("getnewaddress")
        a = 0.5 + draw % 1000 / 100
        return sent(pair, node, node.call("sendmany", "", {to_own: round(a, 8), to_other: round(a * 2, 8)})), None
    if kind == "lock":
        coin = coin_at(node, draw, 0)
        if coin is None:
            return "no coin", None
        o = {"txid": coin["txid"], "vout": coin["vout"]}
        out = node.call("lockunspent", False, [o])
        if out[0] == "ok" and o not in pair.lock_order[n]:
            pair.lock_order[n].append(o)
        return outcome(out), None
    if kind == "unlock one":
        # the coins still locked, in the order the steps locked them (the
        # txids differ between the pairs)
        locked = node.rpc("listlockunspent")
        order = [o for o in pair.lock_order[n] if o in locked]
        if not order:
            return "none locked", None
        o = order[draw % len(order)]
        pair.lock_order[n].remove(o)
        return outcome(node.call("lockunspent", True, [o])), None
    if kind == "unlock all":
        pair.lock_order[n] = []
        return outcome(node.call("lockunspent", True)), None
    if kind == "fundvault":
        owner, manager = node.rpc("getnewaddress"), other.rpc("getnewaddress")
        out = node.call("fundvault", f"{owner}:{manager}", float(f"{1 + draw % 50:.8f}"))
        sent(pair, node, ("ok", out[1]["txhash"]) if out[0] == "ok" else out)
        if out[0] == "ok":
            pair.vault_funded[n].append(i)
        return outcome(out), None
    if kind == "reclaim":
        dest = node.rpc("getnewaddress")
        return sent(pair, node, node.call("reclaimvaultfunds", dest, float(f"{0.5 + draw % 20:.8f}"))), None
    if kind == "mine":
        h0 = node.rpc("getblockcount")
        before, locks = node.call("listunspent", 0), node.call("listlockunspent")
        result = outcome(node.call("setgenerate", 1 + draw % 3))
        pair.stake = stake_kernels(node, h0, before, locks)
        return result, None
    if kind == "invalidate":
        depth = 1 + draw % 3
        height = node.rpc("getblockcount")
        if height - depth + 1 < 1:
            return "too low", None
        target = node.rpc("getblockhash", height - depth + 1)
        trace_mempool(pair, node, f"before invalidateblock of {height - depth + 1}")
        pair.pool_before = pool_inputs(node)
        # the transactions of the blocks about to be disconnected, but their
        # coinbases and coinstakes, which no node puts back in its mempool
        block_txs = []
        for h in range(height - depth + 1, height + 1):
            txs = node.rpc("getblock", node.rpc("getblockhash", h))["tx"]
            block_txs += [t for t in txs[1:] if not is_coinstake(pair, t)]
        mid_trace(pair, node, "before")
        mid_trace(pair, other, "before (other)")
        if MID_TRACE:
            log(f"#   mid {pair.name} disconnects {[t[:8] for t in block_txs]}")
        first = node.call("invalidateblock", target)
        mid_trace(pair, node, "returned")
        trace_mempool(pair, node, f"after invalidateblock of {height - depth + 1}")
        if MID_DELAY:
            time.sleep(MID_DELAY)
        if MID_BARRIER:
            try:
                MID_BARRIER.wait(60)
            except threading.BrokenBarrierError:
                MID_BARRIER.reset()
        mid = snapshot(node)
        mid_pool = node.call("getrawmempool")
        if MID_TRACE:
            log(f"#   mid {time.monotonic() - T0:9.3f} {pair.name} {node.name} read: size "
                f"{mid['mempool size']} pool {sorted(t[:8] for t in mid_pool[1]) if mid_pool[0] == 'ok' else mid_pool}")
            for d in (0.2, 0.5, 1, 2, 4):
                time.sleep(d - (0 if d == 0.2 else {0.5: 0.2, 1: 0.5, 2: 1, 4: 2}[d]))
                mid_trace(pair, node, f"+{d} s")
            mid_trace(pair, other, "+4 s (other)")
        pair.reorg = {"mid": height - depth, "block_txs": block_txs,
                      "mid_pool": set(mid_pool[1]) if mid_pool[0] == "ok" else None}
        # the coins in full, printed with a FAIL but not compared
        coins = node.call("listunspent", 0)
        mid["_coins (amount, confirmations)"] = sorted(
            (str(u["amount"]), u["confirmations"]) for u in coins[1]) if coins[0] == "ok" else coins
        second = node.call("reconsiderblock", target)
        # node n dropped its peer's spends of coins immature in the middle,
        # and a node restarted in the episode lacks its peer's sends: each
        # comes back only by the peer's random mempool rebroadcast (divid
        # main.cpp:1280-1294, irondivid rebroadcast.rs), which lands before
        # the end read on one side and after it on the other. Offer them now,
        # as that rebroadcast would (README, "Fixed rows")
        offer_missing(pair)
        return f"{outcome(first)}/{outcome(second)}", mid
    if kind in ("restart", "kill"):
        pair.restarted.add(n)
    if kind == "restart":
        node.stop()
        node.start()
        return "ok", None
    if kind == "kill":
        node.kill()
        try:
            node.start()
        except RuntimeError as e:
            # divid's block index is not on disk after a kill: it refuses to
            # start until -reindex (BlockIndexLoading.cpp:275, init.cpp:1082),
            # the recovery it asks for; irondivid starts without it
            # (or it aborts while loading the block index); -reindex is the
            # recovery for both
            if node.binary != DIVID:
                raise
            node.start("-reindex")
            pair.note = "divid started again with -reindex after the kill (BlockIndexLoading.cpp:275)"
        return "ok", None
    if kind == "walletlock":
        return outcome(node.call("walletlock")), None
    if kind == "walletpassphrase":
        return outcome(node.call("walletpassphrase", PASSPHRASE, 99999)), None
    if kind == "walletpassphrase timeout":
        # long enough not to run out within a step and its settle
        return outcome(node.call("walletpassphrase", PASSPHRASE, 120 + draw % 600)), None
    if kind == "walletpassphrase staking":
        return outcome(node.call("walletpassphrase", PASSPHRASE, 99999, True)), None
    if kind == "encryptwallet":
        out = node.call("encryptwallet", PASSPHRASE)
        ENCRYPTED.add(n)
        # then a restart, as the brief of a wallet encryption asks
        pair.restarted.add(n)
        if node.call("getblockcount")[0] == "down":
            node.proc.wait(timeout=120)
        else:
            node.stop()
        node.start()
        return outcome(out), None
    if kind == "keypoolrefill":
        return outcome(node.call("keypoolrefill", 1 + draw % (2 * KEYPOOL))), None
    if kind in ("drain getnewaddress", "drain getrawchangeaddress"):
        # until the keypool runs out, or 3 keypools' worth (an unlocked
        # wallet tops it up each time)
        method = kind.split()[1]
        for count in range(1, 3 * KEYPOOL + 1):
            out = node.call(method)
            if out[0] != "ok":
                return f"{outcome(out)} at call {count}", None
        return f"ok x{3 * KEYPOOL}", None
    if kind == "importprivkey":
        rescan = draw % 2 == 0

        def imported_now():
            out = node.call("getaddressesbyaccount", "imported")
            return set(out[1]) if out[0] == "ok" else set()
        before = imported_now()
        out = node.call("importprivkey", step_key(i), "imported", rescan)
        new = imported_now() - before
        if out[0] == "ok" and len(new) == 1:
            pair.imported[n].append(new.pop())
        return outcome(out), None
    if kind == "send imported":
        # to a key an importprivkey step of this node brought in
        if not pair.imported[n]:
            return "nothing imported", None
        target = pair.imported[n][draw % len(pair.imported[n])]
        args = as_number(amount_args(pair, n, "small", draw))
        return sent(pair, node, node.call("sendtoaddress", target, *args)), None
    if kind == "generateblock":
        h0 = node.rpc("getblockcount")
        before, locks = node.call("listunspent", 0), node.call("listlockunspent")
        result = outcome(node.call("generateblock", {}))
        pair.stake = stake_kernels(node, h0, before, locks)
        return result, None
    if kind == "rawtx":
        coin = coin_at(node, draw)
        if coin is None:
            return "no coin", None
        if any(o["txid"] == coin["txid"] and o["vout"] == coin["vout"] for o in node.rpc("listlockunspent")):
            return "coin locked", None
        value = float(coin["amount"]) - 0.001
        if value <= 0:
            return "coin too small", None
        # to its own wallet: what leaves is the fee alone, whichever coin it is
        raw = node.call("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}],
                        {node.rpc("getnewaddress"): round(value, 8)})
        if raw[0] != "ok":
            return "createrawtransaction " + outcome(raw), None
        signed = node.call("signrawtransaction", raw[1])
        if signed[0] != "ok":
            return "signrawtransaction " + outcome(signed), None
        if not signed[1].get("complete"):
            return "signrawtransaction incomplete", None
        return "sendrawtransaction " + outcome(node.call("sendrawtransaction", signed[1]["hex"])), None
    raise ValueError(kind)


# Each kind with its weight in the draw
KINDS = [
    ("getnewaddress", 4), ("send own", 10), ("send other", 10), ("sendmany", 5), ("lock", 6),
    ("unlock one", 3), ("unlock all", 2), ("fundvault", 4), ("reclaim", 3), ("mine", 14),
    ("invalidate", 5), ("restart", 3), ("kill", 2), ("walletlock", 4), ("walletpassphrase", 4),
    ("rawtx", 5),
    # wallet states: unlocks, the keypool, imported keys, generateblock
    ("walletpassphrase timeout", 2), ("walletpassphrase staking", 3), ("keypoolrefill", 2),
    ("drain getnewaddress", 2), ("drain getrawchangeaddress", 2), ("importprivkey", 3),
    ("send imported", 3), ("generateblock", 3),
]


def draw_steps(seed, count):
    rng = random.Random(seed)
    names = [k for k, _ in KINDS]
    weights = [w for _, w in KINDS]
    steps = []
    for i in range(1, count + 1):
        kind = rng.choices(names, weights)[0]
        step = {"i": i, "kind": kind, "node": rng.choice((1, 2)), "draw": rng.randrange(1 << 30)}
        if kind in ("send own", "send other"):
            step["amount"] = rng.choice(AMOUNTS)
        steps.append(step)
    # Each node's wallet is encrypted once, at a step drawn from the seed
    for n in (1, 2):
        at = rng.randrange(count)
        while steps[at]["kind"] == "encryptwallet":
            at = (at + 1) % count
        steps[at] = {"i": steps[at]["i"], "kind": "encryptwallet", "node": n, "draw": steps[at]["draw"]}
    return steps


# --- the run -----------------------------------------------------------------------------

def setup_failed(kind, value, tb):
    log(f"FAIL   setup: {value}"[:600])
    log("FAILS 1")
    sys.exit(1)


sys.excepthook = setup_failed

MATURITY = 20  # regtest coinbase and coinstake maturity, both nodes
PAIRS = []
episode = 0


def both(fn):
    with ThreadPoolExecutor(2) as ex:
        return list(ex.map(fn, PAIRS))


def setup(pair):
    a, b = pair.nodes
    for node, blocks in ((a, 15), (b, 15), (a, 25)):
        node.rpc("setgenerate", blocks)
        if not pair.settle():
            raise RuntimeError(f"{pair.name} pair did not settle after the first blocks")
    # A wallet whose encryptwallet step has run (in an earlier episode) is
    # encrypted again and unlocked
    for n, node in ((1, a), (2, b)):
        if n in ENCRYPTED:
            node.rpc("encryptwallet", PASSPHRASE)
            wait_for(lambda: node.call("getwalletinfo")[0] == "ok", 60)
            node.rpc("walletpassphrase", PASSPHRASE, 99999)
    return True


def keep_logs(tag):
    """Copy the four debug.logs to LOGS, when set"""
    if not LOGS:
        return
    import shutil
    os.makedirs(LOGS, exist_ok=True)
    for pair in PAIRS:
        for node in pair.nodes:
            for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
                if os.path.exists(path):
                    shutil.copy(path, os.path.join(LOGS, f"{node.name}-{tag}.log"))


def new_episode():
    """Four fresh nodes and their first blocks: the start of the run, and the
    restart after an accidental difference of divid's (see EXPLAINED)"""
    global PAIRS, episode, episode_encrypted
    keep_logs(f"episode{episode}")
    for pair in PAIRS:
        for node in pair.nodes:
            node.stop()
    if PAIRS:
        import shutil
        for name in ("divid1", "divid2", "irondivid1", "irondivid2"):
            shutil.rmtree(os.path.join(WORK, name), ignore_errors=True)
    episode += 1
    episode_encrypted = set(ENCRYPTED)
    c1 = Node("divid1", DIVID, 0, ["listen=1"] + CORE_DEBUG)
    c2 = Node("divid2", DIVID, 1, ["listen=0", f"connect={HOST}:{PORT_BASE}"] + CORE_DEBUG)
    phrases = [c1.rpc("dumphdinfo")["mnemonic"], c2.rpc("dumphdinfo")["mnemonic"]]
    if TWIN:
        # divid against divid: the second pair restores the phrases from
        # -mnemonic (init.cpp:877), a line of its 0600 divi.conf
        i1 = Node("irondivid1", IRONDIVID, 2, ["listen=1", f"mnemonic={phrases[0]}"] + CORE_DEBUG)
        i2 = Node("irondivid2", IRONDIVID, 3, ["listen=0", f"connect={HOST}:{PORT_BASE + 4}",
                                               f"mnemonic={phrases[1]}"] + CORE_DEBUG)
        # divid reads -mnemonic at every start, not only when it makes the
        # wallet: the line goes once the wallet is there
        for node in (i1, i2):
            conf = os.path.join(node.dir, "divi.conf")
            with open(conf) as f:
                kept = [line for line in f if not line.startswith("mnemonic=")]
            with open(conf, "w") as f:
                f.writelines(kept)
    else:
        i1 = Node("irondivid1", IRONDIVID, 2, ["listen=1"] + IRON_DEBUG, env={"WALLET_MNEMONIC": phrases[0]})
        i2 = Node("irondivid2", IRONDIVID, 3, ["listen=0", f"connect={HOST}:{PORT_BASE + 4}"] + IRON_DEBUG,
                  env={"WALLET_MNEMONIC": phrases[1]})
    del phrases
    PAIRS = [Pair("divid", [c1, c2]), Pair("irondivid", [i1, i2])]
    both(setup)
    log(f"# episode {episode}: four fresh nodes")


def differs(a, b):
    """The compared keys whose values differ (a key starting with _ is detail)"""
    return [k for k in a if not k.startswith("_") and a[k] != b.get(k)]


# Differences that come from divid's accidental choices, not from a fault:
# after one, the two sides' coins are no longer alike, so the run goes on with
# four fresh nodes (a new episode) and the remaining steps.
EXPLAINED = {
    "coin choice": (
        "divid ranks coins that each cover a send by signature size alone "
        "(MinimumFeeCoinSelectionAlgorithm.cpp:127-139), so among them it takes the first in its "
        "wallet map, ordered by txid; the two pairs' txids differ, so each side spent one coin, of a "
        "different value"),
    "rebroadcast timing": (
        "after the restart each side's restarted node holds only transactions its peer holds too: "
        "divid sends some mempool transactions to its peers again at a random time within 30 minutes "
        "(PeriodicallyRebroadcastMempoolTxs, main.cpp:1280-1294), so whether the restarted node has "
        "the peer's transactions back by now is chance"),
    "divid balance cache": (
        "divid's getbalance disagrees with its own unspent coins (listunspent 1) while irondivid's agrees "
        "with the same coins: divid keeps each wallet transaction's balance in CachedUtxoBalanceCalculator "
        "(CachedUtxoBalanceCalculator.cpp:13-30), recomputed only when a wallet transaction spending it is "
        "added (wallet.cpp:1242-1333), so a spend the mempool drops (removeCoinbaseSpends, "
        "txmempool.cpp:139-157) still counts as spending the coin"),
    "divid reindex after a kill": (
        "divid had to start again with -reindex after the kill; its reindex runs on a thread of its own "
        "(init.cpp:1580) while its wallet's unconfirmed transactions are offered to the mempool at the end "
        "of the start (init.cpp:1646), before the chain is rebuilt, so they are refused and the wallet "
        "counts their inputs unspent; irondivid starts without -reindex and keeps them"),
    "divid wallet after a kill": (
        "after the kill divid's restarted node has fewer transactions or blocks than irondivid's: divid writes "
        "its wallet to disk 2 s after the last change (ThreadFlushWalletDB, "
        "LegacyWalletDatabaseEndpointFactory.cpp:23-50) and its chain state when it flushes (FlushStateToDisk), "
        "so what came just before a kill -9 is lost and has to come again from its peer; irondivid stores a "
        "send before the RPC that made it answers"),
    "maturity window": (
        "only the middle of the invalidate differs, by one or two coins of one value: the two sides had "
        "spent different coins of that value (divid's choice among equal coins is by txid order), and with "
        "the tip lowered one of them sits in the block between the mempool's coinbase maturity (20, "
        "txmempool.cpp:151) and the wallet's (21, MerkleTxConfirmationNumberCalculator.cpp:54-59)"),
    "divid loses a key imported into an encrypted wallet": (
        "divid no longer holds a key importprivkey brought into its encrypted wallet, and irondivid does: "
        "CWallet::AddKeyPubKey writes a key to the wallet file only when the wallet is not encrypted "
        "(wallet.cpp:611-613); on an encrypted one CCryptoKeyStore::AddCryptedKey keeps it in memory alone "
        "(crypter.cpp:295-305), so the next start no longer has it, nor the coins paid to it. irondivid "
        "stores the key"),
    "stake coin choice": (
        "each side staked, in each new block, a coin of its stake set (CWallet::SelectStakeCoins, "
        "wallet.cpp:1433-1465); divid tries the set in outpoint order (StakableCoin.h:21-24, "
        "PoSTransactionCreator.cpp:261, shuffled only with -vault, :63-72, :99) and takes the first coin with a "
        "kernel hash under the target, which is weighted by the coin's value (ProofOfStakeCalculator.cpp:19-24, "
        ":53-54); the two pairs' txids differ, so the coins staked differ in value, and a coinstake's outputs are "
        "immature"),
    "maturity in the middle of a reorg": (
        "only the middle of the invalidate differs: while its tip was lowered, one side dropped transactions that "
        "spend a coinbase or coinstake output immature at that height, or an output of one that does, which "
        "divid's removeCoinbaseSpends drops with their descendants (txmempool.cpp:139-157, :91-126); the other "
        "side had spent an older coin of the same value (divid's coin choice among equal coins is by txid order); "
        "reconsiderblock confirms them again, so the end states agree"),
    "maturity after a reorg": (
        "after invalidateblock the dropped mempool transactions all spend a coinbase or coinstake "
        "output that is immature at the new height, which divid's removeCoinbaseSpends drops too "
        "(txmempool.cpp:139-157); the other side spent an older coin of the same value, divid's coin "
        "choice among equal coins being by txid order (MinimumFeeCoinSelectionAlgorithm.cpp:127-139)"),
}


def lost_imported_key():
    """divid's node no longer holds an address an importprivkey step of this
    episode brought in, while irondivid's still does"""
    for m in (1, 2):
        for address in PAIRS[1].imported[m]:
            c = PAIRS[0].node(m).call("validateaddress", address)
            i = PAIRS[1].node(m).call("validateaddress", address)
            if c[0] == i[0] == "ok" and not c[1].get("ismine") and i[1].get("ismine"):
                return True
    return False


def vault_output(node, outpoint):
    """The value of a vault output the wallet holds (listunspent leaves vault
    coins out, but they are in divid's stake set), or None"""
    tx = node.call("gettransaction", outpoint[0])
    if tx[0] != "ok":
        return None
    decoded = node.call("decoderawtransaction", tx[1]["hex"])
    if decoded[0] != "ok" or not 0 <= outpoint[1] < len(decoded[1]["vout"]):
        return None
    out = decoded[1]["vout"][outpoint[1]]
    return str(out["value"]) if out.get("scriptPubKey", {}).get("type") == "vault" else None


def matured_in_step(node, outpoint, h, tip):
    """The value of the wallet's coinbase or coinstake output that was not
    mature (to be listed) when the step began but is by block h: divid counts
    a generated coin from MATURITY + 1 confirmations (GetBlocksToMaturity,
    MerkleTxConfirmationNumberCalculator.cpp:54-59) at the tip block h is
    made on. Or None"""
    tx = node.call("gettransaction", outpoint[0])
    if tx[0] != "ok" or not tx[1].get("generated"):
        return None
    depth = tx[1].get("confirmations", 0) - (tip - (h - 1))
    if depth < MATURITY + 1:
        return None
    decoded = node.call("decoderawtransaction", tx[1]["hex"])
    if decoded[0] != "ok" or not 0 <= outpoint[1] < len(decoded[1]["vout"]):
        return None
    return str(decoded[1]["vout"][outpoint[1]]["value"])


def coin_detail(node, outpoint):
    """What the node says of an outpoint: its transaction's confirmations and
    kind, and the output's value and script type"""
    tx = node.call("gettransaction", outpoint[0])
    if tx[0] != "ok":
        return f"{outpoint[0][:12]}:{outpoint[1]} unknown to the wallet ({tx[1:]})"[:200]
    decoded = node.call("decoderawtransaction", tx[1]["hex"])
    out = decoded[1]["vout"][outpoint[1]] if decoded[0] == "ok" and outpoint[1] < len(decoded[1]["vout"]) else {}
    return (f"{outpoint[0][:12]}:{outpoint[1]} confirmations {tx[1].get('confirmations')} "
            f"generated {tx[1].get('generated', False)} value {out.get('value')} "
            f"type {out.get('scriptPubKey', {}).get('type')}")


def stake_kernels(node, h0, before, locks):
    """The coin each stake block of a mine or generateblock step staked (its coinstake's first
    input), and whether each is a coin of divid's stake set: one of the
    wallet's coins that is unlocked, has 10 confirmations at that block, and
    no earlier block of the step spent, or a vault output it holds. The set
    is the coins of CWallet::SelectStakeCoins (wallet.cpp:1433-1465): depth 10
    (a coinstake output's is already mature to be listed), no coin age on
    regtest (chainparams.cpp:498). Which coin of the set is staked is not
    checked: divid tries the set in outpoint order (StakableCoin.h:21-24,
    PoSTransactionCreator.cpp:261; shuffled only with -vault, :63-72, :99),
    and a coin is passed over when no timestamp tried gives it a kernel hash
    under the target, which is weighted by the coin's value
    (ProofOfStakeCalculator.cpp:19-24, :53-54). None when no stake block was
    made"""
    if before[0] != "ok" or locks[0] != "ok":
        return None
    locked = {(o["txid"], o["vout"]) for o in locks[1]}
    listed = {(u["txid"], u["vout"]): u for u in before[1]}
    used, kernels, rule, misses = set(), [], True, []
    try:
        tip = node.rpc("getblockcount")
        for h in range(h0 + 1, tip + 1):
            block = node.rpc("getblock", node.rpc("getblockhash", h))
            if len(block["tx"]) < 2:
                continue  # a work block
            stake = node.call("gettransaction", block["tx"][1])
            if stake[0] != "ok":
                continue  # not the wallet's: a work block with others' transactions
            decoded = node.rpc("decoderawtransaction", stake[1]["hex"])
            if not decoded["vout"] or float(decoded["vout"][0]["value"]) != 0:
                continue  # a work block with transactions: no coinstake
            vin = decoded["vin"]
            kernel = (vin[0].get("txid"), vin[0].get("vout"))
            coin = listed.get(kernel)
            if coin is not None:
                # the coin's depth when block h was made on block h - 1
                depth = coin["confirmations"] + (h - 1 - h0)
                value = str(coin["amount"])
                why = ("locked" if kernel in locked else "spent earlier in the step" if kernel in used
                       else f"at depth {depth}" if depth < 10 else None)
            else:
                value = vault_output(node, kernel) or matured_in_step(node, kernel, h, tip)
                why = "spent earlier in the step" if value is not None and kernel in used else None
                if value is None:
                    why = f"not a listed coin or vault output of the wallet: {coin_detail(node, kernel)}"
                elif kernel in locked:
                    why = "locked"
            if why:
                rule = False
                misses.append(f"block {h}: staked {value or '?'}, {why}")
            used.update((v.get("txid"), v.get("vout")) for v in vin)
            kernels.append(value or "?")
    except RuntimeError:
        return None
    return {"rule": rule, "kernels": kernels, "misses": misses, "locked": len(locked)} if kernels else None


def stake_choice_explains(n, diff):
    """A mine or generateblock step after which only node n's balances and
    coins differ, with its balance plus immature balance the same on both
    sides, where on both sides each stake block staked a coin of divid's stake
    set (stake_kernels), and the coins staked differ in value"""
    stakes = [p.stake for p in PAIRS]
    log(f"#   stake rule: divid {stakes[0]}, irondivid {stakes[1]}"[:1500])
    if None in stakes or not all(s["rule"] for s in stakes):
        return False
    if stakes[0]["kernels"] == stakes[1]["kernels"]:
        return False
    allowed = {f"node {n}: {k}" for k in ("getbalance * 0", "getbalance * 1", "listunspent 0 amounts",
                                          "immature balance")}
    if not all(k in allowed for k in diff):
        return False
    totals = []
    for pair in PAIRS:
        info, balance = pair.node(n).call("getwalletinfo"), pair.node(n).call("getbalance", "*", 0)
        if info[0] != "ok" or balance[0] != "ok":
            return False
        totals.append(round(float(balance[1]) + float(info[1].get("immature_balance", 0)), 8))
    return totals[0] == totals[1]


def coin_choice_differs():
    """Both sides made one send, each spending one coin, of different values"""
    txs = [p.last_tx for p in PAIRS]
    if None in txs:
        return False
    try:
        spent = [input_values(node, txid) for node, txid in txs]
    except RuntimeError:
        return False
    return len(spent[0]) == len(spent[1]) == 1 and spent[0] != spent[1]


def pool_inputs(node):
    """Each transaction of node's mempool with the outpoints it spends"""
    out = {}
    pool = node.call("getrawmempool")
    for txid in pool[1] if pool[0] == "ok" else []:
        tx = node.call("getrawtransaction", txid, 1)
        if tx[0] == "ok":
            out[txid] = [(i.get("txid", ""), i.get("vout")) for i in tx[1]["vin"]]
    return out


def spends_immature(pair, holder, txid, next_height, inputs=None):
    """Whether the transaction (in `holder`'s mempool, or with `inputs` given)
    spends a coinbase or coinstake output, of either wallet of the pair,
    immature at `next_height`"""
    if inputs is None:
        tx = holder.call("getrawtransaction", txid, 1)
        if tx[0] != "ok":
            return False
        inputs = [(i.get("txid", ""), i.get("vout")) for i in tx[1]["vin"]]
    for prev_txid, _ in inputs:
        for wallet in pair.nodes:
            prev = wallet.call("gettransaction", prev_txid)
            if prev[0] == "ok" and prev[1].get("generated") and prev[1].get("confirmations", 0) > 0:
                height = wallet.rpc("getblockcount") - prev[1]["confirmations"] + 1
                if next_height - height < MATURITY:
                    return True
                break
    return False


def offer_missing(pair):
    """Each node of the pair is sent the transactions of its peer's mempool
    it lacks, parents first, as the peer's mempool rebroadcast does"""
    for node, peer in (pair.nodes, pair.nodes[::-1]):
        mine, theirs = node.call("getrawmempool"), peer.call("getrawmempool")
        if mine[0] != "ok" or theirs[0] != "ok":
            continue
        todo = [t for t in theirs[1] if t not in mine[1]]
        # a child is refused until its parent is in: pass again while one gets in
        while todo:
            left = []
            for txid in todo:
                raw = peer.call("getrawtransaction", txid)
                if raw[0] != "ok" or node.call("sendrawtransaction", raw[1])[0] != "ok":
                    left.append(txid)
            if len(left) == len(todo):
                break
            todo = left


def wallet_inputs(pair, txid):
    """The outpoints a transaction of one of the pair's wallets spends, or None"""
    for wallet in pair.nodes:
        tx = wallet.call("gettransaction", txid)
        if tx[0] == "ok":
            decoded = wallet.call("decoderawtransaction", tx[1]["hex"])
            if decoded[0] == "ok":
                return [(i.get("txid", ""), i.get("vout")) for i in decoded[1]["vin"]]
    return None


def is_coinstake(pair, txid):
    """A coinstake of one of the pair's wallets: its first output is empty"""
    for wallet in pair.nodes:
        tx = wallet.call("gettransaction", txid)
        if tx[0] == "ok":
            decoded = wallet.call("decoderawtransaction", tx[1]["hex"])
            return decoded[0] == "ok" and bool(decoded[1]["vout"]) and float(decoded[1]["vout"][0]["value"]) == 0
    return False


def mid_maturity_explains(n, diff):
    """Only the middle of an invalidate differs (the end states agree), in
    balances, coins and the mempool's size. On each side every transaction
    node n lost while its tip was lowered (from the disconnected blocks or its
    mempool before) spends a coin immature at the height after the one left,
    or an output of a disconnected transaction that does; divid drops these
    (removeCoinbaseSpends, txmempool.cpp:139-157, with their descendants,
    :91-126), and reconsiderblock confirms them again. The two sides lost
    different transactions: each had spent a different coin of the same
    value (divid's coin choice among equal coins is by txid order)"""
    allowed = {"after invalidateblock: " + k for k in
               ("getbalance * 0", "getbalance * 1", "getunconfirmedbalance", "listunspent 0 amounts", "mempool size",
                "immature balance")}
    if not diff or any(k not in allowed for k in diff):
        return False
    lost_values = []
    for pair in PAIRS:
        reorg = pair.reorg
        if reorg is None or reorg["mid_pool"] is None:
            return False
        next_height = reorg["mid"] + 1
        values = []
        for txid in (set(reorg["block_txs"]) | set(pair.pool_before)) - reorg["mid_pool"]:
            inputs = pair.pool_before.get(txid) or wallet_inputs(pair, txid)
            if inputs is None:
                log(f"#   mid maturity rule: {pair.name} lost {txid[:8]}, whose inputs no wallet of the pair knows")
                return False
            holder = pair.node(n)
            if not (spends_immature(pair, holder, txid, next_height, inputs)
                    or parent_spends_immature(pair, holder, txid, reorg["mid"], next_height, inputs)):
                log(f"#   mid maturity rule: {pair.name} lost {txid[:8]}, not immature at {next_height}")
                return False
            values.append(txid)
        lost_values.append(len(values))
    log(f"#   mid maturity rule: lost {lost_values}")
    return lost_values[0] != lost_values[1]


def parent_spends_immature(pair, holder, txid, mid, next_height, inputs=None):
    """Whether the transaction spends an output of one that sat in a block
    the invalidate disconnected (above `mid`, and confirmed again since) and
    itself spends a coin immature at `next_height`. divid refuses that parent
    when it puts the block's transactions back (removeCoinbaseSpends,
    txmempool.cpp:139-157) and removes its descendants from the mempool with
    it (remove(..., true), txmempool.cpp:91-126); reconsiderblock confirms
    the parent again, but the child stays gone"""
    if inputs is None:
        tx = holder.call("getrawtransaction", txid, 1)
        if tx[0] != "ok":
            return False
        inputs = [(i.get("txid", ""), i.get("vout")) for i in tx[1]["vin"]]
    for prev_txid, _ in inputs:
        for wallet in pair.nodes:
            prev = wallet.call("gettransaction", prev_txid)
            if prev[0] != "ok" or prev[1].get("confirmations", 0) <= 0:
                continue
            height = wallet.rpc("getblockcount") - prev[1]["confirmations"] + 1
            decoded = wallet.call("decoderawtransaction", prev[1]["hex"])
            if height > mid and decoded[0] == "ok" and spends_immature(
                    pair, wallet, prev_txid, next_height,
                    [(i.get("txid", ""), i.get("vout")) for i in decoded[1]["vin"]]):
                log(f"#   maturity rule: {pair.name}: {txid[:8]} spends {prev_txid[:8]} of block {height}, "
                    f"which spends a coin immature at {next_height}")
                return True
            break
    return False


def input_ages(pair, holder, txid):
    """The inputs of a transaction in `holder`'s mempool, with what the
    wallets of the pair know of each: coinbase or coinstake, confirmations"""
    tx = holder.call("getrawtransaction", txid, 1)
    if tx[0] != "ok":
        return []
    out = []
    for i in tx[1]["vin"]:
        known = None
        for wallet in pair.nodes:
            prev = wallet.call("gettransaction", i.get("txid", ""))
            if prev[0] == "ok":
                known = (bool(prev[1].get("generated")), prev[1].get("confirmations"))
                break
        out.append((f"{i.get('txid', '')[:16]}:{i.get('vout')}",) + (known or ("?", "?")))
    return out


def maturity_explains(n, mid_heights):
    """After an invalidate on node n: on each side, every transaction node n
    lacks, of those the other node holds and those node n held itself before
    the invalidate (and the chain has not confirmed since), spends a coin
    immature at the height after the one the invalidate left (`mid_heights`,
    per side), and node n holds none of those itself. Node n's own sends
    count too: the other node may never have had them (it was restarted, and
    a send reaches it again only by the random rebroadcast). A transaction
    node n lacks that spends no immature coin is allowed when node n of the
    other side lacks one with the same output values: a restarted node gets
    its peer's sends back only by that rebroadcast, on both sides alike"""
    dropped, mature = [], []
    for pair, mid in zip(PAIRS, mid_heights):
        node, other = pair.node(n), pair.other(n)
        mine, theirs = set(node.rpc("getrawmempool")), set(other.rpc("getrawmempool"))
        before = pair.pool_before
        next_height = mid + 1
        values, lacked = [], []
        for txid in (theirs | set(before)) - mine:
            known = node.call("getrawtransaction", txid, 1)
            if known[0] == "ok" and known[1].get("confirmations", 0) > 0:
                continue
            holder = other if txid in theirs else node
            inputs = None if txid in theirs else before[txid]
            tx = holder.call("getrawtransaction", txid, 1) if txid in theirs else node.call("gettransaction", txid)
            if txid in theirs:
                outs = sorted(str(o["value"]) for o in tx[1]["vout"]) if tx[0] == "ok" else []
            else:
                decoded = node.call("decoderawtransaction", tx[1]["hex"]) if tx[0] == "ok" else tx
                outs = sorted(str(o["value"]) for o in decoded[1]["vout"]) if decoded[0] == "ok" else []
            if spends_immature(pair, holder, txid, next_height, inputs) \
                    or parent_spends_immature(pair, holder, txid, mid, next_height, inputs):
                values.append(outs)
            else:
                log(f"#   maturity rule: {pair.name} node {n} lacks {txid[:8]}, not immature at {next_height}")
                lacked.append(outs)
        for txid in mine:
            if spends_immature(pair, node, txid, next_height):
                log(f"#   maturity rule: {pair.name} node {n} holds {txid[:8]}, immature at {next_height}")
                return False
        dropped.append(sorted(values))
        mature.append(sorted(lacked))
    if mature[0] != mature[1]:
        log(f"#   maturity rule: the two sides lack different transactions that spend no immature coin: {mature}")
        return False
    # explained only when the two sides dropped different transactions (each
    # spent a different coin); the same drops on both sides leave nothing to
    # explain a difference
    log(f"#   maturity rule: dropped {dropped}")
    return bool(dropped[0] or dropped[1]) and dropped[0] != dropped[1]


def confirmed_sum(node):
    """The confirmed coins getbalance counts: listunspent 1, and the locked
    coins listunspent leaves out but getbalance counts"""
    coins = node.call("listunspent", 1)
    locked = node.call("listlockunspent")
    if coins[0] != "ok" or locked[0] != "ok":
        return None
    total = sum(float(u["amount"]) for u in coins[1])
    for o in locked[1]:
        tx = node.call("gettransaction", o["txid"])
        if tx[0] != "ok" or tx[1].get("confirmations", 0) < 1:
            continue
        decoded = node.call("decoderawtransaction", tx[1]["hex"])
        if decoded[0] == "ok":
            total += float(decoded[1]["vout"][o["vout"]]["value"])
    return round(total, 8)


def balance_cache_explains():
    """On some node both sides list the same confirmed coins, divid's
    getbalance is below their sum (it counts as spent a coin that is not) and
    irondivid's is not (getbalance also counts owned vault coins, which
    listunspent leaves out, so it may be above)"""
    found = False
    for n in (1, 2):
        c, i = PAIRS[0].node(n), PAIRS[1].node(n)
        cs, is_ = confirmed_sum(c), confirmed_sum(i)
        cb, ib = c.call("getbalance"), i.call("getbalance")
        if None in (cs, is_) or cb[0] != "ok" or ib[0] != "ok":
            return False
        cb, ib = round(float(cb[1]), 8), round(float(ib[1]), 8)
        if cb == ib:
            continue
        if cs != is_ or not cb < cs or ib < is_:
            return False
        found = True
    return found


def maturity_window_explains(c_mid, i_mid, diff):
    """Only the middle of an invalidate differs, in balances and coins alone,
    with mempools of one size, and the coins differ by one or two coins of
    one value: one side spent a coin the other did not (divid's coin choice
    among equal coins is by txid order), and in the middle that coin sits in
    the block between the mempool's maturity (20, txmempool.cpp:151) and the
    wallet's (21, MerkleTxConfirmationNumberCalculator.cpp:54-59)"""
    allowed = {"after invalidateblock: " + k
               for k in ("getbalance * 0", "getbalance * 1", "listunspent 0 amounts", "immature balance")}
    if not diff or any(k not in allowed for k in diff):
        return False
    if c_mid["mempool size"] != i_mid["mempool size"]:
        return False
    # the coin moved between mature and immature: the sum is the same

    def total(mid):
        try:
            return round(float(mid["getbalance * 0"][1]) + float(mid["immature balance"]), 8)
        except (TypeError, ValueError, IndexError):
            return None
    if total(c_mid) is None or total(c_mid) != total(i_mid):
        return False
    a, b = c_mid["listunspent 0 amounts"], i_mid["listunspent 0 amounts"]
    if a[0] != "ok" or b[0] != "ok":
        return False
    from collections import Counter
    extra = (Counter(a[1]) - Counter(b[1])) + (Counter(b[1]) - Counter(a[1]))
    return len(extra) == 1 and sum(extra.values()) <= 2


def rebroadcast_explains(n):
    """After a restart of node n: on each side node n's mempool holds nothing
    its peer does not, but for transactions of the same output values on both
    sides (node n's own sends, which reach the peer again only by the same
    rebroadcast), and the two sides differ only in what node n got back"""
    extras = []
    for pair in PAIRS:
        node = pair.node(n)
        mine, theirs = node.call("getrawmempool"), pair.other(n).call("getrawmempool")
        if mine[0] != "ok" or theirs[0] != "ok":
            return False
        values = []
        for txid in set(mine[1]) - set(theirs[1]):
            tx = node.call("getrawtransaction", txid, 1)
            if tx[0] != "ok":
                return False
            values.append(sorted(str(o["value"]) for o in tx[1]["vout"]))
        extras.append(sorted(values))
    return extras[0] == extras[1]


if REPLAY:
    with open(REPLAY) as f:
        steps = json.load(f)
else:
    steps = draw_steps(SEED, STEPS)

# Fixed rows, run first on nodes of their own in every seeded run: stored
# episodes of a case the draw reaches only now and then (README, "Fixed rows")
ROWS = [] if REPLAY or os.environ.get("RANDOM_SEQUENCES_ROWS", "1") == "0" else ["mid-invalidate"]
row_steps = []
for row in ROWS:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "rows", row + ".json")) as f:
        row_steps += [dict(s, row=row) for s in json.load(f)] + [{"kind": "end of row", "row": row}]
steps = row_steps + steps

log(f"# random-sequences: SEED={SEED} STEPS={STEPS}" + (f" REPLAY={REPLAY}" if REPLAY else "")
    + (f" rows first: {', '.join(ROWS)}" if ROWS else ""))
encrypted_at_start = set(ENCRYPTED)
new_episode()
episode_steps = []
fails = 0
started = time.time()
for step in steps:
    if step["kind"] == "end of row":
        # the seeded steps start on fresh nodes, as they would without the row
        log(f"# fixed row {step['row']} done")
        ENCRYPTED.clear()
        ENCRYPTED.update(encrypted_at_start)
        new_episode()
        episode_steps = []
        continue
    spec = json.dumps(step, sort_keys=True)
    episode_steps.append(step)

    def apply(pair):
        pair.last_tx = None
        pair.note = None
        pair.pool_before = {}
        pair.stake = None
        pair.reorg = None
        try:
            result = run_step(pair, step)
        except RuntimeError as e:
            # without the node's name, which differs between the pairs
            import re
            result = ("call failed: " + re.sub(r"^(irondivid|divid)[12] ", "", str(e)))[:1500], None
        settled = pair.settle()
        return result, settled

    (c_res, c_settled), (i_res, i_settled) = both(apply)
    if INJECT and str(step["i"]) == INJECT and "row" not in step:
        i_res = ("injected", i_res[1])
    n = step["node"]
    # The two states, read again for a while if they differ: a wallet can
    # take a moment after the mempool settles
    deadline = time.time() + 15
    while True:
        snaps = [snapshot(p.node(n)) for p in PAIRS] + [snapshot(p.other(n)) for p in PAIRS]
        diff = []
        if c_res[0] != i_res[0]:
            diff.append("outcome")
        if c_res[1] is not None and i_res[1] is not None:
            diff += ["after invalidateblock: " + k for k in differs(c_res[1], i_res[1])]
        diff += [f"node {n}: {k}" for k in differs(snaps[0], snaps[1])]
        diff += [f"node {3 - n}: {k}" for k in differs(snaps[2], snaps[3])]
        if not diff or time.time() > deadline:
            break
        time.sleep(1)
    line = f"step {step['i']:>3}  {step['kind']:<16} node {n}  divid={c_res[0]}  irondivid={i_res[0]}"
    for p in PAIRS:
        if p.note:
            line += f"  [{p.note}]"
    if not c_settled or not i_settled:
        line += f"  [settled: divid {c_settled}, irondivid {i_settled}]"
    explained = None
    if diff and lost_imported_key():
        explained = "divid loses a key imported into an encrypted wallet"
    elif diff and "outcome" not in diff:
        if coin_choice_differs():
            explained = "coin choice"
        elif step["kind"] in ("mine", "generateblock") and stake_choice_explains(n, diff):
            explained = "stake coin choice"
        elif step["kind"] == "invalidate" and c_res[1] and i_res[1] \
                and c_res[1]["height"][0] == i_res[1]["height"][0] == "ok" \
                and maturity_explains(n, [c_res[1]["height"][1], i_res[1]["height"][1]]):
            explained = "maturity after a reorg"
        elif step["kind"] == "invalidate" and c_res[1] and i_res[1] \
                and maturity_window_explains(c_res[1], i_res[1], diff):
            explained = "maturity window"
        elif step["kind"] == "invalidate" and mid_maturity_explains(n, diff):
            explained = "maturity in the middle of a reorg"
        elif step["kind"] == "kill" and PAIRS[0].note:
            explained = "divid reindex after a kill"
        elif step["kind"] == "kill" and (
                counted(PAIRS[0].node(n).call("getrawmempool"))[1:] < counted(PAIRS[1].node(n).call("getrawmempool"))[1:]
                or PAIRS[0].node(n).call("getblockcount")[1:] < PAIRS[1].node(n).call("getblockcount")[1:]):
            explained = "divid wallet after a kill"
        elif all(k.split(": ")[-1].startswith("getbalance") or k == "after invalidateblock: listunspent 0 amounts"
                 or k.endswith("immature balance") for k in diff) \
                and any(not k.startswith("after") for k in diff) and balance_cache_explains():
            explained = "divid balance cache"
        else:
            # a node restarted earlier in the episode holds fewer of its peer's
            # transactions on one side than the other
            for m in (1, 2):
                if m in PAIRS[0].restarted and rebroadcast_explains(m) and all(
                        k in (f"node {m}: mempool size", f"node {m}: getunconfirmedbalance",
                              f"node {m}: listunspent 0 amounts") for k in diff):
                    explained = "rebroadcast timing"
    known = KNOWN.get(step["kind"])
    if diff and (explained or known):
        log(f"KNOWN  {line}  {explained or ''}  [{EXPLAINED[explained] if explained else known}]")
        # the end states agree after a maturity window: the run goes on
        if explained not in ("maturity window", "maturity in the middle of a reorg"):
            new_episode()
            episode_steps = []
        continue
    if diff:
        fails += 1
        log(f"FAIL   {line}")
        log(f"#   " + (f"fixed row {step['row']}" if "row" in step else f"seed {SEED}") + f", episode {episode}, step {spec}")
        for k in diff:
            if k == "outcome":
                log(f"#   outcome: divid {c_res[0]!r} irondivid {i_res[0]!r}")
            elif k.startswith("after invalidateblock: "):
                f = k.split(": ", 1)[1]
                log(f"#   {k}: divid {json.dumps(c_res[1][f])[:3000]} irondivid {json.dumps(i_res[1][f])[:3000]}")
                detail = "_coins (amount, confirmations)"
                if detail in c_res[1] and f == "listunspent 0 amounts":
                    log(f"#   after invalidateblock: {detail}: divid {json.dumps(c_res[1][detail])[:4000]} "
                        f"irondivid {json.dumps(i_res[1][detail])[:4000]}")
            else:
                who, f = k.split(": ", 1)
                a, b = (snaps[0], snaps[1]) if who == f"node {n}" else (snaps[2], snaps[3])
                log(f"#   {k}: divid {json.dumps(a[f])[:3000]} irondivid {json.dumps(b[f])[:3000]}")
        # The coins and mempools in full (without txids and addresses), for
        # looking into the difference
        for p in PAIRS:
            coins = p.node(n).call("listunspent", 0)
            if coins[0] == "ok":
                view = sorted((str(u["amount"]), u["confirmations"], u.get("spendable")) for u in coins[1])
                log(f"#   {p.name} node {n} listunspent 0 (amount, confirmations, spendable): {json.dumps(view)}"[:6000])
            for m in (1, 2):
                node = p.node(m)
                pool = []
                pool_ids = node.call("getrawmempool")
                for txid in (pool_ids[1] if pool_ids[0] == "ok" else []):
                    tx = node.call("getrawtransaction", txid, 1)
                    if tx[0] == "ok":
                        pool.append(sorted(str(o["value"]) for o in tx[1]["vout"]))
                log(f"#   {p.name} node {m} mempool output values: {json.dumps(sorted(pool))}"[:3000])
        # A side branch would show here (invalidateblock moves to the most-work
        # chain left, rpcblockchain.cpp:636-640), and the peer it came from
        for p in PAIRS:
            for m in (1, 2):
                tips = p.node(m).call("getchaintips")
                if tips[0] == "ok":
                    log(f"#   {p.name} node {m} chain tips: "
                        f"{json.dumps([(t.get('height'), t.get('branchlen'), t.get('status')) for t in tips[1]])}")
                # and a peer from outside the pair
                peers = p.node(m).call("getpeerinfo")
                if peers[0] == "ok":
                    log(f"#   {p.name} node {m} peers: {json.dumps(sorted(x.get('addr', '') for x in peers[1]))}")
        # Why a node lacks a transaction its peer holds: offered to it now
        for p in PAIRS:
            for m in (1, 2):
                node, peer = p.node(m), p.other(m)
                mine, theirs = node.call("getrawmempool"), peer.call("getrawmempool")
                if mine[0] != "ok" or theirs[0] != "ok":
                    continue
                for txid in sorted(set(theirs[1]) - set(mine[1])):
                    raw = peer.call("getrawtransaction", txid)
                    if raw[0] != "ok":
                        continue
                    height = node.call("getblockcount")
                    immature = height[0] == "ok" and spends_immature(p, peer, txid, height[1] + 1)
                    offered = node.call("sendrawtransaction", raw[1])
                    log(f"#   {p.name} node {m} lacks a transaction node {3 - m} holds; offered now: "
                        f"{outcome(offered)}; spends a coin immature at node {m}'s next height: {immature}")
                    log(f"#     {txid} inputs (txid:vout, generated, confirmations): {input_ages(p, peer, txid)}")
        if LOGS:
            import shutil
            os.makedirs(LOGS, exist_ok=True)
            for p in PAIRS:
                for node in p.nodes:
                    for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
                        if os.path.exists(path):
                            shutil.copy(path, os.path.join(LOGS, f"{node.name}-step{step['i']}.log"))
        # The steps of this episode: replayed with REPLAY on four fresh nodes,
        # they reach the same point
        log(f"#   episode steps: {json.dumps(episode_steps)}"[:30000])
        log(f"#   encrypted at the episode's start: RANDOM_SEQUENCES_ENCRYPTED="
            f"{','.join(str(m) for m in sorted(episode_encrypted))}")
        if GO_ON:
            continue
        break
    log(f"PASS   {line}")

keep_logs(f"episode{episode}")
log(f"# {len(steps) - len(row_steps)} steps planned" + (" after the fixed rows" if ROWS else "") + f", {episode} episode(s), ran for {int(time.time() - started)} s")
log(f"FAILS {fails}")
sys.exit(min(fails, 254))
