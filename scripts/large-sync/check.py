#!/usr/bin/env python3
"""A long, busy chain synced from scratch both ways, Divi Core divid and
irondivid compared on outcomes (and timed).

One seeded chain is built on divid (an owner that mines and a vault manager):
about 3,000 regtest blocks, proof of work to 100 and staked after, every block
from 101 carrying transactions. Its datadir is copied once; every case starts
from that copy. Cases: irondivid synced from the divid that has the chain, then
a divid synced from that irondivid alone (and a divid synced from divid, for
the timing); a sync stopped cleanly and then killed at seeded heights, on each
node; -reindex on each node; a wallet restored from the owner's phrase with
-rescan on each node. Rows print PASS (same as divid), KNOWN (a difference
listed in README.md) or FAIL. Exit code = FAILs. Timings are printed, not
compared.

Started by run.sh, which owns the work directory and stops the nodes. The
owner's phrase lives in memory, in an RPC reply, in irondivid's environment and
in a 0600 divi.conf of the run; it is never printed or put on a command line.
"""

import base64
import hashlib
import json
import os
import random
import secrets
import shutil
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
BLOCKS = int(os.environ.get("LARGE_SYNC_BLOCKS", "3000"))
SEED = int(os.environ.get("LARGE_SYNC_SEED", "5"))
SAVE = os.environ.get("LARGE_SYNC_SAVE")
FROM = os.environ.get("LARGE_SYNC_CHAIN")
HOST = "127.0.0.2"
RPC_TIMEOUT = 600
START_TIMEOUT = 1800
SYNC_TIMEOUT = 3600
STALL = 600  # a syncing node whose height does not move for this long has stopped
T0 = time.time()
rng = random.Random(SEED)
SAT = 100_000_000


def note(text):
    print(f"# [{time.time() - T0:7.1f}s] {text}", flush=True)


KNOWN = {}
# Fields irondivid adds on purpose (KNOWN in scripts/chain-replies): compared without them
EXTRA = {"getblock": {"mediantime", "nTx"}, "gettxoutsetinfo": {"bogosize"}}
# gettxoutsetinfo fields made from each node's own files (as scripts/coin-locks, unclean-stop)
OWN_FILES = {"bytes_serialized", "hash_serialized"}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same=None):
    global fails
    same = (core == iron) if same is None else same
    if name in KNOWN:
        word = "KNOWN" if not same else "FAIL"
        why = "  [known: " + KNOWN[name] + "]" if not same else "  [listed as KNOWN, but now the same as divid]"
    else:
        word, why = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core, default=str)[:200]}  "
          f"irondivid={json.dumps(iron, default=str)[:200]}{why}", flush=True)


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_tb(tb)
    print(f"FAIL   setup: {kind.__name__}: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- nodes -----------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, template=None):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        if template:
            shutil.copytree(template, self.dir, symlinks=True)
        os.makedirs(self.dir, exist_ok=True)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.password = secrets.token_hex(16)
        self.user = f"ls{index}"
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.proc = None
        self.env = None

    def write_conf(self, extra, secret_lines=()):
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
                 f"rpcpassword={self.password}", "rpcallowip=127.0.0.0/8", f"rpcbind={HOST}", f"bind={HOST}",
                 "server=1", "daemon=0", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
                 "printtoconsole=0"] + list(extra) + list(secret_lines)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self, extra=(), args=(), secret_lines=(), env=None, wait=True):
        """Seconds to the first RPC answer (None: it did not come up)"""
        self.write_conf(extra, secret_lines)
        out = open(os.path.join(WORK, f"{self.name}.out"), "a")
        self.started = time.time()
        full_env = dict(os.environ, **env) if env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=full_env,
                                     stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        return self.wait_ready() if wait else None

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return None
            if self.call("getblockcount", timeout=10)[0] == "ok":
                return time.time() - self.started
            time.sleep(0.1)
        return None

    def call(self, method, *params, timeout=RPC_TIMEOUT):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "")
        except (OSError, ValueError) as e:
            return ("err", "no reply", f"{type(e).__name__}")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:160]}")
        return out[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if not self.alive():
            return
        self.call("stop", timeout=30)
        try:
            self.proc.wait(timeout=600)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def kill(self):
        if self.alive():
            os.killpg(self.proc.pid, signal.SIGKILL)
            self.proc.wait()

    def height(self):
        out = self.call("getblockcount", timeout=30)
        return out[1] if out[0] == "ok" else None


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


def reach(n, cond):
    """Wait until cond(); False at SYNC_TIMEOUT or once n's height has not moved for STALL seconds"""
    deadline, last, since = time.time() + SYNC_TIMEOUT, None, time.time()
    while time.time() < deadline:
        try:
            if cond():
                return True
        except Exception:
            pass
        h = n.height()
        if h != last:
            last, since = h, time.time()
        elif time.time() - since > STALL:
            return False
        time.sleep(0.2)
    return False


def on_tip(n):
    return reach(n, lambda: n.call("getbestblockhash", timeout=30) == ("ok", TIP))


# --- raw transactions (built here, signed by the owner) ------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def raw_tx(inputs, outputs):
    """inputs: (txid, vout); outputs: (satoshis, scriptPubKey bytes)"""
    out = struct.pack("<i", 1) + compact(len(inputs))
    for txid, vout in inputs:
        out += bytes.fromhex(txid)[::-1] + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", 0xffffffff)
    out += compact(len(outputs))
    for value, spk in outputs:
        out += struct.pack("<q", value) + compact(len(spk)) + spk
    return (out + struct.pack("<I", 0)).hex()


def b58decode(text):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in text:
        n = n * 58 + alphabet.index(ch)
    raw = n.to_bytes(25, "big")
    return raw


def p2pkh(address):
    h160 = b58decode(address)[1:21]
    return b"\x76\xa9\x14" + h160 + b"\x88\xac"


def bare_multisig_1of1(pubkey_hex):
    pk = bytes.fromhex(pubkey_hex)
    return b"\x51" + bytes([len(pk)]) + pk + b"\x51\xae"


# --- build the chain ---------------------------------------------------------------------

if FROM:
    # A chain saved by an earlier run (LARGE_SYNC_SAVE): the owner datadir, wallet included
    O = Node("owner", DIVID, 0, template=FROM)
    O.start(["listen=1", "txindex=1", "connect=0"])
    made = json.load(open(os.path.join(FROM, "made.json")))
    V = None
else:
    O = Node("owner", DIVID, 0)
    V = Node("manager", DIVID, 1)
    O.start(["listen=1", "txindex=1"])
    V.start([f"connect={HOST}:{PORT_BASE}", "vault=1", "txindex=1"])
    if not wait_for(lambda: O.rpc("getconnectioncount") >= 1, 60):
        raise RuntimeError("the manager did not connect to the owner")


    def mine(node, n=1):
        for _ in range(n):
            if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok", 180, step=0.2):
                raise RuntimeError(f"{node.name} could not mine at {O.rpc('getblockcount')}")


    def together(secs=600):
        return wait_for(lambda: O.rpc("getbestblockhash") == V.rpc("getbestblockhash"), secs)


    O.rpc("setgenerate", 100)
    if not together():
        raise RuntimeError("the manager did not follow")
    OWN = [O.rpc("getnewaddress") for _ in range(200)]
    PUBS = [O.rpc("validateaddress", a)["pubkey"] for a in OWN[:20]]
    MS = [O.rpc("addmultisigaddress", 2, [PUBS[2 * k], PUBS[2 * k + 1]]) for k in range(5)]
    # Coins on the owner's own addresses: the coinbases pay keypool addresses
    O.rpc("sendmany", "", {a: 400 for a in OWN[:100]})
    mine(O)
    MGR = V.rpc("getnewaddress")
    VAULT = f"{OWN[0]}:{MGR}"
    SIGNED_BY_OWNER = OWN + MS
    made = {"raw spend with change": 0, "many-output receive": 0, "sendtoaddress": 0, "sendmany": 0,
            "multisig funding": 0, "multisig spend": 0, "vault funding": 0, "vault stake": 0,
            "near the size limit": 0, "near the sigop limit": 0}


    def a_coin(at_least):
        """One of the owner's confirmed coins worth at least `at_least` DIVI, not a vault's"""
        for u in sorted(O.rpc("listunspent", 1), key=lambda u: -Decimal(u["amount"])):
            if Decimal(u["amount"]) >= at_least and u.get("spendable", True) and u["address"] in OWN:
                if u["txid"] not in used:
                    used.add(u["txid"])
                    return u
        return None


    def sign_send(hexed):
        out = O.rpc("signrawtransaction", hexed)
        if not out.get("complete"):
            raise RuntimeError("signrawtransaction incomplete")
        return O.rpc("sendrawtransaction", out["hex"])


    def raw_spend(coin, payees, change_to):
        """A spend of `coin` to (sat, script) payees with change to an own address"""
        total_in = int(Decimal(coin["amount"]) * SAT)
        fee = 10_000 * (1 + (200 + 60 * len(payees)) // 1000)
        change = total_in - sum(v for v, _ in payees) - fee
        outs = list(payees) + ([(change, p2pkh(change_to))] if change > 10_000 else [])
        return sign_send(raw_tx([(coin["txid"], coin["vout"])], outs))


    ms_coins = []  # (txid, vout, value sat, multisig address)
    vault_funded = []
    height = O.rpc("getblockcount")
    next_note = 500
    while height < BLOCKS:
        used = set()  # coins spent in this block's transactions
        kind = height % 10
        # Every block from 101 carries transactions
        coin = a_coin(Decimal(3))
        if coin:
            raw_spend(coin, [(int(Decimal(rng.randint(1, 200)) * SAT // 100), p2pkh(rng.choice(OWN)))], rng.choice(OWN))
            made["raw spend with change"] += 1
        if kind in (1, 6):
            coin = a_coin(Decimal(40))
            if coin:
                raw_spend(coin, [(int(SAT * Decimal(rng.randint(5, 50)) / 100), p2pkh(a))
                                 for a in rng.sample(OWN, 30)], rng.choice(OWN))
                made["many-output receive"] += 1
        if kind == 2 and height % 30 == 2:
            O.rpc("sendtoaddress", rng.choice(OWN), float(Decimal(rng.randint(100, 900)) / 100))
            made["sendtoaddress"] += 1
        if kind == 3 and height % 30 == 3:
            O.rpc("sendmany", "", {a: float(Decimal(rng.randint(10, 90)) / 100) for a in rng.sample(OWN, 5)})
            made["sendmany"] += 1
        if kind == 4:
            coin = a_coin(Decimal(5))
            if coin:
                ms = rng.choice(MS)
                p2sh = b"\xa9\x14" + b58decode(ms)[1:21] + b"\x87"
                txid = raw_spend(coin, [(2 * SAT, p2sh)], rng.choice(OWN))
                ms_coins.append((txid, 0, 2 * SAT, ms))
                made["multisig funding"] += 1
        if kind == 5 and len(ms_coins) > 3:
            txid, vout, value, ms = ms_coins.pop(0)
            raw = O.rpc("createrawtransaction", [{"txid": txid, "vout": vout}],
                        {rng.choice(OWN): float(Decimal(value - 20_000) / SAT)})
            out = O.rpc("signrawtransaction", raw)
            if out.get("complete"):
                O.rpc("sendrawtransaction", out["hex"])
                made["multisig spend"] += 1
        if kind == 7 and height % 50 == 7:
            txid = O.rpc("fundvault", VAULT, 500)["txhash"]
            vault_funded.append(txid)
            made["vault funding"] += 1
        if height % 500 == 250:
            # About 95 kB, under the 100,000-byte limit (defaultValues.h:54)
            coin = a_coin(Decimal(10))
            if coin:
                raw_spend(coin, [(100_000, p2pkh(OWN[k % len(OWN)])) for k in range(2800)], rng.choice(OWN))
                made["near the size limit"] += 1
        if height % 500 == 400:
            # 390 bare 1-of-1 multisig outputs, 20 legacy sigops each: 7,800, under the
            # 8,000 a transaction may have (MAX_TX_SIGOPS_CURRENT, defaultValues.h:61,
            # MempoolConsensus.cpp:372-380)
            coin = a_coin(Decimal(10))
            if coin:
                raw_spend(coin, [(100_000, bare_multisig_1of1(PUBS[k % len(PUBS)])) for k in range(390)],
                          rng.choice(OWN))
                made["near the sigop limit"] += 1
        # The block: a vault stake by the manager now and then, once a vault coin is old enough
        if vault_funded and height % 9 == 0 and height > 150 and together(60):
            for t in vault_funded:
                V.call("addvault", VAULT, t)
            if V.call("setgenerate", 1)[0] == "ok":
                made["vault stake"] += 1
                if not together():
                    raise RuntimeError("the owner did not follow the manager's block")
            else:
                mine(O)
        else:
            mine(O)
        height = O.rpc("getblockcount")
        if height >= next_note:
            note(f"chain at {height}: " + ", ".join(f"{k} {v}" for k, v in made.items()))
            next_note += 500
    if not together():
        raise RuntimeError("the manager did not follow the chain")
TIP = O.rpc("getbestblockhash")
HEIGHT = O.rpc("getblockcount")
info = O.rpc("getblock", TIP)
note(f"chain built: {HEIGHT} blocks, {O.rpc('gettxoutsetinfo')['transactions']} transactions with unspent "
     f"outputs; " + ", ".join(f"{k} {v}" for k, v in made.items()))
PHRASE = O.rpc("dumphdinfo")["mnemonic"]
OWNER_BALANCE = O.rpc("getbalance")
OWNER_TXS = len(O.rpc("listtransactions", "*", 1000000, 0))
O.stop()
if V:
    V.stop()
if SAVE:
    shutil.copytree(O.dir, SAVE, symlinks=True)
    with open(os.path.join(SAVE, "made.json"), "w") as f:
        json.dump(made, f)
    note(f"chain saved in {SAVE}")
# The chain, once: every case starts from a copy (the owner's wallet taken out)
CHAIN = os.path.join(WORK, "chain")
shutil.copytree(O.dir, CHAIN, symlinks=True)
for p in ("regtest/wallet.dat", "regtest/database", "regtest/backups"):
    target = os.path.join(CHAIN, p)
    if os.path.isdir(target):
        shutil.rmtree(target)
    elif os.path.exists(target):
        os.remove(target)
if V:
    shutil.rmtree(V.dir)


# --- comparing two nodes ------------------------------------------------------------------

# The choices from here on have their own seed, so a saved chain gives the same run
rng = random.Random(SEED * 7919 + HEIGHT)
SAMPLE = sorted({1, 100, 101, 102, 250, 400, 1001, HEIGHT // 2, HEIGHT - 1, HEIGHT} |
                {rng.randint(101, HEIGHT) for _ in range(10)})


def view(n):
    """What a synced node shows of its chain"""
    v = {"tip": (n.rpc("getblockcount"), n.rpc("getbestblockhash"))}
    v["hash every 100th height"] = [n.rpc("getblockhash", h) for h in range(0, HEIGHT + 1, 100)]
    u = n.rpc("gettxoutsetinfo")
    v["gettxoutsetinfo"] = {k: x for k, x in u.items() if k not in OWN_FILES | EXTRA["gettxoutsetinfo"]}
    v["getchaintips"] = n.rpc("getchaintips")
    v["getblock sample"] = {h: {k: x for k, x in n.rpc("getblock", n.rpc("getblockhash", h)).items()
                                if k not in EXTRA["getblock"] | {"confirmations"}} for h in SAMPLE if h <= HEIGHT}
    return v


def compare_views(label, core, iron):
    for k in core:
        row(f"{label}: {k}", core[k] if k != "hash every 100th height" else f"{len(core[k])} hashes",
            iron[k] if k != "hash every 100th height" else f"{len(iron[k])} hashes", core[k] == iron[k])


def sync(node, peer_port, label, extra=()):
    """Start `node` connected to the peer on `peer_port` only. Returns the seconds to the tip, and the
    height it stopped at if it waited a block short of the tip and was started again.

    divid drops a block whose parent it lacks and asks for it again only with its next getblocks
    (main.cpp:822-833). A peer sends its tip at the end of each batch of block inventory, so a divid
    syncing a chain of more than one batch from a peer that makes no new block can stop a block short
    of the tip and wait there for the next block. Such a node is started again, which fetches the tip;
    the time is taken to where it stopped."""
    conf = [f"connect={HOST}:{peer_port}", "listen=1"] + list(extra)
    node.start(conf)
    reached, secs, short = to_tip(node, conf)
    if not reached:
        raise RuntimeError(f"{label}: {node.name} did not reach the tip (at {node.height()})")
    return secs, short


def to_tip(node, conf):
    """Wait for `node` (started with `conf`) to reach the tip; restart it once if it waits a block short
    (see sync). Returns: reached, seconds from its start to the tip or to where it waited, that height"""
    held = {}

    def done():
        if node.call("getbestblockhash", timeout=30) == ("ok", TIP):
            return True
        if node.height() == HEIGHT - 1:
            held.setdefault("since", time.time())
            return time.time() - held["since"] > 60
        held.clear()
        return False

    if not reach(node, done):
        return False, None, None
    if "since" not in held:
        return True, time.time() - node.started, None
    secs = held["since"] - node.started
    node.stop()
    node.start(conf)
    return on_tip(node), secs, HEIGHT - 1


TIMES = {}
SEEDER_PORT = PORT_BASE  # the divid with the chain listens on the owner's port

# --- 1. irondivid from divid, divid from divid, divid from irondivid ------------------------


def synced_note(what, secs, short):
    note(f"{what} in {secs:.1f} s" + (f", stopped a block short (at {short}) and started again" if short else ""))


D0 = Node("divid-chain", DIVID, 0, template=CHAIN)
D0.start(["listen=1", "disablewallet=1"])
I1 = Node("irondivid-synced", IRONDIVID, 1)
TIMES["sync from scratch from divid", "irondivid"], iron_short = sync(I1, SEEDER_PORT, "irondivid from divid",
                                                                    ["disablewallet=1"])
synced_note("irondivid synced from divid", TIMES["sync from scratch from divid", "irondivid"], iron_short)
D5 = Node("divid-synced", DIVID, 3)
TIMES["sync from scratch from divid", "divid"], core_short = sync(D5, SEEDER_PORT, "divid from divid",
                                                                ["disablewallet=1"])
synced_note("divid synced from divid", TIMES["sync from scratch from divid", "divid"], core_short)
core_view, iron_view = view(D0), view(I1)
compare_views("irondivid synced from divid", core_view, iron_view)
D0.stop()
D5.stop()
D2 = Node("divid-from-irondivid", DIVID, 2)
TIMES["divid synced from irondivid alone", "divid"], d2_short = sync(D2, I1.p2p, "divid from irondivid",
                                                                   ["disablewallet=1"])
synced_note("divid synced from irondivid", TIMES["divid synced from irondivid alone", "divid"], d2_short)
# A divid's sync from irondivid against its sync from divid: the height it waited at before a restart
# (None: it reached the tip)
row("a divid syncing from irondivid, against from divid: the height it waited at",
    core_short, d2_short)
compare_views("divid synced from irondivid alone", view(D2), iron_view)


# --- 2. a sync stopped at seeded heights: a clean stop, then a kill -----------------------

# Both nodes are stopped at the same seeded heights
STOPS = sorted(rng.sample(range(150, HEIGHT - 100), 2))


def interrupted(node_name, binary, index):
    n = Node(node_name, binary, index)
    stops = STOPS
    starts = []
    n.start([f"connect={HOST}:{I1.p2p}", "listen=0", "disablewallet=1"])
    out = {}
    for how, at in zip(("clean stop", "kill"), stops):
        reach(n, lambda: (n.height() or 0) >= at)
        h = n.height()
        n.stop() if how == "clean stop" else n.kill()
        up = n.start([f"connect={HOST}:{I1.p2p}", "listen=0", "disablewallet=1"])
        if up is None:
            # A node that refuses to start after a kill is started with -reindex (as scripts/unclean-stop)
            n.stop()
            up = n.start([f"connect={HOST}:{I1.p2p}", "listen=0", "disablewallet=1"], ["-reindex"])
            starts.append(f"{how} at {h}: needed -reindex")
        else:
            starts.append(f"{how} at {h}: started")
        out[f"{how}: started again"] = up is not None
    reached, _, short = to_tip(n, [f"connect={HOST}:{I1.p2p}", "listen=0", "disablewallet=1"])
    out["reached the tip"] = reached
    if short:
        starts.append(f"waited at {short} and started again")
    u = n.rpc("gettxoutsetinfo") if reached else {}
    out["gettxoutsetinfo"] = {k: x for k, x in u.items() if k not in OWN_FILES | EXTRA["gettxoutsetinfo"]}
    note(f"{node_name}: " + "; ".join(starts))
    n.stop()
    shutil.rmtree(n.dir)
    return out


core_i = interrupted("divid-interrupted", DIVID, 3)
iron_i = interrupted("irondivid-interrupted", IRONDIVID, 4)
for k in core_i:
    row(f"sync stopped (clean stop, then kill): {k}", core_i[k], iron_i[k])
row("sync stopped: gettxoutsetinfo is the chain's", True, iron_i["gettxoutsetinfo"] == core_view["gettxoutsetinfo"])


# --- 3. -reindex on each node with the full chain ----------------------------------------

def reindex(n, extra):
    n.stop()
    t = time.time()
    n.start(extra, ["-reindex"])
    on_tip(n)
    secs = time.time() - t
    u = n.rpc("gettxoutsetinfo")
    return secs, {"tip": (n.rpc("getblockcount"), n.rpc("getbestblockhash")),
                  "gettxoutsetinfo": {k: x for k, x in u.items() if k not in OWN_FILES | EXTRA["gettxoutsetinfo"]}}


I1.stop()
D2.stop()
alone = [f"connect={HOST}:{PORT_BASE + 49}", "listen=0", "disablewallet=1"]
TIMES["-reindex", "divid"], core_r = reindex(D2, alone)
TIMES["-reindex", "irondivid"], iron_r = reindex(I1, alone)
for k in core_r:
    row(f"-reindex: {k}", core_r[k], iron_r[k])


# --- 4. restart, and a wallet restored from the owner's phrase with -rescan ----------------

def restart(n):
    n.stop()
    return n.start(alone)


TIMES["restart", "divid"] = restart(D2)
TIMES["restart", "irondivid"] = restart(I1)
row("restart: tip", (D2.rpc("getblockcount"), D2.rpc("getbestblockhash")),
    (I1.rpc("getblockcount"), I1.rpc("getbestblockhash")))


def restored(n, is_divid):
    n.stop()
    conf = [f"connect={HOST}:{PORT_BASE + 49}", "listen=0", "keypool=1000"]
    t = time.time()
    if is_divid:
        n.start(conf, ["-rescan"], secret_lines=[f"mnemonic={PHRASE}"])
    else:
        n.start(conf, ["-rescan"], env={"WALLET_MNEMONIC": PHRASE})
    # The wallet is ready once a call that reads it answers
    wait_for(lambda: n.call("getbalance", timeout=60)[0] == "ok", START_TIMEOUT, step=0.5)
    secs = time.time() - t
    return secs, {"getbalance": n.rpc("getbalance"),
                  "listtransactions entries": len(n.rpc("listtransactions", "*", 1000000, 0)),
                  "listunspent coins": len(n.rpc("listunspent")),
                  "getwalletinfo txcount": n.rpc("getwalletinfo").get("txcount")}


TIMES["wallet restored with -rescan", "divid"], core_w = restored(D2, True)
TIMES["wallet restored with -rescan", "irondivid"], iron_w = restored(I1, False)
for k in core_w:
    row(f"wallet restored from the phrase with -rescan: {k}", core_w[k], iron_w[k])
note(f"the owner's own wallet had {OWNER_BALANCE} DIVI and {OWNER_TXS} listtransactions entries "
     f"(the restored ones lack the vault manager's view and the wallet's labels)")
for n in (D2, I1):
    n.stop()

print("# timing (seconds, not compared)", flush=True)
for what in ("sync from scratch from divid", "restart", "-reindex", "wallet restored with -rescan"):
    c, i = TIMES.get((what, "divid")), TIMES.get((what, "irondivid"))
    if c and i:
        print(f"#   {what}: divid {c:.1f}, irondivid {i:.1f}, irondivid/divid {i / c:.2f}"
              + ("  (over 3x)" if i > 3 * c else ""), flush=True)
c = TIMES.get(("divid synced from irondivid alone", "divid"))
print(f"#   divid synced from irondivid alone: {c:.1f} (against {TIMES[('sync from scratch from divid', 'divid')]:.1f} "
      f"from divid)", flush=True)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
