#!/usr/bin/env python3
"""kill -9 of irondivid at seeded random points, on regtest next to Divi Core
divid miners; after each kill the node is started again and its chain, UTXO
set, wallet and indexes are compared with a clean node at the same point.
One PASS/FAIL line per kill point (AS CORE/DIFFERS for the divid comparison
rows). Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
Passphrases exist only in memory and in RPC request bodies; private keys are
compared by hash and never printed.
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK, SEED = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
KILLS = int(os.environ.get("UNCLEAN_KILLS", "5"))
# The chain the sync row downloads (row 1 asks for 300 or more)
CHAIN = int(os.environ.get("UNCLEAN_BLOCKS", "320"))
# Leave every irondivid on regtest with all three indexes, as row 4 needs them
INDEX_CONF = ["txindex=1", "addressindex=1", "spentindex=1"]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
# Nodes listen on 127.0.0.2: the ports are inside the host's ephemeral range,
# and other programs' clients on 127.0.0.1 can hold one of them for a while
HOST = "127.0.0.2"
OFFLINE = f"{HOST}:{PORT_BASE + 49}"  # nothing listens there

rng = random.Random(SEED)
fails = 0
T0 = time.time()


def out(word, name, text):
    global fails
    if word == "FAIL":
        fails += 1
    print(f"{word} {name} {text}", flush=True)


def note(text):
    print(f"# [{time.time() - T0:6.1f}s] {text}", flush=True)


class Failed(Exception):
    """A step of a kill point that went wrong: the reason for its FAIL line"""


# --- nodes ---------------------------------------------------------------------

class Node:
    """One role: a binary on fixed ports. start() runs it on a datadir."""

    def __init__(self, name, binary, index, core):
        self.name, self.binary, self.core = name, binary, core
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.addr = f"{HOST}:{self.p2p}"
        self.proc = None
        self.dir = None
        self.auth = None

    def start(self, datadir, conf=(), args=(), wait=True):
        # The ports are inside the host's ephemeral range: a client of some
        # other program can hold one for a moment, so a bind failure is retried
        for attempt in range(6):
            try:
                return self.start_once(datadir, conf, args, wait)
            except Failed as e:
                if "bind" not in str(e).lower() or attempt == 5:
                    raise
                note(f"{self.name}: port busy, starting again")
                time.sleep(3)

    def start_once(self, datadir, conf, args, wait):
        self.dir = datadir
        os.makedirs(datadir, exist_ok=True)
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"u{self.p2p}:{password}".encode()).decode()
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=u{self.p2p}", f"rpcpassword={password}", "rpcallowip=127.0.0.0/8",
            f"rpcbind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", "dnsseed=0", "staking=0",
        ] + list(conf)
        path = os.path.join(datadir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.out_path = os.path.join(WORK, f"{self.name}.out")
        self.log = open(self.out_path, "a")
        self.log.write(f"=== start {time.time() - T0:.1f}s {datadir} {' '.join(args)}\n")
        self.log.flush()
        self.started = time.time()
        self.proc = subprocess.Popen([self.binary, f"-datadir={datadir}"] + list(args), cwd=datadir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if wait and not self.wait_ready():
            raise Failed(f"{self.name} did not start: {self.why_down()}")
        return self

    def call(self, method, *params, timeout=RPC_TIMEOUT):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params, timeout=RPC_TIMEOUT):
        try:
            r = self.call(method, *params, timeout=timeout)
        except Exception as e:
            raise Failed(f"{self.name} {method}: {e}")
        if r[0] != "ok":
            raise Failed(f"{self.name} {method}: {r[1]} {r[2][:160]}")
        return r[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_ready(self, timeout=START_TIMEOUT):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.alive():
                return False
            try:
                if self.call("getblockcount", timeout=5)[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.05)
        return False

    def debug_log(self):
        for sub in ("regtest", ""):
            p = os.path.join(self.dir, sub, "debug.log")
            if os.path.exists(p):
                return p
        return None

    def log_lines(self):
        p = self.debug_log()
        if not p:
            return []
        with open(p, errors="replace") as f:
            return f.read().splitlines()

    def why_down(self):
        """The node's last words: exit status and the last error-looking lines"""
        status = "running" if self.alive() else f"exit {self.proc.returncode}"
        rx = re.compile(r"error|ERROR|Error|need|refus|corrupt|damaged|reindex|panic")
        # divid's masternode caches are missing on every first start: not a reason
        noise = re.compile(r"mncache|mnpayments|netfulfilled|budget|peers\.dat|banlist")
        try:
            with open(self.out_path, errors="replace") as f:
                text = f.read()
            lines = text[text.rfind("=== start"):].splitlines()[1:]
        except OSError:
            lines = []
        bad = [ln for ln in lines if rx.search(ln) and not noise.search(ln)]
        if not bad:
            bad = [ln for ln in self.log_lines()[-40:] if rx.search(ln) and not noise.search(ln)]
        return f"{status}; " + (" | ".join(x.strip()[-200:] for x in bad[-3:]) or "no error line")

    def kill9(self):
        if self.alive():
            os.kill(self.proc.pid, signal.SIGKILL)
        self.proc.wait()
        self.log.close()

    def stop(self):
        if not self.alive():
            self.proc.wait()
            self.log.close()
            return
        try:
            self.call("stop", timeout=10)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def wait_for(fn, secs, step=0.1):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


def wait_log(node, pattern, secs):
    """True once a debug.log line matches (the kill trigger of some points)"""
    rx = re.compile(pattern)
    deadline = time.time() + secs
    f, seen = None, ""
    try:
        while time.time() < deadline and node.alive():
            if f is None:
                p = node.debug_log()
                f = open(p, errors="replace") if p else None
            if f is not None:
                seen = seen[-4096:] + f.read()
                if rx.search(seen):
                    return True
            time.sleep(0.001)
        return False
    finally:
        if f is not None:
            f.close()


def background_call(node, method, *params):
    """Send a call and return at once; the reply (if any) is ignored"""
    def go():
        try:
            node.call(method, *params, timeout=120)
        except Exception:
            pass
    t = threading.Thread(target=go, daemon=True)
    t.start()
    return t


# --- the clean record --------------------------------------------------------------
# Each Core miner records gettxoutsetinfo after every block it mines, so a
# restarted node's UTXO set can be compared at whatever height it stopped.

hist = {}


def utxo(node):
    i = node.rpc("gettxoutsetinfo")
    return (i["height"], i["bestblock"], i["transactions"], i["txouts"], round(i["total_amount"] * 1e8))


def mine(node, n, every=None):
    for k in range(n):
        if every:
            every(k)
        # A proof-of-stake block is not always found at the first try
        for _ in range(20):
            r = node.call("setgenerate", 1)
            if r[0] == "ok":
                break
            if r[1] != -25:
                raise Failed(f"{node.name} setgenerate: {r[1]} {r[2][:120]}")
            time.sleep(0.5)
        else:
            raise Failed(f"{node.name} setgenerate: no block in 20 tries")
        u = utxo(node)
        hist[u[1]] = u


def show_u(u):
    return f"h{u[0]} {u[1][:12]} tx={u[2]} txouts={u[3]} amount={u[4]}"


def check_on_chain(v, sides):
    """The restarted node's tip is a block of one of the Core miners' chains and
    its UTXO set is the clean one at that block. Returns (side, height)."""
    h = v.rpc("getblockcount")
    tip = v.rpc("getbestblockhash")
    u = utxo(v)
    if u[1] != tip or u[0] != h:
        raise Failed(f"gettxoutsetinfo h{u[0]} {u[1][:12]} is not the tip h{h} {tip[:12]}")
    side = None
    for name, core in sides:
        if h <= core.rpc("getblockcount") and core.rpc("getblockhash", h) == tip:
            side = name
            break
    if side is None:
        raise Failed(f"tip h{h} {tip[:12]} is on no miner's chain")
    want = hist.get(tip)
    if want is None:
        raise Failed(f"no clean record for tip h{h} {tip[:12]}")
    if u != want:
        raise Failed(f"UTXO set {show_u(u)} != clean {show_u(want)}")
    return side, h


def restart_after_kill(v, datadir, conf, args=()):
    """Start again with no peer. If the node refuses and names -reindex or a
    damaged database, start it with -reindex. Returns a note on how it came up."""
    try:
        v.start(datadir, conf + [f"connect={OFFLINE}"], args)
        how = "started"
    except Failed:
        why = v.why_down()
        if v.alive():
            v.kill9()
        if not re.search(r"-reindex|corrupt", why) or "-reindex" in args:
            raise Failed(f"restart: {why}")
        v.start(datadir, conf + [f"connect={OFFLINE}"], list(args) + ["-reindex"])
        how = f"refused ({why[why.find(';') + 2:][:140]}); started with -reindex"
    settle(v)
    return how


def settle(v, secs=120):
    """Wait until the height has stood still for 1.5 s: divid answers RPC while
    it still connects blocks at start (and during -reindex)"""
    last, same = None, 0
    deadline = time.time() + secs
    while time.time() < deadline and same < 6:
        h = v.rpc("getblockcount")
        same = same + 1 if h == last else 0
        last = h
        time.sleep(0.25)


def sync_to(v, datadir, conf, peer, timeout=90):
    """Stop the offline node and start it with peer as its only peer; wait until
    it has peer's tip"""
    v.stop()
    v.start(datadir, conf + [f"connect={peer.addr}"])
    tip = peer.rpc("getbestblockhash")
    if not wait_for(lambda: v.rpc("getbestblockhash") == tip, timeout, 0.25):
        raise Failed(f"did not reach {peer.name}'s tip h{peer.rpc('getblockcount')} "
                     f"(at h{v.call('getblockcount')})")
    return tip


def fresh(name):
    d = os.path.join(WORK, name)
    if os.path.exists(d):
        shutil.rmtree(d)
    return d


def copy_of(template, name):
    d = fresh(name)
    shutil.copytree(template, d)
    return d


def kill_point(row, k, fn, delay):
    """Run one kill point; its outcome is one PASS/FAIL line"""
    t = time.time()
    try:
        detail = fn()
        out("PASS", f"{row}#{k}", f"{detail} ({time.time() - t:.0f}s)")
        return True, detail
    except Failed as e:
        out("FAIL", f"{row}#{k}", f"delay={delay * 1000:.1f}ms: {str(e)[:400]}")
        for n in (V, K):
            if n.proc is not None and n.alive():
                n.kill9()
        return False, str(e)


def done_with(d, result):
    """Delete a kill point's datadir, unless it failed and KEEP=1"""
    if result[0] or os.environ.get("KEEP") != "1":
        shutil.rmtree(d, ignore_errors=True)


def keyhash(node, addr):
    return hashlib.sha256(node.rpc("dumpprivkey", addr).encode()).hexdigest()[:16]


def sat(x):
    return round(x * 1e8)


# --- set-up ------------------------------------------------------------------------

def setup_failed(kind, value, tb):
    print(f"FAIL setup {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C1 = Node("core1", DIVID, 0, True)
C2 = Node("core2", DIVID, 1, True)
R = Node("clean", IRONDIVID, 2, False)
V = Node("irondivid", IRONDIVID, 3, False)
K = Node("divid", DIVID, 4, True)
print(f"# seed {SEED}, {KILLS} kill points per row, ports {PORT_BASE}..{PORT_BASE + 9}", flush=True)

C1.start(fresh("c1"), ["listen=1"])
C2.start(fresh("c2"), ["listen=1", f"connect={C1.addr}"])
print(f"# divid {C1.rpc('getinfo').get('version')}", flush=True)
hist[C1.rpc("getbestblockhash")] = utxo(C1)

# C1 mines the chain. C2 (the second miner of row 2) and the clean nodes get
# coins on the way, and coins are sent and spent so the indexes have entries.
c2_addr = C2.rpc("getnewaddress")
c1_addrs = [C1.rpc("getnewaddress") for _ in range(6)]
c2_more = [C2.rpc("getnewaddress") for _ in range(60)]
known_txids = []
spent_outs = []


def payments(k):
    h = C1.rpc("getblockcount")
    if h == 70:
        for _ in range(8):
            known_txids.append(C1.rpc("sendtoaddress", c2_addr, 5000))
    if h == 120:
        # Many coins for C2: each block it stakes uses one for 20 blocks
        known_txids.append(C1.rpc("sendmany", "", {a: 500 for a in c2_more}))
    if h >= 80 and h % 25 == 5 and h < CHAIN - 30:
        a = c1_addrs[(h // 25) % len(c1_addrs)]
        known_txids.append(C1.rpc("sendtoaddress", a, 100 + h))


note(f"C1 mines {CHAIN} blocks")
mine(C1, CHAIN, payments)
if not wait_for(lambda: C2.rpc("getbestblockhash") == C1.rpc("getbestblockhash"), 60):
    raise Failed("C2 did not follow C1")

# The clean irondivid (indexes on, follows C1) and the template irondivid
# (wallet with coins); the time the clean one takes to sync is row 1's window.
t = time.time()
R.start(fresh("clean"), INDEX_CONF + [f"connect={C1.addr}"])
tip = C1.rpc("getbestblockhash")
if not wait_for(lambda: R.rpc("getbestblockhash") == tip, 180, 0.05):
    raise Failed("the clean irondivid did not sync")
SYNC_SECS = time.time() - t
note(f"clean irondivid synced {CHAIN} blocks in {SYNC_SECS:.1f}s (start included)")

TMPL = fresh("tmpl-i")
V.start(TMPL, INDEX_CONF + [f"connect={C1.addr}"])
K.start(fresh("tmpl-c"), ["txindex=1", "addressindex=1", "spentindex=1", f"connect={C1.addr}"])
v_addr, k_addr = V.rpc("getnewaddress"), K.rpc("getnewaddress")
for _ in range(3):
    known_txids.append(C1.rpc("sendtoaddress", v_addr, 1000))
    known_txids.append(C1.rpc("sendtoaddress", k_addr, 1000))
mine(C1, 1)
for n in (V, K):
    if not wait_for(lambda: n.rpc("getbalance") >= 3000, 60):
        raise Failed(f"{n.name} did not get its coins")
# Each wallet spends one of its coins back, so the spent index has wallet entries
known_txids.append(V.rpc("sendtoaddress", c1_addrs[0], 10))
known_txids.append(K.rpc("sendtoaddress", c1_addrs[0], 10))
if not wait_for(lambda: len(C1.rpc("getrawmempool")) >= 2, 30):
    raise Failed("the wallets' sends did not reach C1")
mine(C1, 2)
tip = C1.rpc("getbestblockhash")
for n in (R, V, K, C2):
    if not wait_for(lambda: n.rpc("getbestblockhash") == tip, 60):
        raise Failed(f"{n.name} did not follow C1")
TIP_H = C1.rpc("getblockcount")
W_BAL = {V: sat(V.rpc("getbalance")), K: sat(K.rpc("getbalance"))}
W_KEY = {V: keyhash(V, v_addr), K: keyhash(K, k_addr)}
W_ADDR = {V: v_addr, K: k_addr}

# Outputs that were spent, for getspentinfo; addresses for getaddressbalance
for txid in known_txids:
    tx = R.rpc("getrawtransaction", txid, 1)
    for vin in tx["vin"]:
        if "txid" in vin:
            spent_outs.append({"txid": vin["txid"], "index": vin["vout"]})
known_addrs = sorted(set(c1_addrs + [c2_addr, v_addr, k_addr]))
V.stop()
K.stop()
TMPL_C = os.path.join(WORK, "tmpl-c")
note(f"templates at h{TIP_H}: {len(known_txids)} txids, {len(spent_outs)} spent outputs, "
     f"{len(known_addrs)} addresses")


def index_view(n):
    """What the indexes say about the known txids, addresses and spent outputs"""
    v = {}
    for txid in known_txids:
        r = n.call("getrawtransaction", txid, 1)
        v["tx " + txid[:12]] = (r[1].get("blockhash"), r[1].get("hex")) if r[0] == "ok" else r[:2]
    for a in known_addrs:
        r = n.call("getaddressbalance", {"addresses": [a]})
        v["bal " + a[:10]] = (r[1].get("balance"), r[1].get("received")) if r[0] == "ok" else r[:2]
    for o in spent_outs:
        r = n.call("getspentinfo", o)
        v[f"spent {o['txid'][:12]}:{o['index']}"] = (r[1].get("txid"), r[1].get("index")) if r[0] == "ok" else r[:2]
    return v


def index_diff(a, b):
    d = [k for k in a if a[k] != b.get(k)]
    return f"{len(d)} of {len(a)} differ, e.g. {d[0]}: {a[d[0]]} vs clean {b.get(d[0])}" if d else ""


CLEAN_INDEX = index_view(R)
if any(isinstance(x, tuple) and x and x[0] == "err" for x in CLEAN_INDEX.values()):
    raise Failed("the clean irondivid's indexes answer with errors: "
                 + str([k for k, x in CLEAN_INDEX.items() if x and x[0] == 'err'][:3]))

# Encrypted copies of both templates (rows 3b), and how long the calls take
PW1 = secrets.token_hex(16)
TMPL_ENC = copy_of(TMPL, "tmpl-i-enc")
TMPL_C_ENC = copy_of(TMPL_C, "tmpl-c-enc")
TIMES = {}
for n, d in ((V, TMPL_ENC), (K, TMPL_C_ENC)):
    n.start(d, INDEX_CONF + [f"connect={OFFLINE}"])
    t = time.time()
    n.rpc("encryptwallet", PW1, timeout=120)
    TIMES[(n, "encrypt")] = time.time() - t
    if not n.wait_ready(60):
        # divid of some versions stops after encryptwallet: start it again
        n.stop()
        n.start(d, INDEX_CONF + [f"connect={OFFLINE}"])
    wait_for(lambda: n.call("getwalletinfo")[0] == "ok", 60)
    pw_tmp = secrets.token_hex(16)
    t = time.time()
    n.rpc("walletpassphrasechange", PW1, pw_tmp)
    TIMES[(n, "change")] = time.time() - t
    n.rpc("walletpassphrasechange", pw_tmp, PW1)
    n.stop()
note("call times: " + ", ".join(f"{n.name} {w} {s * 1000:.0f}ms" for (n, w), s in TIMES.items()))


# --- row 1: kill while syncing from a Core peer --------------------------------------

def row1_point(node, k, conf):
    # A fresh chain with the funded wallet of the template: the wallet has
    # seen blocks the node is still to download
    d = fresh(f"r1-{node.name}-{k}")
    if node.core:
        os.makedirs(os.path.join(d, "regtest"))
        shutil.copy(os.path.join(TMPL_C, "regtest", "wallet.dat"), os.path.join(d, "regtest"))
    else:
        shutil.copytree(os.path.join(TMPL, "wallet"), os.path.join(d, "wallet"))
    window = SYNC_SECS * 1.2
    delay = rng.uniform(0.05, window)

    def run():
        node.start(d, conf + [f"connect={C1.addr}"], wait=False)
        time.sleep(delay)
        node.kill9()
        how = restart_after_kill(node, d, conf)
        side, h = check_on_chain(node, [("C1", C1)])
        sync_to(node, d, conf, C1)
        u = utxo(node)
        if u != utxo(C1):
            raise Failed(f"after sync {show_u(u)} != C1 {show_u(utxo(C1))}")
        if node is V and u != utxo(R):
            raise Failed(f"after sync {show_u(u)} != clean irondivid {show_u(utxo(R))}")
        bal = sat(node.rpc("getbalance"))
        if bal != W_BAL[node]:
            raise Failed(f"after sync balance {bal} != {W_BAL[node]}")
        node.stop()
        return (f"delay={delay:.2f}s restart={how} tip=h{h} on C1, UTXO set as clean; synced to h{u[0]}, "
                f"wallet balance as before")
    r = kill_point(f"sync-kill{'-divid' if node.core else ''}", k, run, delay)
    done_with(d, r)
    return r


def first_start_point(node, k, conf):
    """kill -9 in the first start on an empty datadir, while the chain database
    is being made: irondivid a few ms after it says it opens RocksDB, divid at
    a random delay"""
    d = fresh(f"r1b-{node.name}-{k}")
    delay = rng.uniform(0, 0.5) if node.core else rng.uniform(0, 0.01)

    def run():
        node.start(d, conf + [f"connect={C1.addr}"], wait=False)
        if not node.core and not wait_log(node, r"Opening RocksDB", 30):
            raise Failed("no 'Opening RocksDB' line within 30s")
        time.sleep(delay)
        node.kill9()
        how = restart_after_kill(node, d, conf)
        side, h = check_on_chain(node, [("C1", C1)])
        sync_to(node, d, conf, C1)
        u = utxo(node)
        if u != utxo(C1):
            raise Failed(f"after sync {show_u(u)} != C1 {show_u(utxo(C1))}")
        node.stop()
        trig = "after start" if node.core else "after 'Opening RocksDB'"
        return f"delay={delay * 1000:.1f}ms {trig}; restart={how} tip=h{h}; synced to h{u[0]} as C1"
    r = kill_point(f"first-start-kill{'-divid' if node.core else ''}", k, run, delay)
    done_with(d, r)
    return r


# --- row 3: kill during encryptwallet / walletpassphrasechange -------------------------

def wallet_point(node, k, what, template):
    d = copy_of(template, f"r3-{what}-{node.name}-{k}")
    window = TIMES[(node, "encrypt" if what == "encrypt" else "change")] * 1.3 + 0.02
    delay = rng.uniform(0, window)
    pw2 = secrets.token_hex(16)
    conf = INDEX_CONF

    def run():
        node.start(d, conf + [f"connect={OFFLINE}"])
        if what == "encrypt":
            background_call(node, "encryptwallet", PW1)
        else:
            background_call(node, "walletpassphrasechange", PW1, pw2)
        time.sleep(delay)
        node.kill9()
        how = restart_after_kill(node, d, conf)
        wait_for(lambda: node.call("getwalletinfo")[0] == "ok", 60)
        info = node.rpc("getwalletinfo")
        encrypted = "unlocked_until" in info or info.get("encryption_status", "unencrypted") != "unencrypted"
        if what == "encrypt" and not encrypted:
            opened = "unencrypted (old state)"
        else:
            if not encrypted:
                raise Failed("wallet is no longer encrypted after a passphrase change")
            ok = [name for name, p in (("old", PW1), ("new", pw2 if what == "change" else None)) if p
                  and node.call("walletpassphrase", p, 60)[0] == "ok"]
            if not ok:
                raise Failed(f"encrypted wallet opens with neither passphrase ({node.why_down()[:120]})")
            opened = f"encrypted, opens with the {ok[0]} passphrase"
        bal = sat(node.rpc("getbalance"))
        if bal != W_BAL[node]:
            raise Failed(f"{opened}; balance {bal} != {W_BAL[node]}")
        if keyhash(node, W_ADDR[node]) != W_KEY[node]:
            raise Failed(f"{opened}; dumpprivkey of the known address changed")
        node.stop()
        return f"delay={delay * 1000:.0f}ms restart={how}: {opened}, balance and dumpprivkey unchanged"
    r = kill_point(f"{what}-kill{'-divid' if node.core else ''}", k, run, delay)
    done_with(d, r)
    return r


# --- row 4: kill during -reindex with the three indexes -------------------------------

REINDEX_SECS = {}


def calibrate_reindex(node, template):
    d = copy_of(template, f"r4-cal-{node.name}")
    t = time.time()
    node.start(d, INDEX_CONF + [f"connect={OFFLINE}"], ["-reindex"])
    if node.core:
        wait_for(lambda: node.rpc("getblockcount") == TIP_H, 120, 0.05)
    REINDEX_SECS[node] = time.time() - t
    node.stop()
    shutil.rmtree(d, ignore_errors=True)


def reindex_point(node, k, template):
    d = copy_of(template, f"r4-{node.name}-{k}")
    # Odd points: a random delay from the start; even ones: a few ms after the
    # node says it builds the index
    by_log = k % 2 == 0 and not node.core
    delay = rng.uniform(0, 0.015) if by_log else rng.uniform(0.02, REINDEX_SECS[node] * 1.2)
    conf = INDEX_CONF

    def run():
        node.start(d, conf + [f"connect={OFFLINE}"], ["-reindex"], wait=False)
        if by_log and not wait_log(node, r"Building the transaction index", 30):
            raise Failed("no 'Building the transaction index' line within 30s")
        time.sleep(delay)
        lines = len(node.log_lines())
        node.kill9()
        tail = node.log_lines()[:lines]
        phase = ("index build done" if any("Transaction index built" in x for x in tail)
                 else "during index build" if any("Building the transaction index" in x for x in tail)
                 else "before index build")
        how = restart_after_kill(node, d, conf)
        if node.core:
            wait_for(lambda: node.rpc("getblockcount") == TIP_H, 120, 0.25)
        h = node.rpc("getblockcount")
        if h != TIP_H:
            raise Failed(f"{phase}; restart={how}; height {h} != {TIP_H}")
        if node.rpc("getbestblockhash") != C1.rpc("getblockhash", TIP_H):
            raise Failed(f"{phase}; tip is not C1's block at h{TIP_H}")
        u = utxo(node)
        if not node.core and u != hist[u[1]]:
            raise Failed(f"{phase}; UTXO set {show_u(u)} != clean {show_u(hist[u[1]])}")
        diff = index_diff(index_view(node), CLEAN_INDEX)
        if diff:
            raise Failed(f"{phase}; restart={how}; indexes: {diff}")
        node.stop()
        trig = "after 'Building'" if by_log else "after start"
        return f"delay={delay * 1000:.0f}ms {trig} ({phase}); restart={how}; tip, txs, address balances, spent info as clean"
    r = kill_point(f"reindex-kill{'-divid' if node.core else ''}", k, run, delay)
    done_with(d, r)
    return r


# --- row 5: kill after a spork call and after a -minrelaytxfee start --------------------

SPORK_ANSWERS = {}


def show_answer(r):
    return f"error {r[1]} \"{r[2][:80]}\"" if r[0] == "err" else f"ok {json.dumps(r[1])[:80]}"


def relay_point(node, k, template, after):
    d = copy_of(template, f"r5-{after}-{node.name}-{k}")
    conf = INDEX_CONF + ["minrelaytxfee=0.00003"]
    delay = rng.uniform(0, 0.3)

    def run():
        node.start(d, conf + [f"connect={OFFLINE}"])
        relay = node.rpc("getnetworkinfo")["relayfee"]
        show, active = node.call("spork", "show"), node.call("spork", "active")
        change = None
        if after == "spork":
            # Nobody holds the regtest spork key, so a change is refused; the
            # kill follows the call at once
            change = node.call("spork", "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT", "4070908800")
        time.sleep(delay)
        node.kill9()
        how = restart_after_kill(node, d, conf)
        relay2 = node.rpc("getnetworkinfo")["relayfee"]
        show2, active2 = node.call("spork", "show"), node.call("spork", "active")
        if relay2 != relay:
            raise Failed(f"relayfee {relay2} != {relay} before the kill")
        if (show2, active2) != (show, active):
            raise Failed(f"spork show/active changed: {str(show2)[:120]} vs {str(show)[:120]}")
        node.stop()
        if change:
            SPORK_ANSWERS[node] = change
        ch = f"; spork change answered {show_answer(change)}" if change else ""
        return f"delay={delay * 1000:.0f}ms restart={how}; relayfee {relay2}, spork show/active unchanged{ch}"
    r = kill_point(f"{after}-kill{'-divid' if node.core else ''}", k, run, delay)
    done_with(d, r)
    return r


# --- row 2: kill during a reorg between two Core miners --------------------------------
# A proof-of-stake block stakes a coin of the chain it extends; a coin made on
# a branch can stake after 20 blocks (nMaturity), and a node on the other
# branch cannot check such a block (divid: "read txPrev failed"). So each
# branch stays under 20 blocks, and the miners join after every point.

# LOTTERY: a divid that has connected a lottery block (heights 110, 120, ...)
# and then reorganizes to a branch with another block at that height refuses
# the new one ("IsValidLotteryPayment: No payment for winner"), though a fresh
# divid accepts that branch. So the branch a node leaves holds no lottery block.
MINER_CONF = {}


def isolate(miner):
    """Start a miner again with no peer of its own (it drops every connection)"""
    miner.stop()
    miner.start(miner.dir, MINER_CONF[miner])


def join(w, l):
    """w takes l's chain; both are then isolated again"""
    w.rpc("addnode", l.addr, "onetry")
    tip = l.rpc("getbestblockhash")
    if not wait_for(lambda: w.rpc("getbestblockhash") == tip, 60, 0.25):
        raise Failed(f"{w.name} did not take {l.name}'s chain when joined")
    isolate(w)


def reorg_point(node, k, d, W, L):
    """node follows the winner W; the loser L mines a longer branch; node is
    given L as a peer and killed while it reorganizes"""
    by_log = k % 2 == 1 and not node.core
    delay = rng.uniform(0, 0.02) if by_log else rng.uniform(0, 0.8)

    def run():
        fork_h = W.rpc("getblockcount")
        if L.rpc("getbestblockhash") != W.rpc("getbestblockhash"):
            raise Failed("the miners do not share a tip before the point")
        # The old branch holds no lottery block (every 10th height): see LOTTERY
        if (fork_h // 10 + 1) * 10 - fork_h - 1 < 4:
            mine(W, (fork_h // 10 + 1) * 10 - fork_h)
            join(L, W)
            fork_h = W.rpc("getblockcount")
        a = rng.randint(4, (fork_h // 10 + 1) * 10 - fork_h - 1)
        mine(W, a)
        node.start(d, INDEX_CONF + [f"connect={W.addr}"])
        tip = W.rpc("getbestblockhash")
        if not wait_for(lambda: node.rpc("getbestblockhash") == tip, 120, 0.1):
            raise Failed(f"did not follow {W.name} before the point")
        b = a + rng.randint(2, 6)
        mine(L, b)
        node.rpc("addnode", L.addr, "onetry")
        if by_log and not wait_log(node, r"Disconnecting block", 30):
            raise Failed("no 'Disconnecting block' line within 30s of the longer branch")
        time.sleep(delay)
        node.kill9()
        how = restart_after_kill(node, d, INDEX_CONF)
        side, h = check_on_chain(node, [(W.name, W), (L.name, L)])
        old_tip, new_tip = fork_h + a, fork_h + b
        if h <= fork_h:
            where = f"at the fork h{h}"
        elif side == W.name:
            where = f"old tip h{h}" if h == old_tip else f"old branch partly disconnected h{h}/{old_tip}"
        else:
            where = f"new tip h{h}" if h == new_tip else f"new branch partly connected h{h}/{new_tip}"
        sync_to(node, d, INDEX_CONF, L, 120)
        u = utxo(node)
        if u != utxo(L) or u != hist[u[1]]:
            raise Failed(f"after sync {show_u(u)} != {L.name} {show_u(utxo(L))}")
        node.stop()
        trig = "after 'Disconnecting'" if by_log else "after addnode"
        return (f"delay={delay * 1000:.0f}ms {trig}; reorg {a}->{b} blocks; restart={how}; "
                f"{where}, UTXO set as clean; synced to {L.name} h{u[0]}")
    r = kill_point(f"reorg-kill{'-divid' if node.core else ''}", k, run, delay)
    join(W, L)
    return r


def reorg_rows():
    MINER_CONF[C1] = ["listen=1"]
    MINER_CONF[C2] = ["listen=1", f"connect={OFFLINE}"]
    isolate(C2)
    d = copy_of(TMPL, "r2-irondivid")
    results = []
    W, L = C1, C2
    for k in range(1, KILLS + 1):
        results.append(reorg_point(V, k, d, W, L))
        W, L = L, W
    done_with(d, (all(ok for ok, _ in results), ""))
    dk = copy_of(TMPL_C, "r2-divid")
    core = reorg_point(K, 1, dk, W, L)
    done_with(dk, core)
    return results, core


def compare(name, iron, core):
    """Row 6: the divid run of a row next to irondivid's"""
    i_ok = all(ok for ok, _ in iron)
    c_ok = core[0]
    i_ref = sum("restart=refused" in d for _, d in iron)
    c_ref = "restart=refused" in core[1]
    if i_ok and c_ok and (i_ref > 0) != c_ref:
        out("DIFFERS", name, f"both consistent; divid {'refused to start and needed -reindex' if c_ref else 'started'}, "
            f"irondivid refused at {i_ref} of {len(iron)} points")
    elif i_ok == c_ok:
        out("AS CORE", name, f"irondivid {'passes' if i_ok else 'fails'} and divid {'passes' if c_ok else 'fails'}")
    else:
        out("DIFFERS", name, f"irondivid {'passes' if i_ok else 'fails'}, divid {'passes' if c_ok else 'fails'}: "
            f"divid: {core[1][:200]}")


# --- the run -----------------------------------------------------------------------

note("row 1: kill -9 while syncing")
r1 = [row1_point(V, k, INDEX_CONF) for k in range(1, KILLS + 1)]
compare("sync-kill", r1, row1_point(K, 1, INDEX_CONF))
r1b = [first_start_point(V, k, INDEX_CONF) for k in range(1, KILLS + 1)]
compare("first-start-kill", r1b, first_start_point(K, 1, INDEX_CONF))

note("row 3: kill -9 during encryptwallet and walletpassphrasechange")
r3a = [wallet_point(V, k, "encrypt", TMPL) for k in range(1, KILLS + 1)]
compare("encrypt-kill", r3a, wallet_point(K, 1, "encrypt", TMPL_C))
r3b = [wallet_point(V, k, "change", TMPL_ENC) for k in range(1, KILLS + 1)]
compare("change-kill", r3b, wallet_point(K, 1, "change", TMPL_C_ENC))

note("row 4: kill -9 during -reindex with -txindex -addressindex -spentindex")
calibrate_reindex(V, TMPL)
calibrate_reindex(K, TMPL_C)
note(f"clean -reindex start: irondivid {REINDEX_SECS[V]:.2f}s, divid {REINDEX_SECS[K]:.2f}s")
r4 = [reindex_point(V, k, TMPL) for k in range(1, KILLS + 1)]
compare("reindex-kill", r4, reindex_point(K, 1, TMPL_C))

note("row 5: kill -9 after a spork call and after a -minrelaytxfee start")
r5a = [relay_point(V, k, TMPL, "spork") for k in range(1, KILLS + 1)]
compare("spork-kill", r5a, relay_point(K, 1, TMPL_C, "spork"))
if V in SPORK_ANSWERS and K in SPORK_ANSWERS:
    a, b = SPORK_ANSWERS[V], SPORK_ANSWERS[K]
    same = a[0] == b[0] and (a[0] == "ok" or a[1] == b[1])
    out("AS CORE" if same else "DIFFERS", "spork-change-answer",
        f"irondivid {show_answer(a)}; divid {show_answer(b)}")
r5b = [relay_point(V, k, TMPL, "relayfee") for k in range(1, KILLS + 1)]
compare("relayfee-kill", r5b, relay_point(K, 1, TMPL_C, "relayfee"))

note("row 2: kill -9 during a reorg between two Core miners")
r2, r2c = reorg_rows()
compare("reorg-kill", r2, r2c)

for n in (R, C1, C2):
    n.stop()
note(f"done in {time.time() - T0:.0f}s")
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
