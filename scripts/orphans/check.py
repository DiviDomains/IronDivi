#!/usr/bin/env python3
"""The orphan transaction pool of Divi Core divid and irondivid, compared case by
case from outside: each node is fed the same transactions by raw peers, and
what it holds is read from its mempool after a parent arrives, whether it asks
(getdata) for an announced transaction, what it relays to a second raw peer,
the sender's ban score and connection, and its -debug log.

Both wallets come from the same phrase and the nodes share a chain at first;
then irondivid runs alone, so each node sees only the raw peers made here, and
both have the same coins. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
"""

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:1600], flush=True)


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:120]}\""
    return json.dumps(out[1])[:700]


def compare(name, core, iron):
    """Same outcome: for an error the same code and text, for a result the same value"""
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(name, core, iron)
    return core, iron


def facts(name, fn):
    """A row of what each node shows, from fn(node)"""
    c, i = ("ok", fn(C)), ("ok", fn(I))
    compare(name, c, i)
    return c[1], i[1]


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"orph{index}:{password}".encode()).decode()
        self.base = [
            f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=orph{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1",
        ]
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def start(self, extra=("regtest=1",)):
        """('up',) once RPC answers, or ('exit', code, the first stderr line naming an error)"""
        self.write_conf(extra)
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.err = base + ".err"
        env = dict(os.environ, **self.env) if self.env else None
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code, self.error_line())
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.25)
        return ("exit", "none within %d s" % START_TIMEOUT, self.error_line())

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


def restart(extra=("regtest=1",)):
    for n in (C, I):
        n.stop()
    out = C.start(extra), I.start(extra)
    for n, o in zip((C, I), out):
        if o[0] != "up":
            print(f"FAIL   setup: {n.name} did not start with {list(extra)}: {o}", flush=True)
            sys.exit(1)


# --- a raw p2p peer ----------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])


def message(command, payload=b""):
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + check + payload


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def read_compact(b, pos):
    n = b[pos]
    if n < 0xfd:
        return n, pos + 1
    if n == 0xfd:
        return struct.unpack("<H", b[pos + 1:pos + 3])[0], pos + 3
    return struct.unpack("<I", b[pos + 1:pos + 5])[0], pos + 5


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


class Peer:
    """A raw peer from its own loopback address. `state` is 'up' after the
    handshake, 'refused' when the connection is refused or closed before it,
    or 'closed' once the node drops it."""

    def __init__(self, node, src, subver="Divi Core: 3.0.0.0", version=70920):
        self.node, self.src, self.version = node, src, version
        self.subver = subver.encode()
        self.sock = None
        self.invs, self.getdatas, self.txs = set(), set(), set()
        self.state = self.connect()

    def version_payload(self):
        return (struct.pack("<iQq", self.version, 1, int(time.time())) + netaddr(NODE_IP, self.node.p2p)
                + netaddr(self.src, 0) + secrets.token_bytes(8) + compact(len(self.subver)) + self.subver
                + struct.pack("<i", 0) + b"\x01")

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.bind((self.src, 0))
            self.sock.connect((NODE_IP, self.node.p2p))
            self.port = self.sock.getsockname()[1]
            self.sock.sendall(message("version", self.version_payload()))
            got_version = got_verack = False
            deadline = time.time() + 10
            while not (got_version and got_verack) and time.time() < deadline:
                command, payload = self.read()
                if command == "version":
                    got_version = True
                    n = payload[80]  # the subver, after version, services, time, two addresses, nonce
                    self.node_subver = payload[81:81 + n].decode(errors="replace")
                    self.sock.sendall(message("verack"))
                elif command == "verack":
                    got_verack = True
            return "up" if got_version and got_verack else "refused"
        except (OSError, EOFError):
            return "refused"

    def read(self):
        head = self.recv(24)
        command = head[4:16].rstrip(b"\0").decode()
        size = struct.unpack("<I", head[16:20])[0]
        return command, self.recv(size)

    def recv(self, n):
        out = b""
        while len(out) < n:
            part = self.sock.recv(n - len(out))
            if not part:
                raise EOFError
            out += part
        return out

    def send(self, command, payload=b""):
        try:
            self.sock.sendall(message(command, payload))
        except OSError:
            self.state = "closed"

    def pump(self, secs=1.0):
        """Read for `secs`, answering pings; 'closed' if the node drops the connection"""
        if self.state != "up":
            return self.state
        deadline = time.time() + secs
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                command, payload = self.read()
            except socket.timeout:
                break
            except (OSError, EOFError):
                self.state = "closed"
                break
            if command == "ping":
                self.send("pong", payload)
            elif command in ("inv", "getdata"):
                n, pos = read_compact(payload, 0)
                for k in range(n):
                    kind = struct.unpack("<I", payload[pos:pos + 4])[0]
                    item = payload[pos + 4:pos + 36][::-1].hex()
                    pos += 36
                    if kind == 1:
                        (self.invs if command == "inv" else self.getdatas).add(item)
            elif command == "tx":
                self.txs.add(hashlib.sha256(hashlib.sha256(payload).digest()).digest()[::-1].hex())
        return self.state

    def close(self):
        if self.sock:
            self.sock.close()
        self.state = "closed"


def peer_ips(node):
    return sorted(p["addr"].rsplit(":", 1)[0] for p in node.rpc("getpeerinfo"))


def peers_rows(what):
    """getconnectioncount and the peers' addresses, after `what`"""
    both(f"getconnectioncount ({what})", "getconnectioncount")
    facts(f"getpeerinfo addresses ({what})", peer_ips)


def peer_pair(src, **kw):
    """One raw peer to each node from `src`; a row of whether each got in"""
    return Peer(C, src, **kw), Peer(I, src, **kw)


def connect_row(name, src, **kw):
    pc, pi = peer_pair(src, **kw)
    compare(name, ("ok", pc.state), ("ok", pi.state))
    return pc, pi


def dropped_row(name, pc, pi, secs=3.0):
    compare(name, ("ok", pc.pump(secs)), ("ok", pi.pump(secs)))


# --- transactions, serialized here ------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SAT = 100_000_000


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    return n.to_bytes(25, "big")


def p2pkh(address):
    return bytes.fromhex("76a914") + b58decode(address)[1:21] + bytes.fromhex("88ac")


def push(b):
    return bytes([len(b)]) + b


def serialize(vin, vout, locktime=0, version=1):
    """vin: (txid, n, scriptSig bytes); vout: (satoshis, script bytes)"""
    b = struct.pack("<i", version) + compact(len(vin))
    for txid, n, script in vin:
        b += bytes.fromhex(txid)[::-1] + struct.pack("<I", n) + compact(len(script)) + script + b"\xff" * 4
    b += compact(len(vout))
    for value, script in vout:
        b += struct.pack("<q", value) + compact(len(script)) + script
    return (b + struct.pack("<I", locktime)).hex()


# --- logs ------------------------------------------------------------------------------

def log_path(node):
    for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
        if os.path.exists(path):
            return path
    return None


def log_mark(node):
    path = log_path(node)
    return (path, os.path.getsize(path)) if path else (None, 0)


def log_since(node, mark):
    """The log text written since `mark`, once the log has stopped growing: irondivid
    writes its log from a thread of its own, so the lines of what just happened can
    still be on their way (a second's silence is taken as the end, 5 s at most)"""
    path = log_path(node)
    if not path:
        return ""
    last, quiet, deadline = -1, 0, time.time() + 5
    while quiet < 3 and time.time() < deadline:
        size = os.path.getsize(path)
        quiet = quiet + 1 if size == last else 0
        last = size
        time.sleep(0.3)
    with open(path, "rb") as f:
        f.seek(mark[1] if mark[0] == path else 0)
        return f.read().decode(errors="replace")


# The -debug=mempool lines of OrphanTransactions.cpp and main.cpp:743-793
LOG_LINES = ("stored orphan tx", "ignoring large orphan tx", "accepted orphan tx", "invalid orphan tx",
             "removed orphan tx", "mapOrphan overflow", "orphan tx from peer")


def log_facts(text, *txids):
    """Which orphan log lines appear, and how often each txid is named in a 'stored' line"""
    out = {k: text.count(k) > 0 for k in LOG_LINES}
    for t in txids:
        out[f"stored lines naming {t[:8]}"] = sum(1 for line in text.splitlines() if "stored orphan tx" in line and t in line)
    return out


# --- start -----------------------------------------------------------------------------

DEBUG = ["regtest=1", "debug=mempool"]
C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
if C.start(DEBUG)[0] != "up":
    print("FAIL   setup: divid did not start", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I.env = {"WALLET_MNEMONIC": phrase}
del phrase
if I.start(DEBUG + [f"connect={NODE_IP}:{C.p2p}"])[0] != "up":
    print("FAIL   setup: irondivid did not start", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# Coins: 220 outputs of 1 DIVI in one confirmed transaction, and a coinbase
# one block deep (too young to spend: regtest coinbases mature after 20 blocks)
C.rpc("setgenerate", 30)
FAN = [C.rpc("getnewaddress") for _ in range(220)]
fan_txid = C.rpc("sendmany", "", {a: 1 for a in FAN})
C.rpc("setgenerate", 1)
YOUNG_CB = C.rpc("getblock", C.rpc("getbestblockhash"))["tx"][0]
OUT = [C.rpc("getnewaddress") for _ in range(4)]
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
fan = C.rpc("getrawtransaction", fan_txid, 1)
COINS = [(fan_txid, o["n"], round(float(o["value"]) * SAT), o["scriptPubKey"]["hex"])
         for o in fan["vout"] if round(float(o["value"]) * SAT) == SAT]
young = C.rpc("getrawtransaction", YOUNG_CB, 1)["vout"][0]
YOUNG = (YOUNG_CB, 0, round(float(young["value"]) * SAT), young["scriptPubKey"]["hex"])
I.stop()
if I.start(DEBUG)[0] != "up" or not wait_for(lambda: C.rpc("getconnectioncount") == 0, 30):
    print("FAIL   setup: irondivid did not start alone", flush=True)
    sys.exit(1)
print(f"# {len(COINS)} coins of 1 DIVI on both nodes", flush=True)


def take(n=1):
    out, COINS[:n] = COINS[:n], []
    return out


FEE = 100_000


def make(inputs, outputs, sign=True):
    """A transaction spending `inputs` [(txid, n, sats, spk_hex)] to `outputs`
    [(sats, address)], signed by divid's wallet; (hex, txid, [(txid, n, sats, spk_hex)] outputs)"""
    raw = serialize([(t, n, b"") for t, n, _, _ in inputs], [(v, p2pkh(a)) for v, a in outputs])
    if sign:
        prev = [{"txid": t, "vout": n, "scriptPubKey": spk} for t, n, _, spk in inputs]
        raw = C.rpc("signrawtransaction", raw, prev)["hex"]
    txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()
    outs = [(txid, k, v, p2pkh(a).hex()) for k, (v, a) in enumerate(outputs)]
    return raw, txid, outs


def spend(coin, n_out=1, to=0):
    """One coin spent to `n_out` equal outputs, less the fee"""
    each = (coin[2] - FEE) // n_out
    return make([coin], [(each, OUT[(to + k) % len(OUT)]) for k in range(n_out)])


# --- peers and what a node shows ------------------------------------------------------

def watchers():
    """A raw peer on each node that only listens: what the node relays"""
    return {C: Peer(C, "127.0.0.90"), I: Peer(I, "127.0.0.90")}


W = watchers()
SRC = iter(f"127.0.{a}.{b}" for a in range(1, 4) for b in range(10, 250))


def mempool(node):
    return set(node.rpc("getrawmempool"))


def settle(node, want, secs=10):
    """Wait until every txid in `want` is in the node's mempool or `secs` pass"""
    wait_for(lambda: want <= mempool(node), secs)


def relayed(node, txids, secs=12):
    """Which of `txids` the node announced to its watcher within `secs`"""
    w = W[node]
    deadline = time.time() + secs
    while time.time() < deadline and not set(txids) <= w.invs:
        w.pump(0.5)
    return sorted(t[:8] for t in txids if t in w.invs)


def feed(node, peer, hexes, pause=0.3):
    for h in hexes:
        peer.send("tx", bytes.fromhex(h))
        peer.pump(pause)


def asks(node, peer, txid, secs=4):
    """Whether the node answers an inv of `txid` from `peer` with a getdata"""
    peer.getdatas.discard(txid)
    peer.send("inv", compact(1) + struct.pack("<I", 1) + bytes.fromhex(txid)[::-1])
    deadline = time.time() + secs
    while time.time() < deadline and txid not in peer.getdatas:
        peer.pump(0.25)
    return txid in peer.getdatas


def score(node, peer):
    if peer.pump(0.5) != "up":
        return "dropped"
    return next((p.get("banscore") for p in node.rpc("getpeerinfo") if p["addr"] == f"{peer.src}:{peer.port}"),
                "gone")


def case(name, fn):
    """Run fn(node, src) on both nodes with one fresh source address; one row of what it returns"""
    src = next(SRC)
    marks = {n: log_mark(n) for n in (C, I)}
    c, i = fn(C, src, marks[C]), fn(I, src, marks[I])
    compare(name, ("ok", c), ("ok", i))
    return c, i


def short(txids, pool):
    return sorted(t[:8] for t in txids if t in pool)


# --- 1. children before parents (main.cpp:743-782) ---------------------------------------

def child_then_parent(txs, order, extra=None):
    """Send txs (hex, txid) in `order` from one peer; what is in the mempool and relayed"""
    def run(node, src, mark):
        p = Peer(node, src)
        ids = [t for _, t in txs]
        # all but the last sent first: what the node announces while it holds them
        feed(node, p, [txs[k][0] for k in order[:-1]])
        early = relayed(node, ids, secs=3)
        feed(node, p, [txs[order[-1]][0]])
        settle(node, set(ids))
        pool = mempool(node)
        out = {"announced before the last arrives": early, "in the mempool": short(ids, pool),
               "relayed": relayed(node, [t for t in ids if t in pool]), "peer": score(node, p),
               "log": log_facts(log_since(node, mark), *ids)}
        if extra:
            out.update(extra(node, p, pool))
        p.close()
        return out
    return run


par, par_id, par_out = spend(take()[0])
kid, kid_id, _ = spend(par_out[0])
case("a child, then its parent", child_then_parent([(par, par_id), (kid, kid_id)], [1, 0]))

a_hex, a_id, a_out = spend(take()[0])
b_hex, b_id, b_out = spend(a_out[0])
c_hex, c_id, _ = spend(b_out[0])
case("a chain of three, last first", child_then_parent([(a_hex, a_id), (b_hex, b_id), (c_hex, c_id)], [2, 1, 0]))

p2, p2_id, p2_out = spend(take()[0], n_out=2)
k1, k1_id, _ = spend(p2_out[0])
k2, k2_id, _ = spend(p2_out[1], to=1)
case("two children of one parent, then the parent",
     child_then_parent([(p2, p2_id), (k1, k1_id), (k2, k2_id)], [1, 2, 0]))

# a child of two parents: one arrives, then the other
m1, m1_id, m1_out = spend(take()[0])
m2, m2_id, m2_out = spend(take()[0])
both_kid, both_kid_id, _ = make([m1_out[0], m2_out[0]], [(m1_out[0][2] + m2_out[0][2] - FEE, OUT[2])])


def second_parent(node, p, pool):
    feed(node, p, [m2])
    settle(node, {m2_id, both_kid_id})
    after = mempool(node)
    return {"after the second parent": short([m2_id, both_kid_id], after)}


case("a child whose second parent is still missing, then that parent",
     child_then_parent([(m1, m1_id), (both_kid, both_kid_id)], [1, 0], extra=second_parent))

# the same orphan twice: kept once (OrphanTransactions.cpp:47-48)
t_par, t_par_id, t_out = spend(take()[0])
t_kid, t_kid_id, _ = spend(t_out[0])
case("the same orphan twice, then its parent",
     child_then_parent([(t_par, t_par_id), (t_kid, t_kid_id)], [1, 1, 0]))


# --- 2. orphan size, and getdata for an inv (OrphanTransactions.cpp:52-61, main.cpp:140-144)

def filler(n):
    """A push-only scriptSig of exactly n bytes"""
    out = b""
    while n - len(out) > 76:
        out += push(secrets.token_bytes(75))
    rest = n - len(out)
    return out + (push(secrets.token_bytes(rest - 1)) if rest > 1 else b"\x00")


def orphan_of_size(size):
    """An unsigned orphan of exactly `size` bytes: one input of an unknown
    transaction, 140 outputs of 0.01 DIVI; its scriptSig pads it"""
    outs = [(SAT // 100, p2pkh(OUT[k % len(OUT)])) for k in range(140)]
    base = len(bytes.fromhex(serialize([(secrets.token_hex(32), 0, b"")], outs)))
    raw = serialize([(secrets.token_hex(32), 0, filler(size - base))], outs)
    assert len(raw) // 2 == size, (len(raw) // 2, size)
    return raw, hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest()[::-1].hex()


def held(raw, txid):
    """Send `raw` from one peer; whether a second peer's inv of it gets a getdata"""
    def run(node, src, mark):
        p = Peer(node, src)
        feed(node, p, [raw], pause=1.0)
        q = Peer(node, next(SRC))
        # Only the lines about this transaction: the erase of an earlier
        # case's orphans, when its peer went, may be logged in this window
        log = log_facts(log_since(node, mark), txid)
        out = {"announced": relayed(node, [txid], secs=3),
               "getdata for its inv from another peer": asks(node, q, txid),
               "log": {k: v for k, v in log.items() if k in ("stored orphan tx", "ignoring large orphan tx")
                       or k.startswith("stored lines")}}
        p.close()
        q.close()
        return out
    return run


for size in (5000, 5001):
    raw, txid = orphan_of_size(size)
    case(f"an orphan of {size} bytes", held(raw, txid))

# a transaction the mempool refused (not an orphan): divid asks for it again
refused, refused_id, _ = make([take()[0]], [(SAT * 2, OUT[0])])  # pays out more than it has
case("a transaction refused by the mempool", held(refused, refused_id))


def never_sent(node, src, mark):
    q = Peer(node, src)
    out = {"getdata for an inv of a transaction never seen": asks(node, q, secrets.token_hex(32))}
    q.close()
    return out


case("an inv of an unknown transaction", never_sent)


# --- 3. a peer that goes, and one that stays (EraseOrphansFor, NodeState.cpp:41) --------
g_par, g_par_id, g_out = spend(take()[0])
g_kid, g_kid_id, _ = spend(g_out[0])
s_par, s_par_id, s_out = spend(take()[0])
s_kid, s_kid_id, _ = spend(s_out[0])


def gone_and_stays(node, src, mark):
    goes, stays, parents = Peer(node, src), Peer(node, next(SRC)), Peer(node, next(SRC))
    feed(node, goes, [g_kid])
    feed(node, stays, [s_kid])
    goes.close()
    time.sleep(2)
    feed(node, parents, [g_par, s_par])
    settle(node, {g_par_id, s_par_id, s_kid_id})
    pool = mempool(node)
    out = {"in the mempool": short([g_par_id, g_kid_id, s_par_id, s_kid_id], pool),
           "log": log_facts(log_since(node, mark), g_kid_id, s_kid_id)}
    stays.close()
    parents.close()
    return out


case("the sender of one orphan goes before its parent comes; another stays", gone_and_stays)


# --- 4. an orphan found invalid once its parent comes (main.cpp:760-776) -----------------

def invalid_orphan(kid_hex, kid_id, par_hex, par_id, before=None):
    def run(node, src, mark):
        if before:
            before(node)
        sender, parents = Peer(node, src), Peer(node, next(SRC))
        feed(node, sender, [kid_hex], pause=1.0)
        feed(node, parents, [par_hex])
        settle(node, {par_id})
        time.sleep(1)
        pool = mempool(node)
        out = {"in the mempool": short([par_id, kid_id], pool), "parent relayed": relayed(node, [par_id]),
               "the orphan's sender": score(node, sender), "the parent's sender": score(node, parents),
               "log": log_facts(log_since(node, mark), kid_id)}
        sender.close()
        parents.close()
        return out
    return run


# a bad signature: the output changed after signing
x_par, x_par_id, x_out = spend(take()[0])
signed_kid, _, _ = spend(x_out[0])
bad = bytearray(bytes.fromhex(signed_kid))
bad[-12] ^= 0x01  # in the output's value
bad_hex = bad.hex()
bad_id = hashlib.sha256(hashlib.sha256(bytes(bad)).digest()).digest()[::-1].hex()
case("an orphan with a bad signature, then its parent", invalid_orphan(bad_hex, bad_id, x_par, x_par_id))

# spends a coinbase one block deep with its parent's output
y_par, y_par_id, y_out = spend(take()[0])
y_kid, y_kid_id, _ = make([y_out[0], YOUNG], [(y_out[0][2] + YOUNG[2] - FEE, OUT[1])])
case("an orphan spending a coinbase too young, then its parent", invalid_orphan(y_kid, y_kid_id, y_par, y_par_id))

# spends, with its parent's output, a coin a mempool transaction spends
z_par, z_par_id, z_out = spend(take()[0])
taken_coin = take()[0]
first, first_id, _ = spend(taken_coin, to=2)
z_kid, z_kid_id, _ = make([z_out[0], taken_coin], [(z_out[0][2] + taken_coin[2] - FEE, OUT[3])])
case("an orphan spending a coin a mempool transaction spends, then its parent",
     invalid_orphan(z_kid, z_kid_id, z_par, z_par_id, before=lambda n: n.rpc("sendrawtransaction", first)))


# --- 5. the parent in a block, not relayed ---------------------------------------------
b_par, b_par_id, b_out = spend(take()[0])
b_kid, b_kid_id, _ = spend(b_out[0])


def parent_in_block(node, src, mark):
    p = Peer(node, src)
    feed(node, p, [b_kid], pause=1.0)
    node.rpc("sendrawtransaction", b_par)
    time.sleep(1)
    after_rpc = short([b_par_id, b_kid_id], mempool(node))
    node.rpc("setgenerate", 1)
    time.sleep(2)
    block = node.rpc("getblock", node.rpc("getbestblockhash"))["tx"]
    after_block = short([b_kid_id], mempool(node))
    feed(node, p, [b_kid])
    settle(node, {b_kid_id})
    out = {"in the mempool after sendrawtransaction of the parent": after_rpc,
           "the parent in the block": b_par_id in block, "the child in the mempool after the block": after_block,
           "the child in the mempool when sent again": short([b_kid_id], mempool(node)),
           "log": log_facts(log_since(node, mark), b_kid_id)}
    p.close()
    return out


case("an orphan whose parent comes by sendrawtransaction and a block", parent_in_block)


# --- 6. a restart between child and parent: the pool is in memory only --------------------
r_par, r_par_id, r_out = spend(take()[0])
r_kid, r_kid_id, _ = spend(r_out[0])
src = next(SRC)
for n in (C, I):
    feed(n, Peer(n, src), [r_kid], pause=1.0)
restart(DEBUG)
W = watchers()
src = next(SRC)
for n in (C, I):
    feed(n, Peer(n, src), [r_par])
    settle(n, {r_par_id, r_kid_id})
facts("a restart between an orphan and its parent: in the mempool after the parent",
      lambda n: short([r_par_id, r_kid_id], mempool(n)))


# --- 7. -maxorphantx (main.cpp:789-792; default 100, defaultValues.h:64) -----------------
for setting, sent in (("0", 5), ("1", 6), (None, 105), ("-5", 10), ("abc", 10)):
    label = f"-maxorphantx={setting}" if setting is not None else "-maxorphantx not given (100)"
    pairs = []
    for coin in take(sent):
        ph, pid, pout = spend(coin)
        kh, kid_, _ = spend(pout[0])
        pairs.append((ph, pid, kh, kid_))
    restart(DEBUG + ([f"maxorphantx={setting}"] if setting is not None else []))
    W = watchers()

    def limit_run(node, src, mark):
        p = Peer(node, src)
        feed(node, p, [k for _, _, k, _ in pairs], pause=0.05)
        p.pump(2)
        feed(node, p, [ph for ph, _, _, _ in pairs], pause=0.05)
        settle(node, {pid for _, pid, _, _ in pairs}, secs=30)
        time.sleep(2)
        pool = mempool(node)
        text = log_since(node, mark)
        out = {"parents in the mempool": sum(pid in pool for _, pid, _, _ in pairs),
               "children in the mempool": sum(k in pool for _, _, _, k in pairs),
               "overflow logged": "mapOrphan overflow" in text}
        p.close()
        return out

    case(f"{sent} orphans then their parents, {label}", limit_run)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
