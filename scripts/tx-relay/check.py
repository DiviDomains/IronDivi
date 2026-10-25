#!/usr/bin/env python3
"""Transaction relay in a network of Divi Core divid and irondivid on regtest.
Two sides, each a divid bridge with a divid and an irondivid behind it (dialling
it), joined by `addnode onetry` from one bridge to the other and split by a
restart. Transactions are sent from each kind of node, and from a minimal peer
of this script's own, and each row compares which mempools they reach within a
bounded time, between the divid and the irondivid behind the same bridge: plain
sends, a parent and its child, a child before its parent, sends below and at the
relay fee floor and free ones, a non-standard transaction with
-acceptnonstandard, a vault funding and reclaim, the mempool after a restart,
and two conflicting spends on the two sides of a split, one confirmed by a block
of the other side. Each row prints PASS (irondivid as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import struct
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
INJECT = os.environ.get("TX_RELAY_INJECT", "")
# For looking into a difference: both replies of every row that differs
DUMP = os.environ.get("TX_RELAY_DUMP", "")
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
        self.user = f"relay{index}"
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
# Behind the bridges the nodes listen too, for this script's own peer; side L's
# pair takes non-standard transactions
I1 = Node("irondivid-L", IRONDIVID, 1, ["listen=1", "acceptnonstandard=1", lambda: f"connect=127.0.0.1:{C1.p2p}"])
C2 = Node("bridge-R", DIVID, 2, ["listen=1"])
I2 = Node("irondivid-R", IRONDIVID, 3, ["listen=1", lambda: f"connect=127.0.0.1:{C2.p2p}"])
C3 = Node("divid-L", DIVID, 4, ["listen=1", "acceptnonstandard=1", lambda: f"connect=127.0.0.1:{C1.p2p}"])
C4 = Node("divid-R", DIVID, 5, ["listen=1", lambda: f"connect=127.0.0.1:{C2.p2p}"])
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


def spend(node, coin, dest, fee=0.001):
    amount = round(coin["amount"] - fee, 8)
    raw = node.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}], {dest: amount})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign")
    return node.rpc("sendrawtransaction", signed["hex"])




LABELS = {}  # txid: the step that sent it, for rows that list transactions
USED = set()  # coins this script has spent


def fresh_coin(node):
    """A confirmed coin of the shared wallet this script has not spent (the
    wallet's own sends, such as fundvault, pick coins too)"""
    for u in sorted(node.rpc("listunspent", 1), key=lambda u: (-u["amount"], u["txid"], u["vout"])):
        if (u["txid"], u["vout"]) not in USED and u["amount"] >= 1:
            USED.add((u["txid"], u["vout"]))
            return u
    need(False, f"{node.name} has no coin left")


def named(txids):
    return sorted(LABELS.get(t, t[:12]) for t in txids)


def sat(amount):
    return int(round(amount * 1e8))


def build(node, coins, outputs, prevtxs=None):
    """A signed transaction spending `coins` to {address: satoshis}; its hex.
    prevtxs: the outputs spent that the node cannot see yet"""
    raw = node.rpc("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]} for c in coins],
                   {a: round(v / 1e8, 8) for a, v in outputs.items()})
    signed = node.rpc("signrawtransaction", raw, prevtxs) if prevtxs else node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign")
    return signed["hex"]


def txid_of(node, hex_tx):
    return node.rpc("decoderawtransaction", hex_tx)["txid"]


def child_coin(parent_hex, node, vout=0):
    tx = node.rpc("decoderawtransaction", parent_hex)
    return {"txid": tx["txid"], "vout": vout, "amount": tx["vout"][vout]["value"],
            "scriptPubKey": tx["vout"][vout]["scriptPubKey"]["hex"]}


def prevtx(coin):
    return [{"txid": coin["txid"], "vout": coin["vout"], "scriptPubKey": coin["scriptPubKey"]}]


# --- a minimal peer of this script's own (version, verack, tx) --------------------------

REGTEST_MAGIC = bytes([0xA1, 0xCF, 0x7E, 0xAC])  # Divi Core regtest pchMessageStart
PROTOCOL_VERSION = 70915


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(command, payload):
    return (REGTEST_MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + sha256d(payload)[:4] + payload)


def net_addr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", port)


class RawPeer:
    """Connects to a node, completes the handshake, and sends transactions in
    the order given, as a peer relaying them would"""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        ua = b"/tx-relay-check:1/"
        payload = (struct.pack("<iQq", PROTOCOL_VERSION, 1, int(time.time())) + net_addr(port) + net_addr(0)
                   + secrets.token_bytes(8) + bytes([len(ua)]) + ua + struct.pack("<i", 0))
        self.sock.sendall(message("version", payload))
        got_version = got_verack = False
        deadline = time.time() + 15
        buf = b""
        while not (got_version and got_verack) and time.time() < deadline:
            data = self.sock.recv(65536)
            if not data:
                break
            buf += data
            while len(buf) >= 24:
                length = struct.unpack("<I", buf[16:20])[0]
                if len(buf) < 24 + length:
                    break
                command = buf[4:16].rstrip(b"\0").decode(errors="replace")
                buf = buf[24 + length:]
                if command == "version":
                    got_version = True
                    self.sock.sendall(message("verack", b""))
                elif command == "verack":
                    got_verack = True
        need(got_version and got_verack, f"no handshake with the node on port {port}")

    def send_tx(self, hex_tx):
        self.sock.sendall(message("tx", bytes.fromhex(hex_tx)))

    def close(self):
        self.sock.close()


# --- how arrival is compared ---------------------------------------------------------------

ARRIVAL = 30  # seconds a transaction is given to reach a mempool


def arrived(txids, nodes, secs=ARRIVAL):
    """{node name: True if every txid reached its mempool within secs}"""
    got = {n.name: False for n in nodes}
    deadline = time.time() + secs
    while time.time() < deadline and not all(got.values()):
        for n in nodes:
            if not got[n.name]:
                pool = n.call("getrawmempool")
                got[n.name] = pool[0] == "ok" and all(t in pool[1] for t in txids)
        time.sleep(0.5)
    return got


def arrival_rows(label, txids, secs=ARRIVAL):
    """Whether the transactions reached the divid and the irondivid behind each
    bridge within secs"""
    got = arrived(txids, [n for _, c, i in PAIRS for n in (c, i)], secs)
    for side, c, i in PAIRS:
        cv, iv = got[c.name], got[i.name]
        if f"{label} ({side})" == INJECT:
            iv = not iv
        row(f"{label} ({side})", f"in mempool within {secs} s: {cv}", f"{iv}", cv == iv, (("ok", cv), ("ok", iv)))
    return got


def absent_rows(label, txids, secs=10):
    """After `secs`, whether the transactions are in each pair's mempools"""
    time.sleep(secs)
    for side, c, i in PAIRS:
        cv = all(t in c.rpc("getrawmempool") for t in txids)
        iv = all(t in i.rpc("getrawmempool") for t in txids)
        if f"{label} ({side})" == INJECT:
            iv = not iv
        row(f"{label} ({side})", f"in mempool after {secs} s: {cv}", f"{iv}", cv == iv, (("ok", cv), ("ok", iv)))


def outcome_row(name, c, i):
    """sendrawtransaction on a divid and an irondivid: taken (a txid) or refused
    (the error code; the texts are compared by scripts/reject-replies)"""
    cs = "txid" if c[0] == "ok" else f"error {c[1]}"
    is_ = "txid" if i[0] == "ok" else f"error {i[1]}"
    if name == INJECT:
        is_ = "injected"
    text = lambda o: f" ({str(o[2])[:60]})" if o[0] == "err" else ""
    row(name, cs + text(c), is_ + text(i), cs == is_, (c, i))


# --- start: one network, one wallet on side L's pair (and irondivid R) -------------------

for n in (C1, C2, C3, C4):
    need(n.start(), f"{n.name} did not start: {n.why}")
phrase = C3.rpc("dumphdinfo")["mnemonic"]
need(I1.start({"WALLET_MNEMONIC": phrase}), f"irondivid L did not start: {I1.why}")
need(I2.start({"WALLET_MNEMONIC": phrase}), f"irondivid R did not start: {I2.why}")
del phrase
print(f"# divid {C1.rpc('getinfo').get('version')}, irondivid {I1.rpc('getnetworkinfo').get('version')}", flush=True)
need(wait_for(connected_within_sides, 60), "a side did not connect")
join()
mine(C3, 40)
need(one_tip(), "the nodes did not follow the first 40 blocks")
need(wait_for(lambda: I1.rpc("getbalance") == C3.rpc("getbalance") and I2.rpc("getbalance") > 0, 60),
     "the irondivid wallets did not find divid's coins")

coins = sorted(C3.rpc("listunspent"), key=lambda u: (u["txid"], u["vout"]))
need(len(coins) >= 14, f"only {len(coins)} coins in the wallet")
pool = iter(coins)
ADDR = [C3.rpc("getnewaddress") for _ in range(12)]
FEE = 100000  # 0.001 DIVI, far above the floor

# Small coins for the fee floor rows: spent one block after they are made they
# have too little priority to go free (MempoolConsensus.cpp:255-259)
big = next(pool)
small_hex = build(C3, [big], {ADDR[0]: 1000000, ADDR[1]: 1000000, ADDR[2]: 1000000, ADDR[3]: 1000000,
                              ADDR[4]: sat(big["amount"]) - 4000000 - FEE})
small_txid = C3.rpc("sendrawtransaction", small_hex)
mine(C3, 1)
need(one_tip(), "the nodes did not follow")
small = [{"txid": small_txid, "vout": v, "amount": 0.01} for v in range(4)]

# --- 1. plain sends, from each kind -------------------------------------------------------

c1 = next(pool)
t1 = C3.rpc("sendrawtransaction", build(C3, [c1], {ADDR[5]: sat(c1["amount"]) - FEE}))
LABELS[t1] = "plain send from divid-L"
arrival_rows("plain send from divid-L", [t1])
c2 = next(pool)
t2 = I1.rpc("sendrawtransaction", build(I1, [c2], {ADDR[5]: sat(c2["amount"]) - FEE}))
LABELS[t2] = "plain send from irondivid-L"
arrival_rows("plain send from irondivid-L", [t2])

# --- 2. a parent and its child, sent in order, from each kind ----------------------------

for origin in (C3, I1):
    coin = next(pool)
    parent = build(origin, [coin], {ADDR[6]: sat(coin["amount"]) - FEE})
    pid = origin.rpc("sendrawtransaction", parent)
    child = build(origin, [child_coin(parent, origin)], {ADDR[7]: sat(coin["amount"]) - 2 * FEE})
    cid = origin.rpc("sendrawtransaction", child)
    LABELS[pid], LABELS[cid] = f"parent from {origin.name}", f"child from {origin.name}"
    arrival_rows(f"parent then child from {origin.name}", [pid, cid])

# --- 3. a child before its parent, from this script's peer, to each kind -----------------

for target in (C3, I1):
    coin = next(pool)
    parent = build(target, [coin], {ADDR[8]: sat(coin["amount"]) - FEE})
    out = child_coin(parent, target)
    child = build(target, [out], {ADDR[9]: sat(coin["amount"]) - 2 * FEE}, prevtx(out))
    peer = RawPeer(target.p2p)
    peer.send_tx(child)
    time.sleep(2)
    orphan_only = (txid_of(target, child) in target.rpc("getrawmempool"))
    row(f"child before its parent to {target.name}: the child alone is not in its mempool",
        "", "", not orphan_only)
    peer.send_tx(parent)
    LABELS[txid_of(target, parent)] = f"late parent to {target.name}"
    LABELS[txid_of(target, child)] = f"early child to {target.name}"
    arrival_rows(f"child then parent to {target.name}", [txid_of(target, parent), txid_of(target, child)])
    peer.close()

# --- 4. the relay fee floor -------------------------------------------------------------


def at_fee(node, coin, dest, fee_for):
    """A transaction of `coin` whose fee is exactly fee_for(its size). A new
    fee or destination changes the signature's length and so the size: each
    try goes to a new address of the wallet, with the fee the last size asks
    for, until one matches its own transaction"""
    fee = 2000
    for _ in range(60):
        hex_tx = build(node, [coin], {dest: sat(coin["amount"]) - fee})
        want = fee_for(len(hex_tx) // 2)
        if want == fee:
            return hex_tx
        fee, dest = want, node.rpc("getnewaddress")
    need(False, f"no fee matched its transaction's size on {node.name}")


FLOOR_PER_KB = 10000  # -minrelaytxfee default, 0.0001 DIVI per kB (FeeAndPriorityCalculator)
under_c = at_fee(C3, small[0], ADDR[10], lambda size: FLOOR_PER_KB * size // 1000 - 1)
under_i = at_fee(I1, small[1], ADDR[10], lambda size: FLOOR_PER_KB * size // 1000 - 1)
outcome_row("one satoshi under the fee floor, young coin: sendrawtransaction",
            C3.call("sendrawtransaction", under_c), I1.call("sendrawtransaction", under_i))
at_c = at_fee(C3, small[2], ADDR[10], lambda size: FLOOR_PER_KB * size // 1000)
at_i = at_fee(I1, small[3], ADDR[10], lambda size: FLOOR_PER_KB * size // 1000)
oc, oi = C3.call("sendrawtransaction", at_c), I1.call("sendrawtransaction", at_i)
LABELS[txid_of(C3, at_c)], LABELS[txid_of(I1, at_i)] = "fee floor, divid-L", "fee floor, irondivid-L"
outcome_row("the fee floor exactly, young coin: sendrawtransaction", oc, oi)
for label, out in (("from divid-L", oc), ("from irondivid-L", oi)):
    if out[0] == "ok":
        arrival_rows(f"the fee floor exactly {label}", [out[1]])
old = [next(pool), next(pool)]
free_c = build(C3, [old[0]], {ADDR[11]: sat(old[0]["amount"])})
free_i = build(I1, [old[1]], {ADDR[11]: sat(old[1]["amount"])})
fc, fi = C3.call("sendrawtransaction", free_c), I1.call("sendrawtransaction", free_i)
LABELS[txid_of(C3, free_c)], LABELS[txid_of(I1, free_i)] = "free, divid-L", "free, irondivid-L"
outcome_row("no fee, old coin (priority): sendrawtransaction", fc, fi)
for label, out in (("from divid-L", fc), ("from irondivid-L", fi)):
    if out[0] == "ok":
        arrival_rows(f"no fee, old coin {label}", [out[1]])

# --- 5. a non-standard transaction (an OP_TRUE output), side L's pair has -acceptnonstandard --


def nonstandard(node, coin):
    """A spend of coin to one OP_TRUE output: the P2PKH script made by
    createrawtransaction is replaced before signing"""
    addr = node.rpc("getnewaddress")
    raw = node.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}],
                   {addr: round(coin["amount"] - FEE / 1e8, 8)})
    spk = node.rpc("decoderawtransaction", raw)["vout"][0]["scriptPubKey"]["hex"]
    need(raw.count("19" + spk) == 1, "could not find the output script")
    raw = raw.replace("19" + spk, "0151")
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign")
    return signed["hex"]


ns_c, ns_i = nonstandard(C3, next(pool)), nonstandard(I1, next(pool))
LABELS[txid_of(C3, ns_c)], LABELS[txid_of(I1, ns_i)] = "non-standard, divid-L", "non-standard, irondivid-L"
nc, ni = C3.call("sendrawtransaction", ns_c), I1.call("sendrawtransaction", ns_i)
outcome_row("non-standard, with -acceptnonstandard: sendrawtransaction", nc, ni)
ids = [o[1] for o in (nc, ni) if o[0] == "ok"]
time.sleep(10)
for side, c, i in PAIRS:
    if side == "R":
        cv = [t in c.rpc("getrawmempool") for t in ids]
        iv = [t in i.rpc("getrawmempool") for t in ids]
        row("non-standard: reached side R (no -acceptnonstandard there)", cv, iv, cv == iv)
# Bridge L, a divid without -acceptnonstandard, is no pair: what it holds is shown, not compared
print(f"# non-standard: in bridge L's mempool: {[t in C1.rpc('getrawmempool') for t in ids]}", flush=True)
# Each stays on the node that took it (the bridge refuses it): each node mines
# its own into a block, so the later rows see only relayed transactions
for n, t in ((C3, nc), (I1, ni)):
    if t[0] == "ok":
        mine(n, 1)
        need(one_tip(), "the nodes did not follow")
        need(t[1] not in n.rpc("getrawmempool"), f"{n.name} did not mine its non-standard transaction")

# --- 6. a vault funding and a reclaim, from each kind --------------------------------------

for origin in (C3, I1):
    own, mgr, dest = origin.rpc("getnewaddress"), origin.rpc("getnewaddress"), origin.rpc("getnewaddress")
    fund = origin.call("fundvault", f"{own}:{mgr}", 100)
    need(fund[0] == "ok", f"{origin.name} fundvault: {fund}")
    fund_txid = fund[1]["txhash"] if isinstance(fund[1], dict) and "txhash" in fund[1] else fund[1]
    LABELS[fund_txid] = f"vault funding from {origin.name}"
    arrival_rows(f"vault funding from {origin.name}", [fund_txid])
    mine(C1, 1)
    one_tip()
    rec = origin.call("reclaimvaultfunds", dest, 50)
    need(rec[0] == "ok", f"{origin.name} reclaimvaultfunds: {rec}")
    rec_txid = rec[1]["txhash"] if isinstance(rec[1], dict) and "txhash" in rec[1] else rec[1]
    LABELS[rec_txid] = f"vault reclaim from {origin.name}"
    arrival_rows(f"vault reclaim from {origin.name}", [rec_txid])

# --- 7. the mempool after a restart of side L's pair --------------------------------------

c7 = fresh_coin(C3)
lone = C3.rpc("sendrawtransaction", build(C3, [c7], {ADDR[5]: sat(c7["amount"]) - FEE}))
LABELS[lone] = "wallet send before the restart"
before = {n.name: named(n.rpc("getrawmempool")) for n in (C3, I1)}
print(f"# mempool before the restart: divid-L {before[C3.name]}, irondivid-L {before[I1.name]}", flush=True)
arrival_rows("before the restart: a wallet send", [lone])
for n in (C3, I1):
    n.stop()
for n in (C3, I1):
    need(n.start(), f"{n.name} did not start again: {n.why}")
need(wait_for(connected_within_sides, 60), "a side did not connect again")
time.sleep(5)
c_pool, i_pool = sorted(C3.rpc("getrawmempool")), sorted(I1.rpc("getrawmempool"))
compare("after a restart of side L's pair: getrawmempool (L)", ("ok", named(c_pool)), ("ok", named(i_pool)))
row("after a restart: the wallet's own unconfirmed send is back in the mempool (L)",
    lone in c_pool, lone in i_pool, (lone in c_pool) == (lone in i_pool))

# --- 8. conflicting spends on the two sides of a split; a block of side R ----------------

mine(C1, 1)
need(one_tip(), "the nodes did not follow")
x = fresh_coin(C3)
split()
t_a = C3.rpc("sendrawtransaction", build(C3, [x], {ADDR[5]: sat(x["amount"]) - FEE}))
t_b = I2.rpc("sendrawtransaction", build(I2, [x], {ADDR[6]: sat(x["amount"]) - 2 * FEE}))
need(wait_for(lambda: t_a in C1.rpc("getrawmempool") and t_b in C2.rpc("getrawmempool"), 30),
     "the bridges did not take their side's spend")
join()
time.sleep(10)
for side, c, i in PAIRS:
    cv = (t_a in c.rpc("getrawmempool"), t_b in c.rpc("getrawmempool"))
    iv = (t_a in i.rpc("getrawmempool"), t_b in i.rpc("getrawmempool"))
    row(f"conflicting spends after the join: (side L's, side R's) in the mempool ({side})", cv, iv, cv == iv)
mine(C2, 1)
need(one_tip(), "the nodes did not follow side R's block")
time.sleep(3)
for side, c, i in PAIRS:
    cv = (t_a in c.rpc("getrawmempool"), t_b in c.rpc("getrawmempool"))
    iv = (t_a in i.rpc("getrawmempool"), t_b in i.rpc("getrawmempool"))
    row(f"after side R's block confirms its spend: (side L's, side R's) in the mempool ({side})", cv, iv, cv == iv)

for n in ALL:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
