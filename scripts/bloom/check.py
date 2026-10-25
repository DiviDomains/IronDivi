#!/usr/bin/env python3
"""Bloom filters and filtered blocks as Divi Core divid and irondivid serve
them to light clients, on regtest: one divid and one irondivid on one chain
(irondivid dials divid), and a peer of this script's own that speaks the wire
protocol to each, sends the same messages and compares what comes back: the
NODE_BLOOM service bit, the filter messages and the bans they earn, the
merkleblock of a filtered getdata bit for bit and the transactions after it,
announcements of new transactions under each update flag and with relay off,
vault and coinstake outputs, and all of it with -peerbloomfilters=0. Each row
prints PASS (irondivid as divid), KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs.

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
INJECT = os.environ.get("BLOOM_INJECT", "")
# For looking into a difference: both replies of every row that differs
DUMP = os.environ.get("BLOOM_DUMP", "")
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
        self.user = f"bloom{index}"
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



FEE = 100000  # 0.001 DIVI


# --- the two nodes: divid C and irondivid I on one chain --------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=1", lambda: f"connect=127.0.0.1:{C.p2p}"])
BOTH = (C, I)
PEER_IP = "127.0.0.3"  # this script's peer: a ban it earns leaves the nodes' own link alone


def start_both(extra=()):
    for n in BOTH:
        n.extra = [e for e in n.extra if not (isinstance(e, str) and e.startswith("peerbloomfilters="))]
        n.extra += list(extra)
    need(C.start(), f"divid did not start: {C.why}")
    need(I.start(), f"irondivid did not start: {I.why}")
    need(wait_for(lambda: C.rpc("getconnectioncount") >= 1 and I.rpc("getconnectioncount") >= 1, 60),
         "irondivid did not connect to divid")


def stop_both():
    for n in (I, C):
        n.stop()


def synced():
    return wait_for(lambda: C.rpc("getbestblockhash") == I.rpc("getbestblockhash"), 90)


# --- Divi Core's bloom filter, made here as divid's bloom.cpp makes it ----------------------

def murmur3(seed, data):
    c1, c2, h1, m = 0xcc9e2d51, 0x1b873593, seed & 0xffffffff, 0xffffffff
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & m
    n = len(data) // 4
    for i in range(n):
        k1 = int.from_bytes(data[4 * i:4 * i + 4], "little")
        k1 = rotl((k1 * c1) & m, 15) * c2 & m
        h1 = (rotl(h1 ^ k1, 13) * 5 + 0xe6546b64) & m
    tail, k1 = data[4 * n:], 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = rotl((k1 * c1) & m, 15) * c2 & m
        h1 ^= k1
    h1 ^= len(data)
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & m
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & m
    return h1 ^ (h1 >> 16)


assert murmur3(0xFBA4C795, bytes.fromhex("00")) == 0xea3f0b17  # hash_tests.cpp


class Bloom:
    """CBloomFilter(nElements, nFPRate, nTweak, nFlags), bloom.cpp:23-39"""

    def __init__(self, elements, fp, tweak, flags):
        import math
        size = min(int(-1 / 0.4804530139182014 * elements * math.log(fp)), 36000 * 8) // 8
        self.data = bytearray(size)
        self.funcs = min(int(size * 8 / elements * 0.6931471805599453), 50)
        self.tweak, self.flags = tweak, flags

    def insert(self, item):
        for n in range(self.funcs):
            i = murmur3((n * 0xFBA4C795 + self.tweak) & 0xffffffff, item) % (len(self.data) * 8)
            self.data[i >> 3] |= 1 << (7 & i)

    def payload(self):
        return compact(len(self.data)) + bytes(self.data) + struct.pack("<IIB", self.funcs, self.tweak, self.flags)


def compact(n):
    if n < 0xfd:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n) if n <= 0xffff else b"\xfe" + struct.pack("<I", n)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hash160_of(address):
    n = 0
    for ch in address:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(25, "big")
    return raw[1:21]


# --- a peer of this script's own -------------------------------------------------------

class Peer:
    """Connects from 127.0.0.3, says in its version whether it wants
    transactions relayed, completes the handshake, then sends messages and
    collects what comes back"""

    def __init__(self, node, relay=True):
        self.sock = socket.create_connection(("127.0.0.1", node.p2p), timeout=10, source_address=(PEER_IP, 0))
        ua = b"/bloom-check:1/"
        payload = (struct.pack("<iQq", PROTOCOL_VERSION, 1, int(time.time())) + net_addr(node.p2p) + net_addr(0)
                   + secrets.token_bytes(8) + bytes([len(ua)]) + ua + struct.pack("<i", 0) + bytes([relay]))
        self.buf = b""
        self.services = None
        self.closed = False
        self.sock.sendall(message("version", payload))
        got_verack = False
        deadline = time.time() + 15
        while not (self.services is not None and got_verack) and time.time() < deadline:
            for command, body in self.read(1):
                if command == "version":
                    self.services = struct.unpack("<Q", body[4:12])[0]
                    self.sock.sendall(message("verack", b""))
                elif command == "verack":
                    got_verack = True
        need(self.services is not None and got_verack, f"no handshake with {node.name}")

    def read(self, secs):
        """Messages that arrive within secs; stops early on a closed connection"""
        out, deadline = [], time.time() + secs
        self.sock.settimeout(0.2)
        while time.time() < deadline:
            try:
                data = self.sock.recv(65536)
                if not data:
                    self.closed = True
                    break
                self.buf += data
            except socket.timeout:
                pass
            except OSError:
                self.closed = True
                break
            while len(self.buf) >= 24:
                length = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) < 24 + length:
                    break
                command = self.buf[4:16].rstrip(b"\0").decode(errors="replace")
                out.append((command, self.buf[24:24 + length]))
                self.buf = self.buf[24 + length:]
        return out

    def send(self, command, payload=b""):
        try:
            self.sock.sendall(message(command, payload))
        except OSError:
            pass

    def close(self):
        self.sock.close()


def getdata(kind, block_hash):
    return compact(1) + struct.pack("<I", kind) + bytes.fromhex(block_hash)[::-1]


def inv_has(messages, txid):
    h = bytes.fromhex(txid)[::-1]
    return any(c == "inv" and h in body for c, body in messages)


def banned(node):
    out = node.call("listbanned")
    return out[0] == "ok" and PEER_IP in json.dumps(out[1])


def both_rows(name, fn, show=str):
    """fn(node) on divid and on irondivid; the same result is a PASS"""
    c, i = fn(C), fn(I)
    if name == INJECT:
        i = ("injected", i)
    row(name, show(c), show(i), c == i, (("ok", c), ("ok", i)))
    return c, i


def filtered_block(node, filt, block_hash, wait=3):
    """A filterload of `filt` (None: no filter message), then a getdata of the
    block as a filtered block: the merkleblock payload and the transactions after it"""
    peer = Peer(node)
    if filt is not None:
        peer.send("filterload", filt.payload())
    peer.send("getdata", getdata(3, block_hash))
    got = peer.read(wait)
    peer.close()
    merkles = [body.hex() for c, body in got if c == "merkleblock"]
    txs = [body.hex() for c, body in got if c == "tx"]
    return {"merkleblock": merkles, "tx": txs}


def short(v):
    if isinstance(v, dict):
        return json.dumps({k: [x[:16] + f"..({len(x) // 2} B)" for x in v[k]] for k in v})
    return str(v)


# --- 1. a network with bloom filters on, as both run by default -----------------------------

start_both()
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
both_rows("services: NODE_BLOOM with the default -peerbloomfilters", lambda n: bool(Peer(n).services & 4))

# The filter messages and the bans they earn (100 bans: main.cpp:892-939)


def ban_case(messages):
    """Both nodes disconnect a peer at score 100 and, as it is local (127.0.0.3), do not ban it (divid
    main.cpp:1107-1125 "not banning local peer"); every bloom score is 100, so the disconnect is the score"""
    def run(node):
        peer = Peer(node)
        for command, payload in messages:
            peer.send(command, payload)
        peer.read(3)
        dropped = peer.closed
        peer.close()
        time.sleep(1)
        out = f"disconnected={dropped} banned={banned(node)}"
        node.call("clearbanned")
        return out
    return run


ok_filter = Bloom(10, 0.001, 0, 1)
oversize = compact(36001) + bytes(36001) + struct.pack("<IIB", 5, 0, 1)
too_many_funcs = compact(10) + bytes(10) + struct.pack("<IIB", 51, 0, 1)
for name, msgs in (
    ("filterload within the limits: score 100", [("filterload", ok_filter.payload())]),
    ("filteradd before any filterload: score 100", [("filteradd", compact(20) + bytes(20))]),
    ("filterload then filteradd of 520 bytes: score 100", [("filterload", ok_filter.payload()),
                                                         ("filteradd", compact(520) + bytes(520))]),
    ("filterclear: score 100", [("filterclear", b"")]),
    ("filterload of 36,001 bytes: score 100", [("filterload", oversize)]),
    ("filterload with 51 hash functions: score 100", [("filterload", too_many_funcs)]),
    ("filteradd of 521 bytes: score 100", [("filterload", ok_filter.payload()),
                                        ("filteradd", compact(521) + bytes(521))]),
):
    both_rows(name, ban_case(msgs))

# Coins, then one block with a payment to each of three addresses
C.rpc("setgenerate", 25)
need(synced(), "irondivid did not follow")
A = [C.rpc("getnewaddress") for _ in range(4)]
pay = [C.rpc("sendtoaddress", a, 10) for a in A[:3]]
C.rpc("setgenerate", 1)
need(synced(), "irondivid did not follow")
block_pay = C.rpc("getbestblockhash")
C.rpc("setgenerate", 1)
need(synced(), "irondivid did not follow")
block_empty = C.rpc("getbestblockhash")

# Filtered blocks: one filter per update flag, each matching one address
FLAGS = (("BLOOM_UPDATE_ALL", 1), ("BLOOM_UPDATE_NONE", 0), ("BLOOM_UPDATE_P2PUBKEY_ONLY", 2))
filters = {}
for k, (flag_name, flag) in enumerate(FLAGS):
    f = Bloom(10, 0.000001, secrets.randbelow(2 ** 32), flag)
    f.insert(hash160_of(A[k]))
    filters[flag_name] = f
    both_rows(f"merkleblock of the block paying the address, {flag_name}",
              lambda n, f=f: filtered_block(n, f, block_pay), short)
both_rows("merkleblock of a block with no match", lambda n: filtered_block(n, filters["BLOOM_UPDATE_ALL"],
                                                                           block_empty), short)
both_rows("merkleblock with no filter message (every peer's filter matches all)",
          lambda n: filtered_block(n, None, block_pay), short)


def output_to(txid, address):
    tx = C.rpc("getrawtransaction", txid, 1)
    return next(o["n"] for o in tx["vout"] if address in o["scriptPubKey"].get("addresses", []))


# Announcements: after the merkleblock, a spend of the matched output is
# announced only where the flag added that output to the filter
for k, (flag_name, flag) in enumerate(FLAGS):
    peers = {}
    for n in BOTH:
        p = Peer(n)
        p.send("filterload", filters[flag_name].payload())
        p.send("getdata", getdata(3, block_pay))
        p.read(2)
        peers[n.name] = p
    coin = {"txid": pay[k], "vout": output_to(pay[k], A[k]), "amount": 10}
    spend_tx = C.rpc("sendrawtransaction", build(C, [coin], {A[3]: sat(10) - FEE}))
    need(wait_for(lambda: spend_tx in I.rpc("getrawmempool"), 30), "irondivid did not take the spend")
    got = {name: inv_has(p.read(5), spend_tx) for name, p in peers.items()}
    for p in peers.values():
        p.close()
    row(f"inv of a spend of the matched output, {flag_name}", got[C.name], got[I.name],
        got[C.name] == got[I.name], (("ok", got[C.name]), ("ok", got[I.name])))

# A send to an address no filter has, to filtered and relay=0 peers; and to a
# peer with no filter message
watch = {}
for n in BOTH:
    f = Peer(n)
    f.send("filterload", filters["BLOOM_UPDATE_ALL"].payload())
    watch[n.name] = {"filtered": f, "relay=0": Peer(n, relay=False), "no filter message": Peer(n)}
time.sleep(1)
other = C.rpc("sendtoaddress", C.rpc("getnewaddress"), 1)
need(wait_for(lambda: other in I.rpc("getrawmempool"), 30), "irondivid did not take the send")
for kind in ("filtered", "relay=0", "no filter message"):
    got = {name: inv_has(peers_[kind].read(4), other) for name, peers_ in watch.items()}
    row(f"inv of a new send matching no filter, to a {kind} peer", got[C.name], got[I.name],
        got[C.name] == got[I.name], (("ok", got[C.name]), ("ok", got[I.name])))
for peers_ in watch.values():
    for p in peers_.values():
        p.close()

# A vault funding: its script holds both keys' hashes
own, mgr = C.rpc("getnewaddress"), C.rpc("getnewaddress")
fund = C.rpc("fundvault", f"{own}:{mgr}", 100)
fund_txid = fund["txhash"] if isinstance(fund, dict) else fund
C.rpc("setgenerate", 1)
need(synced(), "irondivid did not follow")
block_vault = C.rpc("getbestblockhash")
for who, addr in (("owner", own), ("manager", mgr)):
    f = Bloom(10, 0.000001, secrets.randbelow(2 ** 32), 1)
    f.insert(hash160_of(addr))
    both_rows(f"merkleblock of a vault funding, filter on the {who}",
              lambda n, f=f: filtered_block(n, f, block_vault), short)

# A coinstake: past the last proof-of-work block (100 on regtest)
height = C.rpc("getblockcount")
C.rpc("setgenerate", max(1, 102 - height))
need(synced(), "irondivid did not follow")
block_stake = C.rpc("getbestblockhash")
stake_txs = C.rpc("getblock", block_stake)["tx"]
coinstake = C.rpc("getrawtransaction", stake_txs[1], 1) if len(stake_txs) > 1 else None
is_stake = bool(coinstake) and coinstake["vout"][0]["value"] == 0
print(f"# block {block_stake[:16]}: coinstake {is_stake}", flush=True)
if is_stake:
    spk = bytes.fromhex(coinstake["vout"][1]["scriptPubKey"]["hex"])
    # The key (P2PK) or key hash (P2PKH): the script's one data push, as divid's filter sees it
    push = [spk[i + 1:i + 1 + spk[i]] for i in range(len(spk)) if spk[i] in (20, 33, 65) and i + 1 + spk[i] <= len(spk)][0]
    print(f"# coinstake output 1: {coinstake['vout'][1]['scriptPubKey']['type']}, filter on its {len(push)}-byte push", flush=True)
    f = Bloom(10, 0.000001, secrets.randbelow(2 ** 32), 1)
    f.insert(push)
    c, _ = both_rows("merkleblock of a proof-of-stake block, filter on the coinstake's key",
                     lambda n: filtered_block(n, f, block_stake), short)
    need(c["tx"], "divid matched nothing in the proof-of-stake block")
else:
    row("a proof-of-stake block to filter", "no coinstake", "", False)

# --- 2. -peerbloomfilters=0 on both ----------------------------------------------------------

stop_both()
start_both(["peerbloomfilters=0"])
both_rows("-peerbloomfilters=0: services NODE_BLOOM", lambda n: bool(Peer(n).services & 4))
for name, msgs in (
    ("-peerbloomfilters=0: filterload score 100", [("filterload", ok_filter.payload())]),
    ("-peerbloomfilters=0: filteradd score 100", [("filteradd", compact(20) + bytes(20))]),
    ("-peerbloomfilters=0: filterclear score 100", [("filterclear", b"")]),
):
    both_rows(name, ban_case(msgs))
both_rows("-peerbloomfilters=0: merkleblock of a filtered getdata (the default filter)",
          lambda n: filtered_block(n, None, block_pay), short)

stop_both()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
