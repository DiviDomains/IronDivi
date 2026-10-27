#!/usr/bin/env python3
"""Which peer messages Divi Core divid answers and which it leaves unanswered,
next to irondivid: a raw P2P client sends two divid and one irondivid, on the
same regtest chain, the same message, then a ping with a fresh nonce, then
another. Everything the node sends up to each pong is recorded, so a reply and
a silence are told apart without timing: a node handles a peer's messages in
order (main.cpp:1023-1072), so whatever it answers comes before the pong of a
later ping, or, when it is sent from SendMessages (a getdata it asks for, its
trickled addresses), before the pong of the ping after that.

Each row compares the messages (command and contents, by name: block heights,
the mempool transaction, the unknown hashes made here) and the round they came
in. The two divids must agree, or the case is not settled and the row FAILs.
Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("SILENT_REPLIES_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"
LISTEN_IP = "127.0.0.3"
LISTEN_PORT = PORT_BASE + 6

# --- rows ------------------------------------------------------------------------------

# Rows where irondivid differs on purpose: {row name: (reason, irondivid's value)}.
# A KNOWN row that matches divid, or differs in another way, is a FAIL
NO_BLOOM = ("irondivid offers no bloom filters (no NODE_BLOOM; a filter message is scored 100, as divid run with "
            "-peerbloomfilters=0 does: scripts/handshake/README.md). divid gives every peer a filter that matches "
            "everything (bloom.h:66, Node.cpp:556), so it answers a filtered block with a merkleblock and the "
            "block's transactions (main.cpp:249-281); irondivid sends nothing for it, and like divid ends the "
            "getdata pass there")
KNOWN = {
    "getdata of a filtered block (type 3) of block 5": (NO_BLOOM, [[[], []]]),
    "getdata of an unknown tx, a filtered block 5, another unknown tx": (
        NO_BLOOM, [[[["notfound", ["1:unknown tx"]], ["notfound", ["1:unknown tx2"]]], []]]),
    "a block announced by a peer that has left: the next peer sends block 5": (
        "irondivid hands a block download from a peer that left to another connected peer "
        "(crates/divi-network/src/sync.rs:622-664), and asks for it when the next block arrives; divid drops a "
        "peer's block availability and requests with the peer (FinalizeNode, NodeStateRegistry.cpp:40-45) and asks a peer only "
        "for blocks it announced (FindNextBlocksToDownload, NodeStateRegistry.cpp:146). Kept: a download survives a dropped peer",
        [[[["getdata", ["2:the block a peer announced and left"]]], []]]),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, c1, c2, iron):
    global fails
    if name == INJECT:
        iron = ["injected", iron]
    if c1 != c2:
        word, note = "FAIL", "  [the two divids differ: the case is not settled]"
    elif name in KNOWN:
        reason, shape = KNOWN[name]
        if iron == c1:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif iron == shape:
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if iron == c1 else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    show = lambda v: json.dumps(v)[:700]
    extra = "" if c1 == c2 else f"  divid2={show(c2)}"
    print(f"{word:<5}  {name}  divid={show(c1)}  irondivid={show(iron)}{extra}{note}", flush=True)


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   set-up or step (line {where}): {kind.__name__}: {value}"[:400], flush=True)
    print("FAILS 1", flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def need(ok, what):
    if not ok:
        raise RuntimeError(what)


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
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"sr{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=sr{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "externalip=240.0.0.9",
        ]
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0

    def start(self, extra):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))
        self.starts += 1
        log = os.path.join(WORK, f"{self.name}.{self.starts}")
        with open(log + ".out", "w") as o, open(log + ".err", "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        need(wait_for(lambda: self.call("getblockcount")[0] == "ok", START_TIMEOUT),
             f"{self.name} did not start ({list(extra)})")

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
        need(out[0] == "ok", f"{self.name} {method}: {out[1:]}")
        return out[1]

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


# --- the wire ----------------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
PROTOCOL_VERSION = 70920


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(command, payload=b""):
    return (MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4]
            + payload)


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


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
        return struct.unpack("<H", b[pos + 1:pos + 3])[0], pos + 3
    return struct.unpack("<I", b[pos + 1:pos + 5])[0], pos + 5


def h2b(h):
    """A hash in display hex, as it goes on the wire"""
    return bytes.fromhex(h)[::-1]


def inv_msg(items):
    return compact(len(items)) + b"".join(struct.pack("<I", k) + h2b(h) for k, h in items)


def locator_msg(hashes, stop=None):
    return (struct.pack("<I", PROTOCOL_VERSION) + compact(len(hashes)) + b"".join(h2b(h) for h in hashes)
            + (h2b(stop) if stop else bytes(32)))


def version_payload(src, port):
    ua = b"/silent-replies:1/"
    return (struct.pack("<iQq", PROTOCOL_VERSION, 1, int(time.time())) + netaddr(NODE_IP, port)
            + netaddr(src, 0) + secrets.token_bytes(8) + compact(len(ua)) + ua + struct.pack("<i", 0) + b"\x01")


def header(prev, time_, merkle=None, bits=0x207fffff):
    """A version 4 header on `prev` that meets regtest's work target; (bytes, hash)"""
    merkle = merkle or secrets.token_bytes(32)
    target = (bits & 0xffffff) << (8 * ((bits >> 24) - 3))
    nonce = 0
    while True:
        b = struct.pack("<i", 4) + h2b(prev) + merkle + struct.pack("<III", time_, bits, nonce) + bytes(32)
        h = sha256d(b)
        if int.from_bytes(h, "little") <= target:
            return b, h[::-1].hex()
        nonce += 1


def coinbase(tag):
    return (struct.pack("<i", 1) + b"\x01" + bytes(32) + b"\xff" * 4 + compact(len(tag)) + tag + b"\xff" * 4
            + b"\x01" + struct.pack("<q", 0) + b"\x01\x51" + struct.pack("<I", 0))


def block_on(prev, time_):
    """A block with one coinbase on `prev`; (bytes, hash)"""
    cb = coinbase(secrets.token_bytes(8))
    head, h = header(prev, time_, merkle=sha256d(cb))
    return head + b"\x01" + cb, h


# --- names for what comes back -----------------------------------------------------------

NAMES = {}  # display hex -> name


def name(h):
    return NAMES.get(h, f"?{h[:8]}")


def items_of(payload):
    n, pos = read_compact(payload, 0)
    out = []
    for _ in range(n):
        kind = struct.unpack("<I", payload[pos:pos + 4])[0]
        out.append(f"{kind}:{name(payload[pos + 4:pos + 36][::-1].hex())}")
        pos += 36
    return out


def summary(command, payload):
    try:
        if command in ("inv", "getdata", "notfound"):
            return [command, items_of(payload)]
        if command in ("getblocks", "getheaders"):
            n, pos = read_compact(payload, 4)
            stop = payload[pos + 32 * n:pos + 32 * n + 32][::-1].hex()
            return [command, "stop " + ("none" if stop == "0" * 64 else name(stop))]
        if command == "block":
            return [command, name(sha256d(payload[:112])[::-1].hex())]
        if command == "tx":
            return [command, name(sha256d(payload)[::-1].hex())]
        if command == "reject":
            n = payload[0]
            msg = payload[1:1 + n].decode(errors="replace")
            code = payload[1 + n]
            m, pos = read_compact(payload, 2 + n)
            return [command, msg, code, payload[pos:pos + m].decode(errors="replace")]
        if command in ("addr", "headers"):
            return [command, "some" if read_compact(payload, 0)[0] else "none"]
        if command == "ssc":
            return [command] + list(struct.unpack("<ii", payload[:8]))
        if command == "sporkcount":
            return [command, struct.unpack("<i", payload[:4])[0]]
    except (IndexError, struct.error):
        pass
    return [command]


# --- the raw peer ------------------------------------------------------------------------

class Peer:
    """A raw peer from its own loopback address, past the handshake and the
    messages a node sends a new peer unasked"""

    def __init__(self, node, src, sock=None):
        self.node, self.src = node, src
        self.closed = False
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.bind((src, 0))
            sock.connect((NODE_IP, node.p2p))
            sock.sendall(message("version", version_payload(src, node.p2p)))
            self.sock = sock
            self.handshake(answer_version=False)
        else:
            self.sock = sock
            self.handshake(answer_version=True)
        self.barrier()

    def handshake(self, answer_version):
        got_version = got_verack = False
        deadline = time.time() + 15
        while not (got_version and got_verack) and time.time() < deadline:
            command, _ = self.read(deadline - time.time())
            if command == "version":
                got_version = True
                if answer_version:
                    self.sock.sendall(message("version", version_payload(LISTEN_IP, LISTEN_PORT)))
                self.sock.sendall(message("verack"))
            elif command == "verack":
                got_verack = True
        need(got_version and got_verack, f"no handshake with {self.node.name}")

    def read(self, secs):
        self.sock.settimeout(max(0.05, secs))
        head = self.recv(24)
        size = struct.unpack("<I", head[16:20])[0]
        return head[4:16].rstrip(b"\0").decode(errors="replace"), self.recv(size)

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
            self.closed = True

    def send_raw(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            self.closed = True

    def until_pong(self, secs=30):
        """Send a ping with a fresh nonce; the messages before its pong (pings
        from the node answered and left out), or None when the node closes or
        never answers"""
        nonce = secrets.token_bytes(8)
        self.send("ping", nonce)
        got = []
        deadline = time.time() + secs
        while not self.closed:
            left = deadline - time.time()
            if left <= 0:
                return got + [["no pong"]]
            try:
                command, payload = self.read(left)
            except socket.timeout:
                continue
            except (OSError, EOFError):
                self.closed = True
                break
            if command == "ping":
                self.send("pong", payload)
            elif command == "pong" and payload == nonce:
                return got
            else:
                # A pong to a ping of the step itself is recorded, by its place
                got.append(summary(command, payload))
        return got + [["closed"]]

    def barrier(self):
        """Two ping rounds; what came in each"""
        return [self.until_pong(), self.until_pong()]

    def listen(self, secs):
        """Everything within `secs` (pings answered)"""
        got = []
        deadline = time.time() + secs
        while not self.closed and time.time() < deadline:
            try:
                command, payload = self.read(deadline - time.time())
            except socket.timeout:
                break
            except (OSError, EOFError):
                self.closed = True
                got.append(["closed"])
                break
            if command == "ping":
                self.send("pong", payload)
            elif command != "pong":
                got.append(summary(command, payload))
        return got

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


SRC = iter(f"127.0.0.{b}" for b in range(10, 255))


def answer(node, src, steps, wait=0):
    """A fresh peer from `src` sends each step (a (command, payload) pair, raw
    bytes, or a function of the peer); the rounds after each step's barrier,
    and what comes within `wait` seconds after the last"""
    p = Peer(node, src)
    out = []
    for step in steps:
        if callable(step):
            step(p)
        elif isinstance(step, bytes):
            p.send_raw(step)
        else:
            p.send(*step)
        out.append(p.barrier())
    if wait:
        out.append(p.listen(wait))
    p.close()
    return out


def case(name, *steps, wait=0, before=None, after=None):
    """The same steps from a fresh raw peer to each node: one row"""
    src = next(SRC)
    got = []
    for n in NODES:
        if before:
            before(n)
        got.append(answer(n, src, steps, wait))
        if after:
            after(n)
    row(name, *got)


# --- the chain ---------------------------------------------------------------------------

C1 = Node("divid1", DIVID, 0)
C2 = Node("divid2", DIVID, 1)
I = Node("irondivid", IRONDIVID, 2)
NODES = (C1, C2, I)

C1.start(["connect=127.0.0.2:1"])
for n in (C2, I):
    n.start([f"connect={NODE_IP}:{C1.p2p}"])
print(f"# divid {C1.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
need(wait_for(lambda: C1.rpc("getconnectioncount") == 2, 60), "the followers did not connect")


def mine_one(n):
    """One block; a stake block may take a few tries (-25 until a kernel is found)"""
    before = n.rpc("getblockcount")
    for _ in range(60):
        if n.call("setgenerate", 1)[0] == "ok" and n.rpc("getblockcount") > before:
            return
        time.sleep(1)
    need(False, f"{n.name} could not mine at height {before}")


HEIGHT = 120
while C1.rpc("getblockcount") < HEIGHT:
    mine_one(C1)


def in_step():
    tip = C1.rpc("getbestblockhash")
    return all(n.rpc("getbestblockhash") == tip for n in (C2, I))


need(wait_for(in_step, 120), "the followers did not follow")

# A side branch: every node has the tip connected; the miner replaces it by a
# longer branch, so it is a valid block off the main chain everywhere (divid
# serves such a block only once it has been connected, BLOCK_VALID_SCRIPTS,
# main.cpp:232-236)
SIDE = C1.rpc("getbestblockhash")
C1.rpc("invalidateblock", SIDE)
mine_one(C1)
mine_one(C1)
C1.rpc("reconsiderblock", SIDE)
HEIGHT = C1.rpc("getblockcount")
need(wait_for(in_step, 120), "the followers did not follow the branch")
need(C1.rpc("getblockhash", HEIGHT - 1) != SIDE, "no side branch")

# A transaction in every mempool
POOL_TX = C1.rpc("sendtoaddress", C1.rpc("getnewaddress"), 1)
POOL_HEX = C1.rpc("getrawtransaction", POOL_TX)
HASH = [C1.rpc("getblockhash", h) for h in range(HEIGHT + 1)]
for h, x in enumerate(HASH):
    NAMES[x] = f"block {h}"
NAMES[SIDE] = "the side block"
NAMES[POOL_TX] = "the mempool tx"
CB5 = C1.rpc("getblock", HASH[5])["tx"][0]
NAMES[CB5] = "the coinbase of block 5"
SIDE_HEX = None

# Every node alone from here, with no peer but the raw ones
for n in NODES:
    n.stop()
for n in NODES:
    n.start(["connect=127.0.0.2:1"])
for n in NODES:
    need(n.rpc("getbestblockhash") == HASH[HEIGHT], f"{n.name} is not at the tip after the restart")
    n.call("sendrawtransaction", POOL_HEX)
    need(POOL_TX in n.rpc("getrawmempool"), f"{n.name} has not the mempool transaction")


def has_side(n):
    return n.call("getblock", SIDE)[0] == "ok"


# A node that never got the side block gets it from a raw peer
for n in NODES:
    if not has_side(n):
        hexed = C1.rpc("getblock", SIDE, False) if C1.call("getblock", SIDE, False)[0] == "ok" else None
        need(hexed is not None, "the side block is not on the miner")
        p = Peer(n, "127.0.0.9")
        p.send("block", bytes.fromhex(hexed))
        p.barrier()
        p.close()
    need(has_side(n), f"{n.name} does not have the side block")
print(f"# chain of {HEIGHT} blocks and a side block at {HEIGHT - 1} on all three; one transaction in each "
      f"mempool", flush=True)

# Hashes no node knows
U = {}
for k in ("block", "tx", "tx2", "other"):
    U[k] = secrets.token_hex(32)
    NAMES[U[k]] = f"unknown {k}"


def unknown(label):
    h = secrets.token_hex(32)
    NAMES[h] = label
    return h


TIP_TIME = C1.rpc("getblock", HASH[HEIGHT])["time"]

# --- 0. a ping alone --------------------------------------------------------------------
case("nothing sent: two ping rounds", lambda p: None)

# --- 1. getdata (ProcessGetData, main.cpp:283-347) ----------------------------------------
case("getdata of a block (5)", ("getdata", inv_msg([(2, HASH[5])])))
case("getdata of an unknown block", ("getdata", inv_msg([(2, U["block"])])))
case("getdata of the side block", ("getdata", inv_msg([(2, SIDE)])))
case("getdata of the mempool tx", ("getdata", inv_msg([(1, POOL_TX)])))
case("getdata of the mempool tx and a ping in one write",
     message("getdata", inv_msg([(1, POOL_TX)])) + message("ping", secrets.token_bytes(8)))
case("getdata of the mempool tx and a spork that does not parse, in one write",
     message("getdata", inv_msg([(1, POOL_TX)])) + message("spork", b"\x01\x02"))
case("getdata of an unknown tx", ("getdata", inv_msg([(1, U["tx"])])))
case("getdata of a confirmed tx (the coinbase of block 5)", ("getdata", inv_msg([(1, CB5)])))
case("getdata of a filtered block (type 3) of block 5", ("getdata", inv_msg([(3, HASH[5])])))
case("getdata of a filtered block (type 3) of an unknown block", ("getdata", inv_msg([(3, U["block"])])))
for kind in range(4, 16):
    case(f"getdata of an unknown item of type {kind}", ("getdata", inv_msg([(kind, unknown(f"unknown {kind}"))])))
for kind in (0, 16, 99):
    case(f"getdata of an item of type {kind}", ("getdata", inv_msg([(kind, U["other"])])))
case("getdata of nothing", ("getdata", inv_msg([])))
case("getdata of an unknown tx, a filtered block 5, another unknown tx",
     ("getdata", inv_msg([(1, U["tx"]), (3, HASH[5]), (1, U["tx2"])])))
case("getdata of an unknown tx, an unknown block, another unknown tx",
     ("getdata", inv_msg([(1, U["tx"]), (2, U["block"]), (1, U["tx2"])])))
case("getdata of an unknown tx, an item of type 99, another unknown tx",
     ("getdata", inv_msg([(1, U["tx"]), (99, U["other"]), (1, U["tx2"])])))
case("getdata of an unknown item of type 4, the mempool tx",
     ("getdata", inv_msg([(4, U["other"]), (1, POOL_TX)])))


def invalidate_tip(n):
    n.rpc("invalidateblock", HASH[HEIGHT])


def reconsider_tip(n):
    n.rpc("reconsiderblock", HASH[HEIGHT])
    need(wait_for(lambda: n.rpc("getbestblockhash") == HASH[HEIGHT], 30), f"{n.name} did not go back to the tip")


case("getdata of an invalidated block (the tip, invalidateblock)", ("getdata", inv_msg([(2, HASH[HEIGHT])])),
     before=invalidate_tip, after=reconsider_tip)

# --- 2. inv (main.cpp:559-611): what a node asks for --------------------------------------
case("inv of an unknown tx", ("inv", inv_msg([(1, unknown("unknown tx (inv)"))])))
case("inv of the mempool tx", ("inv", inv_msg([(1, POOL_TX)])))
case("inv of a known block (5)", ("inv", inv_msg([(2, HASH[5])])))
case("inv of the side block", ("inv", inv_msg([(2, SIDE)])))
for kind in range(3, 16):
    case(f"inv of an unknown item of type {kind}", ("inv", inv_msg([(kind, unknown(f"unknown {kind} (inv)"))])))
for kind in (0, 99):
    case(f"inv of an item of type {kind}", ("inv", inv_msg([(kind, U["other"])])))
case("inv of nothing", ("inv", inv_msg([])))

# --- 3. getblocks and getheaders (main.cpp:624-668) --------------------------------------
for command in ("getblocks", "getheaders"):
    case(f"{command} with an unknown locator", (command, locator_msg([U["block"]])))
    case(f"{command} from block 10 with hashStop 20", (command, locator_msg([HASH[10]], HASH[20])))
    case(f"{command} from block 10 with an unknown hashStop", (command, locator_msg([HASH[10]], U["block"])))
    case(f"{command} from the tip", (command, locator_msg([HASH[HEIGHT]])))
    case(f"{command} from the side block", (command, locator_msg([SIDE])))
    case(f"{command} with an empty locator and hashStop the tip", (command, locator_msg([], HASH[HEIGHT])))

# --- 4. headers: read only with headers-first syncing, which no network has (main.cpp:669) -
NEXT_HEADER, NEXT_HASH = header(HASH[HEIGHT], TIP_TIME + 60)
NAMES[NEXT_HASH] = "the next header"
case("headers of one unknown header on the tip", ("headers", b"\x01" + NEXT_HEADER + b"\x00"))
case("headers of nothing", ("headers", b"\x00"))
case("getheaders-style headers request: a locator in a headers message", ("headers", locator_msg([HASH[10]])))

# --- 5. mempool: no branch in Divi Core 3.0.0's ProcessMessage -----------------------------
case("mempool", ("mempool", b""))

# --- 6. getaddr (main.cpp:863-869) --------------------------------------------------------
ADDRS = [(f"240.{k + 1}.0.1", 51472) for k in range(100)]


def addr_msg(addrs):
    now = int(time.time())
    return compact(len(addrs)) + b"".join(struct.pack("<I", now) + netaddr(ip, port) for ip, port in addrs)


src = next(SRC)
for n in NODES:
    p = Peer(n, src)
    p.send("addr", addr_msg(ADDRS))
    p.barrier()
    p.close()
# Addresses are sent from SendMessages to the peer picked for trickling
# (main.cpp:1298-1301, net.cpp:858): a few seconds are given for them
case("getaddr, then getaddr again", ("getaddr", b""), ("getaddr", b""), wait=5)


def outbound(n, steps, wait=5):
    """The node dials a listener here (addnode onetry); the steps on that connection"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_IP, LISTEN_PORT))
    srv.listen(1)
    srv.settimeout(30)
    n.rpc("addnode", f"{LISTEN_IP}:{LISTEN_PORT}", "onetry")
    try:
        conn, _ = srv.accept()
    finally:
        srv.close()
    p = Peer(n, LISTEN_IP, sock=conn)
    out = []
    for step in steps:
        p.send(*step)
        out.append(p.barrier())
    out.append(p.listen(wait))
    p.close()
    need(wait_for(lambda: n.rpc("getconnectioncount") == 0, 30), f"{n.name} kept the outbound connection")
    return out


row("getaddr on a connection the node made", *[outbound(n, [("getaddr", b"")]) for n in NODES])

# --- 7. ping, pong, version, verack, unknown commands, reject -----------------------------
case("ping with an 8-byte nonce, then the barrier", ("ping", secrets.token_bytes(8)))
case("ping with no nonce", ("ping", b""))
case("ping with 4 bytes", ("ping", b"\x01\x02\x03\x04"))
case("ping with 9 bytes", ("ping", secrets.token_bytes(9)))
case("pong nobody asked for", ("pong", secrets.token_bytes(8)))
case("verack again", ("verack", b""))
case("version again", ("version", version_payload("127.0.0.8", 1)))
case("an unknown command", ("silentcheck", b"abc"))
case("an unknown command with no payload", ("zz", b""))
case("a command of 12 letters", ("abcdefghijkl", b""))
case("a reject of a tx", ("reject", b"\x02tx" + b"\x10" + b"\x03bad" + secrets.token_bytes(32)))
case("a reject with only a message", ("reject", b"\x02tx"))
case("an empty reject", ("reject", b""))
case("an alert of nothing", ("alert", b""))
case("an alert of two empty vectors", ("alert", b"\x00\x00"))
case("an addr of nothing", ("addr", b""))
case("an addr of no addresses", ("addr", b"\x00"))
case("a getblocks of nothing", ("getblocks", b""))
case("a getdata of nothing at all (no count)", ("getdata", b""))
case("an inv of nothing at all (no count)", ("inv", b""))

# --- 8. tx and block (main.cpp:705-861) ----------------------------------------------------
case("tx: the mempool tx again", ("tx", bytes.fromhex(POOL_HEX)))
ORPHAN = (struct.pack("<i", 1) + b"\x01" + secrets.token_bytes(32) + b"\x00\x00\x00\x00" + b"\x00" + b"\xff" * 4
          + b"\x01" + struct.pack("<q", 100_000_000) + b"\x19\x76\xa9\x14" + bytes(20) + b"\x88\xac"
          + struct.pack("<I", 0))
NAMES[sha256d(ORPHAN)[::-1].hex()] = "the orphan tx"
case("tx: a tx spending an unknown output (an orphan)", ("tx", ORPHAN))
ORPHAN_BLOCK, ORPHAN_HASH = block_on(secrets.token_hex(32), TIP_TIME + 60)
NAMES[ORPHAN_HASH] = "the orphan block"
case("block with an unknown parent, sent twice", ("block", ORPHAN_BLOCK), ("block", ORPHAN_BLOCK))
case("block 5 again", ("block", bytes.fromhex(C1.rpc("getblock", HASH[5], False))))
case("the side block again", ("block", bytes.fromhex(C1.rpc("getblock", SIDE, False))))

# --- 9. sporks and the masternode sync -------------------------------------------------------
case("getsporks", ("getsporks", b""))
case("sporkcount 0", ("sporkcount", struct.pack("<i", 0)))
case("sporkcount 3", ("sporkcount", struct.pack("<i", 3)))
case("mnget, then mnget again", ("mnget", struct.pack("<i", 10)), ("mnget", struct.pack("<i", 10)))
EMPTY_VIN = bytes(32) + b"\xff" * 4 + b"\x00" + b"\xff" * 4
case("dseg of the whole list, then again", ("dseg", EMPTY_VIN), ("dseg", EMPTY_VIN))
case("dseg of an unknown masternode", ("dseg", secrets.token_bytes(32) + b"\x00" * 4 + b"\x00" + b"\xff" * 4))
case("ssc", ("ssc", struct.pack("<ii", 2, 0)))

# --- 10. a block announced by a peer that then left (last: irondivid keeps asking for it) ----
LEFT = unknown("the block a peer announced and left")
case("inv of an unknown block", ("inv", inv_msg([(2, LEFT)])))
case("a block announced by a peer that has left: the next peer sends block 5",
     ("block", bytes.fromhex(C1.rpc("getblock", HASH[5], False))))

for n in NODES:
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
