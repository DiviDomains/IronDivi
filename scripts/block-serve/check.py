#!/usr/bin/env python3
"""What Divi Core divid and irondivid answer a peer that asks them for blocks,
headers, data and addresses, compared message by message: a raw P2P client
handshakes with each daemon on the same regtest chain of 1200 blocks and sends
both the same getblocks, getheaders, getdata, getaddr and mempool requests. Each
row compares the messages that come back (command, count, hashes, order) and
whether the peer is still connected.

Both wallets come from the same phrase; irondivid follows divid's chain, then
both run with no peer but the raw ones made here. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

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
KNOWN = {
    "getaddr after 100 addresses, no routable local address: addresses sent": (
        "divid keeps no address of a network it has no routable local address in: IPv4 is reachable only once "
        "one is known (-externalip, discovery; NetworkLocalAddressHelpers.cpp:73-106), and its addr handler keeps "
        "only reachable addresses (main.cpp:544-553). irondivid keeps them: matching it would leave a node "
        "without a public address (behind NAT, or -discover=0) with an empty address book",
        lambda c, i: c == ("ok", 0) and i[0] == "ok" and i[1] > 0),
}

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
        self.auth = base64.b64encode(f"bs{index}:{password}".encode()).decode()
        self.base = [
            f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=bs{index}", f"rpcpassword={password}",
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
        self.log = []  # every message after the handshake, in order: (command, payload)
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
            if command not in ("ping", "pong"):
                self.log.append((command, payload))
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


# --- the chain -------------------------------------------------------------------------

HEIGHT = 1200
C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
if C.start(["regtest=1"])[0] != "up":
    print("FAIL   setup: divid did not start", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I.env = {"WALLET_MNEMONIC": phrase}
del phrase
if I.start(["regtest=1", f"connect={NODE_IP}:{C.p2p}"])[0] != "up":
    print("FAIL   setup: irondivid did not start", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
failures = 0
while C.rpc("getblockcount") < HEIGHT:
    out = C.call("setgenerate", min(100, HEIGHT - C.rpc("getblockcount")))
    if out[0] != "ok":
        failures += 1
        if failures > 20:
            with open(os.path.join(C.dir, "regtest", "debug.log"), errors="replace") as f:
                tail = " | ".join(f.read().strip().splitlines()[-6:])
            print(f"FAIL   setup: divid setgenerate at height {C.rpc('getblockcount')}: {show(out)}; log: {tail}"[:900],
                  flush=True)
            sys.exit(1)
        time.sleep(1)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 300):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
HASH = [C.rpc("getblockhash", h) for h in range(HEIGHT + 1)]
HEIGHT_OF = {h: n for n, h in enumerate(HASH)}

# A transaction in both mempools: one of divid's wallet sends, given to irondivid too
POOL_TX = C.rpc("sendtoaddress", C.rpc("getnewaddress"), 1)
I.rpc("sendrawtransaction", C.rpc("getrawtransaction", POOL_TX))

# Both alone from here: no peer but the raw ones
I.stop()
if I.start(["regtest=1", "connect=127.0.0.2:1"])[0] != "up" or not wait_for(
        lambda: C.rpc("getconnectioncount") == 0, 30):
    print("FAIL   setup: irondivid did not start alone", flush=True)
    sys.exit(1)
print(f"# chain of {HEIGHT} blocks on both; transaction {POOL_TX[:8]} in both mempools", flush=True)


# --- reading the replies ---------------------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def invs_of(payload):
    n, pos = read_compact(payload, 0)
    out = []
    for _ in range(n):
        kind = struct.unpack("<I", payload[pos:pos + 4])[0]
        out.append((kind, payload[pos + 4:pos + 36][::-1].hex()))
        pos += 36
    return out


def item_name(kind, h):
    if kind == 2:
        return f"block {HEIGHT_OF[h]}" if h in HEIGHT_OF else f"block ?{h[:8]}"
    if kind == 1:
        return f"tx {h[:8]}"
    return f"type {kind} {h[:8]}"


def runs(names):
    """Consecutive 'block N' names written as 'blocks A..B'"""
    out, i = [], 0
    while i < len(names):
        j = i
        if names[i].startswith("block ") and names[i][6:].isdigit():
            while (j + 1 < len(names) and names[j + 1].startswith("block ") and names[j + 1][6:].isdigit()
                   and int(names[j + 1][6:]) == int(names[j][6:]) + 1):
                j += 1
        out.append(names[i] if j == i else f"blocks {names[i][6:]}..{names[j][6:]}")
        i = j + 1
    return out


def summary(command, payload):
    if command in ("inv", "notfound"):
        return f"{command} [{', '.join(runs([item_name(k, h) for k, h in invs_of(payload)]))}]"
    if command == "block":
        parent = payload[4:36][::-1].hex()  # the header's previous block hash
        return f"block {HEIGHT_OF[parent] + 1}" if parent in HEIGHT_OF else "block ?"
    if command == "tx":
        return f"tx {sha256d(payload)[::-1].hex()[:8]}"
    if command in ("addr", "headers"):
        return f"{command} {read_compact(payload, 0)[0]}"
    return command


def ask(peer, command, payload=b"", quiet=2.0, most=30.0):
    """Send one request; the replies (summaries, in order) until `quiet` seconds pass with none"""
    peer.log.clear()
    peer.send(command, payload)
    deadline, seen, last = time.time() + most, 0, time.time()
    while time.time() < deadline and time.time() - last < quiet:
        peer.pump(0.25)
        if len(peer.log) != seen:
            seen, last = len(peer.log), time.time()
    return [summary(c, p) for c, p in peer.log]


def locator_msg(hashes, stop=None):
    """getblocks/getheaders payload: version, locator, hashStop"""
    return (struct.pack("<I", 70920) + compact(len(hashes)) + b"".join(bytes.fromhex(h)[::-1] for h in hashes)
            + (bytes.fromhex(stop)[::-1] if stop else bytes(32)))


def inv_msg(items):
    return compact(len(items)) + b"".join(struct.pack("<I", k) + bytes.fromhex(h)[::-1] for k, h in items)


SRC = iter(f"127.0.1.{b}" for b in range(10, 250))


def fresh(node, src):
    """A raw peer, past the messages a node sends after the handshake (sporkcount, its
    own getblocks), so they are not taken for replies"""
    p = Peer(node, src)
    p.pump(3)
    p.log.clear()
    return p


def case(name, command, payload=b"", then=None):
    """The same request from a fresh raw peer to each node; one row of the replies and the
    connection after; `then(peer)` may ask a follow-up, whose replies are added"""
    src = next(SRC)
    got = {}
    for node in (C, I):
        p = fresh(node, src)
        replies = ask(p, command, payload)
        if then:
            replies += ["|"] + then(p)
        got[node] = {"replies": replies, "connected": p.pump(0.5) == "up"}
        p.close()
    compare(name, ("ok", got[C]), ("ok", got[I]))
    return got


def ask_block(height):
    """A getdata of one block, as the follow-up of a getblocks"""
    return lambda p: ask(p, "getdata", inv_msg([(2, HASH[height])]))


# --- 0. what a node sends a new inbound peer after the handshake -------------------------
src = next(SRC)
after = {}
for node in (C, I):
    p = Peer(node, src)
    p.pump(4)
    after[node] = sorted({c for c, _ in p.log})
    p.close()
compare("messages a node sends unasked after the handshake", ("ok", after[C]), ("ok", after[I]))


# --- 1. getblocks (main.cpp:624-668): an inv of up to 500 blocks after the locator ------
UNKNOWN = secrets.token_hex(32)
for command in ("getblocks", "getheaders"):
    # getheaders is answered by the same code as getblocks (main.cpp:624); a headers
    # answer is built only for a "headers" request, and only where headers-first
    # syncing is on, which it is on no network (main.cpp:680-702, chainparams.cpp:251, :360, :440)
    case(f"{command} from genesis, then getdata of the 500th block", command, locator_msg([HASH[0]]),
         then=ask_block(500))
    case(f"{command} from height 700, then getdata of the tip (the 500th)", command, locator_msg([HASH[700]]),
         then=ask_block(1200))
    case(f"{command} from height 300 with hashStop 350", command, locator_msg([HASH[300]], HASH[350]))
    case(f"{command} from height 300 with hashStop below the locator (200)", command,
         locator_msg([HASH[300]], HASH[200]))
    case(f"{command} with an unknown locator", command, locator_msg([UNKNOWN]))
    case(f"{command} with an unknown hash, then height 1000", command, locator_msg([UNKNOWN, HASH[1000]]))
    case(f"{command} from the tip", command, locator_msg([HASH[HEIGHT]]))
    case(f"{command} with an empty locator", command, locator_msg([]))
    case(f"{command} with an empty locator and hashStop 10", command, locator_msg([], HASH[10]))
    case(f"{command} with an unknown hashStop", command, locator_msg([HASH[1100]], UNKNOWN))

# --- 2. getdata (main.cpp:613-622, ProcessGetData :283-347) ---------------------------------
UNKNOWN_TX = secrets.token_hex(32)
case("getdata of a block (height 5)", "getdata", inv_msg([(2, HASH[5])]))
case("getdata of the genesis block", "getdata", inv_msg([(2, HASH[0])]))
case("getdata of an unknown block", "getdata", inv_msg([(2, UNKNOWN)]))
case("getdata of a mempool transaction", "getdata", inv_msg([(1, POOL_TX)]))
case("getdata of an unknown transaction", "getdata", inv_msg([(1, UNKNOWN_TX)]))
case("getdata of a confirmed transaction (the coinbase of block 5)", "getdata",
     inv_msg([(1, C.rpc("getblock", HASH[5])["tx"][0])]))
case("getdata of three blocks (8, 9, 10)", "getdata", inv_msg([(2, HASH[8]), (2, HASH[9]), (2, HASH[10])]))
case("getdata of a mix: transaction, block 6, unknown transaction, block 7, unknown block", "getdata",
     inv_msg([(1, POOL_TX), (2, HASH[6]), (1, UNKNOWN_TX), (2, HASH[7]), (2, UNKNOWN)]))
case("getdata of an unknown transaction, then block 11, then another unknown transaction", "getdata",
     inv_msg([(1, UNKNOWN_TX), (2, HASH[11]), (1, secrets.token_hex(32))]))
case("getdata of an item of unknown type 99", "getdata", inv_msg([(99, UNKNOWN)]))
case("getdata of nothing", "getdata", inv_msg([]))


def banscore_after(command, payload):
    def run(node, src):
        p = Peer(node, src)
        p.send(command, payload)
        p.pump(2)
        score = next((x.get("banscore") for x in node.rpc("getpeerinfo") if x["addr"] == f"{src}:{p.port}"),
                     "gone")
        p.close()
        return score
    return run


src = next(SRC)
big = inv_msg([(1, secrets.token_hex(32)) for _ in range(50001)])
compare("getdata of 50001 items: the peer's banscore (MAX_INV_SZ, main.cpp:617-619)",
        ("ok", banscore_after("getdata", big)(C, src)), ("ok", banscore_after("getdata", big)(I, src)))

# --- 3. mempool: Divi Core 3.0.0 has no "mempool" branch in ProcessMessage (main.cpp) ----------
case("mempool", "mempool")


# --- 4. getaddr (main.cpp:863-869): answered on an inbound connection only -------------
# 100 addresses in 240.0.0.0/4 (no node here dials them: both run with connect= set),
# each in its own /16, so the books keep nearly all; divid answers 23% of its book,
# at most 2500, skipping bad entries (addrman.cpp:451-470), so the count is compared
# as 1..23 (the book's bucket placement is random)
ADDRS = [(f"240.{k + 1}.0.1", 51472) for k in range(100)]


def addr_msg(addrs):
    now = int(time.time())
    return compact(len(addrs)) + b"".join(struct.pack("<I", now) + netaddr(ip, port) for ip, port in addrs)


def count_addr(replies):
    return sum(int(r.split()[1]) for r in replies if r.startswith("addr "))


def seed_and_ask():
    src = next(SRC)
    for node in (C, I):
        p = Peer(node, src)
        p.send("addr", addr_msg(ADDRS))
        p.pump(2)
        p.close()
    out = {}
    for node in (C, I):
        p = fresh(node, next(SRC))
        out[node] = count_addr(ask(p, "getaddr", quiet=4.0))
        p.close()
    return out


# divid keeps no address of a network it has no routable local address in: IPv4 is
# reachable only once one is known (NetworkLocalAddressHelpers.cpp:73-106, main.cpp:544-553)
got = seed_and_ask()
compare("getaddr after 100 addresses, no routable local address: addresses sent", ("ok", got[C]), ("ok", got[I]))

restart(["regtest=1", "connect=127.0.0.2:1", "externalip=240.0.0.9"])
got = seed_and_ask()
compare("getaddr after 100 addresses, -externalip=240.0.0.9: addresses sent, 1..23",
        ("ok", 0 < got[C] <= 23), ("ok", 0 < got[I] <= 23))
print(f"# getaddr with -externalip: divid sent {got[C]}, irondivid {got[I]}", flush=True)


def outbound_getaddr(node, port):
    """The node connects out to a listener here; that connection sends getaddr"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.60", port))
    srv.listen(1)
    srv.settimeout(30)
    node.rpc("addnode", f"127.0.0.60:{port}", "onetry")
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return "no connection"
    p = Peer.__new__(Peer)
    p.node, p.src, p.version, p.subver = node, "127.0.0.60", 70920, b"Divi Core: 3.0.0.0"
    p.invs, p.getdatas, p.txs, p.log = set(), set(), set(), []
    p.sock, p.port, p.state = conn, port, "up"
    conn.settimeout(10)
    got_version = False
    deadline = time.time() + 10
    while time.time() < deadline:
        command, _ = p.read()
        if command == "version" and not got_version:
            got_version = True
            p.send("version", p.version_payload())
            p.send("verack")
        elif command == "verack":
            break
    p.pump(3)
    replies = ask(p, "getaddr", quiet=4.0)
    out = {"addresses sent": count_addr(replies), "connected": p.pump(0.5) == "up"}
    p.close()
    srv.close()
    return out


compare("getaddr on an outbound connection (the node connected to the peer)",
        ("ok", outbound_getaddr(C, PORT_BASE + 4)), ("ok", outbound_getaddr(I, PORT_BASE + 4)))


# --- 5. a relayed transaction, asked for once it is in a block (net.cpp:1565-1590) ----------
# divid keeps what it relays for 15 minutes and serves it from there, mined or not
coin = next(u for u in C.rpc("listunspent") if float(u["amount"]) > 2)
raw = C.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}],
            {C.rpc("getnewaddress"): round(float(coin["amount"]) - 0.001, 8)})
RELAYED = C.rpc("signrawtransaction", raw)["hex"]
RELAYED_ID = sha256d(bytes.fromhex(RELAYED))[::-1].hex()
src = next(SRC)
for node in (C, I):
    p = Peer(node, src)
    p.send("tx", bytes.fromhex(RELAYED))
    p.pump(2)
    p.close()
compare("the relayed transaction reaches the mempool", ("ok", RELAYED_ID in C.rpc("getrawmempool")),
        ("ok", RELAYED_ID in I.rpc("getrawmempool")))
case("getdata of the relayed transaction, in the mempool", "getdata", inv_msg([(1, RELAYED_ID)]))
for node in (C, I):
    node.rpc("setgenerate", 1)
compare("the relayed transaction mined", ("ok", RELAYED_ID not in C.rpc("getrawmempool")),
        ("ok", RELAYED_ID not in I.rpc("getrawmempool")))
case("getdata of the relayed transaction, once in a block", "getdata", inv_msg([(1, RELAYED_ID)]))

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
