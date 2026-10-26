#!/usr/bin/env python3
"""Spork messages and the spork RPC, Divi Core divid and irondivid compared case
by case on regtest: the sporkcount a node sends after the handshake, its
answer to sporkcount, getsporks, and an inv or getdata of a spork, what it does
with a spork whose signature is wrong (every kind of wrong), that none of that
is served or announced to a second node, and the state after a restart.

For each kind there are two nodes: the receiver, which raw peers made here
connect to from their own loopback addresses (127.0.0.11 and up), and a second
hop, which connects to the receiver and has a raw observer connected to it.
Both listen on 127.0.0.2. The receiver is connect-only to a port nothing
listens on, so it dials nobody else.

A spork the network accepts is signed with the network's spork key, and
regtest uses the testnet one (divid: chainparams.cpp:443; divid takes -sporkkey
only if it matches that key, spork.cpp:461-480). Nobody here has that key, so
every spork this script sends carries a signature that cannot verify; the rows
that need a good signature are in the node tests (README.md).

Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf; nothing secret goes on a command line.
"""

import base64
import hashlib
import json
import os
import random
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
HOST = "127.0.0.2"
DEAD = PORT_BASE + 49  # the receiver's only -connect peer; nothing listens there
RPC_TIMEOUT = 60
START_TIMEOUT = 120
REGTEST_MAGIC = bytes.fromhex("a1cf7eac")
PROTOCOL = 70920
MSG_SPORK = 6
SPORK_IDS = {
    10001: "SPORK_2_SWIFTTX_ENABLED", 10007: "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT",
    10015: "SPORK_16_LOTTERY_TICKET_MIN_VALUE",
}


# --- rows ------------------------------------------------------------------------------

KNOWN = {}  # row name -> (reason, shape(core, iron) -> bool)

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:900], flush=True)


def show(v):
    if isinstance(v, tuple) and v and v[0] == "err":
        return f"error {v[1]} \"{str(v[2])[:120]}\""
    return json.dumps(v, default=str)[:300]


def compare(name, core, iron):
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
    """The same RPC call on both receivers"""
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(name, core, iron)
    return core, iron


def setup_failed(kind, value, tb):
    # A setup step that fails ends the run with one FAIL line instead of a traceback
    import traceback
    where = traceback.extract_tb(tb)[-1]
    print(f"FAIL   setup: {value} (check.py:{where.lineno})"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, core, hop=False):
        self.name, self.binary, self.core, self.hop = name, binary, core, hop
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"spork{index}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.runs = 0
        self.dir = None
        self.upstream = None  # the receiver a second hop connects to

    def fresh(self, tag):
        self.dir = os.path.join(WORK, f"{self.name}.{tag}")
        os.makedirs(self.dir)

    def write_conf(self):
        target = f"{HOST}:{self.upstream.p2p}" if self.hop else f"{HOST}:{DEAD}"
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "listenonion=0",
            "dnsseed=0", "staking=0", "listen=1", "discover=0", f"connect={target}",
        ]
        path = os.path.join(self.dir, "divi.conf")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)

    def start(self):
        """('up',) once RPC answers, or ('exit', code, first error line)"""
        self.write_conf()
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.run{self.runs}")
        self.err = base + ".err"
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=WORK,
                                         stdout=o, stderr=e, stdin=subprocess.DEVNULL, start_new_session=True,
                                         work=WORK)
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
        return ("exit", f"none within {START_TIMEOUT} s", self.error_line())

    def error_line(self):
        with open(self.err, errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        return next((ln for ln in lines if ln.startswith("Error")), lines[0] if lines else "")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
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
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
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


def start_all(nodes):
    for n in nodes:
        out = n.start()
        if out[0] != "up":
            raise RuntimeError(f"{n.name} did not start: {out}")


# --- the wire -------------------------------------------------------------------------

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(cmd, payload=b""):
    return REGTEST_MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def net_addr(ip, port, services=1):
    return struct.pack("<Q", services) + b"\0" * 10 + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def version_payload(to_ip, to_port, src):
    subver = b"/sporks:1.0/"
    return (struct.pack("<iQq", PROTOCOL, 1, int(time.time())) + net_addr(to_ip, to_port) + net_addr(src, 0)
            + struct.pack("<Q", random.getrandbits(64)) + compact(len(subver)) + subver
            + struct.pack("<i", 0) + b"\x01")


def spork_payload(spork_id, value, when, sig):
    v = value.encode()
    return struct.pack("<i", spork_id) + compact(len(v)) + v + struct.pack("<q", when) + compact(len(sig)) + sig


def inv_payload(items):
    """items: (type, hash bytes)"""
    return compact(len(items)) + b"".join(struct.pack("<I", t) + h for t, h in items)


def parse_inv(payload):
    n, off = payload[0], 1
    if n == 0xfd:
        n, off = struct.unpack("<H", payload[1:3])[0], 3
    return [(struct.unpack("<I", payload[off + 36 * k: off + 36 * k + 4])[0],
             payload[off + 36 * k + 4: off + 36 * (k + 1)].hex()) for k in range(n)]


class Conn:
    """One raw connection: answers ping and version, and keeps every message that comes"""

    def __init__(self, sock, src):
        self.sock, self.src = sock, src
        self.buf = b""
        self.log = []  # (time, command, payload)
        self.closed = False
        self.got_version = self.got_verack = False

    def send(self, cmd, payload=b""):
        try:
            self.sock.sendall(message(cmd, payload))
        except OSError:
            self.closed = True

    def pump(self, secs):
        start = len(self.log)
        deadline = time.time() + secs
        while not self.closed and time.time() < deadline:
            while len(self.buf) >= 24:
                n = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) < 24 + n:
                    break
                cmd = self.buf[4:16].rstrip(b"\0").decode(errors="replace")
                payload, self.buf = self.buf[24:24 + n], self.buf[24 + n:]
                if cmd == "version":
                    self.got_version = True
                    self.send("verack")
                elif cmd == "verack":
                    self.got_verack = True
                elif cmd == "ping":
                    self.send("pong", payload)
                self.log.append((time.time(), cmd, payload))
            self.sock.settimeout(max(0.05, min(0.5, deadline - time.time())))
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.closed = True
                break
            if not data:
                self.closed = True
                break
            self.buf += data
        return self.log[start:]

    def handshake(self, secs=15):
        deadline = time.time() + secs
        while not (self.got_version and self.got_verack) and not self.closed and time.time() < deadline:
            self.pump(min(0.5, max(0.05, deadline - time.time())))
        return self.got_version and self.got_verack

    def commands(self, since=0):
        return [c for _, c, _ in self.log[since:]]

    def payloads(self, command, since=0):
        return [p for _, c, p in self.log[since:] if c == command]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed = True


_sources = iter(range(11, 250))


def next_source():
    return f"127.0.0.{next(_sources)}"


def peer(node, src=None):
    """An inbound peer to `node` from `src`, after the handshake (None if refused)"""
    src = src or next_source()
    try:
        s = socket.create_connection((HOST, node.p2p), timeout=10, source_address=(src, 0))
    except OSError:
        return None
    c = Conn(s, src)
    c.send("version", version_payload(HOST, node.p2p, src))
    if not c.handshake():
        c.close()
        return None
    return c


def settle(c, secs=1.5):
    """Read what the node sends on its own after the handshake"""
    c.pump(secs)


def both_peers(rows_name, fn, *, settle_secs=1.5):
    """Run fn(node, conn) on a fresh peer of each receiver; the two results are compared"""
    out = []
    for n in (C, I):
        c = peer(n)
        if c is None:
            out.append(("ok", "refused"))
            continue
        settle(c, settle_secs)
        try:
            out.append(("ok", fn(n, c)))
        finally:
            c.close()
    compare(rows_name, out[0], out[1])


# --- the nodes of this run -------------------------------------------------------------------

C = Node("divid", DIVID, 0, True)
CH = Node("divid-hop", DIVID, 1, True, hop=True)
I = Node("irondivid", IRONDIVID, 2, False)
IH = Node("irondivid-hop", IRONDIVID, 3, False, hop=True)
CH.upstream, IH.upstream = C, I
ALL = [C, I, CH, IH]
for n in ALL:
    n.fresh("a")

start_all([C, I])
start_all([CH, IH])
for n in (CH, IH):
    # The second hop is connected to its receiver once the receiver counts it
    if not wait_for(lambda n=n: len(n.rpc("getpeerinfo")) == 1, 60):
        raise RuntimeError(f"{n.name} did not connect to its receiver")
hop_peers = {}


def observe_hops():
    """A raw observer on each second hop: it hears what the hop sends on to its peers"""
    for n in (CH, IH):
        c = peer(n)
        if c is None:
            raise RuntimeError(f"{n.name} refused the observer")
        hop_peers[n.name] = c


observe_hops()


def spork_traffic(c, since=0):
    """What a connection was told about sporks: spork messages and inventory of them"""
    msgs = [("spork", struct.unpack("<i", p[:4])[0]) for p in c.payloads("spork", since)]
    invs = [it for p in c.payloads("inv", since) for it in parse_inv(p) if it[0] == MSG_SPORK]
    return {"spork": msgs, "inv": invs}


# --- state before anything is sent ----------------------------------------------------------------

both("spork show", "spork", "show")
both("spork active", "spork", "active")
both("spork unknown name", "spork", "SPORK_99_NOPE", "1")
both("spork set without the spork key", "spork", "SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT", "1")
both("spork set a multi-value spork", "spork", "SPORK_16_LOTTERY_TICKET_MIN_VALUE", "5000;100")
both("spork no arguments", "spork")
both("spork unknown mode", "spork", "bogus")


def handshake_sequence(node, c):
    """What the node sent by itself: the version, verack and sporkcount in order, and the count"""
    seq = [x for x in c.commands() if x in ("version", "verack", "sporkcount")]
    counts = [struct.unpack("<i", p[:4])[0] for p in c.payloads("sporkcount")]
    return {"order": seq, "counts": counts, "payload_bytes": [len(p) for p in c.payloads("sporkcount")]}


both_peers("inbound peer: version, verack, sporkcount, and the count", handshake_sequence)


def getsporks_with_none(node, c):
    mark = len(c.log)
    c.send("getsporks")
    c.pump(2)
    return {"sporks": spork_traffic(c, mark), "stays": not c.closed}


both_peers("getsporks with no sporks: nothing is served, the peer stays", getsporks_with_none)


def answers_sporkcount(count_bytes):
    def fn(node, c):
        mark = len(c.log)
        c.send("sporkcount", count_bytes)
        c.pump(2)
        return {"getsporks": c.commands(mark).count("getsporks"), "stays": not c.closed}
    return fn


both_peers("sporkcount 0: answered with getsporks", answers_sporkcount(struct.pack("<i", 0)))
both_peers("sporkcount 5: answered with getsporks", answers_sporkcount(struct.pack("<i", 5)))
both_peers("sporkcount -1: answered with getsporks", answers_sporkcount(struct.pack("<i", -1)))
both_peers("sporkcount 2 bytes: what the node does", answers_sporkcount(b"\x01\x00"))
both_peers("sporkcount empty: what the node does", answers_sporkcount(b""))


# --- a spork nobody can sign -----------------------------------------------------------------------

# A signature of the right shape (65 bytes, a recovery byte of a compressed key) that verifies against nothing
GOOD_SHAPE = bytes([31]) + os.urandom(64)
NOW = int(time.time())


def bad_spork(payload):
    def fn(node, c):
        mark = len(c.log)
        c.send("spork", payload)
        c.pump(3)
        bans = node.call("listbanned")
        banned = c.src in json.dumps(bans[1]) if bans[0] == "ok" else "?"
        listed = any(p.get("addr", "").startswith(c.src + ":") for p in (node.call("getpeerinfo")[1] or []))
        return {"closed": c.closed, "banned": banned, "still_listed": listed}
    return fn


CASES = [
    ("known id, a signature of the right shape", spork_payload(10007, "0", NOW, GOOD_SHAPE)),
    ("known id, newer time", spork_payload(10007, "0", NOW + 86400, GOOD_SHAPE)),
    ("known id, a time long ago", spork_payload(10007, "0", 1_000_000, GOOD_SHAPE)),
    ("known id, time 0", spork_payload(10007, "0", 0, GOOD_SHAPE)),
    ("multi-value id", spork_payload(10015, "5000;100", NOW, GOOD_SHAPE)),
    ("unknown id 10099", spork_payload(10099, "1", NOW, GOOD_SHAPE)),
    ("unused id 10003", spork_payload(10003, "1", NOW, GOOD_SHAPE)),
    ("id 0", spork_payload(0, "1", NOW, GOOD_SHAPE)),
    ("negative id", spork_payload(-5, "1", NOW, GOOD_SHAPE)),
    ("empty signature", spork_payload(10007, "0", NOW, b"")),
    ("signature of 64 bytes", spork_payload(10007, "0", NOW, GOOD_SHAPE[:64])),
    ("signature of 66 bytes", spork_payload(10007, "0", NOW, GOOD_SHAPE + b"\x00")),
    ("signature header 0x1b (uncompressed key)", spork_payload(10007, "0", NOW, bytes([27]) + GOOD_SHAPE[1:])),
    ("signature header 0x00", spork_payload(10007, "0", NOW, bytes([0]) + GOOD_SHAPE[1:])),
    ("empty value", spork_payload(10007, "", NOW, GOOD_SHAPE)),
    ("value of 5000 bytes", spork_payload(10007, "9" * 5000, NOW, GOOD_SHAPE)),
]
for label, payload in CASES:
    both_peers(f"spork with a bad signature: {label}", bad_spork(payload))


def truncated(payload):
    def fn(node, c):
        c.send("spork", payload)
        c.pump(3)
        return {"closed": c.closed}
    return fn


both_peers("spork cut short (3 bytes)", truncated(b"\x07\x27\x00"))
both_peers("spork with nothing in it", truncated(b""))
both_peers("spork with bytes after the signature",
           truncated(spork_payload(10007, "0", NOW, GOOD_SHAPE) + b"\x00\x00"))


# --- nothing of that is kept, served or announced -------------------------------------------------------

def after_bad_sporks(node, c):
    mark = len(c.log)
    c.send("getsporks")
    c.pump(2)
    return {"served": spork_traffic(c, mark), "tells_count": [struct.unpack("<i", p[:4])[0] for p in c.payloads("sporkcount")]}


both_peers("after the bad sporks: getsporks serves none, and the count is 0", after_bad_sporks)
both("after the bad sporks: spork show", "spork", "show")
both("after the bad sporks: spork active", "spork", "active")


def hop_heard(name):
    c = hop_peers[name]
    c.pump(1)
    return ("ok", spork_traffic(c))


compare("second hop: nothing of the bad sporks was announced or served", hop_heard("divid-hop"), hop_heard("irondivid-hop"))
compare("second hop: no peer was banned or dropped", (C.call("getconnectioncount"), CH.call("getconnectioncount")),
        (I.call("getconnectioncount"), IH.call("getconnectioncount")))


# --- inv and getdata of a spork ---------------------------------------------------------------------------

UNKNOWN = hashlib.sha256(b"sporks-check-unknown").digest()
UNKNOWN2 = hashlib.sha256(b"sporks-check-unknown-2").digest()


def inv_of_unknown(node, c):
    mark = len(c.log)
    c.send("inv", inv_payload([(MSG_SPORK, UNKNOWN)]))
    c.pump(5)
    asked = [it for p in c.payloads("getdata", mark) for it in parse_inv(p)]
    return {"getdata": asked, "stays": not c.closed}


both_peers("inv of a spork it does not have: asked for with getdata", inv_of_unknown)


def inv_twice(node, c):
    mark = len(c.log)
    c.send("inv", inv_payload([(MSG_SPORK, UNKNOWN2)]))
    c.pump(2)
    c.send("inv", inv_payload([(MSG_SPORK, UNKNOWN2)]))
    c.pump(4)
    asked = [it for p in c.payloads("getdata", mark) for it in parse_inv(p)]
    return {"getdata_count": len(asked)}


both_peers("the same spork inv twice: asked for once", inv_twice)


def getdata_of_unknown(node, c):
    mark = len(c.log)
    c.send("getdata", inv_payload([(MSG_SPORK, UNKNOWN)]))
    c.pump(3)
    return {"notfound": [it for p in c.payloads("notfound", mark) for it in parse_inv(p)],
            "spork": spork_traffic(c, mark)["spork"], "stays": not c.closed}


both_peers("getdata of a spork it does not have: notfound", getdata_of_unknown)


def inv_many(node, c):
    mark = len(c.log)
    hashes = [hashlib.sha256(b"many%d" % k).digest() for k in range(3)]
    c.send("inv", inv_payload([(MSG_SPORK, h) for h in hashes]))
    c.pump(4)
    asked = sorted(it[1] for p in c.payloads("getdata", mark) for it in parse_inv(p))
    return {"asked": len(asked), "all_three": asked == sorted(h.hex() for h in hashes)}


both_peers("an inv of three sporks: all three asked for", inv_many)


# --- after a restart ---------------------------------------------------------------------------------------

for c in hop_peers.values():
    c.close()
for n in (CH, IH, C, I):
    n.stop()
start_all([C, I])
both("after a restart: spork show", "spork", "show")
both("after a restart: spork active", "spork", "active")
both_peers("after a restart: version, verack, sporkcount, and the count", handshake_sequence)
both_peers("after a restart: getsporks serves none", getsporks_with_none)

for n in ALL:
    n.stop()

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
