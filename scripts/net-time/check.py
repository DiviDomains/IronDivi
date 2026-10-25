#!/usr/bin/env python3
"""The network time offset of Divi Core divid and of irondivid, side by side on
regtest: each node pair is fed version messages from script peers, each from
an address of its own, with chosen time skews, and their timeoffset (getinfo,
getnetworkinfo), the clock warning, the time of the version message they send
an inbound peer, and whether they take a block dated past now + 2 h on local
time but inside it on adjusted time (and the reverse) are compared.

One node pair runs at a time (a fresh pair per scenario), on regtest only. Each
row prints PASS (same as divid), KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs.

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
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("NET_TIME_INJECT", "")
HOST = "127.0.0.2"
MAGIC = bytes([0xA1, 0xCF, 0x7E, 0xAC])
RPC_TIMEOUT = 120
START_TIMEOUT = 300
# A node reads its clock a moment after a peer wrote its time: offsets of the
# two nodes may differ by this many seconds
TOL = 1
WARNING = ("Warning: Please check that your computer's date and time are correct! If your clock is wrong "
           "DIVI Core will not work properly.")

# Differences listed in README.md, one per row name: (reason, shape)
KNOWN = {}

fails = 0


def show(v):
    return json.dumps(v, sort_keys=True, default=str)[:240]


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = KNOWN.get(name)
    if listed:
        reason, shape = listed
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


def near(a, b):
    return isinstance(a, int) and isinstance(b, int) and abs(a - b) <= TOL


class Node:
    def __init__(self, name, binary, index, extra_conf=()):
        self.name, self.binary = name, binary
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        password = secrets.token_hex(16)
        user = "nt" + name.replace("-", "")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
            f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "listen=1", "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", "connect=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer: {self.tail()}")

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def tail(self, n=4):
        lines = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "regtest", "debug.log"),
                     os.path.join(self.dir, "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def frame(command, payload):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def netaddr(ip="0.0.0.0", port=0):
    return struct.pack("<Q", 1) + b"\0" * 10 + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def version_payload(at):
    return (struct.pack("<iQq", 70915, 1, at) + netaddr() + netaddr() + struct.pack("<Q", secrets.randbits(64))
            + b"\x0b/net-time:1/" + struct.pack("<i", 0) + b"\x01")


class Peer:
    """A script peer from 127.0.0.`n`: sends a version `skew` seconds off our
    clock, keeps the connection, answers pings, and serves `offer` (a block's
    header and bytes) when asked for it"""

    def __init__(self, node, n, skew):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((f"127.0.0.{n}", 0))
        self.s.settimeout(30)
        self.s.connect((HOST, node.p2p))
        self.sent_at = int(time.time()) + skew
        self.s.sendall(frame("version", version_payload(self.sent_at)))
        self.their_version = None
        self.offer = None
        self.lock = threading.Lock()
        self.got = []
        while True:
            cmd, payload = self.read()
            if cmd == "version":
                self.their_version = payload
                self.version_read_at = int(time.time())
            if cmd == "verack":
                break
        self.s.sendall(frame("verack", b""))
        self.alive = True
        threading.Thread(target=self.serve, daemon=True).start()

    def read(self):
        h = b""
        while len(h) < 24:
            chunk = self.s.recv(24 - len(h))
            if not chunk:
                raise ConnectionError("closed")
            h += chunk
        n = struct.unpack("<I", h[16:20])[0]
        p = b""
        while len(p) < n:
            chunk = self.s.recv(n - len(p))
            if not chunk:
                raise ConnectionError("closed")
            p += chunk
        return h[4:16].rstrip(b"\0").decode(), p

    def serve(self):
        self.s.settimeout(None)
        try:
            while self.alive:
                cmd, payload = self.read()
                with self.lock:
                    self.got.append(cmd)
                if cmd == "ping":
                    self.s.sendall(frame("pong", payload))
                elif cmd == "getheaders" and self.offer:
                    self.s.sendall(frame("headers", b"\x01" + self.offer[0] + b"\x00"))
                elif cmd == "getdata" and self.offer and self.offer[2] in payload:
                    self.s.sendall(frame("block", self.offer[1]))
        except (OSError, ConnectionError, ValueError):
            pass

    def offer_block(self, block_hex, block_hash):
        raw = bytes.fromhex(block_hex)
        version = struct.unpack("<i", raw[:4])[0]
        header = raw[:80 + (32 if version > 3 else 0)]
        inv_hash = bytes.fromhex(block_hash)[::-1]
        self.offer = (header, raw, inv_hash)
        self.s.sendall(frame("inv", b"\x01" + struct.pack("<I", 2) + inv_hash))

    def their_time(self):
        """The time in the node's version message, less our clock when it came"""
        return struct.unpack("<q", self.their_version[12:20])[0] - self.version_read_at

    def close(self):
        self.alive = False
        try:
            self.s.close()
        except OSError:
            pass


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    for n in globals().get("RUNNING", ()):
        t = n.tail()
        if t:
            print(f"#      {n.name}: {t}"[:700], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed
RUNNING = []
pair_count = 0


def pair():
    """A fresh divid and irondivid"""
    global pair_count
    pair_count += 1
    c = Node(f"divid-{pair_count}", DIVID, 0)
    i = Node(f"irondivid-{pair_count}", IRONDIVID, 1)
    RUNNING[:] = [c, i]
    return c, i


def end(nodes, peers):
    for p in peers:
        p.close()
    for n in nodes:
        n.stop()


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


def offsets(n):
    return {"getinfo": n.rpc("getinfo")["timeoffset"], "getnetworkinfo": n.rpc("getnetworkinfo")["timeoffset"]}


def compare_offsets(what, c, i):
    """Both nodes' offsets after a peer, within TOL of each other"""
    time.sleep(1)
    oc, oi = offsets(c), offsets(i)
    same = all(near(oc[k], oi[k]) for k in oc)
    row(f"{what}: timeoffset", oc, oi, same)
    return oc, oi


def warnings(n):
    net = n.rpc("getnetworkinfo")
    return {"getinfo errors": n.rpc("getinfo").get("errors"),
            "getmininginfo errors": n.rpc("getmininginfo").get("errors"),
            "getnetworkinfo warnings": net.get("warnings", "(no such field)")}


# --- blocks dated ahead of the clock, made by a divid whose clock is set ahead -----------
def future_block(ahead):
    """A PoW block on genesis dated `ahead` seconds past the clock, and its hash"""
    m = Node(f"miner-{ahead}", DIVID, 2)
    RUNNING[:] = [m]
    m.rpc("setmocktime", int(time.time()) + ahead)
    m.rpc("setgenerate", 1)
    h = m.rpc("getbestblockhash")
    hexblock = m.rpc("getblock", h, False)
    t = m.rpc("getblock", h)["time"]
    m.stop()
    return hexblock, h, t


BLOCK_2H30 = future_block(9000)
BLOCK_1H30 = future_block(5400)
print(f"# blocks dated {BLOCK_2H30[2] - int(time.time())} s and {BLOCK_1H30[2] - int(time.time())} s ahead",
      flush=True)

# --- 1. seven peers, one at a time: the offset after each ------------------------------
c, i = pair()
print(f"# divid {c.rpc('getinfo').get('version')}, irondivid {i.rpc('getnetworkinfo').get('version')}", flush=True)
row("no peers: timeoffset", offsets(c), offsets(i))
peers = []
for k, skew in enumerate([600, 900, 1200, -300, 1500, 1800, -4800]):
    pc, pi = Peer(c, 10 + k, skew), Peer(i, 10 + k, skew)
    peers += [pc, pi]
    compare_offsets(f"peer {k + 1} ({skew:+d} s)", c, i)
    tc, ti = pc.their_time(), pi.their_time()
    row(f"peer {k + 1}: the node's version time, less the peer's clock (within {TOL + 1} s)", tc, ti,
        abs(tc - ti) <= TOL + 1)
# A peer from an address already sampled, and the peers gone: nothing changes
end([], peers)
peers = [Peer(c, 10, -4000), Peer(i, 10, -4000)]
compare_offsets("an address already sampled (-4000 s), the others gone", c, i)
row("seven peers: the clock warning", warnings(c), warnings(i))
end([c, i], peers)

# --- 2. four peers 80 minutes ahead: past the 70-minute cap, and the warning ------------
c, i = pair()
peers = []
for k in range(4):
    peers += [Peer(c, 20 + k, 4800), Peer(i, 20 + k, 4800)]
compare_offsets("four peers +80 min", c, i)
row("four peers +80 min: the clock warning", warnings(c), warnings(i))
peers += [Peer(c, 24, 4800), Peer(i, 24, 4800), Peer(c, 25, 4800), Peer(i, 25, 4800)]
compare_offsets("six peers +80 min", c, i)
end([c, i], peers)

# --- 3. mixed signs, one peer within 5 minutes: 0 and no warning -----------------------
c, i = pair()
peers = []
for k, skew in enumerate([60, -4800, -4800, -4800]):
    peers += [Peer(c, 30 + k, skew), Peer(i, 30 + k, skew)]
compare_offsets("+60 s and three -80 min", c, i)
row("+60 s and three -80 min: the clock warning", warnings(c), warnings(i))
end([c, i], peers)

# --- 4. the future-block limit on the adjusted clock ---------------------------------
for skew, (block_hex, block_hash, block_time) in ((3600, BLOCK_2H30), (-3600, BLOCK_1H30)):
    c, i = pair()
    peers = []
    for k in range(4):
        peers += [Peer(c, 40 + k, skew), Peer(i, 40 + k, skew)]
    oc, oi = compare_offsets(f"offset {skew:+d} s", c, i)
    ahead = block_time - int(time.time())
    for n, p in ((c, peers[-2]), (i, peers[-1])):
        p.offer_block(block_hex, block_hash)
    wait_for(lambda: c.rpc("getblockcount") == 1 and i.rpc("getblockcount") == 1, 20)
    time.sleep(2)
    # Past now + 2 h on the local clock, inside it on the adjusted clock (+1 h);
    # inside it on the local clock, past it on the adjusted clock (-1 h)
    row(f"offset {skew:+d} s: a block {ahead // 60} min ahead of the clock offered: block count",
        c.rpc("getblockcount"), i.rpc("getblockcount"))
    end([c, i], peers)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
