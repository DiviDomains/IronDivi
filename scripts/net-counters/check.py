#!/usr/bin/env python3
"""Traffic counters, ping and the pool summary of Divi Core divid and
irondivid, side by side on regtest: getnettotals, the byte, time and ping
fields of getpeerinfo, the ping call, getmempoolinfo and the counts in
getnetworkinfo. Each node first talks to a raw peer this script plays (so the
bytes on the wire are known exactly), then both follow one divid miner.
Each row prints PASS, KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
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
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's outcome of the named row is changed
INJECT = os.environ.get("NET_COUNTERS_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 60
START_TIMEOUT = 120
MAGIC = bytes([0xA1, 0xCF, 0x7E, 0xAC])     # regtest
PROTOCOL_VERSION = 70915                     # divid's own
PONG_DELAY = 0.3                             # seconds the raw peer waits before it answers a ping
CLOCK_AHEAD = 100                            # seconds the raw peer's clock runs ahead
PING_WINDOW = 130                            # seconds over which automatic pings are counted

# Differences irondivid has on purpose, one per row name: (reason, shape).
# shape takes the two outcomes and is true only for the difference described,
# so a KNOWN row that matches divid, or differs in another way, is a FAIL.
MEMPOOL_EXTRA = {"usage", "maxmempool", "mempoolminfee"}
KNOWN = {
    "getmempoolinfo keys": (
        "irondivid adds usage, maxmempool and mempoolminfee (docs/divid-differences.md R13; divid: "
        "rpcblockchain.cpp:569-574)",
        lambda c, i: c[0] == i[0] == "ok" and set(i[1]) == set(c[1]) | MEMPOOL_EXTRA),
}
fails = 0


def row(name, core, iron, same=None):
    """core, iron: the two outcomes; same: whether they count as equal
    (default: equal values)"""
    global fails
    if INJECT and INJECT == name:
        iron = ("injected", iron)
    if same is None or (INJECT and INJECT == name):
        same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
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
    text = lambda v: json.dumps(v, sort_keys=True, default=str)[:150]
    print(f"{word:<5}  {name}  divid={text(core)}  irondivid={text(iron)}{note}", flush=True)


def not_run(name, why):
    print(f"KNOWN  {name}  not run  [known: {why}]", flush=True)


class Node:
    def __init__(self, name, binary, index, extra=()):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"counters{index}:{password}".encode()).decode()
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=counters{index}", f"rpcpassword={password}", f"rpcbind={HOST}",
            "rpcallowip=127.0.0.0/8", f"bind={HOST}", "daemon=0", "printtoconsole=0", "server=1",
            "discover=0", "listenonion=0", "dnsseed=0", "staking=0", "listen=1",
        ] + list(extra)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")

    def start(self, extra=()):
        self.write_conf(extra)
        self.starts += 1
        out = open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, stdout=out,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited at start ({self.proc.returncode})")
            try:
                if self.call("getblockcount")[0] == "ok":
                    return
            except Exception:
                pass
            time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s")

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

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=float)
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


# --- the raw peer --------------------------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def frame(command, payload):
    return (MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload))
            + sha256d(payload)[:4] + payload)


def net_addr(ip="127.0.0.1", port=51476):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def version_payload():
    return (struct.pack("<iQq", PROTOCOL_VERSION, 1, int(time.time()) + CLOCK_AHEAD) + net_addr() + net_addr()
            + struct.pack("<Q", random.getrandbits(64)) + bytes([7]) + b"/raw:1/" + struct.pack("<i", 0) + b"\x01")


class RawPeer:
    """A peer this script plays: it records every frame both ways (bytes on the
    wire, headers included) and answers pings after PONG_DELAY while `pong` is set"""

    def __init__(self, node, src):
        self.sock = socket.create_connection((HOST, node.p2p), timeout=10, source_address=(src, 0))
        self.sock.settimeout(None)
        self.connected = time.time()
        self.lock = threading.Lock()
        self.sent = 0
        self.recv = 0
        self.frames = []          # (time, command, payload)
        self.pong = True
        self.closed = False
        threading.Thread(target=self.reader, daemon=True).start()

    def send(self, command, payload=b""):
        data = frame(command, payload)
        with self.lock:
            self.sock.sendall(data)
            self.sent += len(data)

    def read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def reader(self):
        try:
            while True:
                header = self.read_exact(24)
                length = struct.unpack("<I", header[16:20])[0]
                payload = self.read_exact(length)
                command = header[4:16].rstrip(b"\0").decode(errors="replace")
                with self.lock:
                    self.recv += 24 + length
                    self.frames.append((time.time(), command, payload))
                if command == "ping" and self.pong:
                    threading.Timer(PONG_DELAY, lambda p=payload: self.safe_send("pong", p)).start()
        except (EOFError, OSError):
            self.closed = True

    def safe_send(self, command, payload):
        try:
            self.send(command, payload)
        except OSError:
            pass

    def commands(self, since=0.0):
        with self.lock:
            return [c for t, c, _ in self.frames if t >= since]

    def wait_for(self, command, secs):
        deadline = time.time() + secs
        while time.time() < deadline:
            if command in self.commands():
                return True
            time.sleep(0.05)
        return False

    def quiet(self, secs=2.0, limit=20):
        """Wait until nothing has come for `secs` (at most `limit` s)"""
        deadline = time.time() + limit
        while time.time() < deadline:
            with self.lock:
                last = self.frames[-1][0] if self.frames else self.connected
            if time.time() - last >= secs:
                return
            time.sleep(0.1)

    def handshake(self):
        self.send("version", version_payload())
        if not (self.wait_for("version", 10) and self.wait_for("verack", 10)):
            raise RuntimeError("no version/verack from the node")
        self.send("verack")

    def counts(self):
        with self.lock:
            return self.sent, self.recv

    def close(self):
        # shutdown first: a close alone does not end the connection while the
        # reader thread waits in recv
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


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


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def both(fn):
    """fn(node) on divid and on irondivid"""
    return fn(D), fn(I)


def totals(n):
    t = n.rpc("getnettotals")
    return t["totalbytesrecv"], t["totalbytessent"]


def peer_of(n):
    peers = n.rpc("getpeerinfo")
    return peers[0] if len(peers) == 1 else None


def counted(n, raw, getter):
    """How the node's counters of the raw peer's connection compare with the bytes
    on the wire: received exactly what the peer sent, sent what the peer read
    (read just before and just after the call, as the node may send meanwhile)"""
    raw_sent, before = raw.counts()
    recv, sent = getter(n)
    raw.quiet(1.0, 5)
    _, after = raw.counts()
    return {"recv = bytes the peer sent": recv == raw_sent,
            "sent = bytes the peer read": before <= sent <= after}


def peer_bytes(n):
    p = peer_of(n)
    return p["bytesrecv"], p["bytessent"]


def netinfo(n):
    i = n.rpc("getnetworkinfo")
    return {"connections": i["connections"], "timeoffset": i["timeoffset"], "localaddresses": i["localaddresses"]}


def pool(n):
    m = n.rpc("getmempoolinfo")
    return {"size": m["size"], "bytes": m["bytes"]}


# --- phase A: each node alone with a raw peer ------------------------------------------

M = Node("miner", DIVID, 0)
D = Node("divid", DIVID, 1, ["disablewallet=1"])
I = Node("irondivid", IRONDIVID, 2, ["disablewallet=1"])
for n in (D, I):
    n.start()
print(f"# divid {D.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

c, i = both(lambda n: n.rpc("getnettotals"))
row("getnettotals keys and types", {k: type(v).__name__ for k, v in c.items()},
    {k: type(v).__name__ for k, v in i.items()})
row("getnettotals before any peer", [c["totalbytesrecv"], c["totalbytessent"]],
    [i["totalbytesrecv"], i["totalbytessent"]])
now_ms = time.time() * 1000
row("getnettotals timemillis is the clock in ms", abs(c["timemillis"] - now_ms) < 5000,
    abs(i["timemillis"] - now_ms) < 5000)
row("getnetworkinfo before any peer", *both(netinfo))
row("getpeerinfo before any peer", *both(lambda n: n.rpc("getpeerinfo")))

raws = {}
for n, src in ((D, "127.0.0.3"), (I, "127.0.0.4")):
    raws[n.name] = RawPeer(n, src)
    raws[n.name].handshake()
for r in raws.values():
    r.quiet(3.0)
R = lambda n: raws[n.name]

row("getnettotals after the handshake", *both(lambda n: counted(n, R(n), totals)))
row("getpeerinfo bytesrecv/bytessent after the handshake", *both(lambda n: counted(n, R(n), peer_bytes)))


def times(n):
    p = peer_of(n)
    now = time.time()
    return {"lastsend within 10 s": abs(now - p["lastsend"]) <= 10,
            "lastrecv within 10 s": abs(now - p["lastrecv"]) <= 10,
            "conntime is the connect time": abs(R(n).connected - p["conntime"]) <= 3,
            # not in divid's getpeerinfo (rpcnet.cpp:117-150)
            "timeoffset": None if "timeoffset" not in p else
            p["timeoffset"] if abs(p["timeoffset"] - CLOCK_AHEAD) > 2 else CLOCK_AHEAD}


row("getpeerinfo lastsend/lastrecv/conntime/timeoffset", *both(times))
row("getnetworkinfo with one peer 100 s ahead", *both(netinfo))


def handshake_ping(n):
    p = peer_of(n)
    return {"pings sent so far": R(n).commands().count("ping"),
            "pingtime is the pong delay": PONG_DELAY - 0.05 <= p["pingtime"] <= PONG_DELAY + 1.0,
            "pingwait": p.get("pingwait")}


row("getpeerinfo pingtime of the ping sent at the handshake", *both(handshake_ping))

# The ping call: one ping to each peer; unanswered, pingwait shows and grows
for r in raws.values():
    r.pong = False
start = time.time()
row("ping", *both(lambda n: n.call("ping")))
row("ping with an argument", *both(lambda n: (lambda o: o[:2] + (o[2].split("\n")[0],) if o[0] == "err" else o)(
    n.call("ping", 1))))
time.sleep(2)
first = {n.name: peer_of(n) for n in (D, I)}
time.sleep(2)


def waiting(n):
    a, b = first[n.name], peer_of(n)
    return {"pings sent by the call": R(n).commands(start).count("ping"),
            "pingwait shown": "pingwait" in a,
            "pingwait grows": "pingwait" in b and b["pingwait"] > a.get("pingwait", 0),
            "pingtime kept meanwhile": b["pingtime"] == a["pingtime"]}


row("getpeerinfo while the ping is unanswered", *both(waiting))
asked = time.time()
for n in (D, I):
    pings = [p for t, c, p in R(n).frames if c == "ping" and t >= start]
    if pings:
        R(n).send("pong", pings[-1])
time.sleep(1)


def answered(n):
    p = peer_of(n)
    return {"pingwait": p.get("pingwait"),
            "pingtime is the wait for the answer": asked - start - 1 <= p["pingtime"] <= asked - start + 2}


row("getpeerinfo after the late pong", *both(answered))

# Automatic pings: how many in PING_WINDOW seconds once a ping is answered
for r in raws.values():
    r.pong = True
window = time.time()
print(f"# counting automatic pings for {PING_WINDOW} s", flush=True)
time.sleep(PING_WINDOW)
row(f"automatic pings in {PING_WINDOW} s", *both(lambda n: R(n).commands(window).count("ping")))
row(f"getnettotals after {PING_WINDOW} s of pings", *both(lambda n: counted(n, R(n), totals)))

# The peer leaves: the totals keep its bytes
kept = {n.name: totals(n) for n in (D, I)}
for r in raws.values():
    r.close()
wait_for(lambda: all(n.rpc("getconnectioncount") == 0 for n in (D, I)), 30)
row("getnettotals after the peer left (its bytes kept)", *both(
    lambda n: (lambda t, k: t[0] == k[0] and t[1] >= k[1])(totals(n), kept[n.name])))
row("getnetworkinfo after the peer left", *both(netinfo))
not_run("a peer that never answers a ping is dropped after 20 minutes",
        "too long for this run; both disconnect when a ping is unanswered for 20 minutes (divid: Node.cpp:829, "
        "irondivid: crates/divi-network/src/connection.rs inactive_peers_time_out_after_twenty_minutes)")

# --- phase B: both follow one divid miner ------------------------------------------------

for n in (D, I):
    n.stop()
for n in (D, I):
    n.start()
row("after restart: getnettotals before any peer (counted from the start)", *both(totals))
for n in (D, I):
    n.stop()
M.start()
M.rpc("setgenerate", 1)
for n in (D, I):
    n.start([f"connect={HOST}:{M.p2p}"])
if not wait_for(lambda: all(n.rpc("getconnectioncount") == 1 and n.rpc("getblockcount") == 1 for n in (D, I)), 90):
    raise RuntimeError("divid and irondivid did not follow the miner")
row("getmempoolinfo keys", *both(lambda n: n.call("getmempoolinfo")))
row("getmempoolinfo empty", *both(pool))

start_totals = {n.name: totals(n) for n in (D, I)}
M.rpc("setgenerate", 104)
if not wait_for(lambda: all(n.rpc("getblockcount") == 105 for n in (D, I)), 120):
    raise RuntimeError("divid and irondivid did not follow 104 blocks")
block_bytes = sum(M.rpc("getblock", M.rpc("getblockhash", h))["size"] for h in range(2, 106))


def grew(n):
    recv, sent = totals(n)
    got = recv - start_totals[n.name][0]
    return {"recv grew by at least the blocks' size": got >= block_bytes,
            "and by less than twice it plus 50 kB": got < 2 * block_bytes + 50_000,
            "sent grew": sent > start_totals[n.name][1]}


row("getnettotals after 104 blocks", *both(grew))
row("getpeerinfo bytes of the miner within the totals", *both(
    lambda n: (lambda p, t: p["bytesrecv"] <= t[0] and p["bytessent"] <= t[1])(peer_of(n), totals(n))))
row("getnetworkinfo following the miner", *both(netinfo))

addr = M.rpc("getnewaddress")
sent_txs = [M.rpc("sendtoaddress", addr, amount) for amount in (1, 2, 3)]
sizes = sum(len(M.rpc("getrawtransaction", t)) // 2 for t in sent_txs)
if not wait_for(lambda: all(set(sent_txs) <= set(n.rpc("getrawmempool")) for n in (D, I)), 60):
    raise RuntimeError("the transactions did not reach divid and irondivid")
row("getmempoolinfo after three transactions", *both(pool))
row("getmempoolinfo bytes is the transactions' size", *both(lambda n: pool(n)["bytes"] == sizes))
M.rpc("setgenerate", 1)
if not wait_for(lambda: all(n.rpc("getblockcount") == 106 for n in (D, I)), 60):
    raise RuntimeError("the block with the transactions did not arrive")
time.sleep(1)
row("getmempoolinfo after they confirm", *both(pool))
tip = M.rpc("getbestblockhash")
for n in (D, I):
    n.rpc("invalidateblock", tip)
time.sleep(1)
row("getmempoolinfo after the block is invalidated (reorg)", *both(pool))
for n in (D, I):
    n.rpc("reconsiderblock", tip)
wait_for(lambda: all(n.rpc("getblockcount") == 106 for n in (D, I)), 30)
time.sleep(1)
row("getmempoolinfo after reconsiderblock", *both(pool))

more = [M.rpc("sendtoaddress", addr, amount) for amount in (4, 5)]
if not wait_for(lambda: all(set(more) <= set(n.rpc("getrawmempool")) for n in (D, I)), 60):
    raise RuntimeError("the last transactions did not reach divid and irondivid")
row("getmempoolinfo before the restart", *both(pool))
for n in (D, I):
    n.stop()
for n in (D, I):
    n.start([f"connect={HOST}:{M.p2p}"])
wait_for(lambda: all(n.rpc("getconnectioncount") == 1 for n in (D, I)), 60)
time.sleep(5)
row("after restart: getmempoolinfo", *both(pool))
row("after restart: getnetworkinfo", *both(netinfo))

for n in (D, I, M):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
