#!/usr/bin/env python3
"""Peer address gossip and peers.dat, Divi Core divid and irondivid compared
case by case on regtest: getaddr from inbound and outbound peers, addr
messages of every size and kind and what a second peer is relayed, addnode,
-connect, -seednode, -addnode, -listen=0 and -discover at start, and
peers.dat after clean and unclean stops, damaged, and swapped between the two.

Both nodes listen on 127.0.0.2 and are connect-only to a port nothing listens
on, so neither dials an address it learns. Raw peers made here connect to them
from their own loopback addresses (127.0.0.11 and up), and raw listeners
(127.0.0.31 and up) take the connections a node is told to make. Each row
prints PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

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
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
DEAD = PORT_BASE + 49  # each node's only -connect peer; nothing listens there
RPC_TIMEOUT = 60
START_TIMEOUT = 120
REGTEST_MAGIC = bytes.fromhex("a1cf7eac")
REGTEST_PORT = 51476
PROTOCOL = 70920
# divid keeps a gossiped address only of a network it can reach, and IPv4 or
# IPv6 is reachable once a routable local address of it is known (AddLocal,
# NetworkLocalAddressHelpers.cpp:81-104); with discover=0 these give it one of
# each. Nothing dials them.
EXTERNAL = ["externalip=1.0.0.255", "externalip=2a0b:7280::255"]


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


PORT_0 = ("divid keeps an address with port 0, as it checks only the IP (CNetAddr::IsRoutable, "
          "netbase.cpp:875-878; addrman.cpp:249-250), though nothing can connect to it; irondivid relays it as divid "
          "does but leaves it out of its book (crates/divi-network/src/addrbook.rs)")
NO_LOCAL = ("divid counts IPv4 and IPv6 as reachable only once it knows a routable local address of its own "
            "(vfReachable starts false and only AddLocal sets it, NetworkLocalAddressHelpers.cpp:18, :73-79, "
            ":163-167), and keeps no gossiped address of an unreachable network (main.cpp:544-551): a node with "
            "-discover=0 and no -externalip, or behind NAT with only private interface addresses, never keeps one. "
            "irondivid keeps them (crates/divi-node/src/node.rs, the addr handler)")
KNOWN = {
    "addr port 0: kept": (PORT_0, pair(("ok", ["kept"]), ("ok", ["not kept"]))),
    "no -externalip: addr of 10 public IPv4 addresses, kept": (
        NO_LOCAL, lambda c, i: c == ("ok", 0) and i[0] == "ok" and i[1] >= 9),
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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


def show(v):
    if isinstance(v, tuple) and v and v[0] == "err":
        return f"error {v[1]} \"{str(v[2])[:120]}\""
    return json.dumps(v, default=str)[:200]


def compare(name, core, iron):
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
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
    def __init__(self, name, binary, index, core):
        self.name, self.binary, self.core = name, binary, core
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"gossip{index}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.runs = 0
        self.dir = None

    def fresh(self, tag):
        """A new, empty data directory"""
        self.dir = os.path.join(WORK, f"{self.name}.{tag}")
        os.makedirs(self.dir)

    def write_conf(self, extra=(), connect=True, external=True):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "listenonion=0",
            "dnsseed=0", "staking=0",
        ]
        if connect:
            lines.append(f"connect={HOST}:{DEAD}")
        if external:
            lines += EXTERNAL
        keys = {e.split("=", 1)[0] for e in extra}
        lines += [ln for ln in ("listen=1", "discover=0") if ln.split("=", 1)[0] not in keys]
        lines += list(extra)
        path = os.path.join(self.dir, "divi.conf")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)

    def net_dir(self):
        """Where the node keeps its regtest files: divid in regtest/, irondivid in the data directory"""
        return os.path.join(self.dir, "regtest") if self.core else self.dir

    def peers_dat(self):
        return os.path.join(self.net_dir(), "peers.dat")

    def launch(self, *args):
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.run{self.runs}")
        self.err = base + ".err"
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=WORK,
                                         stdout=o, stderr=e, stdin=subprocess.DEVNULL, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code, first error line)"""
        self.launch(*args)
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
        """A clean stop (RPC stop, then waiting)"""
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

    def kill(self):
        """An unclean stop"""
        if self.proc is None:
            return
        self.proc.kill()
        self.proc.wait()
        self.proc = None

    def peer_count(self):
        return len(self.rpc("getpeerinfo"))


def start_both(*args, extra=(), connect=True, external=True, after_kill=False, own=None):
    """Start both; `own` maps a node to conf lines of its own"""
    for n in (C, I):
        n.write_conf(list(extra) + list((own or {}).get(n.name, [])), connect=connect, external=external)
        out = n.start(*args)
        if out[0] != "up" and after_kill and n.core:
            # After a kill -9 divid usually refuses its block database
            # (scripts/unclean-stop); the address rows come after that
            out = n.start("-reindex", *args)
        if out[0] != "up":
            raise RuntimeError(f"{n.name} did not start with {list(extra) + list(args)}: {out}")


def stop_both():
    for n in (C, I):
        n.stop()


def fresh_both(tag):
    for n in (C, I):
        n.fresh(tag)


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


def ip16(ip):
    if ":" in ip:
        return socket.inet_pton(socket.AF_INET6, ip)
    return b"\0" * 10 + b"\xff\xff" + socket.inet_aton(ip)


def ip_text(b):
    if b[:12] == b"\0" * 10 + b"\xff\xff":
        return socket.inet_ntoa(b[12:])
    return socket.inet_ntop(socket.AF_INET6, b)


def net_addr(ip, port, services=1):
    return struct.pack("<Q", services) + ip16(ip) + struct.pack(">H", port)


def addr_payload(entries):
    """entries: (time, ip, port)"""
    return compact(len(entries)) + b"".join(struct.pack("<I", t) + net_addr(ip, port) for t, ip, port in entries)


def parse_addr(payload):
    """[(time, ip, port)]"""
    n, off = payload[0], 1
    if n == 0xfd:
        n, off = struct.unpack("<H", payload[1:3])[0], 3
    elif n == 0xfe:
        n, off = struct.unpack("<I", payload[1:5])[0], 5
    out = []
    for k in range(n):
        e = payload[off + 30 * k: off + 30 * (k + 1)]
        if len(e) < 30:
            break
        out.append((struct.unpack("<I", e[:4])[0], ip_text(e[12:28]), struct.unpack(">H", e[28:30])[0]))
    return out


def version_payload(to_ip, to_port, src):
    subver = b"/addr-gossip:1.0/"
    return (struct.pack("<iQq", PROTOCOL, 1, int(time.time())) + net_addr(to_ip, to_port) + net_addr(src, 0)
            + struct.pack("<Q", random.getrandbits(64)) + compact(len(subver)) + subver
            + struct.pack("<i", 0) + b"\x01")


class Conn:
    """One raw connection: answers ping (and version, as the side that did not
    send it first), and keeps every message that comes"""

    def __init__(self, sock, src, responder):
        self.sock, self.src, self.responder = sock, src, responder
        self.buf = b""
        self.log = []  # (time, command, payload)
        self.closed = False
        self.got_version = self.got_verack = False

    def send(self, cmd, payload=b""):
        try:
            self.sock.sendall(message(cmd, payload))
        except OSError:
            self.closed = True

    def pump(self, secs, until=None):
        """Read for secs (or until a message `until` comes); the new messages"""
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
                    if self.responder:
                        self.send("version", version_payload(*self.sock.getpeername()[:2], self.src))
                    self.send("verack")
                elif cmd == "verack":
                    self.got_verack = True
                elif cmd == "ping":
                    self.send("pong", payload)
                self.log.append((time.time(), cmd, payload))
                if until is not None and cmd == until:
                    return self.log[start:]
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

    def addr_messages(self, since=0):
        return [parse_addr(p) for _, c, p in self.log[since:] if c == "addr"]

    def addresses(self, since=0):
        return {(ip, port) for m in self.addr_messages(since) for _, ip, port in m}

    def collect_addr(self, secs=6, quiet=2.5):
        """Pump until no addr has come for `quiet` seconds (at most secs); the
        addr messages that came, each a list"""
        start = len(self.log)
        deadline = time.time() + secs
        last = time.time()
        while time.time() < deadline and not self.closed:
            new = self.pump(0.3)
            if any(c == "addr" for _, c, _ in new):
                last = time.time()
            if time.time() - last > quiet and len(self.log) > start or time.time() - last > quiet + 1.5:
                break
        return self.addr_messages(start)

    def stays(self, secs):
        """True if the node keeps the connection open for secs"""
        self.pump(secs)
        return not self.closed

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed = True


def peer(node, src):
    """An inbound peer to `node` from `src`, after the handshake (None if refused)"""
    try:
        s = socket.create_connection((HOST, node.p2p), timeout=10, source_address=(src, 0))
    except OSError:
        return None
    c = Conn(s, src, responder=False)
    c.send("version", version_payload(HOST, node.p2p, src))
    if not c.handshake():
        c.close()
        return None
    return c


class Listener:
    """A raw peer a node is told to connect to"""

    def __init__(self, ip, port):
        self.ip, self.port = ip, port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(4)
        self.target = f"{ip}:{port}"

    def accept(self, secs):
        """The node's connection after the handshake, or None"""
        self.sock.settimeout(secs)
        try:
            s, _ = self.sock.accept()
        except OSError:
            return None
        c = Conn(s, self.ip, responder=True)
        if not c.handshake():
            c.close()
            return None
        return c

    def close(self):
        self.sock.close()


def accept_both(lc, li, secs):
    """Both nodes' connections, accepted at once (each handshake has its own clock)"""
    import threading
    out = {}
    ts = [threading.Thread(target=lambda k=k, l=l: out.__setitem__(k, l.accept(secs))) for k, l in (("c", lc), ("i", li))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out["c"], out["i"]


def arrivals(conn):
    """How many times each address came in the connection's addr messages"""
    from collections import Counter
    return Counter((ip, port) for m in conn.addr_messages() for _, ip, port in m)


_listeners = iter(range(10, 40, 2))


def listeners():
    """A fresh listener for each node: (divid's, irondivid's), on an address of
    their own, each on its own port"""
    k = next(_listeners)
    ip = f"127.0.0.{21 + k}"
    return Listener(ip, PORT_BASE + k), Listener(ip, PORT_BASE + k + 1)


# --- addresses ---------------------------------------------------------------------------

_groups = ((a, b) for a in range(11, 100) for b in range(256))


def public(n, port=REGTEST_PORT):
    """n public IPv4 addresses, each in a /16 of its own (addrman buckets by group)"""
    out = []
    for _ in range(n):
        a, b = next(_groups)
        out.append((f"{a}.{b}.7.9", port))
    return out


def entries(addrs, t):
    return [(t, ip, port) for ip, port in addrs]


# --- peers.dat -----------------------------------------------------------------------------

def low64(h):
    return int.from_bytes(h[:8], "little")


def group(b):
    """CNetAddr::GetGroup (netbase.cpp:952-1010) for the kinds of address made here"""
    if b[:12] == b"\0" * 10 + b"\xff\xff":
        a, c = b[12], b[13]
        if a in (0, 10, 127) or (a, c) == (192, 168) or (a == 100 and 64 <= c <= 127):
            return bytes([0])
        return bytes([1, a, c])
    if b[:6] == bytes.fromhex("fd87d87eeb43"):
        return bytes([3, b[6] | 0x0f])
    return bytes([2]) + b[:4]


def new_bucket(key, addr, src):
    """CAddrInfo::GetNewBucket (addrman.cpp:20-26)"""
    sg = group(src)
    h1 = low64(dsha(key + compact(len(group(addr))) + group(addr) + compact(len(sg)) + sg))
    return low64(dsha(key + compact(len(sg)) + sg + struct.pack("<Q", h1 % 64))) % 1024


def bucket_position(key, bucket, addr, port):
    """CAddrInfo::GetBucketPosition (addrman.cpp:28-32), the new table"""
    k = addr + struct.pack(">H", port)
    return low64(dsha(key + b"N" + struct.pack("<i", bucket) + compact(len(k)) + k)) % 64


def read_varint(b, off):
    n = b[off]
    if n < 0xfd:
        return n, off + 1
    if n == 0xfd:
        return struct.unpack("<H", b[off + 1:off + 3])[0], off + 3
    return struct.unpack("<I", b[off + 1:off + 5])[0], off + 5


def read_peers(path):
    """What a peers.dat holds: {'state': 'missing'|'unreadable'|'core'|'irondivid', 'addrs':
    {(ip, port): time}, 'key', 'new': {bucket: [(ip16, port)]}, 'src': {(ip, port): src16}}"""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return {"state": "missing", "addrs": {}}
    if len(data) < 32 or dsha(data[:-32]) != data[-32:]:
        return {"state": "unreadable", "addrs": {}}
    body = data[:-32]
    out = {"addrs": {}, "src": {}, "new": {}}
    try:
        if body[:8] == b"IRDPEERS":
            out["state"] = "irondivid"
            count = struct.unpack("<I", body[12:16])[0]
            for k in range(count):
                e = body[16 + 30 * k:46 + 30 * k]
                out["addrs"][(ip_text(e[:16]), struct.unpack(">H", e[16:18])[0])] = struct.unpack("<I", e[26:30])[0]
            return out
        if body[:4] != REGTEST_MAGIC or body[5] != 32:
            return {"state": "unreadable", "addrs": {}}
        out["state"] = "core"
        version, key = body[4], body[6:38]
        out["key"] = key
        n_new, n_tried, n_buckets = struct.unpack("<iii", body[38:50])
        off = 50
        infos = []
        for _ in range(n_new + n_tried):
            # CAddrInfo: nVersion, nTime, nServices, ip, port (big-endian), source, nLastSuccess, nAttempts
            t = struct.unpack("<I", body[off + 4:off + 8])[0]
            a, p, s = body[off + 16:off + 32], struct.unpack(">H", body[off + 32:off + 34])[0], body[off + 34:off + 50]
            infos.append((a, p))
            out["addrs"][(ip_text(a), p)] = t
            out["src"][(ip_text(a), p)] = s
            off += 62
        if version == 1:
            n_buckets ^= 1 << 30
        for bucket in range(n_buckets):
            size = struct.unpack("<i", body[off:off + 4])[0]
            off += 4
            for _ in range(size):
                index = struct.unpack("<i", body[off:off + 4])[0]
                off += 4
                if 0 <= index < n_new:
                    out["new"].setdefault(bucket, []).append(infos[index])
        return out
    except (struct.error, IndexError, ValueError):
        return {"state": "unreadable", "addrs": {}}


def collided(book, ip, port, src):
    """True if the address's place in the new table (the file's own key) holds
    another address: divid drops a new address that lands on a taken place
    (addrman.cpp:291-311)"""
    if book.get("state") != "core":
        return False
    key, a = book["key"], ip16(ip)
    bucket = new_bucket(key, a, ip16(src))
    pos = bucket_position(key, bucket, a, port)
    return any(bucket_position(key, bucket, o, op) == pos and (o, op) != (a, port)
               for o, op in book["new"].get(bucket, []))


def kept(book, addrs, src):
    """For each address: 'kept', 'not kept', or 'collision' when it is not kept
    but its place in the new table holds another address (so the book cannot
    say whether it would have been)"""
    out = []
    ips = {a for a, _ in book["addrs"]}
    for ip, port in addrs:
        if (ip, port) in book["addrs"]:
            out.append("kept")
        elif ip not in ips and not (book is books["i"] and port == 0) and collided(book, ip, port, src):
            # (irondivid keeps no port 0 address, collision or not)
            out.append("collision")
        else:
            out.append("not kept")
    return out


def kept_both(addrs, src_c, src_i=None):
    """kept() on both books; where one side's place was taken, it counts as the other side's outcome"""
    c, i = kept(books["c"], addrs, src_c), kept(books["i"], addrs, src_i or src_c)
    for k in range(len(addrs)):
        if c[k] == "collision":
            c[k] = "kept" if i[k] == "collision" else i[k]
        if i[k] == "collision":
            i[k] = c[k]
    return c, i


def share(n, book_size):
    """A getaddr answer as divid's addrman gives it: 23% of the book (ADDRMAN_GETADDR_MAX_PCT, at most
    ADDRMAN_GETADDR_MAX 2500, addrman.cpp:451-469), and at most 1000 per peer (MAX_ADDR_TO_SEND, Node.cpp:922-931)"""
    want = min(23 * book_size // 100, 2500, 1000)
    return "23% of the book" if n == want else f"{n} of {book_size}"


# --- start -----------------------------------------------------------------------------------

C = Node("divid", DIVID, 0, True)
I = Node("irondivid", IRONDIVID, 1, False)
# Each peer from an address of its own, not used by the listeners (127.0.0.31 and up)
SRC = iter(f"127.0.1.{k}" for k in range(1, 255))


def src_pair():
    return next(SRC)


fresh_both("a")
start_both()
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def reachable(node):
    return {n["name"]: n["reachable"] for n in node.rpc("getnetworkinfo")["networks"]}


compare("getnetworkinfo reachable networks", ("ok", reachable(C)), ("ok", reachable(I)))

# --- getaddr with an empty book; an outbound peer ---------------------------------------------
# main.cpp:438-442: getaddr goes to an outbound peer after its version;
# main.cpp:863-869: only an inbound peer's getaddr is answered

src = src_pair()
pc, pi = peer(C, src), peer(I, src)
for p in (pc, pi):
    p.send("getaddr")
compare("getaddr, empty book: addresses in the answer",
        ("ok", sum(len(m) for m in pc.collect_addr())), ("ok", sum(len(m) for m in pi.collect_addr())))
R = {"c": pc, "i": pi}  # stays: the second peer that relays are watched on

lc, li = listeners()
C.call("addnode", lc.target, "onetry")
I.call("addnode", li.target, "onetry")
oc, oi = accept_both(lc, li, 15)
compare("addnode onetry: the node connects", ("ok", oc is not None), ("ok", oi is not None))
ANSWER = public(5)
if oc and oi:
    oc.pump(5)
    oi.pump(5)
    compare("getaddr sent to an outbound peer after the handshake",
            ("ok", "getaddr" in oc.commands()), ("ok", "getaddr" in oi.commands()))
    compare("getpeerinfo: the outbound peer, inbound",
            ("ok", [p.get("inbound") for p in C.rpc("getpeerinfo") if p["addr"] == lc.target]),
            ("ok", [p.get("inbound") for p in I.rpc("getpeerinfo") if p["addr"] == li.target]))
    # The outbound peer asks for addresses: not answered (main.cpp:863)
    mark = (len(oc.log), len(oi.log))
    for o in (oc, oi):
        o.send("getaddr")
    oc.pump(4)
    oi.pump(4)
    compare("getaddr from an outbound peer: addr messages in answer",
            ("ok", len(oc.addr_messages(mark[0]))), ("ok", len(oi.addr_messages(mark[1]))))
    # Its answer to the node's getaddr: kept, and not relayed (fGetAddr, main.cpp:545)
    now = int(time.time())
    for o in (oc, oi):
        o.send("addr", addr_payload(entries(ANSWER, now)))
    for k in ("c", "i"):
        R[k].pump(6)
    compare("an outbound peer's answer to getaddr: relayed to the inbound peer",
            ("ok", sorted(R["c"].addresses() & set(ANSWER))), ("ok", sorted(R["i"].addresses() & set(ANSWER))))
    for o in (oc, oi):
        o.close()
lc.close()
li.close()
compare("after the outbound peer leaves: peers",
        ("ok", wait_for(lambda: C.peer_count() == 1, 15)), ("ok", wait_for(lambda: I.peer_count() == 1, 15)))

# --- addr: sizes, times, kinds; what the second peer is relayed ---------------------------------
# main.cpp:521-560: over 1000 entries scores 20 and keeps none; a time at or
# before 100000000 or more than 10 minutes ahead becomes 5 days ago; each
# address of a message of at most 10, newer than 10 minutes, routable, goes to
# two peers (one if its network is not reachable), not back to the sender.
# divid sends what it relays on its trickle (main.cpp:1298-1301), so the
# second peer is read once, after all of them.

FEED = src_pair()
fc, fi = peer(C, FEED), peer(I, FEED)
cases = []  # (name, [(ip, port)], [(time, ip, port)] as sent, relay row)


def feed(name, sent, relay_row=True):
    for f in (fc, fi):
        f.send("addr", addr_payload(sent))
    cases.append((name, [(ip, port) for _, ip, port in sent], sent, relay_row))
    for c in (fc, fi, R["c"], R["i"]):
        c.pump(0.3)


now = int(time.time())
ONE = public(1)
feed("of 1 entry", entries(ONE, now))
TEN = public(10)
feed("of 10 entries", entries(TEN, now))
OVER = public(1001)
feed("of 1001 entries", entries(OVER, now))


def banscore(node, src):
    return [p.get("banscore") for p in node.rpc("getpeerinfo") if p["addr"].rsplit(":", 1)[0] == src]


compare("addr of 1001 entries: the sender's banscore, connected", ("ok", banscore(C, FEED)), ("ok", banscore(I, FEED)))

now = int(time.time())
T = public(6)
TIMES = [(now - 3600, *T[0]), (now - 300, *T[1]), (now + 600, *T[2]), (now + 660, *T[3]),
         (0, *T[4]), (100000000, *T[5])]
TIME_NAMES = ["an hour ago", "5 minutes ago", "10 minutes ahead", "11 minutes ahead", "zero", "100000000"]
for (t, ip, port), what in zip(TIMES, TIME_NAMES):
    feed(f"time {what}", [(t, ip, port)])

now = int(time.time())
KINDS = [("unroutable 10.1.2.3", "10.1.2.3", REGTEST_PORT), ("unroutable 192.168.7.7", "192.168.7.7", REGTEST_PORT),
         ("unroutable 127.0.0.99", "127.0.0.99", REGTEST_PORT), ("unroutable 100.64.0.9", "100.64.0.9", REGTEST_PORT),
         ("IPv6", "2a01:4f8:c0c:1234::2", REGTEST_PORT),
         ("onion-mapped", "fd87:d87e:eb43:1234:5678:9abc:def0:1234", REGTEST_PORT),
         ("port 0", "31.4.4.4", 0), ("port 1", "32.5.5.5", 1), ("port 65535", "33.6.6.6", 65535)]
for what, ip, port in KINDS:
    # an onion address goes to one peer only (its network is not reachable),
    # chosen by a hash that may pick the sender: not a row
    feed(what, [(now, ip, port)], relay_row=what != "onion-mapped")

now = int(time.time())
feed("again, the same address and port", entries(ONE, now + 1))
feed("again, the same address with another port", [(now, ONE[0][0], 51999)])
DUP = public(1)
feed("with one address twice", entries(DUP + DUP, now))
# Last, so its 1000 addresses do not take the places in divid's buckets of the
# ones above (addrman.cpp:291-311)
THOUSAND = public(1000)
feed("of 1000 entries", entries(THOUSAND, now))
for k in ("c", "i"):
    R[k].collect_addr(15, quiet=6)
arrived = {k: arrivals(R[k]) for k in ("c", "i")}
for name, addrs, sent, relay_row in cases:
    if not relay_row:
        continue
    if name.startswith("again"):
        # how many times each address came to the second peer in all
        compare(f"addr {name}: times the second peer got it",
                ("ok", [arrived["c"][a] for a in addrs]), ("ok", [arrived["i"][a] for a in addrs]))
        continue
    rc = sorted(a for a in set(addrs) if arrived["c"][a])
    ri = sorted(a for a in set(addrs) if arrived["i"][a])
    if len(addrs) > 10:
        compare(f"addr {name}: relayed to the second peer, how many", ("ok", len(rc)), ("ok", len(ri)))
    else:
        compare(f"addr {name}: relayed to the second peer", ("ok", [f"{a}:{p}" for a, p in rc]),
                ("ok", [f"{a}:{p}" for a, p in ri]))
compare("addr: the sender is still connected", ("ok", fc.stays(1)), ("ok", fi.stays(1)))

# --- getaddr: from the sender, from the second peer, twice on one connection --------------------
# main.cpp:863-869 and :1087-1104: the answer leaves out what the peer is
# known to have (setAddrKnown: what it sent, what it was sent)

fed = {a for _, addrs, _, _ in cases for a in addrs}
mark = (len(fc.log), len(fi.log))
for f in (fc, fi):
    f.send("getaddr")
ac, ai = fc.collect_addr(), fi.collect_addr()
compare("getaddr from the sender: addresses it sent, in the answer",
        ("ok", len({(ip, p) for m in ac for _, ip, p in m} & fed)),
        ("ok", len({(ip, p) for m in ai for _, ip, p in m} & fed)))

relayed = {k: R[k].addresses() for k in ("c", "i")}
mark_r = {k: len(R[k].log) for k in ("c", "i")}
for k in ("c", "i"):
    R[k].send("getaddr")
got = {k: R[k].collect_addr() for k in ("c", "i")}
compare("getaddr from the second peer: addresses it was relayed, in the answer",
        ("ok", len({(ip, p) for m in got["c"] for _, ip, p in m} & relayed["c"])),
        ("ok", len({(ip, p) for m in got["i"] for _, ip, p in m} & relayed["i"])))

Q = src_pair()
qc, qi = peer(C, Q), peer(I, Q)
first = {}
for k, q in (("c", qc), ("i", qi)):
    q.send("getaddr")
    first[k] = q.collect_addr()
for k, q in (("c", qc), ("i", qi)):
    q.send("getaddr")
second = {"c": qc.collect_addr(), "i": qi.collect_addr()}


def flat(ms):
    return [(ip, p) for m in ms for _, ip, p in m]


compare("getaddr twice on one connection: addresses in both answers",
        ("ok", len(set(flat(first["c"])) & set(flat(second["c"])))),
        ("ok", len(set(flat(first["i"])) & set(flat(second["i"])))))
compare("getaddr: every addr message of the answer at most 1000",
        ("ok", all(len(m) <= 1000 for m in first["c"])), ("ok", all(len(m) <= 1000 for m in first["i"])))

# getaddr from an outbound connection made now is not answered either way: done above
for p in (fc, fi, qc, qi, R["c"], R["i"]):
    p.close()
stop_both()

# --- what the book holds after a clean stop ---------------------------------------------------
books = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
compare("peers.dat after a clean stop: readable", ("ok", books["c"]["state"] != "unreadable"),
        ("ok", books["i"]["state"] != "unreadable"))
size = {k: len(books[k]["addrs"]) for k in books}
print(f"# book: divid {size['c']}, irondivid {size['i']}", flush=True)
compare("getaddr from a new peer: share of the book", ("ok", share(len(flat(first["c"])), size["c"])),
        ("ok", share(len(flat(first["i"])), size["i"])))

for name, addrs, sent, _ in cases:
    c, i = kept_both(addrs, FEED)
    if len(addrs) > 10:
        compare(f"addr {name}: kept, how many", ("ok", c.count("kept")), ("ok", i.count("kept")))
    else:
        compare(f"addr {name}: kept", ("ok", c), ("ok", i))
c, i = kept_both(ANSWER, lc.ip, li.ip)
compare("an outbound peer's answer to getaddr: kept", ("ok", c), ("ok", i))


def age(book, ip, port, sent_at):
    t = book["addrs"].get((ip, port))
    if t is None:
        return None
    return round((t - sent_at) / 60)


SENT = TIMES[0][0] + 3600  # when the times were made
for (t, ip, port), what in zip(TIMES, TIME_NAMES):
    c, i = age(books["c"], ip, port, SENT), age(books["i"], ip, port, SENT)
    kc, ki = kept_both([(ip, port)], FEED)
    if c is None and kc == ["kept"]:
        c = i  # its place in divid's buckets was taken
    compare(f"addr time {what}: the time kept, minutes from now", ("ok", c), ("ok", i))
ip, port = ONE[0]
compare("addr again with another port: the port kept",
        ("ok", sorted(p for (a, p) in books["c"]["addrs"] if a == ip)),
        ("ok", sorted(p for (a, p) in books["i"]["addrs"] if a == ip)))

# --- peers.dat read at the next start -------------------------------------------------------------
start_both()


def ask(node):
    q = peer(node, src_pair())
    if q is None:
        return None
    q.send("getaddr")
    got = flat(q.collect_addr())
    q.close()
    return got


got = {"c": ask(C), "i": ask(I)}
compare("after a restart: getaddr from a new peer, share of the book read",
        ("ok", share(len(got["c"]), size["c"])), ("ok", share(len(got["i"]), size["i"])))
compare("after a restart: getaddr answer, all from the book",
        ("ok", set(got["c"]) <= set(books["c"]["addrs"])), ("ok", set(got["i"]) <= set(books["i"]["addrs"])))
stop_both()
again = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
compare("peers.dat after a second clean stop: the same addresses",
        ("ok", set(again["c"]["addrs"]) == set(books["c"]["addrs"])),
        ("ok", set(again["i"]["addrs"]) == set(books["i"]["addrs"])))

# --- 2500 addresses ---------------------------------------------------------------------------------
fresh_both("b")
start_both()
FEED = src_pair()
fc, fi = peer(C, FEED), peer(I, FEED)
MANY = public(2500)
now = int(time.time())
for chunk in (MANY[:1000], MANY[1000:2000], MANY[2000:]):
    for f in (fc, fi):
        f.send("addr", addr_payload(entries(chunk, now - 3600)))
    fc.pump(1)
    fi.pump(1)
fc.pump(2)
fi.pump(2)
qc, qi = peer(C, src_pair()), peer(I, src_pair())
first, second = {}, {}
for k, q in (("c", qc), ("i", qi)):
    q.send("getaddr")
    first[k] = q.collect_addr(10)
    q.send("getaddr")
    second[k] = q.collect_addr(10)
compare("2500 known: getaddr answer, addr messages", ("ok", len(first["c"])), ("ok", len(first["i"])))
compare("2500 known: every addr message at most 1000",
        ("ok", all(len(m) <= 1000 for m in first["c"])), ("ok", all(len(m) <= 1000 for m in first["i"])))
compare("2500 known: getaddr twice on one connection, addresses in both answers",
        ("ok", len(set(flat(first["c"])) & set(flat(second["c"])))),
        ("ok", len(set(flat(first["i"])) & set(flat(second["i"])))))
for p in (fc, fi, qc, qi):
    p.close()
stop_both()
books = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
size = {k: len(books[k]["addrs"]) for k in books}
print(f"# book of 2500: divid {size['c']}, irondivid {size['i']}", flush=True)


def kept_of_2500(n):
    # 2500 addresses from one source group fall in 64 of the 1024 new buckets,
    # 4096 places: about 1870 find a free one (addrman.cpp:20-26, :291-311)
    if n == 2500:
        return "all"
    return "about 1870 (bucket collisions)" if 1750 <= n <= 2000 else str(n)


compare("2500 known: addresses kept", ("ok", kept_of_2500(size["c"])), ("ok", kept_of_2500(size["i"])))
compare("2500 known: getaddr, share of the book", ("ok", share(len(flat(first["c"])), size["c"])),
        ("ok", share(len(flat(first["i"])), size["i"])))

# --- 10 addresses; peers.dat swapped, damaged, and an unclean stop -------------------------------------
fresh_both("c")
start_both()
FEED = src_pair()
fc, fi = peer(C, FEED), peer(I, FEED)
SMALL = public(10)
for f in (fc, fi):
    f.send("addr", addr_payload(entries(SMALL, int(time.time()) - 3600)))
fc.pump(2)
fi.pump(2)
qc, qi = peer(C, src_pair()), peer(I, src_pair())
first, second = {}, {}
for k, q in (("c", qc), ("i", qi)):
    q.send("getaddr")
    first[k] = q.collect_addr()
    q.send("getaddr")
    second[k] = q.collect_addr()
compare("10 known: getaddr answer, addresses", ("ok", len(flat(first["c"]))), ("ok", len(flat(first["i"]))))
compare("10 known: getaddr twice on one connection, addresses in both answers",
        ("ok", len(set(flat(first["c"])) & set(flat(second["c"])))),
        ("ok", len(set(flat(first["i"])) & set(flat(second["i"])))))
for p in (fc, fi, qc, qi):
    p.close()
stop_both()
own = {"c": open(C.peers_dat(), "rb").read(), "i": open(I.peers_dat(), "rb").read()}
own_count = {"c": len(read_peers(C.peers_dat())["addrs"]), "i": len(read_peers(I.peers_dat())["addrs"])}


def plant(node, content):
    with open(node.peers_dat(), "wb") as f:
        f.write(content)


def answer_count():
    start_both()
    out = {"c": ask(C), "i": ask(I)}
    stop_both()
    return {k: (len(v) if v is not None else "no connection") for k, v in out.items()}


# Each reads the other's file: as the writer reading its own
plant(C, own["i"])
plant(I, own["c"])
got = answer_count()
compare("divid's peers.dat read by irondivid: getaddr answer (divid: its own)",
        ("ok", 23 * own_count["c"] // 100), ("ok", got["i"]))
compare("irondivid's peers.dat read by divid: getaddr answer (irondivid: its own)",
        ("ok", got["c"]), ("ok", 23 * own_count["i"] // 100))
after = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
# each wrote back what it read: the other's addresses (the two books can differ
# by a bucket collision, so each is held against the file it was given)
compare("after reading the other's peers.dat and a clean stop: the file holds what was read",
        ("ok", len(after["c"]["addrs"]) == own_count["i"]), ("ok", len(after["i"]["addrs"]) == own_count["c"]))

for what, damage in (("truncated", lambda b: b[:len(b) // 2]), ("zero-length", lambda b: b""),
                     ("wrong checksum", lambda b: b[:-1] + bytes([b[-1] ^ 1]))):
    plant(C, damage(own["c"]))
    plant(I, damage(own["i"]))
    got = answer_count()
    compare(f"peers.dat {what}: getaddr answer after the start", ("ok", got["c"]), ("ok", got["i"]))
    after = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
    compare(f"peers.dat {what}: the file after a clean stop",
            ("ok", (after["c"]["state"] != "unreadable", len(after["c"]["addrs"]))),
            ("ok", (after["i"]["state"] != "unreadable", len(after["i"]["addrs"]))))

# An unclean stop between learning addresses and the dump (every 15 minutes, net.cpp:83, :1471)
plant(C, own["c"])
plant(I, own["i"])
start_both()
FEED = src_pair()
fc, fi = peer(C, FEED), peer(I, FEED)
LATE = public(10)
for f in (fc, fi):
    f.send("addr", addr_payload(entries(LATE, int(time.time()) - 3600)))
fc.pump(2)
fi.pump(2)
compare("before an unclean stop: getaddr answer", ("ok", len(ask(C) or [])), ("ok", len(ask(I) or [])))
for p in (fc, fi):
    p.close()
C.kill()
I.kill()
mid = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
compare("after a kill -9: peers.dat holds the addresses learnt since the start",
        ("ok", len(set(mid["c"]["addrs"]) & set(LATE))), ("ok", len(set(mid["i"]["addrs"]) & set(LATE))))
start_both(after_kill=True)
compare("after a kill -9 and a start: getaddr answer", ("ok", len(ask(C) or [])), ("ok", len(ask(I) or [])))
stop_both()

# --- options at start: -addnode, -connect, -seednode, -listen=0, -discover ---------------------------
# net.cpp:1214-1272 (-addnode), :1086-1103 (-connect, which still dials
# -seednode), :1071-1084 and main.cpp:556-557 (a -seednode peer is dropped
# after its addr), net.cpp:1703-1708 (-listen=0)

fresh_both("e")
UNROUTABLE = [(int(time.time()), "10.9.9.9", REGTEST_PORT)]


def outbound_case(name, option, connect=True, after=None):
    lc, li = listeners()
    start_both(own={"divid": [option.format(lc.target)], "irondivid": [option.format(li.target)]},
               connect=connect)
    oc, oi = accept_both(lc, li, 20)
    compare(f"{name}: the node connects", ("ok", oc is not None), ("ok", oi is not None))
    if oc and oi:
        oc.pump(4)
        oi.pump(4)
        compare(f"{name}: getaddr sent", ("ok", "getaddr" in oc.commands()), ("ok", "getaddr" in oi.commands()))
        for o in (oc, oi):
            o.send("addr", addr_payload(UNROUTABLE))
        compare(f"{name}: connected 5 s after its addr", ("ok", oc.stays(5)), ("ok", oi.stays(5)))
        if after:
            after(lc, li, oc, oi)
    for o in (oc, oi):
        if o:
            o.close()
    lc.close()
    li.close()
    stop_both()


def added_info(node, target):
    out = node.call("getaddednodeinfo", True)
    if out[0] != "ok":
        return out
    return ("ok", [(e.get("addednode") == target, e.get("connected"),
                    [a.get("connected") for a in e.get("addresses", [])]) for e in out[1]])


def after_addnode(lc, li, oc, oi):
    compare("-addnode: getaddednodeinfo true", added_info(C, lc.target), added_info(I, li.target))
    compare("-addnode: addnode remove", C.call("addnode", lc.target, "remove"), I.call("addnode", li.target, "remove"))
    compare("-addnode: connected after addnode remove", ("ok", oc.stays(3)), ("ok", oi.stays(3)))
    compare("-addnode: getaddednodeinfo true after the remove", added_info(C, lc.target), added_info(I, li.target))


outbound_case("-addnode", "addnode={}", after=after_addnode)
outbound_case("-connect", "connect={}", connect=False)
outbound_case("-seednode", "seednode={}")


start_both(extra=["listen=0"])
src = src_pair()
pc, pi = peer(C, src), peer(I, src)
compare("-listen=0: an inbound peer gets in", ("ok", pc is not None), ("ok", pi is not None))
lc, li = listeners()
C.call("addnode", lc.target, "onetry")
I.call("addnode", li.target, "onetry")
oc, oi = accept_both(lc, li, 15)
compare("-listen=0: addnode onetry connects", ("ok", oc is not None), ("ok", oi is not None))
if oc and oi:
    oc.pump(4)
    oi.pump(4)
    compare("-listen=0: getaddr sent to the outbound peer",
            ("ok", "getaddr" in oc.commands()), ("ok", "getaddr" in oi.commands()))
for o in (oc, oi, pc, pi):
    if o:
        o.close()
lc.close()
li.close()


def local_count(node):
    return len(node.rpc("getnetworkinfo").get("localaddresses", []))


compare("-listen=0: getnetworkinfo localaddresses", ("ok", local_count(C)), ("ok", local_count(I)))
stop_both()
for d in ("0", "1"):
    start_both(extra=[f"discover={d}"], external=False)
    # only how many: with -discover=1 these are the host's own addresses
    compare(f"-discover={d}, no -externalip: getnetworkinfo localaddresses (how many)",
            ("ok", local_count(C)), ("ok", local_count(I)))
    stop_both()

# --- addnode add / remove / onetry, getaddednodeinfo -------------------------------------------------
fresh_both("f")
start_both()
lc, li = listeners()
compare("addnode add", C.call("addnode", lc.target, "add"), I.call("addnode", li.target, "add"))
compare("getaddednodeinfo false",
        ("ok", [e.get("addednode") == lc.target for e in C.rpc("getaddednodeinfo", False)]),
        ("ok", [e.get("addednode") == li.target for e in I.rpc("getaddednodeinfo", False)]))
compare("addnode add again", C.call("addnode", lc.target, "add"), I.call("addnode", li.target, "add"))
# divid dials its added nodes every 2 minutes (net.cpp:1270), irondivid on its
# maintenance pass (docs/divid-differences.md P1): both within 130 s
conns = dict(zip(("c", "i"), accept_both(lc, li, 130)))
compare("addnode add: the node connects within 130 s", ("ok", conns["c"] is not None), ("ok", conns["i"] is not None))
if conns["c"] and conns["i"]:
    conns["c"].pump(3)
    conns["i"].pump(3)
    compare("addnode add: getaddr sent", ("ok", "getaddr" in conns["c"].commands()),
            ("ok", "getaddr" in conns["i"].commands()))
    compare("getaddednodeinfo true, connected", added_info(C, lc.target), added_info(I, li.target))
compare("addnode remove", C.call("addnode", lc.target, "remove"), I.call("addnode", li.target, "remove"))
if conns["c"] and conns["i"]:
    compare("addnode remove: the peer stays connected", ("ok", conns["c"].stays(3)), ("ok", conns["i"].stays(3)))
compare("addnode remove again", C.call("addnode", lc.target, "remove"), I.call("addnode", li.target, "remove"))
compare("getaddednodeinfo true after the remove", added_info(C, lc.target), added_info(I, li.target))
compare("getaddednodeinfo true, a node not added", C.call("getaddednodeinfo", True, lc.target),
        I.call("getaddednodeinfo", True, li.target))
for o in conns.values():
    if o:
        o.close()
lc.close()
li.close()
lc, li = listeners()
C.call("addnode", lc.target, "onetry")
I.call("addnode", li.target, "onetry")
oc, oi = accept_both(lc, li, 15)
compare("addnode onetry: connects", ("ok", oc is not None), ("ok", oi is not None))
compare("addnode onetry: getaddednodeinfo true", added_info(C, lc.target), added_info(I, li.target))
if oc and oi:
    for o in (oc, oi):
        o.close()
lc.close()
li.close()
stop_both()

# --- no local address: what divid keeps ----------------------------------------------------------------
fresh_both("g")
start_both(external=False)
compare("no -externalip: getnetworkinfo reachable networks", ("ok", reachable(C)), ("ok", reachable(I)))
FEED = src_pair()
fc, fi = peer(C, FEED), peer(I, FEED)
BARE = public(10)
for f in (fc, fi):
    f.send("addr", addr_payload(entries(BARE, int(time.time()) - 3600)))
fc.pump(2)
fi.pump(2)
for p in (fc, fi):
    p.close()
stop_both()
books = {"c": read_peers(C.peers_dat()), "i": read_peers(I.peers_dat())}
c, i = kept_both(BARE, FEED)
compare("no -externalip: addr of 10 public IPv4 addresses, kept", ("ok", c.count("kept")), ("ok", i.count("kept")))

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
