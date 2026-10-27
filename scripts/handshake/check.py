#!/usr/bin/env python3
"""The peer handshake and the messages a peer sends rarely, Divi Core divid and
irondivid compared case by case: the version/verack exchange and the version
message's variants, messages before the handshake, ping and pong, alert, dstx,
reject, bloom filter messages, an unknown command, and the message header
checks (magic, command, checksum, size).

Both nodes run on regtest with no wallet and no peer of their own. Raw peers
made here connect to each from their own loopback address (127.0.0.20 and up),
one address per case, and record what the node sends back, the peer's ban score
in getpeerinfo, and whether the connection stays open. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"
LISTEN_IP = "127.0.0.3"


# --- rows ------------------------------------------------------------------------------

# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
PARTIAL = ("divid sets the peer's version and services before it reads the rest (main.cpp:372-373), so a version "
           "that fails to parse after addrMe leaves them set; irondivid keeps nothing from a version that does "
           "not parse. Both send the same reject and keep the connection")
KNOWN = {
    "handshake: version: subver": (
        "each names itself: divid FormatSubVersion (clientversion.cpp:82-86) \"DIVI Core: 3.0.0.0\", irondivid "
        "\"/IronDivi:<version>/\" (crates/divi-network/src/constants.rs USER_AGENT; divid's ban outdated reads it, "
        "KNOWN in scripts/bans) [by design]",
        lambda c, i: c == "DIVI Core: 3.0.0.0" and i.startswith("/IronDivi:") and i.endswith("/")),
    "version with a 300-byte sub-version: getpeerinfo": (PARTIAL, lambda c, i: (
        c["version"] == 70920 and i == dict(c, version=0))),
    "version of 85 bytes (up to the nonce and part of the sub-version): getpeerinfo": (PARTIAL, lambda c, i: (
        c["version"] == 70920 and i == dict(c, version=0))),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def matches(shape, core, iron):
    try:
        return bool(shape(core, iron))
    except (KeyError, TypeError, AttributeError, IndexError):
        return False


def row(name, core, iron):
    global fails
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif matches(shape, core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note}"[:900], flush=True)


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {kind.__name__}: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"handshake{index}:{password}".encode()).decode()
        self.conf = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=handshake{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "disablewallet=1", "connect=127.0.0.2:1", "debug=net",
        ]
        os.makedirs(self.dir)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.conf) + "\n")
        self.proc = None

    def start(self):
        self.err = os.path.join(WORK, f"{self.name}.err")
        with open(os.path.join(WORK, f"{self.name}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} exited with {self.proc.returncode}: {self.log_tail()}")
            try:
                if self.call("getblockcount")[0] == "ok":
                    return
            except Exception:
                pass
            time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s: {self.log_tail()}")

    def log_path(self):
        return os.path.join(self.dir, "regtest", "debug.log") if os.path.exists(
            os.path.join(self.dir, "regtest", "debug.log")) else os.path.join(self.dir, "debug.log")

    def log_size(self):
        try:
            return os.path.getsize(self.log_path())
        except OSError:
            return 0

    def log_since(self, offset):
        try:
            with open(self.log_path(), "rb") as f:
                f.seek(offset)
                return f.read().decode(errors="replace")
        except OSError:
            return ""

    def log_tail(self):
        return " | ".join(self.log_since(max(0, self.log_size() - 2000)).splitlines()[-5:])

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

    def peer_info(self, src):
        """getpeerinfo's entry for the peer from `src`, or None"""
        for p in self.rpc("getpeerinfo"):
            if p.get("addr", "").rsplit(":", 1)[0] == src:
                return p
        return None

    def banned(self):
        """The banned addresses, from divid's text list or irondivid's array"""
        out = self.rpc("listbanned")
        if isinstance(out, dict):
            text = out.get("banned:", "")
            return sorted(line.rstrip(",").split("/")[0] for line in text.strip("[]\n").split("\n") if line)
        return sorted(b.get("address", "").split("/")[0] for b in out)


# --- the wire --------------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
EMPTY_TX = bytes.fromhex("01000000" "00" "00" "00000000")


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(command, payload=b"", magic=MAGIC, size=None, check=None, raw_command=None):
    cmd = raw_command if raw_command is not None else command.encode().ljust(12, b"\0")
    return (magic + cmd + struct.pack("<I", len(payload) if size is None else size)
            + (dsha(payload)[:4] if check is None else check) + payload)


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def varstr(b):
    return compact(len(b)) + b


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def read_varint(p, i):
    n = p[i]
    if n < 0xfd:
        return n, i + 1
    if n == 0xfd:
        return struct.unpack_from("<H", p, i + 1)[0], i + 3
    if n == 0xfe:
        return struct.unpack_from("<I", p, i + 1)[0], i + 5
    return struct.unpack_from("<Q", p, i + 1)[0], i + 9


def read_str(p, i):
    n, i = read_varint(p, i)
    return p[i:i + n].decode(errors="replace"), i + n


def addr_of(p, i):
    ip = socket.inet_ntoa(p[i + 20:i + 24]) if p[i + 8:i + 20] == bytes(10) + b"\xff\xff" else p[i + 8:i + 24].hex()
    return {"services": struct.unpack_from("<Q", p, i)[0], "ip": ip, "port": struct.unpack_from(">H", p, i + 24)[0]}


def parse_version(p):
    v = {"version": struct.unpack_from("<i", p, 0)[0], "services": struct.unpack_from("<Q", p, 4)[0],
         "time": struct.unpack_from("<q", p, 12)[0], "addr_recv": addr_of(p, 20), "addr_from": addr_of(p, 46),
         "nonce": struct.unpack_from("<Q", p, 72)[0]}
    v["subver"], i = read_str(p, 80)
    v["start_height"] = struct.unpack_from("<i", p, i)[0]
    v["relay"] = p[i + 4] if len(p) > i + 4 else None
    v["extra_bytes"] = len(p) - (i + 5)
    return v


def version_payload(src, port, version=70920, nonce=None, subver=b"/handshake:1/", height=0, relay=True,
                    services=1):
    p = (struct.pack("<iQq", version, services, int(time.time())) + netaddr(NODE_IP, port) + netaddr(src, 0)
         + struct.pack("<Q", secrets.randbits(63) | 2 if nonce is None else nonce) + varstr(subver)
         + struct.pack("<i", height))
    return p + (b"\x01" if relay else b"\x00")


def describe(command, payload, ping_nonce=None):
    """What a received message says, in a form both nodes can be compared by"""
    if command == "reject":
        try:
            what, i = read_str(payload, 0)
            code = payload[i]
            reason, i = read_str(payload, i + 1)
            return ["reject", what, code, reason, payload[i:][::-1].hex()]
        except (IndexError, struct.error):
            return ["reject", "unparsed", payload.hex()]
    if command == "pong":
        if ping_nonce is not None and len(payload) == 8:
            return ["pong", "same nonce" if struct.unpack("<Q", payload)[0] == ping_nonce else "other nonce"]
        return ["pong", len(payload)]
    if command == "sporkcount":
        return ["sporkcount", struct.unpack("<I", payload)[0] if len(payload) == 4 else payload.hex()]
    return [command]


class Peer:
    """A raw connection from `src` to a node's p2p port; `closed` once the node
    drops it (or refuses it)"""

    def __init__(self, node, src):
        self.node, self.src = node, src
        self.closed = False
        self.got = []  # (command, payload), every message read, in order
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.bind((src, 0))
        try:
            self.sock.connect((NODE_IP, node.p2p))
        except OSError:
            self.closed = True

    def send_raw(self, data):
        if self.closed:
            return
        try:
            self.sock.sendall(data)
        except OSError:
            self.closed = True

    def send(self, command, payload=b""):
        self.send_raw(message(command, payload))

    def recv(self, n, deadline):
        out = b""
        while len(out) < n:
            self.sock.settimeout(max(0.01, deadline - time.time()))
            part = self.sock.recv(n - len(out))
            if not part:
                raise EOFError
            out += part
        return out

    def pump(self, secs, answer_pings=True):
        """Read for `secs`; the messages read in that time, as (command, payload)"""
        new = []
        deadline = time.time() + secs
        buf_deadline = deadline
        while not self.closed and time.time() < deadline:
            try:
                head = self.recv(24, deadline)
                buf_deadline = time.time() + 5  # a message started is read to its end
                payload = self.recv(struct.unpack("<I", head[16:20])[0], buf_deadline)
            except socket.timeout:
                break
            except (OSError, EOFError):
                self.closed = True
                break
            command = head[4:16].rstrip(b"\0").decode(errors="replace")
            new.append((command, payload))
            if command == "ping" and answer_pings:
                self.send("pong", payload)
        self.got += new
        return new

    def handshake(self, **kw):
        """version and verack both ways; True once both came"""
        self.send("version", version_payload(self.src, self.node.p2p, **kw))
        deadline = time.time() + 10
        seen = set()
        while not self.closed and time.time() < deadline and not {"version", "verack"} <= seen:
            for command, _ in self.pump(0.5):
                seen.add(command)
                if command == "version":
                    self.send("verack")
        return {"version", "verack"} <= seen

    def is_open(self, secs=1.5):
        self.pump(secs)
        return not self.closed

    def close(self):
        self.sock.close()
        self.closed = True


# Commands a node sends on its own once a peer is up (sync, address and
# inventory traffic, pings); a case's reply is what is left
CHATTER = {"ping", "getheaders", "getblocks", "inv", "addr", "getaddr", "sporkcount", "mnget", "getsporks",
           "dseg", "mnvs", "ssc"}


def replies(msgs, ping_nonce=None):
    return [describe(c, p, ping_nonce) for c, p in msgs if c not in CHATTER]


# --- running a case on both nodes at once ---------------------------------------------

next_src = [20]


def new_src():
    next_src[0] += 1
    return f"127.0.0.{next_src[0]}"


def on_both(fn):
    """fn(node, src) run on divid and irondivid at the same time, with one new
    source address for both; (divid's result, irondivid's result)"""
    src = new_src()
    out = [None, None]
    errors = []

    def run(k, node):
        try:
            out[k] = fn(node, src)
        except Exception as e:  # reported as the row's value, so the run goes on
            errors.append(e)
            out[k] = f"error: {type(e).__name__}: {e}"

    threads = [threading.Thread(target=run, args=(k, n)) for k, n in enumerate((C, I))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out[0], out[1]


def banscore(node, src):
    p = node.peer_info(src)
    return None if p is None else p.get("banscore")


def case(name, fn):
    """One case: fn(node, src) -> dict of facts; one row per fact"""
    core, iron = on_both(fn)
    if isinstance(core, dict) and isinstance(iron, dict):
        for k in core.keys() | iron.keys():
            row(f"{name}: {k}", core.get(k, "<none>"), iron.get(k, "<none>"))
    else:
        row(name, core, iron)


def up_peer(node, src, **kw):
    """A peer past the handshake whose first messages have been read"""
    p = Peer(node, src)
    if not p.handshake(**kw):
        raise RuntimeError("no handshake")
    p.pump(2.0)
    return p


def after_handshake(send):
    """A case on a peer past the handshake: send(peer), then what came back,
    the ban score and whether the peer is still connected"""
    def fn(node, src):
        p = up_peer(node, src)
        send(p)
        got = p.pump(2.5)
        out = {"replies": replies(got), "connected": not p.closed, "banscore": banscore(node, src)}
        p.close()
        return out
    return fn


def before_handshake(send):
    """A case on a fresh connection that has sent nothing: send(peer), then what
    came back, the ban score and whether the connection stays open"""
    def fn(node, src):
        p = Peer(node, src)
        send(p)
        got = p.pump(2.5, answer_pings=False)
        out = {"replies": [describe(c, x) for c, x in got], "connected": not p.closed,
               "banscore": banscore(node, src)}
        p.close()
        return out
    return fn


# --- the run ---------------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
for n in (C, I):
    n.start()
print(f"# divid on {NODE_IP}:{C.p2p}, irondivid on {NODE_IP}:{I.p2p}; raw peers from 127.0.0.21 up", flush=True)


# The handshake as divid's inbound side does it (main.cpp:400-419): version,
# verack, sporkcount, sent as soon as the peer's version is read
def handshake_reply(node, src):
    p = Peer(node, src)
    p.send("version", version_payload(src, node.p2p))
    first = p.pump(3.0, answer_pings=False)
    out = {"commands before our verack (first 3 s)": [describe(c, x)[0] if c != "sporkcount" else
                                                      describe(c, x) for c, x in first]}
    v = next((parse_version(x) for c, x in first if c == "version"), None)
    if v:
        out["version: protocol"] = v["version"]
        out["version: services"] = v["services"]
        out["version: time within 10 s"] = abs(v["time"] - time.time()) < 10
        out["version: addr_recv (the peer as the node sees it)"] = v["addr_recv"]
        out["version: addr_from"] = dict(v["addr_from"], port="the node's p2p port" if v["addr_from"]["port"]
                                         == node.p2p else v["addr_from"]["port"])
        out["version: nonce above 1"] = v["nonce"] > 1
        out["version: start height"] = v["start_height"]
        out["version: relay"] = v["relay"]
        out["version: bytes after relay"] = v["extra_bytes"]
        out["version: subver"] = v["subver"]
    p.send("verack")
    after = p.pump(3.0)
    out["commands in the first 6 s, as a set"] = sorted({c for c, _ in first + after})
    info = node.peer_info(src) or {}
    for k in ("version", "subver", "startingheight", "banscore", "inbound", "services"):
        out[f"getpeerinfo {k}"] = info.get(k, "<none>")
    out["connected"] = not p.closed
    p.close()
    return out


case("handshake", handshake_reply)


def version_case(**kw):
    def fn(node, src):
        p = Peer(node, src)
        p.send("version", version_payload(src, node.p2p, **kw))
        got = p.pump(3.0)
        out = {"replies": [describe(c, x) for c, x in got if c not in CHATTER],
               "connected": not p.closed}
        info = node.peer_info(src)
        out["getpeerinfo"] = None if info is None else {k: info.get(k) for k in ("version", "subver",
                                                                                 "startingheight", "banscore")}
        p.close()
        out["listbanned has the peer"] = src in node.banned()
        if out["listbanned has the peer"]:
            q = Peer(node, src)
            out["the address again, with protocol 70920"] = q.handshake() and q.is_open()
            q.close()
            node.rpc("clearbanned")
        return out
    return fn


# DisconnectOldProtocol (Node.cpp:981-990) below ActiveProtocol() 70915
# (version.cpp:11-17, version.h:21), and the ban at main.cpp:374-378
case("version 70914 (below the minimum)", version_case(version=70914))
case("version 70915 (the minimum)", version_case(version=70915))
case("version 70920 with services 0", version_case(services=0))
case("version with start height 1000", version_case(height=1000))
case("version with relay 0", version_case(relay=False))
# A sub-version over 256 bytes: LIMITED_STRING throws after the version is set (main.cpp:383)
case("version with a 300-byte sub-version", version_case(subver=b"/" + b"x" * 298 + b"/"))
case("version with an empty sub-version", version_case(subver=b""))


def short_version(n):
    """A version message cut to its first n bytes"""
    def fn(node, src):
        p = Peer(node, src)
        p.send("version", version_payload(src, node.p2p)[:n])
        got = p.pump(3.0)
        info = node.peer_info(src)
        out = {"replies": [describe(c, x) for c, x in got if c not in CHATTER],
               "connected": not p.closed,
               "getpeerinfo": None if info is None else {k: info.get(k) for k in ("version", "subver",
                                                                                  "startingheight", "banscore")}}
        p.close()
        return out
    return fn


# The fields after addrMe are optional (main.cpp:380-391); a message shorter
# than addrMe throws "end of data", answered with reject malformed (:1040-1045)
case("version of 46 bytes (up to addr_recv)", short_version(46))
case("version of 85 bytes (up to the nonce and part of the sub-version)", short_version(85))
case("version of 10 bytes", short_version(10))


def second_version(node, src):
    p = up_peer(node, src)
    p.send("version", version_payload(src, node.p2p))
    got = p.pump(2.5)
    out = {"replies": replies(got), "connected": not p.closed, "banscore": banscore(node, src)}
    p.close()
    return out


# main.cpp:358-362: reject duplicate, Misbehaving 1
case("a second version", second_version)


# A version carrying the nonce of the node's own last version (Node.cpp:887-890,
# main.cpp:394-399): the node dials a raw listener, which reads the node's
# version; a peer then sends that nonce back to the node
def self_connection(node, src):
    port = PORT_BASE + 10 + (0 if node is C else 1)
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((LISTEN_IP, port))
    lsock.listen(1)
    lsock.settimeout(30)
    try:
        node.rpc("addnode", f"{LISTEN_IP}:{port}", "onetry")
        conn, _ = lsock.accept()
        conn.settimeout(10)
        head = b""
        deadline = time.time() + 10
        while len(head) < 24 and time.time() < deadline:
            head += conn.recv(24 - len(head))
        size = struct.unpack("<I", head[16:20])[0]
        body = b""
        while len(body) < size:
            body += conn.recv(size - len(body))
        nonce = parse_version(body)["nonce"]
        p = Peer(node, src)
        p.send("version", version_payload(src, node.p2p, nonce=nonce))
        got = p.pump(3.0)
        out = {"replies": [describe(c, x) for c, x in got if c not in CHATTER],
               "connected": not p.closed, "listbanned has the peer": src in node.banned()}
        p.close()
        conn.close()
        return out
    finally:
        lsock.close()


case("version with the node's own nonce", self_connection)


# --- before the handshake: Misbehaving 1, the message dropped (main.cpp:492-497) ----------

case("ping before version", before_handshake(lambda p: p.send("ping", struct.pack("<Q", 7))))
case("verack before version", before_handshake(lambda p: p.send("verack")))
case("an unknown command before version", before_handshake(lambda p: p.send("hstest")))


def ping_between(node, src):
    """After version, before verack: ping is answered (main.cpp:510-514 needs only the version)"""
    p = Peer(node, src)
    p.send("version", version_payload(src, node.p2p))
    p.pump(1.5, answer_pings=False)
    p.send("ping", struct.pack("<Q", 0x1122334455667788))
    got = p.pump(2.0, answer_pings=False)
    out = {"replies": [describe(c, x, 0x1122334455667788) for c, x in got if c not in CHATTER],
           "connected": not p.closed, "banscore": banscore(node, src)}
    p.close()
    return out


case("ping between version and verack", ping_between)


# --- ping and pong (Node.cpp:734-808) -----------------------------------------------------

def ping_case(payload):
    def fn(node, src):
        p = up_peer(node, src)
        p.send("ping", payload)
        got = p.pump(2.0)
        nonce = struct.unpack("<Q", payload)[0] if len(payload) == 8 else None
        out = {"replies": [describe(c, x, nonce) for c, x in got if c not in CHATTER],
               "connected": not p.closed, "banscore": banscore(node, src)}
        p.close()
        return out
    return fn


case("ping with a nonce", ping_case(struct.pack("<Q", 0x0102030405060708)))
case("ping with no nonce", ping_case(b""))
case("ping with 12 bytes", ping_case(struct.pack("<Q", 5) + b"\0\0\0\0"))


def pong_case(payload_of):
    """A peer that leaves the node's ping unanswered, then sends a pong made by
    payload_of(nonce): is the ping still outstanding (getpeerinfo pingwait)"""
    def fn(node, src):
        p = Peer(node, src)
        p.send("version", version_payload(src, node.p2p))
        nonce = None
        deadline = time.time() + 10
        seen = set()
        while not p.closed and time.time() < deadline and (nonce is None or "verack" not in seen):
            for c, x in p.pump(0.5, answer_pings=False):
                seen.add(c)
                if c == "version":
                    p.send("verack")
                elif c == "ping" and len(x) == 8:
                    nonce = struct.unpack("<Q", x)[0]
        if nonce is None:
            return {"ping from the node after the handshake": False}
        before = node.peer_info(src) or {}
        p.send("pong", payload_of(nonce))
        got = p.pump(1.5, answer_pings=False)
        after = node.peer_info(src) or {}
        out = {"ping from the node after the handshake": True,
               "pingwait before": "pingwait" in before,
               "pingwait after": "pingwait" in after,
               "pingtime after above 0": float(after.get("pingtime", 0) or 0) > 0,
               "replies": [describe(c, x) for c, x in got if c not in CHATTER],
               "connected": not p.closed, "banscore": after.get("banscore")}
        p.close()
        return out
    return fn


case("pong with the node's nonce", pong_case(lambda n: struct.pack("<Q", n)))
case("pong with another nonce", pong_case(lambda n: struct.pack("<Q", n ^ 1)))
case("pong with nonce 0", pong_case(lambda n: struct.pack("<Q", 0)))
case("pong of 4 bytes", pong_case(lambda n: struct.pack("<I", n & 0xffffffff)))
case("pong unasked", after_handshake(lambda p: p.send("pong", struct.pack("<Q", 99))))


# --- alert (main.cpp:870-890, alert.cpp:151-155) -------------------------------------------

def unsigned_alert():
    now = int(time.time())
    return (struct.pack("<iqqii", 1, now + 3600, now + 7200, 5000, 0) + compact(0) + struct.pack("<ii", 0, 999999)
            + compact(0) + struct.pack("<i", 1) + varstr(b"") + varstr(b"handshake test") + varstr(b""))


case("alert with a bad signature",
     after_handshake(lambda p: p.send("alert", varstr(unsigned_alert()) + varstr(bytes(70)))))
case("the same alert again",
     after_handshake(lambda p: [p.send("alert", varstr(unsigned_alert()) + varstr(bytes(70))) for _ in range(2)]))
case("alert, empty", after_handshake(lambda p: p.send("alert")))


# --- dstx: divid reads no transaction from it (main.cpp:705-718), so it checks
# an empty one: CheckTransaction 10 then bad-tx 100 (MempoolConsensus.cpp:276-277)

def dstx_case(payload):
    def fn(node, src):
        p = up_peer(node, src)
        p.send("dstx", payload)
        got = p.pump(3.0)
        out = {"replies": replies(got), "connected": not p.closed, "banscore": banscore(node, src),
               "listbanned has the peer": src in node.banned()}
        p.close()
        return out
    return fn


case("dstx, empty", dstx_case(b""))
case("dstx with a transaction", dstx_case(bytes.fromhex(
    "0100000001" + "11" * 32 + "00000000" + "00" + "ffffffff" + "01" + "e803000000000000" + "0151" + "00000000")))


# --- reject from a peer: only logged, with -debug (main.cpp:940-961) ------------------------

def reject_case(payload, logged):
    def fn(node, src):
        p = up_peer(node, src)
        mark = node.log_size()
        p.send("reject", payload)
        got = p.pump(2.5)
        time.sleep(0.5)
        out = {"replies": replies(got), "connected": not p.closed, "banscore": banscore(node, src)}
        if logged:
            out[f"debug.log names '{logged}'"] = logged in node.log_since(mark)
        p.close()
        return out
    return fn


case("reject of a tx", reject_case(varstr(b"tx") + bytes([0x10]) + varstr(b"handshake-reason-one") + bytes(range(32)),
                                   "handshake-reason-one"))
case("reject of a version", reject_case(varstr(b"version") + bytes([0x11]) + varstr(b"handshake-reason-two"),
                                        "handshake-reason-two"))
case("reject, empty", reject_case(b"", None))
case("reject of a tx with no hash", reject_case(varstr(b"tx") + bytes([0x10]) + varstr(b"handshake-reason-three"),
                                                None))


# --- unknown commands and messages divid has no handler for (main.cpp:963-966) ----------------

case("an unknown command", after_handshake(lambda p: p.send("hstest", b"abc")))
case("mempool", after_handshake(lambda p: p.send("mempool")))


# --- bloom filters, on by default (net.cpp:1722, main.cpp:892-939) --------------------------

case("filteradd before filterload", after_handshake(lambda p: p.send("filteradd", varstr(b"\x01" * 20))))
case("filterload over 36000 bytes",
     after_handshake(lambda p: p.send("filterload", varstr(bytes(36001)) + struct.pack("<IIB", 1, 0, 0))))
case("filterload, then filteradd of 521 bytes",
     after_handshake(lambda p: [p.send("filterload", varstr(bytes(100)) + struct.pack("<IIB", 1, 0, 0)),
                                p.send("filteradd", varstr(b"\x02" * 521))]))
case("filterclear", after_handshake(lambda p: p.send("filterclear")))


# --- the message header (main.cpp:967-1010 CheckNetworkMessageHeader; Node.cpp:55-70, :116-140) ---

def header_case(data):
    """A raw message, then a good ping: whether the ping is answered and the peer stays"""
    def fn(node, src):
        p = up_peer(node, src)
        p.send_raw(data)
        p.pump(1.0)
        p.send("ping", struct.pack("<Q", 0x5151))
        got = p.pump(2.0)
        out = {"replies": [describe(c, x, 0x5151) for c, x in got if c not in CHATTER],
               "connected": not p.closed, "banscore": banscore(node, src),
               "listbanned has the peer": src in node.banned()}
        p.close()
        return out
    return fn


PING = struct.pack("<Q", 0x4242)
case("message with a bad magic", header_case(message("ping", PING, magic=bytes([0xf9, 0xbe, 0xb4, 0xd9]))))
case("message with a bad checksum", header_case(message("ping", PING, check=b"\0\0\0\0")))
case("command with a control character", header_case(message("ping", PING, raw_command=b"pi\x01ng" + bytes(7))))
case("command with bytes after its NUL", header_case(message("ping", PING, raw_command=b"ping\0x" + bytes(6))))
case("command of 12 letters", header_case(message("ping", PING, raw_command=b"abcdefghijkl")))
case("size over 2 MiB (header only)", header_case(message("ping", b"", size=2 * 1024 * 1024 + 1)))
case("size over 32 MiB (header only)", header_case(message("ping", b"", size=0x02000001)))

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
for n in (C, I):
    try:
        n.call("stop")
    except Exception:
        pass
sys.exit(min(fails, 254))
