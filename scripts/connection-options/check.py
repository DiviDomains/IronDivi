#!/usr/bin/env python3
"""The start options that decide which peers a node talks to, Divi Core divid
and irondivid compared case by case: -whitelist and -whitebind (what a
whitelisted peer is spared), -bind several times and with -listen=0, -connect
alone, as 0, and with -addnode and -seednode, -maxconnections and the inbound
slots, -onlynet with a name divid does not know, -timeout, and the names divid
does not have (-maxuploadtarget, -peertimeout).

Each case starts both nodes on fresh regtest datadirs with the case's divi.conf
lines, not connected to each other. Raw peers made here connect from their own
loopback addresses (127.0.0.160 and up, one or more per case); raw targets
listen on 127.0.0.193 to .197 for the nodes to dial. Every row compares what each node
shows: getpeerinfo (count, inbound, whitelisted), getnetworkinfo connections,
listbanned, whether a port listens, which peers are told of a new block or a
transaction, and the start-up and refusal log lines. Each row prints PASS (same
as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import json
import os
import re
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
ONLY = os.environ.get("CONNECTION_OPTIONS_ONLY", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180
NODE_IP = "127.0.0.150"
SECOND_IP = "127.0.0.151"
# target k (1..5) listens on 127.0.0.(192 + k): divid dials an added node by its
# address and skips one whose IP it is connected to (net.cpp:1281-1285)
TARGET_IPS = {k: f"127.0.0.{192 + k}" for k in range(1, 6)}


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


ABORT = ("same error; divid then aborts (SIGABRT, exit -6) in the shutdown after this early InitError, "
         "irondivid exits 1 (as scripts/start-errors lists)")
BANLIST = ("divid answers {\"banned:\": \"<text list>\"} (rpcmisc.cpp:1023-1030), irondivid an array of "
           "{address, ...} (docs/rpc-parity-audit.md: listbanned; KNOWN in scripts/bans and scripts/net-replies) "
           "[by design]")
UNKNOWN = ("divid stores any option name and reads only those it knows, saying nothing of the rest "
           "(Settings.cpp:130-150); irondivid warns about each name divid does not know "
           "(bin/irondivid/src/main.rs option_warning) [by design]")


def same_errors(c, i):
    return (c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2])


def banlist_ips(c, i):
    """The addresses divid's text list and irondivid's array name, or None"""
    if c[0] != "ok" or i[0] != "ok" or not isinstance(c[1], dict) or not isinstance(i[1], list):
        return None
    text = c[1].get("banned:")
    if not isinstance(text, str) or not (text.startswith("[\n") and text.endswith("]")):
        return None
    core = sorted(line.rstrip(",") for line in text[2:-1].split("\n") if line)
    return core, sorted(b.get("address") for b in i[1])


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL. Rows of the same kind are added where they are made.
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}
CASE = ""


def row(name, core, iron, same, raw=None):
    global fails
    name = f"{CASE}: {name}" if CASE else name
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


def known(name, reason, shape):
    KNOWN[f"{CASE}: {name}"] = (reason, shape)


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:120]}\""
    if out[0] == "exit":
        return f"exit {out[1]} \"{out[2][:160]}\""
    if out[0] == "up":
        return "running"
    return json.dumps(out[1])[:200]


def compare(name, core, iron):
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
    print(f"FAIL   setup ({CASE}): {kind.__name__}: {value}"[:300], flush=True)
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
    def __init__(self, name, binary, index):
        self.name, self.binary, self.index = name, binary, index
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.alt = PORT_BASE + 4 + index        # a second -bind
        self.white = PORT_BASE + 6 + index      # -whitebind
        self.targets = [PORT_BASE + 10 + 10 * index + k for k in range(5)]
        self.proc = None
        self.starts = 0

    def roles(self):
        """Each of this node's ports by role, for the text of a row"""
        r = {self.p2p: "<p2p>", self.alt: "<alt>", self.white: "<white>"}
        r.update({p: f"<target{k + 1}>" for k, p in enumerate(self.targets)})
        return r

    def named(self, text):
        for port, role in sorted(self.roles().items(), key=lambda kv: -len(str(kv[0]))):
            text = text.replace(str(port), role)
        return text.replace(self.dir, "<datadir>")

    def start(self, lines):
        """('up',) once RPC answers, or ('exit', code, the first error line), on a fresh datadir"""
        self.starts += 1
        self.dir = os.path.join(WORK, f"{self.name}.{self.starts}")
        os.makedirs(self.dir)
        password = secrets.token_hex(16)
        user = f"co{self.index}"
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        conf = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={user}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "staking=0",
        ] + [self.ported(l) for l in lines]
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(conf) + "\n")
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        with open(self.err + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code, self.named(self.error_line()))
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.25)
        return ("exit", "none within %d s" % START_TIMEOUT, self.named(self.error_line()))

    def ported(self, line):
        """A case's conf line with the role names put back as this node's ports"""
        for port, role in self.roles().items():
            line = line.replace(role, str(port))
        return line

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

    def log(self):
        for p in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(p):
                with open(p, errors="replace") as f:
                    return f.read()
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


def case(name, lines, quiet=False):
    """Start both nodes for case `name` with `lines`; a row of the start. True when
    both run, so the case's rows follow. With `quiet`, the targets send no spork count"""
    global CASE
    for n in (C, I):
        n.stop()
    for t in TARGETS:
        t.reset()
        t.sporks = not quiet
    CASE = name
    if ONLY and ONLY not in name:
        return False
    out = C.start(lines), I.start(lines)
    compare("start", *out)
    return out[0] == out[1] == ("up",)


# --- raw p2p peers -----------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])


def message(command, payload=b""):
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + check + payload


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def version_payload(their_ip, their_port, my_ip, subver=b"Divi Core: 3.0.0.0", height=0):
    return (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(their_ip, their_port)
            + netaddr(my_ip, 0) + secrets.token_bytes(8) + compact(len(subver)) + subver
            + struct.pack("<i", height) + b"\x01")


class Wire:
    """One connection's messages: what came in, in order, and the replies to pings"""

    def __init__(self, sock):
        self.sock = sock
        self.commands = []
        self.invs = []          # (type, hash hex) of each inv item
        self.state = "up"

    def recv(self, n):
        out = b""
        while len(out) < n:
            part = self.sock.recv(n - len(out))
            if not part:
                raise EOFError
            out += part
        return out

    def read(self):
        head = self.recv(24)
        command = head[4:16].rstrip(b"\0").decode(errors="replace")
        size = struct.unpack("<I", head[16:20])[0]
        return command, self.recv(size)

    def send(self, command, payload=b""):
        try:
            self.sock.sendall(message(command, payload))
        except OSError:
            self.state = "closed"

    def note(self, command, payload):
        self.commands.append(command)
        if command == "ping":
            self.send("pong", payload)
        elif command == "inv":
            n, off = payload[0], 1
            if n == 0xfd:
                n, off = struct.unpack("<H", payload[1:3])[0], 3
            for k in range(n):
                item = payload[off + 36 * k: off + 36 * (k + 1)]
                self.invs.append((struct.unpack("<I", item[:4])[0], item[4:][::-1].hex()))

    def pump(self, secs=1.0):
        """Read for `secs`; 'closed' if the node drops the connection"""
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
            self.note(command, payload)
        return self.state

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.state = "closed"


class Peer(Wire):
    """A raw peer from its own loopback address to `port` of `node`. `state` is
    'up' after the handshake, 'refused' when the connection is refused or
    closed before it, or 'closed' once the node drops it."""

    def __init__(self, node, src, port=None, subver="Divi Core: 3.0.0.0"):
        self.node, self.src = node, src
        self.port_to = port or node.p2p
        self.subver = subver.encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        super().__init__(sock)
        self.state = self.connect()

    def connect(self):
        try:
            self.sock.settimeout(10)
            self.sock.bind((self.src, 0))
            self.sock.connect((NODE_IP if self.port_to != self.node.alt else SECOND_IP, self.port_to))
            self.port = self.sock.getsockname()[1]
            self.send("version", version_payload(NODE_IP, self.port_to, self.src, self.subver))
            got_version = got_verack = False
            deadline = time.time() + 10
            while not (got_version and got_verack) and time.time() < deadline:
                command, payload = self.read()
                if command == "version":
                    got_version = True
                    self.send("verack")
                elif command == "verack":
                    got_verack = True
                else:
                    self.note(command, payload)
            return "up" if got_version and got_verack else "refused"
        except (OSError, EOFError):
            return "refused"


class Target:
    """A raw peer that listens on its own address for a node to dial: it answers
    the version with its own, a verack and, as divid answers a peer that dialled
    it (main.cpp:417-420), a spork count of 0; records each connection's
    messages and answers pings"""

    def __init__(self, ip, port):
        self.ip, self.port = ip, port
        self.sporks = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(16)
        self.wires = []
        threading.Thread(target=self.accept, daemon=True).start()

    def reset(self):
        for w in self.wires:
            w.close()
        self.wires = []
        self.sporks = True

    def accept(self):
        while True:
            try:
                s, _ = self.sock.accept()
            except OSError:
                return
            w = Wire(s)
            w.handshake = False
            self.wires.append(w)
            threading.Thread(target=self.serve, args=(w,), daemon=True).start()

    def serve(self, w):
        w.sock.settimeout(None)
        try:
            while w.state == "up":
                command, payload = w.read()
                if command == "version":
                    w.send("version", version_payload(self.ip, self.port, self.ip))
                    w.send("verack")
                    if self.sporks:
                        w.send("sporkcount", struct.pack("<i", 0))
                elif command == "verack":
                    w.handshake = True
                w.note(command, payload)
        except (OSError, EOFError):
            w.state = "closed"

    def dialled(self):
        """Whether a node finished a handshake with this target"""
        return any(w.handshake for w in self.wires)

    def commands(self):
        return sorted({c for w in self.wires for c in w.commands})


def listens(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def peers(node):
    """getpeerinfo as sorted (address by role, inbound, whitelisted)"""
    out = []
    for p in node.rpc("getpeerinfo"):
        ip, port = p["addr"].rsplit(":", 1)
        where = node.named(f"{ip}:{port}") if int(port) in node.roles() else ip
        out.append((where, p.get("inbound"), p.get("whitelisted")))
    return sorted(out)


def peers_row(what, secs=0.0):
    time.sleep(secs)
    facts(f"getpeerinfo (address, inbound, whitelisted) {what}", peers)
    facts(f"getnetworkinfo connections {what}", lambda n: n.rpc("getnetworkinfo").get("connections"))


def connect_row(name, src, port_of=lambda n: n.p2p, **kw):
    pc, pi = Peer(C, src, port_of(C), **kw), Peer(I, src, port_of(I), **kw)
    compare(name, ("ok", pc.state), ("ok", pi.state))
    return pc, pi


def dropped_row(name, pc, pi, secs=3.0):
    compare(name, ("ok", pc.pump(secs)), ("ok", pi.pump(secs)))


def listbanned_row(what):
    name = f"listbanned ({what})"
    known(name, BANLIST, lambda c, i: (lambda ips: ips is not None and ips[0] == ips[1])(banlist_ips(c, i)))
    both(name, "listbanned")


# The log lines compared: divid's parameter interactions (net.cpp:1675-1716) and
# its refusals of a peer (net.cpp:757-762, main.cpp:1111-1113)
LOG_LINES = [
    ("-bind/-whitebind -> -listen=1", r"-bind or -whitebind set -> setting -listen=1"),
    ("-connect -> -dnsseed=0", r"-connect set -> setting -dnsseed=0"),
    ("-connect -> -listen=0", r"-connect set -> setting -listen=0"),
    ("-listen=0 -> -upnp=0", r"-listen=0 -> setting -upnp=0"),
    ("-listen=0 -> -discover=0", r"-listen=0 -> setting -discover=0"),
    ("dropped (full)", r"(?i)connection from \S+ dropped \(full\)"),
    ("dropped (banned)", r"(?i)connection from \S+ dropped \(banned\)"),
    ("not punishing whitelisted", r"not punishing whitelisted peer"),
]


def log_row(what="the log lines"):
    facts(what, lambda n: [tag for tag, pattern in LOG_LINES if re.search(pattern, n.log())])


# An addr message of 1001 addresses costs 20 (main.cpp:528-531); five make the
# default -banscore of 100. The addresses are loopback ones, never dialled off the host.
BIG_ADDR = compact(1001) + b"".join(struct.pack("<I", int(time.time())) + netaddr(f"127.1.{k // 250}.{k % 250 + 1}", 1)
                                    for k in range(1001))


def misbehave(pc, pi, count=5):
    for _ in range(count):
        for p in (pc, pi):
            p.send("addr", BIG_ADDR)


def told(wire, kind, hexhash, secs):
    """Whether `wire` is told of `hexhash` (inv type `kind`) within `secs`"""
    deadline = time.time() + secs
    while time.time() < deadline:
        if (kind, hexhash) in wire.invs:
            return True
        if isinstance(wire, Peer):
            wire.pump(0.25)
        else:
            time.sleep(0.25)
    return (kind, hexhash) in wire.invs


# --- start -----------------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
TARGETS = [Target(TARGET_IPS[k + 1], p) for n in (C, I) for k, p in enumerate(n.targets)]
T = {n.name: dict(zip(range(1, 6), TARGETS[5 * k: 5 * k + 5])) for k, n in enumerate((C, I))}


def target_row(what, k, secs=10.0):
    """Whether each node dialled its target k within `secs`"""
    wait_for(lambda: T["divid"][k].dialled() and T["irondivid"][k].dialled(), secs)
    compare(what, ("ok", T["divid"][k].dialled()), ("ok", T["irondivid"][k].dialled()))


BIND = f"bind={NODE_IP}:<p2p>"

# --- defaults ------------------------------------------------------------------------------
if case("defaults (-bind only)", [BIND]):
    facts("the p2p port listens", lambda n: listens(NODE_IP, n.p2p))
    peers_row("at start", 3.0)
    p = connect_row("raw peer from 127.0.0.160", "127.0.0.160")
    peers_row("with the raw peer", 1.0)
    log_row()
    for x in p:
        x.close()

# --- -whitelist (net.cpp:742, :760; main.cpp:794-799, :1111-1113) ----------------------------
WL = [BIND, "whitelist=127.0.0.161/32", "whitelist=127.0.0.164/30"]
if case("-whitelist", WL):
    a = connect_row("raw peer from 127.0.0.161 (whitelisted)", "127.0.0.161")
    b = connect_row("raw peer from 127.0.0.162 (not whitelisted)", "127.0.0.162")
    c = connect_row("raw peer from 127.0.0.165 (in 127.0.0.164/30)", "127.0.0.165")
    peers_row("with the three raw peers", 1.0)
    misbehave(*a)
    misbehave(*b)
    dropped_row("the whitelisted peer after 5 addr messages of 1001", *a)
    dropped_row("the other peer after 5 addr messages of 1001", *b)
    listbanned_row("after the misbehaviour")
    connect_row("raw peer from 127.0.0.162 again (banned)", "127.0.0.162")
    connect_row("raw peer from 127.0.0.161 again", "127.0.0.161")
    # ban outdated bans each peer older than divid's version, whitelisted or not
    # (rpcnet.cpp, net.cpp:359-376); a whitelisted one still gets in (net.cpp:760)
    old_w = connect_row("raw peer 'Divi Core: 2.4.0.0' from 127.0.0.166 (whitelisted)", "127.0.0.166",
                        subver="Divi Core: 2.4.0.0")
    old_n = connect_row("raw peer 'Divi Core: 2.4.0.0' from 127.0.0.163", "127.0.0.163", subver="Divi Core: 2.4.0.0")
    norm = lambda out: (out[0], sorted(re.sub(r":\d+$", "", x) for x in out[1]["Banned"])) \
        if out[0] == "ok" and isinstance(out[1], dict) and isinstance(out[1].get("Banned"), list) else out
    compare("ban outdated", norm(C.call("ban", "outdated")), norm(I.call("ban", "outdated")))
    dropped_row("the whitelisted 2.4.0.0 peer after ban outdated", *old_w)
    dropped_row("the other 2.4.0.0 peer after ban outdated", *old_n)
    listbanned_row("after ban outdated")
    connect_row("raw peer from 127.0.0.166 again (whitelisted, banned)", "127.0.0.166")
    connect_row("raw peer from 127.0.0.163 again (banned)", "127.0.0.163")
    log_row()
    for x in a + b + c:
        x.close()

for bad in ("127.0.0.1/33", "not-a-net"):
    KNOWN[f"-whitelist={bad}: start"] = (ABORT, same_errors)
    case(f"-whitelist={bad}", [BIND, f"whitelist={bad}"])

# --- -whitebind (net.cpp:1808-1823, :1379) ----------------------------------------------------
WB = f"whitebind={NODE_IP}:<white>"
if case("-whitebind alone", [WB]):
    facts("the p2p port listens", lambda n: listens(NODE_IP, n.p2p))
    facts("the -whitebind port listens", lambda n: listens(NODE_IP, n.white))
    w = connect_row("raw peer from 127.0.0.167 to the -whitebind port", "127.0.0.167", lambda n: n.white)
    peers_row("with the raw peer", 1.0)
    log_row()
    for x in w:
        x.close()
if case("-whitebind with -bind", [BIND, WB]):
    p = connect_row("raw peer from 127.0.0.168 to the -bind port", "127.0.0.168")
    w = connect_row("raw peer from 127.0.0.169 to the -whitebind port", "127.0.0.169", lambda n: n.white)
    peers_row("with both raw peers", 1.0)
    for x in p + w:
        x.close()
KNOWN["-whitebind without a port: start"] = (ABORT, same_errors)
case("-whitebind without a port", [BIND, f"whitebind={NODE_IP}"])

# --- -bind several times, and with -listen=0 (net.cpp:1803-1828) --------------------------------
if case("-bind twice", [BIND, f"bind={SECOND_IP}:<alt>"]):
    facts("the first -bind listens", lambda n: listens(NODE_IP, n.p2p))
    facts("the second -bind listens", lambda n: listens(SECOND_IP, n.alt))
    a = connect_row("raw peer from 127.0.0.170 to the first", "127.0.0.170")
    b = connect_row("raw peer from 127.0.0.171 to the second", "127.0.0.171", lambda n: n.alt)
    peers_row("with both raw peers", 1.0)
    for x in a + b:
        x.close()
if case("-bind with -listen=0", [BIND, f"bind={SECOND_IP}:<alt>", "listen=0"]):
    facts("the first -bind listens", lambda n: listens(NODE_IP, n.p2p))
    facts("the second -bind listens", lambda n: listens(SECOND_IP, n.alt))
    facts("getnetworkinfo localaddresses", lambda n: n.rpc("getnetworkinfo").get("localaddresses"))
    log_row()

# --- -connect (net.cpp:1086-1105, :1682-1688) -----------------------------------------------------
if case("-connect", [f"connect={TARGET_IPS[1]}:<target1>"]):
    target_row("the -connect peer is dialled", 1)
    facts("the p2p port listens", lambda n: listens(NODE_IP, n.p2p))
    peers_row("", 2.0)
    time.sleep(4.0)
    compare("what the -connect peer was sent (as a set)",
            ("ok", T["divid"][1].commands()), ("ok", T["irondivid"][1].commands()))
    log_row()
# divid sends a peer it dialled nothing past the handshake until that peer has
# sent its spork count (CanSendMessagesToPeer, Node.cpp:1024-1036)
QUIET = ("divid sends a peer it dialled nothing after the handshake, no ping, getblocks or inv, until the peer "
         "has sent its spork count and that many sporks (CNode::CanSendMessagesToPeer, Node.cpp:1024-1036; "
         "main.cpp:1296-1320); irondivid has no such wait. It is the handshake's, not a connection option's: "
         "left to the handshake work (B5) and listed in STATUS-connection-options.md")
if case("-connect to a peer that sends no spork count", [f"connect={TARGET_IPS[1]}:<target1>"], quiet=True):
    target_row("the -connect peer is dialled", 1)
    time.sleep(6.0)
    known("what the -connect peer was sent (as a set)", QUIET,
          lambda c, i: set(c[1]) == {"getaddr", "verack", "version"} and set(i[1]) > set(c[1]))
    compare("what the -connect peer was sent (as a set)",
            ("ok", T["divid"][1].commands()), ("ok", T["irondivid"][1].commands()))
    hashes = {}
    for n in (C, I):
        n.rpc("setgenerate", 1)
        hashes[n.name] = n.rpc("getbestblockhash")
    tw = [next((w for w in T[n][1].wires if w.handshake), None) for n in ("divid", "irondivid")]
    known("the -connect peer is told of a new block", QUIET, pair(("ok", False), ("ok", True)))
    compare("the -connect peer is told of a new block",
            ("ok", tw[0] is not None and told(tw[0], 2, hashes["divid"], 6)),
            ("ok", tw[1] is not None and told(tw[1], 2, hashes["irondivid"], 6)))

for value in ("0", "noconnect"):
    line = "noconnect=1" if value == "noconnect" else f"connect={value}"
    if case(f"-{line.split('=')[0] if value == 'noconnect' else line} with -addnode",
            [line, f"addnode={TARGET_IPS[2]}:<target2>"]):
        time.sleep(5.0)
        peers_row("after 5 s")
        compare("the -addnode peer is dialled", ("ok", T["divid"][2].dialled()), ("ok", T["irondivid"][2].dialled()))
        facts("the p2p port listens", lambda n: listens(NODE_IP, n.p2p))
        log_row()

# --- -connect with -addnode and -seednode, and -maxconnections (net.cpp:1090-1105, :1214-1236,
# :1071-1084; no outbound limit since divid's f8c0d2e67) ---------------------------------------
TRIO = [f"connect={TARGET_IPS[1]}:<target1>", f"addnode={TARGET_IPS[2]}:<target2>", f"seednode={TARGET_IPS[3]}:<target3>"]
for setting in ([], ["maxconnections=1"], ["maxconnections=0"]):
    label = " ".join("-" + s for s in setting) or "default -maxconnections"
    if case(f"-connect, -addnode and -seednode ({label})", TRIO + setting):
        target_row("the -connect peer is dialled", 1)
        target_row("the -addnode peer is dialled", 2)
        target_row("the -seednode peer is dialled", 3)
        peers_row("", 2.0)

# --- -addnode alone with -maxconnections (net.cpp:1214-1236): every added node is dialled
for setting in (["maxconnections=1"], ["maxconnections=0"]):
    if case(f"-addnode twice ({' '.join('-' + s for s in setting)})",
            [BIND, f"addnode={TARGET_IPS[4]}:<target4>", f"addnode={TARGET_IPS[5]}:<target5>"] + setting):
        target_row("the first -addnode peer is dialled", 4)
        target_row("the second -addnode peer is dialled", 5)
        peers_row("", 2.0)

# --- the inbound slots: -maxconnections less 16 (net.cpp:757, :1727-1728) -------------------------
for k, (value, srcs) in enumerate((("17", 2), ("16", 1), ("0", 1), ("-1", 1), ("", 1), ("abc", 1))):
    if case(f"-maxconnections={value} inbound", [BIND, f"maxconnections={value}", "debug=net"]):
        got = []
        for j in range(srcs):
            src = f"127.0.0.{172 + 2 * k + j}"
            got.append(connect_row(f"raw peer {j + 1} from {src}", src))
        peers_row("with the raw peers", 1.0)
        log_row()
        for p in got:
            for x in p:
                x.close()
if case("-maxconnections=16 inbound, no -debug=net", [BIND, "maxconnections=16"]):
    p = connect_row("raw peer from 127.0.0.184", "127.0.0.184")
    log_row()
if case("-maxconnections=16 with the peer whitelisted", [BIND, "maxconnections=16", "whitelist=127.0.0.185/32"]):
    connect_row("raw peer from 127.0.0.185 (whitelisted)", "127.0.0.185")

# --- -onlynet with a name divid does not know (net.cpp:1734-1741) ---------------------------------
KNOWN["-onlynet=bogus: start"] = (ABORT, same_errors)
case("-onlynet=bogus", [BIND, "onlynet=bogus"])

# --- -timeout (net.cpp:1719, netbase.cpp:51-54) ----------------------------------------------------
for value in ("1", "0", "-5", "abc", "100000"):
    if case(f"-timeout={value}", [f"timeout={value}", f"connect={TARGET_IPS[1]}:<target1>"]):
        target_row("the -connect peer is dialled", 1)

# --- names divid does not have ---------------------------------------------------------------------
for name, value in (("maxuploadtarget", "100"), ("peertimeout", "5")):
    if case(f"-{name}={value}", [BIND, f"{name}={value}"]):
        known("the log names the option", UNKNOWN, pair(("ok", False), ("ok", True)))
        facts("the log names the option", lambda n: f"-{name}" in n.log())
        p = connect_row("raw peer from 127.0.0.186", "127.0.0.186")
        for x in p:
            x.close()

# --- which peers are told of a new block (init.cpp:117, net.cpp:1491-1497): every peer whose
# starting height less 2000 is below the new height, whitelisted or not, inbound or outbound -----
if case("block relay", [BIND, "whitelist=127.0.0.188/32", "listen=1", f"connect={TARGET_IPS[1]}:<target1>"]):
    target_row("the -connect peer is dialled", 1)
    for n in (C, I):
        n.rpc("setgenerate", 1)
    plain = connect_row("raw peer from 127.0.0.187", "127.0.0.187")
    white = connect_row("raw peer from 127.0.0.188 (whitelisted)", "127.0.0.188")
    for p in plain + white:
        p.pump(1.0)
    hashes = {}
    for n in (C, I):
        n.rpc("setgenerate", 1)
        hashes[n.name] = n.rpc("getbestblockhash")
    compare("the plain inbound peer is told of the new block",
            ("ok", told(plain[0], 2, hashes["divid"], 6)), ("ok", told(plain[1], 2, hashes["irondivid"], 6)))
    compare("the whitelisted inbound peer is told of the new block",
            ("ok", told(white[0], 2, hashes["divid"], 6)), ("ok", told(white[1], 2, hashes["irondivid"], 6)))
    tw = [next((w for w in T[n][1].wires if w.handshake), None) for n in ("divid", "irondivid")]
    compare("the -connect peer is told of the new block",
            ("ok", tw[0] is not None and told(tw[0], 2, hashes["divid"], 6)),
            ("ok", tw[1] is not None and told(tw[1], 2, hashes["irondivid"], 6)))
    for p in plain + white:
        p.close()

# --- a transaction a whitelisted peer sends again is relayed again (main.cpp:794-799) ----------
if case("transaction relay", [BIND, "whitelist=127.0.0.189/32"]):
    raw, txid = {}, {}
    for n in (C, I):
        n.rpc("setgenerate", 25)
        txid[n.name] = n.rpc("sendtoaddress", n.rpc("getnewaddress"), 1)
        raw[n.name] = n.rpc("getrawtransaction", txid[n.name])
    listener = connect_row("raw peer from 127.0.0.191 (listening)", "127.0.0.191")
    for p in listener:
        p.pump(2.0)
    other = connect_row("raw peer from 127.0.0.192 (not whitelisted)", "127.0.0.192")
    for p, n in zip(other, ("divid", "irondivid")):
        p.send("tx", bytes.fromhex(raw[n]))
    compare("the listening peer is told of the transaction the other peer sent again",
            ("ok", told(listener[0], 1, txid["divid"], 5)), ("ok", told(listener[1], 1, txid["irondivid"], 5)))
    white = connect_row("raw peer from 127.0.0.189 (whitelisted)", "127.0.0.189")
    for p, n in zip(white, ("divid", "irondivid")):
        p.send("tx", bytes.fromhex(raw[n]))
    compare("the listening peer is told of the transaction the whitelisted peer sent again",
            ("ok", told(listener[0], 1, txid["divid"], 8)), ("ok", told(listener[1], 1, txid["irondivid"], 8)))
    for p in listener + other + white:
        p.close()

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
