#!/usr/bin/env python3
"""When does a node drop a peer that misbehaves in time: divid and irondivid side by side.

Divi Core checks every peer on each pass of its socket thread (CNode::CheckForInnactivity,
Node.cpp:812-834, called from net.cpp:830): from 60 s after the connection, a peer that has
sent nothing or been sent nothing is dropped; then a peer is dropped 20 minutes after the
last data sent to it, 20 minutes after the last data received from it, or 20 minutes after
a ping it has not answered. Both nodes run at once, each with these raw peers:

  - dialled, never sends sporks, talks every 30 s (an unasked pong, which gets no answer);
  - dialled, sends sporkcount 0, then goes silent;
  - dialled, never sends anything (not even a version);
  - dialled it, answers every ping (the control);
  - dialled it, goes silent after the handshake;
  - dialled it, talks every 30 s but never answers a ping;
  - dialled it, sends nothing;
  - dialled it, sends a ping every 10 s but never a version;
  - dialled, and dialled it, the peer's version only at 45 s (then a well-behaved peer);
  - dialled, and dialled it, half a message and then nothing: half a version at 5 s, or half an
    inv at 60 s after a handshake.

Each row is when the node closed the connection, in seconds after it was opened, or that it
was still up after WATCH seconds; the two count as the same within 10 s. PASS (as divid),
KNOWN (README.md) or FAIL; exit code = FAILs. Started by run.sh, which owns the work
directory and stops the nodes. PEER_TIMEOUTS_WATCH=<s> shortens the watch (default 1500).
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
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
WATCH = int(os.environ.get("PEER_TIMEOUTS_WATCH", "1500"))
SLACK = 10
MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
AGENT = b"/peer-timeouts:1/"
NODE_NETWORK = 1

KNOWN = {}
fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def read_message(sock):
    head = b""
    while len(head) < 24:
        part = sock.recv(24 - len(head))
        if not part:
            raise EOFError
        head += part
    size = struct.unpack("<I", head[16:20])[0]
    payload = b""
    while len(payload) < size:
        part = sock.recv(size - len(payload))
        if not part:
            raise EOFError
        payload += part
    return head[4:16].rstrip(b"\0").decode(), payload


def netaddr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(HOST) + struct.pack(">H", port)


def varint(n):
    return bytes([n]) if n < 0xfd else b"\xfd" + struct.pack("<H", n)


def version_payload(port, services, height):
    return (struct.pack("<iQq", 70920, services, int(time.time())) + netaddr(port) + netaddr(0)
            + secrets.token_bytes(8) + varint(len(AGENT)) + AGENT + struct.pack("<i", height) + b"\x01")


class Peer:
    """A raw peer on `sock`. `dialled`: the node dialled it (it answers the node's version);
    otherwise it sends its version first. `handshake`: it does the handshake at all; `pre_ping`:
    without a version, a ping every 10 s; `sporks`: sporkcount 0 after the handshake; `pong`:
    it answers pings; `talk`: an unasked pong every 30 s; `version_at`: its version only that many
    seconds after the connection opened; `half_at`: that many seconds after the connection opened, half a
    message (its header names 100 bytes of payload, 40 follow: a version when there was no handshake,
    else an inv), and nothing more after it"""

    def __init__(self, name, sock, port, dialled, handshake=True, pre_ping=False, sporks=False, pong=False,
                 talk=False, version_at=0, half_at=None):
        self.name, self.sock, self.port, self.dialled = name, sock, port, dialled
        self.version_at, self.half_at, self.stalled = version_at, half_at, False
        self.handshake, self.pre_ping, self.sporks, self.pong, self.talk = handshake, pre_ping, sporks, pong, talk
        self.opened, self.closed, self.log = time.time(), None, []
        self.lock = threading.Lock()
        threading.Thread(target=self.read, daemon=True).start()
        threading.Thread(target=self.speak, daemon=True).start()

    def send_half(self):
        """A header naming 100 bytes of payload, then 40 of them"""
        command = "inv" if self.handshake else "version"
        payload = secrets.token_bytes(100)
        whole = MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", 100) + sha256d(payload)[:4] + payload
        with self.lock:
            self.stalled = True
            try:
                self.sock.sendall(whole[:24 + 40])
            except OSError:
                pass

    def send(self, command, payload=b""):
        if self.stalled:
            return
        with self.lock:
            try:
                self.sock.sendall(message(command, payload))
            except OSError:
                pass

    def speak(self):
        if self.handshake and not self.dialled:
            time.sleep(self.version_at)
            self.send("version", version_payload(self.port, NODE_NETWORK, 0))
        k = 0
        while self.closed is None:
            time.sleep(1)
            k += 1
            if self.half_at is not None and k == self.half_at:
                self.send_half()
            if self.pre_ping and k % 10 == 0:
                self.send("ping", struct.pack("<Q", k))
            if self.talk and k % 30 == 0:
                self.send("pong", secrets.token_bytes(8))

    def read(self):
        try:
            while True:
                command, payload = read_message(self.sock)
                self.log.append((round(time.time() - self.opened, 1), command))
                if command == "version" and self.handshake:
                    if self.dialled:
                        time.sleep(max(0, self.opened + self.version_at - time.time()))
                        self.send("version", version_payload(self.port, NODE_NETWORK, 0))
                    self.send("verack")
                    if self.sporks:
                        self.send("sporkcount", struct.pack("<i", 0))
                elif command == "ping" and self.pong:
                    self.send("pong", payload)
        except (EOFError, ConnectionError, OSError):
            pass
        self.closed = time.time()

    def outcome(self):
        return "up" if self.closed is None else round(self.closed - self.opened)

    def close(self):
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
        time.sleep(0.2)
    return False


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"pt{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=pt{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}", "dnsseed=0", "staking=0", "txindex=1",
        ]
        self.proc = None

    def start(self, extra=()):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def rpc(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                text = r.read()
        except urllib.error.HTTPError as e:
            text = e.read() or b"{}"
        reply = json.loads(text)
        if reply.get("error"):
            raise RuntimeError(f"{self.name} {method}: {reply['error']}")
        return reply["result"]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                self.rpc("getblockcount")
                return True
            except Exception:
                time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.rpc("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


class Listener:
    """Where the node is told to dial; the first connection becomes a Peer with `kind`"""

    def __init__(self, port, name, **kind):
        self.port, self.name, self.kind, self.peer = port, name, kind, None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, port))
        self.sock.listen(16)
        self.target = f"{HOST}:{port}"
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        try:
            s, _ = self.sock.accept()
        except OSError:
            return
        self.peer = Peer(self.name, s, self.port, True, **self.kind)

    def close(self):
        self.sock.close()


def start_mining(node):
    node.start()
    if not node.wait_ready():
        raise RuntimeError(f"{node.name} did not start")
    node.rpc("setgenerate", 5)
    if not wait_for(lambda: node.rpc("getblockcount") >= 5, 60):
        raise RuntimeError(f"{node.name} did not make five blocks")
    node.stop()


DIALLED = [
    ("dialled, no sporks, talks every 30 s", dict(talk=True)),
    ("dialled, sporkcount 0, then silent", dict(sporks=True)),
    ("dialled, sends nothing", dict(handshake=False)),
    ("dialled, answers with its version at 45 s", dict(version_at=45, sporks=True, pong=True)),
    ("dialled, half a version at 5 s, then nothing", dict(handshake=False, half_at=5)),
    ("dialled, sporkcount 0, half an inv at 60 s, then nothing", dict(sporks=True, pong=True, half_at=60)),
]
INBOUND = [
    ("dialled it, answers pings (control)", dict(pong=True)),
    ("dialled it, silent after the handshake", dict()),
    ("dialled it, talks every 30 s, never answers a ping", dict(talk=True)),
    ("dialled it, sends nothing", dict(handshake=False)),
    ("dialled it, a ping every 10 s, no version", dict(handshake=False, pre_ping=True)),
    ("dialled it, its version at 45 s", dict(version_at=45, pong=True)),
    ("dialled it, half a version at 5 s, then nothing", dict(handshake=False, half_at=5)),
    ("dialled it, half an inv at 60 s, then nothing", dict(pong=True, half_at=60)),
]


def setup(node, first_port):
    ls = [Listener(first_port + k, name, **kind) for k, (name, kind) in enumerate(DIALLED)]
    node.start([f"connect={l.target}" for l in ls] + ["listen=1"])
    if not node.wait_ready():
        raise RuntimeError(f"{node.name} did not start")
    inbound = []
    for name, kind in INBOUND:
        s = socket.create_connection((HOST, node.p2p), timeout=10)
        s.settimeout(None)
        inbound.append(Peer(name, s, node.p2p, False, **kind))
    return ls, inbound


NODES = [Node("divid", DIVID, 0), Node("irondivid", IRONDIVID, 1)]
threads = [threading.Thread(target=start_mining, args=(n,)) for n in NODES]
for t in threads:
    t.start()
for t in threads:
    t.join()
if not all(n.proc.returncode is not None for n in NODES):
    raise RuntimeError("a node did not stop after mining")
print(f"# both nodes up; watching {WATCH} s", flush=True)
sides = {n.name: setup(n, PORT_BASE + 4 + len(DIALLED) * k) for k, n in enumerate(NODES)}
time.sleep(WATCH)

def peers_of(name):
    ls, inbound = sides[name]
    return {l.name: l.peer for l in ls} | {p.name: p for p in inbound}

core, iron = peers_of("divid"), peers_of("irondivid")
for name, _ in DIALLED + INBOUND:
    c = core[name].outcome() if core[name] else "never dialled"
    i = iron[name].outcome() if iron[name] else "never dialled"
    same = c == i or (isinstance(c, int) and isinstance(i, int) and abs(c - i) <= SLACK)
    row(name, c if isinstance(c, str) else f"closed at {c} s", i if isinstance(i, str) else f"closed at {i} s", same)
    if os.environ.get("PEER_TIMEOUTS_TRACE"):
        for side, p in (("divid", core[name]), ("irondivid", iron[name])):
            if p:
                print(f"#   {side}: " + " ".join(f"{c}@{t}" for t, c in p.log), flush=True)
for n in NODES:
    n.stop()
print(f"# PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}")
print(f"FAILS {fails}")
sys.exit(min(fails, 254))
