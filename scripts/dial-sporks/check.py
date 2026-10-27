#!/usr/bin/env python3
"""What does a node send a peer it dialled before that peer's sporks arrive?

Divi Core sends an outbound peer nothing from its send loop (ping, getblocks,
getdata, inv, mempool, ...) until the peer has sent `sporkcount` and as many
sporks (CNode::CanSendMessagesToPeer, Node.cpp:1025-1034); what its message
handlers answer goes out at once (verack, getaddr, getsporks). This runs divid and
irondivid on the same chain of five blocks, each dialling a raw peer that
shakes hands and then sends `sporkcount 0` (a) at once, (b) after 10 s, (c) never,
and records every command the node sends, in order, with its time after the handshake.
Rows compare the two nodes: the commands before the peer's `sporkcount`, the
commands after it, and whether the connection is still up at the end.

Each row prints PASS (the same as divid), KNOWN (listed in README.md) or FAIL.
Exit code = FAILs. Started by run.sh, which owns the work directory and stops
the nodes. DIAL_SPORKS_TRACE=1 prints every message with its time.
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
MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
ONLY = os.environ.get("DIAL_SPORKS_ONLY", "")   # run only the rows whose name has this
TRACE = bool(os.environ.get("DIAL_SPORKS_TRACE"))
AGENT = b"/dial-sporks:1/"
NODE_NETWORK = 1

KNOWN = {}
fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron):
    global fails
    same = core == iron
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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


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
    """A raw peer the node dialled: its handshake, `sporkcount 0` at `spork_at` seconds after it
    (never if None), then every message the node sends it, with the time after the handshake"""

    def __init__(self, sock, port, spork_at):
        self.sock, self.log, self.t0 = sock, [], None
        self.alive, self.port, self.spork_at = True, port, spork_at
        self.spork_sent = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def send_sporkcount(self):
        try:
            self.sock.sendall(message("sporkcount", struct.pack("<i", 0)))
            self.spork_sent = time.time() - self.t0
        except OSError:
            pass

    def run(self):
        try:
            got = set()
            while True:
                command, payload = read_message(self.sock)
                if command == "version":
                    self.sock.sendall(message("version", version_payload(self.port, NODE_NETWORK, 0)))
                    self.sock.sendall(message("verack"))
                    got.add("version")
                elif command == "verack":
                    got.add("verack")
                elif command == "ping":
                    self.sock.sendall(message("pong", payload))
                if self.t0 is None and got == {"version", "verack"}:
                    self.t0 = time.time()
                    if self.spork_at is not None:
                        threading.Timer(self.spork_at, self.send_sporkcount).start()
                elif self.t0 is not None:
                    self.log.append((time.time() - self.t0, command))
        except (EOFError, ConnectionError, OSError):
            self.alive = False

    def commands(self, lo, hi):
        """Distinct commands that arrived from `lo` to `hi` seconds after the handshake, in order"""
        seen = []
        for t, c in self.log:
            if lo <= t < hi and c not in seen:
                seen.append(c)
        return seen

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
        self.auth = base64.b64encode(f"ds{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=ds{index}", f"rpcpassword={password}",
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
    """A raw peer the node is told to dial"""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, port))
        self.sock.listen(4)
        self.target = f"{HOST}:{port}"

    def accept(self, secs, spork_at):
        self.sock.settimeout(secs)
        try:
            s, _ = self.sock.accept()
        except OSError:
            return None
        return Peer(s, self.port, spork_at)

    def close(self):
        self.sock.close()


def start_mining():
    for node in NODES:
        node.start()
        if not node.wait_ready():
            raise RuntimeError(f"{node.name} did not start")
        node.rpc("setgenerate", 5)
        if not wait_for(lambda: node.rpc("getblockcount") >= 5, 60):
            raise RuntimeError(f"{node.name} did not make five blocks")
        node.stop()
        time.sleep(1)


def run_case(node, spork_at, watch, mine_at=None):
    """Start `node` dialling one raw peer that sends `sporkcount 0` at `spork_at` s; watch `watch` s;
    the node makes a block at `mine_at` s"""
    l = Listener(PORT_BASE + 4)
    try:
        node.start([f"connect={l.target}", "listen=1"])
        if not node.wait_ready():
            raise RuntimeError(f"{node.name} did not start")
        p = l.accept(60, spork_at)
        if p is None:
            raise RuntimeError(f"{node.name} did not dial {l.target}")
        if not wait_for(lambda: p.t0 is not None, 30):
            raise RuntimeError(f"{node.name}: the handshake did not finish")
        if mine_at is not None:
            time.sleep(mine_at)
            node.rpc("setgenerate", 1)
            time.sleep(watch - mine_at)
        else:
            time.sleep(watch)
        if TRACE:
            print(f"#   {node.name} spork_at={spork_at} sporkcount sent at {p.spork_sent}: "
                  + " ".join(f"{c}@{t:.1f}" for t, c in p.log), flush=True)
        # sent with the handshake, sporkcount crosses what the node sends at once: the whole
        # order is compared
        sent = 0 if spork_at == 0 else p.spork_sent if p.spork_sent is not None else watch + 1
        before, after = p.commands(0, sent), p.commands(sent, watch + 1)
        out = {"before sporkcount": before, "after sporkcount": after, "still connected": p.alive}
        p.close()
        return out
    finally:
        l.close()


def case(name, spork_at, watch, mine_at=None):
    if ONLY not in name:
        return
    got = {}
    for node in NODES:
        got[node.name] = run_case(node, spork_at, watch, mine_at)
        node.stop()
        time.sleep(1)
    row(name, got["divid"], got["irondivid"])


NODES = [Node("divid", DIVID, 0), Node("irondivid", IRONDIVID, 1)]
start_mining()

case("sporkcount 0 at once", 0, 12)
case("sporkcount 0 after 10 s", 10, 25)
case("no sporkcount in 25 s", None, 25)
case("sporkcount 0 at once, a block made at 3 s", 0, 12, mine_at=3)
case("sporkcount 0 after 10 s, a block made at 3 s", 10, 25, mine_at=3)
case("no sporkcount, a block made at 3 s", None, 15, mine_at=3)

print(f"# PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}")
print(f"FAILS {fails}")
sys.exit(min(fails, 254))
