#!/usr/bin/env python3
"""Which peers does a node ask for blocks when they connect, and when one goes?

Divi Core sends `getblocks` at the start of a connection to the peers it syncs
from: a full node it dialled or one that is whitelisted, and a full node that
dialled it only while it has none of those (main.cpp:1304-1311, 1130-1143,
Node.cpp:1075). This runs divid and irondivid on the same chain of five
blocks, joins raw peers to each (the ones the node dials answer as peers with no
sporks, since divid sends nothing to a peer it dialled before, Node.cpp:1031)
and records which of them is sent `getblocks` or `getheaders` in the seconds
after the handshake. A row per set-up compares the two nodes:

  - two peers the node dialled (-connect) and three that dialled it;
  - three that dialled it, and nothing else;
  - an `addnode onetry` peer and one that dialled it;
  - a peer that is not a full node (no NODE_NETWORK), with a dialled peer;
  - a whitelisted peer that dialled it, with a dialled peer;
  - the first set-up again after a restart, the peers naming a longer chain;
  - a dialled peer that goes: which of the two that dialled it is then asked.

Each row prints PASS (the same as divid), KNOWN (listed in README.md) or FAIL.
Exit code = FAILs. Started by run.sh, which owns the work directory and stops
the nodes. START_GETBLOCKS_TRACE=1 prints every message each peer got, with
its time; START_GETBLOCKS_ONLY=<text> runs only the rows whose name has <text>.
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
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
LEAVE_WATCH = 12   # seconds a peer is watched after another leaves
WATCH = 5          # seconds after the last handshake that the peers are watched
MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
ONLY = os.environ.get("START_GETBLOCKS_ONLY", "")   # run only the rows whose name has this
TRACE = bool(os.environ.get("START_GETBLOCKS_TRACE"))
AGENT = b"/start-getblocks:1/"
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
    """A raw peer: its handshake, then every message the node sends it, with the time"""

    def __init__(self, sock, port, services=NODE_NETWORK, height=0, dialled_by_node=False):
        self.sock, self.log, self.t0 = sock, [], None
        self.alive = True
        self.ok = False
        self.port, self.services, self.height = port, services, height
        self.dialled = dialled_by_node
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            if not self.dialled:
                self.sock.sendall(message("version", version_payload(self.port, self.services, self.height)))
            got = set()
            while True:
                command, payload = read_message(self.sock)
                if command == "version":
                    if self.dialled:
                        self.sock.sendall(message("version", version_payload(self.port, self.services, self.height)))
                    self.sock.sendall(message("verack"))
                    if self.dialled:
                        # divid sends nothing to a peer it dialled until it has that peer's sporks
                        # (Node.cpp:1031); this one has none
                        self.sock.sendall(message("sporkcount", struct.pack("<i", 0)))
                    got.add("version")
                elif command == "verack":
                    got.add("verack")
                elif command == "ping":
                    self.sock.sendall(message("pong", payload))
                if self.t0 is None and got == {"version", "verack"}:
                    self.t0 = time.time()
                    self.ok = True
                elif self.t0 is not None:
                    self.log.append((time.time() - self.t0, command))
        except (EOFError, ConnectionError, OSError):
            self.alive = False
            self.died = time.time()

    def asked(self):
        """'getblocks', 'getheaders', or both, in the order they arrived; '-' if neither"""
        seen = []
        for _, c in self.log:
            if c in ("getblocks", "getheaders") and c not in seen:
                seen.append(c)
        return "+".join(seen) or "-"

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
        self.auth = base64.b64encode(f"sg{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=sg{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}", "dnsseed=0", "staking=0", "txindex=1",
        ]
        self.proc = None

    def start(self, extra=()):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
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

    def __init__(self, port, services=NODE_NETWORK, height=0):
        self.port, self.services, self.height = port, services, height
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, port))
        self.sock.listen(4)
        self.target = f"{HOST}:{port}"

    def accept(self, secs):
        self.sock.settimeout(secs)
        try:
            s, _ = self.sock.accept()
        except OSError:
            return None
        return Peer(s, self.port, self.services, self.height, dialled_by_node=True)

    def close(self):
        self.sock.close()


def dial(node, services=NODE_NETWORK, height=0):
    s = socket.create_connection((HOST, node.p2p), timeout=10)
    return Peer(s, node.p2p, services, height)


def handshaken(peers, secs=30):
    return wait_for(lambda: all(p.ok for p in peers), secs)


def settle(peers, secs=WATCH):
    time.sleep(secs)
    return [p.asked() for p in peers]


def scenario(node, out_n=0, in_n=0, extra=(), height=0, in_services=NODE_NETWORK, onetry=0, watch=WATCH):
    """Start `node` with `out_n` dialled peers (-connect) and `onetry` one-shot ones, join `in_n` that
    dial it, watch. -> (dialled, one-shot, dialled-it) -> what each was asked"""
    ls = [Listener(PORT_BASE + 4 + k, height=height) for k in range(out_n + onetry)]
    out, shot, inn = [], [], []
    try:
        node.start([f"connect={l.target}" for l in ls[:out_n]] + (["listen=1"] if out_n else []) + list(extra))
        if not node.wait_ready():
            raise RuntimeError(f"{node.name} did not start")
        for l in ls[:out_n]:
            p = l.accept(60)
            if p is None:
                raise RuntimeError(f"{node.name} did not dial {l.target}")
            out.append(p)
        for l in ls[out_n:]:
            node.rpc("addnode", l.target, "onetry")
            p = l.accept(60)
            if p is None:
                raise RuntimeError(f"{node.name} did not dial {l.target} (onetry)")
            shot.append(p)
        inn = [dial(node, in_services, height) for _ in range(in_n)]
        if not handshaken(out + shot + inn):
            raise RuntimeError(f"{node.name}: a handshake did not finish")
        res = (settle(out, watch), settle(shot, 0), settle(inn, 0))
        return res, (out, shot, inn), ls
    except BaseException:
        for p in out + shot + inn:
            p.close()
        for l in ls:
            l.close()
        raise


def finish(peers, ls):
    for group in peers:
        for p in group:
            p.close()
    for l in ls:
        l.close()


def compare(name, run):
    """run(node) -> something comparable; row per kind"""
    if ONLY not in name:
        return
    got = {}
    for node in NODES:
        got[node.name] = run(node)
        node.stop()
        time.sleep(1)
    row(name, got["divid"], got["irondivid"])


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


def sc(name, **kw):
    def run(node):
        res, peers, ls = scenario(node, **kw)
        if TRACE:
            for kind, group in zip(("dialled", "one-shot", "dialled-it"), peers):
                for p in group:
                    print(f"#   {node.name} {kind} alive={p.alive}: " + " ".join(f"{c}@{t:.2f}" for t, c in p.log), flush=True)
        finish(peers, ls)
        o, s, i = res
        return {"dialled": o, "one-shot": s, "dialled-it": i}
    compare(name, run)


NODES = [Node("divid", DIVID, 0), Node("irondivid", IRONDIVID, 1)]
start_mining()

sc("two dialled and three that dialled it", out_n=2, in_n=3)
sc("three that dialled it, none dialled", in_n=3)
sc("an addnode onetry peer and one that dialled it", onetry=1, in_n=1)
sc("a peer that is not a full node, with a dialled peer", out_n=1, in_n=1, in_services=0)
sc("a whitelisted peer that dialled it, with a dialled peer", out_n=1, in_n=1, extra=["whitelist=127.0.0.0/8"])
sc("restart, the peers claiming a longer chain", out_n=2, in_n=3, height=400)


def handover(node):
    res, (out, shot, inn), ls = scenario(node, out_n=1, in_n=2, watch=1)
    before = [p.asked() for p in inn]
    left = time.time()
    out[0].close()
    ls[0].close()
    time.sleep(LEAVE_WATCH)
    after = [p.asked() for p in inn]
    if TRACE:
        for p in inn:
            print("#   after:", p.alive, f"died at {getattr(p, 'died', left) - left:.1f}", " ".join(f"{c}@{t:.2f}" for t, c in p.log), flush=True)
    if TRACE:
        os.system(f"tail -40 {node.dir}/regtest/debug.log {node.dir}/debug.log 2>/dev/null | cut -c1-200")
    finish((out, shot, inn), ())
    return {"before": before, "after the dialled peer left": after}


compare("a dialled peer leaves, the two that dialled it", handover)

print(f"# PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}")
print(f"FAILS {fails}")
sys.exit(min(fails, 254))
