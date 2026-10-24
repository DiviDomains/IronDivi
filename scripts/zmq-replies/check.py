#!/usr/bin/env python3
"""ZMQ notifications of Divi Core divid and irondivid, compared message by message.

A third node, a divid, mines and sends; divid and irondivid both follow it on
one regtest chain, with all four -zmqpub options, so both see the same blocks
and transactions arrive the same way. A subscriber on each of their ZMQ
sockets (ZMTP 3.0 written here, standard library only) records every message:
topic, body and sequence number. After each event the two nodes' messages on
the matching sockets are compared. Then the option errors: an address that
does not parse and a port in use. Each row prints PASS (same as divid), KNOWN
(a difference listed in README.md) or FAIL. Exit code = FAILs.

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
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("ZMQ_REPLIES_INJECT", "")
# A directory to write both replies of every compared row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("ZMQ_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {
    "options: a port in use, before a good one":
        "divid aborts at start: the failed bind shuts down every notifier, and Shutdown asserts a socket on the one "
        "after it that was never set up (zmqpublishnotifier.cpp:101, zmqnotificationinterface.cpp:23-31, :92-99); "
        "irondivid starts without ZMQ, as divid does when the address that fails is the last one",
}

fails = 0


def known(name):
    """The KNOWN reason of a row: its own entry, else the entry of the same row
    before the restart"""
    if name in KNOWN:
        return KNOWN[name]
    return KNOWN.get(name.split(": ", 1)[1]) if name.startswith("after restart: ") else None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        self.base = lines[:-len(extra_conf)] if extra_conf else lines
        self.write_conf(extra_conf, os.O_EXCL)
        self.log = None
        self.start()

    def write_conf(self, extra_conf, flag=os.O_TRUNC):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | flag, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra_conf)) + "\n")

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
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

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- how replies are compared ------------------------------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Reals are compared as divid writes
    them (the text of the number)."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:80]}\"".replace("\n", "\\n")
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def compare(name, core, iron, drop=frozenset(), order=None):
    """Same outcome; for a result the same fields and values (except `drop`), list
    items in divid's order unless `order` gives a sort key"""
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else iron[:2] + (iron[2] + " injected",)
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    a, b = unordered(a), unordered(b)
    d = first_difference(a, b)
    if DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1, sort_keys=True)
    row(name, short(core), d or short(iron), d is None)


def unordered(v):
    """txids lists are sets: divid writes them in its wallet map's order"""
    if isinstance(v, dict):
        return {k: sorted(x) if k == "txids" and isinstance(x, list) else unordered(x) for k, x in v.items()}
    if isinstance(v, list):
        return [unordered(x) for x in v]
    return v


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        v = [dict(v[0], amount="0.12345678")] + v[1:]
    elif isinstance(v, dict):
        v = dict(v, injected=True)
    else:
        v = "injected"
    return v


def both(name, method, *params, **kw):
    compare(name, C.call(method, *params), I.call(method, *params), **kw)


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
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- a ZMQ subscriber: ZMTP 3.0, NULL mechanism, written here ------------------------

def greeting():
    # signature, version 3.0, mechanism "NULL", as-server 0, filler (ZMTP 3.0 section 4)
    return b"\xff" + bytes(8) + b"\x7f" + b"\x03\x00" + b"NULL".ljust(20, b"\0") + b"\x00" + bytes(31)


def frame(body, more=False, command=False):
    flags = (1 if more else 0) | (4 if command else 0)
    if len(body) > 255:
        return bytes([flags | 2]) + struct.pack(">Q", len(body)) + body
    return bytes([flags, len(body)]) + body


def ready(socket_type):
    prop = bytes([11]) + b"Socket-Type" + struct.pack(">I", len(socket_type)) + socket_type
    return frame(bytes([5]) + b"READY" + prop, command=True)


class Subscriber:
    """One SUB connection to one address, subscribed to every topic; records
    each message as [topic, body hex, sequence] in arrival order"""

    def __init__(self, port):
        self.port = port
        self.messages = []
        self.lock = threading.Lock()
        self.error = None
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.sendall(greeting())
        peer = self.read(64)
        if peer[0] != 0xff or peer[9] != 0x7f or peer[10] < 3:
            raise RuntimeError(f"port {port}: not a ZMTP 3 peer")
        self.sock.sendall(ready(b"SUB"))
        flags, body = self.read_frame()
        if not flags & 4 or not body[1:6] == b"READY":
            raise RuntimeError(f"port {port}: no READY")
        # A subscription is a message whose body is 1 and the topic prefix (empty: every topic)
        self.sock.sendall(frame(b"\x01"))
        self.sock.settimeout(None)
        threading.Thread(target=self.run, daemon=True).start()

    def read(self, n):
        b = b""
        while len(b) < n:
            part = self.sock.recv(n - len(b))
            if not part:
                raise EOFError
            b += part
        return b

    def read_frame(self):
        flags = self.read(1)[0]
        size = struct.unpack(">Q", self.read(8))[0] if flags & 2 else self.read(1)[0]
        return flags, self.read(size)

    def run(self):
        try:
            while True:
                parts = []
                while True:
                    flags, body = self.read_frame()
                    if flags & 4:
                        break
                    parts.append(body)
                    if not flags & 1:
                        break
                if not parts:
                    continue
                topic = parts[0].decode(errors="replace")
                body = parts[1].hex() if len(parts) > 1 else None
                seq = struct.unpack("<I", parts[2])[0] if len(parts) > 2 and len(parts[2]) == 4 else None
                with self.lock:
                    self.messages.append([topic, body, seq, len(parts)])
        except (EOFError, OSError) as e:
            self.error = str(e) or type(e).__name__

    def take(self):
        with self.lock:
            out, self.messages = self.messages, []
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def listening(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        return True
    except OSError:
        return False


# --- the nodes -------------------------------------------------------------------------

# Ports: 0-1 the miner, 2-3 divid, 4-5 irondivid; their ZMQ sockets
# (hashblock and hashtx share one address, rawblock and rawtx one each)
# 6-8 for divid and 9-11 for irondivid; 12-14 for the option-error nodes
ZMQ = {"divid": PORT_BASE + 6, "irondivid": PORT_BASE + 9}


def zmq_conf(base):
    return [f"zmqpubhashblock=tcp://127.0.0.1:{base}", f"zmqpubhashtx=tcp://127.0.0.1:{base}",
            f"zmqpubrawblock=tcp://127.0.0.1:{base + 1}", f"zmqpubrawtx=tcp://127.0.0.1:{base + 2}"]


SOCKETS = (("hashblock and hashtx", 0), ("rawblock", 1), ("rawtx", 2))

M = Node("miner", DIVID, 0, ["listen=1"])
if not M.wait_ready():
    print(f"FAIL   start: the miner did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
follow = ["listen=0", f"connect=127.0.0.1:{PORT_BASE}", "disablewallet=1"]
C = Node("divid", DIVID, 1, follow + zmq_conf(ZMQ["divid"]))
I = Node("irondivid", IRONDIVID, 2, follow + zmq_conf(ZMQ["irondivid"]))
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def subscribe():
    subs = {}
    for n in (C, I):
        for what, offset in SOCKETS:
            port = ZMQ[n.name] + offset
            try:
                subs[(n.name, what)] = Subscriber(port)
            except (OSError, EOFError, RuntimeError) as e:
                subs[(n.name, what)] = None
                print(f"# {n.name} {what}: no subscriber ({e})", flush=True)
    # libzmq takes a subscription asynchronously: give it a moment
    time.sleep(1)
    return subs


subs = subscribe()


def settled(txids=()):
    """Both followers at the miner's tip, with `txids` in their mempools; then
    a moment for the last messages"""
    tip = M.rpc("getbestblockhash")
    ok = wait_for(lambda: all(n.rpc("getbestblockhash") == tip and
                              all(t in n.rpc("getrawmempool") for t in txids) for n in (C, I)), 90)
    time.sleep(2)
    return ok


def event_rows(event):
    """The messages each node published since the last event, socket by socket"""
    for what, _ in SOCKETS:
        got = {}
        for name in ("divid", "irondivid"):
            sub = subs.get((name, what))
            got[name] = sub.take() if sub else None
        core, iron = got["divid"], got["irondivid"]
        name = f"{event}: {what}"
        if INJECT and INJECT == name and iron:
            iron = iron[:-1] + [[iron[-1][0], "00", iron[-1][2], iron[-1][3]]]
        if DUMP:
            safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
            with open(os.path.join(DUMP, safe + ".json"), "w") as f:
                json.dump({"divid": core, "irondivid": iron}, f, indent=1)
        describe = lambda ms: "no subscriber" if ms is None else \
            f"{len(ms)} messages " + ",".join(f"{m[0]}#{m[2]}" for m in ms)[:120]
        same = core == iron and core is not None
        note = ""
        if not same and core is not None and iron is not None:
            for i, (a, b) in enumerate(zip(core, iron)):
                if a != b:
                    note = f" first difference at message {i}: {a[0]} #{a[2]} {(a[1] or '')[:16]} vs {b[0]} #{b[2]} {(b[1] or '')[:16]}"
                    break
        row(name, describe(core), describe(iron) + note, same)


def mine(n):
    M.rpc("setgenerate", n)


# --- the events --------------------------------------------------------------------------

# 25 blocks, one at a time: the miner's coinbases mature after 20
for _ in range(25):
    mine(1)
    settled()
event_rows("25 blocks")

a = M.rpc("sendtoaddress", M.rpc("getnewaddress"), 10)
settled([a])
event_rows("a transaction")

mine(1)
settled()
event_rows("a block with that transaction")

b = M.rpc("sendtoaddress", M.rpc("getnewaddress"), 5)
c = M.rpc("sendtoaddress", M.rpc("getnewaddress"), 7)
settled([b, c])
mine(1)
settled()
event_rows("two transactions, then a block with both")

# A reorganization: the miner's tip block (with a transaction) is replaced by
# two blocks; the followers see the second one make the other branch longer
d = M.rpc("sendtoaddress", M.rpc("getnewaddress"), 3)
settled([d])
mine(1)
settled()
event_rows("a transaction and its block before the reorganization")
stale = M.rpc("getbestblockhash")
M.rpc("invalidateblock", stale)
mine(2)
settled()
event_rows("reorganization: two blocks replace one")

# Restart both followers: the sequence numbers start again from 0
for s in subs.values():
    if s:
        s.close()
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
subs = subscribe()
settled()
event_rows("after restart, before any block")
e = M.rpc("sendtoaddress", M.rpc("getnewaddress"), 2)
settled([e])
mine(1)
settled()
event_rows("after restart: a transaction and a block")

for s in subs.values():
    if s:
        s.close()
for n in (C, I):
    n.stop()

# --- option errors ---------------------------------------------------------------------------

# A node started with an address libzmq cannot bind, next to a good one: does
# it start, and does the good address listen? divid checks the addresses in
# its own order: hashblock, hashtx, rawblock, rawtx (ZMQNotifierFactory.cpp:4-8)
held = socket.socket()
held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
held.bind(("127.0.0.1", PORT_BASE + 14))
held.listen(1)
good = PORT_BASE + 12
cases = (
    ("an address that does not parse, after a good one",
     [f"zmqpubhashblock=tcp://127.0.0.1:{good}", "zmqpubrawtx=notanaddress"]),
    ("a port in use, after a good one",
     [f"zmqpubhashblock=tcp://127.0.0.1:{good}", f"zmqpubrawtx=tcp://127.0.0.1:{PORT_BASE + 14}"]),
    ("a port in use, before a good one",
     [f"zmqpubhashblock=tcp://127.0.0.1:{PORT_BASE + 14}", f"zmqpubrawtx=tcp://127.0.0.1:{good}"]),
    ("a good address", [f"zmqpubhashblock=tcp://127.0.0.1:{good}"]),
)
for k, (what, conf) in enumerate(cases):
    seen = {}
    for binary, name, index in ((DIVID, "divid", 1), (IRONDIVID, "irondivid", 2)):
        n = Node(f"{name}-options-{k}", binary, index, ["listen=0", "disablewallet=1"] + conf)
        started = n.wait_ready()
        time.sleep(1)
        seen[name] = {"started": started, "listening": listening(good) if started else None}
        n.stop()
    row(f"options: {what}", json.dumps(seen["divid"]), json.dumps(seen["irondivid"]),
        seen["divid"] == seen["irondivid"])
held.close()

M.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
