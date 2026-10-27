#!/usr/bin/env python3
"""-maxreceivebuffer, -maxsendbuffer, -onlynet, -logtimestamps, -logips and
-shrinkdebugfile on Divi Core divid and irondivid, side by side on regtest.

Each daemon runs on its own (they are not connected); the same raw peers and
the same options are put to both, and each row compares what the two do.
Rows print PASS (the same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory
and stops the nodes.
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
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 60
START_TIMEOUT = 120
MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])  # regtest (chainparams.cpp)

KNOWN = {}
fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same=None):
    global fails
    same = core == iron if same is None else same
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


def wait_for(fn, secs, step=0.2):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


def port_free(port):
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


# --- nodes --------------------------------------------------------------------------------

class Node:
    """A daemon on its own datadir under WORK, ports PORT_BASE + 2*slot and +1"""
    runs = 0

    def __init__(self, kind, slot, extra=(), args=(), prepare=None):
        Node.runs += 1
        self.kind = kind
        self.binary = DIVID if kind == "divid" else IRONDIVID
        self.dir = os.path.join(WORK, f"{kind}-{Node.runs}")
        self.p2p = PORT_BASE + 2 * slot
        self.rpcport = PORT_BASE + 2 * slot + 1
        os.makedirs(self.dir)
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"nl:{password}".encode()).decode()
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", "rpcuser=nl",
                 f"rpcpassword={password}", "daemon=0", "server=1", "discover=0", "listenonion=0",
                 "listen=1", f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}", "dnsseed=0",
                 "staking=0"] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        if prepare:
            prepare(self)
        # the previous node's ports, a moment after it stopped; one another process holds is node_ports' to move
        for p in (node_ports.now(self.p2p), node_ports.now(self.rpcport)):
            wait_for(lambda: port_free(p), 60, 0.5)
        self.out = open(os.path.join(WORK, f"{kind}-{Node.runs}.out"), "ab")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"] + list(args), cwd=self.dir,
                                     stdout=self.out, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def log_path(self):
        """debug.log: divid writes it under regtest/, irondivid in the datadir"""
        for p in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(p):
                return p
        return os.path.join(self.dir, "regtest" if self.kind == "divid" else "", "debug.log")

    def call(self, method, *params, timeout=RPC_TIMEOUT):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                text = r.read()
        except urllib.error.HTTPError as e:
            text = e.read() or b"{}"
        reply = json.loads(text)
        if reply.get("error"):
            return ("err", reply["error"].get("code"), reply["error"].get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params, timeout=RPC_TIMEOUT):
        out = self.call(method, *params, timeout=timeout)
        if out[0] != "ok":
            raise RuntimeError(f"{self.kind} {method}: {out[1]} {out[2][:160]}")
        return out[1]

    def ready(self, secs=START_TIMEOUT):
        """True once RPC answers; False if the process ended first"""
        deadline = time.time() + secs
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount", timeout=5)[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.3)
        return False

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.call("stop", timeout=10)
            except Exception:
                pass
            try:
                self.proc.wait(60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.out.close()

    def exit_text(self, secs=60):
        """The process's exit code and output, when it stops by itself (a start error)"""
        try:
            code = self.proc.wait(secs)
        except subprocess.TimeoutExpired:
            return None, ""
        self.out.close()
        with open(self.out.name, "rb") as f:
            out = f.read().decode(errors="replace")
        return code, out


def both(make):
    """make(kind) for divid, then irondivid"""
    return make("divid"), make("irondivid")


# --- raw peers -----------------------------------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


class Peer:
    """A raw P2P peer; `rcvbuf`/`sndbuf` set its socket buffers before it connects"""

    def __init__(self, node, rcvbuf=None, sndbuf=None):
        self.sock = socket.socket()
        if rcvbuf:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        if sndbuf:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        self.sock.settimeout(15)
        self.sock.connect((HOST, node.p2p))
        self.addr = self.sock.getsockname()
        self.buf = b""

    def send(self, command, payload=b""):
        self.sock.sendall(message(command, payload))

    def version(self):
        payload = (struct.pack("<iQq", 70915, 1, int(time.time())) + netaddr(HOST, 0) + netaddr(HOST, 0)
                   + secrets.token_bytes(8) + varint(len(b"/nl:1/")) + b"/nl:1/" + struct.pack("<i", 0) + b"\x01")
        self.send("version", payload)

    def read(self, secs):
        """The next (command, payload), or None after `secs`"""
        deadline = time.time() + secs
        while True:
            if len(self.buf) >= 24:
                n = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) >= 24 + n:
                    cmd = self.buf[4:16].rstrip(b"\0").decode(errors="replace")
                    payload, self.buf = self.buf[24:24 + n], self.buf[24 + n:]
                    return cmd, payload
            left = deadline - time.time()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(1 << 16)
            except socket.timeout:
                return None
            except OSError:
                return ("closed", b"")
            if not chunk:
                return ("closed", b"")
            self.buf += chunk

    def expect(self, command, secs):
        """Read until `command` comes (True), the peer is dropped ('closed') or `secs` pass (False)"""
        deadline = time.time() + secs
        while time.time() < deadline:
            got = self.read(deadline - time.time())
            if got is None:
                return False
            if got[0] == "closed":
                return "closed"
            if got[0] == command:
                return True
        return False

    def handshake(self):
        self.version()
        ok = self.expect("verack", 15)
        self.send("verack")
        return ok

    def closed(self, secs):
        """Whether the node drops this peer within `secs` (reading what it sends meanwhile)"""
        return self.expect("\0never", secs) == "closed"

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --- -maxsendbuffer and -maxreceivebuffer ---------------------------------------------------
#
# divid (Node.cpp:22-23): the buffers are -maxsendbuffer and -maxreceivebuffer
# times 1000 bytes (defaults 1000 and 5000). While a peer's send buffer holds
# -maxsendbuffer or more, divid answers no more of its getdata and processes
# none of its messages (main.cpp:291-293, :1028), and it stops reading from it
# once that peer's unprocessed messages pass -maxreceivebuffer (Node.cpp:335-339).
# It drops neither, and other peers are served as before.

BLOCKS = 100
GETDATA_ITEMS = 50000  # MAX_INV_SZ: the most one getdata may ask for


def block_hashes(node):
    return [bytes.fromhex(node.rpc("getblockhash", h))[::-1] for h in range(1, BLOCKS + 1)]


def getdata_payload(hashes, n):
    return varint(n) + b"".join(struct.pack("<I", 2) + hashes[i % len(hashes)] for i in range(n))


def getheaders_payload(node):
    genesis = bytes.fromhex(node.rpc("getblockhash", 0))[::-1]
    return struct.pack("<I", 70915) + varint(1) + genesis + bytes(32)


def peer_entry(node, addr):
    want = f"{addr[0]}:{addr[1]}"
    for p in node.rpc("getpeerinfo"):
        if p.get("addr") == want:
            return p
    return None


def flood(peer, secs, cap=24 << 20):
    """Bytes of pings `peer` writes, without reading, before a write stalls for
    3 s (the node stopped reading), within `secs`; None if it is dropped"""
    sent, deadline = 0, time.time() + secs
    peer.sock.settimeout(3)
    ping = message("ping", struct.pack("<Q", 1))
    try:
        while sent < cap and time.time() < deadline:
            peer.sock.sendall(ping * 64)
            sent += len(ping) * 64
    except socket.timeout:
        pass
    except OSError:
        return None
    return sent


def bucket(n):
    if n is None:
        return "dropped"
    # Kernel socket buffers take 1 to 2 MB whatever the node does
    if n < 4 << 20:
        return "under 4 MB"
    return "4 MB or more"


def stalled_peer(node):
    """A peer that asks for GETDATA_ITEMS blocks and does not read the answer"""
    p1 = Peer(node, rcvbuf=4096, sndbuf=4096)
    p1.handshake()
    while p1.read(1) not in (None,):
        pass
    p1.send("getdata", getdata_payload(block_hashes(node), GETDATA_ITEMS))
    time.sleep(5)
    return p1


def buffer_case(kind, label, extra):
    """What one daemon does with a stalled peer under `extra` options"""
    out = {}
    node = Node(kind, 0, extra=extra)
    if not node.ready():
        return {"start": "did not start"}
    node.rpc("setgenerate", BLOCKS)
    if not wait_for(lambda: node.rpc("getblockcount") >= BLOCKS, 120):
        return {"start": "did not mine"}
    p1 = stalled_peer(node)
    out["stalled peer kept"] = peer_entry(node, p1.addr) is not None
    # Another peer is served meanwhile
    p2 = Peer(node)
    p2.handshake()
    p2.send("ping", struct.pack("<Q", 7))
    t = time.time()
    out["second peer: pong within 10 s"] = p2.expect("pong", 10) is True
    p2.send("getdata", getdata_payload(block_hashes(node)[:1], 1))
    out["second peer: a block within 10 s"] = p2.expect("block", 10) is True
    out["second peer: answer time"] = "under 2 s" if time.time() - t < 2 else "2 s or more"
    p2.close()
    # The stalled peer floods: how much the node takes before it stops reading
    out["stalled peer flood"] = bucket(flood(p1, 15))
    time.sleep(1)
    entry = peer_entry(node, p1.addr)
    out["stalled peer kept after the flood"] = entry is not None
    out["stalled peer banscore"] = entry.get("banscore", 0) if entry else "-"
    # It reads again: every block it asked for comes
    blocks, deadline = 0, time.time() + 90
    while blocks < GETDATA_ITEMS and time.time() < deadline:
        got = p1.read(10)
        if got is None or got[0] == "closed":
            break
        if got[0] == "block":
            blocks += 1
    out["stalled peer then reads: blocks"] = "all" if blocks == GETDATA_ITEMS else f"{blocks} of {GETDATA_ITEMS}"
    p1.close()
    node.stop()
    return out


def buffer_rows():
    for label, extra in (("defaults", []), ("-maxsendbuffer=1", ["maxsendbuffer=1"]),
                         ("-maxreceivebuffer=50", ["maxreceivebuffer=50"])):
        core, iron = both(lambda k: buffer_case(k, label, extra))
        for key in core.keys() | iron.keys():
            row(f"buffers, {label}: {key}", core.get(key), iron.get(key))


# --- -onlynet ---------------------------------------------------------------------------------
#
# divid (net.cpp:1734-1746): each -onlynet names a network (ParseNetwork,
# netbase.cpp:70-77: ipv4, ipv6, tor or onion, in any case); an unknown one
# stops the start. Every network not named is limited: getnetworkinfo shows
# it limited and not reachable (rpcnet.cpp:323-324), addresses of it are not
# taken as ours (AddLocal, NetworkLocalAddressHelpers.cpp:90) and not dialled
# from learnt addresses (net.cpp:1164). -connect and -addnode are dialled as
# they are given (net.cpp:1282-1289); 127.0.0.2 is not routable, in no
# network, so never limited.

def networks(info):
    return {n["name"]: (n["limited"], n["reachable"]) for n in info.get("networks", [])}


def onlynet_case(kind, values, extra=()):
    lines = [f"onlynet={v}" for v in values] + list(extra)
    node = Node(kind, 0, extra=lines)
    if not node.ready(60):
        code, out = node.exit_text()
        if code is None:
            node.stop()
            return {"start": "did not answer"}
        try:
            with open(node.log_path(), errors="replace") as f:
                out += f.read()
        except OSError:
            pass
        m = re.search(r"Unknown network specified in -onlynet: '[^']*'", out)
        return {"start": f"refused (exit {'non-zero' if code else 0}): {m.group(0) if m else 'no message'}"}
    info = node.rpc("getnetworkinfo")
    nets = networks(info)
    out = {"start": "started"}
    for name in ("ipv4", "ipv6"):
        out[f"{name} limited, reachable"] = nets.get(name)
    out["onion limited"] = nets.get("onion", (None,))[0]
    out["localaddresses"] = sorted(a["address"] for a in info.get("localaddresses", []))
    node.stop()
    return out


def onlynet_rows():
    cases = [
        ("-onlynet=ipv4", ["ipv4"], ["externalip=1.2.3.4", "externalip=[2a00:1450:4001:80b::200e]"]),
        ("-onlynet=IPv6", ["IPv6"], ["externalip=1.2.3.4", "externalip=[2a00:1450:4001:80b::200e]"]),
        ("-onlynet=onion", ["onion"], []),
        ("-onlynet=tor", ["tor"], []),
        ("-onlynet=ipv4 -onlynet=ipv6", ["ipv4", "ipv6"], ["externalip=1.2.3.4"]),
        ("no -onlynet", [], ["externalip=1.2.3.4"]),
        ("-onlynet=bogus", ["bogus"], []),
        ("-onlynet=", [""], []),
    ]
    for label, values, extra in cases:
        core, iron = both(lambda k: onlynet_case(k, values, extra))
        for key in sorted(core.keys() | iron.keys()):
            row(f"{label}: {key}", core.get(key), iron.get(key))
    # -connect to an address that is in no network: dialled under any -onlynet
    for label, values in (("-onlynet=ipv6", ["ipv6"]), ("-onlynet=onion", ["onion"])):
        def dial(kind):
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, PORT_BASE + 4))
            listener.listen(4)
            listener.settimeout(30)
            node = Node(kind, 0, extra=[f"onlynet={v}" for v in values] + [f"connect={HOST}:{PORT_BASE + 4}"])
            try:
                conn, _ = listener.accept()
                conn.close()
                dialled = True
            except socket.timeout:
                dialled = False
            listener.close()
            node.stop()
            return dialled
        core, iron = both(dial)
        row(f"{label}: -connect={HOST} dialled", core, iron)


# --- -logtimestamps, -logips, -shrinkdebugfile -------------------------------------------------
#
# divid: with -logtimestamps (default 1) each debug.log line begins
# "%Y-%m-%d %H:%M:%S ", then the message (Logging.cpp:179-184). -logips
# (default 0) adds the peer's address to three lines only: "Added
# connection" and "send version message" (category net) and "receive
# version message ... peeraddr=" (Node.cpp:577-580, :1000-1003,
# main.cpp:456-461). -shrinkdebugfile (default 1 unless -debug) cuts a
# debug.log over 10 MB to its last 200 000 bytes at start (Logging.cpp:94-118,
# :204-205).

STAMP = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ")
LEVEL = re.compile(r"(^|\s)(INFO|DEBUG|TRACE)\s|\b(divi_\w+|irondivid)::?\w*:")


def debug_log(node):
    try:
        with open(node.log_path(), errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def share(lines, test):
    hits = sum(1 for l in lines if test(l))
    return "every line" if hits == len(lines) else "no line" if hits == 0 else "some lines"


def log_case(kind, extra):
    node = Node(kind, 0, extra=extra)
    if not node.ready():
        return {"start": "did not start"}
    peer = Peer(node)
    peer.handshake()
    peer.read(2)
    at = f"{peer.addr[0]}:{peer.addr[1]}"
    peer.close()
    time.sleep(1)
    node.stop()
    lines = [l for l in debug_log(node).splitlines() if l.strip()]
    version = [l for l in lines if "receive version message" in l]
    return {
        "lines begin with the time": share(lines, lambda l: STAMP.match(l)),
        "lines name a level or module": share(lines, lambda l: LEVEL.search(STAMP.sub("", l))),
        "the peer's address is in the log": any(at in l for l in lines),
        "the version line names the peer (peeraddr=)": any(f"peeraddr={at}" in l for l in version),
        "a version line is logged": bool(version),
    }


def log_rows():
    for label, extra in (("defaults", []), ("-logips=1", ["logips=1"]), ("-logtimestamps=0", ["logtimestamps=0"]),
                         ("-logips=1 -logtimestamps=0", ["logips=1", "logtimestamps=0"])):
        core, iron = both(lambda k: log_case(k, extra))
        for key in sorted(core.keys() | iron.keys()):
            row(f"debug.log, {label}: {key}", core.get(key), iron.get(key))


OLD_LOG = 15_000_000


def old_log(node):
    """A 15 MB debug.log from an earlier run, where the daemon writes it"""
    folder = os.path.join(node.dir, "regtest") if node.kind == "divid" else node.dir
    os.makedirs(folder, exist_ok=True)
    node.old = bytes((b"0123456789abcdef\n"[i % 17] for i in range(OLD_LOG)))
    with open(os.path.join(folder, "debug.log"), "wb") as f:
        f.write(node.old)


def shrink_case(kind, extra):
    node = Node(kind, 0, extra=extra, prepare=old_log)
    if not node.ready():
        return "did not start"
    node.stop()
    path = node.log_path()
    with open(path, "rb") as f:
        log = f.read()
    rotated = path + ".1"
    if log.startswith(node.old[-200_000:]) and len(log) < 1_000_000:
        return "cut to its last 200 000 bytes"
    if log.startswith(node.old):
        return "kept whole"
    if os.path.exists(rotated) and os.path.getsize(rotated) == OLD_LOG:
        return "rotated whole to debug.log.1"
    return f"other ({len(log)} bytes)"


ROTATES = "irondivid also rotates debug.log by size: an old file over -maxlogsize is moved whole to debug.log.1 (docs/divid-differences.md S6)"


def shrink_rows():
    for label, extra in (("defaults", []), ("-shrinkdebugfile=0", ["shrinkdebugfile=0"]), ("-debug", ["debug=1"]),
                         ("-debug -shrinkdebugfile=1", ["debug=1", "shrinkdebugfile=1"])):
        name = f"15 MB old debug.log, {label}: after start"
        if label in ("-shrinkdebugfile=0", "-debug"):
            KNOWN[name] = ROTATES
        core, iron = both(lambda k: shrink_case(k, extra))
        row(name, core, iron)


# --- each option is taken, not warned about -----------------------------------------------------

OPTIONS = ["maxreceivebuffer=5000", "maxsendbuffer=1000", "onlynet=ipv4", "logtimestamps=1", "logips=0",
           "shrinkdebugfile=1"]


def warned_options(kind):
    node = Node(kind, 0, extra=OPTIONS)
    if not node.ready():
        return "did not start"
    node.stop()
    log = debug_log(node)
    names = [o.split("=")[0] for o in OPTIONS]
    warned = [n for n in names if re.search(rf"(not supported|Unknown option)[^\n]*-{n}\b|-{n}\b[^\n]*not supported", log)]
    return ", ".join(warned) or "none"


# --- the run ----------------------------------------------------------------------------------------

def section(name, fn):
    try:
        fn()
    except Exception as e:
        row(f"{name}: setup", "ran", f"stopped: {type(e).__name__}: {e}"[:300], False)


print(f"# net-log-options: ports {PORT_BASE}..{PORT_BASE + 4} on {HOST}", flush=True)
t0 = time.time()
section("buffers", buffer_rows)
section("-onlynet", onlynet_rows)
section("debug.log", log_rows)
section("-shrinkdebugfile", shrink_rows)
section("options", lambda: row("options warned about as not supported", *both(warned_options)))
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL in {time.time() - t0:.0f} s",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
