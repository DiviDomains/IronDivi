#!/usr/bin/env python3
"""What a node keeps across a restart, and block import, on a fresh Divi Core
divid and a fresh irondivid side by side on regtest: peer addresses learnt from
addr gossip (asked back with getaddr) after a clean and an unclean stop, bans,
the masternode list, damaged peers.dat and mncache.dat, the files a new data
directory gets, and -loadblock / bootstrap.dat / -stopafterblockimport with
divid's own block file. Each row prints PASS, KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

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
# For the proof that a difference is caught: irondivid's outcome of the named row
# is changed before it is compared
INJECT = os.environ.get("RESTART_STATE_INJECT", "")
# The nodes listen and answer RPC on HOST; the test peer connects from PEER
HOST = os.environ.get("RESTART_STATE_HOST", "127.0.0.2")
PEER = os.environ.get("RESTART_STATE_PEER", "127.0.0.3")
RPC_TIMEOUT = 60
START_TIMEOUT = 120
REGTEST_MAGIC = bytes.fromhex("a1cf7eac")
PROTOCOL = 70915



def absent(c, i):
    return c == "present" and i == "absent"


def elsewhere(where):
    return (f"irondivid keeps this in {where}, not in a file of divid's format (divid never reads irondivid's "
            "data directory)", absent)


def mncache_refused(c, i):
    return c[0] == "exit" and c[1] == 1 and "Failed to load masternode cache" in c[2] and i[0] == "up"


MNCACHE = ("divid refuses to start on a mncache.dat it cannot read (CFlatDB::Load returns false for anything "
           "but a readable header with bad data, flat-database.h:225-245; MasternodeModule.cpp:262-266); "
           "irondivid keeps its masternode list in its chain database and does not read mncache.dat",
           mncache_refused)

KNOWN = {
    "file blocks/": elsewhere("its chain database (chainstate/), blocks included"),
    "file db.log": elsewhere("its wallet database (wallet/, RocksDB), which writes no Berkeley DB log"),
    "file wallet.dat": elsewhere("wallet/ (RocksDB)"),
    "file mncache.dat": elsewhere("its chain database (the masternode list, crates/divi-node/src/node.rs)"),
    "file mnpayments.dat": ("irondivid keeps no payment votes across a restart: it has them from peers again "
                            "(divid writes the file, and reads it only with a masternode list, "
                            "MasternodeModule.cpp:270-277)", absent),
    "file netfulfilled.dat": ("irondivid keeps no record of the sync requests it answered across a restart "
                              "(divid's expire after 5 minutes on regtest, chainparams.cpp:506)", absent),
    "file sporks/": elsewhere("its chain database (spork_<id> entries, crates/divi-network/src/spork.rs)"),
    "files only irondivid has": ("its own stores: wallet/ (the wallet), txindex/ (the transaction index, which "
                                 "divid keeps in blocks/index)", lambda c, i: i - c <= {"wallet/", "txindex/"}),
    "mncache.dat empty: start": MNCACHE,
    "mncache.dat truncated: start": MNCACHE,
    "mncache.dat garbage: start": MNCACHE,
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    """same: the two outcomes count as equal; raw: both, for a KNOWN shape"""
    global fails
    if INJECT == name:
        iron, same = f"{iron} (injected)", False
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is None or shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


def not_run(name, why):
    counts["KNOWN"] += 1
    print(f"KNOWN  {name}  not run  [known: {why}]", flush=True)


class Node:
    def __init__(self, name, binary, index, core):
        self.name, self.binary, self.core = name, binary, core
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"state{index}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.runs = 0
        self.use(os.path.join(WORK, name))

    def use(self, datadir):
        """Point the node at a data directory (made, with its divi.conf, if new)"""
        self.dir = datadir
        if not os.path.exists(datadir):
            os.makedirs(datadir)
        self.write_conf()

    def write_conf(self, extra=()):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=1",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", f"connect={HOST}:{PORT_BASE + 49}",
            # divid stores gossiped addresses only of a network it can reach, and IPv4
            # becomes reachable with a routable local address (AddLocal,
            # NetworkLocalAddressHelpers.cpp:81-104); nothing dials it
            "externalip=1.0.0.255",
        ] + list(extra)
        path = os.path.join(self.dir, "divi.conf")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)

    def net_dir(self):
        """Where the node keeps its regtest files: divid in regtest/, irondivid in the data directory"""
        return os.path.join(self.dir, "regtest") if self.core else self.dir

    def launch(self, *args):
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.{self.runs}")
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
        line = next((ln for ln in lines if ln.startswith("Error")), lines[0] if lines else "")
        for path in (os.path.join(self.dir, "regtest"), self.dir):
            line = line.replace(path, "<datadir>")
        return line

    def call(self, method, *params):
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

    def exited(self, secs):
        """The exit code if the node exits by itself within secs, else None"""
        try:
            code = self.proc.wait(timeout=secs)
            self.proc = None
            return code
        except subprocess.TimeoutExpired:
            return None


def show_start(o):
    return "up" if o[0] == "up" else f"exit {o[1]} \"{o[2][:140]}\""


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


# --- a peer of our own, over the wire -------------------------------------------------

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(cmd, payload=b""):
    return REGTEST_MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def net_addr(ip, port, with_time=None):
    raw = socket.inet_aton(ip)
    out = b"" if with_time is None else struct.pack("<I", with_time)
    return out + struct.pack("<Q", 1) + b"\0" * 10 + b"\xff\xff" + raw + struct.pack(">H", port)


def varint(n):
    if n < 0xfd:
        return bytes([n])
    return b"\xfd" + struct.pack("<H", n)


class Peer:
    """A peer that connects to a node from PEER, says version, and can send addr,
    ask getaddr, and collect what comes back"""

    def __init__(self, node, version=PROTOCOL):
        self.sock = socket.create_connection((HOST, node.p2p), timeout=10, source_address=(PEER, 0))
        self.buf = b""
        payload = (struct.pack("<iQq", version, 1, int(time.time())) + net_addr(HOST, node.p2p)
                   + net_addr(PEER, 0) + struct.pack("<Q", random.getrandbits(64))
                   + b"\x10/restart-state/" + struct.pack("<i", 0) + b"\x01")
        self.send("version", payload)

    def send(self, cmd, payload=b""):
        self.sock.sendall(message(cmd, payload))

    def messages(self, secs):
        """(command, payload) as they arrive for secs; ends early if the node closes"""
        deadline = time.time() + secs
        while time.time() < deadline:
            while len(self.buf) >= 24:
                n = struct.unpack("<I", self.buf[16:20])[0]
                if len(self.buf) < 24 + n:
                    break
                cmd = self.buf[4:16].rstrip(b"\0").decode(errors="replace")
                payload, self.buf = self.buf[24:24 + n], self.buf[24 + n:]
                if cmd == "version":
                    self.send("verack")
                elif cmd == "ping":
                    self.send("pong", payload)
                yield cmd, payload
            self.sock.settimeout(max(0.05, min(1.0, deadline - time.time())))
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            self.buf += data

    def handshake(self):
        """True once the node's verack came"""
        return any(cmd == "verack" for cmd, _ in self.until("verack", 15))

    def until(self, wanted, secs):
        for cmd, payload in self.messages(secs):
            yield cmd, payload
            if cmd == wanted:
                return

    def addresses(self, secs=15, quiet=4):
        """The addresses of the addr messages that come within secs (ends quiet
        seconds after the last one)"""
        got, last = set(), time.time()
        for cmd, payload in self.messages(secs):
            if cmd == "addr":
                n, off = payload[0], 1
                if n == 0xfd:
                    n, off = struct.unpack("<H", payload[1:3])[0], 3
                for k in range(n):
                    e = payload[off + 30 * k: off + 30 * (k + 1)]
                    got.add((socket.inet_ntoa(e[24:28]), struct.unpack(">H", e[28:30])[0]))
                last = time.time()
            if got and time.time() - last > quiet:
                break
        return got

    def closed(self, secs=5):
        """True when the node closes the connection within secs"""
        for _ in self.messages(secs):
            pass
        try:
            self.sock.settimeout(1)
            return self.sock.recv(1) == b""
        except socket.timeout:
            return False
        except OSError:
            return True

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# 100 public addresses, each in its own /16 (addrman buckets by group), on the
# regtest port; the nodes are connect-only, so none of them is ever dialled
GOSSIP = [(f"{1 + k}.{(7 * k) % 250 + 1}.{(13 * k) % 250 + 1}.{(31 * k) % 250 + 1}", 51476) for k in range(100)]


def gossip(node):
    p = Peer(node)
    ok = p.handshake()
    now = int(time.time())
    payload = varint(len(GOSSIP)) + b"".join(net_addr(ip, port, now - 600) for ip, port in GOSSIP)
    p.send("addr", payload)
    for _ in p.messages(3):
        pass
    p.close()
    return ok


def ask(node):
    """What the node answers a getaddr from a new inbound peer with: how many of
    the gossiped addresses, and whether anything else came"""
    try:
        p = Peer(node)
    except OSError as e:
        return f"no connection ({e.__class__.__name__})"
    if not p.handshake():
        p.close()
        return "no handshake"
    p.send("getaddr")
    got = p.addresses()
    p.close()
    known = got & set(GOSSIP)
    # divid gives 23% of what it holds (ADDRMAN_GETADDR_MAX_PCT); its buckets can
    # drop one or two of the 100 on a collision, so a few less still count
    n = len(known)
    share = "none" if n == 0 else "about 23% of them" if 15 <= n <= 23 else f"{n} of them"
    return share + (f" + {len(got - known)} other" if got - known else "")


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0, True)
I = Node("irondivid", IRONDIVID, 1, False)


def start_both(*args, after_kill=False):
    """Start both; after a kill -9 divid usually refuses its block database and
    needs -reindex (as scripts/unclean-stop records), so it gets it then"""
    outs = []
    for n in (C, I):
        o = n.start(*args)
        if after_kill and o[0] == "exit" and "corruption" in o[2]:
            o = n.start(*args, "-reindex")
            n.reindexed = True
        outs.append(o)
    for n, o in zip((C, I), outs):
        if o[0] != "up":
            print(f"FAIL   setup: {n.name} did not start: {show_start(o)}", flush=True)
            sys.exit(1)


def stop_both():
    for n in (C, I):
        n.stop()


# --- the files of a new data directory -------------------------------------------------

start_both()
stop_both()


def names(node):
    """The files of the data directory, divid's regtest/ folder merged into it"""
    out = set()
    for d in {node.dir, node.net_dir()}:
        for e in os.listdir(d):
            if node.core and d == node.dir and e == "regtest":
                continue
            out.add(e + ("/" if os.path.isdir(os.path.join(d, e)) else ""))
    return out


c_names, i_names = names(C), names(I)
for name in sorted(c_names):
    row(f"file {name}", "present", "present" if name in i_names else "absent", name in i_names)
row("files only irondivid has", "-", ",".join(sorted(i_names - c_names)) or "-", not (i_names - c_names),
    (c_names, i_names))

# --- addresses learnt from gossip --------------------------------------------------------

start_both()
for n in (C, I):
    if not gossip(n):
        print(f"FAIL   setup: {n.name}: the test peer got no verack", flush=True)
        sys.exit(1)
c, i = ask(C), ask(I)
row("getaddr after addr gossip", c, i, c == i)
stop_both()
start_both()
c, i = ask(C), ask(I)
row("getaddr after a clean restart", c, i, c == i)
for n in (C, I):
    n.kill()
start_both(after_kill=True)
c, i = ask(C), ask(I)
row("getaddr after a kill -9 and start (nothing new since the clean stop)", c, i, c == i)
for n in (C, I):
    gossip(n)
for n in (C, I):
    n.kill()
start_both(after_kill=True)
c, i = ask(C), ask(I)
row("getaddr after gossip, then a kill -9 and start", c, i, c == i)
c = len(C.rpc("getpeerinfo"))
i = len(I.rpc("getpeerinfo"))
row("connections after the restart (connect-only, nothing to dial)", c, i, c == i)

# --- bans ----------------------------------------------------------------------------------


def banned(node):
    out = node.call("listbanned")
    if out[0] != "ok":
        return f"error {out[1]}"
    return PEER in json.dumps(out[1])


def old_peer(node):
    """A peer with a version below divid's minimum (70915): banned, local or not
    (main.cpp:370-377)"""
    try:
        p = Peer(node, version=70000)
    except OSError as e:
        return f"no connection ({e.__class__.__name__})"
    closed = p.closed(8)
    p.close()
    return "closed" if closed else "kept"


def reconnect(node):
    try:
        p = Peer(node)
    except OSError as e:
        return f"no connection ({e.__class__.__name__})"
    ok = p.handshake()
    p.close()
    return "handshake" if ok else "refused"


c, i = old_peer(C), old_peer(I)
row("a peer of an old protocol version", c, i, c == i)
time.sleep(1)
c, i = banned(C), banned(I)
row("listbanned names it", c, i, c == i)
c, i = reconnect(C), reconnect(I)
row("it connects again while banned", c, i, c == i)
stop_both()
start_both()
c, i = banned(C), banned(I)
row("listbanned names it after a restart", c, i, c == i)
c, i = reconnect(C), reconnect(I)
row("it connects again after the restart", c, i, c == i)
old_peer(C), old_peer(I)
time.sleep(1)
for n in (C, I):
    n.call("clearbanned")
c, i = banned(C), banned(I)
row("listbanned after clearbanned", c, i, c == i)
c, i = reconnect(C), reconnect(I)
row("it connects again after clearbanned", c, i, c == i)

# --- the masternode list ---------------------------------------------------------------------

c, i = len(C.rpc("listmasternodes")), len(I.rpc("listmasternodes"))
row("listmasternodes after a restart", c, i, c == i)
not_run("masternode list and payment votes kept across a restart",
        "regtest has no masternode network to fill the list or send votes; with an empty list there is "
        "nothing to keep (divid writes an empty mncache.dat and skips mnpayments.dat, MasternodeModule.cpp:262-275)")
stop_both()

# --- damaged cache files ------------------------------------------------------------------------

def damaged(fname, label, content):
    """Plant `content` as fname in each stopped node's network folder, start,
    stop cleanly, and say what the start did and what the file holds after"""
    outs = []
    for n in (C, I):
        path = os.path.join(n.net_dir(), fname)
        with open(path, "wb") as f:
            f.write(content)
        o = n.start()
        if o[0] == "up":
            n.stop()
        after = (open(path, "rb").read() if os.path.exists(path) else None)
        state = ("gone" if after is None else "as planted" if after == content
                 else "empty" if not after else "rewritten")
        outs.append((o, state))
    (c, cs), (i, is_) = outs
    row(f"{fname} {label}: start", show_start(c), show_start(i),
        c[0] == i[0] and (c[0] == "up" or (c[1], c[2]) == (i[1], i[2])), (c, i))
    row(f"{fname} {label}: the file after a clean stop", cs, is_, cs == is_, (cs, is_))
    return outs


for fname in ("peers.dat", "mncache.dat"):
    for label, content in (("empty", b""), ("truncated", None), ("garbage", secrets.token_bytes(300))):
        if content is None:
            # The node's own file, cut in half
            src = os.path.join(C.net_dir(), fname)
            whole = open(src, "rb").read() if os.path.exists(src) else b"\0" * 64
            content = whole[:len(whole) // 2]
        damaged(fname, label, content)
        # The next case starts from a clean file again
        for n in (C, I):
            p = os.path.join(n.net_dir(), fname)
            if os.path.exists(p):
                os.remove(p)
            if n.start()[0] == "up":
                n.stop()

# --- block import ----------------------------------------------------------------------------------

# divid mines 30 blocks into its own block file; that file is what both import
start_both()
C.rpc("setgenerate", 30)
tip = C.rpc("getbestblockhash")
stop_both()
blk = os.path.join(WORK, "blk00000.dat")
shutil.copy(os.path.join(C.net_dir(), "blocks", "blk00000.dat"), blk)
with open(blk, "rb") as f:
    data = f.read()
# The records: magic, size, block; the block of height 15 gets a bad byte in its merkle root
records, off = [], 0
while off + 8 <= len(data) and data[off:off + 4] == REGTEST_MAGIC:
    size = struct.unpack("<I", data[off + 4:off + 8])[0]
    records.append((off + 8, size))
    off += 8 + size
bad = bytearray(data)
if len(records) > 15:
    start15 = records[15][0]
    bad[start15 + 36] ^= 0xFF
bad_blk = os.path.join(WORK, "blk-bad.dat")
with open(bad_blk, "wb") as f:
    f.write(bytes(bad))
print(f"# divid's block file: {len(records)} blocks, tip {tip[:16]}", flush=True)


def fresh(tag):
    for n in (C, I):
        n.use(os.path.join(WORK, f"{n.name}.{tag}"))


def import_case(name, args=(), bootstrap=None, stop_after=False):
    """Start each node on a new data directory with the import; height and tip
    once it has settled; with stop_after, the exit and then a normal start"""
    fresh(name.replace(" ", "-").replace("/", "-").replace("=", "-"))
    outs = []
    for n in (C, I):
        if bootstrap:
            # Both look for it in divid's network folder, <datadir>/regtest
            # (GetDataDir, init.cpp:699; irondivid main.rs core_network_dir)
            os.makedirs(os.path.join(n.dir, "regtest"), exist_ok=True)
            shutil.copy(bootstrap, os.path.join(n.dir, "regtest", "bootstrap.dat"))
        if stop_after:
            n.launch(*args)
            code = n.exited(120)
            if code is None:
                n.kill()
            o = n.start()
            res = [f"exit {code}" if code is not None else "still running after 120 s"]
        else:
            o = n.start(*args)
            res = []
        if o[0] != "up":
            outs.append(res + [show_start(o)])
            continue
        last = None
        for _ in range(60):
            h = n.rpc("getblockcount")
            if h == last:
                break
            last = h
            time.sleep(1)
        best = n.rpc("getbestblockhash")
        res += [f"height {last}", "tip of divid's file" if best == tip else f"tip {best[:12]}"]
        if bootstrap:
            nd = os.path.join(n.dir, "regtest")
            res.append("bootstrap.dat.old" if os.path.exists(os.path.join(nd, "bootstrap.dat.old"))
                       else "bootstrap.dat kept" if os.path.exists(os.path.join(nd, "bootstrap.dat")) else "no file")
        n.stop()
        outs.append(res)
    c, i = outs
    row(name, "; ".join(c), "; ".join(i), c == i, (c, i))
    return c, i


import_case("-loadblock=<divid's blk00000.dat>", [f"-loadblock={blk}"])
import_case("-loadblock with -stopafterblockimport", [f"-loadblock={blk}", "-stopafterblockimport"], stop_after=True)
import_case("bootstrap.dat in the data directory", bootstrap=blk)
import_case("-loadblock of a file with a bad block at height 15", [f"-loadblock={bad_blk}"])
import_case("-loadblock=<a missing file>", [f"-loadblock={os.path.join(WORK, 'missing.dat')}"])

# -reindex after an import: the imported chain is kept
fresh("reindex")
outs = []
for n in (C, I):
    if n.start(f"-loadblock={blk}")[0] == "up":
        wait_for(lambda: n.rpc("getblockcount") == len(records) - 1, 60)
        n.stop()
    o = n.start("-reindex")
    if o[0] == "up":
        wait_for(lambda: n.rpc("getblockcount") == len(records) - 1, 120)
        outs.append(f"height {n.rpc('getblockcount')}")
        n.stop()
    else:
        outs.append(show_start(o))
row("-reindex after an import", outs[0], outs[1], outs[0] == outs[1])

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
