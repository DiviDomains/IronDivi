#!/usr/bin/env python3
"""Clocks and block times of Divi Core divid and of irondivid, side by side on
regtest. Started by run.sh, which owns the work directory and stops the nodes.

Each node pair runs the same steps and their replies are compared. A row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL. Times
are compared relative to the node's own mocked clock, a block's median time
past or the block it was offered, so that the two nodes, which mine their own
chains, can be compared. Exit code = FAILs.
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
INJECT = os.environ.get("NETWORK_TIME_INJECT", "")
HOST = "127.0.0.2"
MAGIC = bytes([0xA1, 0xCF, 0x7E, 0xAC])
RPC_TIMEOUT = 300
START_TIMEOUT = 300
# Divi Core's MaxFutureBlockDrift (Settings.cpp:215-218) and the PoW limit (BlockCheckingHelpers.cpp:30)
POS_DRIFT, POW_DRIFT = 180, 7200

# Differences listed in README.md, one per row name: (reason, shape(core, iron))
KNOWN = {}

fails = 0


def show(v):
    return json.dumps(v, sort_keys=True, default=str)[:300]


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = KNOWN.get(name)
    if listed:
        reason, shape = listed
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
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf=()):
        self.name, self.binary = name, binary
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        user = "nwt" + name.replace("-", "")
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.notify = os.path.join(WORK, name + ".blocks")
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
            f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "listen=1", "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", "connect=0", "checkblockindex=0",
            f"blocknotify=echo %s >> {self.notify}",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        del password
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer")

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:160]}")
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

    def notified(self):
        try:
            with open(self.notify) as f:
                return len(f.read().split())
        except OSError:
            return 0

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
        self.log.close()


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def frame(command, payload):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def netaddr(ip="0.0.0.0", port=0):
    return struct.pack("<Q", 1) + b"\0" * 10 + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


class Peer:
    """A script peer from 127.0.0.10 (one address: one time sample, which alone moves no offset) that offers blocks
    with an inv and serves the header and the block when asked, and keeps the reject messages it is sent"""

    def __init__(self, node):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(("127.0.0.10", 0))
        self.s.settimeout(30)
        self.s.connect((HOST, node.p2p))
        version = (struct.pack("<iQq", 70915, 1, int(time.time())) + netaddr() + netaddr()
                   + struct.pack("<Q", secrets.randbits(64)) + b"\x0f/network-time:1/" + struct.pack("<i", 0) + b"\x01")
        self.s.sendall(frame("version", version))
        self.offers = {}
        self.rejects = []
        self.lock = threading.Lock()
        self.alive = True
        while self.read()[0] != "verack":
            pass
        self.s.sendall(frame("verack", b""))
        threading.Thread(target=self.serve, daemon=True).start()

    def read(self):
        h = b""
        while len(h) < 24:
            chunk = self.s.recv(24 - len(h))
            if not chunk:
                raise ConnectionError("closed")
            h += chunk
        n = struct.unpack("<I", h[16:20])[0]
        p = b""
        while len(p) < n:
            chunk = self.s.recv(n - len(p))
            if not chunk:
                raise ConnectionError("closed")
            p += chunk
        return h[4:16].rstrip(b"\0").decode(), p

    def serve(self):
        self.s.settimeout(None)
        try:
            while self.alive:
                cmd, payload = self.read()
                if cmd == "ping":
                    self.s.sendall(frame("pong", payload))
                elif cmd == "reject":
                    with self.lock:
                        self.rejects.append(payload)
                elif cmd == "getheaders":
                    for header, _ in self.offers.values():
                        self.s.sendall(frame("headers", b"\x01" + header + b"\x00"))
                elif cmd == "getdata":
                    for inv_hash, (_, raw) in list(self.offers.items()):
                        if inv_hash in payload:
                            self.s.sendall(frame("block", raw))
        except (OSError, ConnectionError, ValueError):
            pass

    def offer(self, block_hex, block_hash):
        raw = bytes.fromhex(block_hex)
        version = struct.unpack("<i", raw[:4])[0]
        inv_hash = bytes.fromhex(block_hash)[::-1]
        self.offers = {inv_hash: (raw[:80 + (32 if version > 3 else 0)], raw)}
        self.s.sendall(frame("inv", b"\x01" + struct.pack("<I", 2) + inv_hash))

    def reject_reasons(self):
        out = []
        with self.lock:
            for p in self.rejects:
                n = p[0]
                msg = p[1:1 + n].decode(errors="replace")
                code = p[1 + n]
                m = p[2 + n]
                out.append((msg, code, p[3 + n:3 + n + m].decode(errors="replace")))
        return out

    def close(self):
        self.alive = False
        try:
            self.s.close()
        except OSError:
            pass


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


def offer(node, block_hex, block_hash, peer=None):
    """Offer the block from a script peer; ("taken",) once the node has it, else the reject messages it sent"""
    own = peer is None
    peer = peer or Peer(node)
    try:
        peer.offer(block_hex, block_hash)
        if wait_for(lambda: node.call("getblock", block_hash)[0] == "ok", 8):
            return ("taken",)
        return ("refused", peer.reject_reasons())
    finally:
        if own:
            peer.close()


def tip(node):
    return node.rpc("getblock", node.rpc("getbestblockhash"))


def mtp(node, block=None):
    """Median time past of `block` (default the tip), from the times of it and its 10 parents"""
    b = block or tip(node)
    times = []
    for _ in range(11):
        times.append(b["time"])
        if "previousblockhash" not in b:
            break
        b = node.rpc("getblock", b["previousblockhash"])
    return sorted(times)[len(times) // 2]


def gen(node, n=1):
    """setgenerate n: ("ok", None) or the error"""
    out = node.call("setgenerate", n)
    return out if out[0] == "err" else ("ok",)


def err_shape(out):
    return out if out[0] == "ok" else (out[0], out[1], out[2].split("\n")[0])


def both(fn):
    return fn(core), fn(iron)


def mine_with_clock(node, start, blocks, step=60):
    """Mine `blocks` blocks one at a time, the mocked clock `step` s on before each"""
    t = start
    for _ in range(blocks):
        t += step
        node.rpc("setmocktime", t)
        out = gen(node)
        if out[0] != "ok":
            raise RuntimeError(f"{node.name} setgenerate at {t}: {out}")
    return t


# --- part 1: setmocktime, offsets, the blocks each node makes on its own clock ----------------------------------


core = iron = None
try:
    core = Node("divid", DIVID, 0)
    iron = Node("irondivid", IRONDIVID, 1)

    for params in ([], ["x"], [1.5], [None], [1, 2]):
        c, i = both(lambda n: err_shape(n.call("setmocktime", *params)))
        row(f"setmocktime {json.dumps(params)}", c, i)
    c, i = both(lambda n: n.call("setmocktime", 0))
    row("setmocktime 0", c, i)
    c, i = both(lambda n: (n.rpc("getinfo")["timeoffset"], n.rpc("getnetworkinfo")["timeoffset"]))
    row("timeoffset (getinfo, getnetworkinfo) with no peer", c, i)
    c, i = both(lambda n: n.rpc("getpeerinfo"))
    row("getpeerinfo with no peer", c, i)

    # A chain three days old by the system clock: the node's own blocks take its mocked time
    t0 = int(time.time()) - 3 * 86400
    c, i = both(lambda n: (n.rpc("setmocktime", t0), gen(n), tip(n)["time"] - t0)[1:])
    row("a work block's time on a mocked clock (time - mock)", c, i)

    # A clock set back before the tip: the block is at the median time past + 1
    c, i = both(lambda n: (n.rpc("setmocktime", t0 - 3600), gen(n), tip(n)["time"] - mtp(n, n.rpc(
        "getblock", tip(n)["previousblockhash"])))[1:])
    row("a work block on a clock behind the median time (time - parent's median)", c, i)

    # Proof of work up to 100, then proof of stake
    c, i = both(lambda n: mine_with_clock(n, t0, 100 - n.rpc("getblockcount")))
    ends = {"divid": c, "irondivid": i}
    row("100 work blocks mined", [core.rpc("getblockcount")], [iron.rpc("getblockcount")])

    def stake_row(node):
        clock = ends[node.name] + 60
        node.rpc("setmocktime", clock)
        out = gen(node)
        if out[0] != "ok":
            return err_shape(out)
        b = tip(node)
        # The search starts at the clock (past the median time) and goes back at most 45 s
        return ("block", b["height"], -45 < b["time"] - clock <= 0, b["time"] > mtp(node, node.rpc(
            "getblock", b["previousblockhash"])))
    c, i = both(stake_row)
    row("a stake block on a mocked clock (height, within 45 s before it, past the median)", c, i)

    def skewed_stake(behind):
        def f(node):
            m = mtp(node)
            node.rpc("setmocktime", m - behind)
            out = gen(node)
            if out[0] != "ok":
                return err_shape(out)
            b = tip(node)
            return ("block", m < b["time"] <= m - behind + POS_DRIFT - 1)
        return f
    # The latest time allowed is the clock + 179, the earliest the median time + 1: nothing is left once the
    # clock is 178 s or more behind the median time (PoSTransactionCreator.cpp:335-341)
    for behind in (177, 178, 300):
        c, i = both(skewed_stake(behind))
        row(f"stake with the clock {behind} s behind the median time", c, i)
    c, i = both(skewed_stake(100))
    # Kernel luck: a block or none, but never outside the window
    row("stake with the clock 100 s behind the median time (block inside the window, or none)",
        c[:2] if c[0] == "block" else "none", i[:2] if i[0] == "block" else "none",
        same=(c[0] != "block" or c[1]) and (i[0] != "block" or i[1]))

    # Sporks on the mocked clock: a time spork is active once past GetAdjustedTime (spork.cpp:379)
    for clock in (4070908800, 4070908801):
        c, i = both(lambda n: (n.rpc("setmocktime", clock), n.rpc("spork", "active"))[1])
        row(f"spork active with the clock at {clock}", c, i)

    # The wallet and the mempool on a clock two hours ahead of the system's
    ahead = int(time.time()) + 7200

    def wallet_times(node):
        node.rpc("setmocktime", ahead)
        txid = node.rpc("sendtoaddress", node.rpc("getnewaddress"), 1)
        pool = node.rpc("getrawmempool", True)[txid]["time"] - ahead
        tx = node.rpc("gettransaction", txid)
        node.rpc("setmocktime", ahead + 120)
        out = gen(node)
        mined = node.rpc("gettransaction", txid)
        return {"mempool time": pool, "time": tx["time"] - ahead, "timereceived": tx["timereceived"] - ahead,
                "staked": out[0], "time in a block": mined.get("time", 0) - ahead,
                "blocktime - its block": mined.get("blocktime", 0) - tip(node)["time"]}
    c, i = both(wallet_times)
    row("a wallet send on a clock 2 h ahead (times - mock)", c, i)

    def staked_tx_time(node):
        b = tip(node)
        stake = node.rpc("gettransaction", b["tx"][1])
        return {"time - block": stake["time"] - b["time"], "timereceived - mock": stake["timereceived"] - ahead - 120}
    c, i = both(staked_tx_time)
    row("the coinstake of a block dated ahead of the system clock (wallet times)", c, i)
finally:
    for n in (core, iron):
        if n:
            n.stop()

# --- part 2: blocks a divid makes, offered to a divid and an irondivid on chosen clocks -----------------------------

maker = core = iron = None
try:
    maker = Node("maker", DIVID, 2)
    core = Node("divid-2", DIVID, 3)
    iron = Node("irondivid-2", IRONDIVID, 4)
    t0 = int(time.time()) - 2 * 86400
    maker.rpc("setmocktime", t0)
    hexes = []
    t = t0
    for _ in range(99):
        t += 60
        maker.rpc("setmocktime", t)
        if gen(maker)[0] != "ok":
            raise RuntimeError("maker could not mine")
        best = maker.rpc("getbestblockhash")
        hexes.append((maker.rpc("getblock", best, False), best))

    # Offered on the system clock: two days old, so each node is in its initial block download
    def take_all(node):
        peer = Peer(node)
        try:
            return [offer(node, h, b, peer) for h, b in hexes].count(("taken",))
        finally:
            peer.close()
    c, i = both(take_all)
    row("99 two-day-old blocks taken", c, i)
    time.sleep(2)
    c, i = both(lambda n: n.notified())
    row("blocknotify for blocks older than 6 h", c, i)

    def offer_at(block, ahead_of_clock):
        """Each node's clock set so that the block is `ahead_of_clock` s in its future; what it did, its count"""
        hexblock = maker.rpc("getblock", block["hash"], False)

        def f(node):
            node.rpc("setmocktime", block["time"] - ahead_of_clock)
            return offer(node, hexblock, block["hash"]), node.rpc("getblockcount")
        return both(f)

    # Proof of work, block 100: 2 hours ahead of the clock is the limit
    t += 60
    maker.rpc("setmocktime", t)
    gen(maker)
    pow_block = maker.rpc("getblock", maker.rpc("getbestblockhash"))
    c, i = offer_at(pow_block, POW_DRIFT + 1)
    row("work block 7201 s ahead of the clock", c, i)
    c, i = offer_at(pow_block, POW_DRIFT)
    row("the same block 7200 s ahead (offered again)", c, i)
    # A block inside 6 h of the clock ends the initial block download (ChainSyncHelpers.cpp:42-49):
    # divid signals that tip, the first it runs -blocknotify for (ChainExtensionService.cpp:556-565)
    time.sleep(2)
    c, i = both(lambda n: n.notified())
    row("blocknotify once a block ends the initial download", c, i)

    # Proof of stake: 180 s ahead of the clock is the limit (Settings.cpp:215-218)
    t += 60
    maker.rpc("setmocktime", t)
    if gen(maker)[0] != "ok":
        raise RuntimeError("maker could not stake")
    pos_block = maker.rpc("getblock", maker.rpc("getbestblockhash"))
    c, i = offer_at(pos_block, POS_DRIFT + 1)
    row("stake block 181 s ahead of the clock", c, i)
    c, i = offer_at(pos_block, POS_DRIFT)
    row("the same block 180 s ahead (offered again)", c, i)

finally:
    for n in (maker, core, iron):
        if n:
            n.stop()

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
