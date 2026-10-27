#!/usr/bin/env python3
"""Sporks 13 to 16 in consensus, Divi Core divid and irondivid on one regtest
network, compared block by block.

Both kinds are given the same sporks before they start (see below): spork 16 sets
the lottery ticket minimum from height 150, spork 15 the block value from 200,
spork 13 the split of the block value from 300, and spork 14 the fees. Three
nodes with them: divid A (listens), irondivid I and divid B (both dial A). A
mines the proof-of-work blocks and pays stakes of different sizes to addresses of
all three wallets; then A, I and B take turns staking, so each daemon makes
blocks, lottery and treasury superblocks the other checks. Two more nodes, a divid
and an irondivid, are given no sporks; they follow A and stop where the sporks
begin to matter.

After every block the rows compare getlotteryblockwinners. Then, at chosen
heights, what a block created and what a treasury block paid are compared with
the rules and the sporks; blocks that pay one satoshi over what a spork allows,
and what the usual rule allows, are offered by a raw peer; a longer chain made by
A from before the first spork's height is taken by the other two; and the winners
and tips are compared after invalidateblock and reconsiderblock, a restart and
-reindex.

Nobody here holds the key that signs a regtest spork, so the sporks are written to
each node's own spork database before it starts: divid's `sporks` LevelDB (a
write-ahead log made here) and irondivid's chain database (the spork-seed tool in
the irondivid directory). Both load their database without checking the
signatures again (spork.cpp LoadSporksFromDB), and then act as with sporks they
accepted.

Each row prints PASS (the same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs. Started by run.sh, which owns the work
directory and stops the nodes.
"""

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import sys
import time
import urllib.error
import urllib.request
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
DUMP = os.environ.get("SPORK_CONSENSUS_DUMP", "")
SPORK_SEED = os.path.join(os.path.dirname(IRONDIVID), "spork-seed")

# Regtest (chainparams.cpp:473-498): last proof-of-work block 100; lottery from
# 101 every 10 blocks, treasury from 102 every 50 (until 500,
# LegacyBlockSubsidies.cpp:98-108); subsidies halve every 100 blocks
LAST_POW = 100
SPORK16_HEIGHT, SPORK15_HEIGHT, SPORK13_HEIGHT = 150, 200, 300
# The entries given (spork id, value; signed at second 1000). Spork 13 and 15 take
# effect only at a multiple of the halving interval (spork.cpp:98-99, :118-119).
SPORKS = [
    (10012, f"50;30;10;5;5;{SPORK13_HEIGHT}"),
    (10013, "10000;300;100000;20000;50;0"),
    (10014, f"2000;{SPORK15_HEIGHT}"),
    (10015, f"13500;{SPORK16_HEIGHT}"),
]
SIGNED_AT = 1000
# SPORK_CONSENSUS_SPORKS=15,16 gives only those (to find which one a build gets wrong; the
# amounts and heights of the other rows then do not hold)
_only = os.environ.get("SPORK_CONSENSUS_SPORKS")
if _only:
    SPORKS = [(i, v) for i, v in SPORKS if str(i - 9999) in _only.split(",")]


def is_lottery(h):
    return h % 10 == 0 and h > 101


def is_treasury(h):
    return h % 50 == 0 and h >= 102


END = 500
LOTTERY = [h for h in range(101, END) if is_lottery(h)]
TREASURY = [h for h in range(102, END) if is_treasury(h)]

KNOWN = {}
# The field order of each reply kind: compared once, in its own row at the end
order_seen = {}

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


def ordered(text):
    """JSON with objects as lists of (name, value), so field order is compared"""
    return json.loads(text, object_pairs_hook=lambda pairs: [("{}", pairs)], parse_float=str)


# --- keeping the sporks off the wire ---------------------------------------------------------
#
# A node that holds a spork it was given in its database offers it to every peer
# that asks, and the peer refuses it: the signature is not the network's. So the
# nodes dial each other through a relay that passes everything but the spork
# messages: it makes the listener's `sporkcount` say 0, and drops `getsporks` and
# `spork` both ways. Each node then holds its own sporks and trusts the peer
# about the rest.

class SporkFilter(threading.Thread):
    """Relays `listen` to `target`, message by message, without the spork messages"""

    def __init__(self, listen, target):
        super().__init__(daemon=True)
        self.target = target
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, listen))
        self.server.listen(8)
        self.start()

    def run(self):
        while True:
            try:
                client, _ = self.server.accept()
                upstream = socket.create_connection((HOST, self.target), timeout=10)
            except OSError:
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            # dialer to listener: no getsporks, no spork; listener to dialer: sporkcount 0, no spork
            for src, dst, drop, zero in ((client, upstream, ("getsporks", "spork"), False),
                                         (upstream, client, ("spork",), True)):
                threading.Thread(target=self.pump, args=(src, dst, drop, zero), daemon=True).start()

    @staticmethod
    def pump(src, dst, drop, zero):
        try:
            while True:
                head = b""
                while len(head) < 24:
                    part = src.recv(24 - len(head))
                    if not part:
                        raise EOFError
                    head += part
                size = struct.unpack("<I", head[16:20])[0]
                payload = b""
                while len(payload) < size:
                    part = src.recv(size - len(payload))
                    if not part:
                        raise EOFError
                    payload += part
                command = head[4:16].rstrip(b"\0").decode(errors="replace")
                if command in drop:
                    continue
                if zero and command == "sporkcount":
                    payload = bytes(4)
                    head = head[:16] + struct.pack("<I", 4) + sha256d(payload)[:4]
                dst.sendall(head + payload)
        except (OSError, EOFError):
            pass
        finally:
            for sock in (src, dst):
                try:
                    sock.close()
                except OSError:
                    pass


# --- a divid spork database, written before divid starts ----------------------------------

def _crc32c_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc32c_table()


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def leveldb_varint(n):
    out = b""
    while n >= 0x80:
        out += bytes([n & 0x7F | 0x80])
        n >>= 7
    return out + bytes([n])


def seed_core(net_dir):
    """divid's `sporks` LevelDB with the sporks above in it: a directory holding
    only a write-ahead log, which LevelDB makes a database of when it creates the
    rest and recovers the log. Key: the id as 4 bytes; value: the spork as divid
    stores it (id, value, time, signature)."""
    path = os.path.join(net_dir, "sporks")
    os.makedirs(path)
    records = b""
    for spork_id, value in SPORKS:
        text = value.encode()
        key = struct.pack("<i", spork_id)
        spork = (struct.pack("<i", spork_id) + compact(len(text)) + text + struct.pack("<q", SIGNED_AT)
                 + compact(65) + b"\x1f" * 65)
        records += b"\x01" + leveldb_varint(len(key)) + key + leveldb_varint(len(spork)) + spork
    batch = struct.pack("<QI", 1, len(SPORKS)) + records
    crc = crc32c(b"\x01" + batch)
    crc = ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + 0xA282EAD8) & 0xFFFFFFFF
    with open(os.path.join(path, "000003.log"), "wb") as f:
        f.write(struct.pack("<IHB", crc, len(batch), 1) + batch)


class Node:
    def __init__(self, name, binary, index, extra_conf, core, seeded):
        self.name, self.binary, self.core = name, binary, core
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"sb{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=sb{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}", "dnsseed=0", "staking=0",
            "txindex=1", "addressindex=1", "spentindex=1",
        ] + list(extra_conf)
        self.write_conf()
        self.proc = None
        if seeded:
            self.seed()
        self.start()

    def seed(self):
        if self.core:
            seed_core(os.path.join(self.dir, "regtest"))
        else:
            for spork_id, value in SPORKS:
                subprocess.run([SPORK_SEED, self.dir, str(spork_id), value, str(SIGNED_AT)], check=True)

    def write_conf(self, extra=()):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")

    def start(self, args=()):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"] + list(args), cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def raw_call(self, method, *params):
        """('ok', raw result text) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                text = r.read()
        except urllib.error.HTTPError as e:
            text = e.read() or b"{}"
        reply = json.loads(text, parse_float=str)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        # The result's own text, for field order
        res = json.loads(text, object_pairs_hook=lambda p: p, parse_float=str)
        return ("ok", dict(res)["result"])

    def call(self, method, *params):
        out = self.raw_call(method, *params)
        if out[0] == "ok":
            return ("ok", unpair(out[1]))
        return out

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
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
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def unpair(v):
    """A result read with field pairs kept: dicts again, but the field order of
    each object recorded under the key ' order'"""
    if isinstance(v, list) and v and all(isinstance(x, tuple) and len(x) == 2 for x in v):
        d = {k: unpair(x) for k, x in v}
        d[" order"] = [k for k, _ in v]
        return d
    if isinstance(v, list):
        return [unpair(x) for x in v]
    return v


def first_difference(a, b, path="$", kind=None):
    """Where two replies first differ, or None: field names, types and values,
    list items in order. The field order is recorded for `kind`'s order row."""
    if isinstance(a, dict) and isinstance(b, dict):
        if kind and a.get(" order") != b.get(" order"):
            order_seen.setdefault(kind, (path, a.get(" order"), b.get(" order")))
        for k in sorted((set(a) | set(b)) - {" order"}):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}", kind)
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]", kind)
            if d:
                return d
        return None
    if type(a) is not type(b) or a != b:
        return f"{path}: {json.dumps(a)[:80]} vs {json.dumps(b)[:80]}"
    return None


def short(out):
    if out[0] == "err":
        first = out[2].splitlines()[0] if out[2] else ""
        return f"error {out[1]} \"{first[:80]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict) and " order" not in v:
        return json.dumps(v)[:160]
    if isinstance(v, dict):
        return f"{len(v) - 1} fields"
    return json.dumps(v)[:60]


def usage_text(method, message):
    return message.startswith(method + " ") or message.startswith(method + "\n")


def dump(name, core, iron):
    if not DUMP:
        return
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True, default=str)


def compare(name, method, core, iron):
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and usage_text(method, core[2]):
            same = True
        if not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return same
    d = first_difference(core[1], iron[1], kind=method)
    if d:
        dump(name, core, iron)
    row(name, short(core), f"{short(iron)}  ({d})" if d else short(iron), d is None)
    return d is None


def both(name, method, *params, core=None):
    core = core or A
    return compare(name, method, core.call(method, *params), I.call(method, *params))


# Reply kinds whose field order has a row even when no difference was seen
ORDER_KINDS = ["getlotteryblockwinners", "getblock", "getrawtransaction"]


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
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced(nodes=None, secs=90):
    nodes = nodes or [A, I, B]
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in nodes}) == 1, secs)


def stake(node, n):
    """n blocks by `node`, one setgenerate at a time: a proof-of-stake block can
    be refused (-25) until the clock passes the median time of the last blocks"""
    for _ in range(n):
        start = node.rpc("getblockcount")
        if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok" and node.rpc("getblockcount") > start, 120):
            raise RuntimeError(f"{node.name} could not make block {start + 1}")
        if not synced():
            raise RuntimeError(f"the nodes did not follow {node.name}'s block {start + 1}")


# --- secp256k1, for signing a changed block as its staker would ---------------------------

P_FIELD = 2 ** 256 - 2 ** 32 - 977
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_POINT = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P_FIELD == 0:
        return None
    if p == q:
        m = 3 * p[0] * p[0] * pow(2 * p[1], -1, P_FIELD)
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P_FIELD)
    x = (m * m - p[0] - q[0]) % P_FIELD
    return (x, (m * (p[0] - x) - p[1]) % P_FIELD)


def ec_mul(k, p=G_POINT):
    out = None
    while k:
        if k & 1:
            out = ec_add(out, p)
        p = ec_add(p, p)
        k >>= 1
    return out


def sign_compact(secret, digest):
    """CKey::SignCompact: a recoverable signature of the 32-byte digest, low s,
    header 27 + recovery id + 4 (compressed key)"""
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(N_ORDER - 1) + 1
        R = ec_mul(k)
        r = R[0] % N_ORDER
        if r == 0:
            continue
        s = (z + r * secret) * pow(k, -1, N_ORDER) % N_ORDER
        if s == 0:
            continue
        recid = (R[1] & 1) | (2 if R[0] >= N_ORDER else 0)
        if s > N_ORDER // 2:
            s = N_ORDER - s
            recid ^= 1
        return bytes([27 + recid + 4]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    return raw[:-4]


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def p2pkh_script(address):
    return bytes([0x76, 0xa9, 0x14]) + b58decode(address)[1:] + bytes([0x88, 0xac])


# --- transactions and blocks as bytes ----------------------------------------------------

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def read_compact(b, pos):
    n = b[pos]
    if n < 0xfd:
        return n, pos + 1
    if n == 0xfd:
        return struct.unpack_from("<H", b, pos + 1)[0], pos + 3
    if n == 0xfe:
        return struct.unpack_from("<I", b, pos + 1)[0], pos + 5
    return struct.unpack_from("<Q", b, pos + 1)[0], pos + 9


def parse_tx(b, pos=0):
    """(tx dict, end position)"""
    start = pos
    version = struct.unpack_from("<i", b, pos)[0]
    pos += 4
    n, pos = read_compact(b, pos)
    vin = []
    for _ in range(n):
        prev = b[pos:pos + 36]
        pos += 36
        size, pos = read_compact(b, pos)
        script = b[pos:pos + size]
        pos += size
        seq = struct.unpack_from("<I", b, pos)[0]
        pos += 4
        vin.append([prev, script, seq])
    n, pos = read_compact(b, pos)
    vout = []
    for _ in range(n):
        value = struct.unpack_from("<q", b, pos)[0]
        pos += 8
        size, pos = read_compact(b, pos)
        vout.append([value, b[pos:pos + size]])
        pos += size
    lock = struct.unpack_from("<I", b, pos)[0]
    pos += 4
    return {"version": version, "vin": vin, "vout": vout, "lock": lock, "raw": b[start:pos]}, pos


def tx_bytes(tx):
    out = struct.pack("<i", tx["version"]) + compact(len(tx["vin"]))
    for prev, script, seq in tx["vin"]:
        out += prev + compact(len(script)) + script + struct.pack("<I", seq)
    out += compact(len(tx["vout"]))
    for value, script in tx["vout"]:
        out += struct.pack("<q", value) + compact(len(script)) + script
    return out + struct.pack("<I", tx["lock"])


def parse_block(b):
    header = b[:112]
    n, pos = read_compact(b, 112)
    txs = []
    for _ in range(n):
        tx, pos = parse_tx(b, pos)
        txs.append(tx)
    size, pos = read_compact(b, pos)
    return {"header": header, "txs": txs, "sig": b[pos:pos + size]}


def merkle_root(txids):
    layer = list(txids)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256d(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def block_bytes(block):
    return block["header"] + compact(len(block["txs"])) + b"".join(t["raw"] for t in block["txs"]) \
        + compact(len(block["sig"])) + block["sig"]


def wif_secret(wif):
    raw = b58decode(wif)
    return int.from_bytes(raw[1:33], "big")


def changed_block(node, good_hex, change):
    """The block with its coinstake's outputs changed by `change(vout)`, the
    coinstake signed again by `node`'s wallet, the merkle root and the block
    signature made again with the staker's key"""
    block = parse_block(bytes.fromhex(good_hex))
    stake_tx = block["txs"][1]
    vout = [list(o) for o in stake_tx["vout"]]
    change(vout)
    unsigned = dict(stake_tx, vout=vout, vin=[[p, b"", q] for p, _, q in stake_tx["vin"]])
    # The coin it spends is spent in `node`'s chain by the block itself, so its
    # script is given (prevtxs)
    prevtxs = []
    for prev, _, _ in stake_tx["vin"]:
        txid, n = prev[:32][::-1].hex(), struct.unpack("<I", prev[32:])[0]
        script = node.rpc("getrawtransaction", txid, 1)["vout"][n]["scriptPubKey"]["hex"]
        prevtxs.append({"txid": txid, "vout": n, "scriptPubKey": script})
    signed = node.rpc("signrawtransaction", tx_bytes(unsigned).hex(), prevtxs)
    if not signed.get("complete"):
        raise RuntimeError(f"{node.name} could not sign the changed coinstake")
    new_tx, _ = parse_tx(bytes.fromhex(signed["hex"]))
    block["txs"][1] = new_tx
    root = merkle_root([sha256d(t["raw"]) for t in block["txs"]])
    block["header"] = block["header"][:36] + root + block["header"][68:]
    # The staker: the coinstake's first stake output pays it (BlockSigning.cpp:47-66)
    script = vout[1][1]
    if not (len(script) == 25 and script[:3] == bytes([0x76, 0xa9, 0x14])):
        raise RuntimeError("the coinstake does not pay a key hash; cannot sign it again")
    address = b58check(bytes([139]) + script[3:23])
    secret = wif_secret(node.rpc("dumpprivkey", address))
    block["sig"] = sign_compact(secret, sha256d(block["header"]))
    return block_bytes(block).hex()


# --- a raw peer --------------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
AGENT = b"/spork-consensus:1/"


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def netaddr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(HOST) + struct.pack(">H", port)


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


def varstr(b, pos):
    n, pos = read_compact(b, pos)
    return b[pos:pos + n].decode(errors="replace"), pos + n


def offer_block(node, hexstr):
    """A raw peer sends the block to `node`: what it answers (its `reject`, its
    command, code and reason) and whether its tip is then the block"""
    sock = socket.create_connection((HOST, node.p2p), timeout=10)
    reject = None
    try:
        version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(node.p2p) + netaddr(0)
                   + secrets.token_bytes(8) + compact(len(AGENT)) + AGENT + struct.pack("<i", 0) + b"\x01")
        sock.sendall(message("version", version))
        got = set()
        deadline = time.time() + 15
        while got != {"version", "verack"} and time.time() < deadline:
            command, payload = read_message(sock)
            if command == "version":
                sock.sendall(message("verack"))
            if command in ("version", "verack"):
                got.add(command)
        if got != {"version", "verack"}:
            return ("ok", {"answer": "no handshake"})
        sock.sendall(message("block", bytes.fromhex(hexstr)))
        deadline = time.time() + 8
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                command, payload = read_message(sock)
            except socket.timeout:
                break
            except (EOFError, ConnectionError):
                reject = reject or "disconnected"
                break
            if command == "ping":
                sock.sendall(message("pong", payload))
            elif command == "reject":
                what, pos = varstr(payload, 0)
                code = payload[pos]
                why, pos = varstr(payload, pos + 1)
                reject = [what, code, why]
    except (EOFError, ConnectionError, socket.timeout) as e:
        reject = reject or f"connection ended ({e.__class__.__name__})"
    finally:
        sock.close()
    block_hash = sha256d(bytes.fromhex(hexstr)[:112])[::-1].hex()
    time.sleep(1)
    return ("ok", {"reject": reject, "tip is the block": node.rpc("getbestblockhash") == block_hash})


def isolate(node, alone):
    """Restart `node` on its datadir, alone (no peer) or back on the network"""
    node.stop()
    if alone:
        node.write_conf()
        # divid keeps the first value of an option, so listen=1 goes too
        lines = [l for l in node.lines if not l.startswith(("connect=", "listen="))]
        fd = os.open(os.path.join(node.dir, "divi.conf"), os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines + ["listen=0"]) + "\n")
    else:
        node.write_conf()
    node.start()
    if not node.wait_ready():
        raise RuntimeError(f"{node.name} did not start again")


def stake_alone(node):
    start = node.rpc("getblockcount")
    if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok" and node.rpc("getblockcount") > start, 120):
        raise RuntimeError(f"{node.name} could not make block {start + 1} alone")
    return node.rpc("getblock", node.rpc("getbestblockhash"), False)


def to_height(height):
    while A.rpc("getblockcount") < height:
        next_block()


# --- the nodes -----------------------------------------------------------------------

A = Node("divid-A", DIVID, 0, ["listen=1"], core=True, seeded=True)
if not A.wait_ready():
    print(f"FAIL   start: divid A did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
FILTERS = {}
for n_filter, name in enumerate(("irondivid", "divid-B", "divid-plain", "irondivid-plain")):
    FILTERS[name] = PORT_BASE + 20 + n_filter
    SporkFilter(FILTERS[name], A.p2p)  # A has started: its port, moved if PORT_BASE was taken
I = Node("irondivid", IRONDIVID, 1, ["listen=1", f"connect={HOST}:{FILTERS['irondivid']}"], core=False, seeded=True)
B = Node("divid-B", DIVID, 2, ["listen=1", f"connect={HOST}:{FILTERS['divid-B']}"], core=True, seeded=True)
# Two nodes that were given no sporks: they hold the usual rules
DP = Node("divid-plain", DIVID, 3, ["listen=1", f"connect={HOST}:{FILTERS['divid-plain']}"], core=True, seeded=False)
IP = Node("irondivid-plain", IRONDIVID, 4, ["listen=1", f"connect={HOST}:{FILTERS['irondivid-plain']}"], core=False, seeded=False)
for n in (I, B, DP, IP):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
print(f"# divid {A.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

both("spork show with the sporks given", "spork", "show")
both("spork active with the sporks given", "spork", "active")
compare("spork show without the sporks given", "spork", DP.call("spork", "show"), IP.call("spork", "show"))

t0 = time.time()
A.rpc("setgenerate", LAST_POW)
if not synced():
    print("FAIL   setup: the nodes did not follow A's proof-of-work blocks", flush=True)
    sys.exit(1)
# Stakes of different sizes, each over 10 000 DIVI, to addresses of each wallet;
# I and B hold only these coins. A keeps its coinbases and stakes with them
# when neither I nor B has a coin to stake.
dup = I.rpc("getnewaddress")
STAKES = {A: [(None, 10800)], I: [(dup, 10500), (dup, 11000), (None, 11000), (None, 12000)],
          B: [(None, 10200), (None, 13000), (None, 11500)]}
for node, coins in STAKES.items():
    for address, size in coins:
        A.rpc("sendtoaddress", address or node.rpc("getnewaddress"), size)
stake(A, 1)
print(f"# {A.rpc('getblockcount')} blocks after {time.time() - t0:.0f} s", flush=True)


def winners(node, *height):
    out = node.call("getlotteryblockwinners", *height)
    return out[1] if out[0] == "ok" else None


def winner_addresses(node, height):
    w = winners(node, height) or {}
    return [c.get("Address") for c in w.get("Lottery Candidates", [])]


made_by = {}


def pick(height):
    """Who makes block `height`: at a superblock height divid A and irondivid in
    turn, so each daemon makes superblocks the other checks; otherwise I, then
    B, when it has a coin to stake, else A"""
    if height in LOTTERY or height in TREASURY:
        order = [A, I, B] if (height // 10) % 2 else [I, B, A]
    else:
        order = [I, B, A]
    for n in order:
        if n is A or stakeable(n):
            return n
    return A


coinstake_tx = {}


def stakeable(node):
    """Whether the wallet has a coin it may stake with: 10 blocks deep, or 20
    for a coinstake's output (wallet.cpp:1456)"""
    for coin in node.rpc("listunspent"):
        txid, depth = coin["txid"], coin["confirmations"]
        if txid not in coinstake_tx:
            tx = node.rpc("getrawtransaction", txid, 1)
            coinstake_tx[txid] = len(tx["vout"]) > 1 and tx["vout"][0]["value"] in ("0.00000000", "0.0", 0) \
                and "coinbase" not in tx["vin"][0]
        if depth >= (20 if coinstake_tx[txid] else 10):
            return True
    return False


def next_block():
    h = A.rpc("getblockcount") + 1
    node = pick(h)
    stake(node, 1)
    made_by[h] = node.name
    return h, node


def winners_row(label):
    both(f"getlotteryblockwinners {label}", "getlotteryblockwinners")


# --- what a block should create, from Divi Core's rules and the sporks given ---------------------

COIN = 100_000_000


def subsidy(h):
    """The block value in DIVI: the halving schedule (every 100 blocks on regtest,
    LegacyBlockSubsidies.cpp:15-28), or spork 15's from its height"""
    return 2000 if h >= SPORK15_HEIGHT else max(1250 - 100 * max(h // 100 - 1, 0), 250)


def split(h):
    """Stake, masternode, treasury, proposals, charity, in percent: spork 13's
    from its height"""
    return (50, 30, 10, 5, 5) if h >= SPORK13_HEIGHT else (38, 45, 16, 0, 1)


def rewards(h):
    """(stake, masternode, treasury, charity), in satoshis, of one block"""
    if h <= LAST_POW:
        return (subsidy(h) * COIN, 0, 0, 0)
    d = (subsidy(h) - 50) * COIN
    st, mn, tr, pr, ch = split(h)
    return (d * st // 100, d * mn // 100, d * tr // 100, d * ch // 100)


def expected_mint(h):
    st, mn, _, _ = rewards(h)
    return st + mn


def treasury_due(h):
    """What the treasury block at `h` pays the treasury and the charity: the
    rewards at both ends of its cycle, weighted around the halving
    (BlockSubsidyProvider.cpp:19-37)"""
    prior = h - 50
    boundary = h // 100 * 100
    pw, cw = boundary - prior, h - boundary
    rp, rc = rewards(prior), rewards(h)
    return (rp[2] * pw + rc[2] * cw, rp[3] * pw + rc[3] * cw)


def sats(v):
    return int(Decimal(str(v)) * COIN)


def coinstake_of(node, h):
    block = node.rpc("getblock", node.rpc("getblockhash", h))
    return node.rpc("getrawtransaction", block["tx"][1], 1)


def mint_of(node, h):
    """What the coinstake at `h` creates: its outputs less its inputs, in satoshis"""
    cs = coinstake_of(node, h)
    created = sum(sats(o["value"]) for o in cs["vout"])
    spent = 0
    for vin in cs["vin"]:
        prev = node.rpc("getrawtransaction", vin["txid"], 1)
        spent += sats(prev["vout"][vin["vout"]]["value"])
    return created - spent


def paid_to(node, h, address):
    script = p2pkh_script(address).hex()
    return sum(sats(o["value"]) for o in coinstake_of(node, h)["vout"] if o["scriptPubKey"]["hex"] == script)


def mint_row(h):
    a, b, want = mint_of(A, h), mint_of(I, h), expected_mint(h)
    row(f"block {h} creates {want / COIN:g} DIVI: the stake and masternode rewards", f"{a / COIN:g}", f"{b / COIN:g}",
        a == b == want)


def treasury_row(h):
    want = treasury_due(h)
    a = (paid_to(A, h, TREASURY_ADDRESS), paid_to(A, h, CHARITY_ADDRESS))
    b = (paid_to(I, h, TREASURY_ADDRESS), paid_to(I, h, CHARITY_ADDRESS))
    row(f"treasury block {h} pays {want[0] / COIN:g} and {want[1] / COIN:g} DIVI",
        f"{a[0] / COIN:g} and {a[1] / COIN:g}", f"{b[0] / COIN:g} and {b[1] / COIN:g}", a == b == want)


def bump_stake(delta):
    """A change for `changed_block`: the staker's own output pays `delta` satoshis more"""
    def change(vout):
        vout[1][0] += delta
    return change


def offer_variants(height, variants):
    """A, alone, makes the block at `height`; each changed copy is offered by a
    raw peer to divid B and to irondivid, then the block as made; A then joins
    again"""
    to_height(height - 1)
    isolate(A, True)
    good = stake_alone(A)
    for name, change in variants:
        bad = changed_block(A, good, change)
        compare(f"block {height} {name}: offered by a raw peer", "block", offer_block(B, bad), offer_block(I, bad))
    compare(f"block {height} as made: offered by a raw peer", "block", offer_block(B, good), offer_block(I, good))
    isolate(A, False)
    if not synced(secs=180):
        raise RuntimeError("A did not join the network again")


def to_height(height):
    while A.rpc("getblockcount") < height:
        next_block()


def reorg_across(fork, old_tip):
    """A, alone, makes a longer chain from `fork`; divid B and irondivid then
    take it in place of the one they hold, across the heights of the sporks"""
    target = A.rpc("getblockhash", fork + 1)
    isolate(A, True)
    A.rpc("invalidateblock", target)
    while A.rpc("getblockcount") <= old_tip + 1:
        stake_alone(A)
    new_tip = A.rpc("getblockcount")
    isolate(A, False)
    ok = wait_for(lambda: len({n.rpc("getbestblockhash") for n in (A, I, B)}) == 1
                  and A.rpc("getblockcount") == new_tip, 240)
    row(f"reorg across {SPORK15_HEIGHT}: from {old_tip} to the chain A made from {fork} (to {new_tip}): all three agree",
        f"{B.rpc('getblockcount')}", f"{I.rpc('getblockcount')}", ok)
    return new_tip


# --- the run -------------------------------------------------------------------------------

TREASURY_ADDRESS = "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd"  # BlockIncentivesPopulator.cpp:31-32
CHARITY_ADDRESS = "y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5"
LAST_HEIGHT = 312
MINT_HEIGHTS = [125, 199, 201, 205, 299, 301, 305, 311]
REORG_AT = 208     # the tip when the chain is changed from FORK on
FORK = 194

reorged = False
while A.rpc("getblockcount") < LAST_HEIGHT:
    h = A.rpc("getblockcount") + 1
    if h == 205:
        # a block over what spork 15 allows by one satoshi, then as made
        offer_variants(205, [("paying one satoshi over spork 15's value", bump_stake(1))])
        h = A.rpc("getblockcount") + 1
    if h == 305:
        d = (subsidy(305) - 50) * COIN
        old_limit = d * 38 // 100 + d * 45 // 100
        new_limit = d * 50 // 100 + d * 30 // 100
        offer_variants(305, [
            ("paying what the usual split allows (spork 13 allows less)", bump_stake(old_limit - new_limit)),
            ("paying one satoshi over spork 13's split", bump_stake(1)),
        ])
        h = A.rpc("getblockcount") + 1
    if h == REORG_AT + 1 and not reorged:
        reorged = True
        reorg_across(FORK, A.rpc("getblockcount"))
        continue
    h, node = next_block()
    winners_row(f"after block {h} (by {node.name})")
    if os.environ.get("SPORK_CONSENSUS_TRACE"):
        print(f"#   {h} by {node.name}: {len(winner_addresses(A, h))} candidates on divid, "
              f"{len(winner_addresses(I, h))} on irondivid", flush=True)
print(f"# staked to {A.rpc('getblockcount')} after {time.time() - t0:.0f} s; blocks made: " +
      ", ".join(f"{n} {sum(v == n for v in made_by.values())}" for n in (A.name, I.name, B.name)), flush=True)

TIP = A.rpc("getblockcount")
row("the three nodes hold one chain", A.rpc("getbestblockhash")[:16], I.rpc("getbestblockhash")[:16],
    len({n.rpc("getbestblockhash") for n in (A, I, B)}) == 1)

# What each block created, against the rules and the sporks
for h in MINT_HEIGHTS:
    mint_row(h)
for h in (150, 200, 250, 300):
    treasury_row(h)

# The nodes given no sporks stop at the first block that needs them
stuck = (DP.rpc("getblockcount"), IP.rpc("getblockcount"))
row(f"nodes without the sporks stop at one height, below {SPORK15_HEIGHT}", f"{stuck[0]}", f"{stuck[1]}",
    stuck[0] == stuck[1] < SPORK15_HEIGHT)
row("nodes without the sporks hold one block there",
    DP.rpc("getbestblockhash")[:16], IP.rpc("getbestblockhash")[:16],
    DP.rpc("getbestblockhash") == IP.rpc("getbestblockhash"))
refused = A.rpc("getblock", A.rpc("getblockhash", stuck[0] + 1), False)
compare(f"block {stuck[0] + 1}, the first made under a spork, offered to nodes without it", "block",
        offer_block(DP, refused), offer_block(IP, refused))


# --- each superblock ---------------------------------------------------------------------

# --- each superblock -----------------------------------------------------------------------

def superblock_rows(tag="", first=0, last=None):
    tip = A.rpc("getblockcount") if last is None else last
    for h in sorted(set(LOTTERY + TREASURY)):
        if h < first:
            continue
        if h > tip:
            break
        kind = "treasury" if h in TREASURY else "lottery"
        p = f"{tag}{kind} superblock {h}"
        both(f"{p}: getlotteryblockwinners {h}", "getlotteryblockwinners", h)
        bh = (A.rpc("getblockhash", h), I.rpc("getblockhash", h))
        row(f"{p}: the same block", bh[0][:16], bh[1][:16], bh[0] == bh[1])
        core, iron = A.call("getblock", bh[0]), I.call("getblock", bh[1])
        for out in (core, iron):
            if out[0] == "ok":
                for extra in GETBLOCK_EXTRA:
                    out[1].pop(extra, None)
                if " order" in out[1]:
                    out[1][" order"] = [k for k in out[1][" order"] if k not in GETBLOCK_EXTRA]
        compare(f"{p}: getblock", "getblock", core, iron)
        stake_txid = A.rpc("getblock", bh[0])["tx"][1]
        both(f"{p}: the coinstake (getrawtransaction verbose)", "getrawtransaction", stake_txid, 1)
        if kind == "lottery":
            paid = winner_addresses(A, h - 1)
        else:
            paid = [TREASURY_ADDRESS, CHARITY_ADDRESS]
        for n, address in enumerate(dict.fromkeys(paid)):
            both(f"{p}: getaddressbalance of payee {n + 1}", "getaddressbalance", address)


# getblock members divid lacks (scripts/chain-replies README, KNOWN): compared
# without them
GETBLOCK_EXTRA = ("mediantime", "nTx")


def cycle_rows(tag="", first=0, last=None):
    """Per lottery cycle: how many candidates, how many distinct payees, on both"""
    tip = A.rpc("getblockcount") if last is None else last
    for h in LOTTERY:
        if h < first:
            continue
        if h > tip:
            break
        c, i = winner_addresses(A, h - 1), winner_addresses(I, h - 1)
        sc = f"{len(c)} candidates, {len(set(c))} payees"
        si = f"{len(i)} candidates, {len(set(i))} payees"
        row(f"{tag}cycle to lottery block {h}: winners at {h - 1}", sc, si, c == i)




superblock_rows("", 100)
cycle_rows("", 100)

# The sporks and the winners, then back over the heights of the sporks and forward
both("spork show after the run", "spork", "show")
CHECK_HEIGHTS = [149, 150, 151, SPORK15_HEIGHT - 1, SPORK15_HEIGHT, SPORK15_HEIGHT + 1, SPORK13_HEIGHT - 1,
                 SPORK13_HEIGHT, SPORK13_HEIGHT + 1, TIP]


def winners_at(heights, tag, core=None):
    for h in heights:
        both(f"{tag}: getlotteryblockwinners {h}", "getlotteryblockwinners", h, core=core)


# B and irondivid never set a block aside, so each still holds the chain A left
# at the reorg and goes back to it when a block of the new one is invalidated
for h in (SPORK13_HEIGHT, SPORK15_HEIGHT):
    target = B.rpc("getblockhash", h)
    for n in (B, I):
        n.rpc("invalidateblock", target)
    both(f"after invalidateblock {h}: getblockcount", "getblockcount", core=B)
    both(f"after invalidateblock {h}: getbestblockhash", "getbestblockhash", core=B)
    winners_at([h - 1, h], f"after invalidateblock {h}", core=B)
    for n in (B, I):
        n.rpc("reconsiderblock", target)
    wait_for(lambda: B.rpc("getblockcount") == TIP and I.rpc("getblockcount") == TIP, 120)
    both(f"after reconsiderblock {h}: getblockcount", "getblockcount", core=B)
    both(f"after reconsiderblock {h}: getbestblockhash", "getbestblockhash", core=B)
    winners_at([h - 1, h, TIP], f"after reconsiderblock {h}", core=B)

# A restart of all, then -reindex on A and irondivid
for n in (A, I, B):
    n.stop()
for n in (A, I, B):
    n.start()
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start again")
synced()
both("after a restart: spork show", "spork", "show")
both("after a restart: getbestblockhash", "getbestblockhash")
winners_at(CHECK_HEIGHTS, "after a restart")
for n in (A, I):
    n.stop()
for n in (A, I):
    n.start(["-reindex"])
wait_for(lambda: A.rpc("getblockcount") == TIP and I.rpc("getblockcount") == TIP, 300)
both("after -reindex: getblockcount", "getblockcount")
both("after -reindex: getbestblockhash", "getbestblockhash")
winners_at(CHECK_HEIGHTS, "after -reindex")
for h in MINT_HEIGHTS:
    mint_row(h)

for kind in sorted(set(order_seen) | set(ORDER_KINDS)):
    name = f"{kind}: field order"
    seen = order_seen.get(kind)
    row(name, seen[1] if seen else "same", seen[2] if seen else "same", seen is None)

for n in (A, I, B, DP, IP):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
