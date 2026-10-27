#!/usr/bin/env python3
"""Blocks broken in one way each, offered to Divi Core divid and irondivid on one
regtest network: does each take or refuse them, with what reject message, and
what does it do to the peer that sent them?

Three nodes: divid A (listens), divid B and irondivid I (both dial A). A mines the
proof-of-work blocks and pays stakes to addresses of all three wallets; then
they take turns staking to height 110. At a height, A is cut off and makes the
block alone (so it owns the coins it can spend), and copies of that block broken
one way each are offered to B and to I by a raw peer: the merkle root, the
transactions (duplicate, missing or second coinbase, the coinstake out of
place), the signatures (block and coinstake), the time, the version, the bits,
the stake input (spent, young, in no block), inputs (spent twice, missing, more
out than in, immature coinbase and coinstake, not final), the size and the
signature operations, and the amounts and payees of a treasury and a lottery
block. For each, both are compared on: taken or refused, the reject message, whether the
node closed the connection, whether its tip moved (it is then put back with
invalidateblock) and whether it banned the address. Then the block as made is
offered, A joins again, and a valid block is taken from another peer.

Each row prints PASS (the same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs. Started by run.sh, which owns the work
directory and stops the nodes.
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
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
OFFER_WAIT = 5   # seconds to hear a node's answer to a block
TRACE = bool(os.environ.get("BLOCK_RULES_TRACE"))
DUMP = os.environ.get("BLOCK_RULES_DUMP", "")

# Regtest (chainparams.cpp:473-498): last proof-of-work block 100; coinbase and
# coinstake outputs mature after 20 blocks; lottery from 101 every 10 blocks,
# treasury from 102 every 50
LAST_POW = 100

KNOWN = {}
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




class Node:
    def __init__(self, name, binary, index, extra_conf, indexed=True):
        self.name, self.binary = name, binary
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
        ] + (["txindex=1", "addressindex=1", "spentindex=1"] if indexed else ["txindex=0"]) + list(extra_conf)
        self.write_conf()
        self.proc = None
        self.start()

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
AGENT = b"/block-rules:1/"


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


# --- the nodes -----------------------------------------------------------------------

A = Node("divid-A", DIVID, 0, ["listen=1"])
if not A.wait_ready():
    print(f"FAIL   start: divid A did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
I = Node("irondivid", IRONDIVID, 1, ["listen=1", f"connect={HOST}:{PORT_BASE}"])
B = Node("divid-B", DIVID, 2, ["listen=1", f"connect={HOST}:{PORT_BASE}"])
for n in (I, B):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
print(f"# divid {A.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

t0 = time.time()
A.rpc("setgenerate", LAST_POW)
if not synced():
    print("FAIL   setup: the nodes did not follow A's proof-of-work blocks", flush=True)
    sys.exit(1)
# Stakes of different sizes to addresses of each wallet, so I and B have coins to
# stake; A keeps its coinbases (the ones of blocks 81 to 100 stay unspent)
dup = I.rpc("getnewaddress")
STAKES = {A: [(None, 10800)], I: [(dup, 10500), (None, 11000), (None, 12000)],
          B: [(None, 10200), (None, 13000)]}
for node, coins in STAKES.items():
    for address, size in coins:
        A.rpc("sendtoaddress", address or node.rpc("getnewaddress"), size)
stake(A, 1)
print(f"# {A.rpc('getblockcount')} blocks after {time.time() - t0:.0f} s", flush=True)

made_by = {}


def pick(height):
    """Who makes block `height`: I, then B, when it has a coin to stake, else A"""
    for n in ([A, I, B] if (height // 10) % 2 else [I, B, A]):
        if n is A or stakeable(n):
            return n
    return A


coinstake_tx = {}


def stakeable(node):
    """Whether the wallet has a coin it may stake with: 10 blocks deep, or 20
    for a coinstake's output (wallet.cpp:1456)"""
    for coin in node.rpc("listunspent"):
        txid, depth = coin["txid"], coin["confirmations"]
        if float(coin["amount"]) < 1000:      # too small to stake
            continue
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


def to_height(height):
    while A.rpc("getblockcount") < height:
        next_block()


# --- a block broken in one way ---------------------------------------------------------------

COIN = 100_000_000


def sats(v):
    return int(Decimal(str(v)) * COIN)


def rawtx(node, txid):
    return node.rpc("getrawtransaction", txid, 1)


def outpoint(txid, n):
    return bytes.fromhex(txid)[::-1] + struct.pack("<I", n)


def own_script(node):
    return p2pkh_script(node.rpc("getnewaddress"))


def sign_with(node, tx, spent):
    """`tx` signed by `node`'s wallet; `spent` lists (txid, n) of the outputs it spends"""
    prevtxs = []
    for txid, n in spent:
        prevtxs.append({"txid": txid, "vout": n, "scriptPubKey": rawtx(node, txid)["vout"][n]["scriptPubKey"]["hex"]})
    signed = node.rpc("signrawtransaction", tx_bytes(tx).hex(), prevtxs)
    if not signed.get("complete"):
        raise RuntimeError(f"{node.name} could not sign a test transaction")
    return parse_tx(bytes.fromhex(signed["hex"]))[0]


def spending(node, txid, n, outputs, lock=0, sequence=0xFFFFFFFF, sign=True):
    """A transaction spending output `n` of `txid`, paying `outputs` [(satoshis, script)]"""
    tx = {"version": 1, "vin": [[outpoint(txid, n), b"", sequence]],
          "vout": [[v, s] for v, s in outputs], "lock": lock}
    tx["raw"] = tx_bytes(tx)
    return sign_with(node, tx, [(txid, n)]) if sign else tx


def junk_tx(index, script_len, filler=0x51):
    """A transaction no wallet could have made: an input that does not exist, an
    output with a script of `script_len` bytes"""
    tx = {"version": 1, "vin": [[sha256d(b"junk%d" % index) + struct.pack("<I", 0), b"", 0xFFFFFFFF]],
          "vout": [[1, bytes([filler]) * script_len]], "lock": 0}
    tx["raw"] = tx_bytes(tx)
    return tx


def refresh(tx):
    tx["raw"] = tx_bytes(tx)
    return tx


def staker_secret(node, block):
    script = block["txs"][1]["vout"][1][1]
    address = b58check(bytes([139]) + script[3:23])
    return wif_secret(node.rpc("dumpprivkey", address))


def finish(block, secret, merkle="recompute"):
    """The block as bytes (hex): the merkle root made again unless `merkle` is
    "keep", the block signed with `secret` (a number), none when None"""
    for tx in block["txs"]:
        refresh(tx)
    if merkle == "recompute":
        root = merkle_root([sha256d(t["raw"]) for t in block["txs"]])
        block["header"] = block["header"][:36] + root + block["header"][68:]
    if block.get("grind"):
        # work for the block's bits, which a proof-of-work block needs
        bits = header_u32(block, BITS)
        target = (bits & 0xFFFFFF) << (8 * ((bits >> 24) - 3))
        nonce = 0
        while True:
            set_header(block, 76, struct.pack("<I", nonce))
            if int.from_bytes(sha256d(block["header"])[::-1], "big") <= target:
                break
            nonce += 1
    if struct.unpack_from("<I", block["header"], 0)[0] < 4:
        # before version 4 the header has no accumulator checkpoint
        block["header"] = block["header"][:80]
    if secret is None:
        block["sig"] = b""
    else:
        block["sig"] = sign_compact(secret, sha256d(block["header"]))
    return block_bytes(block).hex()


def set_header(block, offset, data):
    block["header"] = block["header"][:offset] + data + block["header"][offset + len(data):]


VERSION, MERKLE, TIME, BITS = 0, 36, 68, 72


def header_u32(block, offset):
    return struct.unpack_from("<I", block["header"], offset)[0]


def offer(node, hexstr, restore=True, watch=False):
    """A raw peer sends the block to `node`. What comes back: its first `reject`
    (command, code, reason up to the first space, colon or bracket), whether it
    closed the connection, whether its tip moved, whether it banned the address.
    A tip that moved is put back with invalidateblock."""
    before = node.rpc("getbestblockhash")
    reject, closed, raw = None, False, None
    seen = set()
    try:
        sock = socket.create_connection((HOST, node.p2p), timeout=10)
    except OSError as e:
        return ("ok", {"answer": f"no connection ({e.__class__.__name__})"})
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
        if watch:
            # what the node sends a new peer on its own comes first, so that only its answer
            # to the block is counted
            settle = time.time() + 2
            while time.time() < settle:
                sock.settimeout(max(0.1, settle - time.time()))
                try:
                    command, payload = read_message(sock)
                except socket.timeout:
                    break
                if command == "ping":
                    sock.sendall(message("pong", payload))
        sock.sendall(message("block", bytes.fromhex(hexstr)))
        deadline = time.time() + OFFER_WAIT
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                command, payload = read_message(sock)
            except socket.timeout:
                break
            except (EOFError, ConnectionError, OSError):
                closed = True
                break
            seen.add(command)
            if command == "ping":
                sock.sendall(message("pong", payload))
            elif command == "reject" and reject is None:
                what, pos = varstr(payload, 0)
                code = payload[pos]
                why, pos = varstr(payload, pos + 1)
                raw = why
                reject = [what, code, re.split(r"[ :(]", why)[0]]
    except (EOFError, ConnectionError, OSError):
        closed = True
    finally:
        sock.close()
    time.sleep(0.5)
    after = node.rpc("getbestblockhash")
    moved = after != before
    if moved and restore:
        node.rpc("invalidateblock", after)
        wait_for(lambda: node.rpc("getbestblockhash") == before, 30)
    banned = "127.0.0.1" in json.dumps(node.call("listbanned")[1])
    if TRACE:
        print(f"#     {node.name}: reject {raw!r} closed {closed}", flush=True)
    out = {"reject": reject, "closed the connection": closed, "tip moved": moved, "banned": banned}
    if watch:
        out["asked the sender for blocks"] = "getblocks" in seen
    return ("ok", out)


def offer_both(hexstr, restore=True, watch=False, nodes=None):
    """The block offered to divid B and to irondivid (or the two given) at the same time"""
    nodes = nodes or (B, I)
    out = {}
    def run(n):
        try:
            out[n.name] = offer(n, hexstr, restore, watch)
        except Exception as e:      # shown as the node's answer, not lost with its thread
            out[n.name] = ("ok", {"error": f"{e.__class__.__name__}: {str(e)[:100]}"})
    threads = [threading.Thread(target=run, args=(n,)) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out[nodes[0].name], out[nodes[1].name]


def check_case(name, hexstr, restore=True, watch=False, nodes=None):
    core, iron = offer_both(hexstr, restore, watch, nodes)
    compare(name, "block", core, iron)


# --- the run -------------------------------------------------------------------------------

H1 = 112


def median_time_past(node):
    """Divi Core GetMedianTimePast of the tip: the median of the last 11 block times"""
    times = []
    h = node.rpc("getblockcount")
    for k in range(11):
        if h - k < 0:
            break
        times.append(node.rpc("getblock", node.rpc("getblockhash", h - k))["time"])
    return sorted(times)[len(times) // 2]


def new_coinstake(node, block, txid, n, tag="stake", lock=None):
    """The block's coinstake made again to stake output `n` of `txid` (a coin of
    `node`), signed by `node`: the output of the staker's script takes the coin's
    value and what the coinstake created; `lock` is its lock time, if it must differ from the
    block's own (so that the coinstake is not one the chain has)"""
    old = block["txs"][1]
    created = sum(o[0] for o in old["vout"])
    spent = sum(sats(rawtx(node, bytes(p[:32][::-1]).hex())["vout"][struct.unpack("<I", p[32:])[0]]["value"])
                for p, _, _ in old["vin"])
    value = sats(rawtx(node, txid)["vout"][n]["value"])
    tx = {"version": old["version"], "vin": [[outpoint(txid, n), b"", old["vin"][0][2]]],
          "vout": [[0, b""], [value + created - spent, old["vout"][1][1]]],
          "lock": old["lock"] if lock is None else lock}
    tx["raw"] = tx_bytes(tx)
    return sign_with(node, tx, [(txid, n)])


def build_cases(good_hex, extra):
    """[(name, hex)] of the good block broken one way each; `extra` has the coins
    and transactions the cases spend"""
    good = lambda: parse_block(bytes.fromhex(good_hex))
    secret = staker_secret(A, good())
    wrong = secrets.randbelow(N_ORDER - 1) + 1
    cases = []

    def case(name, edit, sign="staker", merkle="recompute"):
        bl = good()
        edit(bl)
        key = {"staker": secret, "wrong": wrong, "none": None}[sign]
        cases.append((name, finish(bl, key, merkle)))

    now = int(time.time())
    # the block's structure
    case("bad merkle root", lambda b: set_header(b, MERKLE, sha256d(b"not the root")), merkle="keep")
    case("a duplicate transaction (merkle root unchanged)", lambda b: b["txs"].append(dict(b["txs"][-1])), merkle="keep")
    case("no coinbase", lambda b: b["txs"].pop(0))
    case("two coinbases", lambda b: b["txs"].append(
        dict(b["txs"][0], vin=[[b["txs"][0]["vin"][0][0], b["txs"][0]["vin"][0][1] + b"\x01", b["txs"][0]["vin"][0][2]]])))
    case("the coinstake is not the second transaction", lambda b: b["txs"].insert(1, b["txs"].pop(2)))
    case("a second coinstake", lambda b: b["txs"].append(dict(b["txs"][1])))
    case("a coinbase that pays in a proof-of-stake block", lambda b: b["txs"][0]["vout"][0].__setitem__(0, 1))
    case("a coinbase that does not start with the height", lambda b: b["txs"][0]["vin"].__setitem__(
        0, [b["txs"][0]["vin"][0][0], b"\x01\x05" + b["txs"][0]["vin"][0][1][2:], b["txs"][0]["vin"][0][2]]))
    # work and stake in the wrong period (Divi Core CheckEnforcedPoSBlocksAndBIP30, BlockConnectionService.cpp:46-60)
    def proof_of_work_block(b):
        # with the coinbase alone divid 3.0.0 stops (see README.md)
        b["txs"] = [b["txs"][0], b["txs"][2]]
        b["txs"][0]["vout"] = [[1250 * COIN, own_script(A)]]
        b["grind"] = True
    case("a proof-of-work block after height 100", proof_of_work_block, sign="none")
    # signatures
    case("block signed by another key", lambda b: None, sign="wrong")
    case("block without a signature", lambda b: None, sign="none")

    def damage_coinstake(b):
        sig = bytearray(b["txs"][1]["vin"][0][1])
        sig[8] ^= 0x01
        b["txs"][1]["vin"][0][1] = bytes(sig)
    case("coinstake signature damaged", damage_coinstake)
    # time, version, bits
    case("timestamp 1000 s ahead", lambda b: set_header(b, TIME, struct.pack("<I", now + 1000)))
    case("timestamp 600 s ahead", lambda b: set_header(b, TIME, struct.pack("<I", now + 600)))
    case("timestamp at the median time past", lambda b: set_header(b, TIME, struct.pack("<I", extra["mtp"])))
    case("timestamp before the median time past", lambda b: set_header(b, TIME, struct.pack("<I", extra["mtp"] - 100)))
    case("bits changed", lambda b: set_header(b, BITS, struct.pack("<I", header_u32(b, BITS) ^ 0x1)))
    case("bits for a lower target", lambda b: set_header(b, BITS, struct.pack("<I", header_u32(b, BITS) - 0x010000)))
    # the stake input
    for label, (txid, n) in extra.get("stake inputs", {}).items():
        def swap(b, txid=txid, n=n):
            b["txs"][1] = new_coinstake(A, b, txid, n)
        case(f"stake input {label}", swap)
    # transactions
    if "double spend" in extra:
        case("an input spent twice within the block", lambda b: b["txs"].__setitem__(slice(2, None), list(extra["double spend"])))
        case("a transaction spending an input that does not exist", lambda b: b["txs"].__setitem__(
            slice(2, None), [extra["no such input"]]))
        case("a transaction paying more than it spends", lambda b: b["txs"].__setitem__(slice(2, None), [extra["overspend"]]))
        case("a transaction spending an immature coinbase", lambda b: b["txs"].__setitem__(slice(2, None), [extra["immature coinbase"]]))
        case("a transaction spending an immature coinstake output", lambda b: b["txs"].__setitem__(slice(2, None), [extra["immature coinstake"]]))
        case("a transaction that is not final", lambda b: b["txs"].__setitem__(slice(2, None), [extra["not final"]]))
    # one transaction broken in one way (Divi Core CheckTransaction, BlockCheckingHelpers.cpp:98-140)
    def broken_tx(edit):
        def apply(b):
            tx = junk_tx(7, 10)
            edit(tx)
            b["txs"].append(tx)
        return apply
    case("a transaction with no inputs", broken_tx(lambda t: t["vin"].clear()))
    case("a transaction with no outputs", broken_tx(lambda t: t["vout"].clear()))
    case("a transaction over 100,000 bytes", broken_tx(lambda t: t["vout"].__setitem__(0, [1, b"\x51" * 100_500])))
    case("a transaction with a negative output", broken_tx(lambda t: t["vout"].__setitem__(0, [-1, b"\x51"])))
    case("a transaction with an output over the money limit", broken_tx(lambda t: t["vout"].__setitem__(0, [10 ** 18, b"\x51"])))
    case("a transaction with an empty output", broken_tx(lambda t: t["vout"].__setitem__(0, [0, b""])))
    case("a coinbase with a script of 101 bytes", lambda b: b["txs"][0]["vin"].__setitem__(
        0, [b["txs"][0]["vin"][0][0], b["txs"][0]["vin"][0][1] + b"\x00" * 101, b["txs"][0]["vin"][0][2]]))
    # size
    case("a block over 2,000,000 bytes", lambda b: b["txs"].extend(junk_tx(k, 90_000) for k in range(23)))
    case("a block with 21,000 signature operations", lambda b: b["txs"].append(junk_tx(0, 21_000, 0xAC)))
    # the amount
    cases.append(("the coinstake paying one satoshi too much",
                  changed_block(A, good_hex, lambda vout: vout[1].__setitem__(0, vout[1][0] + 1))))
    return cases


def bad_blocks(height, label, generic=True, payee=()):
    """A, alone, makes the block at `height`; each broken copy is offered to divid
    B and irondivid by a raw peer; then the block as made; A then joins again"""
    to_height(height - 2)
    stake(A, 1)          # the block before is A's, so A owns its coinstake output
    extra = {}
    if generic:
        A.rpc("sendtoaddress", B.rpc("getnewaddress"), 1)   # a transaction for the block to carry, so it has three
    prev_cs = coinstake_of(A, height - 1)
    spend_from = [c for c in A.rpc("listunspent") if c["confirmations"] >= 25 and c["spendable"]]
    isolate(A, True)
    good = stake_alone(A)
    cases = []
    if generic:
        cases = generic_cases(good, extra, prev_cs, spend_from, height)
    for name, change in payee:
        cases.append((name, changed_block(A, good, change)))
    print(f"# {label}: {len(cases)} broken blocks at height {height}", flush=True)
    for name, hexstr in cases:
        check_case(f"{label}: {name}", hexstr)
    check_case(f"{label}: the block as made", good, restore=False)
    isolate(A, False)
    if not synced(secs=180):
        raise RuntimeError("A did not join the network again")


def generic_cases(good, extra, prev_cs, spend_from, height):
    blk = parse_block(bytes.fromhex(good))
    if len(blk["txs"]) < 3:
        raise RuntimeError(f"the block {height} has {len(blk['txs'])} transactions; wanted a third")
    extra["mtp"] = median_time_past_of_parent(A, height)
    pay = lambda v: [(v, own_script(A))]
    c1, c2 = spend_from[1], spend_from[2]
    value1 = sats(c1["amount"])
    extra["double spend"] = [spending(A, c1["txid"], c1["vout"], pay(value1 - 10_000_000)),
                             spending(A, c1["txid"], c1["vout"], [(value1 - 20_000_000, own_script(A))])]
    extra["no such input"] = spending(A, c2["txid"], c2["vout"], pay(1), sign=False)
    extra["no such input"]["vin"][0][0] = sha256d(b"no such tx") + struct.pack("<I", 0)
    refresh(extra["no such input"])
    value3 = sats(spend_from[3]["amount"])
    extra["overspend"] = spending(A, spend_from[3]["txid"], spend_from[3]["vout"], pay(value3 + 1))
    cb100 = A.rpc("getblock", A.rpc("getblockhash", 100))["tx"][0]
    extra["immature coinbase"] = spending(A, cb100, 0, pay(sats(rawtx(A, cb100)["vout"][0]["value"]) - 10_000_000))
    cs_txid = coinstake_of(A, height - 1)["txid"]
    extra["immature coinstake"] = spending(A, cs_txid, 1, pay(sats(rawtx(A, cs_txid)["vout"][1]["value"]) - 10_000_000))
    extra["not final"] = spending(A, spend_from[4]["txid"], spend_from[4]["vout"],
                                  pay(sats(spend_from[4]["amount"]) - 10_000_000), lock=1_000_000, sequence=0)
    # the stake inputs: young (the coinstake just made), already spent, not yet in a block
    spent_prevout = (prev_cs["vin"][0]["txid"], prev_cs["vin"][0]["vout"])
    A.rpc("sendtoaddress", A.rpc("getnewaddress"), 5)
    mempool_txid = A.rpc("getrawmempool")[0]
    mempool_tx = rawtx(A, mempool_txid)
    mempool_n = next(k for k, o in enumerate(mempool_tx["vout"]) if sats(o["value"]) == 5 * COIN)
    extra["stake inputs"] = {"spent in the chain": spent_prevout,
                             "made by the block before (a few seconds old)": (cs_txid, 1),
                             "in no block yet": (mempool_txid, mempool_n)}
    return build_cases(good, extra)


def median_time_past_of_parent(node, height):
    times = []
    for k in range(1, 12):
        if height - k < 0:
            break
        times.append(node.rpc("getblock", node.rpc("getblockhash", height - k))["time"])
    return sorted(times)[len(times) // 2]


def coinstake_of(node, h):
    block = node.rpc("getblock", node.rpc("getblockhash", h))
    return node.rpc("getrawtransaction", block["tx"][1], 1)


bad_blocks(H1, "block 112")
# A valid block afterwards is taken from the other peers
h, node = next_block()
row("after the broken blocks: a valid block from another peer reaches all three",
    f"{B.rpc('getblockcount')}", f"{I.rpc('getblockcount')}",
    B.rpc("getblockcount") == I.rpc("getblockcount") == A.rpc("getblockcount") == h
    and len({n.rpc("getbestblockhash") for n in (A, B, I)}) == 1)


# --- a block beside the tip ----------------------------------------------------------------------

def sibling_round(label):
    """The tip block broken one way each, offered as a block whose parent is not
    the tip (a block of a side chain): the checks that need no coin set"""
    height = A.rpc("getblockcount")
    tip_hex = A.rpc("getblock", A.rpc("getbestblockhash"), False)
    cases = build_cases(tip_hex, {"mtp": median_time_past_of_parent(A, height)})
    wanted = ("bad merkle root", "a duplicate transaction", "no coinbase", "two coinbases", "a second coinstake",
              "a coinbase that does not start", "block signed by another key", "block without a signature",
              "coinstake signature damaged", "timestamp 1000", "timestamp at the median", "bits changed",
              "a transaction with no inputs", "a block over 2,000,000", "the coinstake paying one satoshi")
    cases = [(n, h) for n, h in cases if n.startswith(wanted)]
    print(f"# {label}: {len(cases)} broken siblings of the tip block at height {height}", flush=True)
    for name, hexstr in cases:
        check_case(f"{label}: {name}", hexstr)


sibling_round("side chain")


# --- a side chain whose first block has a bad proof ------------------------------------------------

def block_hash(hexstr):
    return sha256d(bytes.fromhex(hexstr)[:112])[::-1].hex()


def height_script(n):
    """The script a coinbase begins with: the height, as CScript() << n"""
    if n == 0:
        return b"\x00"
    if n <= 16:
        return bytes([0x50 + n])
    out = bytearray()
    m = n
    while m:
        out.append(m & 0xFF)
        m >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)


def child_of(block_hex, parent_hash, height, secret):
    """A copy of the block on top of `parent_hash`, as the block at `height`"""
    block = parse_block(bytes.fromhex(block_hex))
    old = struct.unpack_from("<I", block["header"], 68)[0]
    script = block["txs"][0]["vin"][0][1]
    old_height = height - 1
    prefix = height_script(old_height)
    if script.startswith(prefix):
        script = height_script(height) + script[len(prefix):]
    block["txs"][0]["vin"][0][1] = script
    set_header(block, 4, bytes.fromhex(parent_hash)[::-1])
    set_header(block, TIME, struct.pack("<I", old + 60))
    return finish(block, secret)


class Observer:
    """A raw peer of `node` that keeps the block hashes the node announces to it"""

    def __init__(self, node):
        self.invs = set()
        self.sock = socket.create_connection((HOST, node.p2p), timeout=10)
        version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(node.p2p) + netaddr(0)
                   + secrets.token_bytes(8) + compact(len(AGENT)) + AGENT + struct.pack("<i", 0) + b"\x01")
        self.sock.sendall(message("version", version))
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        try:
            while True:
                command, payload = read_message(self.sock)
                if command == "version":
                    self.sock.sendall(message("verack"))
                elif command == "ping":
                    self.sock.sendall(message("pong", payload))
                elif command == "inv":
                    n, pos = read_compact(payload, 0)
                    for k in range(n):
                        kind = struct.unpack_from("<I", payload, pos)[0]
                        if kind == 2:
                            self.invs.add(payload[pos + 4:pos + 36][::-1].hex())
                        pos += 36
        except (EOFError, ConnectionError, OSError, struct.error):
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def chain_tips(node):
    return sorted((t["height"], t["branchlen"], t["status"]) for t in node.rpc("getchaintips"))


def chain_state(node, hashes, before):
    """What a node holds of these blocks and what its chain tips gained since `before`:
    found by getblock, the new tips as (height, branch length, status), the block count"""
    now = chain_tips(node)
    tips = [t for t in set(now) if now.count(t) > before.count(t)]
    tips.sort()
    if TRACE:
        print(f"#     {node.name} tips {tips}", flush=True)
    return ("ok", {"known": [node.call("getblock", h)[0] == "ok" for h in hashes], "tips": tips,
                   "blocks": node.rpc("getblockcount")})


def side_chain_proof(label):
    """A sibling of the tip block whose proof of stake is bad (the kernel's signature
    damaged), then two blocks on top of it, so that this side chain is the longer one.
    Divi Core checks the proof when a block arrives (ChainExtensionService.cpp:477) and
    refuses a block that fails it before it is stored"""
    height = A.rpc("getblockcount")
    tip_hex = A.rpc("getblock", A.rpc("getbestblockhash"), False)
    secret = staker_secret(A, parse_block(bytes.fromhex(tip_hex)))
    bad = dict(build_cases(tip_hex, {"mtp": median_time_past_of_parent(A, height)}))["coinstake signature damaged"]
    watchers = {n.name: Observer(n) for n in (B, I)}
    before = {n.name: chain_tips(n) for n in (B, I)}
    time.sleep(2)
    blocks = [bad]
    for k in (1, 2):
        blocks.append(child_of(blocks[-1], block_hash(blocks[-1]), height + k, secret))
    hashes = [block_hash(b) for b in blocks]
    names = ["the bad sibling", "a block on it", "a second block on it"]
    for k, (name, hexstr) in enumerate(zip(names, blocks)):
        check_case(f"{label}: {name}, offered", hexstr, watch=True)
        compare(f"{label}: after {name}: the blocks held and the chain tips", "chain_state",
                chain_state(B, hashes, before[B.name]), chain_state(I, hashes, before[I.name]))
    time.sleep(1)
    compare(f"{label}: announced to another peer", "announced",
            ("ok", sorted(h for h in hashes if h in watchers[B.name].invs)),
            ("ok", sorted(h for h in hashes if h in watchers[I.name].invs)))
    for w in watchers.values():
        w.close()


side_chain_proof("bad-proof side chain")


KNOWN["unknown-coin side chain: the sibling is held"] = (
    "divid refuses a side-chain block that stakes a coin only its own branch made, because its transaction index "
    "holds only the blocks it has connected (TransactionDiskAccessor.cpp:56-72, BlockProofVerifier.cpp:56-57); "
    "irondivid keeps it until the branch is connected, so that a fork that restakes its own coins can be followed")


def unknown_coin_sibling():
    """A sibling of the tip block that stakes a coin in no block yet (a coin of the
    mempool), which is also what a coin only a side chain made looks like"""
    height = A.rpc("getblockcount")
    tip_hex = A.rpc("getblock", A.rpc("getbestblockhash"), False)
    block = parse_block(bytes.fromhex(tip_hex))
    secret = staker_secret(A, block)
    A.rpc("sendtoaddress", A.rpc("getnewaddress"), 5)
    txid = A.rpc("getrawmempool")[0]
    n = next(k for k, o in enumerate(rawtx(A, txid)["vout"]) if sats(o["value"]) == 5 * COIN)
    block["txs"][1] = new_coinstake(A, block, txid, n)
    hexstr = finish(block, secret)
    before = {x.name: chain_tips(x) for x in (B, I)}
    check_case("unknown-coin side chain: the sibling, offered", hexstr, watch=True)
    compare("unknown-coin side chain: the sibling is held", "chain_state",
            chain_state(B, [block_hash(hexstr)], before[B.name]), chain_state(I, [block_hash(hexstr)], before[I.name]))


unknown_coin_sibling()
h, node = next_block()
row("after the side-chain blocks: a valid block from another peer reaches all three",
    f"{B.rpc('getblockcount')}", f"{I.rpc('getblockcount')}",
    B.rpc("getblockcount") == I.rpc("getblockcount") == A.rpc("getblockcount") == h
    and len({n.rpc("getbestblockhash") for n in (A, B, I)}) == 1)


# --- the treasury and lottery payments --------------------------------------------------------

TREASURY_ADDRESS = "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd"  # BlockIncentivesPopulator.cpp:31-32
CHARITY_ADDRESS = "y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5"
NOBODY = b58check(bytes([139]) + secrets.token_bytes(20))


def change_payout(script, how):
    def change(vout):
        for o in vout:
            if o[1] == script:
                how(o, vout)
                return
        raise RuntimeError("payout not found in the coinstake")
    return change


treasury_script, charity_script = p2pkh_script(TREASURY_ADDRESS), p2pkh_script(CHARITY_ADDRESS)
bad_blocks(150, "treasury block 150", generic=False, payee=[
    ("treasury paid one satoshi less", change_payout(treasury_script, lambda o, v: o.__setitem__(0, o[0] - 1))),
    ("treasury paid one satoshi more", change_payout(treasury_script, lambda o, v: o.__setitem__(0, o[0] + 1))),
    ("treasury paid to another address", change_payout(treasury_script, lambda o, v: o.__setitem__(1, p2pkh_script(NOBODY)))),
    ("treasury payment left out", change_payout(treasury_script, lambda o, v: v.remove(o))),
    ("charity payment left out", change_payout(charity_script, lambda o, v: v.remove(o))),
])


def winner_scripts(height):
    w = A.call("getlotteryblockwinners", height - 1)
    candidates = (w[1] or {}).get("Lottery Candidates", []) if w[0] == "ok" else []
    return [p2pkh_script(c["Address"]) for c in candidates]


# The first lottery block from 160 that has winners to pay
L = 160
to_height(L - 3)
while not winner_scripts(L) and L < 220:
    L += 10
    to_height(L - 3)
wins = winner_scripts(L)
print(f"# lottery block {L}: {len(wins)} winners", flush=True)
if wins:
    bad_blocks(L, f"lottery block {L}", generic=False, payee=[
        ("first winner paid one satoshi less", change_payout(wins[0], lambda o, v: o.__setitem__(0, o[0] - 1))),
        ("first winner paid to another address", change_payout(wins[0], lambda o, v: o.__setitem__(1, p2pkh_script(NOBODY)))),
        ("last winner left out", change_payout(wins[-1], lambda o, v: v.remove(o))),
    ])
h, node = next_block()
row("after the payment blocks: a valid block from another peer reaches all three",
    f"{B.rpc('getblockcount')}", f"{I.rpc('getblockcount')}",
    B.rpc("getblockcount") == I.rpc("getblockcount") == A.rpc("getblockcount") == h
    and len({n.rpc("getbestblockhash") for n in (A, B, I)}) == 1)

# --- without a transaction index ------------------------------------------------------------------

def log_lines(node, start=None):
    """The number of lines in the node's debug.log, or the lines from `start`"""
    with open(os.path.join(node.dir, "debug.log"), errors="replace") as f:
        lines = f.read().splitlines()
    return len(lines) if start is None else [l[:240] for l in lines[start:]]


def block_staked_by_a():
    """The newest block A staked, its coinstake's first input (spent by it) and its height"""
    for h in range(A.rpc("getblockcount"), LAST_POW, -1):
        cs = coinstake_of(A, h)
        address = cs["vout"][1]["scriptPubKey"].get("addresses", [""])[0]
        if address and A.rpc("validateaddress", address)["ismine"]:
            return h, cs["vin"][0]["txid"], cs["vin"][0]["vout"]
    raise RuntimeError("A staked no block")


def without_index():
    """A divid and an irondivid with no transaction index (-txindex=0, both new and joined to A:
    the setting cannot change on a datadir without -reindex). divid reads a spent coin only through
    the index (TransactionDiskAccessor.cpp:73-86), so: a block that stakes a coin the chain has
    spent, one that stakes a coin in no block, and then a valid block"""
    C = Node("divid-C", DIVID, 3, ["listen=1", f"connect={HOST}:{PORT_BASE}"], indexed=False)
    J = Node("irondivid-J", IRONDIVID, 4, ["listen=1", f"connect={HOST}:{PORT_BASE}"], indexed=False)
    for n in (C, J):
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not start without the index")
    if not wait_for(lambda: len({n.rpc("getbestblockhash") for n in (A, C, J)}) == 1, 300):
        raise RuntimeError("the nodes without the index did not follow A: " +
                           str({n.name: n.rpc("getblockcount") for n in (A, C, J)}))
    nodes = (C, J)
    height = A.rpc("getblockcount")
    tip_hash = A.rpc("getbestblockhash")
    tip_hex = A.rpc("getblock", tip_hash, False)
    secret = staker_secret(A, parse_block(bytes.fromhex(tip_hex)))
    _, spent_txid, spent_n = block_staked_by_a()
    compare("without -txindex: getrawtransaction of the transaction that made a spent stake input",
            "getrawtransaction", C.call("getrawtransaction", spent_txid), J.call("getrawtransaction", spent_txid))
    A.rpc("sendtoaddress", A.rpc("getnewaddress"), 5)
    mempool_txid = A.rpc("getrawmempool")[0]
    mempool_n = next(k for k, o in enumerate(rawtx(A, mempool_txid)["vout"]) if sats(o["value"]) == 5 * COIN)
    for label, (txid, n) in (("spent in the chain", (spent_txid, spent_n)), ("in no block yet", (mempool_txid, mempool_n))):
        # only the coinbase and the coinstake, both made different from the tip's: a block that repeats a
        # transaction of the chain fails (BIP30) when it is connected, which is not what is looked at here
        sibling = parse_block(bytes.fromhex(tip_hex))
        sibling["txs"][1] = new_coinstake(A, sibling, txid, n, lock=1)
        sibling["txs"] = sibling["txs"][:2]
        sibling["txs"][0]["vin"][0][1] += b"\x01"
        mark = log_lines(J)
        check_case(f"without -txindex: stake input {label}, a sibling of the tip", finish(sibling, secret),
                   watch=True, nodes=nodes)
        if TRACE:
            print("#  J's log:", *log_lines(J, mark), sep="\n#    ", flush=True)
        on_tip = parse_block(bytes.fromhex(child_of(tip_hex, tip_hash, height + 1, secret)))
        on_tip["txs"][1] = new_coinstake(A, on_tip, txid, n, lock=1)
        on_tip["txs"] = on_tip["txs"][:2]
        on_tip["txs"][0]["vin"][0][1] += b"\x02"
        mark = log_lines(J)
        check_case(f"without -txindex: stake input {label}, a block on the tip", finish(on_tip, secret),
                   watch=True, nodes=nodes)
        if TRACE:
            print("#  J's log (block on the tip):", *log_lines(J, mark), sep="\n#    ", flush=True)
    if not wait_for(lambda: A.call("setgenerate", 1)[0] == "ok" and A.rpc("getblockcount") > height, 120):
        raise RuntimeError("A could not make a block")
    h = A.rpc("getblockcount")
    row("without -txindex: a valid block from A reaches both",
        f"{C.rpc('getblockcount')}", f"{J.rpc('getblockcount')}",
        wait_for(lambda: C.rpc("getblockcount") == J.rpc("getblockcount") == h, 60))
    for n in (C, J):
        n.stop()


without_index()

for n in (A, I, B):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
