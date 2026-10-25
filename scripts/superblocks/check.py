#!/usr/bin/env python3
"""Lottery and treasury superblocks of Divi Core divid and irondivid on one
regtest network, compared block by block.

Three nodes: divid A (listens), irondivid I and divid B (both dial A). A mines
the proof-of-work blocks and pays stakes of different sizes (each over the
10 000 DIVI lottery ticket minimum) to addresses of all three wallets; then A,
I and B take turns staking (`setgenerate` on the node whose turn it is, every
node with staking=0 otherwise), so each daemon makes superblocks the other
checks. After every block the rows compare getlotteryblockwinners and, at each
superblock, the coinstake's payees and amounts on both daemons. Then blocks
paying the wrong lottery winner or the wrong treasury amount are offered by a
raw peer, and the winners are compared again after invalidateblock and
reconsiderblock, a restart and -reindex.

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
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
DUMP = os.environ.get("SUPERBLOCKS_DUMP", "")

# Regtest (chainparams.cpp:473-498): last proof-of-work block 100; lottery from
# 101 every 10 blocks, treasury from 102 every 50, until the switch at 10 * 50 =
# 500 (SuperblockHeightValidator.cpp:6-11, LegacyBlockSubsidies.cpp:98-108)
LAST_POW = 100
LOTTERY = [h for h in range(110, 500, 10)]
TREASURY = [h for h in range(150, 500, 50)]

ORDER = ("irondivid writes the members of a result in name order, divid in the order it adds them "
         "(json_spirit Object); docs/divid-differences.md R6")
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


class Node:
    def __init__(self, name, binary, index, extra_conf):
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
            "txindex=1", "addressindex=1", "spentindex=1",
        ] + list(extra_conf)
        self.write_conf()
        self.proc = None
        self.start()

    def write_conf(self, extra=()):
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")

    def start(self, args=()):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"] + list(args), cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
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


# Reply kinds whose field order irondivid does not keep (R6), each with a row
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
# Stakes of different sizes, each over the 10 000 DIVI ticket minimum
# (LotteryWinnersCalculator.cpp:27-37, :50-61), to addresses of each wallet
# (the coinbases of blocks 1-80, 100 000 DIVI, are mature at block 100). I and B
# hold only these coins, so each of their coinstakes is a ticket; two of I's go
# to one address, so one payee can win twice in a cycle. A keeps its coinbases
# and stakes with them when neither I nor B has a coin to stake (a coin that
# stakes is immature for the next 20 blocks).
dup = I.rpc("getnewaddress")
STAKES = {A: [(None, 10800)], I: [(dup, 10500), (dup, 11000), (None, 11000), (None, 12000)],
          B: [(None, 10200), (None, 13000), (None, 11500)]}
for node, coins in STAKES.items():
    for address, size in coins:
        A.rpc("sendtoaddress", address or node.rpc("getnewaddress"), size)
stake(A, 1)
print(f"# {A.rpc('getblockcount')} blocks after {time.time() - t0:.0f} s", flush=True)


def winners_rows(height):
    both(f"getlotteryblockwinners at {height}", "getlotteryblockwinners")


def winners(node, *height):
    out = node.call("getlotteryblockwinners", *height)
    return out[1] if out[0] == "ok" else None


def winner_addresses(node, height):
    w = winners(node, height) or {}
    return [c.get("Address") for c in w.get("Lottery Candidates", [])]


# Turns: A, then irondivid, then B, then irondivid again; after each block the
# winners on both daemons
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


while A.rpc("getblockcount") < 216:
    h, node = next_block()
    both(f"getlotteryblockwinners after block {h} (by {node.name})", "getlotteryblockwinners")
    if os.environ.get("SUPERBLOCKS_TRACE"):
        cs = A.rpc("getrawtransaction", A.rpc("getblock", A.rpc("getblockhash", h))["tx"][1], 1)
        vals = [o["value"] for o in cs["vout"]]
        print(f"#   {h} by {node.name}: {len(winner_addresses(A, h))} candidates; coinstake outputs {vals}", flush=True)
print(f"# staked to {A.rpc('getblockcount')} after {time.time() - t0:.0f} s; blocks made: " +
      ", ".join(f"{n} {sum(v == n for v in made_by.values())}" for n in (A.name, I.name, B.name)), flush=True)


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
AGENT = b"/superblocks:1/"


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


def bad_superblocks(height, variants):
    """A, alone, makes the superblock at `height` (A can always stake, with its
    coinbases); each changed copy is offered by a raw peer to divid B and to
    irondivid, then the block as A made it; A then joins again"""
    to_height(height - 1)
    isolate(A, True)
    good = stake_alone(A)
    for name, change in variants:
        bad = changed_block(A, good, change)
        compare(f"superblock {height} {name}: offered by a raw peer", "block",
                offer_block(B, bad), offer_block(I, bad))
    compare(f"superblock {height} as made: offered by a raw peer", "block", offer_block(B, good), offer_block(I, good))
    isolate(A, False)
    if not synced(secs=180):
        raise RuntimeError("A did not join the network again")


TREASURY_ADDRESS = "xw7G6toCcLr2J7ZK8zTfVRhAPiNc8AyxCd"  # BlockIncentivesPopulator.cpp:31-32
CHARITY_ADDRESS = "y8zytdJziDeXcdk48Wv7LH6FgnF4zDiXM5"
NOBODY = b58check(bytes([139]) + secrets.token_bytes(20))


def lottery_payouts(height):
    """The output positions of the lottery payments in the coinstake at `height`:
    the winners at height - 1, in their order"""
    wins = winner_addresses(A, height - 1)
    return [p2pkh_script(a) for a in wins]


def change_payout(script_list, which, how):
    def change(vout):
        target = script_list[which]
        for o in vout:
            if o[1] == target:
                how(o)
                return
        raise RuntimeError("payout not found in the coinstake")
    return change


# Lottery superblock 220: the first winner paid to somebody else, paid one
# satoshi less, and the last winner left out
# (the first lottery superblock from 220 whose winners are three or more, so the
# first and the last winner are not one)
L = 220
to_height(L - 1)
while len(lottery_payouts(L)) < 3 and L < 330:
    L += 10
    to_height(L - 1)
scripts = lottery_payouts(L)
print(f"# superblock {L}: {len(scripts)} winners", flush=True)
bad_superblocks(L, [
    ("paying the first winner's reward to another address",
     change_payout(scripts, 0, lambda o: o.__setitem__(1, p2pkh_script(NOBODY)))),
    ("paying the first winner one satoshi less", change_payout(scripts, 0, lambda o: o.__setitem__(0, o[0] - 1))),
    ("leaving out the last winner",
     lambda vout: vout.remove(next(o for o in vout if o[1] == scripts[-1]))),
])

# The next treasury superblock: the treasury paid one satoshi less, one more,
# paid to another address, the charity left out
T = min(t for t in TREASURY if t > L)
treasury_script, charity_script = p2pkh_script(TREASURY_ADDRESS), p2pkh_script(CHARITY_ADDRESS)
bad_superblocks(T, [
    ("paying the treasury one satoshi less",
     change_payout([treasury_script], 0, lambda o: o.__setitem__(0, o[0] - 1))),
    ("paying the treasury's amount to another address",
     change_payout([treasury_script], 0, lambda o: o.__setitem__(1, p2pkh_script(NOBODY)))),
    ("leaving out the charity", lambda vout: vout.remove(next(o for o in vout if o[1] == charity_script))),
    ("paying the treasury one satoshi more",
     change_payout([treasury_script], 0, lambda o: o.__setitem__(0, o[0] + 1))),
])
to_height(T + 12)
TIP = A.rpc("getblockcount")


# --- each superblock -----------------------------------------------------------------------

def superblock_rows(tag=""):
    tip = A.rpc("getblockcount")
    for h in sorted(set(LOTTERY + TREASURY)):
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
superblock_rows()


def cycle_rows(tag=""):
    """Per lottery cycle: how many candidates, how many distinct payees, on both"""
    tip = A.rpc("getblockcount")
    for h in LOTTERY:
        if h > tip:
            break
        c, i = winner_addresses(A, h - 1), winner_addresses(I, h - 1)
        sc = f"{len(c)} candidates, {len(set(c))} payees"
        si = f"{len(i)} candidates, {len(set(i))} payees"
        row(f"{tag}cycle to lottery block {h}: winners at {h - 1}", sc, si, c == i)


cycle_rows()


# --- getlotteryblockwinners arguments ------------------------------------------------------

def argument_rows(tag=""):
    tip = A.rpc("getblockcount")
    for label, args in (("no argument", []), ("0", [0]), ("100, before the lottery start", [100]),
                        ("101, the lottery start", [101]), ("105, between superblocks", [105]),
                        ("110, a superblock", [110]), ("111", [111]), ("150, a treasury block", [150]),
                        ("the tip", [tip]), ("above the tip", [tip + 25]), ("text", ["abc"]),
                        ("a real", [1.5]), ("two arguments", [1, 2])):
        both(f"{tag}getlotteryblockwinners {label}", "getlotteryblockwinners", *args)
    row(f"{tag}getlotteryblockwinners -1", "not sent", short(I.call("getlotteryblockwinners", -1)), False)


KNOWN["getlotteryblockwinners -1"] = (
    "not sent to divid: it reads the block at height -1, a null pointer (rpclottery.cpp:48-51), and stops")
argument_rows()


def winners_at(heights, tag):
    for h in heights:
        both(f"{tag}: getlotteryblockwinners {h}", "getlotteryblockwinners", h)


CHECK_HEIGHTS = [109, 110, 119, 149, 150, 151, L - 1, L, T - 1, T, TIP]

# invalidateblock back over the treasury superblock T and the lottery superblock
# L, then reconsiderblock
for h in (T, L):
    target = A.rpc("getblockhash", h)
    for n in (A, I):
        n.rpc("invalidateblock", target)
    both(f"after invalidateblock {h}: getblockcount", "getblockcount")
    both(f"after invalidateblock {h}: getlotteryblockwinners", "getlotteryblockwinners")
    winners_at([h - 1, h], f"after invalidateblock {h}")
    for n in (A, I):
        n.rpc("reconsiderblock", target)
    wait_for(lambda: A.rpc("getblockcount") == TIP and I.rpc("getblockcount") == TIP, 60)
    both(f"after reconsiderblock {h}: getblockcount", "getblockcount")
    winners_at([h - 1, h, TIP], f"after reconsiderblock {h}")

# A restart of all three, then -reindex on A and irondivid
for n in (A, I, B):
    n.stop()
for n in (A, I, B):
    n.start()
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start again")
synced()
winners_at(CHECK_HEIGHTS, "after a restart")
for n in (A, I):
    n.stop()
for n in (A, I):
    n.start(["-reindex"])
wait_for(lambda: A.rpc("getblockcount") == TIP and I.rpc("getblockcount") == TIP, 300)
both("after -reindex: getblockcount", "getblockcount")
winners_at(CHECK_HEIGHTS, "after -reindex")
superblock_rows("after -reindex: ")
for kind in sorted(set(order_seen) | set(ORDER_KINDS)):
    name = f"{kind}: field order"
    KNOWN[name] = ORDER
    seen = order_seen.get(kind)
    row(name, seen[1] if seen else "same", seen[2] if seen else "same", seen is None)

for n in (A, I, B):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
