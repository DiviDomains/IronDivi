#!/usr/bin/env python3
"""Transaction finality and script flags in blocks, Divi Core divid next to
irondivid on one regtest network.

Three nodes: divid A (listens), irondivid I and divid B (both dial A). A mines
most proof-of-work blocks, irondivid five; then they stake. Rows compare divid B
with irondivid:

1. the lock time, sequences and version each writes in its coinbase and coinstake;
2. createrawtransaction with a lock time parameter; transactions at each
   finality boundary (height and time locks, final sequences) sent to each node,
   which then makes a block: what its mempool said and what went into its block;
3. blocks made by A alone on the tip and changed to hold one transaction each
   (height and time locks around the block's height and time, a locked coinbase
   and coinstake, CHECKLOCKTIMEVERIFY, high S, an undefined hash type, a signature
   that is not strict DER, a non-null multisig dummy, a hybrid key), offered to B
   and I by a raw peer: the reject, the connection, whether the tip moved;
4. the same script cases sent to each mempool;
5. a sibling of the tip block holding a transaction that is not final, offered,
   offered again, a block on it, and a final sibling: the reject, the
   connection, whether the node asks for blocks, what it holds, its chain tips.

Each row prints PASS (the same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs. Started by run.sh, which owns the work
directory and stops the nodes. The helpers are block-rules/check.py's.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
OFFER_WAIT = 5   # seconds to hear a node's answer to a block
TRACE = bool(os.environ.get("TX_FINALITY_TRACE"))
DUMP = os.environ.get("TX_FINALITY_DUMP", "")

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
    if isinstance(v, list) and all(isinstance(x, (str, int, bool)) for x in v):
        return json.dumps(v)[:160]
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
    # before version 4 the header has no accumulator checkpoint
    size = 112 if struct.unpack_from("<i", b, 0)[0] >= 4 else 80
    header = b[:size]
    n, pos = read_compact(b, size)
    txs = []
    for _ in range(n):
        tx, pos = parse_tx(b, pos)
        txs.append(tx)
    size, pos = read_compact(b, pos) if pos < len(b) else (0, pos)
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


# --- a raw peer --------------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
AGENT = b"/tx-finality:1/"


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


def median_time_past_of_parent(node, height):
    times = []
    for k in range(1, 12):
        if height - k < 0:
            break
        times.append(node.rpc("getblock", node.rpc("getblockhash", height - k))["time"])
    return sorted(times)[len(times) // 2]


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

SEQ_FINAL = 0xFFFFFFFF


# --- coins of A, and transactions made with createrawtransaction and signrawtransaction --------

used = set()


def a_coin():
    """A mature coinbase of A that no case has used"""
    for c in sorted(A.rpc("listunspent"), key=lambda c: (-c["confirmations"], c["txid"])):
        key = (c["txid"], c["vout"])
        if key not in used and c["confirmations"] >= 25 and c["spendable"] and sats(c["amount"]) >= 1000 * COIN:
            used.add(key)
            return c
    raise RuntimeError("A has no coin left")


def locked_tx(lock, sequences=(0,), coins=None):
    """A's coins spent back to A with createrawtransaction; the lock time and the
    inputs' sequences set in the bytes (divid's createrawtransaction takes neither,
    rpcrawtransaction.cpp:358-360), then signed with signrawtransaction"""
    coins = coins or [a_coin() for _ in sequences]
    total = sum(sats(c["amount"]) for c in coins)
    hexstr = A.rpc("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]} for c in coins],
                   {A.rpc("getnewaddress"): float(Decimal(total - COIN // 10) / COIN)})
    tx = parse_tx(bytes.fromhex(hexstr))[0]
    tx["lock"] = lock
    for k, s in enumerate(sequences):
        tx["vin"][k][2] = s
    signed = A.rpc("signrawtransaction", tx_bytes(tx).hex())
    if not signed.get("complete"):
        raise RuntimeError("A could not sign a locked transaction")
    return parse_tx(bytes.fromhex(signed["hex"]))[0]


def txid_of(tx):
    return sha256d(tx["raw"])[::-1].hex()


def reply(out):
    """An RPC reply as ("ok", "taken") or ("err", code, its text up to the first colon)"""
    if out[0] == "ok":
        return ("ok", "taken")
    return ("err", out[1], out[2].split(":")[0][:60])


# --- what each node writes in its coinbase and coinstake ---------------------------------------

def lock_and_sequences(node, height):
    block = parse_block(bytes.fromhex(node.rpc("getblock", node.rpc("getblockhash", height), False)))
    out = {}
    for k, name in enumerate(["coinbase", "coinstake"][:len(block["txs"])]):
        tx = block["txs"][k]
        if name == "coinstake" and not (len(tx["vout"]) > 1 and tx["vout"][0] == [0, b""]):
            break
        out[name] = {"lock": tx["lock"], "sequences": sorted({s for _, _, s in tx["vin"]}), "version": tx["version"]}
    return out


t0 = time.time()
# Proof of work: A to 90, irondivid 5, A to 100
A.rpc("setgenerate", 90)
if not synced():
    print("FAIL   setup: the nodes did not follow A's proof-of-work blocks", flush=True)
    sys.exit(1)
iron_pow = I.call("setgenerate", 5)
if not synced():
    print("FAIL   setup: the nodes did not follow irondivid's proof-of-work blocks", flush=True)
    sys.exit(1)
A.rpc("setgenerate", LAST_POW - A.rpc("getblockcount"))
if not synced():
    print("FAIL   setup: the nodes did not reach block 100", flush=True)
    sys.exit(1)
# Coins for B and I to stake
# (small, so that A keeps most of its coinbases for the cases)
for node, sizes in ((I, (2000, 2200, 3000, 3200)), (B, (2100, 2300, 3100, 3300))):
    for size in sizes:
        A.rpc("sendtoaddress", node.rpc("getnewaddress"), size)
stake(A, 1)
print(f"# {A.rpc('getblockcount')} blocks after {time.time() - t0:.0f} s", flush=True)


def stakeable(node):
    for coin in node.rpc("listunspent"):
        if float(coin["amount"]) >= 1000 and coin["confirmations"] >= 20:
            return True
    return False


while A.rpc("getblockcount") < 125:
    stake(A, 1)


# --- 1. coinbase and coinstake --------------------------------------------------------------

print("# 1. lock time and sequences each node writes", flush=True)
compare("proof-of-work coinbase (A at 1, irondivid at 91)", "cb", ("ok", lock_and_sequences(A, 1)),
        ("ok", lock_and_sequences(A, 91)) if iron_pow[0] == "ok" else iron_pow)
h = A.rpc("getblockcount")
stake(B, 1)
stake(I, 1)
compare("proof-of-stake coinbase and coinstake (divid B, irondivid)", "cs",
        ("ok", lock_and_sequences(A, h + 1)), ("ok", lock_and_sequences(A, h + 2)))


# --- 2. createrawtransaction and the mempool, then each node's staker ----------------------

print("# 2. the mempool and the staker", flush=True)
c = a_coin()
compare("createrawtransaction with a third (lock time) parameter", "createrawtransaction",
        B.call("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]}], {B.rpc("getnewaddress"): 1}, 5),
        I.call("createrawtransaction", [{"txid": c["txid"], "vout": c["vout"]}], {I.rpc("getnewaddress"): 1}, 5))
used.discard((c["txid"], c["vout"]))


def staker_round(node):
    """Transactions at the boundaries sent to `node`; then `node` makes the next
    block. What its mempool said to each, and which went into its block."""
    tip = node.rpc("getblockcount")
    now = int(time.time())
    cases = [
        ("height lock tip+1 (the next block's height)", locked_tx(tip + 1)),
        ("height lock tip", locked_tx(tip)),
        ("height lock tip+1, all sequences final", locked_tx(tip + 1, (SEQ_FINAL,))),
        ("height lock tip+1, one input final, one not", locked_tx(tip + 1, (SEQ_FINAL, 0))),
        ("time lock 600 s ahead", locked_tx(now + 600)),
        ("time lock 120 s ago", locked_tx(now - 120)),
        ("time lock 500000000", locked_tx(500_000_000)),
        ("height lock 499999999", locked_tx(499_999_999)),
    ]
    out = {}
    for name, tx in cases:
        out[name] = [str(x) for x in reply(node.call("sendrawtransaction", tx["raw"].hex()))]
    stake(node, 1)
    block = node.rpc("getblock", node.rpc("getblockhash", tip + 1))
    for name, tx in cases:
        out[name].append("in block" if txid_of(tx) in block["tx"] else "not in block")
    return out


core_round = staker_round(B)
iron_round = staker_round(I)
for name in core_round:
    compare(f"sent, then the node stakes: {name}", "round", ("ok", core_round[name]), ("ok", iron_round[name]))
# What is left in the mempools (the refused ones were not taken)
synced()
compare("mempool after both rounds", "mempool", ("ok", len(B.rpc("getrawmempool"))), ("ok", len(I.rpc("getrawmempool"))))
# Those refused for now are taken once the chain passes their lock: one
# transaction for each node, so that relay does not answer for the other
lock = A.rpc("getblockcount") + 1
pending = {n.name: locked_tx(lock) for n in (B, I)}
send = lambda n: reply(n.call("sendrawtransaction", pending[n.name]["raw"].hex()))
compare("height lock tip+1, sent now", "late", send(B), send(I))
stake(A, 1)
compare("the same, one block later", "late", send(B), send(I))
# each node makes a block; each transaction is then in the chain (relay may have
# put it in the other node's block first)
stake(B, 1)
stake(I, 1)
mined = lambda n: rawtx(n, txid_of(pending[n.name])).get("confirmations", 0) > 0
compare("the same, in the chain once each node made a block", "late", ("ok", mined(B)), ("ok", mined(I)))


# --- 3. script outputs for the flag cases -----------------------------------------------------

def push(data):
    if len(data) < 0x4c:
        return bytes([len(data)]) + data
    return bytes([0x4c, len(data)]) + data


def script_num(n):
    if n == 0:
        return b""
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes(out)


def ripemd160(msg):
    """RIPEMD-160 (this host's hashlib has none)"""
    rl = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    rr = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    sl = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    sr = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    kl = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    kr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
    fs = [lambda x, y, z: x ^ y ^ z, lambda x, y, z: (x & y) | (~x & z), lambda x, y, z: (x | ~y) ^ z,
          lambda x, y, z: (x & z) | (y & ~z), lambda x, y, z: x ^ (y | ~z)]
    rol = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    data = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack("<Q", 8 * len(msg))
    for off in range(0, len(data), 64):
        x = struct.unpack("<16I", data[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j // 16
            t = rol((al + (fs[r](bl, cl, dl) & 0xFFFFFFFF) + x[rl[j]] + kl[r]) & 0xFFFFFFFF, sl[j]) + el
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t & 0xFFFFFFFF
            t = rol((ar + (fs[4 - r](br, cr, dr) & 0xFFFFFFFF) + x[rr[j]] + kr[r]) & 0xFFFFFFFF, sr[j]) + er
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t & 0xFFFFFFFF
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return struct.pack("<5I", *h)


def hash160(b):
    return ripemd160(hashlib.sha256(b).digest())


def p2sh(redeem):
    return b"\xa9\x14" + hash160(redeem) + b"\x87"


key_address = A.rpc("getnewaddress")
SECRET = wif_secret(A.rpc("dumpprivkey", key_address))
PX, PY = ec_mul(SECRET)
PUB = bytes([2 + (PY & 1)]) + PX.to_bytes(32, "big")
HYBRID = bytes([6 + (PY & 1)]) + PX.to_bytes(32, "big") + PY.to_bytes(32, "big")
LOCK_HEIGHT = 50
LOCK_TIME = int(time.time()) - 3600
CLTV_H = push(script_num(LOCK_HEIGHT)) + b"\xb1\x75\x51"     # <50> CLTV DROP TRUE
CLTV_T = push(script_num(LOCK_TIME)) + b"\xb1\x75\x51"
MULTI = b"\x51" + push(PUB) + b"\x51\xae"                      # 1 <key> 1 CHECKMULTISIG
OUTPUTS = {"cltv height": p2sh(CLTV_H), "cltv time": p2sh(CLTV_T), "multisig": MULTI,
           "hybrid": push(HYBRID) + b"\xac", "p2pkh": p2pkh_script(key_address)}
P2PKH_COUNT = 6


def fund():
    """One transaction of A paying 10 DIVI to each script, P2PKH_COUNT of them for the key"""
    coin = a_coin()
    scripts = [(n, s) for n, s in OUTPUTS.items() if n != "p2pkh"] + [("p2pkh", OUTPUTS["p2pkh"])] * P2PKH_COUNT
    vout = [[10 * COIN, s] for _, s in scripts]
    vout.append([sats(coin["amount"]) - 10 * COIN * len(scripts) - COIN, own_script(A)])
    tx = refresh({"version": 1, "vin": [[outpoint(coin["txid"], coin["vout"]), b"", SEQ_FINAL]], "vout": vout, "lock": 0})
    tx = sign_with(A, tx, [(coin["txid"], coin["vout"])])
    txid = A.rpc("sendrawtransaction", tx["raw"].hex())
    coins = {}
    for k, (name, _) in enumerate(scripts):
        coins.setdefault(name, []).append((txid, k))
    return coins


# one set of coins for the blocks, one for the mempools: a block case that is
# taken and put back with invalidateblock leaves its transaction in the mempool
FUNDED = fund()
FUNDED_POOL = fund()
stake(A, 1)


def der_int(n):
    b = n.to_bytes((n.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + bytes([len(b)]) + b


def sign_der(digest, high_s=False, pad_r=False):
    z = int.from_bytes(digest, "big")
    while True:
        k = secrets.randbelow(N_ORDER - 1) + 1
        r = ec_mul(k)[0] % N_ORDER
        s = (z + r * SECRET) * pow(k, -1, N_ORDER) % N_ORDER
        if r == 0 or s == 0:
            continue
        if (s > N_ORDER // 2) != high_s:
            s = N_ORDER - s
        rb = der_int(r)
        if pad_r:
            rb = b"\x02" + bytes([rb[1] + 1]) + b"\x00" + rb[2:]
        body = rb + der_int(s)
        return b"\x30" + bytes([len(body)]) + body


def sighash(tx, i, script_code, hashtype):
    """The legacy signature hash, SIGHASH_ALL form (any type not NONE or SINGLE
    hashes as ALL; the type is written as given)"""
    copy = dict(tx, vin=[[p, script_code if k == i else b"", s] for k, (p, _, s) in enumerate(tx["vin"])])
    return sha256d(tx_bytes(copy) + struct.pack("<I", hashtype))


def spend(coin, script_sig_fn, lock=0, sequence=SEQ_FINAL):
    txid, n = coin
    tx = {"version": 1, "vin": [[outpoint(txid, n), b"", sequence]],
          "vout": [[10 * COIN - COIN // 10, own_script(A)]], "lock": lock}
    tx["vin"][0][1] = script_sig_fn(tx)
    return refresh(tx)


def key_sig(script_code, hashtype=1, **kw):
    def make(tx):
        return push(sign_der(sighash(tx, 0, script_code, hashtype), **kw) + bytes([hashtype]))
    return make


P2PKH_SCRIPT = OUTPUTS["p2pkh"]


def script_cases(height, funded):
    """(name, tx) for a block at `height`, spending the coins `funded`"""
    pk_coins = funded["p2pkh"]
    ch, ct = funded["cltv height"][0], funded["cltv time"][0]
    redeem = lambda r: (lambda tx: push(r))
    cases = [
        ("own signer, low S (sanity)", spend(pk_coins[0], lambda tx: key_sig(P2PKH_SCRIPT)(tx) + push(PUB))),
        ("high S signature", spend(pk_coins[1], lambda tx: key_sig(P2PKH_SCRIPT, high_s=True)(tx) + push(PUB))),
        ("undefined hash type 0x05", spend(pk_coins[2], lambda tx: key_sig(P2PKH_SCRIPT, hashtype=5)(tx) + push(PUB))),
        ("signature not strict DER (R padded)", spend(pk_coins[3], lambda tx: key_sig(P2PKH_SCRIPT, pad_r=True)(tx) + push(PUB))),
        ("multisig with a non-null dummy", spend(funded["multisig"][0], lambda tx: b"\x51" + key_sig(MULTI)(tx))),
        ("multisig with a null dummy", spend(funded["multisig"][0], lambda tx: b"\x00" + key_sig(MULTI)(tx))),
        ("pay-to-key with a hybrid key", spend(funded["hybrid"][0], key_sig(push(HYBRID) + b"\xac"))),
        ("CLTV height: lock at the script's", spend(ch, redeem(CLTV_H), lock=LOCK_HEIGHT, sequence=0)),
        ("CLTV height: lock one below", spend(ch, redeem(CLTV_H), lock=LOCK_HEIGHT - 1, sequence=0)),
        ("CLTV height: input final", spend(ch, redeem(CLTV_H), lock=LOCK_HEIGHT, sequence=SEQ_FINAL)),
        ("CLTV height: a time lock", spend(ch, redeem(CLTV_H), lock=LOCK_TIME, sequence=0)),
        ("CLTV height: lock at the block's height (not final)", spend(ch, redeem(CLTV_H), lock=height, sequence=0)),
        ("CLTV time: lock at the script's", spend(ct, redeem(CLTV_T), lock=LOCK_TIME, sequence=0)),
        ("CLTV time: lock one below", spend(ct, redeem(CLTV_T), lock=LOCK_TIME - 1, sequence=0)),
    ]
    return cases


# --- 4. blocks built on the tip, holding one transaction each ----------------------------------


def with_txs(good_hex, txs, secret, time_=None, coinbase=None, coinstake=None):
    b = parse_block(bytes.fromhex(good_hex))
    b["txs"] = b["txs"][:2] + list(txs)
    if coinbase:
        coinbase(b["txs"][0])
    if coinstake:
        b["txs"][1] = coinstake
    if time_ is not None:
        set_header(b, TIME, struct.pack("<I", time_))
    return finish(b, secret)


def coinstake_locked(good_hex, lock, sequence):
    """The block's coinstake with this lock time and sequence, signed again by A"""
    b = parse_block(bytes.fromhex(good_hex))
    old = b["txs"][1]
    prev = old["vin"][0][0]
    txid, n = prev[:32][::-1].hex(), struct.unpack("<I", prev[32:])[0]
    tx = {"version": old["version"], "vin": [[prev, b"", sequence]], "vout": [list(o) for o in old["vout"]], "lock": lock}
    return sign_with(A, refresh(tx), [(txid, n)])


def lock_coinbase(lock, sequence):
    def edit(tx):
        tx["lock"] = lock
        tx["vin"][0][2] = sequence
    return edit


print("# 3. blocks on the tip, offered to divid B and irondivid by a raw peer", flush=True)
stake(A, 1)
isolate(A, True)
good = stake_alone(A)
H = A.rpc("getblockcount")
blk = parse_block(bytes.fromhex(good))
T = struct.unpack_from("<I", blk["header"], TIME)[0]
MTP = median_time_past_of_parent(A, H)
secret = staker_secret(A, blk)
print(f"# block {H}, time {T}, parent's median time past {MTP}", flush=True)
tip_cases = [
    ("height lock H (the block's height)", [locked_tx(H)]),
    ("height lock H-1", [locked_tx(H - 1)]),
    ("height lock H+1", [locked_tx(H + 1)]),
    ("height lock H, all sequences final", [locked_tx(H, (SEQ_FINAL,))]),
    ("height lock H, two inputs, one final", [locked_tx(H, (SEQ_FINAL, 0))]),
    ("height lock 499999999", [locked_tx(499_999_999)]),
    ("time lock 500000000", [locked_tx(500_000_000)]),
    ("time lock at the block's time", [locked_tx(T)]),
    ("time lock one below the block's time", [locked_tx(T - 1)]),
    ("time lock one past the block's time", [locked_tx(T + 1)]),
    ("time lock at the median time past (below the block's time)", [locked_tx(MTP)]),
]
for name, txs in tip_cases:
    check_case(f"tip: {name}", with_txs(good, txs, secret))
check_case("tip: coinbase with lock H, sequence 0", with_txs(good, [], secret, coinbase=lock_coinbase(H, 0)))
check_case("tip: coinbase with lock H, sequence final", with_txs(good, [], secret, coinbase=lock_coinbase(H, SEQ_FINAL)))
check_case("tip: coinbase with lock H-1, sequence 0", with_txs(good, [], secret, coinbase=lock_coinbase(H - 1, 0)))
check_case("tip: coinstake with lock H, sequence 0", with_txs(good, [], secret, coinstake=coinstake_locked(good, H, 0)))
check_case("tip: coinstake with lock H-1, sequence 0", with_txs(good, [], secret, coinstake=coinstake_locked(good, H - 1, 0)))
check_case("tip: coinstake with lock past the block's time, sequence 0",
           with_txs(good, [], secret, coinstake=coinstake_locked(good, T + 1, 0)))
for name, tx in script_cases(H, FUNDED):
    check_case(f"tip: {name}", with_txs(good, [tx], secret))
# Each script case sent to the mempools, while A is away so that B and I, which
# have no other peer, relay nothing to each other
print("# 4. the same script cases sent to the mempool", flush=True)
for name, tx in script_cases(H, FUNDED_POOL):
    if "not final" in name:
        continue
    compare(f"mempool: {name}", "sendrawtransaction", reply(B.call("sendrawtransaction", tx["raw"].hex())),
            reply(I.call("sendrawtransaction", tx["raw"].hex())))
check_case("tip: the block as made", good, restore=False)
isolate(A, False)
if not synced(secs=180):
    raise RuntimeError("A did not join the network again")


# --- 5. a block beside the tip ---------------------------------------------------------------

print("# 5. side chain: a sibling of the tip block holding a transaction that is not final", flush=True)
stake(A, 1)
isolate(A, True)
side_parent_height = A.rpc("getblockcount") - 1
tip_hex = A.rpc("getblock", A.rpc("getbestblockhash"), False)
A_tip = A.rpc("getbestblockhash")
isolate(A, False)
synced()
tip_blk = parse_block(bytes.fromhex(tip_hex))
H2 = side_parent_height + 1
secret = staker_secret(A, tip_blk)
T2 = struct.unpack_from("<I", tip_blk["header"], TIME)[0]
nonfinal = with_txs(tip_hex, [locked_tx(H2)], secret, time_=T2 + 1)
final = with_txs(tip_hex, [locked_tx(H2 - 1)], secret, time_=T2 + 2)
hashes = [block_hash(nonfinal)]
before = {n.name: chain_tips(n) for n in (B, I)}
check_case("side: the non-final sibling, offered", nonfinal, watch=True)
compare("side: after it: held and chain tips", "chain_state",
        chain_state(B, hashes, before[B.name]), chain_state(I, hashes, before[I.name]))
check_case("side: the non-final sibling, offered again", nonfinal, watch=True)
kid = child_of(nonfinal, hashes[0], H2 + 1, secret)
hashes.append(block_hash(kid))
check_case("side: a block on the non-final sibling (its branch now the longer)", kid, watch=True)
compare("side: after it: held and chain tips", "chain_state",
        chain_state(B, hashes, before[B.name]), chain_state(I, hashes, before[I.name]))
check_case("side: the final sibling (lock H-1)", final, watch=True)
compare("side: after it: held and chain tips", "chain_state",
        chain_state(B, [block_hash(final)], before[B.name]), chain_state(I, [block_hash(final)], before[I.name]))
compare("side: tips unchanged", "tip", ("ok", B.rpc("getbestblockhash") == A_tip), ("ok", I.rpc("getbestblockhash") == A_tip))

# A valid block from another peer afterwards
stake(A, 1)
row("after the cases: a block from A reaches both", f"{B.rpc('getblockcount')}", f"{I.rpc('getblockcount')}",
    synced(secs=60))

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
