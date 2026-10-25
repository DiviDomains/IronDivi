#!/usr/bin/env python3
"""The relay-policy options Divi Core's mempool reads, on divid and irondivid:
-permitbaremultisig, -datacarrier, -datacarriersize, -limitfreerelay and
-relaypriority (MempoolConsensus.cpp:29-266).

Setup: divid and irondivid restored from divid's phrase share one regtest chain
with a set of coins of the wallet: old ones of 100 DIVI (enough coin age for a
free transaction) and young ones of 1 DIVI (too little). divid signs, with
signrawtransaction, every transaction a case offers: bare multisig outputs
1-of-1 to 3-of-3 (and 1-of-4), OP_META outputs around the size limits, two
OP_META outputs, free transactions of high and low priority, a batch of free
transactions for the rate limiter, and a plain paying one. Then both nodes stop
and their datadirs are kept as templates.

For each set of options, fresh copies of both datadirs start with those options
and no peers. The same transactions go to both, once by sendrawtransaction (one
pair of copies) and once from a raw p2p peer (another pair): the reply or the
peer's `reject` (code and reason) and the mempool are compared. Each row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit
code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in RPC replies and in irondivid's environment at its first
start; it is never printed, written to a file or put on a command line.
"""

import base64
import hashlib
import json
import os
import re
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
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("RELAY_POLICY_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("RELAY_POLICY_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true.
KNOWN = {
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {}
extra_seen = {}

fails = 0


def known(name):
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
    line = f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"
    print(line.replace("\n", "\\n")[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None, template=None):
        """A node with a datadir of its own, or a copy of `template`'s (a
        stopped node's datadir, chain and wallet), with a divi.conf of its own"""
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        if template:
            shutil.copytree(template, self.dir)
            os.remove(os.path.join(self.dir, "divi.conf"))
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir, exist_ok=True)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0", "txindex=1",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        # Text as UTF-8, not as \u escapes: divid reads an escape above 0xff as
        # one byte (scripts/cli-replies)
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)},
                          ensure_ascii=False).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (OSError, ValueError) as e:
            # No reply at all (the node stopped or closed the connection): a row
            # that differs, not the end of the run
            return ("err", "no reply", f"{type(e).__name__}: {e}"[:120])
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


def kind(v):
    return {dict: "object", list: "array", str: "string", bool: "bool", int: "int", type(None): "null"}.get(type(v), "?")


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Reals are compared as divid writes
    them (the text of the number); a real and an integer are different types."""
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
    if type(a) is not type(b):
        return f"{path}: {kind(a)} {json.dumps(a)[:40]} vs {kind(b)} {json.dumps(b)[:40]}"
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:80]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, dict):
        return dict(v, injected=True)
    if isinstance(v, list):
        return v + ["injected"]
    if isinstance(v, int) and not isinstance(v, bool):
        return v + 1
    return "injected"


# divid's help texts name sample addresses in their examples; irondivid's write
# them "diviaddress" (no address of anyone's wallet is written in the tree). A
# help text given as an error is compared with those written alike, as
# scripts/help-replies compares them.
SAMPLE_ADDRESS = re.compile(r"(?<![0-9A-Za-z])(?=[1-9A-HJ-NP-Za-km-z]*\d)(?=[1-9A-HJ-NP-Za-km-z]*[A-Za-z])"
                            r"[1-9A-HJ-NP-Za-km-z]{26,35}(?![0-9A-Za-z])")


def help_text_samples(out):
    if out[0] == "err" and isinstance(out[2], str) and "\nExamples:\n" in out[2]:
        return ("err", out[1], SAMPLE_ADDRESS.sub("diviaddress", out[2]))
    return out


def as_utf8(v):
    """divid writes each byte of a non-ASCII text as its own \\u00XX escape
    (json_spirit), so a JSON reader sees one character per byte; divi-cli reads
    them back as bytes. A text whose characters are all below 0x100 and whose
    bytes are UTF-8 is read as divi-cli reads it (the raw form has a row of its
    own, KNOWN)"""
    if isinstance(v, dict):
        return {as_utf8(k): as_utf8(x) for k, x in v.items()}
    if isinstance(v, list):
        return [as_utf8(x) for x in v]
    if isinstance(v, str) and any(ord(c) > 0x7f for c in v) and all(ord(c) < 0x100 for c in v):
        try:
            return v.encode("latin-1").decode("utf-8")
        except UnicodeDecodeError:
            return v
    return v


def compare(name, core, iron, drop=frozenset(), order=None):
    """Same outcome (a result, or an error with the same code and message); for a
    result the same fields, types and values (except `drop`), list items in
    divid's order unless `order` gives a sort key"""
    core, iron = help_text_samples(core), help_text_samples(iron)
    if core[0] == "ok":
        core = ("ok", as_utf8(core[1]))
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if DUMP and not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        dump(name, ("ok", a), ("ok", b))
    row(name, short(core), d or short(iron), d is None)


def dump(name, core, iron):
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def members(v):
    """The member names of a reply in their order: of the reply, or of its first
    item; None when it has none"""
    if isinstance(v, list) and v:
        v = v[0]
    return list(v) if isinstance(v, dict) else None


order_seen = {}


def note_order(method, core, iron):
    """The order of the members, once per call, compared in a row at the end"""
    if method not in order_seen and core[0] == iron[0] == "ok":
        a, b = members(core[1]), members(iron[1])
        if a is not None and b is not None:
            order_seen[method] = (a, [k for k in b if k not in EXTRA.get(method, ())])


def order_rows():
    for method, (a, b) in order_seen.items():
        row(f"{method}: member order", ",".join(a)[:120], ",".join(b)[:120], a == b)


def strip_extra(method, v):
    """irondivid's reply without the fields it adds on purpose, which are noted
    for the "fields divid lacks" row"""
    extra = EXTRA.get(method)
    if not extra:
        return v
    extra_seen.setdefault("", {}).setdefault(method, set()).update(set(fields_in(v)) & extra)
    return strip(v, extra)


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    note_order(method, core, iron)
    if iron[0] == "ok":
        iron = ("ok", strip_extra(method, iron[1]))
    compare(name, core, iron, **kw)


def fields_in(v):
    """Every member name in a reply, at any depth"""
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from fields_in(x)
    elif isinstance(v, list):
        for x in v:
            yield from fields_in(x)


def extra_rows(when):
    p = f"{when}: " if when else ""
    for method in EXTRA:
        found = extra_seen.get(when, {}).get(method, set())
        row(f"{p}{method}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


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


def setup_failed(kind_, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 90)


def seen_by(node, txid):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), 60)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s







def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    data = n.to_bytes(25, "big")
    return data[1:21]


def p2pkh(address):
    return bytes.fromhex("76a914") + b58decode(address) + bytes.fromhex("88ac")


# --- transactions, serialized here so any of them can be made ------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def serialize(vin, vout, locktime=0, version=1):
    """vin: (txid, n, scriptSig bytes, sequence); vout: (satoshis, script bytes)"""
    b = struct.pack("<i", version) + compact(len(vin))
    for txid, n, script, seq in vin:
        b += bytes.fromhex(txid)[::-1] + struct.pack("<I", n) + compact(len(script)) + script + struct.pack("<I", seq)
    b += compact(len(vout))
    for value, script in vout:
        b += struct.pack("<q", value) + compact(len(script)) + script
    return (b + struct.pack("<I", locktime)).hex()


def txid_of(hexstr):
    return hashlib.sha256(hashlib.sha256(bytes.fromhex(hexstr)).digest()).digest()[::-1].hex()


def spend(coin, outputs, locktime=0, seq=0xffffffff):
    """An unsigned spend of coin = (txid, n)"""
    return serialize([(coin[0], coin[1], b"", seq)], outputs, locktime)



MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])


def message(command, payload=b""):
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + check + payload


def netaddr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton("127.0.0.2") + struct.pack(">H", port)


def read_message(sock):
    head = b""
    while len(head) < 24:
        part = sock.recv(24 - len(head))
        if not part:
            raise EOFError
        head += part
    command = head[4:16].rstrip(b"\0").decode()
    size = struct.unpack("<I", head[16:20])[0]
    payload = b""
    while len(payload) < size:
        part = sock.recv(size - len(payload))
        if not part:
            raise EOFError
        payload += part
    return command, payload


def varstr(b, pos):
    n = b[pos]
    pos += 1
    return b[pos:pos + n].decode(errors="replace"), pos + n


def p2p_reject(port, hexstr):
    """What the node answers a peer that relays the transaction: its `reject`
    (command, code, reason, the txid it names) or None, within 5 seconds"""
    sock = socket.create_connection(("127.0.0.2", port), timeout=10)
    try:
        version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(port) + netaddr(0)
                   + secrets.token_bytes(8) + bytes([18]) + b"/relay-policy:01/" + struct.pack("<i", 0) + b"\x01")
        sock.sendall(message("version", version))
        got_version = got_verack = False
        deadline = time.time() + 10
        while not (got_version and got_verack) and time.time() < deadline:
            command, payload = read_message(sock)
            if command == "version":
                got_version = True
                sock.sendall(message("verack"))
            elif command == "verack":
                got_verack = True
        if not (got_version and got_verack):
            return "no handshake"
        sock.sendall(message("tx", bytes.fromhex(hexstr)))
        deadline = time.time() + 5
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                command, payload = read_message(sock)
            except socket.timeout:
                break
            except (EOFError, ConnectionError):
                return "disconnected without a reject"
            if command == "ping":
                sock.sendall(message("pong", payload))
            elif command == "reject":
                what, pos = varstr(payload, 0)
                code = payload[pos]
                reason, pos = varstr(payload, pos + 1)
                return [what, code, reason, payload[pos:][::-1].hex()]
        return None
    finally:
        sock.close()




SAT = 100_000_000
FEE = 100_000  # 0.001 DIVI: well over the relay fee of these sizes


def wait_all(nodes, secs=90):
    tip = nodes[0].rpc("getbestblockhash")
    if not all(wait_for(lambda n=n: n.rpc("getbestblockhash") == tip, secs) for n in nodes):
        raise RuntimeError("the nodes did not follow the chain")


def mine(n):
    """n blocks on the miner, one call at a time (a stake block can be refused
    until the clock passes the median time of the last blocks)"""
    for _ in range(n):
        if not wait_for(lambda: M.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"the miner could not mine block {M.rpc('getblockcount') + 1}")
    wait_all([M, C, I])


def multisig(m, keys):
    """A bare m-of-n CHECKMULTISIG script"""
    return bytes([0x50 + m]) + b"".join(bytes([33]) + bytes.fromhex(k) for k in keys) + bytes([0x50 + len(keys), 0xae])


def meta(size):
    """An OP_META output script of `size` bytes: OP_META and one push"""
    if size == 1:
        return bytes([0x6a])
    if size - 2 <= 75:
        return bytes([0x6a, size - 2]) + secrets.token_bytes(size - 2)
    if size - 3 <= 255:
        return bytes([0x6a, 0x4c, size - 3]) + secrets.token_bytes(size - 3)
    return bytes([0x6a, 0x4d]) + struct.pack("<H", size - 4) + secrets.token_bytes(size - 4)


# --- setup: one chain, coins of divid's wallet, the transactions -------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"])
M = Node("miner", DIVID, 2, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"])
for n in (C, I, M):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not wait_for(lambda: C.rpc("getconnectioncount") > 1, 60):
    print("FAIL   setup: irondivid and the miner did not connect to divid", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

M.rpc("setgenerate", 100)
wait_all([M, C, I])
mine(5)
# Old coins of 100 DIVI: 25 blocks later a free spend of one has priority to
# spare (MemPoolEntry.h:18-40). Young coins of 1 DIVI, a block old: too little.
OLD, YOUNG = 100 * SAT, 1 * SAT
N_BATCH = 60
old_names = ([f"multisig {m}-of-{n}" for n, m in ((1, 1), (2, 1), (2, 2), (3, 1), (3, 2), (3, 3), (4, 1))]
             + [f"OP_META {s}" for s in (1, 40, 41, 603, 604, 1000, 1001)] + ["two OP_META", "paying", "free old"]
             + [f"batch {k}" for k in range(N_BATCH)])
young_names = ["free young"]
Y = C.rpc("getnewaddress")
addr = {k: C.rpc("getnewaddress") for k in old_names + young_names}


def fund(names, value):
    txid = M.rpc("sendmany", "", {addr[k]: value / SAT for k in names})
    outs = M.rpc("getrawtransaction", txid, 1)["vout"]
    return {k: (txid, next(o["n"] for o in outs if addr[k] in o["scriptPubKey"].get("addresses", []))) for k in names}


coin = fund(old_names, OLD)
mine(25)
coin.update(fund(young_names, YOUNG))
mine(1)

G = ["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
     "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"]  # 1G..4G: no one's keys
to_y = lambda sats: [(sats, p2pkh(Y))]
signed = lambda h: C.rpc("signrawtransaction", h)["hex"]
tx = {}
for n, m in ((1, 1), (2, 1), (2, 2), (3, 1), (3, 2), (3, 3), (4, 1)):
    name = f"multisig {m}-of-{n}"
    tx[f"a bare {m}-of-{n} multisig output"] = signed(spend(coin[name], to_y(OLD - FEE - SAT) + [(SAT, multisig(m, G[:n]))]))
for s in (1, 40, 41, 603, 604, 1000, 1001):
    tx[f"an OP_META output of {s} byte{'s' if s > 1 else ''}"] = signed(spend(coin[f"OP_META {s}"],
                                                                         to_y(OLD - FEE) + [(0, meta(s))]))
tx["two OP_META outputs"] = signed(spend(coin["two OP_META"], to_y(OLD - FEE) + [(0, meta(8))] * 2))
tx["a paying transaction"] = signed(spend(coin["paying"], to_y(OLD - FEE)))
tx["free, an old coin (enough priority)"] = signed(spend(coin["free old"], to_y(OLD)))
tx["free, a young coin (too little priority)"] = signed(spend(coin["free young"], to_y(YOUNG)))
batch = [signed(spend(coin[f"batch {k}"], to_y(OLD))) for k in range(N_BATCH)]
name_of = {txid_of(h): k for k, h in tx.items()}
name_of.update({txid_of(h): f"batch {k}" for k, h in enumerate(batch)})
HEIGHT = C.rpc("getblockcount")
for n in (C, I, M):
    n.stop()
TEMPLATES = (C.dir, I.dir)


# --- the option sets ----------------------------------------------------------------------------

def copies(extra_conf):
    """Fresh copies of both nodes with `extra_conf`, listening for the raw peer
    and with no peers of their own"""
    for name in ("divid-copy", "irondivid-copy"):
        shutil.rmtree(os.path.join(WORK, name), ignore_errors=True)
    dead = f"connect=127.0.0.2:{PORT_BASE + 9}"  # nothing listens there
    c = Node("divid-copy", DIVID, 0, ["listen=1", dead] + list(extra_conf), template=TEMPLATES[0])
    i = Node("irondivid-copy", IRONDIVID, 1, ["listen=1", dead] + list(extra_conf), template=TEMPLATES[1])
    for n in (c, i):
        if not n.wait_ready() or not wait_for(lambda n=n: n.rpc("getblockcount") == HEIGHT, 60):
            raise RuntimeError(f"{n.name} copy did not start at height {HEIGHT}")
    return c, i


def pool(node):
    return sorted(name_of.get(t, t[:16]) for t in node.rpc("getrawmempool"))


def p2p_offer(port, hexes):
    """Relay each transaction from one raw peer, in order; the peer's rejects,
    by txid (code, reason), within 5 seconds of the last"""
    sock = socket.create_connection(("127.0.0.2", port), timeout=10)
    rejects = {}
    try:
        version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(port) + netaddr(0)
                   + secrets.token_bytes(8) + bytes([18]) + b"/relay-policy:01/" + struct.pack("<i", 0) + b"\x01")
        sock.sendall(message("version", version))
        got = set()
        deadline = time.time() + 10
        while got != {"version", "verack"} and time.time() < deadline:
            command, payload = read_message(sock)
            if command == "version":
                sock.sendall(message("verack"))
            got.add(command) if command in ("version", "verack") else None
        if got != {"version", "verack"}:
            return "no handshake"
        for h in hexes:
            sock.sendall(message("tx", bytes.fromhex(h)))
        deadline = time.time() + 5
        while time.time() < deadline:
            sock.settimeout(max(0.1, deadline - time.time()))
            try:
                command, payload = read_message(sock)
            except socket.timeout:
                break
            except (EOFError, ConnectionError):
                rejects["disconnected"] = True
                break
            if command == "ping":
                sock.sendall(message("pong", payload))
            elif command == "reject":
                what, pos = varstr(payload, 0)
                code = payload[pos]
                reason, pos = varstr(payload, pos + 1)
                rejects[payload[pos:][::-1].hex()] = [code, reason]
        return rejects
    finally:
        sock.close()


def option_set(label, conf):
    p = f"{label}: "
    # sendrawtransaction (fLimitFree false: no rate limit)
    c, i = copies(conf)
    try:
        for name, h in tx.items():
            core, iron = c.call("sendrawtransaction", h), i.call("sendrawtransaction", h)
            txid = txid_of(h)
            compare(f"{p}sendrawtransaction {name}", core if core[0] == "err" else ("ok", "txid"),
                    iron if iron[0] == "err" else ("ok", "txid"))
            row(f"{p}sendrawtransaction {name}: in the mempool", txid in c.rpc("getrawmempool"),
                txid in i.rpc("getrawmempool"), (txid in c.rpc("getrawmempool")) == (txid in i.rpc("getrawmempool")))
        taken = lambda n: sum(n.call("sendrawtransaction", h)[0] == "ok" for h in batch)
        a, b = taken(c), taken(i)
        row(f"{p}sendrawtransaction {N_BATCH} free transactions: taken", a, b, a == b)
        compare(f"{p}sendrawtransaction: the mempool", ("ok", pool(c)), ("ok", pool(i)))
    finally:
        for n in (c, i):
            n.stop()
    # a raw p2p peer (fLimitFree true: the free-relay rate limit)
    c, i = copies(conf)
    try:
        hexes = list(tx.values()) + batch
        rc, ri = p2p_offer(c.p2p, hexes), p2p_offer(i.p2p, hexes)
        if not isinstance(rc, dict) or not isinstance(ri, dict):
            compare(f"{p}p2p: the peer", ("ok", str(rc)), ("ok", str(ri)))
            return
        time.sleep(1)
        mc, mi = set(c.rpc("getrawmempool")), set(i.rpc("getrawmempool"))
        for name, h in tx.items():
            txid = txid_of(h)
            compare(f"{p}p2p tx {name}: reject", ("ok", rc.get(txid)), ("ok", ri.get(txid)))
            row(f"{p}p2p tx {name}: in the mempool", txid in mc, txid in mi, (txid in mc) == (txid in mi))
        ids = [txid_of(h) for h in batch]
        a, b = sum(t in mc for t in ids), sum(t in mi for t in ids)
        row(f"{p}p2p {N_BATCH} free transactions: taken", a, b, a == b)
        ra = sorted({tuple(rc[t]) for t in ids if t in rc})
        rb = sorted({tuple(ri[t]) for t in ids if t in ri})
        compare(f"{p}p2p {N_BATCH} free transactions: rejects", ("ok", [list(r) for r in ra]),
                ("ok", [list(r) for r in rb]))
        row(f"{p}p2p: the peer stays connected", "disconnected" not in rc, "disconnected" not in ri,
            ("disconnected" in rc) == ("disconnected" in ri))
    finally:
        for n in (c, i):
            n.stop()


for label, conf in (("defaults", []),
                    ("-permitbaremultisig=0", ["permitbaremultisig=0"]),
                    ("-datacarrier=0", ["datacarrier=0"]),
                    ("-datacarriersize=40", ["datacarriersize=40"]),
                    ("-datacarriersize=1000", ["datacarriersize=1000"]),
                    ("-datacarrier=0 -datacarriersize=1000", ["datacarrier=0", "datacarriersize=1000"]),
                    ("-relaypriority=0", ["relaypriority=0"]),
                    ("-limitfreerelay=0", ["limitfreerelay=0"]),
                    ("-limitfreerelay=1", ["limitfreerelay=1"])):
    option_set(label, conf)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
