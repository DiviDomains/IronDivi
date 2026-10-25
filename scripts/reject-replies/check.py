#!/usr/bin/env python3
"""Transaction refusals of Divi Core divid and irondivid, compared case by case.

Both wallets come from the same phrase and sit on one regtest chain. After the
setup irondivid is restarted with no peer, so a transaction one node takes is
not relayed to the other: each raw transaction is sent to each node on its
own, and the reply (code and message) and whether the transaction is then in
that node's mempool are compared. Then the wallet refusals and the `reject`
message each node sends a raw p2p peer. Each row prints PASS (same as divid),
KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; private
keys and the wallet passphrase only in memory and RPC messages; none is ever
printed or put on a command line.
"""

import base64
import hashlib
import json
import socket
import struct
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("REJECT_REPLIES_INJECT", "")
# A directory to write both replies of every compared row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("REJECT_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {}

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


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 60)


def seen_by(node, txid):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), 60)


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


def signed(hexstr, *args):
    out = C.rpc("signrawtransaction", hexstr, *args)
    return out["hex"]


SAT = 100_000_000


# --- the nodes and the chain -----------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# The last proof-of-work block on regtest is 100 (chainparams.cpp:405); later
# blocks are stake blocks
C.rpc("setgenerate", 100)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# The coins the cases spend: 10 DIVI each to an address of its own, one of 200
NAMES = ["unsigned", "badsig", "wrongkey", "valid", "nofee", "lowfee", "dust", "nonstd", "metabig", "metalimit",
         "metatwo", "oversize", "negative", "dup", "noout", "nonfinal", "malformed", "respent"]
addr = {k: C.rpc("getnewaddress") for k in NAMES + ["big"]}
Y = C.rpc("getnewaddress")
Z = C.rpc("getnewaddress")
W = b58check(bytes([139]) + secrets.token_bytes(20))
fund = C.rpc("sendmany", "", {**{addr[k]: 10 for k in NAMES}, addr["big"]: 200})
C.rpc("setgenerate", 1)
outs = C.rpc("getrawtransaction", fund, 1)["vout"]
coin = {k: (fund, next(o["n"] for o in outs if addr[k] in o["scriptPubKey"].get("addresses", [])))
        for k in NAMES + ["big"]}
# A spend of one of them in the next block: its coin is then spent in the chain
in_chain = C.rpc("sendrawtransaction", signed(spend(coin["respent"], [(10 * SAT - 100_000, p2pkh(Y))])))
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid did not follow the blocks with the coins", flush=True)
    sys.exit(1)
tip = C.rpc("getblockcount")
in_chain_hex = C.rpc("getrawtransaction", in_chain)
# The coinbase of the last work block and the coinstake of the last block: both
# younger than the 20 blocks a coinbase or coinstake output needs (chainparams.cpp:479)
coinbase = C.rpc("getblock", C.rpc("getblockhash", 100))["tx"][0]
cb_out = C.rpc("getrawtransaction", coinbase, 1)["vout"][0]
stake_block = C.rpc("getblock", C.rpc("getblockhash", tip))
coinstake = stake_block["tx"][1]
cs_out = next(o for o in C.rpc("getrawtransaction", coinstake, 1)["vout"] if float(o["value"]) > 0)
print(f"# chain: {tip} blocks, coins in {fund[:16]}, coinstake {coinstake[:16]}", flush=True)

# irondivid alone from here: no peer (connect= to an address nothing listens
# on), listening for the raw peer
I.stop()
I.write_conf(["listen=1", "connect=127.0.0.2:1"])
I.start()
if not I.wait_ready() or I.rpc("getblockcount") != tip:
    print("FAIL   setup: irondivid did not start again alone at divid's tip", flush=True)
    sys.exit(1)
if not wait_for(lambda: C.rpc("getconnectioncount") == 0 and I.rpc("getconnectioncount") == 0, 60):
    print("FAIL   setup: the nodes are still connected", flush=True)
    sys.exit(1)

# Keys for the wrong-key case: in memory and in RPC messages only
wif_z = C.rpc("dumpprivkey", Z)
to_y = lambda sats: [(sats, p2pkh(Y))]
TEN = 10 * SAT
FEE = 100_000

# The raw transactions, made once and sent to both
tx = {}
tx["unsigned"] = spend(coin["unsigned"], to_y(TEN - FEE))
good = signed(spend(coin["badsig"], to_y(TEN - FEE)))
# One satoshi more out after signing: the signature no longer covers the transaction
tx["bad signature"] = good.replace(struct.pack("<q", TEN - FEE).hex(), struct.pack("<q", TEN - FEE + 1).hex())
assert tx["bad signature"] != good
# The scriptSig Z's key makes for a made-up coin of Z's (signature and public
# key of another key), on the spend of the real coin
fake = ("22" * 32, 0)
fake_signed = signed(spend(fake, to_y(TEN - FEE)), [{"txid": fake[0], "vout": 0, "scriptPubKey": p2pkh(Z).hex()}],
                     [wif_z])
b = bytes.fromhex(fake_signed)
script_sig = b[42:42 + b[41]]
tx["wrong key"] = serialize([(*coin["wrongkey"], script_sig, 0xffffffff)], to_y(TEN - FEE))
tx["missing inputs"] = signed(spend(("11" * 32, 0), to_y(TEN - FEE)))
tx["input spent in the chain"] = signed(spend(coin["respent"], to_y(TEN - 2 * FEE)))
tx["valid"] = signed(spend(coin["valid"], to_y(TEN - FEE)))
tx["double spend of a mempool input"] = signed(spend(coin["valid"], to_y(TEN - 2 * FEE)))
tx["no fee"] = signed(spend(coin["nofee"], to_y(TEN)))
tx["fee of 100 satoshis"] = signed(spend(coin["lowfee"], to_y(TEN - 100)))
tx["absurd fee"] = signed(spend(coin["big"], to_y(50 * SAT)))
tx["dust output"] = signed(spend(coin["dust"], to_y(TEN - FEE - 5000) + [(5000, p2pkh(Z))]))
tx["non-standard output script"] = signed(spend(coin["nonstd"], [(TEN - FEE, bytes([0x51]))]))
meta = lambda size: bytes([0x6a, 0x4d]) + struct.pack("<H", size - 4) + secrets.token_bytes(size - 4)
tx["OP_META of 604 bytes"] = signed(spend(coin["metabig"], to_y(TEN - FEE) + [(0, meta(604))]))
tx["OP_META of 603 bytes"] = signed(spend(coin["metalimit"], to_y(TEN - FEE) + [(0, meta(603))]))
tx["two OP_META outputs"] = signed(spend(coin["metatwo"], to_y(TEN - FEE) + [(0, bytes.fromhex("6a046275726e"))] * 2))
tx["oversize"] = spend(coin["oversize"], [(10_000, p2pkh(Y))] * 3000)
tx["negative output"] = spend(coin["negative"], to_y(-1))
tx["output over the money supply"] = spend(coin["negative"], to_y(2 ** 62))
tx["outputs past the int64 range"] = spend(coin["negative"], to_y(2 ** 62) * 2)
tx["duplicate inputs"] = serialize([(*coin["dup"], b"", 0xffffffff)] * 2, to_y(TEN - FEE))
tx["no inputs"] = serialize([], to_y(SAT))
tx["no outputs"] = spend(coin["noout"], [])
tx["non-final locktime"] = signed(spend(coin["nonfinal"], to_y(TEN - FEE), locktime=tip + 100, seq=0))
tx["immature coinbase spend"] = signed(spend((coinbase, cb_out["n"]), to_y(int(round(float(cb_out["value"]) * SAT)) - FEE)))
tx["immature coinstake spend"] = signed(spend((coinstake, cs_out["n"]), to_y(int(round(float(cs_out["value"]) * SAT)) - FEE)))
malformed = signed(spend(coin["malformed"], to_y(TEN - FEE)))


def mempool_has(node, txid):
    return txid in node.rpc("getrawmempool")


def send_row(name, hexstr, *extra):
    """sendrawtransaction on each node: the reply and whether the transaction is
    then in that node's mempool"""
    core, iron = C.call("sendrawtransaction", hexstr, *extra), I.call("sendrawtransaction", hexstr, *extra)
    if INJECT and INJECT == name:
        iron = ("ok", "injected") if iron[0] == "ok" else iron[:2] + (iron[2] + " injected",)
    # The txid a node answers with: with trailing bytes it is not the hash of
    # the hex given
    if core[0] == "ok" or iron[0] == "ok":
        txid = core[1] if core[0] == "ok" else iron[1]
    else:
        try:
            txid = txid_of(hexstr)
        except ValueError:
            txid = None
    if txid:
        cm = mempool_has(C, txid)
        im = wait_for(lambda: mempool_has(I, txid), 3) if cm else mempool_has(I, txid)
    else:
        cm = im = False
    same = core == iron and cm == im
    row(name, f"{short(core)} mempool={cm}", f"{short(iron)} mempool={im}", same)


# --- sendrawtransaction ----------------------------------------------------------------

for name in ("unsigned", "bad signature", "wrong key", "missing inputs", "input spent in the chain", "valid",
             "double spend of a mempool input"):
    send_row(f"sendrawtransaction {name}", tx[name])
send_row("sendrawtransaction already in the mempool", tx["valid"])
send_row("sendrawtransaction already in the chain", in_chain_hex)
send_row("sendrawtransaction no fee", tx["no fee"])
send_row("sendrawtransaction fee of 100 satoshis", tx["fee of 100 satoshis"])
send_row("sendrawtransaction absurd fee", tx["absurd fee"])
send_row("sendrawtransaction absurd fee allowhighfees false", tx["absurd fee"], False)
send_row("sendrawtransaction absurd fee allowhighfees true", tx["absurd fee"], True)
for name in ("dust output", "non-standard output script", "OP_META of 604 bytes", "OP_META of 603 bytes",
             "two OP_META outputs", "oversize", "negative output", "output over the money supply",
             "outputs past the int64 range",
             "duplicate inputs", "no inputs", "no outputs", "non-final locktime", "immature coinbase spend",
             "immature coinstake spend"):
    send_row(f"sendrawtransaction {name}", tx[name])
send_row("sendrawtransaction not hex", "zz")
send_row("sendrawtransaction odd length", malformed[:-1])
send_row("sendrawtransaction truncated", malformed[:-8])
send_row("sendrawtransaction trailing bytes", malformed + "00")
send_row("sendrawtransaction empty", "")


# --- a raw p2p peer ----------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])


def message(command, payload=b""):
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + check + payload


def netaddr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port)


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
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(port) + netaddr(0)
                   + secrets.token_bytes(8) + bytes([18]) + b"/reject-replies:1/" + struct.pack("<i", 0) + b"\x01")
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


# Refusals that do not get the peer banned first (Divi Core bans for a
# DoS score of 100: an unsigned spend fails the script check with 100)
for name in ("dust output", "non-final locktime", "unsigned"):
    core = ("ok", p2p_reject(C.p2p, tx[name]))
    iron = ("ok", p2p_reject(I.p2p, tx[name]))
    compare(f"p2p tx {name}: reject", core, iron)
    row(f"p2p tx {name}: not in the mempool", "-", "-",
        not mempool_has(C, txid_of(tx[name])) and not mempool_has(I, txid_of(tx[name])))


# --- the wallet ----------------------------------------------------------------------------

both("sendtoaddress a dust amount", "sendtoaddress", Y, 0.00001)
both("sendtoaddress over the balance", "sendtoaddress", Y, 1_000_000_000)
both("sendtoaddress zero", "sendtoaddress", Y, 0)
both("sendtoaddress negative", "sendtoaddress", Y, -1)
both("sendtoaddress to an address of no network", "sendtoaddress", "notanaddress", 1)
passphrase = secrets.token_hex(16)
for n in (C, I):
    n.rpc("encryptwallet", passphrase)
del passphrase
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   setup: {n.name} stopped after encryptwallet", flush=True)
        sys.exit(1)
both("sendtoaddress with the wallet locked", "sendtoaddress", Y, 1)
both("sendmany with the wallet locked", "sendmany", "", {Y: 1})
both("sendrawtransaction with the wallet locked", "sendrawtransaction", tx["valid"])
both("getbalance after the refusals", "getbalance", "*", 0)

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
