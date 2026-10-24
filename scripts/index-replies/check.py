#!/usr/bin/env python3
"""Address index, spent index and lottery RPC replies of Divi Core divid and
irondivid, compared field by field.

irondivid follows divid's regtest chain, so both indexes hold the same entries.
First both nodes run with -addressindex -spentindex: divid mines past the last
proof-of-work block into the lottery, makes sends to two of its addresses and
spends one of their coins, and leaves one send in the mempool; then the replies.
Then both are stopped and a fresh pair is started without the indexes, for the
refusals. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import json
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
INJECT = os.environ.get("INDEX_REPLIES_INJECT", "")
# A directory to write both replies of a differing row to; nothing is written without it
DUMP = os.environ.get("INDEX_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {}
KNOWN["no index: getlotteryblockwinners, chain below block 101"] = (
    "not sent to divid: before the first lottery block (101 on regtest) it reads the last lottery block as the "
    "missing block 101 (LotteryWinnersCalculator.cpp:63-68) and stops on its null pointer (rpclottery.cpp:53-56); "
    "irondivid's answer is shown only")
KNOWN["getlotteryblockwinners -1"] = (
    "not sent to divid: it reads the block at height -1, a null pointer (rpclottery.cpp:48-51), and stops; "
    "irondivid's answer is shown only")

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name, self.binary = name, binary
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
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
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

def first_difference(a, b, path="$"):
    """Where two replies first differ, or None: field names, types and values,
    list items in order. Reals are compared as divid writes them (the text)."""
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
    if type(a) is not type(b) or a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def short(out):
    if out[0] == "err":
        first = out[2].splitlines()[0] if out[2] else ""
        return f"error {out[1]} \"{first[:80]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def usage_text(method, message):
    """divid's reply to wrong arguments its help text covers: the help text,
    which starts with the call's name"""
    return message.startswith(method + " ") or message.startswith(method + "\n")


def inject(v):
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return [dict(v[0], injected=True)] + v[1:]
    if isinstance(v, dict):
        return dict(v, injected=True)
    return "injected"


def dump(name, core, iron):
    if not DUMP:
        return
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def compare(name, method, core, iron):
    """Same outcome; an error with the same code and message (a help text is not
    compared, only its code -1); a result with the same fields, types and values,
    list items in divid's order"""
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and usage_text(method, core[2]):
            same = True
        if not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return
    d = first_difference(core[1], iron[1])
    if d:
        dump(name, core, iron)
    row(name, short(core), d or short(iron), d is None)


def both(name, method, *params):
    compare(name, method, C.call(method, *params), I.call(method, *params))


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


def start_pair(tag, extra):
    c = Node(f"divid{tag}", DIVID, 0, ["listen=1"] + extra)
    if not c.wait_ready():
        print(f"FAIL   start: divid{tag} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
    i = Node(f"irondivid{tag}", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"] + extra)
    if not i.wait_ready():
        print(f"FAIL   start: irondivid{tag} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
    return c, i


def mine(n):
    """n blocks on divid, one call at a time: a proof-of-stake block can be refused
    (-25) until the clock passes the median time of the last blocks"""
    for _ in range(n):
        if not wait_for(lambda: C.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"divid could not mine block {C.rpc('getblockcount') + 1}")


# --- with the indexes ------------------------------------------------------------------

INDEXES = ["addressindex=1", "spentindex=1", "txindex=1"]
C, I = start_pair("", INDEXES)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

C.rpc("setgenerate", 40)
A = C.rpc("getnewaddress")
B = C.rpc("getnewaddress")
# An address nobody pays (regtest P2PKH version 139, random bytes)
NONE = b58check(bytes([139]) + secrets.token_bytes(20))
sends = [C.rpc("sendtoaddress", A, 10), C.rpc("sendtoaddress", B, 5), C.rpc("sendtoaddress", A, 3)]
C.rpc("setgenerate", 1)
FIRST = C.rpc("getblockcount")
# A's 10 DIVI coin, spent by a transaction of its own in the next block
coin = next(u for u in C.rpc("listunspent", 1, 9999999, [A]) if u["amount"] in ("10.00000000", "10.0", "10"))
raw = C.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}], {B: 9.99})
SPEND = C.rpc("sendrawtransaction", C.rpc("signrawtransaction", raw)["hex"])
C.rpc("setgenerate", 1)
SECOND = C.rpc("getblockcount")
# Past the last proof-of-work block (100) into the lottery (from 101, every 10 blocks)
mine(112 - SECOND)
TIP = C.rpc("getblockcount")
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
# One payment to A left in the mempool
POOL = C.rpc("sendtoaddress", A, 1)
if not wait_for(lambda: POOL in I.rpc("getrawmempool"), 60):
    print("FAIL   setup: irondivid did not see the payment left in the mempool", flush=True)
    sys.exit(1)
print(f"# chain {TIP} blocks; sends in {FIRST}, spend in {SECOND}; one send in the mempool", flush=True)

ADDRESS_CALLS = ("getaddressbalance", "getaddressdeltas", "getaddresstxids", "getaddressutxos", "getaddressmempool")
for m in ADDRESS_CALLS:
    both(f"{m} address", m, A)
    both(f"{m} {{addresses: [A]}}", m, {"addresses": [A]})
    both(f"{m} {{addresses: [A, B]}}", m, {"addresses": [A, B]})
    both(f"{m} {{addresses: [B, A]}}", m, {"addresses": [B, A]})
    both(f"{m} {{addresses: [A, B], start, end}}", m, {"addresses": [A, B], "start": FIRST, "end": SECOND})
    both(f"{m} {{addresses: [A], start}} only", m, {"addresses": [A], "start": FIRST})
    both(f"{m} {{addresses: [A], chainInfo}}", m, {"addresses": [A], "chainInfo": True})
    both(f"{m} {{addresses: [A, B], start, end, chainInfo}}", m,
         {"addresses": [A, B], "start": FIRST, "end": SECOND, "chainInfo": True})
    both(f"{m} unpaid address", m, NONE)
    both(f"{m} {{addresses: []}}", m, {"addresses": []})
    both(f"{m} {{addresses: [A], start text, end}}", m, {"addresses": [A], "start": str(FIRST), "end": SECOND})
    both(f"{m} {{addresses: [A], chainInfo text}}", m, {"addresses": [A], "chainInfo": "yes"})
    both(f"{m} address, only_vaults", m, A, True)
    both(f"{m} address, only_vaults false", m, A, False)
    # Wrong and missing arguments
    both(f"{m} no argument", m)
    both(f"{m} three arguments", m, A, False, 1)
    both(f"{m} not an address", m, "notanaddress")
    both(f"{m} a number", m, 7)
    both(f"{m} {{addresses: A}} not a list", m, {"addresses": A})
    both(f"{m} {{}} no addresses", m, {})
    both(f"{m} {{addresses: [A, bad]}}", m, {"addresses": [A, "notanaddress"]})
    both(f"{m} {{addresses: [7]}}", m, {"addresses": [7]})
    both(f"{m} only_vaults not a bool", m, A, "yes")
    both(f"{m} {{addresses: [A], start 0, end}}", m, {"addresses": [A], "start": 0, "end": SECOND})
    both(f"{m} {{addresses: [A], end < start}}", m, {"addresses": [A], "start": SECOND, "end": FIRST})
    both(f"{m} {{addresses: [A], start, end past tip, chainInfo}}", m,
         {"addresses": [A], "start": FIRST, "end": TIP + 50, "chainInfo": True})

spend_vout = next(n for n, o in enumerate(C.rpc("getrawtransaction", coin["txid"], 1)["vout"])
                  if o["scriptPubKey"].get("addresses") == [A] and o["value"] in ("10.00000000", "10.0", 10))
both("getspentinfo spent output", "getspentinfo", {"txid": coin["txid"], "index": spend_vout})
both("getspentinfo the spend's own output (unspent)", "getspentinfo", {"txid": SPEND, "index": 0})
both("getspentinfo index past the outputs", "getspentinfo", {"txid": coin["txid"], "index": 99})
both("getspentinfo unknown txid", "getspentinfo", {"txid": "11" * 32, "index": 0})
both("getspentinfo mempool tx output", "getspentinfo", {"txid": POOL, "index": 0})
both("getspentinfo no argument", "getspentinfo")
both("getspentinfo two arguments", "getspentinfo", {"txid": SPEND, "index": 0}, 1)
both("getspentinfo a string", "getspentinfo", SPEND)
both("getspentinfo no index", "getspentinfo", {"txid": SPEND})
both("getspentinfo index as text", "getspentinfo", {"txid": SPEND, "index": "0"})
both("getspentinfo txid not hex", "getspentinfo", {"txid": "zz", "index": 0})
both("getspentinfo txid short", "getspentinfo", {"txid": "ab" * 16, "index": 0})
both("getspentinfo negative index", "getspentinfo", {"txid": coin["txid"], "index": -1})

both("getlotteryblockwinners", "getlotteryblockwinners")
for h in (TIP, 111, 105, 101, 100, 50, TIP + 50):
    both(f"getlotteryblockwinners {h if h != TIP + 50 else 'past the tip'}", "getlotteryblockwinners", h)
both("getlotteryblockwinners text", "getlotteryblockwinners", "abc")
both("getlotteryblockwinners real", "getlotteryblockwinners", 1.5)
both("getlotteryblockwinners two arguments", "getlotteryblockwinners", 1, 2)
row("getlotteryblockwinners -1", "not sent", short(I.call("getlotteryblockwinners", -1)), False)

for n in (C, I):
    n.stop()

# --- without the indexes: the refusals -------------------------------------------------

C, I = start_pair("-noindex", [])
C.rpc("setgenerate", 25)
A = C.rpc("getnewaddress")
C.rpc("sendtoaddress", A, 2)
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid without indexes did not follow divid's chain", flush=True)
    sys.exit(1)
paid = C.rpc("listunspent", 1, 9999999, [A])[0]
for m in ADDRESS_CALLS:
    both(f"no index: {m} address", m, A)
    both(f"no index: {m} {{addresses: [A, B]}}", m, {"addresses": [A, NONE]})
    both(f"no index: {m} not an address", m, "notanaddress")
both("no index: getspentinfo", "getspentinfo", {"txid": paid["txid"], "index": paid["vout"]})
both("no index: getspentinfo no index", "getspentinfo", {"txid": paid["txid"]})
row("no index: getlotteryblockwinners, chain below block 101", "not sent",
    short(I.call("getlotteryblockwinners")), False)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
