#!/usr/bin/env python3
"""Replies of the divid calls no other replies script makes, compared field by
field: getinvalid, getrawchangeaddress, listlockunspent, signtransactionwithaddresskey,
reverseblocktransactions, setmocktime and loadwallet.

Both wallets come from the same phrase and sit on one regtest chain, so they own
the same keys and coins. Each call is made with good arguments, with wrong ones,
and where it changes state, followed by a call that reads the state. Then both
nodes are started again, fresh, without a wallet. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
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
INJECT = os.environ.get("UNCOVERED_REPLIES_INJECT", "")
# A directory to write both replies of a differing row to; nothing is written without it
DUMP = os.environ.get("UNCOVERED_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
NOT_SENT_SHORT = ("not sent to divid: signtransactionwithaddresskey has no argument count check and reads "
                  "params[0..2] (rpcrawtransaction.cpp:566-572); with two or one argument it reads past the list "
                  "(\"value is type obj, expected int\"), with none it stops on a segmentation fault")
NO_MOCK_CLOCK = ("irondivid has no mock clock: each part reads the system clock (block times, mempool, peers), "
                 "so setmocktime is refused on regtest too and a mined block keeps the real time (divid: "
                 "SetMockTime, rpcmisc.cpp:526-541, utiltime.cpp)")
KNOWN = {
    "signtransactionwithaddresskey input index past the inputs": (
        "not sent to divid: SignForOutput reads vin[inputIndex] past the inputs (rpcrawtransaction.cpp:589) and "
        "divid aborts; irondivid's answer is shown only"),
    "signtransactionwithaddresskey two arguments": NOT_SENT_SHORT,
    "signtransactionwithaddresskey one argument": NOT_SENT_SHORT,
    "signtransactionwithaddresskey no argument": NOT_SENT_SHORT,
    "setmocktime": NO_MOCK_CLOCK,
    "setmocktime: own next block's time minus the mock time": NO_MOCK_CLOCK,
    "setmocktime 0 (the clock again)": NO_MOCK_CLOCK,
    "loadwallet a file": (
        "irondivid opens one wallet at start and keeps it; loadwallet is refused with a message naming --wallet "
        "and the wallet in use (docs/divid-differences.md R2)"),
}

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
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
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
    """divid's reply to a wrong argument count: the help text, which starts with
    the call's name"""
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
    out = (C.call(method, *params), I.call(method, *params))
    compare(name, method, *out)
    return out


def only_irondivid(name, method, *params):
    """A row for a call divid cannot answer (it stops); irondivid's answer is shown"""
    row(name, "not sent", short(I.call(method, *params)), False)


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


def start_pair(tag, extra, with_wallet):
    c = Node(f"divid{tag}", DIVID, 0, ["listen=1"] + extra)
    if not c.wait_ready():
        print(f"FAIL   start: divid{tag} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
    env = None
    if with_wallet:
        env = {"WALLET_MNEMONIC": c.rpc("dumphdinfo")["mnemonic"]}
    i = Node(f"irondivid{tag}", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"] + extra, env=env)
    env = None
    if not i.wait_ready():
        print(f"FAIL   start: irondivid{tag} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
    return c, i


# --- with a wallet ---------------------------------------------------------------------

C, I = start_pair("", [], True)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
C.rpc("setgenerate", 40)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
# An address nobody holds a key for (regtest P2PKH version 139, random bytes)
NONE = b58check(bytes([139]) + secrets.token_bytes(20))

# getinvalid: divid's fixed summary (rpcblockchain.cpp:687-725)
both("getinvalid", "getinvalid")
both("getinvalid all", "getinvalid", "all")
both("getinvalid other text", "getinvalid", "spent")
both("getinvalid a number", "getinvalid", 5)
both("getinvalid two arguments", "getinvalid", "all", "x")

# getrawchangeaddress: a new change key each time (rpcwallet.cpp:558-578)
c1, i1 = both("getrawchangeaddress", "getrawchangeaddress")
both("getrawchangeaddress again", "getrawchangeaddress")
both("getrawchangeaddress one argument", "getrawchangeaddress", 1)
both("getrawchangeaddress two arguments", "getrawchangeaddress", 1, 2)
if c1[0] == i1[0] == "ok":
    for who, node, addr in (("divid's", C, c1[1]), ("irondivid's", I, i1[1])):
        both(f"validateaddress of {who} change address", "validateaddress", addr)
    both("getaccount of divid's change address", "getaccount", c1[1])

# listlockunspent, with lockunspent to change what it lists (rpcwallet.cpp:2742-2848)
coins = sorted(C.rpc("listunspent"), key=lambda u: (u["txid"], u["vout"]))
outs = [{"txid": u["txid"], "vout": u["vout"]} for u in coins[:3]]
both("listlockunspent none locked", "listlockunspent")
both("lockunspent false 3 coins", "lockunspent", False, outs)
both("listlockunspent 3 locked", "listlockunspent")
both("lockunspent true 1 coin", "lockunspent", True, outs[1:2])
both("listlockunspent 2 locked", "listlockunspent")
both("listlockunspent one argument", "listlockunspent", "x")
both("lockunspent true all", "lockunspent", True)
both("listlockunspent none locked again", "listlockunspent")

# signtransactionwithaddresskey: one input signed SIGHASH_SINGLE with a wallet key,
# the scriptSig as asm (rpcrawtransaction.cpp:566-596)
# Two inputs (each coinbase pays a key of its own); the key named signs the input
owner, second = coins[0]["address"], coins[1]["address"]
raw = C.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]} for u in coins[:2]], {NONE: 1})
both("signtransactionwithaddresskey input 0", "signtransactionwithaddresskey", raw, owner, 0)
both("signtransactionwithaddresskey input 1", "signtransactionwithaddresskey", raw, second, 1)
both("signtransactionwithaddresskey input 1, the other coin's key", "signtransactionwithaddresskey", raw, owner, 1)
both("signtransactionwithaddresskey address not in the wallet", "signtransactionwithaddresskey", raw, NONE, 0)
both("signtransactionwithaddresskey not an address", "signtransactionwithaddresskey", raw, "notanaddress", 0)
both("signtransactionwithaddresskey hex not hex", "signtransactionwithaddresskey", "zz", owner, 0)
both("signtransactionwithaddresskey hex not a transaction", "signtransactionwithaddresskey", "00", owner, 0)
both("signtransactionwithaddresskey index as text", "signtransactionwithaddresskey", raw, owner, "0")
both("signtransactionwithaddresskey index real", "signtransactionwithaddresskey", raw, owner, 1.5)
both("signtransactionwithaddresskey address a number", "signtransactionwithaddresskey", raw, 5, 0)
both("signtransactionwithaddresskey hex a number", "signtransactionwithaddresskey", 5, owner, 0)
both("signtransactionwithaddresskey four arguments", "signtransactionwithaddresskey", raw, owner, 0, 1)
only_irondivid("signtransactionwithaddresskey input index past the inputs", "signtransactionwithaddresskey",
               raw, owner, 5)
only_irondivid("signtransactionwithaddresskey two arguments", "signtransactionwithaddresskey", raw, owner)
only_irondivid("signtransactionwithaddresskey one argument", "signtransactionwithaddresskey", raw)
only_irondivid("signtransactionwithaddresskey no argument", "signtransactionwithaddresskey")

# reverseblocktransactions: invalidate and reconsider the block; the tip stays at
# its parent until the next block (rpcblockchain.cpp:577-603)
both("reverseblocktransactions no argument", "reverseblocktransactions")
both("reverseblocktransactions two arguments", "reverseblocktransactions", C.rpc("getbestblockhash"), 1)
both("reverseblocktransactions a number", "reverseblocktransactions", 5)
both("reverseblocktransactions unknown block", "reverseblocktransactions", "11" * 32)
both("reverseblocktransactions not hex", "reverseblocktransactions", "zz")
tip, height = C.rpc("getbestblockhash"), C.rpc("getblockcount")
parent = C.rpc("getblockhash", height - 1)
both("reverseblocktransactions the tip", "reverseblocktransactions", tip)
time.sleep(2)
both("getblockcount after reverseblocktransactions", "getblockcount")
both("getbestblockhash after reverseblocktransactions", "getbestblockhash")
row("tip after reverseblocktransactions is the parent", C.rpc("getbestblockhash") == parent,
    I.rpc("getbestblockhash") == parent, (C.rpc("getbestblockhash") == parent) == (I.rpc("getbestblockhash") == parent))
# divid's next block brings the reversed block back as its tip, so it relays a
# second one before irondivid has a block to connect (rpcblockchain.cpp:577-603)
C.rpc("setgenerate", 2)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's blocks after reverseblocktransactions", flush=True)
    sys.exit(1)
both("getblockcount after two more blocks", "getblockcount")
both("getblockhash of the reversed height after them", "getblockhash", height)

# setmocktime: regtest's clock for the node (rpcmisc.cpp:526-541); a block the node
# mines next takes it as its time (the chain is still proof of work, so 1000 s ahead
# is accepted, BlockCheckingHelpers.cpp:30)
both("setmocktime a text", "setmocktime", "soon")
both("setmocktime a real", "setmocktime", 1.5)
both("setmocktime no argument", "setmocktime")
both("setmocktime two arguments", "setmocktime", 1, 2)
mock = C.rpc("getblock", C.rpc("getbestblockhash"))["time"] + 1000
both("setmocktime", "setmocktime", mock)
C.rpc("setgenerate", 1)
synced()
core_own = C.rpc("getblock", C.rpc("getbestblockhash"))["time"] - mock
I.call("setgenerate", 1)
wait_for(lambda: C.rpc("getblockcount") == I.rpc("getblockcount"), 60)
iron_own = I.rpc("getblock", I.rpc("getbestblockhash"))["time"] - mock
row("setmocktime: own next block's time minus the mock time", core_own, iron_own, core_own == iron_own)
both("setmocktime 0 (the clock again)", "setmocktime", 0)

# loadwallet: last, since divid switches its wallet (rpcwallet.cpp:524-536)
both("loadwallet no argument", "loadwallet")
both("loadwallet two arguments", "loadwallet", "a.dat", "b.dat")
both("loadwallet a number", "loadwallet", 5)
both("loadwallet a file", "loadwallet", "other.dat")

for n in (C, I):
    n.stop()

# --- without a wallet: divid's refusal for wallet calls (rpcserver.cpp:1046-1047) -----

# (no chain: divid cannot mine without a wallet; genesis on both)
C, I = start_pair("-nowallet", ["disablewallet=1"], False)
for method, params in (("getrawchangeaddress", []), ("listlockunspent", []), ("loadwallet", ["other.dat"]),
                       ("signtransactionwithaddresskey", ["00", NONE, 0])):
    both(f"no wallet: {method}", method, *params)
both("no wallet: getinvalid", "getinvalid")
both("no wallet: setmocktime a text", "setmocktime", "soon")
both("no wallet: reverseblocktransactions unknown block", "reverseblocktransactions", "11" * 32)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
