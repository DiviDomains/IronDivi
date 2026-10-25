#!/usr/bin/env python3
"""Every number argument of divid's command table, sent the same values on Divi
Core divid and irondivid side by side on one regtest chain.

divid reads a number argument with json_spirit's get_int() (64 bits cut to a C++
int), get_int64() or get_real() (an int taken as a real), and refuses any other
JSON type with "value is type X, expected Y". Each (call, argument) gets each
value of VALUES, written into the request as its literal JSON text. Both wallets
come from the same phrase and follow one chain, so they hold the same keys and
coins. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is
never printed or put on a command line. RPC passwords are made at random and
kept in each node's 0600 divi.conf.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("INT_ARGS_INJECT", "")
HOST = os.environ.get("INT_ARGS_HOST", "127.0.0.2")
# A directory to write both replies of every differing row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("INT_ARGS_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 180

# Each value as a label and the JSON text sent. The last three columns of the
# README's table say what get_int() makes of the extra ones.
VALUES = [
    ("2^31-1", "2147483647"), ("2^31", "2147483648"), ("2^31+41", "2147483689"), ("2^32", "4294967296"),
    ("2^32+41", "4294967337"), ("2^32+2^31", "6442450944"), ("-2^32+2", "-4294967294"), ("-1", "-1"),
    ("2^53+1", "9007199254740993"), ("1.5", "1.5"), ("1e3", "1e3"), ('"5"', '"5"'), ("true", "true"),
    ("null", "null"),
]
SLOT = "@@value@@"

# Differences irondivid has on purpose, and rows not sent, one per row name, each
# listed in README.md. A KNOWN row that starts to match divid is a FAIL.
KNOWN = {}

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


class Node:
    def __init__(self, name, binary, index, extra, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"ia{index}"
        self.password = secrets.token_hex(16)
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", "txindex=1", "addressindex=1", "spentindex=1",
        ] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def post(self, body):
        """('ok', result) or ('err', code, message); reals keep their text"""
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body.encode(),
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def call(self, method, *params):
        return self.post(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}))

    def call_with(self, method, params, literal):
        """params with SLOT (as a string, anywhere inside) replaced by the JSON text `literal`"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
        return self.post(body.replace(json.dumps(SLOT), literal))

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


def dump(name, core, iron):
    if not DUMP:
        return
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:100]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def funds(out):
    """An "Insufficient funds" error without the total available: each wallet has
    paid its own fees by then"""
    if out[0] == "err" and "(total available)" in out[2]:
        return ("err", out[1], re.sub(r"than \d+\(total available\)", "than N(total available)", out[2]))
    return out


def compare(name, method, core, iron, view):
    """Same outcome; an error with the same code and message (a help text by its
    code -1 only); a result: `view` of it with the same fields, types and values"""
    core, iron = funds(core), funds(iron)
    if core[0] == "ok":
        core = ("ok", view(core[1]))
    if iron[0] == "ok":
        iron = ("ok", view(iron[1]))
    if INJECT and INJECT == name:
        iron = ("ok", {"injected": iron[1] if iron[0] == "ok" else list(iron[1:])})
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and usage_text(method, core[2]):
            same = usage_text(method, iron[2])
        if not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return
    d = first_difference(core[1], iron[1])
    if d:
        dump(name, core, iron)
    row(name, short(core), d or short(iron), d is None)


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
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

# --- the chain ---------------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    raise RuntimeError(f"divid did not answer within {START_TIMEOUT} s")
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect={HOST}:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": C.rpc("dumphdinfo")["mnemonic"]})
if not I.wait_ready():
    raise RuntimeError(f"irondivid did not answer within {START_TIMEOUT} s")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120)


def mine(n):
    """n blocks on divid, one call at a time: a proof-of-stake block can be refused
    until the clock passes the median time of the last blocks"""
    for _ in range(n):
        if not wait_for(lambda: C.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"divid could not mine block {C.rpc('getblockcount') + 1}")
    if not synced():
        raise RuntimeError("irondivid did not follow divid's chain")


C.rpc("setgenerate", 40)
A = C.rpc("getnewaddress")
PUB = C.rpc("validateaddress", A)["pubkey"]
PAID = C.rpc("sendtoaddress", A, 10)
mine(1)
# Past the first lottery block (101 on regtest), as getlotteryblockwinners needs
mine(112 - C.rpc("getblockcount"))
TIP = C.rpc("getblockcount")
HASH_50 = C.rpc("getblockhash", 50)
PAID_N = next(o["n"] for o in C.rpc("getrawtransaction", PAID, 1)["vout"]
              if o["scriptPubKey"].get("addresses") == [A])
SPK = next(o["scriptPubKey"]["hex"] for o in C.rpc("getrawtransaction", PAID, 1)["vout"] if o["n"] == PAID_N)
RAW = C.rpc("createrawtransaction", [{"txid": PAID, "vout": PAID_N}], {A: 9.99})
OWN, MGR = C.rpc("getnewaddress"), C.rpc("getnewaddress")
# irondivid's wallet comes from the phrase alone, without divid's address book:
# give A the account "" that divid's getnewaddress gave it
I.rpc("setaccount", A, "")
if not synced():
    raise RuntimeError("irondivid did not follow divid's chain")
print(f"# chain {TIP} blocks", flush=True)

# --- the calls ---------------------------------------------------------------------------------

V = SLOT


def keep(v):
    return v


def txids_of(v):
    """A list of a wallet's entries by what makes them: txid, vout or category, amount"""
    if not isinstance(v, list):
        return v
    return sorted(json.dumps([e.get("txid"), e.get("vout"), e.get("category"), e.get("amount"), e.get("address"),
                              e.get("account")]) for e in v)


def without_coinstake(v):
    """gettxout without irondivid's extra coinstake field (as scripts/chain-replies:
    divid gives coinbase only, rpcblockchain.cpp:398-399)"""
    return {k: x for k, x in v.items() if k != "coinstake"} if isinstance(v, dict) else v


def is_txid(v):
    return "a txid" if isinstance(v, str) and len(v) == 64 else v


def since(v):
    return {"transactions": txids_of(v.get("transactions")), "lastblock": v.get("lastblock")} \
        if isinstance(v, dict) else v


def mined(v):
    return f"{len(v)} blocks" if isinstance(v, list) else v


def vault_fund(v):
    return "funded" if isinstance(v, dict) and "txhash" in v else v


KNOWN["signrawtransaction prevtxs vout 2^31-1"] = (
    "divid's answer is an accident: it sizes a coins entry for output 2^31-1 (rpcrawtransaction.cpp:726, :740-741) and "
    "fails to allocate it, -1 \"vector::_M_default_append\"; irondivid takes the outpoint as given")

# Rows not sent to divid, by value: divid stops on them (irondivid's answer is shown)
LOTTERY_STOPS = ("not sent to divid: a height below 0 after get_int() makes divid read a null block, "
                 "chainTip->GetAncestor(height) (rpclottery.cpp:50-53), and stop")
SIGN_STOPS = ("not sent to divid: an input index past the inputs after get_int() makes divid read vin[index] "
              "(rpcrawtransaction.cpp:572, :589) and abort")
# Rows sent to neither node, by value: they would not end
ENDLESS = {
    "setgenerate": ("not sent: 2^31-1 blocks (divid's get_int() keeps it, rpcmining.cpp:79) take days; 2^31 and "
                    "2^31+41 are below 0 for divid, but irondivid before this check mined them all"),
    "keypoolrefill": "not sent: 2^31-1 keys (rpcwallet.cpp:2559-2566) take days on either node",
    "repetitions": ("not sent: get_int() makes this many outputs (rpcwallet.cpp:1024, :1675); irondivid before this "
                    "check made the uncut count, billions of outputs"),
}

# (call, argument label, params with V for the value, view of a result, values not sent to
#  divid with the reason, values sent to neither with the reason)
CALLS = [
    ("getblockhash", "height", [V], keep, {}, {}),
    ("gettxout", "n", [PAID, V], without_coinstake, {}, {}),
    # verifychain reads params[1] whenever one argument is given (rpcblockchain.cpp:418-420), so two are sent
    ("verifychain", "numblocks", [4, V], keep, {}, {}),
    ("getlotteryblockwinners", "height", [V], keep,
     {k: LOTTERY_STOPS for k in ("2^31", "2^31+41", "2^32+2^31", "-1")}, {}),
    ("getrawtransaction", "verbose", [PAID, V], keep, {}, {}),
    ("listunspent", "minconf", [V], txids_of, {}, {}),
    ("listunspent", "maxconf", [1, V], txids_of, {}, {}),
    ("createrawtransaction", "vout", [[{"txid": PAID, "vout": V}], {A: 1}], keep, {}, {}),
    ("createrawtransaction", "amount", [[{"txid": PAID, "vout": 0}], {A: V}], keep, {}, {}),
    ("signrawtransaction", "prevtxs vout", [RAW, [{"txid": PAID, "vout": V, "scriptPubKey": SPK}]], keep, {}, {}),
    ("signtransactionwithaddresskey", "input index", [RAW, A, V], keep,
     {k: SIGN_STOPS for k in ("2^31-1", "2^31", "2^31+41", "2^32+41", "2^32+2^31", "-2^32+2", "-1", "2^53+1")}, {}),
    ("createmultisig", "nrequired", [V, [PUB]], keep, {}, {}),
    ("getaddresstxids", "start", [{"addresses": [A], "start": V, "end": TIP}], keep, {}, {}),
    ("getaddressdeltas", "end", [{"addresses": [A], "start": 1, "end": V}], keep, {}, {}),
    ("getspentinfo", "index", [{"txid": PAID, "index": V}], keep, {}, {}),
    ("getreceivedbyaddress", "minconf", [A, V], keep, {}, {}),
    ("getreceivedbyaccount", "minconf", ["", V], keep, {}, {}),
    # For "*" divid answers before it reads minconf (rpcwallet.cpp:1576-1577)
    ("getbalance", "minconf", ["*", V], keep, {}, {}),
    ("getbalance", "minconf of an account", ["", V], keep, {}, {}),
    ("listreceivedbyaddress", "minconf", [V], txids_of, {}, {}),
    ("listreceivedbyaccount", "minconf", [V], txids_of, {}, {}),
    ("listtransactions", "count", ["*", V], txids_of, {}, {}),
    ("listtransactions", "from", ["*", 10, V], txids_of, {}, {}),
    ("listaccounts", "minconf", [V], keep, {}, {}),
    ("listsinceblock", "target-confirmations", [HASH_50, V], since, {}, {}),
    ("prioritisetransaction", "fee delta", [PAID, 0, V], keep, {}, {}),
    ("lockunspent", "vout", [False, [{"txid": PAID, "vout": V}]], keep, {}, {}),
    ("addmultisigaddress", "nrequired", [V, [PUB]], keep, {}, {}),
    ("keypoolrefill", "newsize", [V], keep, {}, {"2^31-1": ENDLESS["keypoolrefill"]}),
    ("walletpassphrase", "timeout", ["x", V], keep, {}, {}),
    ("sendtoaddress", "amount", [A, V], is_txid, {}, {}),
    ("sendfrom", "amount", ["", A, V], is_txid, {}, {}),
    ("sendmany", "amount", ["", {A: V}], is_txid, {}, {}),
    # The {"amount", "repetitions"} form: RPCTypeCheck wants a real amount (rpcwallet.cpp:1668)
    ("sendmany", "amount of a repeated output", ["", {A: {"amount": V, "repetitions": 1}}], is_txid, {}, {}),
    ("sendmany", "repetitions", ["", {A: {"amount": 1.5, "repetitions": V}}], is_txid, {},
     {k: ENDLESS["repetitions"] for k in ("2^31-1", "2^31", "2^31+41", "2^32", "2^32+41", "2^32+2^31", "2^53+1")}),
    ("fundvault", "amount", [f"{OWN}:{MGR}", V], vault_fund, {}, {}),
]
# Calls that move the clock or the chain, last
LAST = [
    ("setmocktime", "timestamp", [V], keep, {}, {}),
    ("setgenerate", "numberofblocks", [V], mined, {},
     {k: ENDLESS["setgenerate"] for k in ("2^31-1", "2^31", "2^31+41")}),
    ("generateblock", "blockBitsShift", [{"blockBitsShift": V}], is_txid, {}, {}),
]

for method, arg, params, view, not_to_divid, not_sent in CALLS + LAST:
    for label, text in VALUES:
        name = f"{method} {arg} {label}"
        if label in not_sent:
            KNOWN[name] = not_sent[label]
            row(name, "not sent", "not sent", False)
            continue
        if label in not_to_divid:
            KNOWN[name] = not_to_divid[label]
            out = I.call_with(method, params, text)
            row(name, "not sent", short(("ok", view(out[1])) if out[0] == "ok" else out), False)
            continue
        c = C.call_with(method, params, text)
        i = I.call_with(method, params, text)
        compare(name, method, c, i, view)
        if method == "lockunspent":
            compare(f"{name}: listlockunspent", "listlockunspent", C.call("listlockunspent"),
                    I.call("listlockunspent"), keep)
            C.call("lockunspent", True)
            I.call("lockunspent", True)
        if method == "setmocktime":
            C.call("setmocktime", 0)
            I.call("setmocktime", 0)
        if method in ("setgenerate", "generateblock"):
            # Each daemon's blocks reach the other; wait until both are on one tip
            wait_for(lambda: I.rpc("getblockcount") == C.rpc("getblockcount"), 120)

for n in (I, C):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
