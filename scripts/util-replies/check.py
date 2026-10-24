#!/usr/bin/env python3
"""Utility RPC replies of Divi Core divid and irondivid, compared field by field.

Both wallets come from the same phrase and sit on one regtest chain, so they own
the same keys: the same address validates, signs and verifies alike on both. Each
call is made with good arguments and with wrong or missing ones; for an error the
code and the whole text are compared. Each row prints PASS (same as divid), KNOWN
(a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
"""

import base64
import hashlib
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
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("UTIL_REPLIES_INJECT", "")
# A directory to write both replies of every compared row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("UTIL_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
NOT_IN_DIVID = "not in divid's call table (rpcserver.cpp:323-466): divid answers -32601"
KNOWN = {
    "getinfo: fields divid lacks":
        "keypoololdest, keypoolsize, paytxfee (divid: rpcmisc.cpp:136-157; also KNOWN in scripts/chain-replies)",
    "estimatefee []": "fee estimate for BasicSwap, " + NOT_IN_DIVID + " (docs/divid-differences.md R1)",
    "estimatefee [2]": "fee estimate for BasicSwap, " + NOT_IN_DIVID + " (docs/divid-differences.md R1)",
    "estimatepriority [2]": "answered beside estimatefee, " + NOT_IN_DIVID + " (docs/divid-differences.md R1)",
    "help: calls divid lacks":
        "irondivid's own calls, listed after divid's under \"(irondivid)\" sections (docs/divid-differences.md)",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "getinfo": {"keypoololdest", "keypoolsize", "paytxfee"},
}
extra_seen = {}

# Members that move between two calls on a live node
MOMENT = {"timeoffset"}

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
        if isinstance(a, str) and isinstance(b, str):
            return f"{path}: {text_difference(a, b)}"
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def text_difference(a, b):
    """The first line two texts differ on"""
    la, lb = a.split("\n"), b.split("\n")
    for n in range(max(len(la), len(lb))):
        x = la[n] if n < len(la) else "<end>"
        y = lb[n] if n < len(lb) else "<end>"
        if x != y:
            return f"line {n + 1}: {json.dumps(x)[:70]} vs {json.dumps(y)[:70]}"
    return "the same lines, other line ends"


# divid's help examples name sample addresses of other coins' main networks
# (e.g. rpcmisc.cpp:338); irondivid's examples say "diviaddress". Help texts are
# compared with any address in an example line read as "diviaddress".
EXAMPLE_ADDRESS = re.compile(r'(?<=")[1-9A-HJ-NP-Za-km-z]{26,35}(?=")')


def examples_masked(text):
    return "\n".join(EXAMPLE_ADDRESS.sub("diviaddress", line) if line.startswith("> ") else line
                     for line in text.split("\n"))


def short(out):
    if out[0] == "err":
        first = out[2].split("\n", 1)[0]
        more = " ..." if "\n" in out[2] else ""
        return f"error {out[1]} \"{first[:70]}{more}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    if isinstance(v, str) and "\n" in v:
        return f"text of {v.count(chr(10)) + 1} lines"
    return json.dumps(v)[:60]


def masked(out):
    if out[0] == "err":
        return ("err", out[1], examples_masked(out[2]))
    if isinstance(out[1], str):
        return ("ok", examples_masked(out[1]))
    return out


def compare(name, core, iron, drop=MOMENT):
    """Same outcome; for an error the same code and text; for a result the same
    fields and values (except `drop`)"""
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    core, iron = masked(core), masked(iron)
    if DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        detail = short(iron)
        if core[0] == iron[0] == "err" and core[1] == iron[1] and not same:
            detail += " " + text_difference(core[2], iron[2])
        row(name, short(core), detail, same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    d = first_difference(a, b)
    row(name, short(core), d or short(iron), d is None)


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, dict):
        return dict(v, injected=True)
    if isinstance(v, str):
        return v + " injected"
    return "injected"


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok" and isinstance(iron[1], dict):
        when = name.split(": ", 1)[0] if name.startswith("after restart: ") else ""
        extra_seen.setdefault(when, {}).setdefault(method, set()).update(extra & set(iron[1]))
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)
    return core, iron


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


# --- the nodes -----------------------------------------------------------------------

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

# Coins: divid mines past maturity; both wallets own the coinbases
C.rpc("setgenerate", 40)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# Addresses:
#   X  the wallet's, with an account on both (named when divid hands it out)
#   W  watched on both, nobody holds its key (regtest P2PKH version 139, random bytes)
#   F  nobody's, not watched
#   M  a 1-of-1 multisig (P2SH) of X's key, not in either wallet
#   D  a P2PKH address of the main network (version 30), random bytes
X = C.rpc("getnewaddress", "acct1")
I.rpc("setaccount", X, "acct1")
W = b58check(bytes([139]) + secrets.token_bytes(20))
for n in (C, I):
    n.rpc("importaddress", W, "watch", False)
F = b58check(bytes([139]) + secrets.token_bytes(20))
M = C.rpc("createmultisig", 1, [C.rpc("validateaddress", X)["pubkey"]])["address"]
D = b58check(bytes([30]) + secrets.token_bytes(20))

# One send left in both mempools, so getmininginfo's pooledtx is not 0
pending = C.rpc("sendtoaddress", F, 1)
if not seen_by(I, pending):
    print("FAIL   setup: irondivid did not get the mempool transaction", flush=True)
    sys.exit(1)

# The message signed by divid, verified on both
SIG = C.rpc("signmessage", X, "hello")

# The calls whose whole help text is compared (help <call>, and the wrong
# argument counts that answer it)
HELP_CALLS = ("validateaddress", "signmessage", "verifymessage", "getinfo", "getmininginfo",
              "getdifficulty", "verifychain", "help")


# --- the replies -----------------------------------------------------------------------

def replies(when):
    p = f"{when}: " if when else ""
    # validateaddress
    for what, args in (("own", [X]), ("watched", [W]), ("foreign", [F]), ("foreign multisig", [M]),
                       ("other network", [D]), ("garbage", ["notanaddress"]), ("empty", [""]),
                       ("no arguments", []), ("one argument too many", [X, 1]), ("not a string", [1])):
        both(f"{p}validateaddress {what}", "validateaddress", *args)

    # signmessage: divid and irondivid sign alike (RFC 6979 nonces)
    for what, args in (("good", [X, "hello"]), ("hex message", [X, "68656c6c6f", "hex"]),
                       ("b64 message", [X, "aGVsbG8=", "b64"]), ("hex signature", [X, "hello", "", "hex"]),
                       ("watched", [W, "hello"]), ("foreign", [F, "hello"]), ("multisig", [M, "hello"]),
                       ("garbage address", ["garbage", "hello"]), ("message missing", [X]),
                       ("no arguments", []), ("one argument too many", [X, "hello", "", "", ""]),
                       ("address not a string", [1, "hello"])):
        both(f"{p}signmessage {what}", "signmessage", *args)

    # verifymessage of divid's signature
    for what, args in (("good", [X, SIG, "hello"]), ("wrong address", [F, SIG, "hello"]),
                       ("watched address", [W, SIG, "hello"]), ("wrong message", [X, SIG, "other"]),
                       ("bad base64", [X, "!!notbase64!!", "hello"]), ("short signature", [X, "aGVsbG8=", "hello"]),
                       ("garbage address", ["garbage", SIG, "hello"]), ("multisig address", [M, SIG, "hello"]),
                       ("message missing", [X, SIG]), ("no arguments", []),
                       ("one argument too many", [X, SIG, "hello", 1]), ("signature not a string", [X, 1, "hello"])):
        both(f"{p}verifymessage {what}", "verifymessage", *args)

    # Fee and priority estimates (irondivid only)
    for args in ([], [2]):
        both(f"{p}estimatefee {json.dumps(args)}", "estimatefee", *args)
    both(f"{p}estimatepriority [2]", "estimatepriority", 2)

    # Node state
    both(f"{p}getinfo", "getinfo")
    both(f"{p}getinfo one argument too many", "getinfo", 1)
    both(f"{p}getmininginfo", "getmininginfo")
    both(f"{p}getmininginfo one argument too many", "getmininginfo", 1)
    both(f"{p}getdifficulty", "getdifficulty")
    both(f"{p}getdifficulty one argument too many", "getdifficulty", 1)

    # Calls neither has
    for method, args in (("getnetworkhashps", []), ("getnetworkhashps", [120, -1]), ("settxfee", [0.001]),
                         ("settxfee", []), ("getblocktemplate", []), ("getblocktemplate", [{"mode": "template"}])):
        both(f"{p}{method} {json.dumps(args)}", method, *args)

    # verifychain
    for args in ([], [4, 10], [9, 10], [0, 0], [1, 2, 3]):
        both(f"{p}verifychain {json.dumps(args)}", "verifychain", *args)
    # divid reads a second argument that is not there when one is given
    # (rpcblockchain.cpp:419-420: params[1] with params.size() == 1): its reply
    # is undefined (random error text, or the connection dropped), so the call
    # is not made on divid. irondivid takes the one argument as numblocks, as
    # the help text says.
    for args in ([4], ["x"]):
        iron = I.call("verifychain", *args)
        ok = iron == ("ok", True) if args == [4] else iron[0] == "err" or iron == ("ok", True)
        row(f"{p}verifychain {json.dumps(args)} (irondivid only)", "not called", short(iron), ok)

    # help: the list, with no command and with "" (both list every call)
    for what, args in (("", []), (" \"\"", [""])):
        core_list, iron_list = C.call("help", *args), I.call("help", *args)
        if core_list[0] == iron_list[0] == "ok" and isinstance(iron_list[1], str):
            ours, theirs = split_list(iron_list[1])
            compare(f"{p}help{what}", core_list, ("ok", ours))
            if not args:
                row(f"{p}help: calls divid lacks", "-", f"{len(theirs)} calls" if theirs else "-", not theirs)
        else:
            compare(f"{p}help{what}", core_list, iron_list)
    for method in HELP_CALLS:
        both(f"{p}help {method}", "help", method)
    for what, args in (("unknown call", ["nosuch"]), ("not a string", [1]), ("one argument too many", ["help", 1])):
        both(f"{p}help {what}", "help", *args)
    extra_rows(when)


def split_list(text):
    """irondivid's help list: divid's calls, then its own under "(irondivid)" sections"""
    marker = re.search(r"(^|\n)\n== [^\n]* \(irondivid\) ==\n", text)
    if not marker:
        return text, []
    ours, theirs = text[:marker.start()], text[marker.start():]
    return ours, [l for l in theirs.split("\n") if l and not l.startswith("== ")]


replies("")

# Restart both: the replies must come back the same from disk
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not synced():
    print("FAIL   restart: irondivid did not reconnect to divid", flush=True)
    sys.exit(1)
# The mempool transaction back in both mempools (divid's wallet resends it)
if not (seen_by(C, pending) and seen_by(I, pending)):
    print("FAIL   restart: the mempool transaction is not back in both mempools", flush=True)
    sys.exit(1)
replies("after restart")

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
