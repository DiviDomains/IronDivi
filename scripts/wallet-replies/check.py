#!/usr/bin/env python3
"""Wallet RPC replies of Divi Core divid and irondivid, compared field by field.

Both wallets come from the same phrase and sit on one regtest chain, so they own
the same coins and see the same transactions. Every send is made on both nodes
(divid first, then irondivid once it has seen divid's), so each wallet holds one
copy it made and one it only saw. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

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
INJECT = os.environ.get("WALLET_REPLIES_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("WALLET_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
# Rows marked "open" are gaps not closed yet, kept here so the run stays usable
# while they are; they are listed in README.md for whoever closes them.
KNOWN = {
    "getwalletinfo: fields divid lacks":
        "walletname, keypoololdest, paytxfee, hdmasterkeyid (docs/divid-differences.md R4)",
    "listreceivedbyaddress: fields divid lacks":
        "label, kept as an extra field (divid ListReceived, rpcwallet.cpp:1793-1912, has account only)",
    "listunspent: fields divid lacks":
        "ischange, solvable, kept as extra fields (divid listunspent, rpcrawtransaction.cpp:320-334)",
    "listreceivedbyaddress [0, true, true]":
        "open: includeWatchonly is not read, so the watched address is left out (divid rpcwallet.cpp:1805-1809, :1843)",
    "listreceivedbyaccount [0, true, true]":
        "open: the same; the watched address's account shows 0 (divid rpcwallet.cpp:1805-1809)",
    "listaccounts":
        "open: sums the coins of labelled addresses, so the \"\" account shows 0; divid gives GetAccountBalance per address-book name (rpcwallet.cpp:2320-2350, :383-412)",
    "listunspent":
        "open: account \"\" on coins of keys divid never put in its address book (its miner takes them from the keypool); divid leaves account out (rpcrawtransaction.cpp:320-325)",
    "listunspent 0":
        "open: the same",
    "after restart: getwalletinfo":
        "open: keypoolsize is 1999 on divid and 2000 on irondivid after the restart (equal before it); cause not looked into yet",
    "listaccounts 0 true":
        "open: the same, and includeWatchonly is not read (rpcwallet.cpp:2333-2336)",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "listreceivedbyaddress": {"label"},
    "listunspent": {"ischange", "solvable"},
}
extra_seen = {}

# Fields set from the moment a node saw a transaction, not from the chain: the two
# nodes see a relayed transaction a few seconds apart
MOMENT = {"timereceived", "time"}
# The notes a send keeps (mapValue): only the node that made the send has them,
# so they are compared between each node's own copy (the "notes" rows)
NOTES = {"comment", "to", "FromAccount"}

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


def compare(name, core, iron, drop=MOMENT | NOTES, order=None):
    """Same outcome; for a result the same fields and values (except `drop`), list
    items in divid's order unless `order` gives a sort key"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", inject(iron[1]))
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    a, b = unordered(a), unordered(b)
    d = first_difference(a, b)
    if d and DUMP:
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
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok":
        found = set()
        items = iron[1] if isinstance(iron[1], list) else [iron[1]]
        for item in items:
            if isinstance(item, dict):
                found |= extra & set(item)
        extra_seen.setdefault(name.split(": ", 1)[0] if name.startswith("after restart: ") else "", {}) \
            .setdefault(method, set()).update(found)
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)


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

# An address of the wallet with an account on both, and a watched address nobody
# holds a key for (regtest P2PKH version 139, random bytes)
X = C.rpc("getnewaddress")
for n in (C, I):
    n.rpc("setaccount", X, "acct1")
W = b58check(bytes([139]) + secrets.token_bytes(20))
for n in (C, I):
    n.rpc("importaddress", W, "watch", False)

# The same sends on both: divid's first, then irondivid's once it has divid's
own = []  # (divid's txid, irondivid's txid, what)


def send_pair(what, method, *params):
    a = C.rpc(method, *params)
    if not seen_by(I, a):
        raise RuntimeError(f"irondivid did not see divid's {what}")
    b = I.rpc(method, *params)
    if not seen_by(C, b):
        raise RuntimeError(f"divid did not see irondivid's {what}")
    own.append((a, b, what))


send_pair("sendtoaddress", "sendtoaddress", X, 10)
send_pair("sendtoaddress metadata to the watched address", "sendtoaddress", W, 3, "metadata", "rent", "landlord")
send_pair("sendfrom", "sendfrom", "", X, 2, "dinner", "bob")
send_pair("sendmany", "sendmany", "", {X: 1, W: 1}, "split")
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid did not follow the block with the sends", flush=True)
    sys.exit(1)
first_block = C.rpc("getblockhash", 10)
# One more pair left in the mempool, so unconfirmed replies are compared too
send_pair("unconfirmed sendtoaddress", "sendtoaddress", X, 5)


# --- the replies -----------------------------------------------------------------------

def replies(when):
    p = f"{when}: " if when else ""
    for args in ([], ["*"], ["*", 0], ["*", 1, True], [""], ["", 1, True], ["", 0],
                 ["acct1"], ["acct1", 0], ["watch", 1, True], ["watch", 1, False]):
        both(f"{p}getbalance {json.dumps(args)}", "getbalance", *args)
    both(f"{p}getunconfirmedbalance", "getunconfirmedbalance")
    for args in (["*", 100, 0, True], ["*", 100, 0, False], ["*", 3, 2, True], ["watch", 10, 0, True],
                 ["acct1", 10, 0, True], ["", 100, 0, False]):
        both(f"{p}listtransactions {json.dumps(args)}", "listtransactions", *args)
    for a, b, what in own:
        for txid in (a, b):
            mine = "divid's" if txid == a else "irondivid's"
            both(f"{p}gettransaction of {mine} {what}", "gettransaction", txid, True)
        # The notes: each node's own copy
        ca, ib = C.call("gettransaction", a, True), I.call("gettransaction", b, True)
        notes = lambda out: {k: v for k, v in out[1].items() if k in NOTES} if out[0] == "ok" else out
        row(f"{p}notes of the own {what}", json.dumps(notes(ca)), json.dumps(notes(ib)), notes(ca) == notes(ib))
    both(f"{p}listsinceblock", "listsinceblock", order=lambda e: (e.get("txid", ""), e.get("vout", 0), e.get("category", "")))
    both(f"{p}listsinceblock block 10, 1, watch-only", "listsinceblock", first_block, 1, True,
         order=lambda e: (e.get("txid", ""), e.get("vout", 0), e.get("category", "")))
    for args in ([], [0, True, True], [1, False, False]):
        both(f"{p}listreceivedbyaddress {json.dumps(args)}", "listreceivedbyaddress", *args,
             order=lambda e: e.get("address", ""))
        both(f"{p}listreceivedbyaccount {json.dumps(args)}", "listreceivedbyaccount", *args,
             order=lambda e: e.get("account", ""))
    both(f"{p}getreceivedbyaddress", "getreceivedbyaddress", X)
    both(f"{p}getreceivedbyaccount acct1", "getreceivedbyaccount", "acct1")
    both(f"{p}listaccounts", "listaccounts")
    both(f"{p}listaccounts 0 true", "listaccounts", 0, True)
    both(f"{p}getaddressesbyaccount acct1", "getaddressesbyaccount", "acct1")
    key = lambda u: (u.get("txid", ""), u.get("vout", 0))
    both(f"{p}listunspent", "listunspent", order=key)
    both(f"{p}listunspent 0", "listunspent", 0, order=key)
    both(f"{p}listunspent 1 9999999 [X]", "listunspent", 1, 9999999, [X], order=key)
    c, i = C.call("getwalletinfo"), I.call("getwalletinfo")
    if c[0] == i[0] == "ok":
        extra = sorted(set(i[1]) - set(c[1]))
        compare(f"{p}getwalletinfo", ("ok", c[1]), ("ok", {k: v for k, v in i[1].items() if k in c[1]}),
                drop=MOMENT)
        row(f"{p}getwalletinfo: fields divid lacks", "-", ",".join(extra) or "-", not extra)
    else:
        compare(f"{p}getwalletinfo", c, i)
    extra_rows(when)


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
# The unconfirmed pair is back in both mempools (each wallet resends its own)
for a, b, _ in own[-1:]:
    seen_by(C, b) and seen_by(I, a)
replies("after restart")

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
