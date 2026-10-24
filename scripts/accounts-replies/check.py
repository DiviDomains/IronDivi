#!/usr/bin/env python3
"""Account, address-grouping, mempool-entry and abandon RPC replies
of Divi Core divid and irondivid, compared field by field.

Both wallets come from the same phrase and sit on one regtest chain, so they own
the same keys and see the same transactions. Every account change is made on
both nodes. Calls divid does not have are compared too: both must refuse them
the same way. Each row prints PASS (same as divid), KNOWN (a difference listed
in README.md) or FAIL. Exit code = FAILs.

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
INJECT = os.environ.get("ACCOUNTS_REPLIES_INJECT", "")
# A directory to write both replies of every compared row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("ACCOUNTS_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {}
EXTRA = {}
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
        return f"error {out[1]} \"{out[2][:80]}\"".replace("\n", "\\n")
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


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


def compare(name, core, iron, drop=MOMENT | NOTES, order=None):
    """Same outcome; for a result the same fields and values (except `drop`), list
    items in divid's order unless `order` gives a sort key"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", inject(iron[1]))
    core, iron = help_text_samples(core), help_text_samples(iron)
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


# --- calls divid does not have -------------------------------------------------------

def absent(name, method, *params):
    """A call divid has nowhere in its table (rpcserver.cpp:324-467): KNOWN when
    irondivid refuses it as divid does, FAIL when irondivid answers"""
    global fails
    core, iron = C.call(method, *params), I.call(method, *params)
    same = core[0] == iron[0] == "err" and core[1:] == iron[1:]
    if same:
        print(f"KNOWN  {name}  divid={short(core)}  irondivid={short(iron)}  "
              f"[known: divid has no {method} (not in rpcserver.cpp:324-467); irondivid refuses it the same way]",
              flush=True)
    else:
        fails += 1
        print(f"FAIL   {name}  divid={short(core)}  irondivid={short(iron)}"[:400], flush=True)


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


# estimatefee and estimatepriority are compared in scripts/util-replies



def mine(n):
    """Each node mines n blocks. Both wallets then have used the same HD keys for
    coinbases, so the next key each hands out is the same (a wallet restored from
    a phrase does not know which keys the other node used: Divi Core has no
    MarkReserveKeysAsUsed)"""
    for node in (C, I):
        node.rpc("setgenerate", n)
        if not synced():
            print(f"FAIL   setup: the nodes did not agree on the chain after {node.name} mined", flush=True)
            sys.exit(1)


# Coins: 40 blocks past maturity; both wallets own the coinbases
mine(20)

# An address nobody holds a key for (regtest P2PKH version 139, random bytes)
W = b58check(bytes([139]) + secrets.token_bytes(20))


def same_on_both(what, method, *params):
    """Make the same account change on both wallets; the reply must agree"""
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(what, core, iron)
    if core[0] != "ok":
        raise RuntimeError(f"{what}: divid {core}")
    return core[1]


# Addresses handed out on both nodes: the same keys, in the same order
A0 = same_on_both('getnewaddress ""', "getnewaddress", "")
B0 = same_on_both("getnewaddress acctB", "getnewaddress", "acctB")
C0 = same_on_both("getaccountaddress acctC (a new account)", "getaccountaddress", "acctC")
for args in (["*"], [5], ["a", "b"]):
    both(f"getnewaddress {json.dumps(args)}", "getnewaddress", *args)


def account_rows(p):
    """Every account call with good and wrong arguments"""
    for args in ([A0], [B0], [C0], [W], ["xyz"], [], [123], [A0, 1]):
        both(f"{p}getaccount {json.dumps(args)}", "getaccount", *args)
    for args in ([""], ["acctB"], ["acctC"], ["acctD"], [], ["*"], [5], ["a", "b"]):
        both(f"{p}getaccountaddress {json.dumps(args)}", "getaccountaddress", *args)
    for args in ([""], ["acctB"], ["acctC"], ["acctD"], ["nosuch"], [], [5], ["a", "b"], ["*"]):
        both(f"{p}getaddressesbyaccount {json.dumps(args)}", "getaddressesbyaccount", *args,
             order=lambda a: a)
    for args in ([], [0], [1], [9999999], [0, True], [1, False], ["x"], [1, 2, 3]):
        both(f"{p}listaccounts {json.dumps(args)}", "listaccounts", *args)
    for args in ([""], ["acctB"], ["acctC"], ["acctD"], ["nosuch"], ["acctD", 0], ["acctD", 1],
                 ["acctD", 9999999], ["", 0], [], ["acctD", "1"], ["*"]):
        both(f"{p}getreceivedbyaccount {json.dumps(args)}", "getreceivedbyaccount", *args)
    for args in ([], [0], [0, True], [1, False], [9999999, True], [0, True, True], ["x"]):
        both(f"{p}listreceivedbyaccount {json.dumps(args)}", "listreceivedbyaccount", *args,
             order=lambda e: e.get("account", ""))


def wallet_rows(p):
    """Balances and history next to the account rows"""
    for args in ([], ["*", 0], [""], ["acctB"], ["acctD"], ["acctD", 0]):
        both(f"{p}getbalance {json.dumps(args)}", "getbalance", *args)
    for args in (["*", 100, 0], ["acctD", 100, 0]):
        both(f"{p}listtransactions {json.dumps(args)}", "listtransactions", *args)


account_rows("before sends: ")

# setaccount: move B0 (acctB's current address) to acctD, both nodes
same_on_both("setaccount B0 acctD", "setaccount", B0, "acctD")
for args in ([W, "x"], ["xyz", "x"], [], [A0, "*"], [A0, 5], [A0, "a", "b"]):
    both(f"setaccount {json.dumps(args)}", "setaccount", *args)
both("setaccount [A0] (account omitted)", "setaccount", A0)
account_rows("after setaccount: ")

# Coins move between the wallet's addresses: confirmed sends, then one in the mempool
sent = []
for to, amount in ((B0, 7), (A0, 3), (W, 1)):
    sent.append(C.rpc("sendtoaddress", to, amount))
    if not seen_by(I, sent[-1]):
        raise RuntimeError("irondivid did not see divid's send")
mine(1)
pending = C.rpc("sendtoaddress", C0, 2)
if not seen_by(I, pending):
    raise RuntimeError("irondivid did not see divid's unconfirmed send")
account_rows("after sends: ")
wallet_rows("after sends: ")

# Calls divid does not have
for args in ([], [1], ["x"]):
    absent(f"listaddressgroupings {json.dumps(args)}", "listaddressgroupings", *args)
for args in ([pending], [sent[0]], ["11" * 32], ["zz"], []):
    absent(f"getmempoolentry {json.dumps(args)}", "getmempoolentry", *args)
for args in ([pending], [sent[0]], ["11" * 32], []):
    absent(f"abandontransaction {json.dumps(args)}", "abandontransaction", *args)
wallet_rows("after abandontransaction: ")

# Restart both: the account replies must come back the same from disk
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
seen_by(I, pending)
account_rows("after restart: ")
wallet_rows("after restart: ")

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
