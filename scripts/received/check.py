#!/usr/bin/env python3
"""The received-by calls, getunconfirmedbalance, getaccountaddress, sendfrom,
addmultisigaddress and getstakingstatus of Divi Core divid and irondivid,
compared field by field across confirmations, accounts, watch-only, multisig
and change, before and after a reorganization, and on a locked wallet.

Both nodes sit on one regtest chain that divid mines (past the proof-of-stake
height, so there are coinbase and stake rewards). irondivid's wallet comes from
divid's phrase, and every send is made on both nodes (divid's first), so the
wallets hold the same coins and see the same transactions. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
and the wallet passphrase live only in memory and in RPC messages (and the phrase
in irondivid's environment); they are never printed, written to a file or put on
a command line.
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
INJECT = os.environ.get("RECEIVED_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("RECEIVED_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true.
MNSYNC = ("irondivid has no masternode sync stages and reports whether the chain is synced; divid's stages "
          "need 3 spork-synced peers to move on (masternode-sync.cpp:425-455), so on this two-node chain it "
          "stays false (as in scripts/masternode-replies)")
R6 = ("irondivid writes a reply's members in name order (docs/divid-differences.md R6); divid in the order "
      "it adds them")
KNOWN = {
    **{f"getstakingstatus ({when}): mnsync": MNSYNC
       for when in ("immature coins only", "mature coins", "after stake blocks", "locked", "unlocked for staking only",
                    "unlocked")},
    "getstakingstatus (after stake blocks): staking status":
        "divid counts a stake search made through setgenerate as staking for 5 minutes (init.cpp:157-174); "
        "irondivid reports its staker, which is off here (staking=0)",
    **{f"{method}: member order": R6
       for method in ("getstakingstatus", "listreceivedbyaddress", "listreceivedbyaccount", "validateaddress")},
    "listreceivedbyaddress: fields divid lacks":
        "irondivid adds label, the account's newer name (as in scripts/wallet-replies)",
    "getstakingstatus: fields divid lacks":
        "irondivid adds \"staking status text\", the staker's state in words",
    **{f"getaccountaddress {label}":
       "divid's last address of an account is the last one ever given its name, also after setaccount moved it to "
       "another account (AddressBookManager, rpcwallet.cpp:339-341): here the 1-of-[K3] address, now in \"msig\"; "
       "irondivid gives the account's last address that still has its name"
       for label in ('"" (the default account)', '"" again')},
    "getaccountaddress \"fresh\" (locked, divid's greatest fresh address the paid one)":
        "divid reloads its wallet after encryptwallet (\"Wallet reloaded!\"), and a wallet read back takes an "
        "account's greatest address as its last (the address records in key order): here the paid fresh#1, so "
        "divid hands out a new one; irondivid keeps running its wallet, whose last is still fresh#3",
    "getaccount <the \"Zürich ✓\" address>: the text as written":
        "divid writes each byte of non-ASCII text as its own \\u00XX escape (json_spirit), which divi-cli reads back "
        "as bytes; irondivid writes the text as UTF-8. Every other row reads divid's text as divi-cli does",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {
    "listreceivedbyaddress": {"label"},
    "getstakingstatus": {"staking status text"},
}
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




def mine(n, node=None):
    """n blocks on the miner (or `node`), one call at a time: a proof-of-stake
    block can be refused (-25) until the clock passes the median time of the last
    blocks"""
    node = node or M
    for _ in range(n):
        if not wait_for(lambda: node.call("setgenerate", 1)[0] == "ok", 90):
            raise RuntimeError(f"{node.name} could not mine block {node.rpc('getblockcount') + 1}")
    tip = node.rpc("getbestblockhash")
    if not all(wait_for(lambda: n_.rpc("getbestblockhash") == tip, 90) for n_ in (C, M, I)):
        raise RuntimeError("the nodes did not follow the chain")


# Addresses each node hands out are given a name, the same on both nodes for the
# n-th address of the same call; replies are compared with addresses written as
# their names, so two wallets that hand out different keys still compare
names = ({}, {})


def name_it(label, core_addr, iron_addr):
    names[0][core_addr] = label
    names[1][iron_addr] = label


def named(side, v):
    if isinstance(v, dict):
        return {k: named(side, x) for k, x in v.items()}
    if isinstance(v, list):
        return [named(side, x) for x in v]
    if isinstance(v, str):
        return names[side].get(v, v)
    return v


def both_named(name, method, *params, order=None):
    core, iron = C.call(method, *params), I.call(method, *params)
    note_order(method, core, iron)
    if core[0] == "ok":
        core = ("ok", named(0, core[1]))
    if iron[0] == "ok":
        iron = ("ok", named(1, strip_extra(method, iron[1])))
    compare(name, core, iron, order=order)
    return core, iron


# --- the nodes -----------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
# The miner: a divid with a wallet of its own, which makes the blocks (so the
# twins' wallets hand out the same keys: a block divid makes takes a key for its
# coinbase) and pays them as another wallet
M = Node("miner", DIVID, 2, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"])
for n in (I, M):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not wait_for(lambda: C.rpc("getconnectioncount") > 1 and I.rpc("getconnectioncount") > 0, 60):
    print("FAIL   setup: irondivid and the miner did not connect to divid", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def staking(name):
    """getstakingstatus: mnsync and "staking status" on rows of their own, then
    the rest"""
    c, i = C.call("getstakingstatus"), I.call("getstakingstatus")
    note_order("getstakingstatus", c, i)
    for field in ("mnsync", "staking status"):
        pick = lambda out: ("ok", out[1].get(field)) if out[0] == "ok" and isinstance(out[1], dict) else out
        compare(f"{name}: {field}", pick(c), pick(i))
    if i[0] == "ok":
        i = ("ok", strip_extra("getstakingstatus", i[1]))
    compare(name, c, i, drop={"mnsync", "staking status"})


staking("getstakingstatus (fresh wallet, no coins)")
both("getunconfirmedbalance (fresh wallet)", "getunconfirmedbalance")
both("listreceivedbyaddress 0 true (fresh wallet)", "listreceivedbyaddress", 0, True)
both("listreceivedbyaccount 0 true (fresh wallet)", "listreceivedbyaccount", 0, True)

# The wallet's addresses: X with an account, Y in the default account, K1..K3
# for multisig keys
X, Y, K1, K2, K3 = (C.rpc("getnewaddress", a) for a in ("acct1", "", "keys", "keys", "keys"))
iron_first = [I.rpc("getnewaddress", a) for a in ("acct1", "", "keys", "keys", "keys")]
row("getnewaddress x5: the same addresses", "-", "same" if iron_first == [X, Y, K1, K2, K3] else "different",
    iron_first == [X, Y, K1, K2, K3])
if iron_first != [X, Y, K1, K2, K3]:
    print("FAIL   setup: the two wallets hand out different keys", flush=True)
    sys.exit(1)

# One block of divid's own, for a coinbase of the wallet. Its key is the next one
# irondivid would hand out, so irondivid hands it out (and the one after, which
# divid hands out next), and divid names its coinbase key alike: both books then
# hold the same keys, and the twins hand out the same keys again
C.rpc("setgenerate", 1)
CB = C.rpc("getrawtransaction", C.rpc("getblock", C.rpc("getbestblockhash"))["tx"][0], 1)["vout"][0]
CB = CB["scriptPubKey"]["addresses"][0]
nxt = C.rpc("getnewaddress", "skip")
iron_next = [I.rpc("getnewaddress", "skip"), I.rpc("getnewaddress", "skip")]
if iron_next != [CB, nxt]:
    print("FAIL   setup: irondivid's next keys are not divid's coinbase key and next key", flush=True)
    sys.exit(1)
C.rpc("setaccount", CB, "skip")
names[0][CB] = names[1][CB] = "coinbase"

# Addresses nobody here holds a key for (regtest P2PKH version 139, random bytes):
# W watched by both wallets, OTHER of another wallet
W = b58check(bytes([139]) + secrets.token_bytes(20))
OTHER = b58check(bytes([139]) + secrets.token_bytes(20))
both("importaddress <watched> watch false", "importaddress", W, "watch", False)
PK = {a: C.rpc("validateaddress", a)["pubkey"] for a in (K1, K2, K3)}
# A key not in either wallet: the secp256k1 generator, whose private key is 1
G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

# --- addmultisigaddress ------------------------------------------------------------------

both("addmultisigaddress 0 [K1]", "addmultisigaddress", 0, [K1])
both("addmultisigaddress -1 [K1]", "addmultisigaddress", -1, [K1])
both("addmultisigaddress 4 [K1,K2,K3] (n+1)", "addmultisigaddress", 4, [K1, K2, K3])
both("addmultisigaddress \"1\" [K1] (nrequired as text)", "addmultisigaddress", "1", [K1])
both("addmultisigaddress 1 K1 (keys not an array)", "addmultisigaddress", 1, K1)
both("addmultisigaddress 1 [] (no keys)", "addmultisigaddress", 1, [])
both("addmultisigaddress 1 [17 keys]", "addmultisigaddress", 1, [PK[K1]] * 17)
both("addmultisigaddress 1 [OTHER] (an address not in the wallet)", "addmultisigaddress", 1, [OTHER])
both("addmultisigaddress 1 [invalid]", "addmultisigaddress", 1, ["notakey"])
both("addmultisigaddress 1 [\"00\"] (bad hex key)", "addmultisigaddress", 1, ["00"])
both("addmultisigaddress 1 [K1] \"*\" (account *)", "addmultisigaddress", 1, [K1], "*")
both("addmultisigaddress 1 [K1] 5 (account a number)", "addmultisigaddress", 1, [K1], 5)
both("addmultisigaddress 1 [K1, 5] (a key a number)", "addmultisigaddress", 1, [K1, 5])
both("addmultisigaddress 1 [K1] null (account null)", "addmultisigaddress", 1, [K1], None)
both("addmultisigaddress 1 [notakey] \"*\" (the account is read first)", "addmultisigaddress", 1, ["notakey"], "*")
MS = {}
for label, params in (
        ("1 [K1]", (1, [K1])),
        ("2 [K1,K2] msig", (2, [K1, K2], "msig")),
        ("3 [K1,K2,K3] (n of n) msig", (3, [K1, K2, K3], "msig")),
        ("2 [hex1,hex2] (keys as hex)", (2, [PK[K1], PK[K2]])),
        ("1 [K1,hex2] (an address and a hex key)", (1, [K1, PK[K2]])),
        ("1 [G] (a key not in the wallet) watched", (1, [G], "watchms")),
        ("1 [K1,G] (one key of the wallet, one not)", (1, [K1, G], "half")),
        ("2 [K1,K1] (the same key twice)", (2, [K1, K1])),
        ("1 [K3] \"\"", (1, [K3], "")),
        ("1 [K3] again msig (the same address again, another account)", (1, [K3], "msig"))):
    core, iron = both_named(f"addmultisigaddress {label}", "addmultisigaddress", *params)
    if core[0] == iron[0] == "ok":
        MS[label] = core[1]
        names[0].setdefault(core[1], f"multisig {label}")
        names[1].setdefault(iron[1], f"multisig {label}")
for label, a in MS.items():
    both_named(f"validateaddress <multisig {label}>", "validateaddress", a)
    both_named(f"getaccount <multisig {label}>", "getaccount", a)
M2 = MS.get("2 [K1,K2] msig")
MW = MS.get("1 [G] (a key not in the wallet) watched")

# --- the chain: the miner's proof-of-work blocks to 100, then stake blocks -------------

mine(5)
staking("getstakingstatus (immature coins only)")
mine(94)
# Coins from the miner, another wallet, then 21 stake blocks of the miner's so
# they are mature (20 blocks, chainparams.cpp:479)
for _ in range(4):
    M.rpc("sendtoaddress", Y, 5000)
mine(21)
staking("getstakingstatus (mature coins)")
# divid's wallet stakes: a stake reward of the wallet (a coinstake takes no new key)
# A stake block of each twin's (both have then tried to stake, "staking status")
mine(1, C)
stake_tx = C.rpc("getblock", C.rpc("getbestblockhash"))["tx"][1]
mine(1, I)
staking("getstakingstatus (after stake blocks)")
# More coins for the sends (the coins staked are immature for 20 blocks)
for _ in range(12):
    M.rpc("sendtoaddress", Y, 1000)
mine(1)
ST = next(o["scriptPubKey"]["addresses"][0] for o in C.rpc("getrawtransaction", stake_tx, 1)["vout"]
          if o["scriptPubKey"].get("addresses"))
names[0].setdefault(ST, "stake"), names[1].setdefault(ST, "stake")

# --- sends, on both: divid's first, then irondivid's once it has divid's --------------------

own = []  # (divid's txid, irondivid's txid, what)


def send_both(name, method, *params, wait=True):
    """The same send on both; the outcome compared (a txid as "txid")"""
    core = C.call(method, *params)
    if core[0] == "ok" and wait and not seen_by(I, core[1]):
        raise RuntimeError(f"irondivid did not see divid's {name}")
    iron = I.call(method, *params)
    if iron[0] == "ok" and wait and not seen_by(C, iron[1]):
        raise RuntimeError(f"divid did not see irondivid's {name}")
    txid = lambda out: ("ok", "txid") if out[0] == "ok" and isinstance(out[1], str) and len(out[1]) == 64 else out
    compare(name, txid(core), txid(iron))
    if core[0] == iron[0] == "ok":
        own.append((core[1], iron[1], name))
    return core, iron


send_both("sendtoaddress X 10", "sendtoaddress", X, 10)
send_both("sendtoaddress Y 4 (default account)", "sendtoaddress", Y, 4)
send_both("sendtoaddress <watched> 3", "sendtoaddress", W, 3)
send_both("sendtoaddress OTHER 2 (another wallet)", "sendtoaddress", OTHER, 2)
if M2:
    send_both("sendtoaddress <multisig 2 of 2> 2", "sendtoaddress", M2, 2)
if MW:
    send_both("sendtoaddress <watched multisig> 1", "sendtoaddress", MW, 1)
# The change address of divid's first send, and of irondivid's
change = []
for side, (node, txid) in enumerate(((C, own[0][0]), (I, own[0][1]))):
    outs = C.rpc("getrawtransaction", txid, 1)["vout"]
    ch = next((o["scriptPubKey"]["addresses"][0] for o in outs
               if o["scriptPubKey"].get("addresses") and o["scriptPubKey"]["addresses"][0] != X), None)
    change.append(ch)
if change[0]:
    names[0][change[0]] = "change of divid's send"
    names[1][change[0]] = "change of divid's send"
if change[1]:
    names[0][change[1]] = "change of irondivid's send"
    names[1][change[1]] = "change of irondivid's send"

MINCONF = [None, 0, 1, 6, 100, -1]
ADDRS = [("X", X), ("Y", Y), ("watched", W), ("OTHER", OTHER), ("coinbase", CB), ("stake", ST)]
ADDRS += [(n, a) for n, a in (("multisig 2 of 2", M2), ("watched multisig", MW)) if a]
ADDRS += [(n, a) for n, a in (("divid's change", change[0]), ("irondivid's change", change[1])) if a]
ACCOUNTS = ["", "acct1", "keys", "msig", "watch", "watchms", "skip", "nosuch"]
LISTS = [[], [0], [1], [6], [100], [-1], [0, True], [1, True], [0, False, True], [0, True, True], [1, True, True],
         [100, True, False]]
by_address = lambda e: (e.get("address", ""),)
# The addresses both wallets have alike, by name, so an address one twin hands
# out shows as which it is
for label, a in ADDRS:
    names[0].setdefault(a, label), names[1].setdefault(a, label)
by_account = lambda e: (e.get("account", ""),)


def views(when):
    p = f"{when}: "
    for label, a in ADDRS:
        for m in (MINCONF if label in ("X", "stake", "coinbase") else [None, 0, 6]):
            args = [a] if m is None else [a, m]
            both(f"{p}getreceivedbyaddress {label} {'' if m is None else m}".rstrip(), "getreceivedbyaddress", *args)
    for acct in ACCOUNTS:
        for m in (MINCONF if acct in ("", "acct1") else [None, 0]):
            args = [acct] if m is None else [acct, m]
            both(f"{p}getreceivedbyaccount {json.dumps(acct)} {'' if m is None else m}".rstrip(),
                 "getreceivedbyaccount", *args)
    for args in LISTS:
        both_named(f"{p}listreceivedbyaddress {json.dumps(args)}", "listreceivedbyaddress", *args, order=by_address)
        both_named(f"{p}listreceivedbyaccount {json.dumps(args)}", "listreceivedbyaccount", *args)
    # The order of the entries, of the addresses both wallets hold alike
    c, i = C.call("listreceivedbyaddress", 0, True, True), I.call("listreceivedbyaddress", 0, True, True)
    if c[0] == i[0] == "ok":
        shared = set(e["address"] for e in c[1]) & set(e["address"] for e in i[1])
        oc = [named(0, e["address"]) for e in c[1] if e["address"] in shared]
        oi = [named(1, e["address"]) for e in i[1] if e["address"] in shared]
        compare(f"{p}listreceivedbyaddress 0 true true: order of the entries", ("ok", oc), ("ok", oi))
        if DUMP and oc != oi:
            dump(f"{p}raw order", c, i)
    both(f"{p}getunconfirmedbalance", "getunconfirmedbalance")


# A payment from another wallet, unconfirmed: not the wallet's own, so not trusted
from_miner = M.rpc("sendtoaddress", X, 7)
if not (seen_by(C, from_miner) and seen_by(I, from_miner)):
    print("FAIL   setup: the twins did not see the miner's payment", flush=True)
    sys.exit(1)
views("sent, unconfirmed")
mine(1)
SENT_BLOCK = C.rpc("getbestblockhash")
views("1 confirmation")
mine(5)
views("6 confirmations")
# A reorganization that drops the block with the sends (and the blocks after it):
# the sends are back in the mempool, unconfirmed
for n in (C, M, I):
    n.rpc("invalidateblock", SENT_BLOCK)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 60):
    print("FAIL   setup: the nodes differ after invalidateblock", flush=True)
    sys.exit(1)
both("after invalidateblock of the block with the sends: getrawmempool", "getrawmempool", order=lambda t: t)
views("after invalidateblock of the block with the sends")
for n in (C, M, I):
    n.rpc("reconsiderblock", SENT_BLOCK)
if not synced():
    print("FAIL   setup: the nodes differ after reconsiderblock", flush=True)
    sys.exit(1)
views("after reconsiderblock")

# --- arguments of the received-by calls -------------------------------------------------------

for label, args in (("\"1\" (minconf as text)", [X, "1"]), ("1.5 (minconf a real)", [X, 1.5]),
                    ("true (minconf a bool)", [X, True]), ("null minconf", [X, None])):
    both(f"getreceivedbyaddress X {label}", "getreceivedbyaddress", *args)
for label, a in (("not an address", "notanaddress"), ("empty", ""), ("a number", 5),
                 ("X with a wrong checksum", X[:-1] + ("1" if X[-1] != "1" else "2")),
                 ("an address of another network (version 0)", b58check(bytes([0]) + secrets.token_bytes(20)))):
    both(f"getreceivedbyaddress <{label}>", "getreceivedbyaddress", a)
both("getreceivedbyaddress <multisig 1 of [K3]>", "getreceivedbyaddress", MS.get("1 [K3] \"\"", X))
# minconf is read only for an address of the wallet (rpcwallet.cpp:1455-1461)
both("getreceivedbyaddress OTHER null", "getreceivedbyaddress", OTHER, None)
both("getreceivedbyaddress OTHER \"1\"", "getreceivedbyaddress", OTHER, "1")
both("getreceivedbyaddress notanaddress \"1\"", "getreceivedbyaddress", "notanaddress", "1")
# minconf is read before the account (rpcwallet.cpp:1517-1523)
both("getreceivedbyaccount 5 \"1\"", "getreceivedbyaccount", 5, "1")
for label, args in (("\"*\"", ["*"]), ("5 (a number)", [5]), ("\"acct1\" \"1\"", ["acct1", "1"]),
                    ("null", [None]), ("\" spaced \"", [" spaced "]), ("\"Zürich ✓\"", ["Zürich ✓"])):
    both(f"getreceivedbyaccount {label}", "getreceivedbyaccount", *args)
for method in ("listreceivedbyaddress", "listreceivedbyaccount"):
    for label, args in (("\"1\"", ["1"]), ("1 \"true\"", [1, "true"]), ("1 true \"true\"", [1, True, "true"]),
                        ("1 1", [1, 1]), ("null", [None]), ("1.0", [1.0])):
        both(f"{method} {label}", method, *args)
both("getunconfirmedbalance 1 (an argument)", "getunconfirmedbalance", 1)

# --- getaccountaddress ---------------------------------------------------------------------


def account_address(label, acct, alias):
    core, iron = C.call("getaccountaddress", acct), I.call("getaccountaddress", acct)
    if core[0] == iron[0] == "ok" and core[1] not in names[0] and iron[1] not in names[1]:
        name_it(alias, core[1], iron[1])
    compare(f"getaccountaddress {label}", ("ok", named(0, core[1])) if core[0] == "ok" else core,
            ("ok", named(1, iron[1])) if iron[0] == "ok" else iron)
    return core, iron


account_address("\"fresh\" (a new account)", "fresh", "fresh#1")
account_address("\"fresh\" again (nothing paid to it)", "fresh", "fresh#2")
both_named("getaccount <fresh>", "getaccount", C.rpc("getaccountaddress", "fresh"))
account_address("\"acct1\" (X was paid)", "acct1", "acct1#1")
account_address("\"acct1\" again", "acct1", "acct1#2")
account_address("\"keys\" (an account whose addresses were never paid)", "keys", "keys#1")
account_address("\"\" (the default account)", "", "default#1")
account_address("\"\" again", "", "default#2")
account_address("\"watch\" (an account of a watched address)", "watch", "watch#1")
account_address("\"msig\" (an account of multisig addresses)", "msig", "msig#1")
account_address("\"*\"", "*", "star")
account_address("5 (a number)", 5, "five")
account_address("null", None, "null")
account_address("\" spaced \"", " spaced ", "spaced#1")
account_address("\"Zürich ✓\"", "Zürich ✓", "unicode#1")
account_address("a 300-character name", "a" * 300, "long#1")
c = C.call("getaccount", C.rpc("getaccountaddress", "Zürich ✓"))
i = I.call("getaccount", I.rpc("getaccountaddress", "Zürich ✓"))
row("getaccount <the \"Zürich ✓\" address>: the text as written", json.dumps(c[1:])[:80], json.dumps(i[1:])[:80],
    c == i)
both("getaccountaddress (no account)", "getaccountaddress")
both("getaccountaddress \"a\" \"b\"", "getaccountaddress", "a", "b")
# Paid, then asked again: a new address
fresh = (C.rpc("getaccountaddress", "fresh"), I.rpc("getaccountaddress", "fresh"))
send_both("sendtoaddress <fresh> 1", "sendtoaddress", fresh[0], 1)
if fresh[0] != fresh[1]:
    send_both("sendtoaddress <irondivid's fresh> 1", "sendtoaddress", fresh[1], 1)
account_address("\"fresh\" after it was paid (unconfirmed)", "fresh", "fresh#3")
account_address("\"fresh\" after it was paid, again", "fresh", "fresh#4")
both_named("getaddressesbyaccount fresh", "getaddressesbyaccount", "fresh", order=lambda a: a)
both_named("listreceivedbyaddress 0 true (after getaccountaddress)", "listreceivedbyaddress", 0, True,
           order=by_address)
both_named("listreceivedbyaccount 0 true (after getaccountaddress)", "listreceivedbyaccount", 0, True)
mine(1)

# --- sendfrom --------------------------------------------------------------------------------

send_both("sendfrom \"\" X 1", "sendfrom", "", X, 1)
send_both("sendfrom \"acct1\" Y 1 (an account with coins)", "sendfrom", "acct1", Y, 1)
send_both("sendfrom \"nosuch\" Y 1 (an account without coins)", "sendfrom", "nosuch", Y, 1)
send_both("sendfrom \"acct1\" Y 100000 (more than the account has)", "sendfrom", "acct1", Y, 100000)
send_both("sendfrom \"\" Y 100000000 (more than the wallet has)", "sendfrom", "", Y, 100000000)
send_both("sendfrom \"\" X 1 \"dinner\" \"bob\" (comments)", "sendfrom", "", X, 1, "dinner", "bob")
send_both("sendfrom \"\" X 1 6 (a minconf in place of the comment)", "sendfrom", "", X, 1, 6)
send_both("sendfrom \"\" X 1 \"\" \"\" (empty comments)", "sendfrom", "", X, 1, "", "")
send_both("sendfrom \"\" X 1 null \"bob\"", "sendfrom", "", X, 1, None, "bob")
send_both("sendfrom \"\" X 1 \"a\" \"b\" 6 (a sixth argument)", "sendfrom", "", X, 1, "a", "b", 6)
send_both("sendfrom \"\" OTHER 1 (another wallet)", "sendfrom", "", OTHER, 1)
send_both("sendfrom \"\" <watched> 1", "sendfrom", "", W, 1)
send_both("sendfrom \"*\" X 1", "sendfrom", "*", X, 1)
send_both("sendfrom 5 X 1 (account a number)", "sendfrom", 5, X, 1)
send_both("sendfrom \"\" notanaddress 1", "sendfrom", "", "notanaddress", 1)
send_both("sendfrom \"\" <wrong checksum> 1", "sendfrom", "", X[:-1] + ("1" if X[-1] != "1" else "2"), 1)
send_both("sendfrom \"\" 5 1 (address a number)", "sendfrom", "", 5, 1)
send_both("sendfrom \"\" X 0", "sendfrom", "", X, 0)
send_both("sendfrom \"\" X -1", "sendfrom", "", X, -1)
send_both("sendfrom \"\" X \"1\" (amount as text)", "sendfrom", "", X, "1")
send_both("sendfrom \"\" X 0.000000001 (below a satoshi)", "sendfrom", "", X, 0.000000001)
send_both("sendfrom \"\" X 1 5 (a comment a number)", "sendfrom", "", X, 1, 5)
# Each node's own send: the comments are kept only by the wallet that sent it
NOTES = ("amount", "fee", "comment", "to", "account")
for a, b, what in own:
    if what.startswith("sendfrom"):
        c, i = C.call("gettransaction", a), I.call("gettransaction", b)
        pick = lambda out: ("ok", {k: out[1][k] for k in NOTES if k in out[1]}) if out[0] == "ok" else out
        compare(f"gettransaction of the own {what}: comments and amounts", pick(c), pick(i))
mine(1)
for args in ([], [0, True], [0, True, True]):
    both_named(f"listreceivedbyaccount {json.dumps(args)} (after sendfrom)", "listreceivedbyaccount", *args)
both("getreceivedbyaccount \"acct1\" (after sendfrom)", "getreceivedbyaccount", "acct1")
both("getreceivedbyaddress Y (after sendfrom)", "getreceivedbyaddress", Y)

# --- an encrypted wallet ---------------------------------------------------------------------

WALLET_PASS = secrets.token_urlsafe(18)
compare("encryptwallet <passphrase>", ("ok", C.call("encryptwallet", WALLET_PASS)[0]),
        ("ok", I.call("encryptwallet", WALLET_PASS)[0]))
for n in (C, I):
    # divid 3.0.0 keeps running after encryptwallet; a node that stopped is started again
    if n.proc.poll() is not None:
        n.log.close()
        n.start()
        if not n.wait_ready():
            print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
            sys.exit(1)
wait_for(lambda: C.rpc("getconnectioncount") > 0 and I.rpc("getconnectioncount") > 0, 60)
staking("getstakingstatus (locked)")
send_both("sendfrom \"\" X 1 (locked)", "sendfrom", "", X, 1)
send_both("sendfrom \"\" notanaddress 1 (locked)", "sendfrom", "", "notanaddress", 1)
send_both("sendfrom \"\" X 0 (locked)", "sendfrom", "", X, 0)
# divid reloads its wallet on encryptwallet, and a wallet read back takes an
# account's greatest address as its last: when that is the paid fresh#1, divid
# hands out a new address (KNOWN); when it is fresh#3, the same as irondivid
by_name = {v: k for k, v in names[0].items()}
reloaded_paid = max(by_name["fresh#1"], by_name["fresh#3"]) == by_name["fresh#1"]
account_address("\"fresh\" (locked" + (", divid's greatest fresh address the paid one)" if reloaded_paid else ")"),
                "fresh", "fresh#5")
account_address("\"new while locked\" (locked)", "new while locked", "locked#1")
both("addmultisigaddress 1 [K1] (locked)", "addmultisigaddress", 1, [K1])
both("getunconfirmedbalance (locked)", "getunconfirmedbalance")
both("walletpassphrase <passphrase> 300 true (staking only)", "walletpassphrase", WALLET_PASS, 300, True)
staking("getstakingstatus (unlocked for staking only)")
send_both("sendfrom \"\" X 1 (unlocked for staking only)", "sendfrom", "", X, 1)
both("walletpassphrase <passphrase> 300", "walletpassphrase", WALLET_PASS, 300)
staking("getstakingstatus (unlocked)")
send_both("sendfrom \"\" X 1 (unlocked)", "sendfrom", "", X, 1)
both("walletlock", "walletlock")
del WALLET_PASS

extra_rows("")
order_rows()
for n in (C, I, M):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
