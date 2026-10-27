#!/usr/bin/env python3
"""Which coins a send spends, the fee it pays and the change it makes, on Divi
Core divid and on irondivid restored from divid's phrase.

Setup: divid, irondivid and a miner divid on one regtest chain. The miner pays
the twins a set of coins with known values, accounts and depths (and some left
unconfirmed); divid funds two vaults the twins own. Then every node stops, and
the twins' datadirs are kept as templates.

Each scenario starts a fresh copy of each twin's datadir, with no peers, makes
the same send on both, and compares what each built: the outcome, the inputs
(as the setup named the coins), the payee outputs, the change (amount, kind,
address), the fee, and the fee the wallet reports. The two copies of a send
are never relayed to each other, so neither is a double spend of the other.

Every send RPC of divid 3.0.0 selects coins with MinimumFeeCoinSelectionAlgorithm
(rpcwallet.cpp:705-719, through AccountCoinSelector or VaultCoinSelector), which
is deterministic: its inputs are compared exactly. The one random step is where
the change output goes (AttachChangeOutput, wallet.cpp:1626-1632); the change is
found by its address, not its position. Each row prints PASS (same as divid),
KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

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
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("COIN_SELECT_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("COIN_SELECT_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true.
KNOWN = {}

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
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
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






SAT = 100_000_000


def sat(v):
    """An amount as divid writes it (a text with 8 decimals) in satoshis"""
    return int(round(float(v) * SAT))


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


def in_mempools(txid):
    if not (seen_by(C, txid) and seen_by(I, txid)):
        raise RuntimeError(f"the twins did not see {txid[:16]}")


# --- setup: one chain, a known coin set on both twins ------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
M = Node("miner", DIVID, 2, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"])
for n in (I, M):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not wait_for(lambda: C.rpc("getconnectioncount") > 1, 60):
    print("FAIL   setup: irondivid and the miner did not connect to divid", flush=True)
    sys.exit(1)
I.env = None  # later starts read the wallet irondivid made
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# The twins' addresses, in the same order on both (the same keys): a list of
# (account, value in DIVI) per coin the miner pays
PLAN_OLD = ([("", v) for v in (1000, 50, 30, 20, 10, 10, 7)] + [("small", 0.1)] * 10
            + [("dust", 7), ("exact", 3), ("chg", 100)])
PLAN_LATER = [("", 10)]
PLAN_YOUNG = [("young", v) for v in (1, 2, 3, 4, 5)]
PLAN_UNCONF = [("unconf", 50)]
coin_name = {}  # outpoint "txid:vout" -> name
addresses = {}  # address -> name of its coin


def new_addresses(plan, tag):
    out = []
    for n, (account, value) in enumerate(plan):
        a = C.rpc("getnewaddress", account)
        b = I.rpc("getnewaddress", account)
        if a != b:
            raise RuntimeError(f"the twins hand out different addresses ({tag} {n})")
        addresses[a] = f"{account or 'default'} {value}{'' if plan.count((account, value)) == 1 else '#' + str(n)}"
        out.append((a, value))
    return out


def pay(pairs):
    """One miner transaction paying each (address, value); returns its txid"""
    txid = M.rpc("sendmany", "", {a: v for a, v in pairs})
    for vout in M.rpc("getrawtransaction", txid, 1)["vout"]:
        for a in vout["scriptPubKey"].get("addresses", []):
            if a in addresses:
                coin_name[f"{txid}:{vout['n']}"] = addresses[a]
    return txid


M.rpc("setgenerate", 100)
wait_all([M, C, I])
mine(5)
DEST, Z = M.rpc("getnewaddress"), M.rpc("getnewaddress")
MANY = [M.rpc("getnewaddress") for _ in range(12)]
OWN = new_addresses([("vault owner", 0)], "vault owner")[0][0]
MGR = M.rpc("getnewaddress")
VAULT = f"{OWN}:{MGR}"
old = new_addresses(PLAN_OLD, "old")
# sendmany pays each address once: the two default 10s and the ten small coins
# come in one transaction, each at an address of its own
pay(old)
vault_tx = [M.rpc("fundvault", VAULT, 200)["txhash"]]
mine(6)
pay(new_addresses(PLAN_LATER, "later"))
vault_tx.append(M.rpc("fundvault", VAULT, 100)["txhash"])
mine(1)
for addr_value in new_addresses(PLAN_YOUNG, "young"):
    pay([addr_value])
    mine(1)
for t in vault_tx:
    for vout in C.rpc("getrawtransaction", t, 1)["vout"]:
        if vout["scriptPubKey"].get("type") not in ("pubkeyhash", "nulldata"):
            coin_name[f"{t}:{vout['n']}"] = f"vault {sat(vout['value']) // SAT}"
VAULT_SCRIPTS = {vout["scriptPubKey"]["hex"] for t in vault_tx for vout in C.rpc("getrawtransaction", t, 1)["vout"]
                 if vout["scriptPubKey"].get("type") not in ("pubkeyhash", "nulldata")}
# Unconfirmed: divid's send from "chg" leaves its change unconfirmed (irondivid
# takes the change key out of its pool as divid did), and the miner pays
# "unconf" without a block
chg_send = C.rpc("sendfrom", "chg", Z, 1)
in_mempools(chg_send)
I.rpc("getrawchangeaddress")
for vout in C.rpc("getrawtransaction", chg_send, 1)["vout"]:
    if Z not in vout["scriptPubKey"].get("addresses", []):
        coin_name[f"{chg_send}:{vout['n']}"] = "unconfirmed change"
in_mempools(pay(new_addresses(PLAN_UNCONF, "unconf")))

# Both wallets hold the same coins, and hand out the same change key next
key = lambda u: (u["txid"], u["vout"])
cu, iu = sorted(C.rpc("listunspent", 0), key=key), sorted(I.rpc("listunspent", 0), key=key)
same_coins = [(u["txid"], u["vout"], u["amount"], u["confirmations"]) for u in cu] == \
    [(u["txid"], u["vout"], u["amount"], u["confirmations"]) for u in iu]
row("setup: listunspent 0 (the coin set)", f"{len(cu)} coins", f"{len(iu)} coins", same_coins)
for u in cu:
    coin_name.setdefault(f"{u['txid']}:{u['vout']}", f"{u['txid'][:8]}:{u['vout']}")
DEPTH = {f"{u['txid']}:{u['vout']}": u["confirmations"] for u in cu}
print("# coins: " + ", ".join(f"{coin_name[o]} ({DEPTH[o]} conf)" for o in sorted(DEPTH, key=lambda o: coin_name[o])),
      flush=True)
HEIGHT = C.rpc("getblockcount")
for n in (C, I, M):
    n.stop()
TEMPLATES = (C.dir, I.dir)


# --- the scenarios -------------------------------------------------------------------------------

def copies(extra_conf=()):
    """Fresh copies of the twins, with no peers"""
    for name in ("divid-copy", "irondivid-copy"):
        shutil.rmtree(os.path.join(WORK, name), ignore_errors=True)
    dead = f"connect=127.0.0.2:{PORT_BASE + 9}"  # nothing listens there
    c = Node("divid-copy", DIVID, 0, ["listen=0", dead] + list(extra_conf), template=TEMPLATES[0])
    i = Node("irondivid-copy", IRONDIVID, 1, ["listen=0", dead] + list(extra_conf), template=TEMPLATES[1])
    for n in (c, i):
        if not n.wait_ready() or not wait_for(lambda n=n: n.rpc("getblockcount") == HEIGHT, 60):
            raise RuntimeError(f"{n.name} copy did not start at height {HEIGHT}")
    return c, i


def describe(node, out, payees, payee_scripts):
    """What a send built: inputs (as the setup named the coins), payees,
    change and fee, from the node's own transaction"""
    if out[0] != "ok":
        return out
    txid = out[1]["txhash"] if isinstance(out[1], dict) else out[1]
    tx = node.rpc("getrawtransaction", txid, 1)
    inputs, value_in = [], 0
    for vin in tx["vin"]:
        prev = node.rpc("getrawtransaction", vin["txid"], 1)["vout"][vin["vout"]]
        value_in += sat(prev["value"])
        inputs.append(coin_name.get(f"{vin['txid']}:{vin['vout']}", f"{vin['txid'][:8]}:{vin['vout']}"))
    paid, change = [], []
    for vout in tx["vout"]:
        spk = vout["scriptPubKey"]
        addrs = spk.get("addresses", [])
        entry = (spk.get("type"), sat(vout["value"]))
        if any(a in payees for a in addrs) or spk["hex"] in payee_scripts:
            paid.append(entry + (payees.get(addrs[0], "payee") if addrs else "payee script",))
        else:
            # the change: the twins' next change key, or the vault's script
            change.append(entry + (addrs[0] if addrs else ("the vault" if spk["hex"] in VAULT_SCRIPTS else spk["hex"]),))
    fee = value_in - sum(sat(v["value"]) for v in tx["vout"])
    size = len(tx["hex"]) // 2
    wallet_fee = node.rpc("gettransaction", txid).get("fee")
    return ("ok", {"inputs": sorted(inputs), "payee order": [p[2] for p in paid], "input depths": sorted(DEPTH.get(f"{v['txid']}:{v['vout']}", 0)
                                                                    for v in tx["vin"]),
                   "payees": sorted(paid, key=lambda p: p[2]), "change": change, "fee": fee, "wallet fee": wallet_fee,
                   "fee covers its size": fee >= size * 10, "size": size})


def scenario(name, method, *params, conf=(), payees=None, payee_scripts=()):
    payees = payees if payees is not None else {DEST: "DEST", Z: "Z", **{a: f"M{n}" for n, a in enumerate(MANY)}}
    c, i = copies(conf)
    try:
        core, iron = c.call(method, *params), i.call(method, *params)
        dc, di = describe(c, core, payees, set(payee_scripts)), describe(i, iron, payees, set(payee_scripts))
    finally:
        for n in (c, i):
            n.stop()
    if dc[0] != "ok" or di[0] != "ok":
        compare(f"{name}: outcome", dc, di)
        return
    a, b = dc[1], di[1]
    for field in ("inputs", "input depths", "payees", "payee order", "change", "fee", "wallet fee",
                  "fee covers its size"):
        compare(f"{name}: {field}", ("ok", a[field]), ("ok", b[field]))
    print(f"#      {name}: fee {a['fee']} sat on {a['size']} bytes ({a['fee'] * 1000 // a['size']} sat/kB) on divid, "
          f"{b['fee']} sat on {b['size']} bytes ({b['fee'] * 1000 // b['size']} sat/kB) on irondivid", flush=True)


# sendtoaddress: the default account takes every coin of the wallet
scenario("sendtoaddress DEST 5 (many coins cover it alone)", "sendtoaddress", DEST, 5)
scenario("sendtoaddress DEST 900 (one coin covers it alone)", "sendtoaddress", DEST, 900)
scenario("sendtoaddress DEST 1080 (no coin covers it alone)", "sendtoaddress", DEST, 1080)
scenario("sendtoaddress DEST 1150 (needs the young coins)", "sendtoaddress", DEST, 1150)
scenario("sendtoaddress DEST 1300 (more than the confirmed coins)", "sendtoaddress", DEST, 1300)
scenario("sendtoaddress DEST 1180 (only with the unconfirmed change)", "sendtoaddress", DEST, 1180)
scenario("sendtoaddress DEST 1180 with -spendzeroconfchange", "sendtoaddress", DEST, 1180,
         conf=["spendzeroconfchange=1"])
scenario("sendtoaddress DEST 5 with -spendzeroconfchange", "sendtoaddress", DEST, 5, conf=["spendzeroconfchange=1"])
scenario("sendtoaddress DEST 0.00005 (a dust payment)", "sendtoaddress", DEST, 0.00005)
scenario("sendtoaddress DEST 5 receiver_pays", "sendtoaddress", DEST, 5, "receiver_pays")
scenario("sendtoaddress DEST 900 receiver_pays", "sendtoaddress", DEST, 900, "receiver_pays")
scenario("sendtoaddress DEST 1 sweep_funds", "sendtoaddress", DEST, 1, "sweep_funds")
# sendmany: more payees, a larger fee. Each request lists its payees in
# descending address order, so the payee order row shows that both keep the
# request's order, not the address order
down = lambda pairs: dict(sorted(pairs, key=lambda p: p[0], reverse=True))
scenario("sendmany \"\" {DEST: 2, Z: 3}", "sendmany", "", down([(DEST, 2), (Z, 3)]))
scenario("sendmany \"\" 12 payees of 1", "sendmany", "", down([(a, 1) for a in MANY]))
scenario("sendmany \"\" 12 payees of 90 (no coin covers it alone)", "sendmany", "", down([(a, 90) for a in MANY]))
# sendfrom: an account's own coins
scenario("sendfrom \"small\" DEST 0.55 (ten equal coins)", "sendfrom", "small", DEST, 0.55)
scenario("sendfrom \"dust\" DEST 6.999926 (the change would be dust)", "sendfrom", "dust", DEST, 6.999926)
scenario("sendfrom \"dust\" DEST 6.99992 (change just above dust)", "sendfrom", "dust", DEST, 6.99992)
scenario("sendfrom \"exact\" DEST 3 (the account's coin is the amount)", "sendfrom", "exact", DEST, 3)
scenario("sendfrom \"young\" DEST 4.5", "sendfrom", "young", DEST, 4.5)
scenario("sendfrom \"young\" DEST 9", "sendfrom", "young", DEST, 9)
scenario("sendfrom \"unconf\" DEST 1 (only an unconfirmed coin)", "sendfrom", "unconf", DEST, 1)
scenario("sendfrom \"\" DEST 5", "sendfrom", "", DEST, 5)
# vaults: the twins own two vaults; their change goes back to the vault
scenario("fundvault <vault> 20", "fundvault", VAULT, 20, payee_scripts=VAULT_SCRIPTS)
scenario("reclaimvaultfunds DEST 50", "reclaimvaultfunds", DEST, 50)
scenario("reclaimvaultfunds DEST 50 receiver_pays", "reclaimvaultfunds", DEST, 50, "receiver_pays")
scenario("reclaimvaultfunds DEST 150 (more than the younger vault coin)", "reclaimvaultfunds", DEST, 150)
scenario("reclaimvaultfunds DEST 1 sweep_funds", "reclaimvaultfunds", DEST, 1, "sweep_funds")
scenario("debitvaultbyname <vault> DEST 50", "debitvaultbyname", VAULT, DEST, 50)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
