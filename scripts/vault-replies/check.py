#!/usr/bin/env python3
"""Vault RPC replies and vault coin handling of Divi Core divid and irondivid,
compared field by field.

Four nodes on one regtest chain: divid's owner wallet (it mines) and manager
wallet (-vault=1), and an irondivid owner and manager restored from the same two
phrases, so each irondivid wallet holds the same keys as its divid twin and sees
the same vault coins. Every vault step is made on divid first and then on
irondivid once it has seen divid's transaction; after each step the wallet views
of each twin pair are compared. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases live only in memory, in an RPC reply and in irondivid's environment;
they are never printed or put on a command line.
"""

import base64
import fnmatch
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
INJECT = os.environ.get("VAULT_REPLIES_INJECT", "")
# A directory to write both replies of every row that is not PASS
DUMP = os.environ.get("VAULT_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences listed in README.md with divid's source line. A KNOWN row that
# starts to match divid is a FAIL, so the list stays true. "open:" rows are gaps
# not closed yet.
KNOWN = {
    "*getcoinavailability: fields divid lacks":
        "total_vaults and vaults, kept as extra fields (divid getcoinavailability, rpcwallet.cpp:818-987, has Vaulted, Stakable, Spendable)",
    "reclaimvaultfunds*: reply":
        "open: rpc-left: divid answers the txid as a string (rpcwallet.cpp:1189), irondivid an object {amount, fee, txid}",
    "removevault with tx_hash: reply":
        "by design: irondivid still takes a second argument for older IronDivi callers (its help says so); divid takes exactly one (rpcwallet.cpp:1194-1201)",
    "after removevault: manager listtransactions * 100 0 true":
        "open: divid's removevault drops the vault script from memory only (wallet.cpp:707-716) and keeps the wallet's transactions, so the manager still lists them; irondivid removes the vault and its records",
    "after removevault: manager gettransaction of * fundvault owner:manager":
        "open: the same",
    "after removevault: manager gettransaction of * debitvaultbyname":
        "open: the same",
    "after removevault: manager gettransaction of * debitvaultbyname receiver_pays":
        "open: the same",
    "after removevault: manager gettransaction of * reclaimvaultfunds":
        "open: the same",
    "after removevault: manager gettransaction of * reclaimvaultfunds metadata":
        "open: the same",
    "after restart: manager listtransactions * 100 0 true":
        "open: the same; divid also reads the vault script back from its wallet file at the restart, so the vault is managed again (wallet.cpp:707-716 erases mapScripts only)",
    "after restart: manager gettransaction of * fundvault owner:manager":
        "open: the same",
    "after restart: manager gettransaction of * debitvaultbyname":
        "open: the same",
    "after restart: manager gettransaction of * debitvaultbyname receiver_pays":
        "open: the same",
    "after restart: manager gettransaction of * reclaimvaultfunds":
        "open: the same",
    "after restart: manager gettransaction of * reclaimvaultfunds metadata":
        "open: the same",
}

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<call>: fields divid lacks" row
EXTRA = {
    "getcoinavailability": {"total_vaults", "vaults"},
}
extra_seen = {}

# Fields set from the moment a node saw a transaction, not from the chain
MOMENT = {"timereceived", "time"}
# Notes only the node that made a send has
NOTES = {"comment", "to", "FromAccount"}

fails = 0


def known(name):
    """The KNOWN reason of a row: its own entry, else the first pattern
    (shell-style, * and ?) it matches"""
    if name in KNOWN:
        return KNOWN[name]
    for pattern, reason in KNOWN.items():
        if fnmatch.fnmatchcase(name, pattern):
            return reason
    return None


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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:420], flush=True)


class Node:
    def __init__(self, name, binary, rpcport, extra_conf, env=None):
        self.name, self.binary, self.env, self.rpcport = name, binary, env, rpcport
        self.dir = os.path.join(WORK, name)
        password = secrets.token_hex(16)
        user = "vault" + name.replace("-", "")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"rpcport={rpcport}", f"rpcuser={user}", f"rpcpassword={password}",
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
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def wait_ready(self, retries=30):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                # A port can be held for a while by the local end of an outbound
                # connection (these ports are inside the kernel's ephemeral
                # range) or by a closed connection in TIME-WAIT from an earlier
                # run: start again, 2 s apart, for up to a minute
                t = self.tail()
                if retries and ("already in use" in t or "Unable to bind" in t):
                    retries -= 1
                    time.sleep(2)
                    self.log.close()
                    self.start()
                    continue
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def tail(self, n=4):
        """The last lines of the node's output and debug.log, for a start failure"""
        lines = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "debug.log"),
                     os.path.join(self.dir, "regtest", "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        held = subprocess.run(["ss", "-tanpH"], capture_output=True, text=True).stdout.splitlines()
        held = [" ".join(l.split()[:6]) for l in held if f":{self.rpcport} " in l]
        return (" | ".join(lines)[-500:] + (" | port held: " + "; ".join(held[:3]) if held else ""))

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

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None"""
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
        return f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:70]


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return [dict(v[0], amount="0.12345678")] + v[1:]
    if isinstance(v, dict):
        return dict(v, injected=True)
    return "injected"


def compare(name, core, iron, drop=MOMENT | NOTES, order=None, mask=None, extra=None):
    """Same outcome; for a result the same fields and values (except `drop`); list
    items sorted by `order` when given; `mask` rewrites both replies first;
    `extra` names the call whose EXTRA fields are taken out of irondivid's reply"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", inject(iron[1]))
    if extra and iron[0] == "ok" and isinstance(iron[1], dict):
        found = EXTRA[extra] & set(iron[1])
        extra_seen.setdefault(extra, set()).update(found)
        iron = ("ok", {k: v for k, v in iron[1].items() if k not in found})
    if core[0] == "err" or iron[0] == "err":
        row(name, short(core), short(iron), core[0] == iron[0] and core[1:] == iron[1:])
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if mask:
        a, b = mask(a), mask(b)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:90]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1, sort_keys=True)
    row(name, short(core), d or short(iron), d is None)


def masked(v, names=None):
    """64-hex strings (txids, block hashes) replaced, so two nodes' own
    transactions compare by shape; `names` maps known strings to their roles"""
    names = names or {}
    if isinstance(v, dict):
        return {k: masked(x, names) for k, x in v.items()}
    if isinstance(v, list):
        return [masked(x, names) for x in v]
    if isinstance(v, str):
        if v in names:
            return names[v]
        if HEX64.match(v):
            return "<hash>"
    return v


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
    print(f"FAIL   setup: {value}"[:300], flush=True)
    for n in globals().get("NODES", ()):
        t = n.tail()
        if t:
            print(f"#      {n.name}: {t}"[:700], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- the nodes -----------------------------------------------------------------------

P2P = PORT_BASE
CO = Node("divid-owner", DIVID, PORT_BASE + 1, ["listen=1", f"port={P2P}"])
if not CO.wait_ready():
    print(f"FAIL   start: divid owner did not answer within {START_TIMEOUT} s: {CO.tail()}", flush=True)
    sys.exit(1)
CM = Node("divid-manager", DIVID, PORT_BASE + 2, ["listen=0", f"port={P2P}", f"connect=127.0.0.1:{P2P}", "vault=1"])
if not CM.wait_ready():
    print(f"FAIL   start: divid manager did not answer within {START_TIMEOUT} s: {CM.tail()}", flush=True)
    sys.exit(1)
owner_phrase, manager_phrase = CO.rpc("dumphdinfo")["mnemonic"], CM.rpc("dumphdinfo")["mnemonic"]
IO = Node("irondivid-owner", IRONDIVID, PORT_BASE + 3, ["listen=0", f"port={P2P}", f"connect=127.0.0.1:{P2P}"],
          env={"WALLET_MNEMONIC": owner_phrase})
IM = Node("irondivid-manager", IRONDIVID, PORT_BASE + 4,
          ["listen=0", f"port={P2P}", f"connect=127.0.0.1:{P2P}", "vault=1"],
          env={"WALLET_MNEMONIC": manager_phrase})
del owner_phrase, manager_phrase
for n in (IO, IM):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s: {n.tail()}", flush=True)
        sys.exit(1)
NODES = (CO, CM, IO, IM)
print(f"# divid {CO.rpc('getinfo').get('version')}, irondivid {IO.rpc('getnetworkinfo').get('version')}", flush=True)


def synced():
    best = lambda: CO.rpc("getbestblockhash")
    return wait_for(lambda: all(n.rpc("getbestblockhash") == best() for n in NODES), 90)


def mine(n=1, node=None):
    (node or CO).rpc("setgenerate", n)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


def seen_by_all(txid):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in NODES), 60)


mine(101)
OWN = CO.rpc("getnewaddress")      # an owner address; irondivid's owner has its key too
MGR = CM.rpc("getnewaddress")      # a manager address; irondivid's manager has its key too
VAULT = f"{OWN}:{MGR}"
DEST = CO.rpc("getnewaddress")     # where the owner withdraws to
NAMES = {OWN: "<owner>", MGR: "<manager>", DEST: "<dest>"}

tracked = []   # (what, divid's txid, irondivid's txid)


def tx_shape(node, txid):
    """A transaction as the roles of its outputs: destination, vault (with whose
    keys), change to the wallet, other; with values"""
    raw = node.rpc("getrawtransaction", txid, 1)
    outs = []
    for v in raw["vout"]:
        spk = v.get("scriptPubKey", {})
        addrs = spk.get("addresses", [])
        kind = spk.get("type", "")
        if kind == "vault" or (len(addrs) == 2 and kind != "multisig"):
            role = "vault " + ":".join(NAMES.get(a, "<other>") for a in addrs)
        elif addrs and addrs[0] in NAMES:
            role = NAMES[addrs[0]]
        elif addrs and node.rpc("validateaddress", addrs[0]).get("ismine"):
            role = "<wallet>"
        else:
            role = kind or "<none>"
        outs.append((role, v.get("value")))
    return {"inputs": len(raw["vin"]), "outputs": sorted(outs)}


def step_pair(what, fn_core, fn_iron, reply_mask=None):
    """A vault step on divid, then on irondivid once all have seen divid's
    transaction; the two replies and the two transactions compared by shape"""
    c = fn_core()
    ctx = c[1].get("txhash") if c[0] == "ok" and isinstance(c[1], dict) else (c[1] if c[0] == "ok" else None)
    if ctx and HEX64.match(str(ctx)) and not seen_by_all(ctx):
        raise RuntimeError(f"divid's {what} did not reach every node")
    i = fn_iron()
    itx = i[1].get("txhash", i[1].get("txid")) if i[0] == "ok" and isinstance(i[1], dict) else (i[1] if i[0] == "ok" else None)
    if itx and HEX64.match(str(itx)) and not seen_by_all(itx):
        raise RuntimeError(f"irondivid's {what} did not reach every node")
    compare(f"{what}: reply", c, i, mask=reply_mask or (lambda v: masked(v, NAMES)))
    if ctx and itx and HEX64.match(str(ctx)) and HEX64.match(str(itx)):
        tracked.append((what, ctx, itx))
        compare(f"{what}: transaction", ("ok", tx_shape(CO, ctx)), ("ok", tx_shape(CO, itx)))
    return ctx, itx


def re_owner(v):
    """The manager-only fundvault form takes the owner key from each wallet's own
    keypool: an encoding's owner half that is no known address is compared as
    "a new key of this wallet" """
    if isinstance(v, dict):
        return {k: re_owner(x) for k, x in v.items()}
    if isinstance(v, list):
        return [re_owner(x) for x in v]
    if isinstance(v, str) and v.count(":") == 1:
        owner, manager = v.split(":")
        if owner not in NAMES:
            return "<new owner key>:" + NAMES.get(manager, manager)
    return v


# --- the views -------------------------------------------------------------------------

def views(when):
    p = f"{when}: "
    txkey = lambda e: (e.get("txid", ""), e.get("vout", 0), e.get("category", ""), str(e.get("amount", "")))
    for side, c, i in (("owner", CO, IO), ("manager", CM, IM)):
        q = f"{p}{side} "
        for args in ([], ["*", 1, True], ["*", 0]):
            compare(f"{q}getbalance {json.dumps(args)}", c.call("getbalance", *args), i.call("getbalance", *args))
        compare(f"{q}listunspent", c.call("listunspent"), i.call("listunspent"),
                order=lambda u: (u.get("txid", ""), u.get("vout", 0)), drop=MOMENT | {"ischange", "solvable"})
        compare(f"{q}listtransactions * 100 0 true", c.call("listtransactions", "*", 100, 0, True),
                i.call("listtransactions", "*", 100, 0, True), order=txkey)
        for what, a, b in tracked:
            for txid in (a, b):
                mine_ = "divid's" if txid == a else "irondivid's"
                compare(f"{q}gettransaction of {mine_} {what}", c.call("gettransaction", txid, True),
                        i.call("gettransaction", txid, True))
        compare(f"{q}getcoinavailability", c.call("getcoinavailability"), i.call("getcoinavailability"),
                extra="getcoinavailability")
        compare(f"{q}getcoinavailability true", c.call("getcoinavailability", True),
                i.call("getcoinavailability", True), mask=lambda v: sort_txids(v), extra="getcoinavailability")
        cw, iw = c.call("getwalletinfo"), i.call("getwalletinfo")
        if cw[0] == iw[0] == "ok":
            compare(f"{q}getwalletinfo", cw, ("ok", {k: v for k, v in iw[1].items() if k in cw[1]}))
        else:
            compare(f"{q}getwalletinfo", cw, iw)
    for call in EXTRA:
        found = extra_seen.pop(call, set())
        row(f"{p}{call}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


def sort_txids(v):
    if isinstance(v, dict):
        return {k: sorted(x) if k == "txids" and isinstance(x, list) else sort_txids(x) for k, x in v.items()}
    if isinstance(v, list):
        return sorted((sort_txids(x) for x in v), key=lambda e: json.dumps(e, sort_keys=True))
    return v


def refusals(when):
    p = f"{when}: refused "
    both = lambda name, c, i, method, *params: compare(p + name, c.call(method, *params), i.call(method, *params),
                                                      mask=lambda v: masked(v, NAMES))
    bad = "notanaddress"
    both("fundvault bad manager-only encoding", CO, IO, "fundvault", bad, 1)
    both("fundvault bad manager", CO, IO, "fundvault", f"{OWN}:{bad}", 1)
    both("fundvault bad owner", CO, IO, "fundvault", f"{bad}:{MGR}", 1)
    both("fundvault amount too high", CO, IO, "fundvault", VAULT, 90000000)
    both("addvault no separator", CM, IM, "addvault", OWN, tracked[0][1])
    both("addvault on the owner wallet", CO, IO, "addvault", VAULT, tracked[0][1])
    both("addvault bad manager", CM, IM, "addvault", f"{OWN}:{bad}", tracked[0][1])
    both("addvault unknown funding", CM, IM, "addvault", VAULT, "11" * 32)
    both("removevault no separator", CM, IM, "removevault", OWN)
    both("removevault bad owner", CM, IM, "removevault", f"{bad}:{MGR}")
    both("debitvaultbyname bad encoding", CO, IO, "debitvaultbyname", bad, DEST, 1)
    both("debitvaultbyname from the manager wallet", CM, IM, "debitvaultbyname", VAULT, DEST, 1)
    both("debitvaultbyname bad destination", CO, IO, "debitvaultbyname", VAULT, bad, 1)
    both("debitvaultbyname amount too high", CO, IO, "debitvaultbyname", VAULT, DEST, 90000000)
    both("debitvaultbyname bad fee mode", CO, IO, "debitvaultbyname", VAULT, DEST, 1, "nosuchmode")
    both("addvault bad owner", CM, IM, "addvault", f"{bad}:{MGR}", tracked[0][1])
    both("removevault bad manager", CM, IM, "removevault", f"{OWN}:{bad}")
    both("reclaimvaultfunds bad address", CO, IO, "reclaimvaultfunds", bad, 1)
    both("reclaimvaultfunds amount too high", CO, IO, "reclaimvaultfunds", DEST, 90000000)
    both("reclaimvaultfunds bad fee mode", CO, IO, "reclaimvaultfunds", DEST, 1, "nosuchmode")


# --- the steps -------------------------------------------------------------------------

# 1. fundvault, owner:manager form and manager-only form
step_pair("fundvault owner:manager", lambda: CO.call("fundvault", VAULT, 100), lambda: IO.call("fundvault", VAULT, 100))
step_pair("fundvault manager-only", lambda: CO.call("fundvault", MGR, 50), lambda: IO.call("fundvault", MGR, 50),
          reply_mask=lambda v: masked(re_owner(v), NAMES))


mine(1)
views("after fundvault")

# 2. addvault on both managers, for divid's and irondivid's owner:manager funding
fund_c, fund_i = tracked[0][1], tracked[0][2]
compare("addvault divid's funding: reply", CM.call("addvault", VAULT, fund_c), IM.call("addvault", VAULT, fund_c))
compare("addvault irondivid's funding: reply", CM.call("addvault", VAULT, fund_i), IM.call("addvault", VAULT, fund_i))
mine(20)
views("after addvault")

# 3. the owner spends from the vaults: debitvaultbyname, reclaimvaultfunds
step_pair("debitvaultbyname", lambda: CO.call("debitvaultbyname", VAULT, DEST, 10),
          lambda: IO.call("debitvaultbyname", VAULT, DEST, 10))
mine(1)
step_pair("debitvaultbyname receiver_pays", lambda: CO.call("debitvaultbyname", VAULT, DEST, 10, "receiver_pays"),
          lambda: IO.call("debitvaultbyname", VAULT, DEST, 10, "receiver_pays"))
mine(1)
step_pair("reclaimvaultfunds", lambda: CO.call("reclaimvaultfunds", DEST, 10),
          lambda: IO.call("reclaimvaultfunds", DEST, 10))
mine(1)
step_pair("reclaimvaultfunds receiver_pays", lambda: CO.call("reclaimvaultfunds", DEST, 10, "receiver_pays"),
          lambda: IO.call("reclaimvaultfunds", DEST, 10, "receiver_pays"))
for owner in (CO, IO):
    f = owner.rpc("fundvault", VAULT, 50)
    seen_by_all(f["txhash"] if isinstance(f, dict) else f)
mine(1)
step_pair("reclaimvaultfunds metadata", lambda: CO.call("reclaimvaultfunds", DEST, 10, "metadata", "rent", "landlord"),
          lambda: IO.call("reclaimvaultfunds", DEST, 10, "metadata", "rent", "landlord"))
mine(1)
# sweep_funds spends a whole vault, so each side sweeps one funded just before it
SWEEP = f"{CO.rpc('getnewaddress')}:{MGR}"
NAMES[SWEEP.split(':')[0]] = "<sweep owner>"
sweeps = []
for node in (CO, IO):
    fund = node.rpc("fundvault", SWEEP, 30)
    seen_by_all(fund["txhash"] if isinstance(fund, dict) else fund)
    mine(1)
    out = node.call("debitvaultbyname", SWEEP, DEST, 30, "sweep_funds")
    if out[0] == "ok":
        seen_by_all(out[1])
    sweeps.append((node.name, out, tx_shape(CO, out[1]) if out[0] == "ok" else None))
    mine(1)
c_sweep, i_sweep = sweeps
compare("debitvaultbyname sweep_funds: reply", c_sweep[1], i_sweep[1], mask=lambda v: masked(v, NAMES))
compare("debitvaultbyname sweep_funds: transaction", ("ok", c_sweep[2]), ("ok", i_sweep[2]))
views("after the owner spent")

# Spending a vault whose only coins are unconfirmed change while another vault
# has confirmed coins: divid's balance check is over all vaults and passes
# (GetVaultedBalance, rpcwallet.cpp:727-734), then its coin selection for this
# vault finds nothing (rpcwallet.cpp:796-800)
UNCONF = f"{CO.rpc('getnewaddress')}:{MGR}"
OTHER = f"{CO.rpc('getnewaddress')}:{MGR}"
NAMES[UNCONF.split(':')[0]] = "<unconfirmed-vault owner>"
NAMES[OTHER.split(':')[0]] = "<other-vault owner>"
f = CO.rpc("fundvault", OTHER, 50)
seen_by_all(f["txhash"] if isinstance(f, dict) else f)
f = CO.rpc("fundvault", UNCONF, 40)
seen_by_all(f["txhash"] if isinstance(f, dict) else f)
mine(1)
d = CO.rpc("debitvaultbyname", UNCONF, DEST, 39.9)
seen_by_all(d)
compare("refused debitvaultbyname with only unconfirmed vault coins",
        CO.call("debitvaultbyname", UNCONF, DEST, 0.05), IO.call("debitvaultbyname", UNCONF, DEST, 0.05),
        mask=lambda v: masked(v, NAMES))
mine(1)

# 4. the manager stakes a vault coin: divid's manager first, then irondivid's
staked = []
for node in (CM, IM):
    # fresh vault coins for each manager: divid's stake combines every mature
    # vault coin it manages, so the second manager needs coins of its own
    for owner in (CO, IO):
        fund = owner.rpc("fundvault", VAULT, 100)
        seen_by_all(fund["txhash"] if isinstance(fund, dict) else fund)
    mine(25)
    # divid looks for a stake time back from the clock (only irondivid starts
    # past the median time): let the clock pass the tip first
    tip_time = CO.rpc("getblock", CO.rpc("getbestblockhash"))["time"]
    wait_for(lambda: time.time() > tip_time + 2, 180)
    before = node.rpc("getblockcount")
    for _ in range(5):
        out = node.call("setgenerate", 1)
        if out[0] == "ok":
            break
        time.sleep(2)
    if out[0] == "ok" and synced():
        block = node.rpc("getblock", node.rpc("getblockhash", before + 1))
        # the roles of the coinstake's outputs (the coins it combines differ)
        shape = tx_shape(CO, block["tx"][1]) if len(block["tx"]) > 1 else {"outputs": []}
        staked.append({"output roles": sorted(r for r, _ in shape["outputs"])})
    else:
        staked.append({"error": short(out)})
compare("manager stakes a vault coin: coinstake", ("ok", staked[0]), ("ok", staked[1]))
views("after the managers staked")

# 5. removevault, without and with a tx_hash
compare("removevault: reply", CM.call("removevault", VAULT), IM.call("removevault", VAULT))
compare("removevault again: reply", CM.call("removevault", VAULT), IM.call("removevault", VAULT))
compare("removevault with tx_hash: reply", CM.call("removevault", VAULT, fund_c),
        IM.call("removevault", VAULT, fund_c))
views("after removevault")

refusals("before restart")

# 6. restart all four: the views must come back the same from disk
for n in NODES:
    n.stop()
for n in NODES:
    n.start()
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s: {n.tail()}", flush=True)
        sys.exit(1)
if not synced():
    print("FAIL   restart: the nodes did not reconnect", flush=True)
    sys.exit(1)
views("after restart")

# 7. locked: the owner wallets encrypted with the same throwaway passphrase
passphrase = secrets.token_hex(16)
for n in (CO, IO):
    n.rpc("encryptwallet", passphrase)
del passphrase
for n in (CO, IO):
    wait_for(lambda: n.call("getwalletinfo")[0] == "ok", 60)
lp = "locked: refused "
for name, method, params in (("fundvault", "fundvault", [VAULT, 1]),
                             ("debitvaultbyname", "debitvaultbyname", [VAULT, DEST, 1]),
                             ("reclaimvaultfunds", "reclaimvaultfunds", [DEST, 1])):
    compare(lp + name, CO.call(method, *params), IO.call(method, *params))

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
