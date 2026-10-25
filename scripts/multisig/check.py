#!/usr/bin/env python3
"""A multisig address from creation to spend, on Divi Core divid and irondivid
side by side on one regtest chain mined by a divid of its own.

Each daemon runs five wallets: `all` (the three keys), `k1` and `k2` (one key
each), `w0` and `w1` (no key: the address imported watch-only, without and with
rescan). The same three keys, made on the miner, go into each daemon's wallets,
so no single wallet but `all` holds every key. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. Private
keys live only in memory and in RPC request bodies; they are never printed or
put on a command line. RPC passwords are made at random and kept in each node's
0600 divi.conf.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("MULTISIG_INJECT", "")
HOST = os.environ.get("MULTISIG_HOST", "127.0.0.2")
# A directory to write both replies of every compared row to (for looking into
# a FAIL); nothing is written without it
DUMP = os.environ.get("MULTISIG_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 180

KNOWN = {
    "listunspent: fields divid lacks": (
        "ischange and solvable, kept as extra fields (divid's listunspent, rpcrawtransaction.cpp:320-334; "
        "the same KNOWN as scripts/wallet-replies)", lambda c, i: i <= {"ischange", "solvable"} and not c),
    "decodescript: fields divid lacks": (
        "hex, the script given (divid: rpcrawtransaction.cpp:556-563 calls ScriptPubKeyToJSON without it; the "
        "same KNOWN as scripts/raw-replies and chain-replies)", lambda c, i: i == {"hex"} and not c),
    "importaddress of the redeemScript hex (w0)": (
        "irondivid watches P2PKH and P2SH scripts only (its watch list is keyed by address); divid watches any "
        "script (rpcdump.cpp:122-148), but a watched script never brings a transaction into its wallet "
        "(wallet.cpp:1299-1309 adds only what credits or debits a spendable output), so the reply is the "
        "only difference", lambda c, i: c == ("ok", None) and i[0] == "err" and i[1] == -4),
}

# Fields irondivid adds on purpose: compared without them, and named in one row each
EXTRA = {"listunspent": {"ischange", "solvable"}, "decodescript": {"hex"}}
extra_seen = {m: set() for m in EXTRA}


def without_extra(method, out):
    if out[0] != "ok":
        return out
    v = out[1]
    for item in (v if isinstance(v, list) else [v]):
        if isinstance(item, dict):
            extra_seen[method] |= EXTRA[method] & set(item)
    return ("ok", strip(v, EXTRA[method]))

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is None or shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


class Node:
    def __init__(self, name, binary, index, core, extra=()):
        self.name, self.binary, self.core = name, binary, core
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"ms{index}"
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
        self.proc = None
        self.runs = 0

    def start(self):
        self.runs += 1
        self.log = open(os.path.join(WORK, f"{self.name}.{self.runs}.out"), "w")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=WORK, stdout=self.log,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

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

    def call(self, method, *params):
        """('ok', result) or ('err', code, message); reals keep their text"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
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

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
        return out[1]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- how replies are compared ---------------------------------------------------------

def first_difference(a, b, path="$"):
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
    if a != b or type(a) is not type(b):
        return f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"
    return None


def help_first_line(out):
    """divid's help text (a -1 error of several lines): its first line"""
    if out[0] == "err" and out[1] == -1 and "\n" in out[2].strip():
        return ("err", out[1], out[2].strip().split("\n")[0])
    return out


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\"".replace("\n", "\\n")
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:70]


def compare(name, core, iron, key=None, drop=()):
    """Same outcome; an error: the same code and message; a result: the same
    fields, types and values (list items sorted by `key`, fields in `drop` left out)"""
    core, iron = help_first_line(core), help_first_line(iron)
    if INJECT == name and iron[0] == "ok":
        iron = ("ok", {"injected": iron[1]})
    if core[0] == "err" or iron[0] == "err":
        row(name, short(core), short(iron), core == iron, (core, iron))
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if key and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=key), sorted(b, key=key)
    d = first_difference(a, b)
    if DUMP and d:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1, sort_keys=True)
    row(name, short(core), d or short(iron), d is None, (a, b))


def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def both(name, role, method, *params, key=None, drop=(), core_params=None):
    c = D[role].call(method, *(params if core_params is None else core_params))
    i = I[role].call(method, *params)
    compare(name, c, i, key, drop)
    return c, i


def wait_for(fn, secs):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

ROLES = ("all", "k1", "k2", "w0", "w1")
M = Node("miner", DIVID, 0, True, ["listen=1"])
D = {r: Node(f"divid-{r}", DIVID, 1 + k, True, ["listen=0", f"connect={HOST}:{PORT_BASE}"])
     for k, r in enumerate(ROLES)}
I = {r: Node(f"irondivid-{r}", IRONDIVID, 6 + k, False, ["listen=0", f"connect={HOST}:{PORT_BASE}"])
     for k, r in enumerate(ROLES)}
NODES = [M] + list(D.values()) + list(I.values())
for n in NODES:
    n.start()
for n in NODES:
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)


def synced():
    tip = M.rpc("getbestblockhash")
    return all(wait_for(lambda n=n: n.rpc("getbestblockhash") == tip, 120) for n in NODES[1:])


def mine(n):
    M.rpc("setgenerate", n)
    if not synced():
        print("FAIL   setup: a node did not follow the miner", flush=True)
        sys.exit(1)


mine(40)

# --- the keys -----------------------------------------------------------------------------

addr = [M.rpc("getnewaddress") for _ in range(3)]
pub = [M.rpc("validateaddress", a)["pubkey"] for a in addr]
wif = [M.rpc("dumpprivkey", a) for a in addr]
more = [M.rpc("validateaddress", M.rpc("getnewaddress"))["pubkey"] for _ in range(14)]
other_wif = M.rpc("dumpprivkey", M.rpc("getnewaddress"))
holds = {"all": (0, 1, 2), "k1": (0,), "k2": (1,), "w0": (), "w1": ()}
for side in (D, I):
    for role, ks in holds.items():
        for k in ks:
            side[role].rpc("importprivkey", wif[k], "", False)

# An uncompressed form of key 3 (secp256k1: y from x, p = 3 mod 4), for the uncompressed-key rows
P = 2 ** 256 - 2 ** 32 - 977
x = int(pub[2][2:], 16)
y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
if y % 2 != int(pub[2][:2], 16) % 2:
    y = P - y
uncompressed = "04" + f"{x:064x}" + f"{y:064x}"
print("# keys made on the miner and imported; none is printed", flush=True)

# --- createmultisig and addmultisigaddress ------------------------------------------------

forms = [
    ("1-of-1", 1, [pub[0]]),
    ("2-of-3 hex keys", 2, pub),
    ("3-of-3 hex keys", 3, pub),
    ("2-of-3 addresses", 2, addr),
    ("2-of-3 a mix of address and hex keys", 2, [addr[0], pub[1], addr[2]]),
    ("2-of-3 with an uncompressed key", 2, [pub[0], pub[1], uncompressed]),
    ("15 keys", 2, pub + more[:12]),
    ("16 keys", 2, pub + more[:13]),
    ("17 keys", 2, pub + more[:14]),
    ("nrequired 0", 0, pub),
    ("nrequired above the key count", 4, pub),
    ("nrequired negative", -1, pub),
    ("nrequired as text", "2", pub),
    ("a duplicate key", 2, [pub[0], pub[0], pub[1]]),
    ("bad hex", 1, ["02zz"]),
    ("a key of the wrong length", 1, ["02abcd"]),
    ("an empty array", 1, []),
    ("keys as text", 1, "notalist"),
]
for label, n, keys in forms:
    # k1 holds key 1 only: an address of key 2 or 3 is "no full public key" there
    both(f"createmultisig {label}", "k1", "createmultisig", n, keys)
both("createmultisig an address not in the wallet (k2's key on k1)", "k1", "createmultisig", 1, [addr[1]])
both("createmultisig with three arguments", "k1", "createmultisig", 1, [pub[0]], "x")
both("createmultisig no arguments", "k1", "createmultisig")
for label, n, keys in forms[:6] + forms[9:12] + forms[13:15]:
    both(f"addmultisigaddress {label}", "all", "addmultisigaddress", n, keys)
both("addmultisigaddress with an account", "all", "addmultisigaddress", 2, pub, "msacct")
both("addmultisigaddress account as a number", "all", "addmultisigaddress", 2, pub, 5)
both("addmultisigaddress four arguments", "all", "addmultisigaddress", 2, pub, "a", "b")

# The address of the rest of the run: 2 of the 3 keys
c, i = both("addmultisigaddress 2-of-3 on k1 (one key)", "k1", "addmultisigaddress", 2, pub)
both("addmultisigaddress 2-of-3 on k2 (one key)", "k2", "addmultisigaddress", 2, pub)
ms = M.rpc("createmultisig", 2, pub)
MS, REDEEM = ms["address"], ms["redeemScript"]
both("validateaddress of it (all)", "all", "validateaddress", MS)
both("validateaddress of it (k1)", "k1", "validateaddress", MS)
both("validateaddress of it (w0, not imported yet)", "w0", "validateaddress", MS)
c, i = D["k1"].call("decodescript", REDEEM), I["k1"].call("decodescript", REDEEM)
compare("decodescript of the redeemScript", c, without_extra("decodescript", i))
both("getaddressesbyaccount msacct", "all", "getaddressesbyaccount", "msacct")
both("getaccount of it", "all", "getaccount", MS)

# --- funding --------------------------------------------------------------------------------

# Each k2 wallet pays the address from coins of its own; the miner pays it once
# more, the coin the signing rows spend on both sides alike
for side in (D, I):
    M.rpc("sendtoaddress", side["k2"].rpc("getnewaddress"), 200)
mine(1)
sent = {}
for side, tag in ((D, "D"), (I, "I")):
    out = side["k2"].call("sendtoaddress", MS, 50)
    sent[tag] = out
row("sendtoaddress to it", short(sent["D"]), short(sent["I"]),
    sent["D"][0] == sent["I"][0] == "ok" and len(sent["D"][1]) == len(sent["I"][1]) == 64)
shared_tx = M.rpc("sendtoaddress", MS, 30)
if not wait_for(lambda: len(M.rpc("getrawmempool")) >= 3, 60):
    print("FAIL   setup: the payments to the address did not reach the miner", flush=True)
    sys.exit(1)
mine(1)


def vout_to(txid, address, node=M):
    tx = node.rpc("getrawtransaction", txid, 1)
    for o in tx["vout"]:
        if address in o["scriptPubKey"].get("addresses", []):
            return o["n"], o["value"], o["scriptPubKey"]["hex"]
    raise RuntimeError(f"no output to {address} in {txid}")


coins = {tag: (sent[tag][1],) + vout_to(sent[tag][1], MS) for tag in ("D", "I")}
coins["S"] = (shared_tx,) + vout_to(shared_tx, MS)
SPK = coins["S"][3]

# --- the wallet views -------------------------------------------------------------------------

utxo_key = lambda u: (u.get("txid", ""), u.get("vout", 0))
tx_key = lambda t: (t.get("txid", ""), t.get("category", ""), t.get("vout", 0), str(t.get("amount")))
MOMENT = ("time", "timereceived", "blocktime", "confirmations")


def of_ms(out):
    """The entries for the multisig address"""
    if out[0] != "ok" or not isinstance(out[1], list):
        return out
    return ("ok", [e for e in out[1] if e.get("address") == MS])


def views(p):
    for role, label in (("all", "all keys"), ("k1", "one key"), ("w0", "watch-only, no rescan"),
                        ("w1", "watch-only, rescan")):
        c, i = D[role].call("listunspent", 0), I[role].call("listunspent", 0)
        compare(f"{p}listunspent ({label})", without_extra("listunspent", of_ms(c)),
                without_extra("listunspent", of_ms(i)), key=utxo_key, drop=("confirmations",))
        both(f"{p}getbalance ({label})", role, "getbalance")
        both(f"{p}getbalance * 0 watch-only ({label})", role, "getbalance", "*", 0, True)
        c = D[role].call("listtransactions", "*", 100, 0, True)
        i = I[role].call("listtransactions", "*", 100, 0, True)
        compare(f"{p}listtransactions with watch-only ({label})", of_ms(c), of_ms(i), key=tx_key, drop=MOMENT)
        both(f"{p}getreceivedbyaddress ({label})", role, "getreceivedbyaddress", MS)
        both(f"{p}getreceivedbyaddress 0 ({label})", role, "getreceivedbyaddress", MS, 0)


both("importaddress without rescan (w0)", "w0", "importaddress", MS, "", False)
both("importaddress with rescan (w1)", "w1", "importaddress", MS, "watched", True)
both("importaddress again (w1)", "w1", "importaddress", MS, "watched", True)
both("importaddress of an address whose keys the wallet holds (all)", "all", "importaddress", MS, "", False)
both("importaddress of the redeemScript hex (w0)", "w0", "importaddress", REDEEM, "", False)
both("validateaddress of it (w0, imported)", "w0", "validateaddress", MS)
views("")

# --- the address index --------------------------------------------------------------------------


def index(p):
    q = {"addresses": [MS]}
    both(f"{p}getaddressbalance", "all", "getaddressbalance", q)
    both(f"{p}getaddressutxos", "all", "getaddressutxos", q, key=utxo_key)
    both(f"{p}getaddresstxids", "all", "getaddresstxids", q, key=lambda t: t)
    both(f"{p}getaddressdeltas", "all", "getaddressdeltas", q,
         key=lambda d: (d.get("txid", ""), d.get("index", 0), d.get("satoshis", 0)))


index("before the spend: ")

# --- signing the coin both sides see alike -------------------------------------------------------

dest = M.rpc("getnewaddress")
txid, n, value, _ = coins["S"]
inputs = [{"txid": txid, "vout": n}]
outs = {dest: float(value) - 0.001}
c_raw, i_raw = D["k1"].call("createrawtransaction", inputs, outs), I["k1"].call("createrawtransaction", inputs, outs)
compare("createrawtransaction spending it", c_raw, i_raw)
raw = c_raw[1]
prev = [{"txid": txid, "vout": n, "scriptPubKey": SPK}]
prev_rs = [dict(prev[0], redeemScript=REDEEM)]


def sign(name, role, *params):
    """signrawtransaction on both; the replies compared whole (the signatures are
    deterministic, RFC 6979, so the hex is the same on both when all goes alike)"""
    return both(name, role, "signrawtransaction", *params)


c1, i1 = sign("signrawtransaction with one key (k1)", "k1", raw)
part_c = c1[1]["hex"] if c1[0] == "ok" else raw
part_i = i1[1]["hex"] if i1[0] == "ok" else raw
c2 = D["k2"].call("signrawtransaction", part_c)
i2 = I["k2"].call("signrawtransaction", part_i)
compare("signrawtransaction of the partial hex with the second key (k2)", c2, i2)
sign("signrawtransaction with one key, then the same key again", "k1", part_c)
sign("signrawtransaction with all keys (all)", "all", raw)
sign("signrawtransaction with no key (w0)", "w0", raw)
sign("signrawtransaction privkey 1, prevtxs without redeemScript (w0)", "w0", raw, prev, [wif[0]])
sign("signrawtransaction privkey 1, prevtxs with redeemScript (w0)", "w0", raw, prev_rs, [wif[0]])
sign("signrawtransaction privkeys 1 and 2, prevtxs with redeemScript (w0)", "w0", raw, prev_rs, [wif[0], wif[1]])
sign("signrawtransaction privkeys, no prevtxs (w0)", "w0", raw, [], [wif[0], wif[1]])
sign("signrawtransaction a wrong privkey (w0)", "w0", raw, prev_rs, [other_wif])
sign("signrawtransaction a bad privkey (w0)", "w0", raw, prev_rs, ["notakey"])
sign("signrawtransaction prevtxs with redeemScript, wallet keys (k1)", "k1", raw, prev_rs)
sign("signrawtransaction prevtxs without scriptPubKey", "k1", raw, [{"txid": txid, "vout": n}])
sign("signrawtransaction prevtxs with a wrong scriptPubKey", "k1", raw,
     [{"txid": txid, "vout": n, "scriptPubKey": "76a914" + "00" * 20 + "88ac"}])
for sighash in ("ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY", "FOO"):
    sign(f"signrawtransaction sighash {sighash} (all)", "all", raw, None, None, sighash)
sign("signrawtransaction not hex", "k1", "zz")
sign("signrawtransaction no arguments", "k1")
both("sendrawtransaction of the partial hex", "k1", "sendrawtransaction", part_i, core_params=(part_c,))

# --- spending each side's own coin ---------------------------------------------------------------

done = {}
for side, tag in ((D, "D"), (I, "I")):
    t, n, v, _ = coins[tag]
    r = side["k1"].rpc("createrawtransaction", [{"txid": t, "vout": n}], {dest: float(v) - 0.001})
    p1 = side["k1"].rpc("signrawtransaction", r)["hex"]
    sent_partial = side["k1"].call("sendrawtransaction", p1)
    full = side["k2"].rpc("signrawtransaction", p1)
    sent_full = side["k2"].call("sendrawtransaction", full["hex"])
    again = side["k2"].call("sendrawtransaction", full["hex"])
    done[tag] = (sent_partial, full["complete"], sent_full, again)
row("sendrawtransaction of the partial hex (own coin)", short(done["D"][0]), short(done["I"][0]),
    done["D"][0] == done["I"][0])
row("signrawtransaction second key: complete", done["D"][1], done["I"][1], done["D"][1] == done["I"][1])
row("sendrawtransaction of the complete hex", short(done["D"][2]), short(done["I"][2]),
    done["D"][2][0] == done["I"][2][0] == "ok")
# Each side's own transaction: the same outcome, and a txid that is the one just sent
again = {t: ("txid of it" if d[3] == d[2] else short(d[3])) for t, d in done.items()}
row("sendrawtransaction of it again", again["D"], again["I"], again["D"] == again["I"], (done["D"][3], done["I"][3]))
if not wait_for(lambda: len(M.rpc("getrawmempool")) >= 2, 60):
    print("FAIL   setup: the spends did not reach the miner", flush=True)
    sys.exit(1)
mine(1)
views("after the spend: ")
index("after the spend: ")

# --- a restart --------------------------------------------------------------------------------------

for n in NODES[1:]:
    n.stop()
for n in NODES[1:]:
    n.start()
for n in NODES[1:]:
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not synced():
    print("FAIL   restart: a node did not reconnect to the miner", flush=True)
    sys.exit(1)
views("after a restart: ")
both("after a restart: validateaddress of it (k1)", "k1", "validateaddress", MS)
both("after a restart: getaddressesbyaccount msacct", "all", "getaddressesbyaccount", "msacct")

for method in EXTRA:
    found = extra_seen[method]
    row(f"{method}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found, (set(), found))

for n in NODES:
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
