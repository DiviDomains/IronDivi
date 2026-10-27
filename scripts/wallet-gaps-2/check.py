#!/usr/bin/env python3
"""The next wallet cases of Divi Core divid that no other script compares,
next to irondivid on regtest: sweeps (too large, too little left, past
-maxtxfee), vaults whitelisted at start or added with another transaction,
reclaimvaultfunds' notes, imports of the wallet's own key and script,
out-of-range keys and hex scripts, bip38decrypt's rescan, -hdseed with
-mnemonic, and refusals on a locked wallet.

S, a divid, mines and pays; C, a divid wallet; I, an irondivid restored from
C's phrase (WALLET_MNEMONIC), so the twins hold the same keys. Each case runs
on both and their outcomes are compared (replies, error codes and texts, the
wallet's state after), not timing. Each row prints PASS (same as divid), KNOWN
(a difference listed in README.md) or FAIL. Exit code = FAILs.

Throwaway keys, phrases, seeds and passphrases are made in the run and go over
RPC or into the run's own 0600 divi.conf files; none is printed or put on a
command line.
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
INJECT = os.environ.get("WALLET_GAPS_2_INJECT", "")
HOST = "127.0.0.150"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
OWN_SCRIPT = ("divid takes the hex of the wallet's own P2PKH script as watch-only, as a script names no address for its "
              "spendable check (rpcdump.cpp:138-147), and then counts the address as watch-only, not its own "
              "(ismine false), so a second importaddress of the address passes too; irondivid refuses both with -4 "
              "[on purpose: it would turn an address of the wallet's own into a watch-only one; docs/divid-differences.md R18]")
OWN_REFUSED = {"error": -4, "message": "The wallet already contains the private key for this address or script"}
KNOWN = [
    (lambda n: n in ("importaddress <hex script of an own address> '' false", "importaddress <own address> '' false"),
     OWN_SCRIPT, lambda c, i: c == {"ok": None} and i == OWN_REFUSED),
    (lambda n: n == "then: validateaddress of the own address", OWN_SCRIPT,
     lambda c, i: c == {"ismine": False, "iswatchonly": True} and i == {"ismine": True, "iswatchonly": False}),
]

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if os.environ.get("WALLET_GAPS_2_WIDE") else text[:260]


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = known(name)
    if listed:
        reason, shape = listed
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


class Node:
    """A node on `datadir` (made with a divi.conf when new)"""

    def __init__(self, name, binary, index, extra_conf=(), env=None, datadir=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = datadir or os.path.join(WORK, name)
        self.starts = 0
        self.proc = None
        if not os.path.exists(os.path.join(self.dir, "divi.conf")):
            os.makedirs(self.dir, exist_ok=True)
            password = secrets.token_hex(16)
            user = "wg2" + secrets.token_hex(4)
            lines = [
                "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
                f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
                "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "dnsseed=0",
                "staking=0", "allowunencryptedwallet=1",
            ] + list(extra_conf)
            fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines) + "\n")
        self.read_conf()

    def read_conf(self):
        conf = dict(l.split("=", 1) for l in open(os.path.join(self.dir, "divi.conf")).read().split("\n") if "=" in l)
        self.rpcport = int(conf["rpcport"])
        self.auth = base64.b64encode(f"{conf['rpcuser']}:{conf['rpcpassword']}".encode()).decode()

    def set_conf(self, key, value):
        """Replace (or add) one line of divi.conf"""
        path = os.path.join(self.dir, "divi.conf")
        lines = [l for l in open(path).read().split("\n") if l and not l.startswith(key + "=")]
        lines.append(f"{key}={value}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.read_conf()

    def launch(self, *args):
        self.starts += 1
        self.out = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        env = dict(os.environ, **self.env) if self.env else None
        with open(self.out, "w") as o:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=o, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code)"""
        self.log_from = {p: size(p) for p in self.logs()}
        self.launch(*args)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code)
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.5)
        return ("exit", "none within %d s" % START_TIMEOUT)

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def logs(self):
        return [os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")]

    def new_log(self):
        """The log written since the last start"""
        text = ""
        for p in self.logs():
            try:
                with open(p, errors="replace") as f:
                    f.seek(self.log_from.get(p, 0))
                    text += f.read()
            except OSError:
                pass
        return text

    def stderr(self):
        with open(self.out, errors="replace") as f:
            return f.read()

    def tail(self, n=4):
        lines = []
        for path in [self.out] + self.logs() if self.starts else self.logs():
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


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



def outcome(out, value=lambda v: v):
    if out[0] == "err":
        return {"error": out[1], "message": out[2]}
    return {"ok": value(out[1])}


def amount(v):
    return None if v is None else round(float(v), 8)


def both(name, fn):
    c, i = fn(C), fn(I)
    row(name, c, i)
    return c, i


def raw_call(n, method, params_json):
    """A call whose params are written as JSON text (a JSON object with a
    repeated member, which no Python dict can hold)"""
    body = ('{"jsonrpc": "1.0", "id": 1, "method": "%s", "params": %s}' % (method, params_json)).encode()
    req = urllib.request.Request(f"http://{HOST}:{n.rpcport}/", data=body,
                                 headers={"Authorization": "Basic " + n.auth, "Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
            reply = json.loads(r.read())
    except urllib.error.HTTPError as e:
        reply = json.loads(e.read() or b"{}")
    err = reply.get("error")
    if err:
        return ("err", err.get("code"), err.get("message", ""))
    return ("ok", reply.get("result"))


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        raise ValueError("bad base58 checksum")
    return body


def b58encode(body):
    raw = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def p2pkh_hex(address):
    return "76a914" + b58decode(address)[1:].hex() + "88ac"


# --- the wallets ---------------------------------------------------------------------
# The twins cap a wallet fee at 0.001 DIVI: far above a send of a few inputs,
# below a sweep of hundreds (the -maxtxfee rows)
TWIN_CONF = ["listen=0", "vault=1", "maxtxfee=0.001"]
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
C = Node("divid-wallet", DIVID, 1, TWIN_CONF + [f"connect={HOST}:{S.p2p}"])
if C.start()[0] != "up":
    raise RuntimeError(f"C did not start: {C.tail()}")
C_WORDS = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, TWIN_CONF + [f"connect={HOST}:{S.p2p}"],
         env={"WALLET_MNEMONIC": C_WORDS})
if I.start()[0] != "up":
    raise RuntimeError(f"I did not start: {I.tail()}")
NODES = [S, C, I]
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(n=1):
    for _ in range(n):
        out = S.call("setgenerate", 1)
        if out[0] != "ok":
            tip = S.rpc("getblock", S.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            S.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


def seen(txid):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in NODES), 60)


def shared_address(label=""):
    a = C.rpc("getnewaddress", label)
    I.rpc("setaccount", a, label)
    if not I.rpc("validateaddress", a).get("ismine"):
        raise RuntimeError("the twins' keys parted")
    return a


mine(110)
for _ in range(8):
    S.rpc("sendtoaddress", shared_address(), 100)
# Two sets of 400 coins of 0.25 DIVI, one for each twin's sweeps, and a coin of
# 0.00006
SET_A = [shared_address() for _ in range(10)]
SET_B = [shared_address() for _ in range(10)]
for r in range(40):
    S.rpc("sendmany", "", {a: 0.25 for a in SET_A})
    S.rpc("sendmany", "", {a: 0.25 for a in SET_B})
    if r % 10 == 9:
        mine(1)
TINY = shared_address()
S.rpc("sendtoaddress", TINY, 0.00006)
mine(2)
PAYEE = S.rpc("getnewaddress")
for n in TWINS:
    small = sum(1 for u in n.rpc("listunspent") if u.get("address") in SET_A + SET_B)
    if small != 800:
        raise RuntimeError(f"{n.name} holds {small} of the 800 small coins")


def sent(n, out, notes=False):
    """A send's outcome; a txid is mined before the twin's own send"""
    if out[0] == "ok" and isinstance(out[1], str) and len(out[1]) == 64:
        txid = out[1]
        if not seen(txid):
            raise RuntimeError(f"{n.name}'s send did not reach the others")
        tx = n.rpc("gettransaction", txid)
        mine(1)
        got = {"ok": "txid", "fee": amount(tx.get("fee")),
               "inputs": len(n.rpc("getrawtransaction", txid, 1)["vin"]),
               "to the payee": sorted(amount(d.get("amount")) for d in tx.get("details", [])
                                      if d.get("category") == "send")}
        if notes:
            got.update({k: tx.get(k) for k in ("comment", "to")})
        return got
    return outcome(out)


def send_case(name, method, *params, notes=False, before=None):
    got = {}
    for n in TWINS:
        if before:
            before(n)
        got[n.name] = sent(n, n.call(method, *params), notes)
    row(name, got[C.name], got[I.name])


def first_line(out):
    """An error's code and first line (a help text's usage line)"""
    if out[0] == "err":
        return {"error": out[1], "message": str(out[2]).split("\n")[0]}
    return {"ok": out[1]}


# --- imports -------------------------------------------------------------------------
# The wallet's own HD key again, with a label: divid relabels the address
# first, then returns null as it holds the key (rpcdump.cpp:83-89)
OWN = shared_address("own")
own_key = C.rpc("dumpprivkey", OWN)
both("importprivkey <own HD key> relabelled", lambda n: outcome(n.call("importprivkey", own_key, "relabelled")))
both("then: the own address's account", lambda n: n.rpc("getaccount", OWN))
both("then: getaddressesbyaccount own, relabelled",
     lambda n: [sorted(n.rpc("getaddressesbyaccount", "own")), sorted(n.rpc("getaddressesbyaccount", "relabelled"))])
del own_key
# Keys outside 1 .. n-1 in a well-formed WIF (rpcdump.cpp:76-77)
version = b58decode(S.rpc("dumpprivkey", PAYEE))[:1]
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
for name, secret in (("zero", 0), ("the curve order", ORDER)):
    wif = b58encode(version + secret.to_bytes(32, "big") + b"\1")
    both(f"importprivkey <WIF of {name}>", lambda n: outcome(n.call("importprivkey", wif, "", False)))
# A P2PKH script in hex with a label: watched, but the label is not stored, as
# only a parsed address is labelled (rpcdump.cpp:126-128, :151)
WATCHED = S.rpc("getnewaddress")
both("importaddress <hex script of S's address> hexlabel false",
     lambda n: outcome(n.call("importaddress", p2pkh_hex(WATCHED), "hexlabel", False)))
both("then: validateaddress of S's address",
     lambda n: {k: n.rpc("validateaddress", WATCHED).get(k) for k in ("ismine", "iswatchonly", "account")})
both("then: getaddressesbyaccount hexlabel", lambda n: sorted(n.rpc("getaddressesbyaccount", "hexlabel")))
# setaccount on that watched address (rpcwallet.cpp:600-615)
both("setaccount <the watched address> watched", lambda n: outcome(n.call("setaccount", WATCHED, "watched")))
both("then: getaccount of the watched address", lambda n: n.rpc("getaccount", WATCHED))
# The wallet's own P2PKH script in hex: the spendable check sees no address
# and lets it through (rpcdump.cpp:147)
OWN2 = shared_address()
both("importaddress <hex script of an own address> '' false",
     lambda n: outcome(n.call("importaddress", p2pkh_hex(OWN2), "", False)))
both("then: validateaddress of the own address",
     lambda n: {k: n.rpc("validateaddress", OWN2).get(k) for k in ("ismine", "iswatchonly")})
both("importaddress <own address> '' false", lambda n: outcome(n.call("importaddress", OWN2, "", False)))
# bip38decrypt rescans the whole chain, so a coin paid to the key before it is
# found (rpcdump.cpp:336-345)
BIP_PASS = secrets.token_hex(8)
paper = S.rpc("bip38paperwallet", BIP_PASS)
S.rpc("sendtoaddress", paper["Address"], 5)
mine(1)
balance = lambda n: amount(n.rpc("getbalance"))
before = {n.name: balance(n) for n in TWINS}
both("bip38decrypt <a paper key paid 5 earlier>",
     lambda n: outcome(n.call("bip38decrypt", paper["Encrypted Key"], BIP_PASS)))
both("then: balance change", lambda n: round(balance(n) - before[n.name], 8))
del paper, BIP_PASS
# getcoinavailability's verbose flag is read with get_bool (rpcwallet.cpp:828)
for flag in ("yes", 1, None):
    both(f"getcoinavailability {json.dumps(flag)}", lambda n: first_line(n.call("getcoinavailability", flag)))

# --- vaults ------------------------------------------------------------------------------
MANAGER = shared_address()
# addvault with a mined txid that does not fund the vault: divid stores the
# script first; the call fails unless the tx is already the wallet's
# (rpcwallet.cpp:1295-1301, wallet.cpp:695-704)
V_OTHER = f"{S.rpc('getnewaddress')}:{MANAGER}"
V_OWNTX = f"{S.rpc('getnewaddress')}:{MANAGER}"
other_tx = S.rpc("sendtoaddress", S.rpc("getnewaddress"), 1)
own_tx = S.rpc("sendtoaddress", shared_address(), 1)
mine(1)
both("addvault <vault> <a mined tx not the wallet's>", lambda n: outcome(n.call("addvault", V_OTHER, other_tx)))
both("addvault <vault> <a mined tx of the wallet's, not funding it>",
     lambda n: outcome(n.call("addvault", V_OWNTX, own_tx)))
S.rpc("fundvault", V_OTHER, 4)
S.rpc("fundvault", V_OWNTX, 3)
mine(1)


def vaults(n):
    """The vaults getcoinavailability lists, owned (Vaulted) and managed
    (Stakable), by encoding"""
    out = n.call("getcoinavailability", True)
    if out[0] != "ok":
        return outcome(out)
    return {kind: sorted([v.get("vault"), amount(v.get("value"))] for v in (out[1].get(kind) or {}).get("AllVaults", []))
            for kind in ("Vaulted", "Stakable")}


both("then, both vaults funded: the vaults", vaults)

# -whitelisted_vault=<script hex>: a vault this wallet manages is added at
# load, without its earlier fundings; one it does not manage, or no vault, is
# left out (init.cpp:1182-1191, wallet.cpp:1992-2003)
V_WHITE = f"{S.rpc('getnewaddress')}:{shared_address()}"
V_OWNER = f"{shared_address()}:{S.rpc('getnewaddress')}"


def vault_script(vault, value):
    txid = S.rpc("fundvault", vault, value)["txhash"]
    tx = S.rpc("getrawtransaction", txid, 1)
    return next(o["scriptPubKey"]["hex"] for o in tx["vout"] if amount(o["value"]) == value)


white_hex = vault_script(V_WHITE, 1)
owner_hex = vault_script(V_OWNER, 1.5)
# divid rescans from its last block at every start (wallet.cpp:258-266,
# init.cpp:1242), so these fundings are buried before the restart
mine(3)


def restart_twins(lines):
    for n in TWINS:
        n.stop()
        path = os.path.join(n.dir, "divi.conf")
        kept = [l for l in open(path).read().split("\n") if l and not l.startswith("whitelisted_vault=")]
        with open(path, "w") as f:
            f.write("\n".join(kept + lines) + "\n")
    return {n.name: n.start() for n in TWINS}


got = restart_twins([f"whitelisted_vault={white_hex}", f"whitelisted_vault={owner_hex}",
                     f"whitelisted_vault={p2pkh_hex(PAYEE)}", "whitelisted_vault=nothex"])
row("start with -whitelisted_vault (a managed, an owned, a P2PKH, not hex)", got[C.name], got[I.name])
if any(g[0] != "up" for g in got.values()):
    raise RuntimeError("a twin did not start with -whitelisted_vault")
if not synced():
    raise RuntimeError("the twins did not catch up")
both("after the start: the vaults", vaults)
S.rpc("fundvault", V_WHITE, 2)
S.rpc("fundvault", V_OWNER, 2.5)
mine(1)
both("then, both funded again: the vaults", vaults)
got = restart_twins([])
row("start without -whitelisted_vault", got[C.name], got[I.name])
if not synced():
    raise RuntimeError("the twins did not catch up")
both("then: the vaults", vaults)

# reclaimvaultfunds <dest> <n> "metadata" <comment> <to>: the notes are kept
# with the wallet's transaction (rpcwallet.cpp:1170-1176)
OWN_VAULT = f"{shared_address()}:{shared_address()}"
S.rpc("fundvault", OWN_VAULT, 10)
mine(1)
send_case('reclaimvaultfunds <payee> 1 "metadata" "a note" "a shop"', "reclaimvaultfunds", PAYEE, 1, "metadata",
          "a note", "a shop", notes=True)

# --- a locked wallet --------------------------------------------------------------------
PASS = secrets.token_hex(12)
for n in TWINS:
    n.rpc("encryptwallet", PASS)
if not wait_for(lambda: all(n.rpc("getwalletinfo").get("encryption_status") == "locked" for n in TWINS), 30):
    raise RuntimeError("the twins did not lock")
status = lambda n: n.rpc("getwalletinfo").get("encryption_status")
# The address and amount are read before the lock is checked (rpcwallet.cpp:1324-1358)
for name, params in (("notanaddress 1", ("notanaddress", 1)), ("<payee> -1", (PAYEE, -1)),
                     ('<payee> "abc"', (PAYEE, "abc")), ('<payee> 1 "bogus"', (PAYEE, 1, "bogus"))):
    both(f"locked: sendtoaddress {name}", lambda n: outcome(n.call("sendtoaddress", *params)))
both("then: encryption status", status)
for n in TWINS:
    n.rpc("walletpassphrase", PASS, 99999)

# --- sweeps ------------------------------------------------------------------------------
def only(addresses):
    """Lock every coin of the twin but those paid to `addresses`"""
    def f(n):
        n.rpc("lockunspent", True)
        others = [{"txid": u["txid"], "vout": u["vout"]} for u in n.rpc("listunspent", 0)
                  if u.get("address") not in addresses]
        if others:
            n.rpc("lockunspent", False, others)
    return f


# The coin of 0.00006 alone: what is left after the fee is below the dust
# floor (wallet.cpp:1683-1691, :1794-1798)
send_case('sweep_funds with only a coin of 0.00006: sendtoaddress <payee> 1 "sweep_funds"', "sendtoaddress",
          PAYEE, 1, "sweep_funds", before=only([TINY]))
send_case('sweep_funds with no coin left unlocked', "sendtoaddress", PAYEE, 1, "sweep_funds", before=only([]))
# All 800 small coins: the signed sweep is over 100,000 bytes (wallet.cpp:1595-1597, :1812-1816)
send_case('sweep_funds of 800 coins: sendtoaddress <payee> 1 "sweep_funds"', "sendtoaddress", PAYEE, 1,
          "sweep_funds", before=only(SET_A + SET_B))
# 400 coins: C's set for C, B's for I. A plain send of most of them pays more
# than -maxtxfee (MinimumFeeCoinSelectionAlgorithm.cpp:97); the sweep's selection
# returns at :77, before that check (wallet.cpp:1736-1748)
own_set = lambda n: SET_A if n is C else SET_B
send_case("400 coins of 0.25, -maxtxfee=0.001: sendtoaddress <payee> 90", "sendtoaddress", PAYEE, 90,
          before=lambda n: only(own_set(n))(n))
send_case('400 coins of 0.25, -maxtxfee=0.001: sendtoaddress <payee> 1 "sweep_funds"', "sendtoaddress", PAYEE, 1,
          "sweep_funds", before=lambda n: only(own_set(n))(n))
for n in TWINS:
    n.rpc("lockunspent", True)
    n.rpc("walletlock")

# --- restores from -hdseed ---------------------------------------------------------------
TIP = S.rpc("getblockcount")
S_SEED = S.rpc("dumphdinfo")["hdseed"]
S_ADDRESS = PAYEE
for n in NODES:
    n.stop()
copies = 0


def copy_with(n, lines):
    global copies
    copies += 1
    dest = os.path.join(WORK, f"{n.name}-restore{copies}")
    shutil.copytree(n.dir, dest)
    c = Node(f"{n.name}-restore{copies}", n.binary, 1 if n is C else 2, datadir=dest)
    path = os.path.join(dest, "divi.conf")
    kept = [l for l in open(path).read().split("\n") if l and not l.startswith("connect=")]
    with open(path, "w") as f:
        f.write("\n".join(kept + ["connect=0"] + lines) + "\n")
    return c


def restore(name, lines, view, log_lines):
    """Start a copy of each twin with no wallet and `lines` in its divi.conf
    (a wallet already there is moved aside first; that part is
    fix/wallet-gaps, so it is left out here)"""
    got = {}
    for n in TWINS:
        c = copy_with(n, lines)
        # divid's regtest/wallet.dat, irondivid's wallet folder
        for d in (c.dir, os.path.join(c.dir, "regtest")):
            for w in ("wallet.dat", "wallet"):
                p = os.path.join(d, w)
                if os.path.isdir(p):
                    shutil.rmtree(p)
                elif os.path.exists(p):
                    os.remove(p)
        out = c.start()
        if out[0] == "up":
            wait_for(lambda: c.rpc("getblockcount") == TIP, 60)
            time.sleep(3)
            g = {"start": "up", **view(c)}
            c.stop()
        else:
            err = ""
            with open(c.out, errors="replace") as f:
                for line in f:
                    if line.startswith("Error"):
                        err = line.strip()
                        break
            g = {"start": "exit", "exit code": out[1], "error line": err}
        log = c.new_log()
        for text in log_lines:
            g[f"log: {text}"] = text in log
        got[n.name] = g
        shutil.rmtree(c.dir)
    for k in sorted(got[C.name].keys() | got[I.name].keys()):
        row(f"{name}: {k}", got[C.name].get(k), got[I.name].get(k))


def restored_view(c):
    return {"S's address is mine": c.rpc("validateaddress", S_ADDRESS).get("ismine"),
            "the twins' address is mine": c.rpc("validateaddress", OWN).get("ismine")}


PREFER = "can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed"
INCORRECT = "Incorrect seed, generating random one instead"
# A hex -hdseed wins over -mnemonic (init.cpp:945-951, wallet.cpp:2286-2293)
restore("hdseed=<S's seed> with mnemonic=<the twins' words>", [f"hdseed={S_SEED}", f"mnemonic={C_WORDS}"],
        restored_view, [PREFER])
# One that is not hex: a new random wallet (wallet.cpp:2295-2300)
restore("hdseed=nothex", ["hdseed=nothex"], restored_view, [INCORRECT])
# Not hex, with words: the words are used
restore("hdseed=nothex with mnemonic=<the twins' words>", ["hdseed=nothex", f"mnemonic={C_WORDS}"],
        restored_view, [INCORRECT, PREFER])
del S_SEED, C_WORDS

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
