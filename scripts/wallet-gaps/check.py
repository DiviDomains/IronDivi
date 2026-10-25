#!/usr/bin/env python3
"""Wallet cases of Divi Core divid that no other script compares, next to
irondivid on regtest: sends with a Bitcoin-style comment or minconf, sendmany
refusals, a receiver-pays send smaller than its fee, unlock timers and unlocks
of an unlocked wallet, a passphrase change while unlocked, imports of a
watched address and imports without and then with a rescan, addvault of an
unconfirmed funding, fundvault's object form, and restores from mnemonic=.

S, a divid, mines and pays; C, a divid wallet; I, an irondivid restored from
C's phrase (WALLET_MNEMONIC), so the twins hold the same keys. Each case runs
on both and their outcomes are compared (replies, error codes and texts, the
wallet's state after), not timing. Each row prints PASS (same as divid), KNOWN
(a difference listed in README.md) or FAIL. Exit code = FAILs.

Throwaway keys, phrases and the passphrase are made in the run and go over RPC
or into the run's own 0600 divi.conf files; none is printed or put on a
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("WALLET_GAPS_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape); none at present
KNOWN = []

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v):
    return json.dumps(v, sort_keys=True, default=str)[:260]


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
            user = "wg" + secrets.token_hex(4)
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
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=o, start_new_session=True)
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


# --- the wallets ---------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}", "vault=1"])
if C.start()[0] != "up":
    raise RuntimeError(f"C did not start: {C.tail()}")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}", "vault=1"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
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
    return a


mine(110)
for _ in range(8):
    S.rpc("sendtoaddress", shared_address(), 100)
LABELLED = shared_address("savings")
S.rpc("sendtoaddress", LABELLED, 30)
mine(1)
PAYEE = S.rpc("getnewaddress")


def sent(n, out):
    """A send's outcome; a txid is mined before the twin's own send"""
    # fundvault answers {txhash, vault}; the txid itself is not compared, as
    # divid puts its change at a random index (wallet.cpp:1630-1631)
    funded = out[0] == "ok" and isinstance(out[1], dict) and "txhash" in out[1]
    if funded or (out[0] == "ok" and isinstance(out[1], str) and len(out[1]) == 64):
        txid = out[1]["txhash"] if funded else out[1]
        if not seen(txid):
            raise RuntimeError(f"{n.name}'s send did not reach the others")
        tx = n.rpc("gettransaction", txid)
        mine(1)
        return {"ok": "txid", "fee": amount(tx.get("fee")),
                **({"vault": out[1]["vault"]} if funded else {}),
                "to the payee": sorted(amount(d.get("amount")) for d in tx.get("details", [])
                                       if d.get("category") == "send")}
    return outcome(out)


def send_case(name, method, *params):
    got = {}
    for n in TWINS:
        got[n.name] = sent(n, n.call(method, *params))
    row(name, got[C.name], got[I.name])


# --- sends ---------------------------------------------------------------------------
# divid's 3rd sendtoaddress argument is a fee mode or "metadata"; a Bitcoin-style
# comment there is refused (rpcwallet.cpp:1336-1356)
send_case('sendtoaddress <payee> 1 "donation" (a Bitcoin-style comment)', "sendtoaddress", PAYEE, 1, "donation")
send_case('sendtoaddress <payee> 1 "donation" "a shop"', "sendtoaddress", PAYEE, 1, "donation", "a shop")
send_case('sendtoaddress <payee> 1 ""', "sendtoaddress", PAYEE, 1, "")
send_case("sendtoaddress <payee> 1 null", "sendtoaddress", PAYEE, 1, None)
# sendmany's 3rd argument is the comment: Bitcoin's minconf there is a type
# error (rpcwallet.cpp:1722), as divid's own help example writes it
send_case('sendmany "" {payee: 1} 6 "testing" (minconf as Bitcoin has it)', "sendmany", "", {PAYEE: 1}, 6, "testing")
send_case('sendmany "" {payee: 1} "testing"', "sendmany", "", {PAYEE: 1}, "testing")
send_case('sendmany "" {"notanaddress": 1}', "sendmany", "", {"notanaddress": 1})
send_case('sendmany "" {payee: 1, "notanaddress": 2}', "sendmany", "", {PAYEE: 1, "notanaddress": 2})
got = {n.name: sent(n, raw_call(n, "sendmany", '["", {"%s": 1, "%s": 2}]' % (PAYEE, PAYEE))) for n in TWINS}
row("sendmany with the same address twice", got[C.name], got[I.name])
# receiver_pays on amounts near or below the fee (wallet.cpp:1653-1680, :1788-1793)
for value in (0.0001, 0.00008, 0.00006, 0.00002):
    send_case(f'sendtoaddress <payee> {value} "receiver_pays"', "sendtoaddress", PAYEE, value, "receiver_pays")

# --- imports ---------------------------------------------------------------------------
# Keys of S's, paid to before the twins know them
keys = {}
for name in ("watched", "first", "second"):
    a = S.rpc("getnewaddress")
    keys[name] = (a, S.rpc("dumpprivkey", a))
    S.rpc("sendtoaddress", a, 7)
mine(1)
# A watched address whose key comes later (wallet.cpp:604-608)
wa, wk = keys["watched"]
for n in TWINS:
    n.rpc("importaddress", wa, "watch", False)
both("importaddress <S's address> watch false, then validateaddress",
     lambda n: {k: n.rpc("validateaddress", wa).get(k) for k in ("ismine", "iswatchonly")})
both("importprivkey <its key> held false",
     lambda n: outcome(n.call("importprivkey", wk, "held", False)))
both("after importprivkey of the watched address: validateaddress",
     lambda n: {k: n.rpc("validateaddress", wa).get(k) for k in ("ismine", "iswatchonly", "account")})
both("after importprivkey of the watched address: getaddressesbyaccount watch, held",
     lambda n: [sorted(n.rpc("getaddressesbyaccount", "watch")), sorted(n.rpc("getaddressesbyaccount", "held"))])
# An import without a rescan, then one with: the rescan finds both (rpcdump.cpp:96-99)
(fa, fk), (sa, sk) = keys["first"], keys["second"]
balance = lambda n: amount(n.rpc("getbalance"))
before = {n.name: balance(n) for n in TWINS}
for n in TWINS:
    n.rpc("importprivkey", fk, "first", False)
both("importprivkey <first> first false: balance change",
     lambda n: round(balance(n) - before[n.name], 8))
for n in TWINS:
    n.rpc("importprivkey", sk, "second", True)
both("then importprivkey <second> second true: balance change",
     lambda n: round(balance(n) - before[n.name], 8))
both("then: the first key's coin listed",
     lambda n: any(u.get("address") == fa for u in n.rpc("listunspent")))
del keys, wk, fk, sk

# --- vaults ------------------------------------------------------------------------------
MANAGER = shared_address()
VAULT = f"{S.rpc('getnewaddress')}:{MANAGER}"
funding = S.rpc("fundvault", VAULT, 50)["txhash"]
if not seen(funding):
    raise RuntimeError("the vault funding did not reach the twins")
# Funding still in the mempool (rpcwallet.cpp:1280-1290)
both("addvault of an unconfirmed funding", lambda n: outcome(n.call("addvault", VAULT, funding)))
mine(1)
both("addvault of the same funding once mined", lambda n: outcome(n.call("addvault", VAULT, funding)))
# fundvault's object forms (rpcwallet.cpp:989-1036)
OWN_VAULT = f"{shared_address()}:{shared_address()}"
send_case("fundvault {<owner:manager>: 3}", "fundvault", {OWN_VAULT: 3})
send_case('fundvault {<owner:manager>: {"amount": 2, "repetitions": 2}}', "fundvault",
          {OWN_VAULT: {"amount": 2, "repetitions": 2}})
send_case('fundvault {<owner:manager>: {"amount": "x"}}', "fundvault", {OWN_VAULT: {"amount": "x"}})
send_case('fundvault {<owner:manager>: [1]}', "fundvault", {OWN_VAULT: [1]})

# --- encryption and unlocks ---------------------------------------------------------------
PASS = secrets.token_hex(12)
for n in TWINS:
    n.rpc("encryptwallet", PASS)
wait_for(lambda: all(n.rpc("getwalletinfo").get("encryption_status") == "locked" for n in TWINS), 30)
status = lambda n: n.rpc("getwalletinfo").get("encryption_status")
send_case("locked: sendmany", "sendmany", "", {PAYEE: 1})
for n in TWINS:
    n.rpc("walletpassphrase", PASS, 60, True)
send_case("staking only: sendmany", "sendmany", "", {PAYEE: 1})
for n in TWINS:
    n.rpc("walletlock")
    n.rpc("walletpassphrase", PASS, 60)
# Already fully unlocked: divid does not check the passphrase again (wallet.cpp:781-784)
both("fully unlocked: walletpassphrase <wrong> 60", lambda n: outcome(n.call("walletpassphrase", "wrong" + PASS, 60)))
both("then: encryption status", status)
both("fully unlocked: walletpassphrase <passphrase> 60 true", lambda n: outcome(n.call("walletpassphrase", PASS, 60, True)))
both("then: encryption status", status)
# walletpassphrasechange while unlocked (wallet.cpp:843-844)
for n in TWINS:
    n.rpc("walletlock")
    n.rpc("walletpassphrase", PASS, 60)
NEW = secrets.token_hex(12)
both("unlocked: walletpassphrasechange", lambda n: outcome(n.call("walletpassphrasechange", PASS, NEW)))
both("after the change: encryption status", status)
PASS = NEW
# timeout 0: never locks again (rpcserver.cpp:1206-1213)
for n in TWINS:
    n.rpc("walletlock")
both("walletpassphrase <passphrase> 0", lambda n: outcome(n.call("walletpassphrase", PASS, 0)))
time.sleep(3)
both("3 s after a timeout of 0: encryption status", status)
both("timeout 0: unlocked_until", lambda n: (lambda u: "absent" if u is None else "0" if u == 0 else "near now"
                                              if abs(u - time.time()) < 30 else u)(n.rpc("getwalletinfo").get("unlocked_until")))
# A second unlock replaces the first one's timer
for n in TWINS:
    n.rpc("walletlock")
    n.rpc("walletpassphrase", PASS, 2)
    n.rpc("walletpassphrase", PASS, 60)
time.sleep(4)
both("unlocked for 2 s, then for 60 s: status after 4 s", status)
# A staking-only unlock that runs out
for n in TWINS:
    n.rpc("walletlock")
    n.rpc("walletpassphrase", PASS, 2, True)
time.sleep(4)
both("unlocked for staking for 2 s: status after 4 s", status)
for n in TWINS:
    n.call("walletlock")

# --- restores from mnemonic= --------------------------------------------------------------
TIP = S.rpc("getblockcount")
words = S.rpc("dumphdinfo")["mnemonic"]
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


def restore(name, lines, view):
    got = {}
    for n in TWINS:
        c = copy_with(n, lines)
        before = set(os.listdir(c.dir)) | set(os.listdir(os.path.join(c.dir, "regtest")) if os.path.isdir(
            os.path.join(c.dir, "regtest")) else [])
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
        after = set(os.listdir(c.dir)) | set(os.listdir(os.path.join(c.dir, "regtest")) if os.path.isdir(
            os.path.join(c.dir, "regtest")) else [])
        g["a .moved wallet left"] = any(x.endswith(".moved") for x in after - before)
        got[n.name] = g
        shutil.rmtree(c.dir)
    for k in got[C.name].keys() | got[I.name].keys():
        row(f"{name}: {k}", got[C.name].get(k), got[I.name].get(k))


def restored_view(c):
    return {"the old savings address is mine": c.rpc("validateaddress", LABELLED).get("ismine"),
            "S's first address is mine": c.rpc("validateaddress", S_ADDRESS).get("ismine"),
            "balance > 0": amount(c.rpc("getbalance")) > 0}


# Words that fail their checksum (init.cpp:1204-1209, hdchain.cpp:63-65)
restore("mnemonic= with words that fail their checksum", ["mnemonic=" + " ".join(["abandon"] * 12)],
        restored_view)
# A wallet already there and mnemonic= (S's words): divid moves the wallet
# aside and makes a new one from the words (init.cpp:875-883, wallet.cpp:2300-2331)
restore("mnemonic=<other words> with a wallet already there", ["mnemonic=" + words], restored_view)
del words

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
