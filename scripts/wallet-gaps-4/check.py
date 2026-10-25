#!/usr/bin/env python3
"""Wallet rows of Divi Core divid that no other script compares and that run
on a plain regtest chain, next to irondivid: -prunewalletconfs, a send the
mempool refuses after the wallet has committed it, sendfrom from an account
named "comment" or "to", -upgradewallet for a new wallet, bip38decrypt of a
labelled key the wallet holds, bip38paperwallet's passphrase, and divid's log
lines for encryption, the key pool and address book at start, and
backupwallet.

S, a divid, mines and pays; C, a divid wallet; I, an irondivid restored from
C's phrase (WALLET_MNEMONIC), so the twins hold the same keys. Each case runs
on both and their outcomes are compared (replies, error codes and texts, the
wallet's state after, log lines), not timing. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Throwaway keys, phrases and passphrases are made in the run and go over RPC
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
INJECT = os.environ.get("WALLET_GAPS_4_INJECT", "")
HOST = "127.0.0.150"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
PRUNE_ORDER = ("divid's PruneWallet sorts the transactions from the coinbases, finds none in a wallet that does not "
               "mine, and goes on in txid order (wallet.cpp:1092-1133, :1185-1197). A sweep whose txid sorts below the "
               "funding it spends is then looked at first and dropped, though the funding is kept, so the swept coin "
               "counts as unspent again (B: listed without its sweep, the balance 10 higher, one more unspent coin, one fewer "
               "transaction in memory). "
               "irondivid looks at a transaction only after those it spends, so it keeps the sweep "
               "[on purpose: copying it would count a spent coin as spendable; docs/divid-differences.md W4]")
B_SWEEP = "B: its sweep (txid below)"
KNOWN = [
    (lambda n: n == "start with -prunewalletconfs=100: listed", PRUNE_ORDER,
     lambda c, i: B_SWEEP not in c and sorted(c + [B_SWEEP]) == i),
    (lambda n: n == "start with -prunewalletconfs=100: balance", PRUNE_ORDER,
     lambda c, i: c is not None and i is not None and round(c - i, 8) == 10),
    (lambda n: n == "start with -prunewalletconfs=100: unspent", PRUNE_ORDER, lambda c, i: c == i + 1),
    (lambda n: n == "start with -prunewalletconfs=100: log: pruned", PRUNE_ORDER, lambda c, i: pruned_one_more(c, i)),
]


def pruned_one_more(c, i):
    """The same "Original <n>", and divid's "Current" one less"""
    pattern = r"Original (\d+) vs\. Current (\d+)"
    if len(c) != 1 or len(i) != 1:
        return False
    mc, mi = re.search(pattern, c[0]), re.search(pattern, i[0])
    return bool(mc and mi) and mc.group(1) == mi.group(1) and int(mc.group(2)) + 1 == int(mi.group(2))

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if os.environ.get("WALLET_GAPS_4_WIDE") else text[:260]


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
            user = "wg4" + secrets.token_hex(4)
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
TWIN_CONF = ["listen=0", "vault=1"]
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


def seen(txid, nodes=None):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in (nodes or NODES)), 60)


def shared_address(label=""):
    a = C.rpc("getnewaddress", label)
    I.rpc("setaccount", a, label)
    if not I.rpc("validateaddress", a).get("ismine"):
        raise RuntimeError("the twins' keys parted")
    return a


mine(110)
for _ in range(6):
    S.rpc("sendtoaddress", shared_address(), 100)
mine(1)
PAYEE = S.rpc("getnewaddress")


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
            got.update({k: tx.get(k) for k in ("comment", "to", "FromAccount")})
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




def mark(n):
    """Where each of the node's logs ends now"""
    return {p: size(p) for p in n.logs()}


def since(n, at):
    """The node's log written after `at`"""
    text = ""
    for p in n.logs():
        try:
            with open(p, errors="replace") as f:
                f.seek(at.get(p, 0))
                text += f.read()
        except OSError:
            pass
    return text


def lines(text, pattern):
    """The lines of `text` matching `pattern`, without their time stamps"""
    return [m.group(0) for m in re.finditer(pattern, text)]


def only(n, keep):
    """Lock every coin of the twin but the outpoints in `keep`"""
    n.rpc("lockunspent", True)
    others = [{"txid": u["txid"], "vout": u["vout"]} for u in n.rpc("listunspent", 0)
              if (u["txid"], u["vout"]) not in keep]
    if others:
        n.rpc("lockunspent", False, others)


def restart(n, lines_=()):
    """Stop the twin and start it with `lines_` in place of the case lines of
    its divi.conf; ('up',) or ('exit', code)"""
    n.stop()
    path = os.path.join(n.dir, "divi.conf")
    kept = [l for l in open(path).read().split("\n") if l and not l.startswith(("prunewalletconfs=",))]
    with open(path, "w") as f:
        f.write("\n".join(kept + list(lines_)) + "\n")
    got = n.start()
    if got[0] == "up" and not synced():
        raise RuntimeError(f"{n.name} did not catch up")
    return got


def outpoint_of(txid, address, node=None):
    tx = (node or S).rpc("getrawtransaction", txid, 1)
    return next((txid, o["n"]) for o in tx["vout"] if address in o["scriptPubKey"].get("addresses", []))


# --- sendfrom from an account named "comment" or "to" ----------------------------------
# SendMoney erases the note named after the account, not FromAccount, so the
# account's name takes that note away (wallet.cpp:1915-1922, rpcwallet.cpp:1610-1646;
# divid's sendfrom takes no minconf)
# Each twin spends a coin of its own in each account (the twins share keys,
# and irondivid reckons an account by its coins), everything else locked
ACCOUNT_COINS = {}
for account in ("comment", "to", "shop"):
    for n in TWINS:
        a = shared_address(account)
        ACCOUNT_COINS[(n.name, account)] = (S.rpc("sendtoaddress", a, 10), a)
mine(1)
for account in ("comment", "to", "shop"):
    def lock_for(n, account=account):
        txid, a = ACCOUNT_COINS[(n.name, account)]
        only(n, {outpoint_of(txid, a)})
    send_case(f'sendfrom "{account}" <payee> 1 "a note" "a shop"', "sendfrom", account, PAYEE, 1, "a note", "a shop",
              notes=True, before=lock_for)
for n in TWINS:
    n.rpc("lockunspent", True)

# --- bip38 ---------------------------------------------------------------------------------
# bip38decrypt clears the label before it finds the key is held (rpcdump.cpp:329-336)
BIP_PASS = secrets.token_hex(8)
paper = S.rpc("bip38paperwallet", BIP_PASS)
for n in TWINS:
    n.rpc("bip38decrypt", paper["Encrypted Key"], BIP_PASS)
    n.rpc("setaccount", paper["Address"], "paper")
both("bip38decrypt <a held key labelled paper>",
     lambda n: outcome(n.call("bip38decrypt", paper["Encrypted Key"], BIP_PASS)))
both("then: getaccount of its address", lambda n: n.rpc("getaccount", paper["Address"]))
del paper, BIP_PASS
# bip38paperwallet takes any passphrase, the empty one too (rpcdump.cpp:262-288)
for text, passphrase in (('""', ""), ('"a b\\"c" (outside the listed set)', 'a b"c')):
    both(f"bip38paperwallet {text}", lambda n: (lambda o: {"ok": sorted(o[1])} if o[0] == "ok" else outcome(o))(
        n.call("bip38paperwallet", passphrase)))

# --- backupwallet's log line ---------------------------------------------------------------
# walletdb.cpp:619
for n in TWINS:
    dest = os.path.join(WORK, f"{n.name}-backup.dat")
    at = mark(n)
    n.rpc("backupwallet", dest)
    time.sleep(1)
    n.backup_line = f"copied wallet.dat to {dest}" in since(n, at)
row("backupwallet <file>: the log has divid's \"copied wallet.dat to <file>\"", C.backup_line, I.backup_line)

# --- a send the mempool refuses after the wallet committed it ------------------------------
# S pays a key of its own, then spends that coin in X, which every mempool
# holds. The twins import the key with a rescan, which reads blocks only, so
# the coin looks unspent to them; their send of it is committed to the
# wallet, then refused by their own mempool (rpcwallet.cpp:774-782,
# wallet.cpp:1866-1878, MempoolConsensus.cpp:296-305)
Q = S.rpc("getnewaddress")
q_key = S.rpc("dumpprivkey", Q)
k_txid = S.rpc("sendtoaddress", Q, 7)
mine(1)
K = outpoint_of(k_txid, Q)
raw = S.rpc("createrawtransaction", [{"txid": K[0], "vout": K[1]}], {S.rpc("getnewaddress"): 6.999})
X = S.rpc("sendrawtransaction", S.rpc("signrawtransaction", raw)["hex"])
if not seen(X):
    raise RuntimeError("X did not reach the twins")
PAYEE2 = S.rpc("getnewaddress")
before = {}
sends = {}
for n in TWINS:
    n.rpc("importprivkey", q_key, "q", True)
    before[n.name] = amount(n.rpc("getbalance"))
both("after importprivkey <the key> q true: the coin X spends is listed unspent",
     lambda n: any((u["txid"], u["vout"]) == K for u in n.rpc("listunspent", 0)))
del q_key
for n in TWINS:
    only(n, {K})
    out = n.call("sendtoaddress", PAYEE2, 1)
    n.rpc("lockunspent", True)
    mine_txs = [t for t in n.rpc("listtransactions", "*", 50) if t.get("category") == "send"
                and t.get("address") == PAYEE2]
    sends[n.name] = (out, mine_txs[-1]["txid"] if mine_txs else None)
row("sendtoaddress <payee> 1 spending that coin", outcome(sends[C.name][0]), outcome(sends[I.name][0]))
both("then: the send is in the wallet (listtransactions)", lambda n: sends[n.name][1] is not None)
both("then: balance change", lambda n: round(amount(n.rpc("getbalance")) - before[n.name], 8))
both("then: the coin is listed unspent", lambda n: any((u["txid"], u["vout"]) == K for u in n.rpc("listunspent", 0)))
both("then: the send's confirmations",
     lambda n: n.rpc("gettransaction", sends[n.name][1]).get("confirmations") if sends[n.name][1] else None)
both("then: the send is in the twin's mempool",
     lambda n: sends[n.name][1] in n.rpc("getrawmempool") if sends[n.name][1] else None)
for n in TWINS:
    if restart(n)[0] != "up":
        raise RuntimeError(f"{n.name} did not start again")
time.sleep(3)
both("after a restart: the send is in the twin's mempool",
     lambda n: sends[n.name][1] in n.rpc("getrawmempool") if sends[n.name][1] else None)
both("after a restart: balance change", lambda n: round(amount(n.rpc("getbalance")) - before[n.name], 8))
mine(1)
both("after X is mined: the send's confirmations",
     lambda n: n.rpc("gettransaction", sends[n.name][1]).get("confirmations") if sends[n.name][1] else None)
both("after X is mined: balance change", lambda n: round(amount(n.rpc("getbalance")) - before[n.name], 8))
both("after X is mined: the coin is listed unspent",
     lambda n: any((u["txid"], u["vout"]) == K for u in n.rpc("listunspent", 0)))

# --- -prunewalletconfs ---------------------------------------------------------------------
# At the start, a wallet transaction whose own outputs are all spent by a
# transaction with at least max(N, 20) confirmations, and whose inputs come
# from no transaction kept, is dropped from memory; the log says how many
# are left (wallet.cpp:900-920, :1162-1240; init.cpp:1574-1577, :1647-1653)
def sweep_with_order(funding_addr, low):
    """Fund `funding_addr` from S, then sweep its coin from C in a raw
    transaction whose txid sorts below the funding's (`low`) or above it,
    trying payees until it does. divid prunes in txid order when its sort
    finds no coinbase to start from (wallet.cpp:1092-1133, :1185-1188)"""
    f_txid = S.rpc("sendtoaddress", funding_addr, 10)
    mine(1)
    f = outpoint_of(f_txid, funding_addr)
    for _ in range(64):
        raw = C.rpc("createrawtransaction", [{"txid": f[0], "vout": f[1]}], {S.rpc("getnewaddress"): 9.999})
        signed = C.rpc("signrawtransaction", raw)
        if not signed.get("complete"):
            raise RuntimeError("C could not sign its sweep")
        txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed["hex"])).digest()).digest()[::-1].hex()
        if (txid < f_txid) == low:
            return f_txid, C.rpc("sendrawtransaction", signed["hex"])
    raise RuntimeError("no sweep txid in the order wanted")


# Pair A: the sweep's txid sorts above its funding's, so divid looks at the
# funding first; pair B: below it
p_txid, q_txid = sweep_with_order(shared_address(), low=False)
pb_txid, qb_txid = sweep_with_order(shared_address(), low=True)
for t in (q_txid, qb_txid):
    if not seen(t):
        raise RuntimeError("a sweep did not reach the others")
mine(25)
r_txid = S.rpc("sendtoaddress", shared_address(), 5)
mine(1)
WATCH = {"A: a funding, its coin swept 25 blocks back": p_txid, "A: its sweep (txid above)": q_txid,
         "B: a funding, its coin swept 25 blocks back": pb_txid, "B: its sweep (txid below)": qb_txid,
         "a funding left unspent": r_txid}
PRUNED = r"Pruned wallet transactions loaded to memory: Original \d+ vs\. Current \d+"
START_LINES = (r"Key Pool size = \d+", r"Address Book size = \d+")


def wallet_view(n):
    listed = {t.get("txid") for t in n.rpc("listtransactions", "*", 1000)}
    return {"listed": sorted(k for k, t in WATCH.items() if t in listed),
            "gettransaction of the funding": outcome(n.call("gettransaction", p_txid), lambda v: "ok"),
            "balance": amount(n.rpc("getbalance")),
            "unspent": len(n.rpc("listunspent", 0))}


for setting in ("20", "5", "100", None):
    name = f"-prunewalletconfs={setting}" if setting else "no -prunewalletconfs"
    got = {}
    for n in TWINS:
        at = mark(n)
        started = restart(n, [f"prunewalletconfs={setting}"] if setting else [])
        time.sleep(2)
        log = since(n, at)
        got[n.name] = {"start": started, "log: pruned": lines(log, PRUNED), **wallet_view(n),
                       **{f"log: {p.split(' =')[0]}": bool(re.search(p, log)) for p in START_LINES}}
    for k in got[C.name]:
        row(f"start with {name}: {k}", got[C.name][k], got[I.name][k])

# --- encryption's log lines ----------------------------------------------------------------
# wallet.cpp:949, :836: the iterations are timed, so only the text is compared
PASS = secrets.token_hex(12)
NEW = secrets.token_hex(12)
for n in TWINS:
    at = mark(n)
    n.rpc("encryptwallet", PASS)
    wait_for(lambda: n.rpc("getwalletinfo").get("encryption_status") == "locked", 30)
    n.rpc("walletpassphrase", PASS, 60)
    n.rpc("walletpassphrasechange", PASS, NEW)
    time.sleep(1)
    log = since(n, at)
    n.crypt_lines = [bool(re.search(r"Encrypting Wallet with an nDeriveIterations of \d+", log)),
                     bool(re.search(r"Wallet passphrase changed to an nDeriveIterations of \d+", log))]
row("encryptwallet: the log has \"Encrypting Wallet with an nDeriveIterations of <n>\"", C.crypt_lines[0],
    I.crypt_lines[0])
row("walletpassphrasechange: the log has \"Wallet passphrase changed to an nDeriveIterations of <n>\"",
    C.crypt_lines[1], I.crypt_lines[1])
del PASS, NEW

# --- -upgradewallet for a new wallet -------------------------------------------------------
# A new wallet gets the latest version only when -upgradewallet is absent or
# is the client version; below the base version it stops the load
# (wallet.cpp:854-887, :1963-1979, :2336)
for n in NODES:
    n.stop()
copies = 0


def fresh_copy(n, lines_):
    """A copy of the twin's datadir with no wallet and `lines_` in its divi.conf"""
    global copies
    copies += 1
    dest = os.path.join(WORK, f"{n.name}-new{copies}")
    shutil.copytree(n.dir, dest)
    for d in (dest, os.path.join(dest, "regtest")):
        for w in ("wallet.dat", "wallet"):
            p = os.path.join(d, w)
            if os.path.isdir(p):
                shutil.rmtree(p)
            elif os.path.exists(p):
                os.remove(p)
    path = os.path.join(dest, "divi.conf")
    kept = [l for l in open(path).read().split("\n") if l and not l.startswith(("connect=", "prunewalletconfs="))]
    with open(path, "w") as f:
        f.write("\n".join(kept + ["connect=0"] + lines_) + "\n")
    return Node(f"{n.name}-new{copies}", n.binary, 1 if n is C else 2, datadir=dest)


for value in (None, "10499", "10500", "61000", "120200", "3000000", "3000001"):
    got = {}
    for n in TWINS:
        c = fresh_copy(n, [f"upgradewallet={value}"] if value else [])
        out = c.start()
        if out[0] == "up":
            g = {"start": "up", "walletversion": c.rpc("getwalletinfo").get("walletversion")}
            c.rpc("encryptwallet", secrets.token_hex(8))
            wait_for(lambda: c.rpc("getwalletinfo").get("encryption_status") == "locked", 30)
            g["walletversion after encryptwallet"] = c.rpc("getwalletinfo").get("walletversion")
            c.stop()
        else:
            err = next((l.strip() for l in open(c.out, errors="replace") if l.startswith("Error")), "")
            g = {"start": "exit", "exit code": out[1], "error line": err}
        got[n.name] = g
        shutil.rmtree(c.dir)
    name = f"-upgradewallet={value}" if value else "no -upgradewallet"
    for k in sorted(got[C.name].keys() | got[I.name].keys()):
        row(f"a new wallet with {name}: {k}", got[C.name].get(k), got[I.name].get(k))

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
