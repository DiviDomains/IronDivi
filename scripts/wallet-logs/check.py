#!/usr/bin/env python3
"""The wallet's log lines of Divi Core divid next to irondivid's, on a plain
regtest chain: the keypool lines (a key added, reserved, kept and returned),
LoadWallet's counts at start, CommitTransaction's dump of the transaction it
commits, and "Relaying wtx" when the wallet relays its own send.

S, a divid, mines and pays; C, a divid wallet; I, an irondivid wallet. The
two wallets are new and their own (the keypool numbers follow what each
wallet has done, so they share no keys), and each step runs on both in the
same order. Each row prints PASS (same as divid), KNOWN (a difference listed
in README.md) or FAIL. Exit code = FAILs.

The passphrase is random and goes over RPC; no key, phrase or passphrase is
printed or put on a command line.
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
INJECT = os.environ.get("WALLET_LOGS_INJECT", "")
HOST = "127.0.0.150"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
KNOWN = []

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if os.environ.get("WALLET_LOGS_WIDE") else text[:260]


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
            user = "wl" + secrets.token_hex(4)
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


def settled(n, at, secs=3):
    """The log since `at`, once it has stopped growing (it is written behind
    the calls)"""
    last, still = None, 0
    deadline = time.time() + 30
    while time.time() < deadline:
        text = since(n, at)
        still = still + 1 if text == last else 0
        if still >= secs * 4:
            break
        last = text
        time.sleep(0.25)
    return since(n, at)


KEYPOOL = re.compile(r"keypool (?:added key -?\d+, size=\d+, internal=\d|reserve -?\d+|keep -?\d+|return -?\d+)")
NEWPOOL = "CWallet::NewKeyPool rewrote keypool"
FILEVERSION = re.compile(r"nFileVersion = \d+")
KEYS = re.compile(r"Keys: \d+ plaintext, \d+ encrypted, \d+ w/ metadata, \d+ total")
LACK = "Some keys lack metadata. Wallet may require a rescan"


def keypool(text):
    """The keypool lines, in order; a long run of "added" is summed up"""
    found = KEYPOOL.findall(text)
    added = [l for l in found if l.startswith("keypool added")]
    if len(added) > 6:
        return {"added": len(added), "first": added[:2], "last": added[-2:],
                "others": [l for l in found if not l.startswith("keypool added")]}
    return found


def load_lines(text):
    return {"nFileVersion": FILEVERSION.findall(text), "Keys": KEYS.findall(text), "lack metadata": LACK in text}


# --- the wallets ---------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}"])
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}"])
TWINS = (C, I)
first = {}
for n in TWINS:
    at = mark(n)
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
    first[n.name] = settled(n, at)
NODES = [S, C, I]
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
row("a new wallet's first start: keypool lines", keypool(first[C.name]), keypool(first[I.name]))
for k, v in load_lines(first[C.name]).items():
    row(f"a new wallet's first start: LoadWallet {k}", v, load_lines(first[I.name])[k])
both("then: getwalletinfo keypoolsize", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))


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


def step(name, fn):
    """Run `fn` on each wallet and compare the keypool lines it logged; the
    values `fn` returns go back by node"""
    got, logs = {}, {}
    for n in TWINS:
        at = mark(n)
        got[n.name] = fn(n)
        logs[n.name] = settled(n, at)
    row(f"{name}: keypool lines", keypool(logs[C.name]), keypool(logs[I.name]))
    return got, logs


step("getnewaddress", lambda n: n.rpc("getnewaddress"))
step("getnewaddress again", lambda n: n.rpc("getnewaddress"))
step("getrawchangeaddress", lambda n: n.rpc("getrawchangeaddress"))
step("getaccountaddress acct", lambda n: n.rpc("getaccountaddress", "acct"))
step("getaccountaddress acct again (the same address)", lambda n: n.rpc("getaccountaddress", "acct"))

mine(110)
funded = {}
for n in TWINS:
    a, b = n.rpc("getnewaddress"), n.rpc("getnewaddress")
    funded[n.name] = (S.rpc("sendtoaddress", a, 10), a, S.rpc("sendtoaddress", b, 20), b)
mine(2)
PAYEE = S.rpc("getnewaddress")
# The payee's script as CScript::ToString writes it, cut at 30 (primitives/transaction.cpp:117)
PAYEE_ASM = ("OP_DUP OP_HASH160 " + b58decode(PAYEE)[1:].hex())[:30]

DUMP_HEAD = re.compile(r"CommitTransaction:\s*\n?.*?CTransaction\((\w{10}), ver=(\d+), vin\.size=(\d+), vout\.size=(\d+), "
                       r"nLockTime=(\d+)\)")
# COutPoint::ToString gives the whole hash (OutPoint.cpp:29-32)
DUMP_IN = re.compile(r"^\s+CTxIn\(COutPoint\((\w{64}), (\d+)\), scriptSig=([^,)]*)(?:, nSequence=(\d+))?\)\s*$", re.M)
DUMP_OUT = re.compile(r"^\s+CTxOut\(nValue=(\d+\.\d{8}), scriptPubKey=([^)]{0,30})\)\s*$", re.M)
RELAY = re.compile(r"(\w{10}): Relaying wtx SendMoney")


def dump(text, txid):
    """CommitTransaction's dump, its txid-dependent parts checked against
    `txid` and the funding, the rest as written"""
    m = DUMP_HEAD.search(text)
    if not m:
        return None
    rest = text[m.end():]
    cut = re.search(r"^\S", rest, re.M)
    body = rest[:cut.start()] if cut else rest
    return {"hash is the send's": m.group(1) == txid[:10], "ver": m.group(2), "vin.size": m.group(3),
            "vout.size": m.group(4), "nLockTime": m.group(5),
            # (spends the funding coin, scriptSig's length as cut, nSequence); the coin's
            # index is where S's send put it, so it is checked, not compared
            "vin": sorted(((p, int(v)) == current_funding, len(sig), seq) for p, v, sig, seq in DUMP_IN.findall(body)),
            "vout": sorted((v, sc if sc == PAYEE_ASM else "<own>") for v, sc in DUMP_OUT.findall(body))}


def relay(text, txid):
    return [m == txid[:10] for m in RELAY.findall(text)]


def send(name, fn, keep):
    """A send from the funding coin `keep` (the other coin locked): its keypool
    lines, its dump and its relay line"""
    global current_funding
    out = {}
    for n in TWINS:
        f10, a10, f20, a20 = funded[n.name]
        use = (f10, a10) if keep == 10 else (f20, a20)
        n.rpc("lockunspent", True)
        coins = n.rpc("listunspent", 0)
        current_funding = next(((u["txid"], u["vout"]) for u in coins
                                if u["txid"] == use[0] and u.get("address") == use[1]), None)
        others = [{"txid": u["txid"], "vout": u["vout"]} for u in coins
                  if not (u["txid"] == use[0] and u.get("address") == use[1])]
        if others:
            n.rpc("lockunspent", False, others)
        at = mark(n)
        reply = n.call(*fn)
        log = settled(n, at)
        n.rpc("lockunspent", True)
        txid = reply[1] if reply[0] == "ok" else ""
        out[n.name] = {"reply": "txid" if txid else outcome(reply), "keypool": keypool(log),
                       "dump": dump(log, txid) if txid else None, "relay": relay(log, txid) if txid else None}
    for k in out[C.name]:
        row(f"{name}: {k}", out[C.name][k], out[I.name][k])
    mine(1)


current_funding = None
send("sendtoaddress <payee> 1 from the coin of 10 (with change)", ("sendtoaddress", PAYEE, 1), 10)
send('sendtoaddress <payee> 1 "sweep_funds" from the coin of 20 (no change)', ("sendtoaddress", PAYEE, 1, "sweep_funds"), 20)

step("keypoolrefill 1003", lambda n: n.rpc("keypoolrefill", 1003))
both("then: getwalletinfo keypoolsize", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))

# A restart: LoadWallet's counts of a wallet that is there
got = {}
for n in TWINS:
    n.stop()
    at = mark(n)
    n.start()
    got[n.name] = settled(n, at)
if not synced():
    raise RuntimeError("the twins did not catch up")
row("a restart: keypool lines", keypool(got[C.name]), keypool(got[I.name]))
for k, v in load_lines(got[C.name]).items():
    row(f"a restart: LoadWallet {k}", v, load_lines(got[I.name])[k])

# encryptwallet makes a new keypool (wallet.cpp:976-1000, :2032-2054)
PASS = secrets.token_hex(12)
got, _ = step("encryptwallet", lambda n: n.call("encryptwallet", PASS))
for n in TWINS:
    wait_for(lambda: n.rpc("getwalletinfo").get("encryption_status") == "locked", 30)
both("then: getwalletinfo keypoolsize", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))
step("locked: getnewaddress", lambda n: n.rpc("getnewaddress"))
step("locked: getrawchangeaddress", lambda n: n.rpc("getrawchangeaddress"))
got = {}
for n in TWINS:
    n.stop()
    at = mark(n)
    n.start()
    got[n.name] = settled(n, at)
row("an encrypted wallet's restart: keypool lines", keypool(got[C.name]), keypool(got[I.name]))
for k, v in load_lines(got[C.name]).items():
    row(f"an encrypted wallet's restart: LoadWallet {k}", v, load_lines(got[I.name])[k])
step("unlocked: getnewaddress", lambda n: (n.rpc("walletpassphrase", PASS, 60), n.rpc("getnewaddress")))
del PASS

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
