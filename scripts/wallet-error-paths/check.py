#!/usr/bin/env python3
"""Wallet error replies next to Divi Core divid: keypoolrefill sizes that
json_spirit's get_int folds into another int, bip38paperwallet's argument and
lock checks, and sends that fail once the wallet has started to build them.
After each, whether the wallet changed: its key pool size and its addresses.

divid mines a short regtest chain; irondivid, restored from divid's phrase,
follows it, so both wallets hold the same keys and coins. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrase and the passphrase live only in memory, in RPC requests and replies and
in irondivid's environment; they are never printed or put on a command line.
No key is printed: an address or an encrypted key shows as its form only.
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
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("WALLET_ERROR_PATHS_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 300
START_TIMEOUT = 180

# Differences irondivid has on purpose, by row name, each listed in README.md
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word, note = ("FAIL", "  [listed as KNOWN but now matches divid: update README.md]") if same \
            else ("KNOWN", "  [known: " + reason + "]")
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


def setup_failed(kind, value, tb):
    print(f"FAIL   set-up: {kind.__name__}: {value}"[:300], flush=True)
    print("FAILS 1", flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"wep{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=wep{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        # SIGXFSZ ignored, as in scripts/disk-errors: once section 3b lowers the
        # file size limit, a write past it fails with EFBIG instead of ending the node
        script = "trap '' XFSZ; exec \"$0\" \"$@\""
        self.proc = subprocess.Popen(["bash", "-c", script, self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     env=env, stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (OSError, ValueError) as e:
            return ("err", "no reply", type(e).__name__)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:100]}")
        return out[1]

    def limit(self, soft):
        """The soft file size limit of the running node, in bytes or 'unlimited'"""
        subprocess.run(["prlimit", f"--pid={self.proc.pid}", f"--fsize={soft}:unlimited"], check=True)

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            if self.call("getblockcount")[0] == "ok":
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


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


# --- how replies are compared ---------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ADDRESS = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{26,35}$")


def b58check_form(text):
    """(version byte, payload length) of a base58check string, or None"""
    n = 0
    for ch in text:
        if ch not in B58:
            return None
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        return None
    return body[0], len(body) - 1


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def form(v):
    """A value as compared: an address or encrypted key by its form, a dict
    member by member, the rest as it is"""
    if isinstance(v, dict):
        return {k: form(x) for k, x in v.items()}
    if isinstance(v, str) and ADDRESS.match(v) and b58check_form(v):
        f = b58check_form(v)
        return f"<base58check version {f[0]}, {f[1]} bytes>"
    if isinstance(v, str) and v.startswith("6P") and b58check_form(v):
        f = b58check_form(v)
        return f"<BIP38 key, {f[1] + 1} bytes>"
    return v


def view(out):
    if out[0] == "err":
        message = str(out[2])
        return ("err", out[1], message.split("\n", 1)[0])
    return ("ok", form(out[1]))


def show(v):
    if v[0] == "err":
        return f"error {v[1]} \"{v[2][:110]}\""
    return json.dumps(v[1])[:160]


def compare(name, core, iron):
    if INJECT and INJECT == name:
        iron = ("ok", "injected") if iron[0] == "ok" else iron[:2] + (str(iron[2]) + " injected",)
    a, b = view(core), view(iron)
    row(name, show(a), show(b), a == b)


def both(name, method, *params):
    compare(name, C.call(method, *params), I.call(method, *params))


def wallet_state(name):
    """Whether the wallet changed: getwalletinfo keypoolsize, and how many
    addresses the default account holds"""
    def pick(n):
        info = n.call("getwalletinfo")
        held = n.call("getaddressesbyaccount", "")
        size = info[1].get("keypoolsize") if info[0] == "ok" and isinstance(info[1], dict) else info
        count = len(held[1]) if held[0] == "ok" else held
        return ("ok", {"keypoolsize": size, "addresses": count})
    compare(f"{name}: keypoolsize and addresses", pick(C), pick(I))


# --- the pair ------------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    raise RuntimeError("divid did not answer")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect={HOST}:{C.p2p}"], env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    raise RuntimeError("irondivid did not answer")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
while C.rpc("getblockcount") < 110:
    if C.call("setgenerate", 1)[0] != "ok":
        time.sleep(1)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 180):
    raise RuntimeError("irondivid did not follow divid's chain")
if not wait_for(lambda: I.rpc("getbalance") == C.rpc("getbalance"), 120):
    raise RuntimeError("the two wallets do not hold the same coins")
wallet_state("start")

# --- 1. keypoolrefill sizes folded by get_int (rpcwallet.cpp:2556-2566) ------------------
# json_spirit's get_int takes the low 32 bits of an integer as a C++ int: a size
# from 2^31 up turns negative ("Invalid parameter, expected valid size."), 2^32
# is 0 (the -keypool default) and 2^32 + 1 is 1
for size in (2147483648, 3000000000, 4294967296, 4294967297, -4294967295, 6442450944):
    both(f"keypoolrefill {size}", "keypoolrefill", size)
    wallet_state(f"after keypoolrefill {size}")

# --- 2. bip38paperwallet (rpcdump.cpp:249-292) --------------------------------------
# Its "Invalid key" is for a fresh key whose public key is not valid, which
# CKey::MakeNewKey never gives: no call reaches it (see README.md)
both("bip38paperwallet (no argument)", "bip38paperwallet")
both("bip38paperwallet <passphrase> <extra>", "bip38paperwallet", secrets.token_urlsafe(12), "x")
both("bip38paperwallet 5 (not a string)", "bip38paperwallet", 5)
both("bip38paperwallet <passphrase>", "bip38paperwallet", secrets.token_urlsafe(12))
both("bip38paperwallet \"\" (an empty passphrase)", "bip38paperwallet", "")
wallet_state("after bip38paperwallet")

# --- 3. sends that fail once the wallet has started to build them -------------------
# divid reserves a change key before it signs and checks the transaction, and
# returns it when the send fails (wallet.cpp:1786-1816, CReserveKey); the
# wallet is left as it was
# The payees are addresses of no wallet: random key hashes with the network's
# P2PKH version byte (from one new address of each wallet, the same key on both)
both("getnewaddress", "getnewaddress")
version = b58check_form(C.rpc("getaddressesbyaccount", "")[0])[0]
payees = {b58check(bytes([version]) + secrets.token_bytes(20)): 0.01 for _ in range(3000)}
wallet_state("after getnewaddress")
both("sendmany \"\" of 3000 outputs (Transaction too large)", "sendmany", "", payees)
wallet_state("after the sendmany that is too large")
both("sendtoaddress of more than the balance", "sendtoaddress", next(iter(payees)), 10 ** 7)
wallet_state("after the sendtoaddress of more than the balance")
# A payment whose fee the receiver pays and that the fee would leave as dust:
# divid fails it after it has reserved the change key ("Cannot subtract needed
# fees from outputs.", wallet.cpp:1786-1793), which tops the key pool up
# (wallet.cpp:2129-2130); a new address first leaves the pool one short
both("getnewaddress (the pool one short)", "getnewaddress")
wallet_state("after getnewaddress (the pool one short)")
both("sendtoaddress 0.00006 receiver_pays (the fee leaves dust)", "sendtoaddress", next(iter(payees)), 0.00006,
     "receiver_pays")
wallet_state("after the receiver_pays send that fails")

# --- 3b. the same while the wallet's writes fail ------------------------------------
# Each node's soft file size limit is lowered to one byte while it runs
# (prlimit; scripts/wallet-write-failures), so its wallet writes fail and
# nothing else is written. The change key of a send that fails goes back to
# the key pool in memory (CReserveKey::ReturnKey, reservekey.cpp:44-51), which
# writes nothing; a key the pool must derive cannot be written. Each step is
# followed by the key pool size, the default account's address count, and
# whether the next change key is the same on both wallets.
def writes_fail():
    for n in (C, I):
        n.limit(1)


def writes_work():
    for n in (C, I):
        n.limit("unlimited")


def next_change(name):
    """getrawchangeaddress on both: the same key, since both wallets come from one phrase"""
    c, i = C.call("getrawchangeaddress"), I.call("getrawchangeaddress")
    same = c[0] == i[0] == "ok" and c[1] == i[1]
    row(f"{name}: the next change key is the same on both", "ok" if c[0] == "ok" else show(view(c)),
        "same" if same else ("another" if i[0] == "ok" else show(view(i))), same or (c[0] != "ok" and c == i))


# With the key pool full, the change key comes from the pool and nothing is
# derived: the failed send gives it back in memory (ReturnKey) and the pool is
# full again. With it one short, the reservation must derive a key, and its
# write fails first: -1 "loadHDChain: WriteHDChain failed" (wallet.cpp:2339-2347)
both("keypoolrefill (the pool full)", "keypoolrefill")
wallet_state("before the writes fail, the pool full")
for pool in ("the pool full", "the pool one short"):
    writes_fail()
    both(f"sendmany \"\" of 3000 outputs, writes failing, {pool}", "sendmany", "", payees)
    wallet_state(f"after the sendmany that is too large, writes failing, {pool}")
    both(f"sendtoaddress 0.00006 receiver_pays, writes failing, {pool}", "sendtoaddress", next(iter(payees)),
         0.00006, "receiver_pays")
    wallet_state(f"after the receiver_pays send that fails, writes failing, {pool}")
    writes_work()
    wallet_state(f"once writes work again, after the failed sends, {pool}")
    # getrawchangeaddress takes the next change key: the pool is one short after it
    next_change(f"once writes work again, after the failed sends, {pool}")
# A key pool one short (getrawchangeaddress took a change key and getnewaddress
# a receiving one): keypoolrefill must derive keys, and writing them fails,
# -1 "TopUpKeyPool: writing generated key failed" (wallet.cpp:2104-2105)
both("getnewaddress (the pool one short again)", "getnewaddress")
writes_fail()
both("keypoolrefill, writes failing (the pool one short)", "keypoolrefill")
wallet_state("after keypoolrefill, writes failing")
writes_work()
both("keypoolrefill once writes work again", "keypoolrefill")
wallet_state("after keypoolrefill once writes work again")
next_change("after keypoolrefill once writes work again")

# A restart: what is on disk. irondivid starts without the phrase, which would
# move the wallet it has aside (init.cpp:864-888)
for n in (I, C):
    n.stop()
I.env = None
for n in (C, I):
    n.start()
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not answer after the restart")
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 180):
    raise RuntimeError("irondivid did not follow divid's chain after the restart")
wallet_state("after a restart")
next_change("after a restart")

# --- 4. the same with the wallet encrypted -------------------------------------------
PASS = secrets.token_urlsafe(18)
for n in (C, I):
    n.call("encryptwallet", PASS)
for n in (C, I):
    if n.proc.poll() is not None:
        n.log.close()
        n.start()
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not answer after encryptwallet")
wallet_state("encrypted, locked")
target = next(iter(payees))
both("locked: bip38paperwallet <passphrase>", "bip38paperwallet", secrets.token_urlsafe(12))
both("locked: sendtoaddress 1", "sendtoaddress", target, 1)
both("locked: sendmany \"\" of 1 output", "sendmany", "", {target: 1})
both("locked: keypoolrefill 4294967297", "keypoolrefill", 4294967297)
wallet_state("locked: after the refused calls")
both("walletpassphrase <passphrase> 60 true (staking only)", "walletpassphrase", PASS, 60, True)
both("staking only: bip38paperwallet <passphrase>", "bip38paperwallet", secrets.token_urlsafe(12))
both("staking only: sendtoaddress 1", "sendtoaddress", target, 1)
both("staking only: keypoolrefill 4294967297", "keypoolrefill", 4294967297)
wallet_state("staking only: after the refused calls")
both("walletlock", "walletlock")
both("walletpassphrase <passphrase> 60", "walletpassphrase", PASS, 60)
del PASS
both("unlocked: bip38paperwallet <passphrase>", "bip38paperwallet", secrets.token_urlsafe(12))
wallet_state("unlocked: after bip38paperwallet")
both("unlocked: keypoolrefill 4294967296", "keypoolrefill", 4294967296)
wallet_state("unlocked: after keypoolrefill 4294967296")
both("walletlock again", "walletlock")

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
