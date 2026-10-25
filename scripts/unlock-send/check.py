#!/usr/bin/env python3
"""Wallet encryption, unlock (full and staking-only), lock and send refusals,
run step by step on a fresh Divi Core divid and a fresh irondivid side by side.
Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
Passphrases exist only in memory and in RPC request bodies; they are never
printed or passed on a command line.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row runs differently on irondivid
INJECT = os.environ.get("UNLOCK_SEND_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose or has not closed yet, one per row name.
# Each is listed in README.md with divid's source line; a KNOWN row that starts
# to match divid is a FAIL, so the list stays true.
KNOWN = {
}

fails = 0


def row(name, core, iron, same):
    """same: True when the two outcomes count as equal for this row"""
    global fails
    if name in KNOWN:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + KNOWN[name] + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name = name
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"unlock{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=unlock{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(WORK, name + ".out"), "w")
        self.proc = subprocess.Popen([binary, f"-datadir={self.dir}"], cwd=self.dir,
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
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
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


# --- how outcomes are compared ---------------------------------------------------

def show(out, kind):
    """One short text for an outcome; never the value of a key, seed or passphrase"""
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\""
    v = out[1]
    if kind == "null":
        return "null" if v is None else "ok"
    if kind == "txid":
        return "txid" if isinstance(v, str) and len(v) == 64 else f"ok {type(v).__name__}"
    if kind == "unlock":
        return unlock_fields(v)
    if kind == "staking":
        return f"walletunlocked={v.get('walletunlocked')}" if isinstance(v, dict) else "ok"
    return "ok"


def unlock_fields(info):
    if not isinstance(info, dict):
        return "ok"
    u = info.get("unlocked_until", "absent")
    if u != "absent":
        u = "0" if u == 0 else ">0" if isinstance(u, int) and u > 0 else repr(u)
    return f"unlocked_until={u} encryption_status={info.get('encryption_status', 'absent')}"


def compare(name, core, iron, kind="ok", message=True):
    """Same outcome (ok/error), same error code, and the same message when
    divid's is a fixed text (message=True)"""
    a, b = show(core, kind), show(iron, kind)
    if core[0] == "err" and iron[0] == "err":
        same = core[1] == iron[1] and (not message or core[2] == iron[2])
    else:
        same = a == b
    row(name, a, b, same)


def both(name, method, *params, kind="ok", message=True, iron_params=None):
    c = C.call(method, *params)
    i = I.call(method, *(params if iron_params is None else iron_params))
    compare(name, c, i, kind, message)
    return c, i


# --- a mainnet address nobody holds a key for ------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


# mainnet P2PKH version 30; the 20 bytes are random, so no key exists for it
MAINNET_ADDR = b58check(bytes([30]) + secrets.token_bytes(20))


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


def raw_spend(node, dest):
    """An unsigned transaction spending one of the node's coins (no key needed)"""
    u = max(node.rpc("listunspent"), key=lambda x: x["amount"])
    return node.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]}], {dest: 1})


# --- the run ---------------------------------------------------------------------

def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"])
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)

# Coins for both: divid mines past maturity and pays irondivid
C.rpc("setgenerate", 30)
if not wait_for(lambda: I.rpc("getblockcount") == C.rpc("getblockcount"), 60):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
c_addr, i_addr = C.rpc("getnewaddress"), I.rpc("getnewaddress")
# Four confirmed coins each side, so no send has to wait for change: neither spends
# unconfirmed change by default (divid -spendzeroconfchange=0, wallet.cpp:1848)
for _ in range(4):
    C.rpc("sendtoaddress", i_addr, 1000)
C.rpc("setgenerate", 1)
if not wait_for(lambda: I.rpc("getbalance") >= 4000, 60):
    print("FAIL   setup: irondivid did not receive its coins", flush=True)
    sys.exit(1)
# Each sends to the other; a raw spend of each one's own coin for the sign rows
C.dest, I.dest = i_addr, c_addr
C.mine, I.mine = c_addr, i_addr
c_raw, i_raw = raw_spend(C, i_addr), raw_spend(I, c_addr)

pw, pw2, wrong = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)


def send(name, amount=10, dest=None, kind="txid", message=True):
    c = C.call("sendtoaddress", dest or C.dest, amount)
    i = I.call("sendtoaddress", dest or I.dest, amount)
    compare(name, c, i, kind, message)


def mine_dumps(name):
    """dumpprivkey, signmessage, dumphdinfo, signrawtransaction for the state at hand"""
    compare(f"{name}: dumpprivkey", C.call("dumpprivkey", C.mine), I.call("dumpprivkey", I.mine))
    compare(f"{name}: signmessage", C.call("signmessage", C.mine, "unlock-send"), I.call("signmessage", I.mine, "unlock-send"))
    compare(f"{name}: dumphdinfo", C.call("dumphdinfo"), I.call("dumphdinfo"))
    compare(f"{name}: signrawtransaction", C.call("signrawtransaction", c_raw), I.call("signrawtransaction", i_raw))


def states(name):
    both(f"{name}: getwalletinfo", "getwalletinfo", kind="unlock")
    both(f"{name}: getstakingstatus", "getstakingstatus", kind="staking")


# Unencrypted
states("unencrypted")
both("unencrypted: walletlock", "walletlock", kind="null")
both("unencrypted: walletpassphrase", "walletpassphrase", pw, 60, kind="null")
both("unencrypted: walletpassphrasechange", "walletpassphrasechange", pw, pw2, kind="null")

# encryptwallet: divid reloads the wallet and keeps running (rpcwallet.cpp:2722-2723)
c, i = C.call("encryptwallet", pw), I.call("encryptwallet", pw)
row("encryptwallet", show(c, "ok"), show(i, "ok"), c[0] == i[0] == "ok")
for n in (C, I):
    wait_for(lambda: n.call("getwalletinfo")[0] == "ok", 60)
both("encryptwallet again", "encryptwallet", pw, kind="null")

# Locked
states("locked")
send("locked: sendtoaddress")
mine_dumps("locked")
both("locked: getnewaddress", "getnewaddress")
both("locked: walletlock", "walletlock", kind="null")
both("wrong passphrase", "walletpassphrase", wrong, 60, kind="null",
     iron_params=(pw, 60) if INJECT == "wrong-passphrase" else None)
I.call("walletlock")

# Staking only
both("walletpassphrase staking-only", "walletpassphrase", pw, 300, True, kind="null")
states("staking-only")
send("staking-only: sendtoaddress")
mine_dumps("staking-only")
both("staking-only: walletpassphrase staking-only again", "walletpassphrase", pw, 300, True, kind="null")

# Full unlock, from staking-only
both("walletpassphrase full", "walletpassphrase", pw, 300, kind="null")
states("unlocked")
send("unlocked: sendtoaddress")
mine_dumps("unlocked")
send("dust send 0.00001", 0.00001)
send("send to a mainnet address", 1, dest=MAINNET_ADDR)
send("send above balance", 100000000, message=False)
send("send of 0", 0)

# Unlock timeout expiry from locked: back to locked
both("walletlock", "walletlock", kind="null")
states("after walletlock")
both("walletpassphrase 2 s", "walletpassphrase", pw, 2, kind="null")
time.sleep(4)
states("2 s expired")
send("2 s expired: sendtoaddress")

# Unlock timeout expiry from staking-only: back to staking-only (rpcwallet.cpp:2613, rpcserver.cpp:1168)
both("walletpassphrase staking-only (before a 2 s unlock)", "walletpassphrase", pw, 300, True, kind="null")
both("walletpassphrase 2 s from staking-only", "walletpassphrase", pw, 2, kind="null")
time.sleep(4)
states("2 s expired from staking-only")
send("2 s expired from staking-only: sendtoaddress")

# walletpassphrasechange
both("walletlock before change", "walletlock", kind="null")
both("walletpassphrasechange wrong old", "walletpassphrasechange", wrong, pw2, kind="null")
both("walletpassphrasechange", "walletpassphrasechange", pw, pw2, kind="null")
both("old passphrase after change", "walletpassphrase", pw, 60, kind="null")
both("new passphrase after change", "walletpassphrase", pw2, 60, kind="null")
send("new passphrase: sendtoaddress")
both("walletlock at the end", "walletlock", kind="null")
states("locked at the end")

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
