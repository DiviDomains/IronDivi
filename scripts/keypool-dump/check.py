#!/usr/bin/env python3
"""The key pool and the wallet dump files of Divi Core divid and irondivid,
compared call by call.

Each step starts a fresh divid and a fresh irondivid wallet with the same
options (-keypool unset, 0, 1, 3, 2000), makes the same calls on both and
compares the replies: the pool size after each, the addresses' shape (each
wallet has its own keys, so an address is compared by its form only) and the
errors. The 3-key step encrypts both wallets and takes keys while locked,
unlocked for staking only and unlocked. Divi Core 3.0.0 has no dumpwallet or
importwallet; the rows check that both refuse them alike and write no file.
Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
passphrase is made by this run, lives only in memory and in RPC requests, and
is never printed, logged, written to a file or put on a command line. No key is
printed: an address shows as its form only.
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
INJECT = os.environ.get("KEYPOOL_DUMP_INJECT", "")
RPC_TIMEOUT = 300
START_TIMEOUT = 180

# Differences irondivid has on purpose, by row name. Each is listed in
# README.md; a KNOWN row that starts to match divid is a FAIL, so the list
# stays true.
KEYPOOLOLDEST = ("irondivid adds keypoololdest to getwalletinfo (docs/divid-differences.md R4; "
                 "divid's members: rpcwallet.cpp:2894-2906)")
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, reason=None):
    global fails
    reason = reason or KNOWN.get(name)
    if reason:
        word, note = ("FAIL", "  [listed as KNOWN but now matches divid: update README.md]") if same \
            else ("KNOWN", "  [known: " + reason + "]")
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"keypool{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=keypool{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
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
        except (OSError, ValueError) as e:
            return ("err", "no reply", type(e).__name__)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

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


# --- how replies are compared ---------------------------------------------------------

ADDRESS = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{26,35}$")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def address_version(text):
    """The version byte of a base58check address and its payload length, or
    None: the form an address is compared by (each wallet has its own keys)"""
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    body, check = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != check:
        return None
    return body[0], len(body) - 1


def view(out):
    """A reply as compared: an error by code and message (a help text by its
    first line), an address by its form (version byte, payload length), the
    rest as it is"""
    if out[0] == "err":
        message = str(out[2])
        return ("err", out[1], message.split("\n", 1)[0] if "\n" in message else message)
    v = out[1]
    if isinstance(v, str) and ADDRESS.match(v):
        form = address_version(v)
        if form:
            return ("ok", f"<address version {form[0]}, {form[1]} bytes>")
    return ("ok", v)


def show(v):
    if v[0] == "err":
        return f"error {v[1]} \"{v[2][:90]}\""
    return json.dumps(v[1])[:90]


def compare(name, core, iron):
    if INJECT and INJECT == name:
        iron = ("ok", "injected") if iron[0] == "ok" else iron[:2] + (str(iron[2]) + " injected",)
    a, b = view(core), view(iron)
    row(name, show(a), show(b), a == b)
    return core, iron


def both(name, method, *params):
    return compare(name, C.call(method, *params), I.call(method, *params))


def pool(name):
    """getwalletinfo keypoolsize on both, and whether each has keypoololdest"""
    c, i = C.call("getwalletinfo"), I.call("getwalletinfo")
    pick = lambda out, k: ("ok", out[1].get(k)) if out[0] == "ok" and isinstance(out[1], dict) else out
    compare(f"{name}: keypoolsize", pick(c, "keypoolsize"), pick(i, "keypoolsize"))
    has = lambda out: out[0] == "ok" and isinstance(out[1], dict) and "keypoololdest" in out[1]
    oldest_seen.append((has(c), has(i)))


oldest_seen = []


def start_pair(step, extra):
    global C, I
    C = Node(f"{step}-divid", DIVID, 0, extra)
    I = Node(f"{step}-irondivid", IRONDIVID, 1, extra)
    for n in (C, I):
        if not n.wait_ready():
            print(f"FAIL   start ({step}): {n.name} did not answer within {START_TIMEOUT} s", flush=True)
            sys.exit(1)


def stop_pair():
    for n in (C, I):
        n.stop()


def restart_if_stopped():
    """divid 3.0.0 keeps running after encryptwallet ("Wallet reloaded!"); a
    node that stopped is started again"""
    for n in (C, I):
        if n.proc.poll() is not None:
            n.log.close()
            n.start()
            if not n.wait_ready():
                print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
                sys.exit(1)


def keys(label, method, times):
    for k in range(1, times + 1):
        both(f"{label}: {method} #{k}", method)
        pool(f"{label}: after {method} #{k}")


# --- 1. -keypool unset: divid's default of 1000 per chain (wallet.cpp:2059) ------------------
start_pair("default", [])
pool("default, fresh wallet")
keys("default", "getnewaddress", 1)
keys("default", "getrawchangeaddress", 1)
both("default: keypoolrefill", "keypoolrefill")
pool("default: after keypoolrefill")
both("default: keypoolrefill 5 (below the pool)", "keypoolrefill", 5)
pool("default: after keypoolrefill 5")
both("default: keypoolrefill 0", "keypoolrefill", 0)
pool("default: after keypoolrefill 0")
both("default: keypoolrefill 1200", "keypoolrefill", 1200)
pool("default: after keypoolrefill 1200")
both("default: keypoolrefill -1", "keypoolrefill", -1)
both("default: keypoolrefill \"x\"", "keypoolrefill", "x")
both("default: keypoolrefill 1.5", "keypoolrefill", 1.5)
both("default: keypoolrefill 1 2 (two arguments)", "keypoolrefill", 1, 2)
pool("default: after the refused calls")

# dumpwallet and importwallet: not in divid 3.0.0 (rpcserver.cpp:420-464)
dump = os.path.join(WORK, "dump.txt")
both("dumpwallet <new file>", "dumpwallet", dump)
row("dumpwallet <new file>: no file written", "-", "-", not os.path.exists(dump))
existing = os.path.join(WORK, "existing.txt")
with open(existing, "w") as f:
    f.write("not a wallet dump\n")
both("dumpwallet <an existing file>", "dumpwallet", existing)
with open(existing) as f:
    row("dumpwallet <an existing file>: the file left as it was", "-", "-", f.read() == "not a wallet dump\n")
missing = os.path.join(WORK, "no-such-dir", "dump.txt")
both("dumpwallet <a file in a missing directory>", "dumpwallet", missing)
row("dumpwallet <a file in a missing directory>: no directory made", "-", "-",
    not os.path.exists(os.path.dirname(missing)))
both("dumpwallet (no argument)", "dumpwallet")
both("importwallet <a file that is no dump>", "importwallet", existing)
both("importwallet <a missing file>", "importwallet", dump)
pool("default: after the dump calls")
stop_pair()

# --- 2. -keypool=0: a target of at least 1 per chain (wallet.cpp:2079-2080) ------------------
start_pair("keypool0", ["keypool=0"])
pool("-keypool=0, fresh wallet")
keys("-keypool=0", "getnewaddress", 2)
keys("-keypool=0", "getrawchangeaddress", 2)
both("-keypool=0: keypoolrefill", "keypoolrefill")
pool("-keypool=0: after keypoolrefill")
stop_pair()

# --- 3. -keypool=1 ---------------------------------------------------------------------------
start_pair("keypool1", ["keypool=1"])
pool("-keypool=1, fresh wallet")
keys("-keypool=1", "getnewaddress", 3)
keys("-keypool=1", "getrawchangeaddress", 2)
both("-keypool=1: keypoolrefill 4", "keypoolrefill", 4)
pool("-keypool=1: after keypoolrefill 4")
stop_pair()

# --- 4. -keypool=3 and an encrypted wallet ------------------------------------------------------
start_pair("keypool3", ["keypool=3"])
pool("-keypool=3, fresh wallet")
keys("-keypool=3", "getnewaddress", 1)
PASS = secrets.token_urlsafe(18)
both("-keypool=3: encryptwallet <passphrase>", "encryptwallet", PASS)
restart_if_stopped()
pool("-keypool=3: encrypted, locked")
# Locked: keys come from the pool only, and an empty pool is -12 (rpcwallet.cpp:305-307, :574-576)
keys("-keypool=3 locked", "getnewaddress", 5)
keys("-keypool=3 locked", "getrawchangeaddress", 5)
both("-keypool=3 locked: keypoolrefill", "keypoolrefill")
both("-keypool=3 locked: keypoolrefill 5", "keypoolrefill", 5)
both("-keypool=3 locked: dumpwallet <new file>", "dumpwallet", dump)
row("-keypool=3 locked: dumpwallet: no file written", "-", "-", not os.path.exists(dump))
pool("-keypool=3 locked: after the refused calls")
# Unlocked for staking only: still locked to these calls (IsLocked(), crypter.h:139-157)
both("-keypool=3: walletpassphrase <passphrase> 60 true (staking only)", "walletpassphrase", PASS, 60, True)
pool("-keypool=3 staking only: after walletpassphrase")
keys("-keypool=3 staking only", "getnewaddress", 2)
keys("-keypool=3 staking only", "getrawchangeaddress", 1)
both("-keypool=3 staking only: keypoolrefill", "keypoolrefill")
pool("-keypool=3 staking only: after keypoolrefill")
both("-keypool=3: walletlock (from staking only)", "walletlock")
# Unlocked: the pool tops up again
both("-keypool=3: walletpassphrase <passphrase> 60", "walletpassphrase", PASS, 60)
pool("-keypool=3 unlocked: after walletpassphrase")
keys("-keypool=3 unlocked", "getnewaddress", 1)
both("-keypool=3 unlocked: keypoolrefill", "keypoolrefill")
pool("-keypool=3 unlocked: after keypoolrefill")
both("-keypool=3 unlocked: keypoolrefill 6", "keypoolrefill", 6)
pool("-keypool=3 unlocked: after keypoolrefill 6")
both("-keypool=3: walletlock", "walletlock")
pool("-keypool=3 locked again")
keys("-keypool=3 locked again", "getnewaddress", 1)
del PASS
stop_pair()

# --- 5. -keypool=2000: a large pool ----------------------------------------------------------
start_pair("keypool2000", ["keypool=2000"])
pool("-keypool=2000, fresh wallet")
keys("-keypool=2000", "getnewaddress", 1)
keys("-keypool=2000", "getrawchangeaddress", 1)
both("-keypool=2000: keypoolrefill 100 (below the target)", "keypoolrefill", 100)
pool("-keypool=2000: after keypoolrefill 100")
stop_pair()

# keypoololdest: an irondivid member of getwalletinfo, never divid's
c_has = any(c for c, _ in oldest_seen)
i_all = all(i for _, i in oldest_seen)
row("getwalletinfo keypoololdest (every step)", "absent" if not c_has else "present",
    "present" if i_all else "absent", c_has == i_all, reason=KEYPOOLOLDEST if not c_has and i_all else None)

for path in (dump, existing):
    if os.path.exists(path):
        os.remove(path)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
