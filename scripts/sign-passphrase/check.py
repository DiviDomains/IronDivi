#!/usr/bin/env python3
"""signmessage, verifymessage, walletpassphrasechange, walletpassphrase and
walletlock on Divi Core divid and irondivid side by side on regtest.

Both wallets come from one phrase, so they hold the same keys, and a signature
(RFC 6979, deterministic) is the same on both. The nodes dial nobody. First the
calls on unencrypted wallets, then both are encrypted with one passphrase and
the calls run again locked, unlocked for staking only, and fully unlocked; the
passphrase is changed in each state, and the unlock state compared after; then
walletpassphrase's timeout, and a restart. Each row prints PASS (same as
divid), KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
passphrases are made at random into a 0600 file in the work directory; they go
only into RPC request bodies, never onto a command line or into the output, and
a row checks that neither node's log holds one.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import member_order  # noqa: E402  (scripts/lib: the order check the replies scripts share)
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("SIGN_PASSPHRASE_INJECT", "")
HOST = os.environ.get("SIGN_PASSPHRASE_HOST", "127.0.0.2")
RPC_TIMEOUT = 120
START_TIMEOUT = 180

# Differences irondivid has on purpose, one per row name, each listed in
# README.md with divid's source line; a KNOWN row that matches divid is a FAIL
KNOWN = {}
# json_spirit keeps only the low byte of a \uXXXX escape (unicode_str_to_char,
# json/json_spirit_reader_template.h:71-82, :111-116), so divid signs another
# message than the one sent; the same text sent as UTF-8 matches
ESCAPED = ("divid keeps the low byte of each \\u escape: "
           "json_spirit_reader_template.h:71-82, :111-116")
for p in ("unencrypted: ", "unlocked: "):
    for m in ("signmessage", "verifymessage"):
        KNOWN[f"{p}{m}, a non-ASCII message, \\u-escaped"] = ESCAPED

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


# --- the passphrases, made here and kept in a 0600 file ---------------------------------

def passphrase_file():
    path = os.path.join(WORK, "passphrases.json")
    words = {k: secrets.token_hex(16) for k in ("first", "second", "third", "fourth")}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(words, f)
    with open(path) as f:
        return json.load(f)


PASS = passphrase_file()


class Node:
    def __init__(self, name, binary, index, extra, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"sp{index}"
        self.password = secrets.token_hex(16)
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=0",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", f"connect={HOST}:{PORT_BASE + 49}",
        ] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.runs = 0
        self.start()

    def start(self):
        self.runs += 1
        self.log = open(os.path.join(WORK, f"{self.name}.{self.runs}.out"), "w")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s")

    def call(self, method, *params, raw=False):
        """('ok', result) or ('err', code, message); `raw`: text beyond ASCII
        is sent as UTF-8, not as \\u escapes"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)},
                          ensure_ascii=not raw).encode()
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

    def debug_log(self):
        for p in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(p):
                with open(p, errors="replace") as f:
                    return f.read()
        return ""


# --- how replies are compared ---------------------------------------------------------------

def usage_text(method, message):
    """divid's reply to wrong arguments its help covers: the help text, which
    starts with the call's name"""
    return message.startswith(method + " ") or message.startswith(method + "\n")


def short(out):
    if out[0] == "err":
        first = out[2].splitlines()[0] if out[2] else ""
        return f"error {out[1]} \"{first[:90]}\""
    return json.dumps(out[1])[:90]


def compare(name, method, core, iron):
    """Same outcome; an error with the same code and message (a help text by its
    code -1 and first line); a result with the same value and member order"""
    if INJECT and INJECT == name:
        iron = ("ok", "injected") if iron[0] == "err" else ("err", -1, "injected")
    if core[0] == "err" or iron[0] == "err":
        same = core == iron
        if core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and usage_text(method, core[2]):
            same = core[2].splitlines()[0] == iron[2].splitlines()[0]
        row(name, short(core), short(iron), same)
        return
    order = member_order.difference(core[1], iron[1])
    same = core[1] == iron[1] and order is None
    row(name, short(core), order or short(iron), same)


def both(name, method, *params, raw=False):
    out = (C.call(method, *params, raw=raw), I.call(method, *params, raw=raw))
    compare(name, method, *out)
    return out


def unlock_state(node):
    """getwalletinfo's encryption_status, and unlocked_until as 0, or seconds
    from now in steps of 10 (the two nodes are read a moment apart)"""
    info = node.rpc("getwalletinfo")
    until = info.get("unlocked_until")
    if until is None:
        when = "absent"
    elif until == 0:
        when = 0
    else:
        when = int(round((until - time.time()) / 10.0)) * 10
    return {"encryption_status": info.get("encryption_status"), "unlocked_until": when}


def state_row(name):
    c, i = unlock_state(C), unlock_state(I)
    row(name, json.dumps(c), json.dumps(i), c == i)


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


# --- the nodes --------------------------------------------------------------------------------

C = Node("divid", DIVID, 0, [])
I = Node("irondivid", IRONDIVID, 1, [], env={"WALLET_MNEMONIC": C.rpc("dumphdinfo")["mnemonic"]})
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# divid's first two addresses; irondivid's wallet, from the same phrase, holds their keys
A = C.rpc("getnewaddress")
B_ = C.rpc("getnewaddress")
for a in (A, B_):
    if not I.rpc("validateaddress", a).get("ismine"):
        raise RuntimeError(f"irondivid's wallet does not hold the key of divid's address {a}")
PUB_A = C.rpc("validateaddress", A)["pubkey"]
PUB_B = C.rpc("validateaddress", B_)["pubkey"]
MS = C.rpc("addmultisigaddress", 1, [PUB_A, PUB_B])
I.rpc("addmultisigaddress", 1, [PUB_A, PUB_B])
# An address of no key either wallet holds (regtest P2PKH version 139, random bytes)
NONE = b58check(bytes([139]) + secrets.token_bytes(20))
VAULT = f"{A}:{B_}"

LONG = "x" * 20000
TEXT = "héllo ✓ 中文 \U0001f600"
# (label, message, sent as UTF-8 rather than \u-escaped)
MESSAGES = (("a short message", "hello", False), ("an empty message", "", False),
            ("a 20000-character message", LONG, False),
            ("a non-ASCII message, \\u-escaped", TEXT, False), ("a non-ASCII message, as UTF-8", TEXT, True))


def sign_rows(p, expect_signatures):
    """signmessage and verifymessage in each form; `expect_signatures`: the
    wallet can sign (else every signmessage is refused alike)"""
    sigs = {}
    for label, message, raw in MESSAGES:
        c, i = both(f"{p}signmessage, {label}", "signmessage", A, message, raw=raw)
        if c[0] == "ok":
            sigs[label] = c[1]
    both(f"{p}signmessage, hex input", "signmessage", A, "68656c6c6f", "hex")
    both(f"{p}signmessage, b64 input", "signmessage", A, "aGVsbG8=", "b64")
    both(f"{p}signmessage, an unknown input format", "signmessage", A, "hello", "foo")
    both(f"{p}signmessage, hex output", "signmessage", A, "hello", "", "hex")
    both(f"{p}signmessage, the multisig address", "signmessage", MS, "hello")
    both(f"{p}signmessage, a vault owner:manager", "signmessage", VAULT, "hello")
    both(f"{p}signmessage, an address not in the wallet", "signmessage", NONE, "hello")
    both(f"{p}signmessage, a bad address", "signmessage", "notanaddress", "hello")
    both(f"{p}signmessage, one argument", "signmessage", A)
    both(f"{p}signmessage, five arguments", "signmessage", A, "hello", "", "", "x")
    both(f"{p}signmessage, a number as the message", "signmessage", A, 5)
    for label, message, raw in MESSAGES:
        if label in sigs:
            both(f"{p}verifymessage, {label}", "verifymessage", A, sigs[label], message, raw=raw)
    if "a short message" in sigs:
        good = sigs["a short message"]
        both(f"{p}verifymessage, another message", "verifymessage", A, good, "hellp")
        both(f"{p}verifymessage, the wrong address", "verifymessage", B_, good, "hello")
        both(f"{p}verifymessage, the multisig address", "verifymessage", MS, good, "hello")
        both(f"{p}verifymessage, an address not in the wallet", "verifymessage", NONE, good, "hello")
        both(f"{p}verifymessage, a bad address", "verifymessage", "notanaddress", good, "hello")
        both(f"{p}verifymessage, a signature that is not base64", "verifymessage", A, "!!!not base64!!!", "hello")
        both(f"{p}verifymessage, base64 that is no signature", "verifymessage", A, "AAAA", "hello")
        both(f"{p}verifymessage, an empty signature", "verifymessage", A, "", "hello")
        both(f"{p}verifymessage, the signature without its padding", "verifymessage", A, good.rstrip("="), "hello")
        hex_sig = C.call("signmessage", A, "hello", "", "hex")
        if hex_sig[0] == "ok":
            both(f"{p}verifymessage, the hex signature", "verifymessage", A, hex_sig[1], "hello")
    both(f"{p}verifymessage, two arguments", "verifymessage", A, "AAAA")
    return sigs


# --- unencrypted ------------------------------------------------------------------------------

sign_rows("unencrypted: ", True)
state_row("unencrypted: getwalletinfo unlock state")
both("unencrypted: walletpassphrasechange", "walletpassphrasechange", PASS["first"], PASS["second"])
both("unencrypted: walletpassphrase", "walletpassphrase", PASS["first"], 60)
both("unencrypted: walletlock", "walletlock")

# --- encrypted --------------------------------------------------------------------------------

c, i = C.call("encryptwallet", PASS["first"]), I.call("encryptwallet", PASS["first"])
row("encryptwallet", short(c), short(i), c[0] == i[0] == "ok")
for n in (C, I):
    # divid reloads the wallet and keeps running (rpcwallet.cpp:2722-2723); a node
    # that stops instead is started again
    if n.proc.poll() is not None:
        n.start()
state_row("encrypted: unlock state")
sign_rows("locked: ", False)
both("locked: walletlock", "walletlock")
state_row("locked: unlock state after walletlock")

# Unlocked for staking only
both("walletpassphrase for staking only", "walletpassphrase", PASS["first"], 600, True)
state_row("staking only: unlock state")
both("staking only: signmessage", "signmessage", A, "hello")
both("staking only: walletpassphrase for staking only again", "walletpassphrase", PASS["first"], 600, True)
both("walletlock from staking only", "walletlock")
state_row("unlock state after walletlock from staking only")

# Fully unlocked
both("walletpassphrase", "walletpassphrase", PASS["first"], 600)
state_row("unlocked: unlock state")
sign_rows("unlocked: ", True)
both("unlocked: walletpassphrase with a wrong passphrase", "walletpassphrase", PASS["fourth"], 600)
state_row("unlocked: unlock state after a wrong walletpassphrase")
both("unlocked: walletpassphrase for staking only", "walletpassphrase", PASS["first"], 600, True)
state_row("unlocked: unlock state after walletpassphrase for staking only")
both("walletlock", "walletlock")
state_row("unlock state after walletlock")

# --- walletpassphrasechange in each state ----------------------------------------------------

both("locked: walletpassphrasechange, a wrong old passphrase", "walletpassphrasechange", PASS["fourth"], PASS["second"])
state_row("locked: unlock state after a wrong walletpassphrasechange")
both("locked: walletpassphrasechange, an empty new passphrase", "walletpassphrasechange", PASS["first"], "")
both("locked: walletpassphrasechange, an empty old passphrase", "walletpassphrasechange", "", PASS["second"])
both("locked: walletpassphrasechange, one argument", "walletpassphrasechange", PASS["first"])
both("locked: walletpassphrasechange, a number", "walletpassphrasechange", PASS["first"], 5)
both("locked: walletpassphrasechange", "walletpassphrasechange", PASS["first"], PASS["second"])
state_row("locked: unlock state after walletpassphrasechange")
both("after a change: walletpassphrase with the old passphrase", "walletpassphrase", PASS["first"], 600)
both("after a change: walletpassphrase with the new passphrase", "walletpassphrase", PASS["second"], 600)
state_row("after a change: unlock state")

# Unlocked (by the line above): change again, then a wrong one
both("unlocked: walletpassphrasechange", "walletpassphrasechange", PASS["second"], PASS["third"])
state_row("unlocked: unlock state after walletpassphrasechange")
both("unlocked: signmessage after walletpassphrasechange", "signmessage", A, "hello")
both("unlocked: walletpassphrasechange, a wrong old passphrase", "walletpassphrasechange", PASS["fourth"], PASS["first"])
state_row("unlocked: unlock state after a wrong walletpassphrasechange")
both("unlocked: signmessage after a wrong walletpassphrasechange", "signmessage", A, "hello")
both("walletlock before staking only", "walletlock")

# Unlocked for staking only: change, then a wrong one
both("walletpassphrase for staking only, the third passphrase", "walletpassphrase", PASS["third"], 600, True)
both("staking only: walletpassphrasechange", "walletpassphrasechange", PASS["third"], PASS["second"])
state_row("staking only: unlock state after walletpassphrasechange")
both("staking only: walletpassphrasechange, a wrong old passphrase", "walletpassphrasechange", PASS["fourth"], PASS["third"])
state_row("staking only: unlock state after a wrong walletpassphrasechange")
both("walletlock after the changes", "walletlock")

# A change while a short unlock runs out
both("walletpassphrase for 3 seconds", "walletpassphrase", PASS["second"], 3)
both("walletpassphrasechange during a 3-second unlock", "walletpassphrasechange", PASS["second"], PASS["first"])
time.sleep(5)
state_row("unlock state 5 seconds after a 3-second unlock with a change in it")
both("walletlock after the short unlock", "walletlock")

# --- walletpassphrase's timeout ---------------------------------------------------------------

for label, timeout in (("0", 0), ("1000000000", 1000000000), ("2^31", 2 ** 31), ("-5", -5), ("1.5", 1.5),
                       ("\"60\" (text)", "60"), ("true", True), ("null", None)):
    both(f"walletpassphrase, timeout {label}", "walletpassphrase", PASS["first"], timeout)
    state_row(f"unlock state after walletpassphrase, timeout {label}")
    both(f"walletlock after timeout {label}", "walletlock")
both("walletpassphrase, timeout 2", "walletpassphrase", PASS["first"], 2)
time.sleep(4)
state_row("unlock state 4 seconds after a 2-second unlock")
both("walletpassphrase, a wrong passphrase", "walletpassphrase", PASS["fourth"], 60)
state_row("unlock state after a wrong walletpassphrase")
both("walletpassphrase, one argument", "walletpassphrase", PASS["first"])
both("walletpassphrase, four arguments", "walletpassphrase", PASS["first"], 60, False, 1)
both("walletpassphrase, the passphrase a number", "walletpassphrase", 5, 60)
both("walletpassphrase, staking-only not a bool", "walletpassphrase", PASS["first"], 60, "yes")
both("walletlock, an argument", "walletlock", 1)
both("walletlock again", "walletlock")

# --- after a restart --------------------------------------------------------------------------

for n in (C, I):
    n.stop()
    n.start()
state_row("after a restart: unlock state")
both("after a restart: walletpassphrase with the passphrase before the last change", "walletpassphrase",
     PASS["second"], 600)
both("after a restart: walletpassphrase with the last passphrase", "walletpassphrase", PASS["first"], 600)
state_row("after a restart: unlock state after walletpassphrase")
both("after a restart: signmessage", "signmessage", A, "hello")
both("after a restart: walletlock", "walletlock")

# --- the logs ---------------------------------------------------------------------------------

logs = {n.name: n.debug_log() for n in (C, I)}
held = {name: any(p in text for p in PASS.values()) for name, text in logs.items()}
row("no passphrase in the debug log", "holds one" if held["divid"] else "none",
    "holds one" if held["irondivid"] else "none", not held["divid"] and not held["irondivid"])
changed = {name: len(re.findall(r"(?i)passphrase changed", text)) for name, text in logs.items()}
row("log lines naming a passphrase change", changed["divid"], changed["irondivid"],
    changed["divid"] == changed["irondivid"])

for n in (I, C):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
