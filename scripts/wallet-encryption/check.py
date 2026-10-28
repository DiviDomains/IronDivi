#!/usr/bin/env python3
"""An encrypted wallet from encryptwallet to unlock, on Divi Core divid and on
irondivid side by side: the arguments each call takes, the unlock timer's edges,
what each lock state allows, the wallet after a restart, BIP38, a backup of the
encrypted wallet started on a new node, and whether a private key or the phrase
is left on disk in the clear.

Two nodes, not connected, each mining its own regtest chain with the same calls.
Each row is one call on both; compared are the outcome (a result's shape, or the
error code and text) and, where the row says so, the wallet's lock state after
it (getwalletinfo's encryption_status, unlocked_until relative to the call, and
keypoolsize). A row that differs is a FAIL unless it is in KNOWN; exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
passphrases and the imported keys live only in memory and in RPC request
bodies; they are never printed or put on a command line.
"""

import base64
import json
import os
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
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
KEYPOOL = 5
# Seconds a short timer runs, and how long a row waits for it to end
SHORT = 3
PAST = 6

# Rows where irondivid differs from divid on purpose: row name -> reason with
# divid's source line (divi/src/ of Divi Core 3.0.0). A KNOWN row that matches
# divid is a FAIL, so the list stays true.
KNOWN = {
    # irondivid has bip38encrypt (PIVX's), divid only bip38paperwallet
    # (rpcserver.cpp:424-425)
    "locked: bip38encrypt": "irondivid-only RPC; divid: method not found",
    "staking only: bip38encrypt": "irondivid-only RPC; divid: method not found",
    "unlocked: bip38encrypt": "irondivid-only RPC; divid: method not found",
    # divid copies the passphrase with c_str() (rpcwallet.cpp:2711, :2603), so
    # it ends at the first NUL; irondivid uses every character given
    "passphrase with a NUL: the part before it": "divid cuts the passphrase at a NUL (c_str, rpcwallet.cpp:2603)",
    # divid adds whatever key a wrong passphrase decrypts to (rpcdump.cpp:316-339)
    "unlocked: bip38decrypt, wrong passphrase": "irondivid refuses a key that does not match the address hash",
    # json_spirit reads a real beyond double as infinity and divid unlocks,
    # then refuses the timeout's type; serde_json has no infinite number, so
    # irondivid refuses the request (-32700) and unlocks nothing
    "timeout written 1e400": "a real beyond f64 is a parse error on irondivid",
    # Divi Core's boost timer overflows on a timeout this long and relocks at
    # once (rpcserver.cpp:852, posix_time::seconds); irondivid keeps the
    # wallet unlocked until walletlock
    "timeout 2^62": "divid's timer overflows and relocks at once",
    # irondivid adds the account path its keys derive from (wallet.rs dump_hd_info)
    "unlocked: dumphdinfo": "irondivid's extra hdaccountpath member",
}

fails = 0


def log(line):
    print(line, flush=True)


class Raw:
    """A parameter written into the request as this text, not as JSON"""

    def __init__(self, text):
        self.text = text


class Node:
    def __init__(self, name, binary, index, extra_conf=()):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"we{index}:{password}".encode()).decode()
        os.makedirs(self.dir, exist_ok=True)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=we{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=0",
            f"bind={HOST}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            f"keypool={KEYPOOL}", "checkblockindex=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.start()

    def start(self):
        out = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        out.close()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            if self.call("getblockcount")[0] == "ok":
                return
            time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s; exit {self.proc.poll()}")

    def call(self, method, *params):
        """('ok', result), ('err', code, message), or ('down',)"""
        args = ",".join(p.text if isinstance(p, Raw) else json.dumps(p) for p in params)
        body = ('{"jsonrpc": "1.0", "id": 1, "method": %s, "params": [%s]}' % (json.dumps(method), args)).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}")
            except ValueError:
                return ("err", e.code, "HTTP")
        except (OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1:]}"[:300])
        return out[1]

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def shape(out, exact=False, message=True):
    """What is compared of an answer; never a key, phrase or passphrase"""
    if out[0] == "down":
        return "down"
    if out[0] == "err":
        first = out[2].splitlines()[0] if out[2] else ""
        return f"error {out[1]} {first!r}" if message else f"error {out[1]}"
    v = out[1]
    if exact:
        return json.dumps(v)
    if v is None:
        return "null"
    if isinstance(v, bool):
        return json.dumps(v)
    if isinstance(v, str):
        return "txid" if len(v) == 64 and all(ch in "0123456789abcdef" for ch in v) else "string"
    if isinstance(v, dict):
        return "object{" + ",".join(sorted(v)) + "}"
    return type(v).__name__


def lock_state(node, t_call):
    info = node.rpc("getwalletinfo")
    u = info.get("unlocked_until", "absent")
    if isinstance(u, int) and u != 0:
        # relative to the call: set before it or by it with timeout 0 or less,
        # a few seconds on, or a longer time to 10 s
        d = u - t_call
        u = "past/now" if d <= 1 else "call+few s" if d <= 10 else f"call+{int(round(d / 10.0) * 10)}s"
    return f"{info.get('encryption_status')} until={u} keypool={info.get('keypoolsize')}"


def row(name, method, *params, each=None, exact=False, message=True, state=True):
    """One call on both nodes (each(node) gives per-node parameters), then
    compare. Returns the two raw answers."""
    global fails
    outs, shown = [], []
    for node in NODES:
        t = time.time()
        out = node.call(method, *(each(node) if each else params))
        outs.append(out)
        s = shape(out, exact, message)
        if state:
            s += " | " + lock_state(node, t)
        shown.append(s)
    same = shown[0] == shown[1]
    report(name, same, shown[0], shown[1])
    return outs


def report(name, same, c, i):
    global fails
    known = KNOWN.get(name)
    if same and not known:
        log(f"PASS   {name:58} {c}")
        return
    if not same and known:
        log(f"KNOWN  {name:58} [{known}]")
        log(f"#        divid:     {c}")
        log(f"#        irondivid: {i}")
        return
    fails += 1
    if known:
        log(f"FAIL   {name:58} listed as KNOWN but matches divid now: {c}")
        return
    log(f"FAIL   {name}")
    log(f"#        divid:     {c}")
    log(f"#        irondivid: {i}")


def status_row(name):
    """The wallet's lock state on both, as one row"""
    a, b = (lock_state(n, time.time()) for n in NODES)
    sa = NODES[0].rpc("getstakingstatus").get("walletunlocked")
    sb = NODES[1].rpc("getstakingstatus").get("walletunlocked")
    report(name, (a, sa) == (b, sb), f"{a} walletunlocked={sa}", f"{b} walletunlocked={sb}")


def key_fields(name):
    """Which members getwalletinfo and getinfo have about encryption"""
    def fields(node):
        w = node.rpc("getwalletinfo")
        g = node.rpc("getinfo")
        return (f"getwalletinfo {sorted(k for k in w if 'unlock' in k or 'encrypt' in k)} "
                f"getinfo {sorted(k for k in g if 'unlock' in k or 'encrypt' in k)}")
    a, b = fields(NODES[0]), fields(NODES[1])
    report(name, a == b, a, b)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(data):
    import hashlib
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def wif(secret):
    """A compressed regtest WIF (prefix 239)"""
    return b58check(bytes([239]) + secret + b"\x01")


def b58decode_secret(w):
    n = 0
    for ch in w:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(38, "big") if len(w) > 51 else n.to_bytes(37, "big")
    return raw[1:33]


def scan(top, needles):
    """The names of the needles found in any file under `top` (a file or a
    folder; a node's data directory once it stopped, so everything it wrote
    is on disk)"""
    found = set()
    walk = [(os.path.dirname(top), [], [os.path.basename(top)])] if os.path.isfile(top) else os.walk(top)
    for root, _, files in walk:
        for f in files:
            path = os.path.join(root, f)
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            for label, needle in needles.items():
                if needle and needle in data:
                    found.add(label)
    return sorted(found)


def matrix(state):
    """The calls that need the keys, or hand out keys, in one lock state"""
    row(f"{state}: sendtoaddress", "sendtoaddress", each=lambda n: [n.addr, 1])
    row(f"{state}: sendmany", "sendmany", "", each=lambda n: ["", {n.addr: 1}])
    row(f"{state}: dumpprivkey", "dumpprivkey", each=lambda n: [n.imported])
    row(f"{state}: dumphdinfo", "dumphdinfo")
    row(f"{state}: dumpwallet", "dumpwallet", each=lambda n: [os.path.join(n.dir, f"dump-{state[:3]}.txt")],
        message=False)
    row(f"{state}: signmessage", "signmessage", each=lambda n: [n.imported, "a message"])
    row(f"{state}: signrawtransaction", "signrawtransaction", each=lambda n: [n.raw])
    row(f"{state}: bip38paperwallet", "bip38paperwallet", "paper")
    row(f"{state}: bip38decrypt (not a key)", "bip38decrypt", "6PYnotakey", "x")
    row(f"{state}: bip38encrypt", "bip38encrypt", each=lambda n: [n.imported, "x"])
    row(f"{state}: importprivkey", "importprivkey", each=lambda n: [wif(secrets.token_bytes(32)), "", False])
    row(f"{state}: keypoolrefill", "keypoolrefill")
    row(f"{state}: getnewaddress", "getnewaddress")
    row(f"{state}: getrawchangeaddress", "getrawchangeaddress")
    row(f"{state}: setgenerate 1", "setgenerate", 1, message=False)


def main():
    global NODES, fails
    c = Node("divid", DIVID, 0)
    i = Node("irondivid", IRONDIVID, 1)
    NODES = [c, i]
    pw, pw2, wrong = secrets.token_hex(16), secrets.token_hex(16), secrets.token_hex(16)

    # Coins: each mines its own chain past maturity
    for n in NODES:
        n.rpc("setgenerate", 30)
        n.addr = n.rpc("getnewaddress")
        n.k1 = secrets.token_bytes(32)
        n.rpc("importprivkey", wif(n.k1), "imported", False)
        n.imported = n.rpc("getaddressesbyaccount", "imported")[0]
        n.rpc("sendtoaddress", n.imported, 100)
        n.rpc("setgenerate", 1)
        u = max(n.rpc("listunspent"), key=lambda x: x["amount"])
        n.raw = n.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]}], {n.addr: 1})
        n.mnemonic = n.rpc("dumphdinfo")["mnemonic"].encode()
        n.hdkey = b58decode_secret(n.rpc("dumpprivkey", n.addr))

    # --- unencrypted ---------------------------------------------------------
    key_fields("unencrypted: encryption members")
    row("unencrypted: walletpassphrase, one argument", "walletpassphrase", pw)
    row("unencrypted: walletlock, one argument", "walletlock", 1)
    row("unencrypted: walletpassphrasechange, one argument", "walletpassphrasechange", pw)
    row("encryptwallet, no argument", "encryptwallet")
    row("encryptwallet, two arguments", "encryptwallet", pw, pw)
    row("encryptwallet, empty passphrase", "encryptwallet", "")
    row("encryptwallet, a number", "encryptwallet", 5)
    row("encryptwallet", "encryptwallet", pw, exact=True)
    key_fields("encrypted: encryption members")
    status_row("after encryptwallet")
    row("encryptwallet again", "encryptwallet", pw)

    # --- locked: argument shapes of walletpassphrase -----------------------------
    row("locked: walletpassphrase, one argument", "walletpassphrase", pw)
    row("locked: walletpassphrase, four arguments", "walletpassphrase", pw, 10, True, 1)
    row("locked: walletpassphrase, empty passphrase", "walletpassphrase", "", 10)
    row("locked: walletpassphrase, wrong passphrase", "walletpassphrase", wrong, 10)
    row("locked: walletpassphrase, 5000-character passphrase", "walletpassphrase", "p" * 5000, 10)
    row("locked: walletpassphrase, passphrase a number", "walletpassphrase", 5, 10)
    row("locked: walletpassphrase, stakingOnly \"true\"", "walletpassphrase", pw, 10, "true")
    row("locked: walletpassphrase, stakingOnly 1", "walletpassphrase", pw, 10, 1)
    # divid unlocks before it reads the timeout (rpcwallet.cpp:2614-2623)
    row("locked: walletpassphrase, timeout \"10\"", "walletpassphrase", pw, "10")
    row("walletlock", "walletlock")
    row("locked: walletpassphrase, timeout 1.5", "walletpassphrase", pw, 1.5)
    row("walletlock", "walletlock")
    row("locked: walletpassphrase, timeout null", "walletpassphrase", pw, None)
    row("walletlock", "walletlock")
    row("locked: walletlock, one argument", "walletlock", 1)
    row("locked: walletlock again", "walletlock")

    # --- what each state allows ---------------------------------------------------
    matrix("locked")
    row("walletpassphrase staking only, no timer", "walletpassphrase", pw, 0, True)
    matrix("staking only")
    row("staking only: walletpassphrase wrong passphrase", "walletpassphrase", wrong, 0)
    row("staking only: walletpassphrase staking only again", "walletpassphrase", pw, 0, True)
    row("walletpassphrase full, no timer", "walletpassphrase", pw, 0)
    matrix("unlocked")

    # BIP38 round trip on the unlocked wallet
    outs = row("unlocked: bip38paperwallet, a key to decrypt", "bip38paperwallet", "bip38pass")
    for n, out in zip(NODES, outs):
        n.bip38 = out[1]["Encrypted Key"] if out[0] == "ok" else "6PYnotakey"
    row("unlocked: bip38decrypt, wrong passphrase", "bip38decrypt", each=lambda n: [n.bip38, "other"])
    row("unlocked: bip38decrypt", "bip38decrypt", each=lambda n: [n.bip38, "bip38pass"])
    row("unlocked: bip38decrypt again", "bip38decrypt", each=lambda n: [n.bip38, "bip38pass"])

    # Fully unlocked, any passphrase passes (CWallet::Unlock, wallet.cpp:781-784)
    row("unlocked: walletpassphrase wrong passphrase", "walletpassphrase", wrong, 0)
    row("unlocked: walletpassphrase wrong passphrase, staking only", "walletpassphrase", wrong, 0, True)
    row("staking only: walletpassphrase full", "walletpassphrase", pw, 0)

    # --- the timer ----------------------------------------------------------------
    row("walletlock", "walletlock")
    row("timeout 0", "walletpassphrase", pw, 0)
    time.sleep(PAST)
    status_row("timeout 0, later")
    row("walletlock", "walletlock")
    row("timeout -5", "walletpassphrase", pw, -5)
    time.sleep(PAST)
    status_row("timeout -5, later")
    row("walletlock", "walletlock")
    row(f"timeout {SHORT}", "walletpassphrase", pw, SHORT)
    row(f"timeout {SHORT}, then timeout 0", "walletpassphrase", pw, 0)
    time.sleep(PAST)
    status_row(f"timeout {SHORT} then 0, later")
    row("walletlock", "walletlock")
    row("timeout 100", "walletpassphrase", pw, 100)
    row(f"timeout 100, then timeout {SHORT}", "walletpassphrase", pw, SHORT)
    time.sleep(PAST)
    status_row(f"timeout 100 then {SHORT}, later")
    row(f"timeout {SHORT} (to be locked early)", "walletpassphrase", pw, SHORT)
    row("walletlock before the timer", "walletlock")
    row("timeout 0 after a pending timer", "walletpassphrase", pw, 0)
    time.sleep(PAST)
    status_row("timeout 0 after a pending timer, later")
    row("walletlock", "walletlock")
    row("timeout 2^62", "walletpassphrase", pw, 2 ** 62)
    row("walletlock", "walletlock")
    row("timeout 10^10", "walletpassphrase", pw, 10 ** 10)
    time.sleep(PAST)
    status_row("timeout 10^10, later")
    row("walletlock", "walletlock")
    row("timeout 2^64 (no int64)", "walletpassphrase", pw, 2 ** 64)
    row("walletlock", "walletlock")
    # json_spirit's numbers (json_spirit_reader_template.h:498-501), written as
    # a client may write them
    for text in ["+60", "060", "-0", "60.", ".5", "1e400", "-9223372036854775809"]:
        row(f"timeout written {text}", "walletpassphrase", pw, Raw(text))
        row("walletlock", "walletlock")
    row(f"staking only, timeout {SHORT}", "walletpassphrase", pw, SHORT, True)
    time.sleep(PAST)
    status_row(f"staking only, timeout {SHORT}, later")
    row("timeout 100 (full)", "walletpassphrase", pw, 100)
    row(f"full, then staking only timeout {SHORT}", "walletpassphrase", pw, SHORT, True)
    time.sleep(PAST)
    status_row(f"full then staking only {SHORT}, later")
    row("staking only, no timer", "walletpassphrase", pw, 0, True)
    row(f"staking only, then full timeout {SHORT}", "walletpassphrase", pw, SHORT)
    time.sleep(PAST)
    status_row(f"staking only then full {SHORT}, later")
    row(f"back to staking only: full timeout {SHORT}", "walletpassphrase", pw, SHORT)
    row("then full, no timer", "walletpassphrase", pw, 0)
    time.sleep(PAST)
    status_row(f"staking, full {SHORT}, full 0, later")

    # --- walletpassphrasechange ----------------------------------------------------
    row("walletlock", "walletlock")
    row("walletpassphrasechange, one argument", "walletpassphrasechange", pw)
    row("walletpassphrasechange, three arguments", "walletpassphrasechange", pw, pw2, pw2)
    row("walletpassphrasechange, empty old", "walletpassphrasechange", "", pw2)
    row("walletpassphrasechange, empty new", "walletpassphrasechange", pw, "")
    row(f"timeout {SHORT} before a change", "walletpassphrase", pw, SHORT)
    row("walletpassphrasechange while unlocked", "walletpassphrasechange", pw, pw2)
    time.sleep(PAST)
    status_row("walletpassphrasechange while unlocked, later")
    row("old passphrase after the change", "walletpassphrase", pw, 0)
    row("staking only with the new passphrase", "walletpassphrase", pw2, 0, True)
    row("walletpassphrasechange while staking only", "walletpassphrasechange", pw2, pw)
    row("walletpassphrasechange wrong old while staking only", "walletpassphrasechange", wrong, pw)
    row("walletpassphrasechange back", "walletpassphrasechange", pw2, pw)
    row("a passphrase with a NUL", "walletpassphrasechange", pw, "ab\u0000cd")
    row("passphrase with a NUL: the part before it", "walletpassphrase", "ab", 0)
    row("walletlock", "walletlock")
    row("passphrase with a NUL: all of it", "walletpassphrase", "ab\u0000cd", 0)
    row("walletlock", "walletlock")
    long_pw = "q" * 3000
    row("walletpassphrasechange to 3000 characters", "walletpassphrasechange", "ab\u0000cd", long_pw)
    row("walletpassphrase 3000 characters", "walletpassphrase", long_pw, 0)
    row("walletpassphrasechange back from 3000 characters", "walletpassphrasechange", long_pw, pw)

    # --- keys on disk ----------------------------------------------------------------
    row("unlocked: importprivkey (a second key)", "importprivkey",
        each=lambda n: [wif(n.__dict__.setdefault("k2", secrets.token_bytes(32))), "k2", False], state=False)
    row("unlocked: keypoolrefill 20", "keypoolrefill", 20)
    outs = row("unlocked: getnewaddress (a new HD key)", "getnewaddress")
    for n, out in zip(NODES, outs):
        n.newkey = b58decode_secret(n.rpc("dumpprivkey", out[1])) if out[0] == "ok" else b""
    row("staking only before the restart", "walletpassphrase", pw, 0, True)
    for n in NODES:
        n.stop()
    needles = lambda n: {"imported key": n.k1, "imported key 2": n.k2, "HD key from before": n.hdkey,
                         "HD key made unlocked": n.newkey, "phrase": n.mnemonic}
    found = [scan(n.dir, needles(n)) for n in NODES]
    log(f"#        keys in the clear on disk: divid {found[0]}  irondivid {found[1]}")
    if found[1]:
        fails += 1
        log(f"FAIL   irondivid keeps keys in the clear: {found[1]}")
    else:
        log("PASS   irondivid: no key or phrase in the clear on disk")

    # --- restart ----------------------------------------------------------------------
    for n in NODES:
        n.start()
    status_row("after a restart")
    row("after a restart: getnewaddress", "getnewaddress")

    # --- a backup started on a new node ---------------------------------------------------
    row("locked: backupwallet", "backupwallet", each=lambda n: [os.path.join(WORK, f"backup-{n.name}")])
    # divid reads wallet.dat in its regtest folder; irondivid opens the
    # backup's folder named by -wallet
    d = os.path.join(WORK, "divid-restored", "regtest")
    os.makedirs(d)
    shutil.copy(os.path.join(WORK, "backup-divid"), os.path.join(d, "wallet.dat"))
    restored = [Node("divid-restored", c.binary, 2),
                Node("irondivid-restored", i.binary, 3, [f"wallet={os.path.join(WORK, 'backup-irondivid')}"])]
    old = NODES
    NODES = restored
    found = [scan(os.path.join(WORK, f"backup-{n.name}"), needles(n)) for n in old]
    log(f"#        keys in the clear in the backup: divid {found[0]}  irondivid {found[1]}")
    if found[1]:
        fails += 1
        log(f"FAIL   irondivid's backup holds keys in the clear: {found[1]}")
    else:
        log("PASS   irondivid: no key or phrase in the clear in the backup")
    status_row("restored backup")
    row("restored: walletpassphrase wrong", "walletpassphrase", wrong, 0)
    row("restored: walletpassphrase", "walletpassphrase", pw, 0)
    same = [r.rpc("dumphdinfo")["mnemonic"].encode() == n.mnemonic for r, n in zip(restored, old)]
    report("restored: the same phrase", same[0] == same[1], f"same={same[0]}", f"same={same[1]}")
    for r in restored:
        r.stop()
    NODES = old
    for n in NODES:
        n.stop()

    log(f"FAILS {fails}")
    sys.exit(min(fails, 254))


NODES = []
if __name__ == "__main__":
    main()
