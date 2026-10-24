#!/usr/bin/env python3
"""Key import/export and wallet-upkeep RPC replies of Divi Core divid and
irondivid, compared call by call.

Both wallets come from the same phrase and sit on one regtest chain. Every call is
made on both nodes with the same arguments, first on unlocked wallets, then after
encryptwallet on locked ones. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase,
the private keys and the passphrases are made by this run, live only in memory and
in RPC requests, and are never printed, logged or put on a command line or in a
file: a row names them by placeholder and shows a secret reply only as hidden.
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
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Calls irondivid has and divid 3.0.0 does not (not in rpcserver.cpp:324-467).
# Each is listed in README.md; a row of one of them is KNOWN while divid answers
# "Method not found" and irondivid answers, and FAIL otherwise, so the list stays true.
IRONDIVID_ONLY = {
    "bip38encrypt": "divid has bip38paperwallet only (rpcdump.cpp:249-293)",
    "setstakesplitthreshold": "divid takes -stakesplitthreshold at start only",
    "getstakesplitthreshold": "divid takes -stakesplitthreshold at start only",
    "reservebalance": "divid has no reservebalance call in 3.0.0",
}

# Differences irondivid has on purpose, by row name. Each is listed in README.md
# with divid's source line; a KNOWN row that starts to match divid is a FAIL, so
# the list stays true.
KNOWN = {
    "bip38decrypt <encrypted key> <wrong passphrase>":
        "divid does not check the address hash and adds whatever key comes out "
        "(bip38.cpp:131-178, rpcdump.cpp:313-343); irondivid refuses with -4 \"Failed To Decrypt\"",
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(word, name, core, iron, note=""):
    global fails
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    line = f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}".replace("\n", "\\n")
    print(line[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
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


# --- how replies are compared ------------------------------------------------------

def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Reals are compared as each node
    writes them (the text of the number)."""
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
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def same_usage(a, b):
    """A wrong argument count is answered with the call's help as a -1 error;
    each program words its help itself (divid's bip38paperwallet help even
    starts with "bip38encrypt"), so two help texts agree as help texts"""
    return "\n" in a and "\n" in b


def short(out, hide):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:80]}\""
    if hide:
        return "(hidden)"
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def compare(name, core, iron, hide=False, norm=None):
    """Same outcome; for an error the same code and text (a help reply by its usage
    line); for a result the same value. `hide`: the result holds a secret and is
    shown only as hidden. `norm`: applied to both results before comparing."""
    method = name.split(" ", 1)[0]
    if method in IRONDIVID_ONLY:
        absent = core[0] == "err" and core[1] == -32601
        answered = not (iron[0] == "err" and iron[1] == -32601)
        word = "KNOWN" if absent and answered else "FAIL"
        note = f"  [known: irondivid only; {IRONDIVID_ONLY[method]}]" if word == "KNOWN" \
            else "  [listed as irondivid only, but divid answers or irondivid does not: update README.md]"
        row(word, name, short(core, hide), short(iron, hide), note)
        return
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1] == iron[1] and \
            (core[2] == iron[2] or (core[1] == -1 and same_usage(core[2], iron[2])))
        shown = short(iron, hide)
    else:
        a, b = core[1], iron[1]
        if norm:
            a, b = norm(a), norm(b)
        d = first_difference(a, b)
        if d and hide:
            d = "results differ (hidden)"
        same, shown = d is None, d or short(iron, hide)
    if name in KNOWN:
        word = "FAIL" if same else "KNOWN"
        note = "  [listed as KNOWN but now matches divid: update README.md]" if same \
            else "  [known: " + KNOWN[name] + "]"
        row(word, name, short(core, hide), shown, note)
        return
    row("PASS" if same else "FAIL", name, short(core, hide), shown)


def both(name, method, *params, hide=False, norm=None, iron_params=None):
    core = C.call(method, *params)
    iron = I.call(method, *(params if iron_params is None else iron_params))
    compare(name, core, iron, hide=hide, norm=norm)
    return core, iron


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


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def fresh_key():
    """A new compressed regtest private key in WIF (Divi Core regtest SECRET_KEY
    prefix 239, chainparams.cpp:428)"""
    return b58check(bytes([239]) + secrets.token_bytes(32) + b"\x01")


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 60)


# --- the nodes -----------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

C.rpc("setgenerate", 25)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# An address both wallets own (the first of the phrase) and one nobody holds a
# key for (regtest P2PKH version 139, random bytes)
X = C.rpc("getnewaddress")
I.rpc("setaccount", X, "")
W = b58check(bytes([139]) + secrets.token_bytes(20))
KEY1, KEY2, KEY3 = fresh_key(), fresh_key(), fresh_key()
PASS1 = secrets.token_urlsafe(18)


def addresses_of(label):
    return lambda node: sorted(node.rpc("getaddressesbyaccount", label))


# --- unlocked wallets -------------------------------------------------------------------

def unlocked():
    # importprivkey (rpcdump.cpp:41-103)
    both("importprivkey <key1> imported1 false", "importprivkey", KEY1, "imported1", False)
    both("getaddressesbyaccount imported1 (after the import)", "getaddressesbyaccount", "imported1")
    a1 = C.rpc("getaddressesbyaccount", "imported1")
    # Core sets the label before it sees the key is held (rpcdump.cpp:79-84)
    both("importprivkey <key1> again (already held)", "importprivkey", KEY1)
    both("getaddressesbyaccount imported1 (label cleared by the import again)", "getaddressesbyaccount", "imported1")
    both("importprivkey <key2> imported2 (rescan by default)", "importprivkey", KEY2, "imported2")
    both("importprivkey <key3> \"\" true", "importprivkey", KEY3, "", True)
    both("importprivkey (no argument)", "importprivkey")
    both("importprivkey <key1> a b c d (four arguments)", "importprivkey", KEY1, "a", True, 1)
    both("importprivkey 1 (not a string)", "importprivkey", 1)
    both("importprivkey <key1> 7 (label not a string)", "importprivkey", KEY1, 7)
    both("importprivkey <key1> x \"yes\" (rescan not a bool)", "importprivkey", KEY1, "x", "yes")
    both("importprivkey <key1 with a changed character>", "importprivkey", KEY1[:-1] + ("1" if KEY1[-1] != "1" else "2"))

    # importaddress (rpcdump.cpp:105-168)
    both("importaddress <watched> watch false", "importaddress", W, "watch", False)
    both("importaddress <watched> again", "importaddress", W)
    both("getaddressesbyaccount watch", "getaddressesbyaccount", "watch")
    both("importaddress <own address>", "importaddress", X)
    both("importaddress notanaddress", "importaddress", "notanaddress")
    both("importaddress <script hex> script false", "importaddress", "76a914" + "ab" * 20 + "88ac", "script", False)
    both("importaddress zz (bad hex)", "importaddress", "zz")
    both("importaddress (no argument)", "importaddress")
    both("importaddress 1 (not a string)", "importaddress", 1)
    both("importaddress <watched> watch \"no\" (rescan not a bool)", "importaddress", W, "watch", "no")

    # dumpprivkey (rpcdump.cpp:170-198); unknown and script addresses are in
    # crates/divi-rpc/tests/core_replies.rs key_errors
    both("dumpprivkey <own address>", "dumpprivkey", X, hide=True)
    both("dumpprivkey <imported1 address>", "dumpprivkey", a1[0], hide=True)
    both("dumpprivkey <watched address>", "dumpprivkey", W)
    both("dumpprivkey notanaddress", "dumpprivkey", "notanaddress")
    both("dumpprivkey (no argument)", "dumpprivkey")
    both("dumpprivkey 1 (not a string)", "dumpprivkey", 1)
    c = C.call("dumpprivkey", a1[0])
    row("PASS" if c == ("ok", KEY1) else "FAIL", "dumpprivkey <imported1 address> gives the imported key back",
        "(hidden)", "-")
    i = I.call("dumpprivkey", a1[0])
    row("PASS" if i == ("ok", KEY1) else "FAIL", "dumpprivkey <imported1 address> gives the imported key back (irondivid)",
        "-", "(hidden)")

    # dumpwallet and importwallet: in neither program (rpcserver.cpp:324-467)
    dump = os.path.join(WORK, "dump.txt")
    both("dumpwallet <file in the run directory>", "dumpwallet", dump)
    both("importwallet <file in the run directory>", "importwallet", dump)
    row("PASS" if not os.path.exists(dump) else "FAIL", "dumpwallet wrote no file", "-", "-")

    # backupwallet (rpcwallet.cpp:2525-2542)
    both("backupwallet <new path>", "backupwallet", os.path.join(WORK, "backup-divid"),
         iron_params=[os.path.join(WORK, "backup-irondivid")])
    both("backupwallet <the same path again>", "backupwallet", os.path.join(WORK, "backup-divid"),
         iron_params=[os.path.join(WORK, "backup-irondivid")])
    both("backupwallet <a folder that does not exist>/x", "backupwallet",
         os.path.join(WORK, "missing-divid", "x"), iron_params=[os.path.join(WORK, "missing-irondivid", "x")])
    both("backupwallet (no argument)", "backupwallet")
    both("backupwallet 1 (not a string)", "backupwallet", 1)

    # keypoolrefill (rpcwallet.cpp:2544-2568)
    both("keypoolrefill", "keypoolrefill")
    both("keypoolrefill 0 (the default size)", "keypoolrefill", 0)
    both("keypoolrefill 5", "keypoolrefill", 5)
    both("keypoolrefill 1200", "keypoolrefill", 1200)
    both("keypoolrefill -1", "keypoolrefill", -1)
    both("keypoolrefill \"5\" (not an int)", "keypoolrefill", "5")
    both("keypoolrefill 5 5 (two arguments)", "keypoolrefill", 5, 5)
    both("getwalletinfo keypoolsize after keypoolrefill 1200", "getwalletinfo",
         norm=lambda v: v.get("keypoolsize") if isinstance(v, dict) else v)

    # walletverify and settxfee: in neither program
    both("walletverify", "walletverify")
    both("settxfee 0.001", "settxfee", 0.001)

    # bip38: divid's bip38paperwallet makes a fresh key and its encrypted form
    # (rpcdump.cpp:249-293); bip38decrypt adds it to the wallet (:295-340)
    paper = C.rpc("bip38paperwallet", PASS1)
    ip = I.call("bip38paperwallet", PASS1)
    row("PASS" if ip[0] == "ok" and sorted(ip[1]) == sorted(paper) else "FAIL",
        "bip38paperwallet <passphrase>: Address and Encrypted Key", ",".join(sorted(paper)),
        ",".join(sorted(ip[1])) if ip[0] == "ok" else short(ip, True))
    both("bip38paperwallet (no argument)", "bip38paperwallet")
    encrypted = paper["Encrypted Key"]
    both("bip38decrypt <divid's encrypted key> <passphrase>", "bip38decrypt", encrypted, PASS1, hide=True)
    both("bip38decrypt <the same key again> (already held)", "bip38decrypt", encrypted, PASS1, hide=True)
    both("bip38decrypt <encrypted key> <wrong passphrase>", "bip38decrypt", encrypted, PASS1 + "x", hide=True)
    both("bip38decrypt notakey <passphrase>", "bip38decrypt", "notakey", PASS1, hide=True)
    both("bip38decrypt <encrypted key> (one argument)", "bip38decrypt", encrypted, hide=True)
    both("bip38decrypt 1 <passphrase> (not a string)", "bip38decrypt", 1, PASS1, hide=True)
    # Each node decrypts a key the other made: the BIP38 forms agree
    if ip[0] == "ok":
        both("bip38decrypt <irondivid's encrypted key> <passphrase>", "bip38decrypt",
             ip[1]["Encrypted Key"], PASS1, hide=True)
    paper2 = C.rpc("bip38paperwallet", PASS1)
    both("bip38decrypt <a second key of divid's> <passphrase>", "bip38decrypt",
         paper2["Encrypted Key"], PASS1, norm=lambda v: v, hide=False)
    both("bip38encrypt <own address> <passphrase>", "bip38encrypt", X, PASS1, hide=True)
    both("bip38encrypt (no argument)", "bip38encrypt", hide=True)

    # Stake split threshold and reserve balance: irondivid only
    both("getstakesplitthreshold", "getstakesplitthreshold")
    both("setstakesplitthreshold 30000", "setstakesplitthreshold", 30000)
    both("setstakesplitthreshold -1", "setstakesplitthreshold", -1)
    both("setstakesplitthreshold (no argument)", "setstakesplitthreshold")
    both("reservebalance (show)", "reservebalance")
    both("reservebalance true 100 (set)", "reservebalance", True, 100)
    both("reservebalance false (unset)", "reservebalance", False)
    both("reservebalance true (no amount)", "reservebalance", True)


def locked():
    """The same calls on locked wallets: the ones divid unlocks for answer -13"""
    both("importprivkey <new key> (locked)", "importprivkey", fresh_key(), "", False)
    both("importaddress <watched> (locked)", "importaddress", W, "watch", False)
    both("dumpprivkey <own address> (locked)", "dumpprivkey", X, hide=True)
    both("dumpprivkey notanaddress (locked)", "dumpprivkey", "notanaddress")
    both("backupwallet <new path> (locked)", "backupwallet", os.path.join(WORK, "backup-locked-divid"),
         iron_params=[os.path.join(WORK, "backup-locked-irondivid")])
    both("keypoolrefill (locked)", "keypoolrefill")
    both("keypoolrefill -1 (locked)", "keypoolrefill", -1)
    both("bip38paperwallet <passphrase> (locked)", "bip38paperwallet", PASS1, hide=True)
    both("bip38decrypt notakey <passphrase> (locked)", "bip38decrypt", "notakey", PASS1, hide=True)
    both("bip38encrypt <own address> <passphrase> (locked)", "bip38encrypt", X, PASS1, hide=True)
    both("setstakesplitthreshold 20000 (locked)", "setstakesplitthreshold", 20000)
    both("reservebalance true 100 (locked)", "reservebalance", True, 100)


unlocked()

# Encrypt both wallets with a passphrase made by this run (rpcwallet.cpp:2690-2740)
WALLET_PASS = secrets.token_urlsafe(18)
both("encryptwallet <passphrase>", "encryptwallet", WALLET_PASS)
for n in (C, I):
    # divid 3.0.0 keeps running after encryptwallet ("Wallet reloaded!"); a node
    # that stopped is started again
    if n.proc.poll() is not None:
        n.log.close()
        n.start()
        if not n.wait_ready():
            print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
            sys.exit(1)
both("getwalletinfo unlocked_until (locked)", "getwalletinfo",
     norm=lambda v: v.get("unlocked_until") if isinstance(v, dict) else v)
locked()

# Unlocked again with the passphrase: the key calls answer as before
both("walletpassphrase <passphrase> 60", "walletpassphrase", WALLET_PASS, 60)
both("dumpprivkey <own address> (unlocked again)", "dumpprivkey", X, hide=True)
both("importprivkey <new key> (unlocked again)", "importprivkey", fresh_key(), "", False)
both("walletlock", "walletlock")
both("dumpprivkey <own address> (locked again)", "dumpprivkey", X, hide=True)
del WALLET_PASS

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
