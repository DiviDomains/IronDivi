#!/usr/bin/env python3
"""Wallet cases of Divi Core divid that need a chain with stakes, a block taken
off the chain, or a damaged wallet, next to irondivid on regtest:

- a coinbase of the wallet's whose block is invalidated: "orphan"
  (rpcwallet.cpp:2193-2199);
- a lottery block staked by another node that pays the wallet: "lottery"
  entries (rpcwallet.cpp:2082-2110); a lottery block the wallet stakes itself
  after winning: "stake_reward" for a stake over the stake reward, else
  "stake_reward+" (:2049-2081);
- listtransactions of an account other than the stake's ("" by default) leaves
  the stakes out (:2051-2052);
- signmessage with "hex" input that is not all hex (:1389-1395);
- divid only: an encrypted wallet with one imported key's ciphertext damaged,
  then walletpassphrase (crypter.cpp:225-250). irondivid's side of it is a Rust
  test (crates/divi-wallet/tests), as the script cannot damage its database.

S, a divid, mines and stakes; C, a divid wallet; I, an irondivid restored from
C's phrase (WALLET_MNEMONIC), so the twins hold the same keys and parse the
same transactions. Rows print PASS (same as divid), KNOWN (listed in
README.md) or FAIL; exit code = FAILs.

Throwaway keys and phrases are made in the run and go over RPC or into the
run's own 0600 divi.conf files; none is printed or put on a command line.
"""

import base64
import collections
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
INJECT = os.environ.get("WALLET_GAPS_3_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
KNOWN = []

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v, cut=260):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if cut is None else text[:cut]


def first_difference(core, iron):
    """Where two long values first part, as the row is cut at 260 characters"""
    c, i = show(core, cut=None), show(iron, cut=None)
    if len(c) <= 260 and len(i) <= 260:
        return ""
    k = next((n for n, (x, y) in enumerate(zip(c, i)) if x != y), min(len(c), len(i)))
    return f"  [first difference at {k}: divid ...{c[max(0, k - 40):k + 60]}... irondivid ...{i[max(0, k - 40):k + 60]}...]"


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
        note += first_difference(core, iron)
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
            user = "g3" + secrets.token_hex(4)
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


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def key_id(address):
    """A P2PKH address's 20 bytes as map<CKeyID> orders them: a CKeyID compares
    as a little-endian number (uint256.cpp CompareTo), so from its last byte"""
    n = 0
    for ch in address:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes(25, "big")
    return raw[1:21][::-1]


# --- the wallets ---------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}"])
if C.start()[0] != "up":
    raise RuntimeError(f"C did not start: {C.tail()}")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if I.start()[0] != "up":
    raise RuntimeError(f"I did not start: {I.tail()}")
NODES = [S, C, I]
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def block_by(node):
    """One block from `node` with setgenerate; a stake needs the clock past the tip"""
    for _ in range(20):
        tip = node.rpc("getblock", node.rpc("getbestblockhash"))
        wait_for(lambda: time.time() > tip["time"] + 1, 60)
        out = node.call("setgenerate", 1)
        if out[0] == "ok" and node.rpc("getblockcount") > tip["height"]:
            break
        time.sleep(1)
    else:
        raise RuntimeError(f"{node.name} made no block: {out}")
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")
    return node.rpc("getblockcount")


def mine(n=1, by=None):
    for _ in range(n):
        block_by(by or S)


def entries(n, txid, account="*"):
    """The listtransactions entries of `txid`, without the times"""
    return sorted(([e.get("category"), amount(e.get("amount")), e.get("vout"), e.get("account")]
                   for e in n.rpc("listtransactions", account, 1000, 0, True) if e.get("txid") == txid),
                  key=json.dumps)


def tx_of_block(height, k):
    return S.rpc("getblock", S.rpc("getblockhash", height))["tx"][k]


# --- a coinbase whose block is taken off the chain --------------------------------------
# C mines the first blocks; its last coinbase loses its block on both twins
# (rpcwallet.cpp:2193-2199: a coinbase at depth < 1 is "orphan")
mine(5, by=C)
LOST = C.rpc("getblockhash", 5)
LOST_CB = tx_of_block(5, 0)
for n in TWINS:
    n.rpc("invalidateblock", LOST)
wait_for(lambda: all(n.rpc("getblockcount") == 4 for n in TWINS), 60)
both("block 5 invalidated: its coinbase in listtransactions", lambda n: entries(n, LOST_CB))
both("block 5 invalidated: gettransaction of its coinbase: confirmations",
     lambda n: outcome(n.call("gettransaction", LOST_CB), lambda v: v.get("confirmations")))
both("block 5 invalidated: gettransaction of its coinbase: details",
     lambda n: outcome(n.call("gettransaction", LOST_CB),
                       lambda v: [[d.get("category"), amount(d.get("amount"))] for d in v.get("details", [])]))
both("block 5 invalidated: getbalance", lambda n: amount(n.rpc("getbalance")))
for n in TWINS:
    n.rpc("reconsiderblock", LOST)
if not synced():
    raise RuntimeError("the twins did not take block 5 back")
both("block 5 back: its coinbase in listtransactions", lambda n: entries(n, LOST_CB))

# --- coins to stake -------------------------------------------------------------------------
mine(95)
STAKER = C.rpc("getnewaddress")
I.rpc("setaccount", STAKER, "")
SAVINGS = C.rpc("getnewaddress", "savings")
I.rpc("setaccount", SAVINGS, "savings")
# Coins of 12000 at one address: each one stakes alone (divid combines coins
# of one script only while the total stays under half of -stakesplitthreshold,
# 20000 by default, PoSTransactionCreator.cpp:172-210, :358-362), and C's
# lottery winnings come back to that address
for _ in range(6):
    S.rpc("sendtoaddress", STAKER, 12000)
S.rpc("sendtoaddress", SAVINGS, 50)
mine(25)


def lottery(h):
    """A lottery block that is not a treasury block (every 10th from 101, every
    50th from 102 the treasury)"""
    return h >= 101 and h % 10 == 0 and h % 50 != 0


def special(h):
    return (h >= 101 and h % 10 == 0) or (h >= 102 and h % 50 == 0)


def up_to(h):
    """S stakes until the tip is h - 1"""
    while S.rpc("getblockcount") < h - 1:
        block_by(S)


def next_lottery(after):
    h = after + 1
    while not lottery(h):
        h += 1
    return h


# A stake of C's at an ordinary height: "stake_reward+" (rpcwallet.cpp:2049-2081)
h = S.rpc("getblockcount") + 1
while special(h) or special(h + 1):
    block_by(S)
    h = S.rpc("getblockcount") + 1
block_by(C)
PLAIN = tx_of_block(h, 1)
both(f"C's stake at an ordinary height: its entries", lambda n: entries(n, PLAIN))
both(f"C's stake: listtransactions \"\" has it", lambda n: entries(n, PLAIN, ""))
both(f"C's stake: listtransactions \"savings\" has it", lambda n: entries(n, PLAIN, "savings"))

# A cycle in which C stakes, then a lottery block staked by S that pays the
# winners (rpcwallet.cpp:2082-2110: "lottery" at a lottery height)
L1 = next_lottery(S.rpc("getblockcount") + 3)
block_by(C)
while S.rpc("getblockcount") < L1 - 1:
    block_by(S)
block_by(S)
LOT1 = tx_of_block(L1, 1)
print(f"# lottery block {L1} staked by S", flush=True)
both(f"S's lottery block: C's entries", lambda n: entries(n, LOT1))
both(f"S's lottery block: listtransactions \"\" entries", lambda n: entries(n, LOT1, ""))
both(f"S's lottery block: listtransactions \"savings\" entries", lambda n: entries(n, LOT1, "savings"))
both(f"S's lottery block: gettransaction details",
     lambda n: outcome(n.call("gettransaction", LOT1),
                       lambda v: sorted([[d.get("category"), amount(d.get("amount"))] for d in v.get("details", [])],
                                        key=json.dumps)))

# A cycle in which C stakes, then C stakes the lottery block itself: its own
# winnings make the stake more than the stake reward ("stake_reward")
L2 = next_lottery(L1 + 3)
block_by(C)
while S.rpc("getblockcount") < L2 - 1:
    block_by(S)
block_by(C)
LOT2 = tx_of_block(L2, 1)
print(f"# lottery block {L2} staked by C", flush=True)
both(f"C's lottery block: its entries", lambda n: entries(n, LOT2))
both(f"C's lottery block: gettransaction amount, fee and details",
     lambda n: outcome(n.call("gettransaction", LOT2),
                       lambda v: [amount(v.get("amount")), amount(v.get("fee")),
                                  sorted([[d.get("category"), amount(d.get("amount"))] for d in v.get("details", [])],
                                         key=json.dumps)]))
both("after the stakes: getbalance", lambda n: amount(n.rpc("getbalance")))
both("after the stakes: the categories listtransactions \"*\" gives, and how many",
     lambda n: sorted(collections.Counter(e.get("category") for e in n.rpc("listtransactions", "*", 1000)).items()))

# --- signmessage with "hex" input that is not all hex ------------------------------------
# ParseHex stops at the first pair that is not hex and skips spaces between
# bytes (rpcwallet.cpp:1389-1395, utilstrencodings.cpp ParseHex); the twins
# hold the same key and sign deterministically
for text in ("6869zz", "68 69 7a", "zz6869", "686", "6g69", ""):
    both(f'signmessage <C\'s address> "{text}" "hex"', lambda n: outcome(n.call("signmessage", STAKER, text, "hex")))

for n in NODES:
    n.stop()

# --- divid only: one imported key's ciphertext damaged -----------------------------------
# CCryptoKeyStore::Unlock (crypter.cpp:225-250) walks the imported keys in
# CKeyID order: a key that fails first is a wrong passphrase (-14); one that
# fails after a good one logs "The wallet is probably corrupted: Some keys
# decrypt but not all." and stops the node (assert). irondivid's side is the
# Rust test (crates/divi-wallet/tests/encryption_tests.rs).
CORRUPT = "The wallet is probably corrupted: Some keys decrypt but not all."
src = Node("keys-divid", DIVID, 3)
if src.start()[0] != "up":
    raise RuntimeError(f"the key node did not start: {src.tail()}")
held = []
for _ in range(2):
    a = src.rpc("getnewaddress")
    held.append((key_id(a), a, src.rpc("dumpprivkey", a)))
src.stop()
shutil.rmtree(src.dir, ignore_errors=True)
held.sort()
WPASS = secrets.token_hex(12)
for which, name, expected in ((0, "the first", {"reply": {"error": -14,
                                                         "message": "Error: The wallet passphrase entered was incorrect."},
                                                "still up": True, "log: " + CORRUPT: False}),
                              (1, "the second", {"reply": "no reply", "still up": False, "log: " + CORRUPT: True})):
    d = Node(f"damaged-{which}", DIVID, 4)
    if d.start()[0] != "up":
        raise RuntimeError(f"{d.name} did not start: {d.tail()}")
    for _, a, k in held:
        d.rpc("importprivkey", k, "", False)
    pubkey = d.rpc("validateaddress", held[which][1])["pubkey"]
    d.rpc("encryptwallet", WPASS)
    wait_for(lambda: d.rpc("getwalletinfo").get("encryption_status") == "locked", 30)
    d.stop()
    path = os.path.join(d.dir, "regtest", "wallet.dat")
    data = bytearray(open(path, "rb").read())
    key = b"\x04ckey" + bytes([33]) + bytes.fromhex(pubkey)
    i = data.find(key)
    if i < 0:
        raise RuntimeError("the imported key's ckey record is not in wallet.dat")
    while i >= 0:
        # The record's value item sits just before its key item: a 3-byte
        # header, the length 48, then the ciphertext; a byte of its last block
        # is changed
        if data[i - 55:i - 51] != b"\x31\x00\x01\x30":
            raise RuntimeError("the ckey value is not where it was expected")
        data[i - 51 + 40] ^= 0x5A
        i = data.find(key, i + 1)
    with open(path, "wb") as f:
        f.write(bytes(data))
    if d.start()[0] != "up":
        raise RuntimeError(f"{d.name} did not start again: {d.tail()}")
    try:
        out = d.call("walletpassphrase", WPASS, 30)
        reply = outcome(out)
    except RuntimeError:
        reply = "no reply"
    alive = wait_for(lambda: d.proc.poll() is None and d.call("getblockcount")[0] == "ok", 5) if reply != "no reply" else False
    got = {"reply": reply, "still up": alive, "log: " + CORRUPT: CORRUPT in d.new_log()}
    for k in expected:
        row(f"divid only, {name} imported key (by CKeyID) damaged: walletpassphrase: {k}", expected[k], got[k])
    if d.proc is not None and d.proc.poll() is None:
        d.stop()
    else:
        d.proc = None
    shutil.rmtree(d.dir, ignore_errors=True)
del held, WPASS

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
