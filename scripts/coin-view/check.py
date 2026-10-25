#!/usr/bin/env python3
"""The coin view of Divi Core divid and irondivid, side by side on one regtest
network: gettxout for one output after another across its life (unconfirmed,
confirmed, spent in the mempool, spent, immature and mature coinbase and
coinstake, a vault), and again after invalidateblock, reconsiderblock, a
restart and -reindex; verifychain at each level and depth and after an unclean
stop; -checklevel and -checkblocks at start; getdifficulty, the difficulty
fields and gettxoutsetinfo across the change from proof of work to proof of
stake. divid mines; irondivid follows it. Each row prints PASS, KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
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
INJECT = os.environ.get("COIN_VIEW_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose or has not closed yet, one per row name:
# (reason, shape). Each is listed in README.md with divid's source line. shape
# takes the two raw outcomes and is true only for the difference described, so
# a KNOWN row that matches divid, or differs in another way, is a FAIL.


def core_aborts(c, i):
    return c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2]


ABORT = ("same message; divid then aborts (SIGABRT) in the shutdown after this early InitError: "
         "PrepareShutdown's FlushStateToDisk (divi/src/init.cpp:381) asserts in ChainstateManager::Get "
         "(divi/src/ChainstateManager.cpp:102) before the chain state exists; irondivid exits 1", core_aborts)
KNOWN = {
    "start -checklevel=4": ABORT,
    "start -checklevel=0": ABORT,
    "start -checklevel=abc": ABORT,
    "gettxout: fields divid lacks": (
        "coinstake, whether the output is a coinstake's, beside coinbase (divid: rpcblockchain.cpp:389-399; "
        "the same row in scripts/chain-replies)", lambda c, i: True),
    "gettxoutsetinfo: fields divid lacks": (
        "bogosize, the size of irondivid's own UTXO records (divid: rpcblockchain.cpp:319-325; "
        "the same row in scripts/chain-replies)", lambda c, i: True),
}
# Members irondivid adds on purpose: compared without them, and named once per
# call in a "<method>: fields divid lacks" row
EXTRA = {"gettxout": "coinstake", "gettxoutsetinfo": "bogosize"}
extra_seen = {m: False for m in EXTRA}

fails = 0


def row(name, core, iron, same, raw=None):
    """same: True when the two outcomes count as equal for this row; raw: the
    two outcomes, for the shape of a KNOWN difference"""
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def iron_row(name, expected, got):
    """A row with no divid counterpart: irondivid against the expected outcome"""
    global fails
    word = "PASS" if expected == got else "FAIL"
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  expected={expected}  irondivid={got}  [irondivid only]", flush=True)


def not_run(name, why):
    print(f"KNOWN  {name}  not run  [known: {why}]", flush=True)


class Node:
    def __init__(self, name, binary, index, extra=()):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"coinview{index}:{password}".encode()).decode()
        self.conf = os.path.join(self.dir, "divi.conf")
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=coinview{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ] + list(extra)
        os.makedirs(self.dir)
        self.write_conf()
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        """divi.conf, 0600; extra lines are for one start only (a key never goes on argv)"""
        tmp = self.conf + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")
        os.replace(tmp, self.conf)

    def launch(self, *args):
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.out, self.err = base + ".out", base + ".err"
        with open(self.out, "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code, first stderr line naming an error)"""
        self.launch(*args)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code, self.error_line())
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.25)
        return ("exit", "none within %d s" % START_TIMEOUT, self.error_line())

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
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

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


# --- how outcomes are compared ---------------------------------------------------

def ordered(v):
    """A reply with its members in the order the node wrote them (amounts stay
    the text the node printed)"""
    if isinstance(v, dict):
        return [[k, ordered(x)] for k, x in v.items()]
    if isinstance(v, list):
        return [ordered(x) for x in v]
    return v


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:80]}\"".replace("\n", "\\n")
    return json.dumps(out[1])[:160]


def first_difference(a, b, path="$"):
    if isinstance(a, dict) and isinstance(b, dict):
        if list(a) != list(b):
            return f"{path} members {list(a)} vs {list(b)}"
        for k in a:
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    if a != b or type(a) is not type(b):
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def compare(name, core, iron):
    """Same outcome: the same error, or the same result with the same members in
    the same order, of the same types, with the same values as printed"""
    if INJECT and INJECT == name:
        iron = ("ok", {"injected": True}) if iron[0] == "ok" else iron[:2] + (iron[2] + " injected",)
    if core[0] == "err" or iron[0] == "err":
        row(name, show(core), show(iron), core == iron, (core, iron))
        return
    d = first_difference(core[1], iron[1])
    row(name, show(core), d or show(iron), d is None and ordered(core[1]) == ordered(iron[1]), (core, iron))


def both(name, method, *params):
    core, iron = D.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok" and isinstance(iron[1], dict) and extra in iron[1]:
        extra_seen[method] = True
        iron = ("ok", {k: v for k, v in iron[1].items() if k != extra})
    compare(name, core, iron)


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


def synced():
    """Same tip and the same mempool on both"""
    return wait_for(lambda: D.rpc("getbestblockhash") == I.rpc("getbestblockhash")
                    and sorted(D.rpc("getrawmempool")) == sorted(I.rpc("getrawmempool")), 90)


def setup(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind_, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- the nodes ---------------------------------------------------------------------

D = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}", "disablewallet=1"])
for n in (D, I):
    setup(n.start() == ("up",), f"{n.name} did not start")
print(f"# divid {D.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def restart(*args):
    """Both stopped and started; the same tip, and then (within 60 s) the same
    mempool if divid's wallet hands its unconfirmed sends back to it"""
    for n in (D, I):
        n.stop()
    for n in (D, I):
        setup(n.start(*args) == ("up",), f"{n.name} did not start again {' '.join(args)}")
    setup(wait_for(lambda: D.rpc("getbestblockhash") == I.rpc("getbestblockhash"), 120),
          f"the nodes do not agree on the tip after the start {' '.join(args)}")
    # divid's wallet takes its unconfirmed sends back at start without relaying
    # them; sendrawtransaction of one in the mempool relays it
    for txid in D.rpc("getrawmempool"):
        D.call("sendrawtransaction", D.rpc("getrawtransaction", txid))
    wait_for(lambda: sorted(D.rpc("getrawmempool")) == sorted(I.rpc("getrawmempool")), 60)


def mine(n):
    D.rpc("setgenerate", n)
    setup(synced(), "irondivid did not follow the miner")


# --- difficulty and the coin set across the change to proof of stake -------------------

def difficulty_rows():
    h = D.rpc("getblockcount")
    both(f"getdifficulty at height {h}", "getdifficulty")
    for method in ("getblockchaininfo", "getinfo"):
        c, i = D.call(method), I.call(method)
        pick = lambda out: ("ok", out[1].get("difficulty")) if out[0] == "ok" else out
        compare(f"{method} difficulty at height {h}", pick(c), pick(i))
    both(f"gettxoutsetinfo at height {h}", "gettxoutsetinfo")


difficulty_rows()
mine(97)
# The last work block on regtest is 100 (chainparams.cpp:405); the stake blocks follow
for _ in range(9):
    mine(1)
    difficulty_rows()
first_stake = D.rpc("getblock", D.rpc("getblockhash", 101))
h106 = D.rpc("getblockcount")

# Outputs only young here: the coinbase of the last work block and the
# coinstake of the tip (20 blocks to maturity, chainparams.cpp:479)
cb100 = D.rpc("getblock", D.rpc("getblockhash", 100))["tx"][0]
tip_block = D.rpc("getblock", D.rpc("getbestblockhash"))
cs_young = tip_block["tx"][1]


def outpoints_of(txid):
    return range(len(D.rpc("getrawtransaction", txid, 1)["vout"]))


def gettxout_rows(when, outputs):
    p = f"{when}: " if when else ""
    for what, txid, n in outputs:
        for flag in ((), (True,), (False,)):
            suffix = "" if not flag else f" includemempool={json.dumps(flag[0])}"
            both(f"{p}gettxout {what} {n}{suffix}", "gettxout", txid, n, *flag)


gettxout_rows(f"at height {h106}", [("coinbase of block 100 (immature)", cb100, 0),
                                     ("coinstake of the tip (immature)", cs_young, 1),
                                     ("coinbase of the tip (empty)", tip_block["tx"][0], 0)])

mine(19)
difficulty_rows()

# The outputs of the life rows
X = D.rpc("getnewaddress")
cs101 = first_stake["tx"][1]
vault = D.rpc("fundvault", f"{D.rpc('getnewaddress')}:{D.rpc('getnewaddress')}", 250)["txhash"]
A = D.rpc("sendtoaddress", X, 10)
mine(1)
# A mature coinbase still unspent (staking and the sends take some of them)
cb1 = next(cb for cb in (D.rpc("getblock", D.rpc("getblockhash", h))["tx"][0] for h in range(1, 101))
           if D.rpc("gettxout", cb, 0) is not None)
# The vault output: the one of 250 DIVI (the other is the change)
vault_n = next(o["n"] for o in D.rpc("getrawtransaction", vault, 1)["vout"] if o["value"] == "250.00000000")
hA = D.rpc("getblockcount")
blockA = D.rpc("getbestblockhash")
a_vout = next(o["n"] for o in D.rpc("getrawtransaction", A, 1)["vout"]
              if X in o["scriptPubKey"].get("addresses", []))
spent_in = D.rpc("getrawtransaction", A, 1)["vin"][0]
# The output of A to X spent by a transaction in the mempool; B unconfirmed
A2 = D.rpc("sendrawtransaction", D.rpc("signrawtransaction", D.rpc(
    "createrawtransaction", [{"txid": A, "vout": a_vout}], {D.rpc("getnewaddress"): 9.99}))["hex"])
B = D.rpc("sendtoaddress", D.rpc("getnewaddress"), 7)
setup(synced(), "irondivid did not get the mempool transactions")
LIFE = [
    ("unconfirmed", B, 0), ("unconfirmed", B, 1),
    ("confirmed, spent in the mempool", A, a_vout), ("confirmed, unspent", A, 1 - a_vout if a_vout < 2 else 0),
    ("spending the mempool output", A2, 0),
    ("spent in a block", spent_in["txid"], spent_in["vout"]),
    ("mature coinbase", cb1, 0), ("mature coinstake", cs101, 1), ("vault", vault, vault_n),
    ("past the last output", A, 99),
]
gettxout_rows("", LIFE)
unknown = "11" * 32
for what, args in (("unknown txid", [unknown, 0]), ("txid not hex", ["xyz", 0]), ("txid too short", ["11", 0]),
                   ("empty txid", ["", 0]), ("negative index", [A, -1]), ("index as text", [A, "0"]),
                   ("index 1.5", [A, 1.5]), ("includemempool as text", [A, 0, "true"]),
                   ("includemempool 1", [A, 0, 1]), ("txid a number", [5, 0]), ("one argument", [A]),
                   ("no arguments", []), ("four arguments", [A, 0, True, 1])):
    both(f"gettxout {what}", "gettxout", *args)

# Back over the outputs and forward again, on both nodes
for n in (D, I):
    n.rpc("invalidateblock", blockA)
setup(wait_for(lambda: D.rpc("getbestblockhash") == I.rpc("getbestblockhash"), 60), "invalidateblock")
time.sleep(1)
both("after invalidateblock: getrawmempool", "getrawmempool")
gettxout_rows("after invalidateblock", LIFE)
for n in (D, I):
    n.rpc("reconsiderblock", blockA)
setup(synced(), "reconsiderblock")
both("after reconsiderblock: getrawmempool", "getrawmempool")
gettxout_rows("after reconsiderblock", LIFE)

restart()
both("after restart: getrawmempool", "getrawmempool")
gettxout_rows("after restart", LIFE)
both("after restart: gettxoutsetinfo", "gettxoutsetinfo")

restart("-reindex")
both("after -reindex: getrawmempool", "getrawmempool")
gettxout_rows("after -reindex", LIFE)
both("after -reindex: gettxoutsetinfo", "gettxoutsetinfo")


# --- verifychain ---------------------------------------------------------------------------

def verifychain_rows(when):
    p = f"{when}: " if when else ""
    tip = D.rpc("getblockcount")
    both(f"{p}verifychain", "verifychain")
    for level in range(5):
        both(f"{p}verifychain {level} 10", "verifychain", level, 10)
    for depth, what in ((0, "0"), (1, "1"), (tip, "the tip height"), (tip + 1, "the tip height + 1"),
                        (-1, "-1")):
        both(f"{p}verifychain 4 {what}", "verifychain", 4, depth)
    for args in ([4, "x"], ["x", 10], [4, 1.5], [1, 2, 3]):
        both(f"{p}verifychain {json.dumps(args)}", "verifychain", *args)
    # One argument: divid reads the depth from the second (rpcblockchain.cpp:419-420),
    # past the end of the array; it crashed on it here, so it is not sent to divid
    out = I.call("verifychain", 10)
    not_run(f"{p}verifychain 10", f"one argument is read past the end of divid's array (rpcblockchain.cpp:419-420) "
            f"and crashes it; irondivid answers {show(out)}")


verifychain_rows("")

# An unclean stop: both killed, then started again
for n in (D, I):
    n.proc.kill()
    n.proc.wait()
    n.proc = None
for n in (D, I):
    setup(n.start() == ("up",), f"{n.name} did not start after being killed")
setup(wait_for(lambda: D.rpc("getbestblockhash") == I.rpc("getbestblockhash"), 120),
      "the nodes do not agree on the tip after the unclean stop")
verifychain_rows("after an unclean stop")
both("after an unclean stop: gettxoutsetinfo", "gettxoutsetinfo")


# --- -checklevel and -checkblocks --------------------------------------------------------------

for n in (D, I):
    n.stop()
for option in ("-checklevel=4", "-checklevel=0", "-checklevel=abc", "-checkblocks=0", "-checkblocks=1",
               "-checkblocks=50", "-checkblocks=-1", "-checkblocks=abc", "-checkblocks=99999999"):
    outs = []
    for n in (D, I):
        out = n.start(option)
        if out == ("up",):
            out = ("up", n.call("getblockcount")[1])
            n.stop()
        outs.append(out)
    row(f"start {option}", json.dumps(outs[0]), json.dumps(outs[1]), outs[0] == outs[1], tuple(outs))

for method, field in EXTRA.items():
    row(f"{method}: fields divid lacks", "-", field if extra_seen[method] else "-", not extra_seen[method],
        (None, None))
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
