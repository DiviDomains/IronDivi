#!/usr/bin/env python3
"""Chain inspection and repair calls of Divi Core divid and irondivid, compared
step by step: invalidateblock, reconsiderblock, getchaintips, verifychain,
gettxoutsetinfo, getblockchaininfo, getblock and getblockheader around them,
and the fee estimate calls.

Both nodes are given one regtest chain with a stale block (divid mines it,
irondivid follows), then cut apart, and the same steps are driven on each.
Block hashes and txids are shown as labels (a<height> for the shared chain,
s45 for its stale block, n<height> for a block each node mined on its own in
the same step), so replies of two nodes that mined their own blocks still
compare. Each row prints PASS, KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("CHAIN_ADMIN_INJECT", "")
DUMP = os.environ.get("CHAIN_ADMIN_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 180
HOST = "127.0.0.2"

# Differences irondivid keeps, by row name, each listed in README.md with the
# reason. A KNOWN row that starts to match divid is a FAIL, so the list stays true.
R1 = "divid 3.0.0 has no fee estimate calls; irondivid answers them (docs/divid-differences.md R1)"
TIE = ("equal work after invalidateblock: divid moves to the branch it received first in this run "
       "(CBlockIndexWorkComparator, BlockIndexWork.h:11-28; after a restart, memory address order); "
       "irondivid keeps its tip, as both do for blocks that arrive")
GENESIS = ("invalidateblock of the genesis block: divid answers null and rolls its chain and wallet back "
           "to height 0 (BlockInvalidationHelpers.cpp:133-143); irondivid refuses it, -20")
KNOWN = {
    **{f"{when}: {call} 2": R1 for when in ("no data", "F mempool", "F blocks", "F after restart")
       for call in ("estimatefee", "estimatesmartfee")},
    "no data: estimatepriority 2": R1,
    "D side invalid: getchaintips": (
        "a tip above an invalidated block of its side branch: divid reads only the tip's own flags "
        "(rpcblockchain.cpp:531-533), valid-fork; irondivid looks down the branch, invalid, as getchaintips' "
        "help defines it (\"This branch contains at least one invalid block\")"),
    **{f"D equal work: {c}": TIE for c in ("getchaintips", "getblockchaininfo", "getbestblockhash",
                                           "gettxoutsetinfo")},
    **{f"G: {c}": GENESIS for c in ("invalidateblock a0", "getchaintips", "getblockchaininfo",
                                    "getbestblockhash", "gettxoutsetinfo", "getbalance")},
}
# getblockchaininfo headers: divid keeps its best header (pindexBestHeader) through
# invalidateblock and reconsiderblock, so it can name an invalid block's height or
# lag behind blocks after a restart (ChainSyncHelpers.cpp:17-23); irondivid
# names its best header on a valid chain. Compared in a row of its own that prints
# KNOWN when they differ and is never counted
HEADERS_NOTE = "divid's best header is not moved by invalidateblock or reconsiderblock (README.md)"

# Members irondivid adds on purpose (compared without them)
EXTRA = {
    "getblockchaininfo": {"fullhistorypeers", "lastblockfetch", "mediantime", "pruned", "pruneheight",
                          "snapshotbase", "warnings", "winnersstripheight"},
    "getblock": {"mediantime", "nTx"},
    "getblockheader": {"chainwork", "confirmations", "difficulty", "hash", "height", "mediantime", "nTx"},
    "gettxoutsetinfo": {"bogosize"},
}

fails = 0


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    line = f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}".replace("\n", " ")
    print(line[:600], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"admin{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=admin{index}", f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", "dnsseed=0", "staking=0", "txindex=1",
        ]
        self.write_conf(extra_conf)
        self.log = None
        self.labels = {}
        self.start()

    def write_conf(self, extra_conf):
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra_conf)) + "\n")

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
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
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", f"http {e.code}", "")
        except (OSError, ValueError) as e:
            return ("err", "no reply", f"{type(e).__name__}: {e}"[:120])
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
            if self.call("getblockcount")[0] == "ok":
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def restart(self, extra_conf=None):
        self.stop()
        if extra_conf is not None:
            self.write_conf(extra_conf)
        self.start()
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not start again")

    def label(self, v):
        """Hashes the run knows replaced by their labels, at any depth"""
        if isinstance(v, dict):
            return {k: self.label(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.label(x) for x in v]
        if isinstance(v, str) and len(v) == 64 and v in self.labels:
            return self.labels[v]
        return v

    def hash_of(self, label):
        return next(h for h, l in self.labels.items() if l == label)


SHARED = {}


def label_all(lab, h):
    for n in (C, I):
        n.labels[h] = lab


# --- comparing ---------------------------------------------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
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
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid: {json.dumps(a)[:200]} vs {json.dumps(b)[:200]}"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if type(a) is not type(b) or a != b:
        return f"{path}: {json.dumps(a)[:90]} vs {json.dumps(b)[:90]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:100]}\""
    return json.dumps(out[1])[:160]


def compare(name, core, iron, drop=frozenset(), order=None, method=""):
    if INJECT and INJECT == name:
        iron = ("ok", "injected") if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if not same and core[0] == iron[0] == "err" and core[1] == iron[1] == -1 and method \
                and (core[2].startswith(method + " ") or core[2].startswith(method + "\n")):
            same = True  # a wrong argument count: divid's text is its whole help
        if DUMP and not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return same
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        dump(name, ("ok", a), ("ok", b))
    row(name, short(("ok", a)), d or "same", d is None)
    return d is None


def dump(name, core, iron):
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def both(name, method, *params, drop=frozenset(), order=None, args=None, keep=None):
    """The same call on both nodes; `args(node)` builds per-node params (a label
    turned into that node's hash)"""
    pc = args(C) if args else params
    pi = args(I) if args else params
    core, iron = C.call(method, *pc), I.call(method, *pi)
    if core[0] == "ok":
        core = ("ok", C.label(core[1]))
    if iron[0] == "ok":
        iron = ("ok", I.label(strip(iron[1], EXTRA.get(method, set()))))
    if keep:
        core = ("ok", {k: v for k, v in core[1].items() if k in keep}) if core[0] == "ok" else core
        iron = ("ok", {k: v for k, v in iron[1].items() if k in keep}) if iron[0] == "ok" else iron
    return compare(name, core, iron, drop=drop, order=order, method=method)


def on(label):
    return lambda n: [n.hash_of(label)]


TIP_ORDER = lambda t: (-t["height"], t["hash"])  # noqa: E731  (divid orders equal heights by memory address)


def state(step, utxo_same=True):
    """The chain as each node shows it"""
    both(f"{step}: getchaintips", "getchaintips", order=TIP_ORDER)
    both(f"{step}: getblockchaininfo", "getblockchaininfo", drop=frozenset({"headers"}))
    core, iron = C.rpc("getblockchaininfo")["headers"], I.rpc("getblockchaininfo")["headers"]
    word = "PASS" if core == iron else "KNOWN"
    note = "" if core == iron else f"  [known: {HEADERS_NOTE}]"
    print(f"{word:<5}  {step}: getblockchaininfo headers  divid={core}  irondivid={iron}{note}", flush=True)
    both(f"{step}: getbestblockhash", "getbestblockhash")
    both(f"{step}: getrawmempool", "getrawmempool", order=str)
    drop = frozenset() if utxo_same else frozenset({"hash_serialized"})
    both(f"{step}: gettxoutsetinfo", "gettxoutsetinfo", drop=drop)
    both(f"{step}: getbalance", "getbalance")


def mine_each(step, count):
    """Each node mines `count` blocks of its own; they get the same labels"""
    for n in (C, I):
        start = n.rpc("getblockcount")
        n.rpc("setgenerate", count)
        for h in range(start + 1, start + count + 1):
            n.labels[n.rpc("getblockhash", h)] = f"n{h}{step}"


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


def setup_failed(kind_, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

# --- the shared chain -----------------------------------------------------------------

# Regtest turns on divid's block index self-check, which mainnet and testnet leave
# off; with it, divid stops on an assertion after some reconsiderblock steps
# below (BlockCheckingHelpers.cpp:231), so it runs as a live node does
C = Node("divid", DIVID, 0, ["listen=1", "checkblockindex=0"])
if not C.wait_ready():
    print("FAIL   start: divid did not answer", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I_CONF = ["listen=0", f"connect={HOST}:{PORT_BASE}"]
I = Node("irondivid", IRONDIVID, 1, I_CONF, env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print("FAIL   start: irondivid did not answer", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120)


# Fee estimates with no data at all: before any block
both("no data: estimatefee 2", "estimatefee", 2)
both("no data: estimatesmartfee 2", "estimatesmartfee", 2)
both("no data: estimatepriority 2", "estimatepriority", 2)

C.rpc("setgenerate", 40)
X = C.rpc("getnewaddress")
sends = {}
for h, amount in ((41, 10), (42, 5), (43, 3)):
    sends[C.rpc("sendtoaddress", X, amount)] = f"t{h}"
    C.rpc("setgenerate", 1)
C.rpc("setgenerate", 2)
# irondivid must hold block 45 before divid replaces it, or it never sees the stale block
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
# The stale block: 45 is replaced by a longer branch, then reconsidered
old45 = C.rpc("getblockhash", 45)
C.rpc("invalidateblock", old45)
C.rpc("setgenerate", 2)
C.rpc("reconsiderblock", old45)
if not synced() or I.call("getblockheader", old45)[0] != "ok":
    print("FAIL   setup: irondivid did not follow divid's chain and its stale block", flush=True)
    sys.exit(1)
for h in range(0, C.rpc("getblockcount") + 1):
    label_all(f"a{h}", C.rpc("getblockhash", h))
label_all("s45", old45)
for txid, lab in sends.items():
    label_all(lab, txid)

# Cut irondivid off: from here each node only sees its own steps
I.restart(["listen=0", f"connect={HOST}:1"])
if not wait_for(lambda: C.rpc("getconnectioncount") == 0, 60):
    print("FAIL   setup: divid still has a peer", flush=True)
    sys.exit(1)
print(f"# shared chain to a46, stale s45; nodes cut apart", flush=True)

# --- A: one chain, the same on both -----------------------------------------------------

state("A")
both("A: getblock s45", "getblock", args=on("s45"))
both("A: getblockheader s45", "getblockheader", args=on("s45"))
both("A: getblock a45", "getblock", args=on("a45"))
both("A: verifychain", "verifychain")
for level, depth in ((0, 0), (4, 10), (3, 1000), (1, 1), (4, -1)):
    both(f"A: verifychain {level} {depth}", "verifychain", level, depth)
both("A: verifychain 4 0 \"x\"", "verifychain", 4, 0, "x")

UNKNOWN = "00" * 31 + "01"
for m in ("invalidateblock", "reconsiderblock"):
    both(f"A: {m} unknown hash", m, UNKNOWN)
    both(f"A: {m} not a hash", m, "xyz")
    both(f"A: {m} number", m, 5)
    both(f"A: {m} none", m)
    both(f"A: {m} two", m, args=lambda n: [n.hash_of("a10"), 1])
both("A: reconsiderblock a10 (not invalid)", "reconsiderblock", args=on("a10"))
state("A after reconsider a10")
both("A: getchaintips 1", "getchaintips", 1)
both("A: gettxoutsetinfo 1", "gettxoutsetinfo", 1)

# --- B: invalidate a43, three blocks deep with sends -----------------------------------

both("B: invalidateblock a43", "invalidateblock", args=on("a43"))
state("B")
both("B: getblock a43", "getblock", args=on("a43"))
both("B: getblockheader a43", "getblockheader", args=on("a43"))
both("B: getblock a42 (tip)", "getblock", args=on("a42"))
both("B: getblock a44", "getblock", args=on("a44"))
both("B: gettransaction t43", "gettransaction", keep={"confirmations", "blockhash", "amount", "fee"},
     args=lambda n: [n.hash_of("t43")])
both("B: verifychain 4 0", "verifychain", 4, 0)
both("B: invalidateblock a43 again", "invalidateblock", args=on("a43"))
both("B: invalidateblock a44 (above it)", "invalidateblock", args=on("a44"))
state("B again")
# Reconsidering a block above the invalid one clears its ancestors too
both("B: reconsiderblock a45 (above it)", "reconsiderblock", args=on("a45"))
state("B reconsidered")
both("B: getblock a43 after", "getblock", args=on("a43"))

# --- D: a reorganization onto blocks each node mines -----------------------------------

both("D: invalidateblock a45", "invalidateblock", args=on("a45"))
state("D invalidated")
mine_each("", 3)
state("D mined", utxo_same=False)
# a45-a46 has less work than n45-n47: it stays a side branch
both("D: reconsiderblock a45", "reconsiderblock", args=on("a45"))
state("D reconsidered", utxo_same=False)
both("D: getblock a46", "getblock", args=on("a46"))
both("D: getblockheader a46", "getblockheader", args=on("a46"))
# A block of the side branch under its tip
both("D: invalidateblock a45 (side branch)", "invalidateblock", args=on("a45"))
state("D side invalid", utxo_same=False)
both("D: reconsiderblock a45 (side branch)", "reconsiderblock", args=on("a45"))
state("D side reconsidered", utxo_same=False)
# Equal work: invalidating n47 leaves n46 and a46 at one height and work
both("D: invalidateblock n47", "invalidateblock", args=on("n47"))
state("D equal work", utxo_same=False)
both("D: reconsiderblock n47", "reconsiderblock", args=on("n47"))
state("D back", utxo_same=False)

# --- E: invalidate below the fork point ------------------------------------------------

both("E: invalidateblock a44", "invalidateblock", args=on("a44"))
state("E", utxo_same=True)
both("E: reconsiderblock a44", "reconsiderblock", args=on("a44"))
state("E reconsidered", utxo_same=False)
both("E: invalidateblock a44 again", "invalidateblock", args=on("a44"))
# Reconsidering the side branch's tip clears its ancestors, not the other branch
both("E: reconsiderblock a46 (side tip)", "reconsiderblock", args=on("a46"))
state("E side tip", utxo_same=False)
both("E: reconsiderblock n47", "reconsiderblock", args=on("n47"))
state("E both", utxo_same=False)

# --- F: fees with transactions, then a restart ------------------------------------------

Y = C.rpc("getnewaddress")
for n in (C, I):
    n.labels[n.rpc("sendtoaddress", Y, 1)] = "w1"
    n.labels[n.rpc("sendtoaddress", Y, 2)] = "w2"
both("F mempool: estimatefee 2", "estimatefee", 2)
both("F mempool: estimatesmartfee 2", "estimatesmartfee", 2)
both("F mempool: getinfo relayfee", "getinfo", keep={"relayfee"})
both("F: gettransaction w1 fee", "gettransaction", keep={"fee", "amount"}, args=lambda n: [n.hash_of("w1")])
mine_each("f", 1)
both("F blocks: estimatefee 2", "estimatefee", 2)
both("F blocks: estimatesmartfee 2", "estimatesmartfee", 2)
# Leave an invalid block over the restart
both("F: invalidateblock tip", "invalidateblock", args=lambda n: [n.rpc("getbestblockhash")])
state("F before restart", utxo_same=False)
C.restart()
I.restart()
state("F after restart", utxo_same=False)
both("F after restart: estimatefee 2", "estimatefee", 2)
both("F after restart: estimatesmartfee 2", "estimatesmartfee", 2)
both("F after restart: verifychain", "verifychain")
both("F after restart: reconsiderblock tip", "reconsiderblock", args=lambda n: [n.hash_of(f"n{n.rpc('getblockcount') + 1}f")])
state("F after reconsider", utxo_same=False)

# --- G: the genesis block, last (divid may not survive it) ------------------------------

both("G: invalidateblock a0", "invalidateblock", args=on("a0"))
state("G", utxo_same=False)
both("G: reconsiderblock a0", "reconsiderblock", args=on("a0"))
state("G reconsidered", utxo_same=False)

print(f"FAILS {fails}", flush=True)
for n in (C, I):
    n.stop()
sys.exit(min(fails, 254))
