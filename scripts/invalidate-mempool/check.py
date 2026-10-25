#!/usr/bin/env python3
"""The mempool during invalidateblock and reconsiderblock, on two Divi Core
divid nodes and two irondivid nodes, compared row by row.

Pair C is two divid nodes connected to each other; pair I is two irondivid nodes
connected to each other, restored from the phrases of their divid twins. Each
row makes one kind of send on node 1 of both pairs from the same coins (picked
by confirmations, so the two sides spend coins of the same age), places it in
the mempool or in a block 1 to 3 deep, then calls invalidateblock on node 1 at
depth 1 to 3 and reconsiderblock. Both nodes' mempools are sampled, by the
label of each transaction, before, right after each call and once both nodes
settle. A sample that differs between the pairs is a DIFFERS row, printed with
the divid and irondivid log lines on the row's transactions. Exit code = the
number of DIFFERS rows not listed in KNOWN.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases live only in memory, in RPC replies and in irondivid's environment.
"""

import base64
import json
import os
import random
import secrets
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
SEED = int(os.environ.get("SEED") or 1)
# Rows to run: "all" (every kind, depth and placement), or a comma-separated
# list of kind:depth:placement
ROWS = os.environ.get("ROWS", "all")
# Seconds to wait after the settle for divid's mempool rebroadcast (a random
# time within 30 minutes, main.cpp:1280-1294) before the last sample
RESEND_WAIT = int(os.environ.get("RESEND_WAIT") or 0)
# A folder to copy the four logs to at the end
LOGS = os.environ.get("INVALIDATE_MEMPOOL_LOGS", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 180
SETTLE_TIMEOUT = 45
FEE = 0.001

# Rows where divid's behaviour is accidental and irondivid keeps its own:
# (kind, placement) -> reason with the Core line
KNOWN = {}


def log(line):
    print(line, flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"im{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=im{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log_offset, self.log_inode = 0, None
        self.start()

    def start(self):
        out = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
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

    def log_path(self):
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(path):
                return path
        return None

    def new_log_lines(self):
        """The log lines written since the last call. irondivid moves a full
        debug.log to debug.log.1 and starts a new one, so a log that is no
        longer the file read last is finished from debug.log.1."""
        path = self.log_path()
        if not path:
            return []
        text = ""
        inode = os.stat(path).st_ino
        if self.log_inode is not None and inode != self.log_inode:
            rotated = path + ".1"
            if os.path.exists(rotated) and os.stat(rotated).st_ino == self.log_inode:
                with open(rotated, errors="replace") as f:
                    f.seek(self.log_offset)
                    text = f.read()
            self.log_offset = 0
        with open(path, errors="replace") as f:
            f.seek(self.log_offset)
            text += f.read()
            self.log_offset = f.tell()
        self.log_inode = inode
        return text.splitlines()

    def call(self, method, *params):
        """('ok', result), ('err', code, message), or ('down',)"""
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


class Pair:
    def __init__(self, name, nodes):
        self.name, self.nodes = name, nodes
        self.labels = {}  # txid -> label of the row that made it
        self.last_made = None
        self.inputs = {}  # label -> the inputs of the row's transaction: (confirmations, kind)

    def settle(self, mempools=True):
        """Both nodes connected and on one tip, and the two mempools equal or
        still for 8 s"""
        a, b = self.nodes
        deadline = time.time() + SETTLE_TIMEOUT
        last, steady = None, 0
        while time.time() < deadline:
            try:
                if a.rpc("getconnectioncount") < 1 or b.rpc("getconnectioncount") < 1:
                    time.sleep(0.5)
                    continue
                tips = (a.rpc("getbestblockhash"), b.rpc("getbestblockhash"))
                pools = (sorted(a.rpc("getrawmempool")), sorted(b.rpc("getrawmempool")))
            except RuntimeError:
                time.sleep(0.5)
                continue
            if tips[0] == tips[1] and (not mempools or pools[0] == pools[1]):
                return True
            steady = steady + 1 if (tips, pools) == last else 0
            last = (tips, pools)
            if tips[0] == tips[1] and steady >= 16:
                return True
            time.sleep(0.5)
        return False

    def mempool_labels(self, node):
        return sorted(self.labels.get(t, "?" + t[:8]) for t in node.rpc("getrawmempool"))


def both(fn):
    with ThreadPoolExecutor(2) as ex:
        return list(ex.map(fn, PAIRS))


# --- transactions ------------------------------------------------------------------------

def varint(data, i):
    n = data[i]
    if n < 0xfd:
        return n, i + 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
    return int.from_bytes(data[i + 1:i + 1 + size], "little"), i + 1 + size


def with_lock_time(hex_tx, lock_time):
    """An unsigned transaction from createrawtransaction (which takes no lock
    time in Divi Core 3.0.0) with nLockTime set and every input's sequence
    0xfffffffe, so the lock time applies"""
    data = bytearray(bytes.fromhex(hex_tx))
    n_in, i = varint(data, 4)
    for _ in range(n_in):
        i += 36
        script_len, i = varint(data, i)
        i += script_len
        data[i:i + 4] = struct.pack("<I", 0xfffffffe)
        i += 4
    data[-4:] = struct.pack("<I", lock_time)
    return data.hex()


def coins(node):
    """Spendable coins as (confirmations, amount, generated, txid, vout), oldest first"""
    out = []
    for c in node.rpc("listunspent", 0):
        tx = node.rpc("gettransaction", c["txid"])
        out.append((c["confirmations"], c["amount"], bool(tx.get("generated")), c["txid"], c["vout"]))
    return sorted(out, key=lambda c: (-c[0], float(c[1])))


# A coinbase or coinstake output this deep stays mature after any depth 1 to
# 3 invalidate (maturity 20)
DEEP = 25


def input_class(coin):
    """How a row's input is compared between the pairs: "mature" when no depth
    1 to 3 invalidate can make it immature, else its confirmations"""
    if not coin[2] or coin[0] >= DEEP:
        return "mature"
    return f"generated {coin[0]}"


def pick(node, how):
    """The coins a row spends. `old` and `old8`: the oldest one or eight coins
    that no depth 1 to 3 invalidate can make immature (not a coinbase or
    coinstake output, or one with at least DEEP confirmations); the pairs stake
    from different coins, so their exact ages differ. `age<n>`: a coinbase or
    coinstake output with exactly n confirmations, the same on both pairs."""
    have = [c for c in coins(node) if c[0] >= 1 and (not c[2] or c[0] >= DEEP)]
    # large enough for the row's 10 DIVI send and fee
    if how == "old":
        return [c for c in have if float(c[1]) >= 20][:1]
    if how == "old8":
        return [c for c in have if float(c[1]) >= 1][:8]
    return [generated_at(node, int(how[3:]))]


def generated_at(node, age):
    """Node's largest unspent coinstake (or coinbase) output in the block with
    `age` confirmations. listunspent leaves out what the wallet counts as
    immature (under 21 confirmations), so the block is read instead."""
    height = node.rpc("getblockcount") - age + 1
    block = node.rpc("getblock", node.rpc("getblockhash", height))
    for txid in block["tx"][:2]:
        got = node.call("gettransaction", txid)
        if got[0] != "ok":
            continue
        tx = node.rpc("decoderawtransaction", got[1]["hex"])
        outs = []
        for o in tx["vout"]:
            addresses = o.get("scriptPubKey", {}).get("addresses", [])
            if float(o["value"]) > 0 and addresses and node.rpc("validateaddress", addresses[0]).get("ismine") \
                    and node.rpc("gettxout", txid, o["n"]):
                outs.append((age, o["value"], True, txid, o["n"]))
        if outs:
            return max(outs, key=lambda c: float(c[1]))
    raise RuntimeError(f"{node.name}: no own coinbase or coinstake output at height {height}")


def raw_spend(node, chosen, lock_time=None, fee=FEE):
    total = sum(float(c[1]) for c in chosen)
    inputs = [{"txid": c[3], "vout": c[4]} for c in chosen]
    unsigned = node.rpc("createrawtransaction", inputs, {node.rpc("getnewaddress"): round(total - fee, 8)})
    if lock_time is not None:
        unsigned = with_lock_time(unsigned, lock_time)
    signed = node.rpc("signrawtransaction", unsigned)
    if not signed.get("complete"):
        raise RuntimeError(f"{node.name}: signrawtransaction incomplete")
    return node.call("sendrawtransaction", signed["hex"])


def with_only(node, chosen, fn):
    """Run a wallet RPC with every other coin locked, so the wallet spends the
    chosen coins and nothing else"""
    others = [{"txid": c[3], "vout": c[4]} for c in coins(node) if (c[3], c[4]) not in {(x[3], x[4]) for x in chosen}]
    node.rpc("lockunspent", False, others)
    try:
        return fn()
    finally:
        node.rpc("lockunspent", True)


def make(pair, kind, stage):
    """Make the row's transaction(s) of `kind` on node 1; `stage` is "parent"
    for the first half of a child row. Returns [(label, outcome)]"""
    n1, n2 = pair.nodes
    made = []

    def keep(label, out, chosen):
        if out[0] == "ok" and isinstance(out[1], dict):
            out = ("ok", out[1]["txhash"])  # fundvault (rpcwallet.cpp:1060)
        if out[0] == "ok":
            pair.labels[out[1]] = label
        pair.inputs[label] = sorted(input_class(c) for c in chosen)
        if out[0] != "ok":
            out = (out[0], out[1], f"{out[2]} [spending {[(c[0], c[1], c[2]) for c in chosen]}]")
        made.append((label, out if out[0] != "ok" else ("ok",)))
        pair.last_made = (label, out)

    if kind == "plain":
        chosen = pick(n1, "old")
        keep("plain", with_only(n1, chosen, lambda: n1.call("sendtoaddress", n2.rpc("getnewaddress"), 10)), chosen)
    elif kind == "child" and stage == "parent":
        chosen = pick(n1, "old")
        keep("parent", with_only(n1, chosen, lambda: n1.call("sendtoaddress", n1.rpc("getnewaddress"), 10)), chosen)
    elif kind == "child":
        parents = [t for t, label in pair.labels.items() if label == "parent"]
        out = [c for c in coins(n1) if c[3] == parents[-1] and float(c[1]) == 10.0]
        if not out:
            have = [c[:2] for c in coins(n1) if c[3] == parents[-1]]
            raise RuntimeError(f"{n1.name}: no 10 DIVI output of the parent {parents[-1][:16]}; its coins: {have}; "
                               f"last send: {pair.last_made}")
        keep("child", raw_spend(n1, out), out)
    elif kind in ("age20", "age21"):
        chosen = pick(n1, kind)
        keep(kind, raw_spend(n1, chosen), chosen)
    elif kind == "vault":
        chosen = pick(n1, "old")
        spec = f"{n1.rpc('getnewaddress')}:{n2.rpc('getnewaddress')}"
        keep("vault", with_only(n1, chosen, lambda: n1.call("fundvault", spec, 10)), chosen)
    elif kind == "locktime":
        chosen = pick(n1, "old")
        keep("locktime", raw_spend(n1, chosen, lock_time=n1.rpc("getblockcount")), chosen)
    elif kind == "large":
        chosen = pick(n1, "old8")
        keep("large", raw_spend(n1, chosen, fee=0.01), chosen)
    else:
        raise RuntimeError(f"unknown kind {kind}")
    return made


# --- rows ----------------------------------------------------------------------------------

KINDS = ["plain", "child", "age20", "age21", "vault", "locktime", "large"]
# mempool: unconfirmed at the invalidate; top: in the tip block; deep: in the
# lowest block the invalidate takes off; split (child only): the parent in the
# lowest block taken off, the child unconfirmed
PLACEMENTS = {"child": ["mempool", "top", "deep", "split"]}


def all_rows():
    rows = []
    for kind in KINDS:
        for placement in PLACEMENTS.get(kind, ["mempool", "top", "deep"]):
            for depth in (1, 2, 3):
                if placement == "deep" and depth == 1:
                    continue  # the same as top
                rows.append((kind, depth, placement))
    random.Random(SEED).shuffle(rows)
    return rows


def mine(pair, blocks, node=0):
    """Blocks from node 1 (so it has coinstake outputs of every age), or from
    node 2 with node=1"""
    pair.nodes[node].rpc("setgenerate", blocks)
    if not pair.settle(mempools=False):
        raise RuntimeError(f"{pair.name} did not settle after mining")


def clear():
    """Mine on both pairs alike until every mempool is empty (a locked-time
    transaction waits for its height), so the two chains keep one height"""
    for _ in range(6):
        if not any(n.rpc("getrawmempool") for pair in PAIRS for n in pair.nodes):
            break
        both(lambda pair: mine(pair, 1))
        # what only node 2 holds (node 1 dropped it) goes in node 2's block
        if any(n.rpc("getrawmempool") for pair in PAIRS for n in pair.nodes):
            both(lambda pair: mine(pair, 1, node=1))
    heights = [pair.nodes[0].rpc("getblockcount") for pair in PAIRS]
    if heights[0] != heights[1] or any(n.rpc("getrawmempool") for pair in PAIRS for n in pair.nodes):
        raise RuntimeError(f"mempools not empty after 6 blocks, or heights apart: {heights}")


def build(pair, kind, depth, placement):
    """Make and place the row's transactions; returns the creation outcomes"""
    made = []
    if placement == "mempool":
        mine(pair, depth)
        made += make(pair, kind, "parent")
        if kind == "child":
            pair.settle()
            made += make(pair, kind, "child")
    elif placement == "top":
        if depth > 1:
            mine(pair, depth - 1)
        made += make(pair, kind, "parent")
        if kind == "child":
            pair.settle()
            made += make(pair, kind, "child")
        pair.settle()
        mine(pair, 1)
    elif placement == "deep":
        made += make(pair, kind, "parent")
        if kind == "child":
            pair.settle()
            made += make(pair, kind, "child")
        pair.settle()
        mine(pair, depth)
    elif placement == "split":
        made += make(pair, kind, "parent")
        pair.settle()
        mine(pair, depth)
        made += make(pair, kind, "child")
    pair.settle()
    return made


def sample(pair):
    return {f"node{i + 1}": pair.mempool_labels(n) for i, n in enumerate(pair.nodes)}


def run_row(pair, kind, depth, placement):
    n1 = pair.nodes[0]
    for n in pair.nodes:
        n.new_log_lines()
    made = build(pair, kind, depth, placement)
    samples = {"before": sample(pair)}
    height = n1.rpc("getblockcount")
    target = n1.rpc("getblockhash", height - depth + 1)
    out_inv = n1.call("invalidateblock", target)
    samples["after invalidateblock"] = sample(pair)
    samples["middle height"] = n1.rpc("getblockcount")
    out_rec = n1.call("reconsiderblock", target)
    samples["after reconsiderblock"] = sample(pair)
    pair.settle()
    samples["settled"] = sample(pair)
    if RESEND_WAIT:
        time.sleep(RESEND_WAIT)
        samples["after resend wait"] = sample(pair)
    outcomes = [(label, o[0] if o[0] == "ok" else f"error {o[1]} {o[2]}"[:300]) for label, o in made]
    samples["inputs"] = {label: pair.inputs.get(label) for label, _ in made}
    outcomes += [("invalidateblock", out_inv[0]), ("reconsiderblock", out_rec[0])]
    logs = {}
    for i, n in enumerate(pair.nodes):
        mine_ids = [t for t in pair.labels if pair.labels[t] in {l for l, _ in made}]
        logs[f"node{i + 1}"] = [line for line in n.new_log_lines()
                                if "RPC re" not in line
                                and (any(t in line or t[:16] in line for t in mine_ids)
                                     or "Reorg:" in line or ("mempool" in line.lower() and "remov" in line.lower()))]
    return {"outcomes": outcomes, "samples": samples, "logs": logs}


def setup(pair):
    a, b = pair.nodes
    # 100 work blocks (the last work block on regtest is 100), then stake
    # blocks from node 1, so node 1 has coinstake outputs of every age
    for node, blocks in ((a, 60), (b, 40), (a, 30)):
        node.rpc("setgenerate", blocks)
        if not pair.settle():
            raise RuntimeError(f"{pair.name} did not settle after the first blocks")
    # Plain coins for node 1 (no invalidate can make them immature), as
    # node 1's staking uses up its old coins
    b.rpc("sendmany", "", {a.rpc("getnewaddress"): 25 for _ in range(150)})
    pair.settle()
    mine(pair, 1)


def keep_logs():
    if not LOGS:
        return
    import shutil
    os.makedirs(LOGS, exist_ok=True)
    for pair in PAIRS:
        for node in pair.nodes:
            path = node.log_path()
            if path:
                shutil.copy(path, os.path.join(LOGS, f"{node.name}.log"))


def main():
    global PAIRS
    log(f"# invalidate-mempool: SEED={SEED} ROWS={ROWS} RESEND_WAIT={RESEND_WAIT}")
    c1 = Node("divid1", DIVID, 0, ["listen=1", "debug=mempool"])
    c2 = Node("divid2", DIVID, 1, ["listen=0", f"connect={HOST}:{PORT_BASE}", "debug=mempool"])
    phrases = [c1.rpc("dumphdinfo")["mnemonic"], c2.rpc("dumphdinfo")["mnemonic"]]
    i1 = Node("irondivid1", IRONDIVID, 2, ["listen=1", "debug=1"], env={"WALLET_MNEMONIC": phrases[0]})
    i2 = Node("irondivid2", IRONDIVID, 3, ["listen=0", f"connect={HOST}:{PORT_BASE + 4}", "debug=1"],
              env={"WALLET_MNEMONIC": phrases[1]})
    del phrases
    PAIRS = [Pair("divid", [c1, c2]), Pair("irondivid", [i1, i2])]
    both(setup)
    rows = all_rows() if ROWS == "all" else [
        (k, int(d), p) for k, d, p in (r.split(":") for r in ROWS.split(","))]
    differs = 0
    for kind, depth, placement in rows:
        name = f"{kind}:{depth}:{placement}"
        try:
            clear()
            c, i = both(lambda pair: run_row(pair, kind, depth, placement))
        except Exception as e:  # a row that cannot be built ends the run
            log(f"FAIL   {name:24} setup: {e}"[:400])
            differs += 1
            break
        diff = [k for k in c["samples"] if c["samples"][k] != i["samples"][k]]
        if c["outcomes"] != i["outcomes"]:
            diff.insert(0, "outcomes")
        if not diff:
            log(f"PASS   {name:24} {c['samples']['after invalidateblock']['node1']} -> {c['samples']['settled']['node1']}")
            continue
        known = KNOWN.get((kind, placement))
        tag = "KNOWN " if known else "DIFFERS"
        if not known:
            differs += 1
        log(f"{tag} {name:24} at: {', '.join(diff)}" + (f"  [{known}]" if known else ""))
        for k in ["outcomes"] + list(c["samples"]):
            cv = c[k] if k == "outcomes" else c["samples"][k]
            iv = i[k] if k == "outcomes" else i["samples"][k]
            log(f"#   {k}: divid {json.dumps(cv)} irondivid {json.dumps(iv)}")
        for side, res in (("divid", c), ("irondivid", i)):
            for node, lines in res["logs"].items():
                for line in lines[-12:]:
                    log(f"#   {side} {node} log: {line[:300]}")
        # the two pairs no longer agree on their mempools: start the next row
        # from empty ones
    keep_logs()
    log(f"# {len(rows)} rows")
    log(f"DIFFERS {differs}")
    for pair in PAIRS:
        for node in pair.nodes:
            node.stop()
    sys.exit(min(differs, 254))


PAIRS = []
if __name__ == "__main__":
    main()
