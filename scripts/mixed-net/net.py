#!/usr/bin/env python3
"""Three Divi Core divid and three irondivid nodes on one regtest network, run
for HOURS with traffic, restarts, an unclean stop, a node joining from nothing
and two partitions that mine apart and rejoin; every node must keep agreeing on
the chain and the mempool.

Every random choice comes from SEED: the links (each node 2-3 peers, both kinds,
the graph connected), which node mines each block, the sends and their amounts,
the steps and their order. Blocks come only from setgenerate (staking is off),
spread over both kinds, so each kind makes blocks the other must take.

Agreement: every running node in one connected part has the same best hash within
60 s of the last block, and every transaction sent (that every node can take) is in
every mempool within 60 s. A snapshot of every node (best hash and height, mempool,
chain tips, peers and ban scores) is written every 30 s and 60 s after each rejoin.
On the first lasting disagreement the run records the seed, the step, each node's
view and the last 200 lines of each debug.log, and stops.

Run by run.sh, which owns the work directory and stops the nodes. Wallet keys are
throwaway regtest keys made in the run's datadirs; none is printed or put on a
command line.
"""

import base64
import json
import os
import random
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK, OUT = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
SEED = int(os.environ.get("SEED", "1"))
HOURS = float(os.environ.get("HOURS", "1"))
# BURST=1: the 100 work blocks are mined in rotation with no wait between them, the
# nodes racing each other, then one agreement check; the run stops there
BURST = os.environ.get("BURST") == "1"
NODE_IP = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
AGREE_SECS = 60
SNAPSHOT_SECS = 30
SAT = 100_000_000

rng = random.Random(SEED)
started_at = time.time()
end_at = started_at + HOURS * 3600
stats = {"seed": SEED, "hours": HOURS, "steps": 0, "blocks": 0, "transactions": 0, "reorgs": [],
         "restarts": 0, "unclean stops": 0, "joined": None, "partitions": 0, "send errors": {}}
step_log = []  # (step number, what)
events = open(os.path.join(OUT, f"seed{SEED}.jsonl"), "w")


def note(kind, **data):
    events.write(json.dumps({"t": round(time.time() - started_at, 1), "kind": kind, **data}) + "\n")
    events.flush()


def say(text):
    print(f"[{time.time() - started_at:7.0f}s] {text}", flush=True)


# --- nodes -----------------------------------------------------------------------------

class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code} {message}")
        self.code, self.message = code, message


class Node:
    def __init__(self, index, kind):
        self.index, self.kind = index, kind
        self.name = f"{kind}{index}"
        self.binary = DIVID if kind == "divid" else IRONDIVID
        self.dir = os.path.join(WORK, self.name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"mn{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser=mn{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1", "dnsseed=0",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "staking=0", "debug=net",
        ]
        os.makedirs(self.dir, exist_ok=True)
        self.proc = None
        self.peers = []  # nodes this one connects out to

    def write_conf(self, connect_to):
        tmp = os.path.join(self.dir, "divi.conf.new")
        lines = self.base + [f"connect={NODE_IP}:{n.p2p}" for n in connect_to]
        if not connect_to:
            lines.append(f"connect={NODE_IP}:1")  # none: -connect with no reachable peer
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def start(self, connect_to):
        self.write_conf(connect_to)
        log = open(os.path.join(self.dir, "stdout.log"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, stdout=log, stderr=log,
                                     start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                with open(os.path.join(self.dir, "stdout.log"), errors="replace") as f:
                    said = f.read().strip().splitlines()[-8:]
                with open(os.path.join(OUT, f"seed{SEED}-{self.name}-start-failure.log"), "w") as f:
                    f.write("\n".join(said + ["--- debug.log"] + self.log_tail(80)) + "\n")
                raise RuntimeError(f"{self.name} exited at start with {self.proc.returncode}: {' | '.join(said)[-400:]}")
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.5)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s")

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        if reply.get("error"):
            raise RpcError(reply["error"].get("code"), reply["error"].get("message", ""))
        return reply.get("result")

    def rpc(self, method, *params):
        return self.call(method, *params)

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if not self.running():
            self.proc = None
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def kill(self):
        if self.running():
            os.kill(self.proc.pid, signal.SIGKILL)
            self.proc.wait()
        self.proc = None

    def log_tail(self, n=200):
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(path):
                with open(path, errors="replace") as f:
                    return f.read().splitlines()[-n:]
        return []


# --- the network -----------------------------------------------------------------------

def draw_links(nodes):
    """Each node 2-3 peers, at least one of the other kind, the graph connected: a random
    spanning tree over the nodes, then edges added until every node has 2-3 and both kinds"""
    order = nodes[:]
    rng.shuffle(order)
    edges = set()
    for k in range(1, len(order)):
        a, b = order[k], rng.choice(order[:k])
        edges.add(frozenset((a.index, b.index)))

    def degree(n):
        return sum(1 for e in edges if n.index in e)

    def kinds(n):
        return {nodes[j].kind for e in edges if n.index in e for j in e if j != n.index}

    for _ in range(200):
        need = [n for n in nodes if degree(n) < 2 or len(kinds(n)) < 2]
        if not need:
            break
        n = rng.choice(need)
        options = [m for m in nodes if m is not n and frozenset((n.index, m.index)) not in edges and degree(m) < 3
                   and (len(kinds(n)) == 2 or m.kind != n.kind)]
        if options and degree(n) < 3:
            edges.add(frozenset((n.index, rng.choice(options).index)))
    return edges


def connect_lists(nodes, edges, allowed=None):
    """Each edge becomes one outbound connect= line, on its lower-indexed end"""
    out = {n.index: [] for n in nodes}
    by = {n.index: n for n in nodes}
    for e in edges:
        a, b = sorted(e)
        if allowed is None or (a in allowed and b in allowed) or (a not in allowed and b not in allowed):
            if a in by and b in by:
                out[a].append(by[b])
    return out


def parts(nodes, edges):
    """The connected parts of the running nodes"""
    alive = {n.index for n in nodes if n.running()}
    seen, out = set(), []
    for n in nodes:
        if n.index not in alive or n.index in seen:
            continue
        group, todo = set(), [n.index]
        while todo:
            x = todo.pop()
            if x in group:
                continue
            group.add(x)
            todo += [y for e in edges if x in e for y in e if y != x and y in alive]
        seen |= group
        out.append(sorted(group))
    return out


KINDS = ["divid", "divid", "divid", "irondivid", "irondivid", "irondivid"]
rng.shuffle(KINDS)
NODES = [Node(i, k) for i, k in enumerate(KINDS)]
EDGES = draw_links(NODES)
ACTIVE_EDGES = set(EDGES)


def start_all(nodes, edges):
    lists = connect_lists(NODES, edges)
    for n in nodes:
        n.start(lists[n.index])


# --- views and agreement ---------------------------------------------------------------

def view(n):
    """What one node shows; None for a node not running or not answering"""
    if not n.running():
        return {"running": False}
    try:
        return {
            "running": True,
            "height": n.rpc("getblockcount"),
            "best": n.rpc("getbestblockhash"),
            "mempool": sorted(n.rpc("getrawmempool")),
            "tips": [(t.get("height"), t.get("hash"), t.get("status")) for t in n.rpc("getchaintips")],
            "peers": sorted((p.get("addr"), p.get("banscore")) for p in n.rpc("getpeerinfo")),
        }
    except Exception as e:
        return {"running": True, "error": str(e)[:200]}


def snapshot(why):
    views = {n.name: view(n) for n in NODES if n.running()}
    note("snapshot", why=why, views={k: {kk: vv for kk, vv in v.items() if kk != "tips"} | {"tips": len(v.get("tips", []))}
                                     for k, v in views.items()})
    return views


def disagreement(what, detail):
    """Record everything about the first lasting disagreement, and stop the run"""
    views = {n.name: view(n) for n in NODES}
    dump = {"seed": SEED, "step": stats["steps"], "what": what, "detail": detail, "steps": step_log[-60:],
            "views": views, "links": sorted(sorted(e) for e in ACTIVE_EDGES),
            "kinds": {n.name: n.kind for n in NODES}}
    with open(os.path.join(OUT, f"seed{SEED}-disagreement.json"), "w") as f:
        json.dump(dump, f, indent=1)
    for n in NODES:
        with open(os.path.join(OUT, f"seed{SEED}-{n.name}-debug-tail.log"), "w") as f:
            f.write("\n".join(n.log_tail()) + "\n")
    say(f"DISAGREEMENT at step {stats['steps']}: {what}: {json.dumps(detail)[:400]}")
    finish(1)


def wait_chain(group_nodes, why, tie_breaks=1):
    """The group's running nodes share one best hash within AGREE_SECS. Tips of equal
    height are a tie, which both kinds keep until a block comes on one of them (the
    first block seen stays, as in Divi Core): one more block is mined to break it"""
    deadline = time.time() + AGREE_SECS
    while True:
        try:
            bests = {n.name: n.rpc("getbestblockhash") for n in group_nodes if n.running()}
        except Exception as e:
            bests = {"error": str(e)[:100]}
        if len(set(bests.values())) == 1:
            return next(iter(bests.values()))
        if time.time() > deadline:
            heights = {}
            for n in group_nodes:
                try:
                    heights[n.name] = n.rpc("getblockcount")
                except Exception:
                    heights[n.name] = None
            if tie_breaks > 0 and len(set(heights.values())) == 1 and None not in heights.values():
                note("tie", why=why, height=next(iter(heights.values())))
                mine(rng.choice([n for n in group_nodes if n.running()]))
                return wait_chain(group_nodes, f"{why}, then a block to break a tie", tie_breaks - 1)
            disagreement(f"best hash after {why}", {"best": bests, "height": heights})
        time.sleep(1)


def wait_mempool(group_nodes, txids, why):
    """Every txid is in every running node's mempool of the group within AGREE_SECS (or
    mined by then: the group's best chain holds it)"""
    deadline = time.time() + AGREE_SECS
    while True:
        missing = {}
        for n in group_nodes:
            if not n.running():
                continue
            pool = set(n.rpc("getrawmempool"))
            left = [t for t in txids if t not in pool]
            # mined meanwhile: no longer expected in the mempool
            left = [t for t in left if not in_chain(n, t)]
            if left:
                missing[n.name] = [t[:16] for t in left]
        if not missing:
            return
        if time.time() > deadline:
            disagreement(f"mempool after {why}", {"missing": missing})
        time.sleep(1)


def in_chain(n, txid):
    try:
        tx = n.rpc("getrawtransaction", txid, 1)
        return bool(tx.get("blockhash"))
    except Exception:
        return False


def wait_links(nodes, edges, secs=90):
    """Every running node has its links of `edges` up before anything is mined: a block
    announced before a peer connects is never announced to it, and a node fetches only
    from its outbound peers (main.cpp:1301-1311), on divid as on irondivid"""
    deadline = time.time() + secs
    want = {n.index: sum(1 for e in edges if n.index in e and all(NODES[i].running() for i in e))
            for n in nodes if n.running()}
    while time.time() < deadline:
        try:
            if all(NODES[i].rpc("getconnectioncount") >= k for i, k in want.items()):
                return
        except Exception:
            pass
        time.sleep(1)
    have = {}
    for i in want:
        try:
            have[NODES[i].name] = NODES[i].rpc("getconnectioncount")
        except Exception:
            have[NODES[i].name] = None
    disagreement("links did not come up", {"want": {NODES[i].name: k for i, k in want.items()}, "have": have})


def group_of(n):
    for g in parts(NODES, ACTIVE_EDGES):
        if n.index in g:
            return [NODES[i] for i in g]
    return [n]


def everyone():
    return [n for n in NODES if n.running()]


# --- steps -----------------------------------------------------------------------------

def address_of(n):
    return n.rpc("getnewaddress")


def mine(n, count=1, among=None):
    """count blocks by n; a node with no coin to stake (one that joined from nothing)
    hands the block to another running node of `among` (default every node)"""
    for _ in range(count):
        others = [m for m in (among or NODES) if m is not n and m.running()]
        rng.shuffle(others)
        for m in [n] + others:
            try:
                m.rpc("setgenerate", 1)
                break
            except RpcError as e:
                note("setgenerate refused", node=m.name, error=str(e)[:100])
                time.sleep(1)
        else:
            raise RuntimeError(f"no node of {[x.name for x in [n] + others]} could make a block")
        stats["blocks"] += 1


def balance(n):
    return float(n.rpc("getbalance"))


def sent(n, txid, why):
    stats["transactions"] += 1
    note("send", node=n.name, txid=txid, why=why)
    return txid


def step_mine():
    n = rng.choice(everyone())
    mine(n)
    wait_chain(group_of(n), f"a block by {n.name}")
    return f"{n.name} mines 1"


def step_race():
    """A divid and an irondivid each mine a block at the same moment, as two miners
    finding blocks close together do: the blocks race, one side reorganizes"""
    import threading
    alive = everyone()
    a = rng.choice([n for n in alive if n.kind == "divid"] or alive)
    b = rng.choice([n for n in alive if n.kind == "irondivid" and n is not a] or [n for n in alive if n is not a])
    count = rng.randint(1, 3)
    errors = []

    def run(n):
        try:
            for _ in range(count):
                n.rpc("setgenerate", 1)
                stats["blocks"] += 1
        except Exception as e:
            errors.append(f"{n.name}: {e}")

    threads = [threading.Thread(target=run, args=(n,)) for n in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wait_chain(everyone(), f"{a.name} and {b.name} mining {count} at once")
    return f"{a.name} and {b.name} mine {count} each at once{' (' + '; '.join(errors) + ')' if errors else ''}"


def step_send():
    a, b = rng.sample(everyone(), 2)
    amount = round(rng.uniform(0.5, min(50, max(0.6, balance(a) / 4))), 8)
    try:
        txid = sent(a, a.rpc("sendtoaddress", address_of(b), amount), "send")
    except RpcError as e:
        stats["send errors"][e.message[:60]] = stats["send errors"].get(e.message[:60], 0) + 1
        return f"{a.name} send {amount} to {b.name}: refused {e.code}"
    wait_mempool(group_of(a), [txid], f"{a.name} sends {amount} to {b.name}")
    return f"{a.name} sends {amount} to {b.name}"


def step_dust():
    a, b = rng.sample(everyone(), 2)
    try:
        txid = sent(a, a.rpc("sendtoaddress", address_of(b), 0.00001), "dust")
        wait_mempool(group_of(a), [txid], f"{a.name} sends dust")
        return f"{a.name} sends dust to {b.name}"
    except RpcError as e:
        return f"{a.name} dust to {b.name}: refused {e.code}"


def step_sendmany():
    a = rng.choice(everyone())
    to = {}
    for b in rng.sample([n for n in everyone() if n is not a], k=min(3, len(everyone()) - 1)):
        to[address_of(b)] = round(rng.uniform(0.1, 5), 8)
    try:
        txid = sent(a, a.rpc("sendmany", "", to), "sendmany")
    except RpcError as e:
        return f"{a.name} sendmany: refused {e.code}"
    wait_mempool(group_of(a), [txid], f"{a.name} sendmany")
    return f"{a.name} sendmany to {len(to)}"


def step_whole_balance():
    a, b = rng.sample(everyone(), 2)
    bal = a.rpc("getbalance")
    if float(bal) < 1:
        return f"{a.name} whole balance: too little"
    try:
        txid = sent(a, a.rpc("sendtoaddress", address_of(b), float(bal), "receiver_pays"), "whole balance")
    except RpcError as e:
        return f"{a.name} whole balance to {b.name}: refused {e.code} {e.message[:60]}"
    wait_mempool(group_of(a), [txid], f"{a.name} sends its whole balance")
    return f"{a.name} sends its whole balance {bal} to {b.name}"


def step_raw():
    """A transaction made and signed on one node, sent from another"""
    a = rng.choice(everyone())
    coins = [u for u in a.rpc("listunspent", 1) if float(u["amount"]) > 1.01]
    if not coins:
        return f"{a.name} raw: no coin"
    u = rng.choice(coins)
    b = rng.choice(everyone())
    raw = a.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]}],
                {address_of(b): round(float(u["amount"]) - 0.001, 8)})
    hexed = a.rpc("signrawtransaction", raw)["hex"]
    via = rng.choice(everyone())
    try:
        txid = sent(via, via.rpc("sendrawtransaction", hexed), "raw")
    except RpcError as e:
        return f"raw from {a.name} via {via.name}: refused {e.code}"
    wait_mempool(group_of(via), [txid], f"a raw transaction of {a.name} sent by {via.name}")
    return f"raw transaction of {a.name} sent by {via.name}"


VAULTS = []  # (owner node, txid)


def step_vault_fund():
    owner, manager = rng.sample(everyone(), 2)
    try:
        out = owner.rpc("fundvault", f"{address_of(owner)}:{address_of(manager)}", round(rng.uniform(5, 20), 8))
    except RpcError as e:
        return f"{owner.name} fundvault: refused {e.code}"
    txid = out["txhash"] if isinstance(out, dict) else out
    sent(owner, txid, "fundvault")
    VAULTS.append(owner)
    wait_mempool(group_of(owner), [txid], f"{owner.name} funds a vault managed by {manager.name}")
    return f"{owner.name} funds a vault managed by {manager.name}"


def step_vault_reclaim():
    owners = [o for o in VAULTS if o.running()]
    if not owners:
        return "reclaim: no vault"
    owner = rng.choice(owners)
    try:
        txid = sent(owner, owner.rpc("reclaimvaultfunds", address_of(owner), 1), "reclaim")
    except RpcError as e:
        return f"{owner.name} reclaim: refused {e.code} {e.message[:50]}"
    wait_mempool(group_of(owner), [txid], f"{owner.name} reclaims from its vault")
    return f"{owner.name} reclaims 1 from its vault"


def far_pair():
    """Two running nodes as far apart in the graph as there are"""
    best, pair = -1, None
    alive = everyone()
    for a in alive:
        dist, todo = {a.index: 0}, [a.index]
        while todo:
            x = todo.pop(0)
            for e in ACTIVE_EDGES:
                if x in e:
                    for y in e:
                        if y not in dist and NODES[y].running():
                            dist[y] = dist[x] + 1
                            todo.append(y)
        for b in alive:
            if b.index in dist and dist[b.index] > best and b is not a:
                best, pair = dist[b.index], (a, b)
    return pair


def step_double_spend():
    """One coin spent twice, each spend sent to a node far from the other; once a block
    holds one, no mempool may keep the other"""
    a = rng.choice(everyone())
    coins = [u for u in a.rpc("listunspent", 1) if float(u["amount"]) > 1.01]
    if not coins:
        return f"{a.name} double spend: no coin"
    u = rng.choice(coins)
    spends = []
    for _ in range(2):
        raw = a.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]}],
                    {address_of(rng.choice(everyone())): round(float(u["amount"]) - 0.001, 8)})
        spends.append(a.rpc("signrawtransaction", raw)["hex"])
    x, y = far_pair()
    ids = []
    for node, hexed in ((x, spends[0]), (y, spends[1])):
        try:
            ids.append(node.rpc("sendrawtransaction", hexed))
        except RpcError as e:
            ids.append(f"refused {e.code}")
    time.sleep(10)
    m = rng.choice(everyone())
    mine(m)
    wait_chain(group_of(m), "a block after a double spend")
    time.sleep(AGREE_SECS / 2)
    holders = {n.name: [t[:16] for t in ids if len(t) == 64 and t in n.rpc("getrawmempool")] for n in everyone()}
    mined = [t for t in ids if len(t) == 64 and in_chain(m, t)]
    if any(holders.values()) and mined:
        disagreement("a spend of a mined coin left in a mempool", {"mined": mined, "held": holders})
    note("double spend", ids=ids, mined=mined, to=[x.name, y.name])
    return f"double spend of a coin of {a.name} sent to {x.name} and {y.name}; mined {[t[:8] for t in mined]}"


def settle():
    """Mine until every mempool is empty (at most 5 blocks), so a restart loses no transaction"""
    for _ in range(5):
        if all(not n.rpc("getrawmempool") for n in everyone()):
            return
        m = rng.choice(everyone())
        mine(m)
        wait_chain(everyone(), "a block that empties the mempools")
        time.sleep(5)


def step_restart():
    settle()
    n = rng.choice(everyone())
    lists = connect_lists(NODES, ACTIVE_EDGES)
    n.stop()
    n.start(lists[n.index])
    stats["restarts"] += 1
    wait_links(NODES, ACTIVE_EDGES)
    wait_chain(everyone(), f"{n.name} restarted")
    return f"{n.name} restarted"


def step_unclean():
    settle()
    n = rng.choice(everyone())
    lists = connect_lists(NODES, ACTIVE_EDGES)
    n.kill()
    time.sleep(2)
    n.start(lists[n.index])
    stats["unclean stops"] += 1
    wait_links(NODES, ACTIVE_EDGES)
    wait_chain(everyone(), f"{n.name} killed and started again")
    return f"{n.name} killed (SIGKILL) and started again"


def step_partition():
    """Split the nodes in two halves, each with both kinds; each side mines (1-6 blocks,
    one side more), then they rejoin and the shorter side reorganizes"""
    global ACTIVE_EDGES
    settle()
    alive = everyone()
    for _ in range(100):
        side = set(n.index for n in rng.sample(alive, len(alive) // 2))
        a = [n for n in alive if n.index in side]
        b = [n for n in alive if n.index not in side]
        if {n.kind for n in a} == {"divid", "irondivid"} and {n.kind for n in b} == {"divid", "irondivid"}:
            break
    else:
        return "partition: no split with both kinds on each side"
    kept = {e for e in EDGES if all(i in side for i in e) or all(i not in side for i in e)}
    # inside each side the graph must stay connected
    for half in (a, b):
        idx = {n.index for n in half}
        if len(parts(half, {e for e in kept if e <= idx})) > 1:
            first = sorted(idx)[0]
            for other in sorted(idx)[1:]:
                kept.add(frozenset((first, other)))
                if len(parts(half, {e for e in kept if e <= idx})) == 1:
                    break
    ACTIVE_EDGES = kept
    lists = connect_lists(NODES, ACTIVE_EDGES)
    for n in alive:
        n.stop()
    for n in alive:
        n.start(lists[n.index])
    wait_links(NODES, ACTIVE_EDGES)
    long_side, short_side = (a, b) if rng.random() < 0.5 else (b, a)
    depth = rng.randint(1, 6)
    for half, count in ((short_side, depth), (long_side, depth + rng.randint(1, 3))):
        for _ in range(count):
            m = rng.choice(half)
            mine(m, among=half)
            wait_chain(half, f"a block on one side of a partition by {m.name}")
    winner = long_side[0].rpc("getbestblockhash")
    # rejoin
    ACTIVE_EDGES = set(EDGES) | {e for e in kept if all(NODES[i].running() for i in e)}
    lists = connect_lists(NODES, ACTIVE_EDGES)
    for n in alive:
        n.stop()
    for n in alive:
        n.start(lists[n.index])
    wait_links(NODES, ACTIVE_EDGES)
    stats["partitions"] += 1
    best = wait_chain(everyone(), "a partition rejoined")
    time.sleep(AGREE_SECS)
    snapshot("60 s after a rejoin")
    stats["reorgs"].append(depth)
    if best != winner:
        disagreement("the longer side did not win", {"winner": winner, "best": best})
    return (f"partition {sorted(n.name for n in short_side)} | {sorted(n.name for n in long_side)}: "
            f"{depth} blocks against more; rejoined, reorg depth {depth}")


def step_join():
    """A new node from nothing, connected to two running nodes, of a kind drawn"""
    global ACTIVE_EDGES
    kind = rng.choice(["divid", "irondivid"])
    n = Node(len(NODES), kind)
    to = rng.sample(everyone(), 2)
    NODES.append(n)
    new = {frozenset((n.index, t.index)) for t in to}
    EDGES.update(new)
    ACTIVE_EDGES |= new
    n.start(to)
    wait_links(NODES, ACTIVE_EDGES)
    deadline = time.time() + 180
    tip = to[0].rpc("getbestblockhash")
    while time.time() < deadline and n.rpc("getbestblockhash") != tip:
        time.sleep(2)
    stats["joined"] = n.name
    wait_chain(everyone(), f"{n.name} joined from nothing")
    return f"{n.name} joins from nothing, connected to {[t.name for t in to]}"


WEIGHTED = [(step_mine, 36), (step_race, 6), (step_send, 20), (step_sendmany, 8), (step_dust, 3), (step_whole_balance, 3),
            (step_raw, 6), (step_vault_fund, 3), (step_vault_reclaim, 3), (step_double_spend, 3),
            (step_restart, 3), (step_unclean, 3)]


def finish(code):
    stats["elapsed hours"] = round((time.time() - started_at) / 3600, 2)
    stats["nodes"] = {n.name: n.kind for n in NODES}
    stats["links"] = sorted(sorted(e) for e in EDGES)
    try:
        stats["height"] = max(n.rpc("getblockcount") for n in NODES if n.running())
    except Exception:
        pass
    with open(os.path.join(OUT, f"seed{SEED}-summary.json"), "w") as f:
        json.dump(stats, f, indent=1)
    note("end", code=code)
    for n in NODES:
        n.stop()
    say(f"END seed {SEED}: {'AGREED' if code == 0 else 'DISAGREED'}; {json.dumps(stats)[:600]}")
    sys.exit(code)


def setup_failed(kind, value, tb):
    import traceback
    say("SETUP FAILED: " + "".join(traceback.format_exception(kind, value, tb))[-1500:])
    try:
        for n in NODES:
            with open(os.path.join(OUT, f"seed{SEED}-{n.name}-debug-tail.log"), "w") as f:
                f.write("\n".join(n.log_tail()) + "\n")
    except Exception:
        pass
    for n in NODES:
        try:
            n.kill()
        except Exception:
            pass
    sys.exit(2)


sys.excepthook = setup_failed


# --- the run ---------------------------------------------------------------------------

say(f"seed {SEED}, {HOURS} h; nodes {[n.name for n in NODES]}; links {sorted(sorted(e) for e in EDGES)}")
start_all(NODES, EDGES)
wait_links(NODES, EDGES)
# 100 work blocks, spread over every node so each wallet holds coins to stake with
for k in range(100):
    mine(NODES[k % len(NODES)])
    if not BURST:
        wait_chain(NODES, f"work block {k + 1}")
if BURST:
    wait_chain(NODES, "100 work blocks mined in rotation with no wait")
    say(f"burst: every node agreed at height {NODES[0].rpc('getblockcount')}")
    finish(0)
# stake blocks past the coinbase maturity
for k in range(25):
    mine(rng.choice(NODES))
    wait_chain(NODES, f"stake block {k + 1}")
say(f"setup done at height {NODES[0].rpc('getblockcount')}")
snapshot("after setup")

partition_at = [started_at + HOURS * 3600 * f for f in (0.3, 0.7)]
join_at = started_at + HOURS * 3600 * 0.5
last_snapshot = time.time()
while time.time() < end_at:
    stats["steps"] += 1
    if partition_at and time.time() >= partition_at[0]:
        partition_at.pop(0)
        fn = step_partition
    elif join_at and time.time() >= join_at:
        join_at = None
        fn = step_join
    else:
        fns, weights = zip(*WEIGHTED)
        fn = rng.choices(fns, weights)[0]
    what = fn()
    step_log.append((stats["steps"], what))
    note("step", n=stats["steps"], what=what)
    if stats["steps"] % 25 == 0:
        say(f"step {stats['steps']}: {what}; blocks {stats['blocks']}, transactions {stats['transactions']}")
    if time.time() - last_snapshot >= SNAPSHOT_SECS:
        views = snapshot("every 30 s")
        last_snapshot = time.time()
        # same best hash across each connected part, checked again outside a step
        for g in parts(NODES, ACTIVE_EDGES):
            wait_chain([NODES[i] for i in g], "a snapshot")
    time.sleep(rng.uniform(2, 6))

settle()
wait_chain(everyone(), "the end of the run")
finish(0)
