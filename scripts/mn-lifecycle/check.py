#!/usr/bin/env python3
"""The steps of a masternode's life that scripts/mn-life does not take, on
Divi Core divid and on irondivid side by side.

A divid controller C and an irondivid controller I each set up and start
masternodes of the gold, platinum and diamond tiers that run on no node: their
broadcast's ping keeps them ENABLED for two hours, which is how a masternode
whose node stops is seen. Then:
- setupmasternode with the collateral still in the mempool, and again for the
  same alias;
- listmnbroadcasts with several broadcasts stored;
- a broadcast sent once its ping names a block more than 24 deep, and one sent
  again once listed;
- a divid node and an irondivid node without the transaction index (txindex=0)
  that only follow the network: what they list, and what they charge C;
- the node clock moved on with setmocktime, a block at each step, on C and I:
  the masternodes EXPIRED, a collateral spent after that, REMOVE, and dropped.

Each row prints PASS, KNOWN (a difference listed in README.md) or FAIL. Exit
code = FAILs. Started by run.sh, which owns the work directory and stops the
nodes. Keys are never printed: setupmasternode's config_line and the
broadcasts are compared by their shape.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("MN_LIFECYCLE_INJECT", "")
# Loopback address every node binds to: the ports are inside the host's
# ephemeral range, where other programs' 127.0.0.1 sockets can hold them
HOST = "127.0.0.2"
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has on purpose: row name -> reason. Each is listed in
# README.md; a KNOWN row that starts to match divid is a FAIL.
KNOWN = {}

# Fields that change from one moment to the next
MOMENT = {"lastseen", "activetime", "lastpaid", "sigtime", "timestamp"}
TIERS = {"copper", "silver", "gold", "platinum", "diamond"}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, reason=None):
    global fails
    reason = reason or KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


def info(text):
    print(f"#      {text}", flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf=()):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.addr = f"{HOST}:{self.p2p}"
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"mnlc{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=mnlc{index}", f"rpcpassword={password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"externalip={HOST}", "dnsseed=0", "staking=0",
            "debug=masternode", "keypool=10",
        ] + list(extra_conf)
        if not any(line.startswith("txindex=") for line in self.lines):
            self.lines.append("txindex=1")
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines) + "\n")
        self.proc = None
        self.log = None

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        need(self.wait_ready(), f"{self.name} did not answer within {START_TIMEOUT} s")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
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
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:160]}")
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


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def wait_for(fn, secs, step=1.0):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


# --- how replies are compared ------------------------------------------------------

def strip(v, drop=MOMENT):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def shape(v):
    if isinstance(v, dict):
        return {k: shape(x) for k, x in v.items()}
    if isinstance(v, list):
        return [shape(x) for x in v]
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, str):
        return "string"
    return type(v).__name__


def show(out, by_shape=False):
    if out[0] == "err":
        return f"error {out[1]} {json.dumps(str(out[2]).splitlines()[0] if out[2] else '')}"
    return json.dumps(shape(out[1]) if by_shape else out[1])


def compare(name, c, i, by_shape=False, mask=None):
    """Same outcome; an error with the same code and first line; a result with the
    same fields, types and values (by_shape: names and types)"""
    if INJECT == name and i[0] == "ok":
        i = ("ok", {"injected": True})
    if mask and c[0] == "ok":
        c = ("ok", mask(c[1]))
    if mask and i[0] == "ok":
        i = ("ok", mask(i[1]))
    if c[0] == "ok":
        c = ("ok", strip(c[1]))
    if i[0] == "ok":
        i = ("ok", strip(i[1]))
    canon = lambda o: json.dumps(shape(o[1]) if by_shape else o[1], sort_keys=True) if o[0] == "ok" else show(o)
    row(name, show(c, by_shape), show(i, by_shape), canon(c) == canon(i))


def value(name, c, i):
    """Two values computed on each side"""
    if INJECT == name:
        i = "injected"
    row(name, json.dumps(c), json.dumps(i), c == i)


def count_view(v):
    return {k: x for k, x in v.items() if k not in TIERS}


# --- the network ---------------------------------------------------------------------

def mesh(nodes):
    for a in nodes:
        for b in nodes:
            if a is not b:
                a.call("addnode", b.addr, "onetry")


def synced(nodes, secs=120):
    def same():
        return len({n.rpc("getbestblockhash") for n in nodes}) == 1
    return wait_for(same, secs)


C = Node("divid-C", DIVID, 0)
I = Node("irondivid-I", IRONDIVID, 1)
CN = Node("divid-noindex", DIVID, 2, ["txindex=0"])
IN = Node("irondivid-noindex", IRONDIVID, 3, ["txindex=0"])
NODES = [C, I, CN, IN]
CONTROLLERS = (C, I)


def mine(node, blocks=1):
    for _ in range(blocks):
        node.rpc("setgenerate", 1)
        need(synced(NODES), f"the nodes did not follow {node.name}'s block")


for n in NODES:
    n.start()
mesh(NODES)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)
# Coins on both: 50 blocks by C, whose first 30 are mature (20 confirmations,
# chainparams.cpp:479), and to I one coin for each allocation, so that each
# finds a confirmed coin. The whole run stays below height 101, in proof of
# work
mine(C, 50)
C.rpc("sendmany", "", {I.rpc("getnewaddress"): amount for amount in (11000, 3500, 1500, 500)})
mine(C, 1)


# 1. The collaterals: each controller's diamond, platinum and gold, then a
# copper one set up while it is in the mempool
def collateral_pubkey(node, txhash, vout):
    tx = node.rpc("getrawtransaction", txhash, 1)
    address = tx["vout"][vout]["scriptPubKey"]["addresses"][0]
    return address, node.rpc("validateaddress", address)["pubkey"]


def config_key(out):
    return out[1]["config_line"].split()[2] if out[0] == "ok" else None


def setup(node, alias, txhash, vout, mnode_addr):
    _, pubkey = collateral_pubkey(node, txhash, vout)
    return node.call("setupmasternode", alias, txhash, str(vout), pubkey, mnode_addr)


mn = {}  # alias -> details
# Largest first: I holds one coin for each
plan = {C: [("mndc", "diamond"), ("mnxc", "platinum"), ("mngc", "gold")],
        I: [("mndi", "diamond"), ("mnxi", "platinum"), ("mngi", "gold")]}
for node, entries in plan.items():
    for k, (alias, tier) in enumerate(entries):
        a = node.call("allocatefunds", "masternode", alias, tier)
        need(a[0] == "ok", f"{node.name} allocatefunds {tier}: {a}")
        mn[alias] = {"controller": node, "tier": tier, "txhash": a[1]["txhash"], "vout": a[1]["vout"],
                     "addr": f"{HOST}:{PORT_BASE + 41 + k + (0 if node is C else 4)}"}
# setupmasternode with the collateral in the mempool (GetTransaction looks
# there first, TransactionDiskAccessor.cpp:58-61)
pool = {}
for n, alias in ((C, "mnpc"), (I, "mnpi")):
    a = n.rpc("allocatefunds", "masternode", alias, "copper")
    pool[n.name] = (alias, a["txhash"], a["vout"])
    # The allocation is in each node's own mempool at once
    pool[n.name + "/setup"] = setup(n, alias, a["txhash"], a["vout"], f"{HOST}:{PORT_BASE + 40}")
compare("setupmasternode with the collateral in the mempool", pool[C.name + "/setup"], pool[I.name + "/setup"],
        by_shape=True)
need(synced(NODES), "the allocations did not reach every node")

# The copper collateral set up from the mempool is started late (section 4)
for n in CONTROLLERS:
    alias, txhash, vout = pool[n.name]
    mn[alias] = {"controller": n, "tier": "copper", "txhash": txhash, "vout": vout, "addr": f"{HOST}:{PORT_BASE + 40}"}
    plan[n].append((alias, "copper"))
need(synced(NODES), "the allocations did not reach every node")
for (ca, _), (ia, _) in zip(plan[C], plan[I]):
    amounts = []
    for alias in (ca, ia):
        d = mn[alias]
        d["amount"] = d["controller"].rpc("getrawtransaction", d["txhash"], 1)["vout"][d["vout"]]["value"]
        amounts.append(d["amount"])
    value(f"{mn[ca]['tier']}: collateral amount", *amounts)
mine(C, 16)

# 2. setupmasternode for the mempool collateral again, now confirmed: the same
# key as before, the address of the account "reserved-><alias>"
# (rpcmasternode.cpp:207, rpcwallet.cpp:334-375)
again = {}
for n in CONTROLLERS:
    alias, txhash, vout = pool[n.name]
    first = pool[n.name + "/setup"]
    second = setup(n, alias, txhash, vout, f"{HOST}:{PORT_BASE + 40}")
    again[n.name] = (config_key(first) is not None and config_key(first) == config_key(second))
    reserved = n.call("getaddressesbyaccount", f"reserved->{alias}")
    again[n.name + "/reserved"] = len(reserved[1]) if reserved[0] == "ok" else show(reserved)
value("setupmasternode again for the alias: the same masternode key", again[C.name], again[I.name])
value("the account reserved-><alias> holds the masternode key", again[C.name + "/reserved"],
      again[I.name + "/reserved"])

for node, entries in plan.items():
    for alias, _ in entries:
        d = mn[alias]
        s = setup(node, alias, d["txhash"], d["vout"], d["addr"])
        need(s[0] == "ok", f"{node.name} setupmasternode {alias}: {s}")
        signed = node.rpc("signmnbroadcast", s[1]["broadcast_data"])
        d["signed"] = signed["broadcast_data"]
        need(node.rpc("importmnbroadcast", d["signed"]) is True, f"{node.name} importmnbroadcast {alias}")

# listmnbroadcasts in std::map's order of the collateral: the txid as a
# number, which is the order of its hex (StoredMasternodeBroadcasts.h:19,
# OutPoint.cpp:14-17, uint256.cpp:139-147)
listed = {}
for n in CONTROLLERS:
    out = n.rpc("listmnbroadcasts")
    hashes = [(e["txhash"], e["outidx"]) for e in out]
    listed[n.name] = (len(hashes), hashes == sorted(hashes))
value("listmnbroadcasts: count, and in collateral order", list(listed[C.name]), list(listed[I.name]))


# 3. Start: the three tiers from each controller
def status_on(node, alias):
    out = node.call("listmasternodes", mn[alias]["txhash"])
    if out[0] != "ok":
        return show(out)
    return [e.get("status") for e in out[1]] or None


def statuses(node, aliases):
    return {a: status_on(node, a) for a in aliases}


started = [a for a in mn if mn[a]["tier"] != "copper"]
c_started = [a for a in started if mn[a]["controller"] is C]
i_started = [a for a in started if mn[a]["controller"] is I]
for ca, ia in zip(c_started, i_started):
    tier = mn[ca]["tier"]
    compare(f"{tier}: broadcaststartmasternode", C.call("broadcaststartmasternode", mn[ca]["signed"]),
            I.call("broadcaststartmasternode", mn[ia]["signed"]))
for observer in NODES:
    wait_for(lambda: all(status_on(observer, a) == ["ENABLED"] for a in started), 60)


def tier_view(node, aliases):
    out = node.call("listmasternodes")
    if out[0] != "ok":
        return show(out)
    by = {e["txhash"]: e for e in out[1]}
    return {mn[a]["tier"] + ("/own" if mn[a]["controller"] is node else "/other"):
            (by.get(mn[a]["txhash"], {}).get("tier"), by.get(mn[a]["txhash"], {}).get("status")) for a in aliases}


value("each tier listed with its tier, on its controller and the other", tier_view(C, started), tier_view(I, started))
compare("getmasternodecount with the three tiers of each", C.call("getmasternodecount"),
        I.call("getmasternodecount"), mask=count_view)
compare("broadcaststartmasternode again once listed", C.call("broadcaststartmasternode", mn[c_started[0]]["signed"]),
        I.call("broadcaststartmasternode", mn[i_started[0]]["signed"]))

# The nodes without the transaction index took the masternodes from the
# network (IsVinAssociatedWithPubkey finds the collateral through the coins
# view, masternodeman.cpp:62-77, TransactionDiskAccessor.cpp:87-110), and did
# not charge the relaying nodes for them
wait_for(lambda: len(CN.rpc("listmasternodes")) == len(started), 60)
wait_for(lambda: len(IN.rpc("listmasternodes")) == len(started), 30)
value("txindex=0: the masternodes the network relayed, listed", len(CN.rpc("listmasternodes")),
      len(IN.rpc("listmasternodes")))


def scores(node):
    return sorted(p.get("banscore", 0) for p in node.rpc("getpeerinfo"))


value("txindex=0: the misbehaviour scores of its peers", scores(CN), scores(IN))

# 4. A broadcast sent once its ping names a block more than 24 deep: the list
# refuses it (masternodeman.cpp:342-352), and divid answers with what its list
# did (RpcMasternodeFeatures.cpp:104-121)
mine(C, 13)
late = [a for a in mn if mn[a]["tier"] == "copper"]
compare("a broadcast whose ping is 25 blocks deep", C.call("broadcaststartmasternode", mn[late[0]]["signed"]),
        I.call("broadcaststartmasternode", mn[late[1]]["signed"]))
time.sleep(3)
value("a broadcast whose ping is 25 blocks deep: listed", statuses(C, late), statuses(I, late))

# 5. The masternodes ping no more: the node clock moved on (setmocktime) on C
# and I, a block mined at each step so the chain stays synced
# (IsBlockchainSynced, MasternodeHelpers.cpp:35-63). A masternode is EXPIRED
# once its last ping is 120 minutes old, REMOVE at 130, both on the node's
# clock (TimeSinceLastPingIsWithin, MasternodeHelpers.cpp:172-181), and each
# minute's pass drops the REMOVE ones (MasternodeModule.cpp:515-519)
pings = [e["lastseen"] for e in C.rpc("listmasternodes")]
first_ping, last_ping = min(pings), max(pings)
info(f"the masternodes' last pings span {last_ping - first_ping} s")


def step(at, label):
    """Every node's clock to `at`, then a block. Steps are 15 minutes or less:
    a peer that sent nothing for 20 minutes on the node's clock is dropped
    (CNode::CheckForInnactivity, Node.cpp:812-834)"""
    for n in NODES:
        n.rpc("setmocktime", at)
    C.rpc("setgenerate", 1)
    need(synced(NODES), f"{label}: the nodes did not follow C's block")
    # The minute's pass runs within a second of the clock moving
    time.sleep(3)
    for n in CONTROLLERS:
        n.call("getmasternodecount")


def view(label):
    value(f"{label}: statuses", statuses(C, started), statuses(I, started))
    compare(f"{label}: getmasternodecount", C.call("getmasternodecount"), I.call("getmasternodecount"),
            mask=count_view)


# Each step is also less than an hour on, so the chain does not count as
# stalled (MasternodeHelpers.cpp:27-34)
now = int(time.time())
for k, at in enumerate(range(now + 900, first_ping + 7200 - 60, 900)):
    step(at, f"clock step {k}")
step(first_ping + 7200 - 60, "a minute before the first expiry")
view("a minute before the masternodes expire")
step(last_ping + 7200 + 30, "just past the last expiry")
view("past two hours without a ping")

# An expired masternode whose collateral is then spent stays EXPIRED: Check
# looks at the collateral only after the ping times (masternodeman.cpp:160-178)
spent = [a for a in started if mn[a]["tier"] == "gold"]
for alias in spent:
    d = mn[alias]
    node = d["controller"]
    raw = node.rpc("createrawtransaction", [{"txid": d["txhash"], "vout": d["vout"]}],
                   {node.rpc("getnewaddress"): round(float(d["amount"]) - 0.01, 8)})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign the collateral spend")
    node.rpc("sendrawtransaction", signed["hex"])
need(wait_for(lambda: len(C.rpc("getrawmempool")) == 2, 30), "the collateral spends did not reach C")
step(last_ping + 7200 + 90, "the gold collaterals spent")
view("the gold collaterals spent after the expiry")
step(last_ping + 7800 + 30, "past the removal time")
view("past 130 minutes without a ping")
step(last_ping + 7800 + 120, "a minute's pass later")
value("a minute's pass after the removal time: listmasternodes", len(C.rpc("listmasternodes")),
      len(I.rpc("listmasternodes")))

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
