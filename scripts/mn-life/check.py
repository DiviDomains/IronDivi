#!/usr/bin/env python3
"""A masternode from setup to payment, on Divi Core divid and on irondivid.

irondivid cannot run as a masternode (it refuses -masternode), so the network
is mixed: a divid controller C and an irondivid controller I each set up and
start masternodes that run on divid nodes (M1 and M3 for C, M2 and M4 for I).
Every controller step is made on C and on I and the two replies are compared;
what the network then does with the masternodes is read on C and on I side by
side (listmasternodes, getmasternodecount, mnsync status, getmasternodestatus,
getmasternodewinners, and with MN_LIFE_PAYMENTS=1 the payee of each block).
Each row prints PASS, KNOWN (a difference listed in README.md) or FAIL. Exit
code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. Keys are
never printed: setupmasternode's config_line and the broadcasts are compared by
their shape, and the config lines go to the masternode nodes' 0600 files only.
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
import mnsync_stages  # noqa: E402  (scripts/lib: the sync stages of nodes over time)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("MN_LIFE_INJECT", "")
# With 1, the payment phase runs too: on regtest a masternode is ranked, and so
# can vote and be paid, only 25 minutes after its broadcast was signed
# (masternode-payments.cpp:558)
PAYMENTS = os.environ.get("MN_LIFE_PAYMENTS", "") == "1"
# With 1 (scripts/mn-reward), the payment phase runs with masternode payments on,
# and the wallet rows of a payment (mn_reward, stake_reward) are compared. divid
# pays no masternode once DeprecateMasternodes is active, from a median time past
# of 2023-08-23 (ForkActivation.cpp:31, BlockIncentivesPopulator.cpp:142-152);
# -manual_fork=<time> moves that fork, and CheckLockTimeVerify, to <time>
# (ForkActivation.cpp:21, :48-55). The divid nodes get 2100-01-01
REWARDS = os.environ.get("MN_LIFE_REWARDS", "") == "1"
PAYMENTS = PAYMENTS or REWARDS
MANUAL_FORK = "manual_fork=4102444800"
# Loopback address every node binds to: the ports are inside the host's
# ephemeral range, where other programs' 127.0.0.1 sockets can hold them
HOST = "127.0.0.2"
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has on purpose or has not closed yet: row name -> reason.
# Each is listed in README.md with divid's source line; a KNOWN row that starts to
# match divid is a FAIL, so the list stays true.
KNOWN = {
    "getmasternodecount: tier counts divid lacks":
        "copper, silver, gold, platinum, diamond, kept on purpose (divid rpcmasternode.cpp:327-358 has the 8 "
        "counts only; scripts/masternode-replies README)",
}
if REWARDS:
    KNOWN["payments: blocks that pay a masternode"] = (
        "only divid is given -manual_fork, so only C's blocks pay a masternode; irondivid does not take the option "
        "and keeps DeprecateMasternodes active, as every network has had it since 2023-08-23 (scripts/mn-reward README)")
TIERS = {"copper", "silver", "gold", "platinum", "diamond"}

# Fields that change from one moment to the next
MOMENT = {"lastseen", "activetime", "lastpaid", "sigtime", "timestamp"}

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


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
        self.auth = base64.b64encode(f"mnlife{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        # divid keeps regtest data (and masternode.conf) in <datadir>/regtest
        self.netdir = os.path.join(self.dir, "regtest") if binary == DIVID else self.dir
        os.makedirs(self.netdir, exist_ok=True)
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=mnlife{index}", f"rpcpassword={password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", f"externalip={HOST}", "dnsseed=0", "staking=0", "txindex=1",
            "debug=masternode", "keypool=10",
        ] + ([MANUAL_FORK] if REWARDS and binary == DIVID else []) + list(extra_conf)
        self.write_conf()
        self.proc = None
        self.log = None

    def write_conf(self, extra=()):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def write_masternode_conf(self, line):
        """masternode.conf, 0600: the line holds the masternode's private key"""
        path = os.path.join(self.netdir, "masternode.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(line + "\n")

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
        self.log.close()


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def refusals(node):
    """The payment votes the irondivid node did not take, by reason, from its
    debug.log (node.rs logs each at debug, which debug=masternode turns on)"""
    reasons = {}
    for root, _, files in os.walk(node.dir):
        for f in files:
            if f.startswith("debug.log"):
                with open(os.path.join(root, f), errors="replace") as log:
                    for line in log:
                        if "Masternode winner from peer" in line and "not taken:" in line:
                            why = line.split("not taken:", 1)[1].strip()
                            reasons[why] = reasons.get(why, 0) + 1
    info(f"votes {node.name} did not take, by reason: {json.dumps(reasons)}"[:600])


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
    v = shape(out[1]) if by_shape else out[1]
    return json.dumps(v, sort_keys=False)


def compare(name, c, i, by_shape=False, mask=None):
    """Same outcome; an error with the same code and first line; a result with the
    same fields in the same order, types and values (by_shape: names and types)"""
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
    a, b = show(c, by_shape), show(i, by_shape)
    canon = lambda o: json.dumps(shape(o[1]) if by_shape else o[1], sort_keys=True) if o[0] == "ok" else show(o)
    row(name, a, b, canon(c) == canon(i))
    if canon(c) != canon(i) and c[0] == i[0] == "ok" and isinstance(c[1], list) and isinstance(i[1], list):
        # The row is cut at 600 characters: name the entries that differ
        for k in range(max(len(c[1]), len(i[1]))):
            x = c[1][k] if k < len(c[1]) else None
            y = i[1][k] if k < len(i[1]) else None
            if x != y:
                info(f"  entry {k}: divid={json.dumps(x)}  irondivid={json.dumps(y)}"[:600])
    return c, i


def compare_mnsync(name, c, i):
    """mnsync status: whether the chain is synced, the stage, and the shape of
    the node's own counters and times"""
    cv = mnsync_view(c[1]) if c[0] == "ok" else c
    iv = mnsync_view(i[1]) if i[0] == "ok" else i
    a, b = json.dumps(cv, sort_keys=True), json.dumps(iv, sort_keys=True)
    row(name, a, b, a == b)


def stage_rows(name, seqs):
    """The stages C and I went through, compared as sequences"""
    a, b = seqs[C.name], seqs[I.name]
    row(name, mnsync_stages.text(a), mnsync_stages.text(b), a == b)


def sorted_list(v):
    return sorted(v, key=lambda e: (e.get("txhash", ""), e.get("outidx", 0))) if isinstance(v, list) else v


def mnsync_view(v):
    """mnsync status: the fields, and the two values that are not this node's own
    counters and times"""
    return {k: (x if k in ("IsBlockchainSynced", "currentMasternodeSyncStatus") else shape(x)) for k, x in v.items()}


def count_view(v):
    return {k: x for k, x in v.items() if k not in TIERS}


def both(name, method, *params, by_shape=False, mask=None, on=None):
    c_node, i_node = on or (C, I)
    return compare(name, c_node.call(method, *params), i_node.call(method, *params), by_shape, mask)


# --- the network ---------------------------------------------------------------------

def mesh():
    """Every running node connected to every other (addnode onetry both ways)"""
    running = [n for n in NODES if n.proc]
    for a in running:
        for b in running:
            if a is not b:
                a.call("addnode", b.addr, "onetry")


def synced(nodes=None, secs=120):
    nodes = [n for n in (nodes or NODES) if n.proc]
    def same():
        tips = {n.rpc("getbestblockhash") for n in nodes}
        return len(tips) == 1
    return wait_for(same, secs)


def mine(node, blocks):
    for _ in range(blocks):
        node.rpc("setgenerate", 1)
        need(synced(), f"the nodes did not follow {node.name}'s block")


C = Node("divid-C", DIVID, 0)
I = Node("irondivid-I", IRONDIVID, 1)
M1 = Node("divid-M1", DIVID, 2, ["masternode=mnc"])
M2 = Node("divid-M2", DIVID, 3, ["masternode=mni"])
M3 = Node("divid-M3", DIVID, 4, ["masternode=mnc2"])
M4 = Node("divid-M4", DIVID, 5, ["masternode=mni2"])
NODES = [C, I, M1, M2, M3, M4]

# 1. The two controllers, one chain, coins on both
for n in (C, I):
    n.start()
poller = mnsync_stages.StagePoller([C, I]).start()
mesh()
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)
mine(C, 30)
C.rpc("sendtoaddress", I.rpc("getnewaddress"), 3000)
mine(C, 1)

# The state before any masternode
compare_mnsync("before: mnsync status", C.call("mnsync", "status"), I.call("mnsync", "status"))
both("before: listmasternodes", "listmasternodes")
both("before: getmasternodecount", "getmasternodecount", mask=count_view)
both("before: getmasternodestatus (a controller)", "getmasternodestatus")
both("before: listmnbroadcasts", "listmnbroadcasts")
counts_ = [C.rpc("getmasternodecount"), I.rpc("getmasternodecount")]
extra = sorted(set(counts_[1]) - set(counts_[0]))
row("getmasternodecount: tier counts divid lacks", "-", ",".join(extra) or "-", not extra)


# 2. allocatefunds, setupmasternode, signmnbroadcast on each controller
def collateral_pubkey(node, txhash, vout):
    tx = node.rpc("getrawtransaction", txhash, 1)
    address = tx["vout"][vout]["scriptPubKey"]["addresses"][0]
    return address, node.rpc("validateaddress", address)["pubkey"]


def config_parts(line):
    """setupmasternode's config_line without the key: alias, address, txhash, index"""
    parts = line.split()
    return [parts[0], parts[1], parts[3], parts[4]] if len(parts) == 5 else parts


mn = {}  # (controller, alias) -> details
plan = [(C, "mnc", "copper", M1), (I, "mni", "copper", M2)]
second = [(C, "mnc2", "silver", M3), (I, "mni2", "silver", M4)]


def set_up(pairs, label):
    (c, ca, tier, cm), (i, ia, _, im) = pairs
    alloc = [c.call("allocatefunds", "masternode", ca, tier), i.call("allocatefunds", "masternode", ia, tier)]
    compare(f"{label}: allocatefunds masternode <alias> {tier}", *alloc, by_shape=True)
    for (node, alias, _, mnode), a in zip(pairs, alloc):
        need(a[0] == "ok", f"{node.name} allocatefunds: {a}")
        mn[alias] = {"controller": node, "node": mnode, "txhash": a[1]["txhash"], "vout": a[1]["vout"], "tier": tier}
    need(synced(), "the allocations did not reach every node")
    for alias in (ca, ia):
        d = mn[alias]
        tx = d["controller"].rpc("getrawtransaction", d["txhash"], 1)
        d["amount"] = tx["vout"][d["vout"]]["value"]
    row(f"{label}: collateral amount", mn[ca]["amount"], mn[ia]["amount"], mn[ca]["amount"] == mn[ia]["amount"])
    # 15 confirmations before a broadcast is taken (masternode.h:16)
    mine(C, 16)
    setups = []
    for node, alias, _, mnode in pairs:
        d = mn[alias]
        d["address"], pubkey = collateral_pubkey(node, d["txhash"], d["vout"])
        setups.append(node.call("setupmasternode", alias, d["txhash"], str(d["vout"]), pubkey, mnode.addr))
    compare(f"{label}: setupmasternode", *setups, by_shape=True)
    if label == "copper" and setups[0][0] == setups[1][0] == "ok":
        order = [list(o[1]) for o in setups]
        row("member order of an object (setupmasternode)", order[0], order[1], order[0] == order[1])
    for (node, alias, _, mnode), s in zip(pairs, setups):
        need(s[0] == "ok", f"{node.name} setupmasternode: {s}")
        mn[alias]["config_line"] = s[1]["config_line"]
        mn[alias]["unsigned"] = s[1]["broadcast_data"]
    row(f"{label}: setupmasternode protocol_version", setups[0][1]["protocol_version"],
        setups[1][1]["protocol_version"], setups[0][1]["protocol_version"] == setups[1][1]["protocol_version"])
    parts = [config_parts(mn[a]["config_line"]) for a in (ca, ia)]
    expected = [[a, mn[a]["node"].addr, mn[a]["txhash"], str(mn[a]["vout"])] for a in (ca, ia)]
    row(f"{label}: config_line is alias, address, key, txhash, index", parts[0] == expected[0],
        parts[1] == expected[1], (parts[0] == expected[0]) == (parts[1] == expected[1]))
    signed = [node.call("signmnbroadcast", mn[alias]["unsigned"]) for node, alias, _, _ in pairs]
    compare(f"{label}: signmnbroadcast", *signed, by_shape=True)
    for (node, alias, _, _), s in zip(pairs, signed):
        need(s[0] == "ok", f"{node.name} signmnbroadcast: {s}")
        mn[alias]["signed"] = s[1]["broadcast_data"]
    compare(f"{label}: importmnbroadcast on the controller",
            c.call("importmnbroadcast", mn[ca]["signed"]), i.call("importmnbroadcast", mn[ia]["signed"]))
    compare(f"{label}: importmnbroadcast again", c.call("importmnbroadcast", mn[ca]["signed"]),
            i.call("importmnbroadcast", mn[ia]["signed"]))
    listed = [c.call("listmnbroadcasts"), i.call("listmnbroadcasts")]
    own = lambda out, aliases: [e for e in out[1] if e.get("txhash") in {mn[a]["txhash"] for a in aliases}] \
        if out[0] == "ok" else out
    compare(f"{label}: listmnbroadcasts", *listed, by_shape=True)
    for out, alias in zip(listed, (ca, ia)):
        mine_ = [e for e in out[1] if e.get("txhash") == mn[alias]["txhash"]] if out[0] == "ok" else []
        mn[alias]["listed"] = len(mine_) == 1 and mine_[0].get("outidx") == mn[alias]["vout"]
    row(f"{label}: listmnbroadcasts has the broadcast, txhash and outidx", mn[ca]["listed"], mn[ia]["listed"],
        mn[ca]["listed"] == mn[ia]["listed"])
    compare(f"{label}: startmasternode <alias> on the controller (not a masternode)",
            c.call("startmasternode", ca), i.call("startmasternode", ia))
    compare(f"{label}: startmasternode <alias> true on the controller",
            c.call("startmasternode", ca, True), i.call("startmasternode", ia, True))


set_up(plan, "copper")

# 3. The masternode nodes: masternode.conf from the controller's config line
for alias in ("mnc", "mni"):
    d = mn[alias]
    d["node"].write_masternode_conf(d["config_line"])
    d["node"].start()
mesh()
need(synced(secs=180), "the masternode nodes did not reach the tip")
# The masternode node keeps the signed broadcast too, for startmasternode <alias>
for alias in ("mnc", "mni"):
    mn[alias]["node"].rpc("importmnbroadcast", mn[alias]["signed"])


def sync_state(node):
    out = node.call("mnsync", "status")
    return out[1].get("currentMasternodeSyncStatus") if out[0] == "ok" else out


# The masternode sync moves through its stages with three peers it may ask
# (inbound or spork-synced), on each controller as on the masternode nodes
t0 = time.time()
finished = wait_for(lambda: all(sync_state(n) == 999 for n in (C, M1, M2, I)), 240, step=2)
info(f"the nodes' masternode sync finished: {finished} after {time.time() - t0:.0f} s")
stage_rows("mnsync stages from start to the network up", poller.stop())
compare_mnsync("mnsync status, the network up", C.call("mnsync", "status"), I.call("mnsync", "status"))
compare("getmasternodestatus on a masternode node before its start (M1 for C, M2 for I)",
        M1.call("getmasternodestatus"), M2.call("getmasternodestatus"))


# 4. Start: broadcaststartmasternode from each controller
def enabled_on(node, alias):
    out = node.call("listmasternodes", mn[alias]["txhash"])
    return out[0] == "ok" and any(e.get("status") == "ENABLED" for e in out[1])


def start_in_turn(name, c_alias, i_alias):
    """C's broadcast, then I's once I lists C's masternode. A node lists the
    masternodes in the order it took them, and a controller takes its own
    broadcast before relaying it; sent one right after the other, whether C's
    relay reaches I before I's own call is a race. In turn, both nodes take C's
    first. Returns when each was sent"""
    sent = {c_alias: time.time()}
    c_out = C.call("broadcaststartmasternode", mn[c_alias]["signed"])
    t0 = time.time()
    listed = wait_for(lambda: bool(I.rpc("listmasternodes", mn[c_alias]["txhash"])), 60, step=0.5)
    info(f"{c_alias} listed on {I.name} before {i_alias} was sent: {listed} after {round(time.time() - t0)} s")
    sent[i_alias] = time.time()
    i_out = I.call("broadcaststartmasternode", mn[i_alias]["signed"])
    compare(name, c_out, i_out)
    return sent


starts = start_in_turn("broadcaststartmasternode <signed broadcast> from the controller", "mnc", "mni")
times = {}
for alias in ("mnc", "mni"):
    for observer in (C, I):
        ok = wait_for(lambda: enabled_on(observer, alias), 120, step=1)
        times[(alias, observer.name)] = round(time.time() - starts[alias]) if ok else None
info("seconds to ENABLED: " + ", ".join(f"{a} on {o}: {t}" for (a, o), t in times.items()))
row("C's masternode ENABLED on each controller within 120 s", times[("mnc", C.name)] is not None,
    times[("mnc", I.name)] is not None, (times[("mnc", C.name)] is None) == (times[("mnc", I.name)] is None))
row("I's masternode ENABLED on each controller within 120 s", times[("mni", C.name)] is not None,
    times[("mni", I.name)] is not None, (times[("mni", C.name)] is None) == (times[("mni", I.name)] is None))
row("each controller's own masternode ENABLED on the network (seen on C)", times[("mnc", C.name)] is not None,
    times[("mni", C.name)] is not None, (times[("mnc", C.name)] is None) == (times[("mni", C.name)] is None))


def views(label):
    # Each node lists masternodes in the order it took them, and both took C's
    # first (start_in_turn), so the lists are compared in txhash order and the
    # first entry on its own
    lists = [C.call("listmasternodes"), I.call("listmasternodes")]
    compare(f"{label}: listmasternodes (in txhash order)", *lists, mask=sorted_list)
    took_first = {mn[a]["txhash"] for a in mn if mn[a]["controller"] is C}
    first = [o[1][0].get("txhash") in took_first if o[0] == "ok" and o[1] else None for o in lists]
    row(f"{label}: the masternode taken first (C's) listed first", first[0], first[1], first[0] == first[1])
    both(f"{label}: getmasternodecount", "getmasternodecount", mask=count_view)
    compare_mnsync(f"{label}: mnsync status", C.call("mnsync", "status"), I.call("mnsync", "status"))
    both(f"{label}: getmasternodestatus (a controller)", "getmasternodestatus")
    compare(f"{label}: getmasternodestatus on the masternode node (M1 for C's, M2 for I's)",
            M1.call("getmasternodestatus"), M2.call("getmasternodestatus"),
            mask=lambda v: {k: x for k, x in v.items() if k not in ("txhash", "outputidx", "netaddr", "addr")})
    both(f"{label}: getmasternodewinners", "getmasternodewinners", "5")


# A masternode node's own status follows the network's ENABLED on its own
# timer: until then divid answers "Can't detect external address", on M1 and on
# M2 alike, so both are given the same time to start
t0 = time.time()
up = wait_for(lambda: all(n.call("getmasternodestatus")[0] == "ok" for n in (M1, M2)), 120, step=2)
info(f"masternode nodes' own status started: {up} after {round(time.time() - t0)} s")
views("started")

# startmasternode <alias> on the masternode node itself (divid only): its reply,
# and the broadcast it hands back with deferRelay
for alias, node in (("mnc", M1), ("mni", M2)):
    out = node.call("startmasternode", alias, True)
    info(f"startmasternode {alias} true on {node.name}: {show(out, by_shape=True)}")

# 5. A second masternode of another tier on each side
set_up(second, "silver")
for alias in ("mnc2", "mni2"):
    d = mn[alias]
    d["node"].write_masternode_conf(d["config_line"])
    d["node"].start()
mesh()
need(synced(secs=180), "the second masternode nodes did not reach the tip")
wait_for(lambda: all(sync_state(n) == 999 for n in (M3, M4)), 240, step=2)
start_in_turn("silver: broadcaststartmasternode from the controller", "mnc2", "mni2")
for alias in ("mnc2", "mni2"):
    wait_for(lambda: enabled_on(C, alias) and enabled_on(I, alias), 120)
views("four masternodes")

# 6. Restarts: the peer, then the masternode nodes
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
poller = mnsync_stages.StagePoller([C, I]).start()
mesh()
need(synced(secs=180), "the controllers did not come back to the tip")
wait_for(lambda: all(sync_state(n) == 999 for n in (C, I)), 240, step=2)
stage_rows("mnsync stages after the controllers restarted", poller.stop())
time.sleep(5)
views("after the controllers restarted")
for n in (M1, M2):
    n.stop()
for n in (M1, M2):
    n.start()
mesh()
need(synced(secs=180), "the masternode nodes did not come back to the tip")
time.sleep(5)
views("after the masternode nodes restarted")

# 7. The collateral spent: each controller spends its copper collateral
for alias in ("mnc", "mni"):
    d = mn[alias]
    node = d["controller"]
    node.call("lockunspent", True, [{"txid": d["txhash"], "vout": d["vout"]}])
    raw = node.rpc("createrawtransaction", [{"txid": d["txhash"], "vout": d["vout"]}],
                   {node.rpc("getnewaddress"): round(float(d["amount"]) - 0.01, 8)})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign the collateral spend")
    d["spend"] = node.call("sendrawtransaction", signed["hex"])
compare("sendrawtransaction of the copper collateral", mn["mnc"]["spend"], mn["mni"]["spend"], by_shape=True)
mine(C, 1)


def status_of(node, alias):
    out = node.call("listmasternodes", mn[alias]["txhash"])
    if out[0] != "ok":
        return out
    return [e.get("status") for e in out[1]]


for blocks in (0, 1, 5):
    if blocks:
        mine(C, blocks)
    # divid shows the state of its last check, made once a minute or by
    # getmasternodecount, at most every 5 s per masternode (masternode.h:22,
    # masternodeman.cpp:152-157): both are checked here before the list is read
    time.sleep(6)
    for n in (C, I):
        n.call("getmasternodecount")
    for alias in ("mnc", "mni"):
        a, b = status_of(C, alias), status_of(I, alias)
        row(f"collateral spent, {blocks + 1} block(s) on: status of {alias}", json.dumps(a), json.dumps(b), a == b)
views("after the copper collateral was spent")

# 8. Payments (MN_LIFE_PAYMENTS=1): ranked 25 minutes after the broadcast was
# signed; then each block is mined in turn by C and by I
if PAYMENTS:
    # I stakes ten blocks below. A stake combines the wallet's coins paying the
    # kernel's script, and a coinstake output needs 20 confirmations before it
    # stakes again (wallet.cpp:1452-1457), so I gets twelve coins of its own,
    # each to a new address, well before they are needed. The silver
    # collaterals are locked, so neither is staked and both masternodes stay
    # to vote (locked coins are not available, AvailableUtxoCalculator.cpp:91).
    # C and I have no masternode.conf to lock them when they start
    # (init.cpp:1246-1258), and a collateral would be staked with its
    # masternode's rewards, which share its script (PoSTransactionCreator.cpp
    # :172-209); a vote for it within a second of that block is taken or
    # refused by each node as its last check of the masternode is under 5 s
    # old or not (masternodeman.cpp:153-180): a race, not a rule
    for alias in ("mnc2", "mni2"):
        d = mn[alias]
        need(d["controller"].call("lockunspent", False, [{"txid": d["txhash"], "vout": d["vout"]}]) == ("ok", True),
             f"{d['controller'].name} could not lock the {alias} collateral")
    for _ in range(12):
        C.rpc("sendtoaddress", I.rpc("getnewaddress"), 200)
    mine(C, 1)
    ready = max(starts.values()) + 25 * 60 + 60
    info(f"waiting {max(0, ready - time.time()):.0f} s for the masternodes to be ranked")
    while time.time() < ready:
        time.sleep(30)
        C.call("getblockcount")
    # A height is scored with the block 101 below it and is paid only then
    # (MasternodeHelpers.cpp:75-86): the chain first passes height 110
    while C.rpc("getblockcount") < 110:
        mine(C, 1)
    collateral_addresses = {mn[a]["address"]: a for a in mn}

    def coinstake_view(height):
        """The masternode payments in the block (outputs to a masternode's
        collateral address that is not one of the coinstake's own inputs, so a
        staked collateral is not a payment) and what it minted"""
        block = C.rpc("getblock", C.rpc("getblockhash", height))
        tx = C.rpc("getrawtransaction", block["tx"][1], 1)
        inputs, spent = set(), 0.0
        for i in tx["vin"]:
            prev = C.rpc("getrawtransaction", i["txid"], 1)["vout"][i["vout"]]
            spent += float(prev["value"])
            inputs.update(prev.get("scriptPubKey", {}).get("addresses", []))
        payments, made = [], 0.0
        for o in tx["vout"]:
            made += float(o["value"])
            for addr in o.get("scriptPubKey", {}).get("addresses", []):
                if addr in collateral_addresses and addr not in inputs:
                    payments.append((collateral_addresses[addr], o["value"]))
        return payments, round(made - spent, 8)

    # Divi Core pays no masternode once DeprecateMasternodes is active (median
    # time past from 2023-08-23, ForkActivation.cpp:31; BlockIncentivesPopulator
    # .cpp:142-152), so each block's masternode payments are compared, and what
    # it minted; the votes still flow and are compared after each block
    views_by = {C.name: [], I.name: []}
    paid = []  # (height, miner, masternode payments) of each block
    paid_owners = lambda: {mn[a]["controller"].name for _, _, p in paid for a, _ in p}
    by_txhash = {mn[a]["txhash"]: a for a in mn}
    for n in (C, I):
        info(f"masternodes on {n.name} before the payments: " + json.dumps(
            {by_txhash.get(e.get("txhash"), e.get("txhash")): e.get("status") for e in n.rpc("listmasternodes")}))
    # With MN_LIFE_REWARDS, on until a block paid each controller's masternode
    # (divid picks the payee: in one run it paid one masternode 10 times)
    for k in range(40 if REWARDS else 20):
        if k >= 20 and paid_owners() >= {C.name, I.name}:
            break
        miner = (C, I)[k % 2]
        height = miner.rpc("getblockcount") + 1
        # Past 20 blocks, short of the treasury block, which mints more
        # (every 50 blocks on regtest, chainparams.cpp:492-493)
        if k >= 20 and height % 50 == 0:
            break
        out = miner.call("setgenerate", 1)
        if out[0] != "ok":
            row(f"payments: setgenerate by {miner.name} at height {height}", "ok", show(out), False)
            break
        need(synced(), f"the nodes did not follow {miner.name}'s block")
        payments, minted = coinstake_view(height)
        views_by[miner.name].append((payments, minted))
        paid.append((height, miner, payments))
        info(f"height {height} mined by {miner.name}: masternode payments {payments}, minted {minted}")
        same = lambda: C.call("getmasternodewinners", "20") == I.call("getmasternodewinners", "20")
        wait_for(same, 30)
        before = fails
        compare(f"payments: getmasternodewinners 20 after height {height}",
                C.call("getmasternodewinners", "20"), I.call("getmasternodewinners", "20"))
        if fails > before:
            refusals(I)
    if REWARDS and not paid_owners() >= {C.name, I.name}:
        info("masternodes on divid-C: " + json.dumps(
            {by_txhash.get(e.get("txhash"), e.get("txhash")): {k: e.get(k) for k in ("status", "lastpaid", "activetime")}
             for e in C.rpc("listmasternodes")}))
    voted = C.call("getmasternodewinners", "20")
    row("payments: divid's winners carry votes", any(
        (w["winner"].get("nVotes", 0) if isinstance(w["winner"], dict) else 1) for w in voted[1])
        if voted[0] == "ok" else voted, True, True)
    pays = {n: sum(1 for p, _ in v if p) for n, v in views_by.items()}
    row("payments: blocks that pay a masternode", pays[C.name], pays[I.name], pays[C.name] == pays[I.name])
    minted = {n: sorted({m for _, m in v}) for n, v in views_by.items()}
    row("payments: what a block mints", minted[C.name], minted[I.name], minted[C.name] == minted[I.name])

    # listmasternodes' lastpaid: the time of the newest of the last
    # (masternodes x 5 / 4) blocks whose payees give the masternode two votes,
    # plus its DeterministicTimeOffset (RpcMasternodeFeatures.cpp:244-277,
    # :289; masternode.cpp:219-227). Compared once the votes settled, as the
    # rows above leave it out
    def lastpaid(node):
        out = node.call("listmasternodes")
        return {e["txhash"]: e["lastpaid"] for e in out[1]} if out[0] == "ok" else show(out)
    wait_for(lambda: lastpaid(C) == lastpaid(I), 30)
    paid_c, paid_i = lastpaid(C), lastpaid(I)
    row("payments: listmasternodes lastpaid", paid_c, paid_i, paid_c == paid_i)
    # Whether any is paid: only when two masternodes are left to vote, as the
    # spent ones leave the lists (MasternodeNetworkMessageManager.cpp:36-56)
    found_c, found_i = (isinstance(p, dict) and any(p.values()) for p in (paid_c, paid_i))
    row("payments: a masternode has a lastpaid", found_c, found_i, found_c == found_i)

# 9. The wallet rows of a masternode payment (MN_LIFE_REWARDS=1, scripts/mn-reward):
# Divi Core's ParseTransactionDetails (rpcwallet.cpp:2016-2112) gives a coinstake
# a stake_reward row for the staker's wallet and an mn_reward (or lottery) row
# for each other output the wallet owns
if REWARDS:
    REWARD_DROP = MOMENT | {"time", "timereceived"}

    def coinstake_of(height):
        block = C.rpc("getblock", C.rpc("getblockhash", height))
        return block["tx"][1], C.rpc("getrawtransaction", block["tx"][1], 1)

    def rows_of(out, txid):
        """A list reply's rows of one transaction, times left out, in vout and category order"""
        if out[0] != "ok":
            return out
        rows = out[1]["transactions"] if isinstance(out[1], dict) else out[1]
        return sorted((strip(r, REWARD_DROP) for r in rows if r.get("txid") == txid),
                      key=lambda r: (r.get("vout", -1), r.get("category", "")))

    def payment_view(r, height, tip, alias):
        """A payment row by its fields, its confirmations against its height, and
        the masternode's alias in its account written as <alias> (C's and I's
        masternodes have their own aliases)"""
        v = {k: r.get(k) for k in ("category", "amount", "vout", "account", "involvesWatchonly")}
        if isinstance(v["account"], str):
            v["account"] = v["account"].replace(alias, "<alias>")
        if "confirmations" in r:
            v["confirmations is tip - height + 1"] = r["confirmations"] == tip - height + 1
        return v

    # The first block paying each controller's masternode: C's are paid in C's
    # blocks with C as the staker, I's in C's blocks with C as the staker
    owner = {a: mn[a]["controller"] for a in mn}
    first = {}
    for height, miner, payments in paid:
        for alias, value in payments:
            first.setdefault(owner[alias].name, (height, alias, value))
    info("first payment to each controller's masternode: " + json.dumps(
        {k: [h, a, v] for k, (h, a, v) in first.items()}))
    row("rewards: a block paid C's masternode and a block paid I's masternode", C.name in first, I.name in first,
        C.name in first and I.name in first)

    # Each owner's own wallet: C (divid) on a payment to its masternode, I
    # (irondivid) on a payment to its own
    if C.name in first and I.name in first:
        tip = C.rpc("getblockcount")
        own = {}
        for node in (C, I):
            height, alias, _ = first[node.name]
            txid, tx = coinstake_of(height)
            address = mn[alias]["address"]
            listed = node.call("listtransactions", "*", 1000)
            got = node.call("gettransaction", txid)
            since = node.call("listsinceblock", C.rpc("getblockhash", height - 1))
            pick = lambda rows: [r for r in rows if r.get("address") == address and r.get("category") != "send"] \
                if isinstance(rows, list) else rows
            own[node.name] = {
                "listtransactions": [payment_view(r, height, tip, alias) for r in pick(rows_of(listed, txid))],
                "gettransaction details": [payment_view(r, height, tip, alias) for r in pick(
                    got[1].get("details", []) if got[0] == "ok" else got)],
                "gettransaction confirmations": (got[1].get("confirmations") == tip - height + 1)
                if got[0] == "ok" else got,
                "listsinceblock": [payment_view(r, height, tip, alias) for r in pick(rows_of(since, txid))],
            }
        for what in own[C.name]:
            a, b = own[C.name][what], own[I.name][what]
            row(f"rewards, the owner's own wallet: {what} of the payment", json.dumps(a), json.dumps(b), a == b)

    # Two fresh wallets, a divid and an irondivid, given the keys of the payees
    # and stakers: both see the same transactions, so every row is compared
    # whole. divid 3.0.0 has no dumpwallet (rpcserver.cpp:420-464): each key
    # goes from dumpprivkey into importprivkey, in the RPC bodies only
    OD = Node("divid-OD", DIVID, 6)
    OI = Node("irondivid-OI", IRONDIVID, 7)
    for n in (OD, OI):
        n.start()
        NODES.append(n)
    mesh()
    need(synced(secs=240), "the fresh wallets did not reach the tip")
    cases = []
    for name in (C.name, I.name):
        if name in first:
            height, alias, _ = first[name]
            cases.append((f"C's block paying {name.split('-')[-1]}'s masternode", height, mn[alias]["address"]))
    i_blocks = [h for h, miner, _ in paid if miner is I]
    if i_blocks:
        cases.append(("I's block (no masternode paid)", i_blocks[0], None))
    addresses = set()
    for _, height, payee in cases:
        _, tx = coinstake_of(height)
        addresses.update(tx["vout"][1]["scriptPubKey"].get("addresses", []))
        if payee:
            addresses.add(payee)
    imported = {OD.name: [], OI.name: []}
    for address in sorted(addresses):
        holder = next((n for n in (C, I) if n.rpc("validateaddress", address).get("ismine")), None)
        need(holder is not None, f"no controller owns {address}")
        key = holder.rpc("dumpprivkey", address)
        for n in (OD, OI):
            out = n.call("importprivkey", key, "", True)
            imported[n.name].append(out[0])
        del key
    row("rewards, fresh wallets: importprivkey with rescan of each payee and staker key",
        imported[OD.name], imported[OI.name], imported[OD.name] == imported[OI.name])
    need(synced(secs=60), "the fresh wallets fell behind")
    for label, height, _ in cases:
        txid, _ = coinstake_of(height)
        since_hash = C.rpc("getblockhash", height - 1)
        a, b = rows_of(OD.call("listtransactions", "*", 1000), txid), rows_of(OI.call("listtransactions", "*", 1000), txid)
        row(f"rewards, fresh wallets, {label}: listtransactions rows", json.dumps(a), json.dumps(b), a == b)
        info(f"{label} at height {height}: categories {[r.get('category') for r in a] if isinstance(a, list) else a}")
        got = [n.call("gettransaction", txid) for n in (OD, OI)]
        compare(f"rewards, fresh wallets, {label}: gettransaction", *[
            (g[0], strip(g[1], REWARD_DROP)) if g[0] == "ok" else g for g in got])
        since = [n.call("listsinceblock", since_hash) for n in (OD, OI)]
        a, b = rows_of(since[0], txid), rows_of(since[1], txid)
        row(f"rewards, fresh wallets, {label}: listsinceblock rows", json.dumps(a), json.dumps(b), a == b)
        last = [x[1].get("lastblock") if x[0] == "ok" else x for x in since]
        row(f"rewards, fresh wallets, {label}: listsinceblock lastblock", last[0], last[1], last[0] == last[1])

for n in NODES:
    n.stop()
print(f"# {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
