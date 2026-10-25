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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("MN_LIFE_INJECT", "")
# With 1, the payment phase runs too: on regtest a masternode is ranked, and so
# can vote and be paid, only 25 minutes after its broadcast was signed
# (masternode-payments.cpp:558)
PAYMENTS = os.environ.get("MN_LIFE_PAYMENTS", "") == "1"
# Loopback address every node binds to: the ports are inside the host's
# ephemeral range, where other programs' 127.0.0.1 sockets can hold them
HOST = "127.0.0.2"
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has on purpose or has not closed yet: row name -> reason.
# Each is listed in README.md with divid's source line; a KNOWN row that starts to
# match divid is a FAIL, so the list stays true.
KNOWN = {
    "member order of an object (setupmasternode)":
        "irondivid writes a result's members in name order (serde_json without preserve_order; "
        "docs/divid-differences.md R6); the members are otherwise compared as sets",
    "getmasternodecount: tier counts divid lacks":
        "copper, silver, gold, platinum, diamond, kept on purpose (divid rpcmasternode.cpp:327-358 has the 8 "
        "counts only; scripts/masternode-replies README)",
}
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
        ] + list(extra_conf)
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
    return c, i


STAGES = ("irondivid has no masternode sync stages and reports 999 (finished); divid moves through its stages "
          "with three spork-synced peers (masternode-sync.cpp:425-455) and was still in one here "
          "(scripts/masternode-replies README)")


def compare_mnsync(name, c, i):
    """mnsync status; a divid still in a sync stage against irondivid's 999 is the
    known difference, anything else is compared as usual"""
    cv = mnsync_view(c[1]) if c[0] == "ok" else c
    iv = mnsync_view(i[1]) if i[0] == "ok" else i
    a, b = json.dumps(cv, sort_keys=True), json.dumps(iv, sort_keys=True)
    staged = (c[0] == i[0] == "ok" and cv.get("currentMasternodeSyncStatus") != 999
              and iv.get("currentMasternodeSyncStatus") == 999
              and {k: x for k, x in cv.items() if k != "currentMasternodeSyncStatus"}
              == {k: x for k, x in iv.items() if k != "currentMasternodeSyncStatus"})
    row(name, a, b, a == b, reason=STAGES if staged else None)


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


# divid's masternode sync moves through its stages with three spork-synced peers
t0 = time.time()
finished = wait_for(lambda: all(sync_state(n) == 999 for n in (C, M1, M2)), 240, step=2)
info(f"divid nodes' masternode sync finished: {finished} after {time.time() - t0:.0f} s")
compare_mnsync("mnsync status, the network up", C.call("mnsync", "status"), I.call("mnsync", "status"))
compare("getmasternodestatus on a masternode node before its start (M1 for C, M2 for I)",
        M1.call("getmasternodestatus"), M2.call("getmasternodestatus"))


# 4. Start: broadcaststartmasternode from each controller
def enabled_on(node, alias):
    out = node.call("listmasternodes", mn[alias]["txhash"])
    return out[0] == "ok" and any(e.get("status") == "ENABLED" for e in out[1])


starts = {}
compare("broadcaststartmasternode <signed broadcast> from the controller",
        C.call("broadcaststartmasternode", mn["mnc"]["signed"]),
        I.call("broadcaststartmasternode", mn["mni"]["signed"]))
for alias in ("mnc", "mni"):
    starts[alias] = time.time()
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
    # Each node lists masternodes in the order it took them, its own controller's
    # first (RelayParsedMasternodeBroadcast takes it before relaying), so the
    # lists are compared in txhash order and the first entry on its own
    lists = [C.call("listmasternodes"), I.call("listmasternodes")]
    compare(f"{label}: listmasternodes (in txhash order)", *lists, mask=sorted_list)
    own = {C.name: {mn[a]["txhash"] for a in mn if mn[a]["controller"] is C},
           I.name: {mn[a]["txhash"] for a in mn if mn[a]["controller"] is I}}
    first = [o[1][0].get("txhash") in own[n.name] if o[0] == "ok" and o[1] else None for o, n in zip(lists, (C, I))]
    row(f"{label}: the controller's own masternode listed first", first[0], first[1], first[0] == first[1])
    both(f"{label}: getmasternodecount", "getmasternodecount", mask=count_view)
    compare_mnsync(f"{label}: mnsync status", C.call("mnsync", "status"), I.call("mnsync", "status"))
    both(f"{label}: getmasternodestatus (a controller)", "getmasternodestatus")
    compare(f"{label}: getmasternodestatus on the masternode node (M1 for C's, M2 for I's)",
            M1.call("getmasternodestatus"), M2.call("getmasternodestatus"),
            mask=lambda v: {k: x for k, x in v.items() if k not in ("txhash", "outputidx", "netaddr", "addr")})
    both(f"{label}: getmasternodewinners", "getmasternodewinners", "5")


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
compare("silver: broadcaststartmasternode from the controller",
        C.call("broadcaststartmasternode", mn["mnc2"]["signed"]),
        I.call("broadcaststartmasternode", mn["mni2"]["signed"]))
for alias in ("mnc2", "mni2"):
    wait_for(lambda: enabled_on(C, alias) and enabled_on(I, alias), 120)
views("four masternodes")

# 6. Restarts: the peer, then the masternode nodes
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
mesh()
need(synced(secs=180), "the controllers did not come back to the tip")
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
    paid = {C.name: [], I.name: []}
    for k in range(20):
        miner = (C, I)[k % 2]
        height = miner.rpc("getblockcount") + 1
        winners = [n.call("getmasternodewinners", "1") for n in (C, I)]
        mine(miner, 1)
        block = C.rpc("getblock", C.rpc("getblockhash", height))
        payees = []
        for txid in block["tx"][:2]:
            tx = C.rpc("getrawtransaction", txid, 1)
            for o in tx["vout"]:
                for addr in o.get("scriptPubKey", {}).get("addresses", []):
                    if addr in collateral_addresses:
                        payees.append((collateral_addresses[addr], o["value"]))
        paid[miner.name].append(bool(payees))
        info(f"height {height} mined by {miner.name}: masternode payment {payees}")
        compare(f"payments: getmasternodewinners before height {height}", *winners)
    row("payments: blocks that pay a masternode, of 10 mined by each", sum(paid[C.name]), sum(paid[I.name]),
        sum(paid[C.name]) == sum(paid[I.name]))

for n in NODES:
    n.stop()
print(f"# {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
