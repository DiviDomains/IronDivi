#!/usr/bin/env python3
"""Masternode and spork RPC replies of Divi Core divid and irondivid, compared
field by field.

Both nodes sit on one regtest chain with no masternode running. Every call is
made on both, with good arguments and with wrong or missing ones; parameters are
strings, as divi-cli sends them for these methods (divid's rpcclient.cpp has no
conversion entry for any of them). Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
masternode key setupmasternode puts in config_line is never printed: replies that
carry key material are compared by their shape only.
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
INJECT = os.environ.get("MASTERNODE_REPLIES_INJECT", "")
# Loopback address the nodes bind to (127.0.0.2 keeps clear of other programs'
# clients on 127.0.0.1 when the ports are inside the host's ephemeral range)
HOST = os.environ.get("MASTERNODE_REPLIES_HOST", "127.0.0.1")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {
    "getmasternodecount: tier counts divid lacks":
        "copper, silver, gold, platinum, diamond, kept on purpose (divid rpcmasternode.cpp:327-358 has the 8 "
        "counts only; scripts/net-replies README)",
    "mnsync status: currentMasternodeSyncStatus":
        "irondivid has no masternode sync stages and reports 999 (finished); divid's stages need 3 spork-synced "
        "peers to move on (masternode-sync.cpp:425-455), so on this two-node chain it stays at the first",
    "mnsync status after reset: currentMasternodeSyncStatus":
        "as for mnsync status: reset has no stages to restart in irondivid (rpcmisc.cpp:217-220)",
}

TIERS = {"copper", "silver", "gold", "platinum", "diamond"}

# Fields that change from one moment to the next
MOMENT = {"timestamp", "lastseen", "activetime", "lastpaid", "sigtime"}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def known(name):
    """The KNOWN reason of a row: its own entry, else the entry of the same row
    before the restart"""
    if name in KNOWN:
        return KNOWN[name]
    return KNOWN.get(name.split(": ", 1)[1]) if name.startswith("after restart: ") else None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.addr = f"{HOST}:{self.p2p}"
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            f"bind={HOST}", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
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

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def shape(v):
    """A reply's field names and JSON types, without its values"""
    if isinstance(v, dict):
        return {k: shape(x) for k, x in v.items()}
    if isinstance(v, list):
        return [shape(x) for x in v]
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, str):
        # parse_float=str: a JSON number with a fraction arrives as text
        return "string"
    return type(v).__name__


def first_difference(a, b, path="$", values=True):
    """Where two replies first differ, or None. With values=False the values
    themselves are not shown (a reply that carries key material)."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}", values)
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]", values)
            if d:
                return d
        return None
    if a != b or type(a) is not type(b):
        if not values:
            return f"{path} differs"
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def help_text(out):
    """divid answers a call it cannot run with its help text as a -1 error
    (runtime_error, rpcserver.cpp): such errors are compared by their first line"""
    return out[0] == "err" and out[1] == -1 and "\n" in out[2].strip()


def error_text(out):
    return out[2].strip().split("\n")[0] if help_text(out) else out[2]


def short(out, values=True):
    if out[0] == "err":
        return f"error {out[1]} \"{error_text(out)[:80]}\"".replace("\n", "\\n")
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60] if values else type(v).__name__


def compare(name, core, iron, drop=MOMENT, by_shape=False):
    """Same outcome. An error: same code and message (the first line of a help
    text). A result: the same fields, JSON types and values (except `drop`), or
    with by_shape only the same fields and types"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", inject(iron[1]))
    values = not by_shape
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1] == iron[1] and error_text(core) == error_text(iron)
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if by_shape:
        a, b = shape(a), shape(b)
    d = first_difference(a, b, values=values)
    row(name, short(core, values), d or short(iron, values), d is None)


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, dict):
        return dict(v, injected=True)
    if isinstance(v, list):
        return v + ["injected"]
    return "injected"


def safe_call(node, method, *params):
    """A call; a node that gives no reply, or stops, is noted and started again"""
    try:
        out = node.call(method, *params)
    except Exception as e:
        out = ("err", "no reply", str(e)[:80])
    if node.proc.poll() is not None:
        out = ("err", "no reply", f"{node.name} stopped (exit {node.proc.returncode})")
        node.log.close()
        node.start()
        if not node.wait_ready():
            print(f"FAIL   {node.name} did not start again after {method}", flush=True)
            sys.exit(1)
        synced()
    return out


def both(name, method, *params, **kw):
    core, iron = safe_call(C, method, *params), safe_call(I, method, *params)
    compare(name, core, iron, **kw)
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


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0, ["listen=1"])
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect={HOST}:{PORT_BASE}"])
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 60)


# divid mines past maturity and pays irondivid, so both wallets can fund a
# copper collateral (100 DIVI on regtest, chainparams.cpp:147-148). Past height
# 101, so getmasternodewinners has heights to score: height h is scored with the
# block at h - 101 (MasternodeHelpers.cpp:75-86)
C.rpc("setgenerate", 130)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
i_addr = I.rpc("getnewaddress")
for _ in range(3):
    C.rpc("sendtoaddress", i_addr, 1000)
C.rpc("setgenerate", 1)
if not wait_for(lambda: float(I.rpc("getbalance")) >= 3000, 60) or not synced():
    print("FAIL   setup: irondivid did not receive its coins", flush=True)
    sys.exit(1)


def mnsync_status(name):
    """mnsync status without its sync stage, then the stage on a row of its own"""
    c, i = both(name, "mnsync", "status", drop=MOMENT | {"currentMasternodeSyncStatus"})
    if c[0] == i[0] == "ok":
        a, b = c[1].get("currentMasternodeSyncStatus"), i[1].get("currentMasternodeSyncStatus")
        row(f"{name}: currentMasternodeSyncStatus", a, b, a == b)


def state(p):
    """Calls whose reply depends only on the chain and the stored broadcasts"""
    both(f"{p}spork show", "spork", "show")
    both(f"{p}spork active", "spork", "active")
    mnsync_status(f"{p}mnsync status")
    both(f"{p}listmasternodes", "listmasternodes")
    c, i = both(f"{p}getmasternodecount", "getmasternodecount", drop=MOMENT | TIERS)
    if c[0] == i[0] == "ok":
        extra = sorted(set(i[1]) - set(c[1]))
        row(f"{p}getmasternodecount: tier counts divid lacks", "-", ",".join(extra) or "-", not extra)
    both(f"{p}getmasternodestatus", "getmasternodestatus")
    both(f"{p}getmasternodewinners", "getmasternodewinners")
    both(f"{p}listmnbroadcasts", "listmnbroadcasts", by_shape=True)


state("")

# spork (rpcmisc.cpp:277-315)
both("spork unknown name", "spork", "SPORK_99_NOT_A_SPORK", "1")
both("spork set without the key", "spork", "SPORK_2_SWIFTTX_ENABLED", "4070908800")
both("spork set, value as a number", "spork", "SPORK_2_SWIFTTX_ENABLED", 4070908800)
both("spork no arguments", "spork")
both("spork unknown mode", "spork", "list")
both("spork show with a value", "spork", "show", "1")
both("spork three arguments", "spork", "SPORK_2_SWIFTTX_ENABLED", "1", "2")

# mnsync (rpcmisc.cpp:160-200)
both("mnsync no arguments", "mnsync")
both("mnsync unknown mode", "mnsync", "next")
both("mnsync two arguments", "mnsync", "status", "status")
both("mnsync reset", "mnsync", "reset")
mnsync_status("mnsync status after reset")

# list, count, status, winners (rpcmasternode.cpp:263-593)
both("listmasternodes filter", "listmasternodes", "127.0.0.1")
both("listmasternodes two arguments", "listmasternodes", "a", "b")
both("listmasternodes filter as a number", "listmasternodes", 5)
both("getmasternodecount with an argument", "getmasternodecount", "x")
both("getmasternodestatus with an argument", "getmasternodestatus", "x")
both("getmasternodewinners 5", "getmasternodewinners", "5")
both("getmasternodewinners 5 filter", "getmasternodewinners", "5", "Unknown")
both("getmasternodewinners 5 filter no match", "getmasternodewinners", "5", "nomatch")
both("getmasternodewinners not a number", "getmasternodewinners", "abc")
both("getmasternodewinners blocks as a number", "getmasternodewinners", 5)
both("getmasternodewinners four arguments", "getmasternodewinners", "5", "a", "b", "c")

# allocatefunds (rpcmasternode.cpp:63-120)
both("allocatefunds no arguments", "allocatefunds")
both("allocatefunds two arguments", "allocatefunds", "masternode", "mn1")
both("allocatefunds other purpose", "allocatefunds", "vault", "mn1", "copper")
both("allocatefunds unknown tier", "allocatefunds", "masternode", "mn1", "bronze")
c_alloc, i_alloc = both("allocatefunds masternode mn1 copper", "allocatefunds", "masternode", "mn1", "copper",
                        by_shape=True)

# setupmasternode (rpcmasternode.cpp:183-247): key material in config_line, so by shape.
# Both allocations go into the next block: divid mines once it has irondivid's too
allocations = [a[1]["txhash"] for a in (c_alloc, i_alloc) if a[0] == "ok"]
if not wait_for(lambda: set(allocations) <= set(C.rpc("getrawmempool")), 60):
    print("FAIL   setup: the allocations did not reach divid's mempool", flush=True)
    sys.exit(1)
C.rpc("setgenerate", 1)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's block", flush=True)
    sys.exit(1)


def collateral_pubkey(node):
    return node.rpc("validateaddress", node.rpc("getnewaddress")).get("pubkey", "")


both("setupmasternode no arguments", "setupmasternode")
both("setupmasternode four arguments", "setupmasternode", "mn1", "00" * 32, "0", "02" + "00" * 32)
both("setupmasternode seven arguments", "setupmasternode", "mn1", "00" * 32, "0", "02" + "00" * 32,
     "127.0.0.1", "x", "y")
both("setupmasternode unknown collateral", "setupmasternode", "mn9", "11" * 32, "0",
     collateral_pubkey(C), "127.0.0.1", by_shape=True)
setups = {}
if c_alloc[0] == "ok" and i_alloc[0] == "ok":
    c_setup = C.call("setupmasternode", "mn1", c_alloc[1]["txhash"], str(c_alloc[1]["vout"]),
                     collateral_pubkey(C), "127.0.0.1")
    i_setup = I.call("setupmasternode", "mn1", i_alloc[1]["txhash"], str(i_alloc[1]["vout"]),
                     collateral_pubkey(I), "127.0.0.1")
    compare("setupmasternode mn1 (shape)", c_setup, i_setup, by_shape=True)
    setups = {C: c_setup, I: i_setup}
    if c_setup[0] == i_setup[0] == "ok":
        both_v = [s[1].get("protocol_version") for s in (c_setup, i_setup)]
        row("setupmasternode mn1 protocol_version", both_v[0], both_v[1], both_v[0] == both_v[1])

        def config_line(setup, alloc):
            """config_line is "<alias> <ip:port> <masternode key> <txhash> <index>": every
            part but the key, the txhash and index against the node's own allocation"""
            parts = setup.get("config_line", "").split(" ")
            if len(parts) != 5:
                return f"{len(parts)} parts"
            ok = parts[3] == alloc["txhash"] and parts[4] == str(alloc["vout"])
            return f"{parts[0]} {parts[1]} <key> {'own txhash and index' if ok else 'other txhash or index'}"
        c_cl, i_cl = config_line(c_setup[1], c_alloc[1]), config_line(i_setup[1], i_alloc[1])
        row("setupmasternode mn1 config_line without the key", c_cl, i_cl, c_cl == i_cl)

# verifymasternodesetup (rpcmasternode.cpp:122-159): divid aborts on every call to it,
# before the arguments are read (its table entry is thread-safe and asks for the
# wallet lock, which the assertion at rpcserver.cpp:1045 forbids), and then needs
# -reindex to start. So irondivid alone is checked against what the handler says.


def iron_only(name, method, *params, expect, text):
    out = safe_call(I, method, *params)
    row(f"{name} [irondivid only]", "aborts (rpcserver.cpp:1045)", short(out), expect(out))


iron_only("verifymasternodesetup", "verifymasternodesetup", "127.0.0.1", "1700000000", "02" + "11" * 32,
          "03" + "22" * 32, text="expected_message_to_sign",
          expect=lambda o: o[0] == "ok" and isinstance(o[1], dict) and list(o[1]) == ["expected_message_to_sign"]
          and all(c in "0123456789abcdef" for c in o[1]["expected_message_to_sign"]))
iron_only("verifymasternodesetup bad sigtime", "verifymasternodesetup", "127.0.0.1", "abc", "02", "03",
          text="error -32602", expect=lambda o: o[:3] == ("err", -32602, "Error parsing input arguments\n"))
iron_only("verifymasternodesetup three arguments", "verifymasternodesetup", "127.0.0.1", "1700000000", "02",
          text="help", expect=lambda o: o[0] == "err" and o[1] == -1
          and error_text(o) == "verifymasternodesetup ip_address sigtime collateralPubKey masternodePubKey")

# signmnbroadcast, importmnbroadcast, listmnbroadcasts (rpcmasternode.cpp:161-181, 595-640)
both("signmnbroadcast no arguments", "signmnbroadcast")
both("signmnbroadcast not a broadcast", "signmnbroadcast", "zz")
both("importmnbroadcast no arguments", "importmnbroadcast")
both("importmnbroadcast short hex", "importmnbroadcast", "00")
both("listmnbroadcasts with an argument", "listmnbroadcasts", "x")
signed = {}
if setups and all(s[0] == "ok" for s in setups.values()):
    c_sig = C.call("signmnbroadcast", setups[C][1]["broadcast_data"])
    i_sig = I.call("signmnbroadcast", setups[I][1]["broadcast_data"])
    compare("signmnbroadcast of setupmasternode's broadcast (shape)", c_sig, i_sig, by_shape=True)
    if c_sig[0] == i_sig[0] == "ok":
        signed = {C: c_sig[1]["broadcast_data"], I: i_sig[1]["broadcast_data"]}
        compare("importmnbroadcast signed", C.call("importmnbroadcast", signed[C]),
                I.call("importmnbroadcast", signed[I]))
        compare("importmnbroadcast signed again", C.call("importmnbroadcast", signed[C]),
                I.call("importmnbroadcast", signed[I]))
        both("listmnbroadcasts after import", "listmnbroadcasts", by_shape=True)

# broadcaststartmasternode, startmasternode (rpcmasternode.cpp:361-425)
both("broadcaststartmasternode no arguments", "broadcaststartmasternode")
both("broadcaststartmasternode not a broadcast", "broadcaststartmasternode", "zz")
both("broadcaststartmasternode three arguments", "broadcaststartmasternode", "zz", "a", "b")
both("startmasternode no arguments", "startmasternode")
both("startmasternode unknown alias", "startmasternode", "nosuchalias")
both("startmasternode defer not a bool", "startmasternode", "nosuchalias", "yes")
both("startmasternode three arguments", "startmasternode", "a", True, "c")

# Calls of older masternode software that divid 3.0.0 does not have (rpcserver.cpp:325-409)
for m in ("masternode", "masternodelist", "masternodeconnect", "fundmasternode", "getpoolinfo", "mnbudget",
          "mnbudgetvote", "mnfinalbudget", "getbudgetinfo", "getbudgetprojection", "getbudgetvotes",
          "checkbudgets", "createmasternodekey", "getmasternodeoutputs", "listmasternodeconf",
          "startmasternodes", "obfuscation"):
    both(f"{m} (not a divid method)", m)

# Restart both: the state calls and the stored broadcast come back the same
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
if not synced():
    print("FAIL   restart: irondivid did not reconnect to divid", flush=True)
    sys.exit(1)
state("after restart: ")

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
