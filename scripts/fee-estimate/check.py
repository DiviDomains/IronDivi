#!/usr/bin/env python3
"""Fee settings of Divi Core divid and irondivid, compared case by case: the fee
options at start, what getinfo and getwalletinfo report, the fee the wallet
pays, what sendrawtransaction takes and refuses, and a fee estimates file across
a restart. divid 3.0.0 has no estimatefee, estimatepriority or settxfee call and
never makes its fee estimator (txmempool.cpp:50 is commented out), so it reads
and writes no estimates file; estimatefee and settxfee are compared in
scripts/util-replies and scripts/keys-replies, estimatepriority once here.

Both wallets come from the same phrase and sit on one regtest chain. After the
setup irondivid is restarted with no peer: each node then sees only its own
sends, so both wallets keep the same coins and choose the same ones, and a raw
transaction one node takes is not relayed to the other. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
SAT = 100_000_000

# Calls irondivid has and divid 3.0.0 does not (not in rpcserver.cpp:324-467): a
# row of one is KNOWN while divid answers "Method not found" and irondivid
# answers, otherwise FAIL, so the list stays true
IRONDIVID_ONLY = {
    "estimatepriority": "answered -1 (no estimate), kept with estimatefee and estimatesmartfee for "
                        "Bitcoin-family clients (docs/divid-differences.md R1)",
}


def core_aborts(c, i):
    return c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2]


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
ABORT = ("same message; divid then aborts (SIGABRT) in the shutdown after this early InitError: "
         "PrepareShutdown's FlushStateToDisk (init.cpp:381) asserts in ChainstateManager::Get "
         "(ChainstateManager.cpp:102) before the chain state exists; irondivid exits 1 "
         "(also KNOWN in scripts/restart-options)", core_aborts)
def only_iron(c, i):
    return c == ("ok", "absent") and i[0] == "ok" and i[1] != "absent"


EXTRA_FIELD = ("irondivid adds the field (getinfo: also KNOWN in scripts/chain-replies; getwalletinfo: "
               "docs/divid-differences.md R4); divid's rpcmisc.cpp:136-157 and rpcwallet.cpp:2873-2907 "
               "have no paytxfee", only_iron)
KNOWN = {
    "start -minrelaytxfee=0": ABORT,
    "start -minrelaytxfee=abc": ABORT,
    "start -maxtxfee=0": ABORT,
    "start -maxtxfee=abc": ABORT,
    "getinfo paytxfee": EXTRA_FIELD,
    "getwalletinfo paytxfee": EXTRA_FIELD,
}


def known_entry(name):
    """A row's KNOWN entry; the paytxfee rows under a setting share one"""
    if name in KNOWN:
        return KNOWN[name]
    base = name.split(" (", 1)[0]
    return KNOWN.get(base) if base.endswith("paytxfee") else None

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    method = name.split(" ", 1)[0]
    if method in IRONDIVID_ONLY and raw is not None:
        c, i = raw
        if c[0] == "err" and c[1] == -32601 and not (i[0] == "err" and i[1] == -32601):
            word, note = "KNOWN", f"  [known: irondivid only; {IRONDIVID_ONLY[method]}]"
        else:
            word, note = "FAIL", "  [listed as irondivid only, but divid answers or irondivid does not]"
    elif known_entry(name):
        reason, shape = known_entry(name)
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"fee{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=fee{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ]
        self.peer = list(extra_conf)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + self.peer + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def start(self, extra=()):
        """('up',) once RPC answers, or ('exit', code, the first stderr line naming an error)"""
        self.write_conf(extra)
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.err = base + ".err"
        env = dict(os.environ, **self.env) if self.env else None
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
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


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:100]}\""
    return json.dumps(out[1])[:80]


def compare(name, core, iron):
    """Same outcome: for an error the same code and text, for a result the same value"""
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(name, core, iron)
    return core, iron


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


def restart(extra=(), iron_extra=None):
    """Both nodes again with `extra` divi.conf lines (irondivid: `iron_extra` if
    given); their start outcomes"""
    for n in (C, I):
        n.stop()
    out = C.start(extra), I.start(extra if iron_extra is None else iron_extra)
    lock_raw(out)
    return out


def lock_raw(outcomes=(("up",), ("up",))):
    """Keep the coins the raw transactions spend out of each wallet's own sends
    (a lock lasts until the node stops)"""
    for n, o in zip((C, I), outcomes):
        if o[0] == "up" and RAW:
            n.rpc("lockunspent", False, [{"txid": t, "vout": v} for t, v, _ in RAW])


def need_up(outcomes, what, nodes=None):
    for n, o in zip(nodes or (C, I), outcomes):
        if o[0] != "up":
            print(f"FAIL   setup: {n.name} did not start {what}: {o}", flush=True)
            sys.exit(1)


# --- raw transactions -------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    return n.to_bytes(25, "big")[1:21]


def p2pkh(address):
    return bytes.fromhex("76a914") + b58decode(address) + bytes.fromhex("88ac")


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def spend(coin, outputs):
    """An unsigned spend of coin = (txid, n); outputs: (satoshis, address)"""
    b = struct.pack("<i", 1) + compact(1)
    b += bytes.fromhex(coin[0])[::-1] + struct.pack("<I", coin[1]) + compact(0) + struct.pack("<I", 0xffffffff)
    b += compact(len(outputs))
    for value, address in outputs:
        script = p2pkh(address)
        b += struct.pack("<q", value) + compact(len(script)) + script
    return (b + struct.pack("<I", 0)).hex()


def signed(hexstr):
    return C.rpc("signrawtransaction", hexstr)["hex"]


def fee_paid(node, txid):
    """The fee in satoshis and the size in bytes of the node's own send"""
    if isinstance(txid, dict):  # fundvault answers {"txhash": ...}
        txid = txid["txhash"]
    tx = node.rpc("gettransaction", txid)
    size = len(node.rpc("getrawtransaction", txid)) // 2
    return (round(abs(float(tx["fee"])) * SAT), size)


def send_pair(name, method, *params):
    """The same send made by each wallet on its own node: the fee each pays"""
    c, i = C.call(method, *params), I.call(method, *params)
    if c[0] == i[0] == "ok":
        cf, ifee = fee_paid(C, c[1]), fee_paid(I, i[1])
        # the size may differ by a byte per input: a signature is 71 or 72 bytes
        row(name, f"fee {cf[0]} sat, {cf[1]} bytes", f"fee {ifee[0]} sat, {ifee[1]} bytes", cf[0] == ifee[0])
    else:
        compare(name, c, i)


# --- the nodes and the chain -----------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
need_up([C.start()], "at first", [C])
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.2:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
need_up([I.start()], "at first", [I])
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

C.rpc("setgenerate", 60)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# Addresses both wallets own (handed out by divid, given the same account on
# irondivid), and the oldest coins, the same on both
X, Y, Z, OWN, MGR = (C.rpc("getnewaddress") for _ in range(5))
for a in (X, Y, Z, OWN, MGR):
    I.rpc("setaccount", a, "")
coins = sorted(C.rpc("listunspent"), key=lambda u: -u["confirmations"])
OLD = [(u["txid"], u["vout"], round(float(u["amount"]) * SAT)) for u in coins]
RAW = []

# irondivid alone from here: no peer
I.stop()
I.peer = ["listen=0", "connect=127.0.0.2:1"]
need_up([I.start()], "alone", [I])
RAW = OLD[:12]
lock_raw()
if not wait_for(lambda: C.rpc("getconnectioncount") == 0 and I.rpc("getconnectioncount") == 0, 60):
    print("FAIL   setup: the nodes are still connected", flush=True)
    sys.exit(1)

def fee_fields(when=""):
    """relayfee and paytxfee as getinfo and getwalletinfo report them"""
    suffix = f" ({when})" if when else ""
    for method in ("getinfo", "getwalletinfo"):
        c, i = C.rpc(method), I.rpc(method)
        for field in ("relayfee", "paytxfee"):
            if field == "relayfee" and method == "getwalletinfo" and field not in c:
                continue
            compare(f"{method} {field}{suffix}", ("ok", c.get(field, "absent")), ("ok", i.get(field, "absent")))


def log_since(node, mark):
    """The node's debug.log lines written since `mark` (its size before a start)"""
    for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
        if os.path.exists(path):
            with open(path, "rb") as f:
                f.seek(mark.get(path, 0))
                return f.read().decode(errors="replace")
    return ""


def log_marks(node):
    out = {}
    for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
        if os.path.exists(path):
            out[path] = os.path.getsize(path)
    return out


def mentions(text, *words):
    low = text.lower()
    return any(w in low for w in words)


# --- the calls divid does not have: one refusal --------------------------------------
both("estimatepriority 2", "estimatepriority", 2)

# --- what getinfo and getwalletinfo report at divid's defaults ------------------------
fee_fields()

# --- the fee the wallet pays, at divid's default relay fee (10,000 sat/kB) --------------
send_pair("sendtoaddress 10 (default relay fee)", "sendtoaddress", X, 10)
send_pair("sendmany 1+2+3 (default relay fee)", "sendmany", "", {X: 1, Y: 2, Z: 3})
THIRTY = {C.rpc("getnewaddress"): 1 for _ in range(30)}
send_pair("sendmany to 30 addresses (default relay fee)", "sendmany", "", THIRTY)
send_pair("fundvault owner:manager 100 (default relay fee)", "fundvault", f"{OWN}:{MGR}", 100)
send_pair("sendtoaddress 4000, several inputs (default relay fee)", "sendtoaddress", Y, 4000)

# --- sendrawtransaction against -maxtxfee (default 100 DIVI) --------------------------
high = signed(spend(OLD[0][:2], [(OLD[0][2] - 150 * SAT, X)]))
both("sendrawtransaction with a 150 DIVI fee", "sendrawtransaction", high)
c, i = C.call("sendrawtransaction", high, True), I.call("sendrawtransaction", high, True)
compare("sendrawtransaction with a 150 DIVI fee, allowhighfees", ("ok", "txid") if c[0] == "ok" else c,
        ("ok", "txid") if i[0] == "ok" else i)
under = signed(spend(OLD[1][:2], [(OLD[1][2] - 99 * SAT, X)]))
c, i = C.call("sendrawtransaction", under), I.call("sendrawtransaction", under)
compare("sendrawtransaction with a 99 DIVI fee", ("ok", "txid") if c[0] == "ok" else c,
        ("ok", "txid") if i[0] == "ok" else i)
# the same coin again, paying another fee: a conflict with the mempool
again = signed(spend(OLD[1][:2], [(OLD[1][2] - 98 * SAT, Y)]))
both("sendrawtransaction spending a coin a mempool transaction spends", "sendrawtransaction", again)
for n in (C, I):
    n.rpc("setgenerate", 1)
both("sendrawtransaction spending a coin spent in a block", "sendrawtransaction", again)
both("sendrawtransaction of a transaction in a block", "sendrawtransaction", under)

# --- blocks with fee-paying transactions at several rates, mined by each node ------------
for k, sats_per_kb in enumerate((20_000, 50_000, 100_000, 500_000)):
    coin = OLD[2 + k]
    tx = signed(spend(coin[:2], [(coin[2] - sats_per_kb * 192 // 1000, Z)]))
    for n in (C, I):
        n.call("sendrawtransaction", tx)
for n in (C, I):
    n.rpc("setgenerate", 3)

# --- a fee estimates file across a restart: none, kept, corrupt, removed ----------------
def estimates_file(node):
    """fee_estimates.dat in the node's network directory: <datadir>/regtest for
    divid; irondivid keeps regtest's files in the -datadir itself"""
    sub = os.path.join(node.dir, "regtest")
    return os.path.join(sub if os.path.isdir(sub) else node.dir, "fee_estimates.dat")


def restart_logged(what, before=None):
    """Both nodes again; their start outcomes and whether each log names the file"""
    marks = {n: log_marks(n) for n in (C, I)}
    for n in (C, I):
        n.stop()
    if before:
        before()
    outcomes = (C.start(), I.start())
    lock_raw(outcomes)
    named = [mentions(log_since(n, marks[n]), "fee_estimates", "estimates file") for n in (C, I)]
    c, i = (f"{o[0]}, log {'names' if m else 'does not name'} the file" for o, m in zip(outcomes, named))
    row(f"start {what}", c, i, c == i, outcomes)
    need_up(outcomes, what)


restart_logged("with no fee estimates file")
c, i = (os.path.exists(estimates_file(n)) for n in (C, I))
row("a fee_estimates.dat written by the clean stop", "yes" if c else "no", "yes" if i else "no", c == i)


def corrupt():
    for n in (C, I):
        with open(estimates_file(n), "wb") as f:
            f.write(secrets.token_bytes(64))


restart_logged("with a corrupt fee_estimates.dat", corrupt)
restart_logged("with the corrupt fee_estimates.dat kept", None)


def remove():
    for n in (C, I):
        try:
            os.remove(estimates_file(n))
        except FileNotFoundError:
            pass


restart_logged("with fee_estimates.dat removed", remove)

# --- -minrelaytxfee=0.001: what is paid and what is relayed ----------------------------
need_up(restart(["minrelaytxfee=0.001"]), "with -minrelaytxfee=0.001")
fee_fields("-minrelaytxfee=0.001")
send_pair("sendtoaddress 10 (-minrelaytxfee=0.001)", "sendtoaddress", X, 10)
send_pair("sendmany 1+2+3 (-minrelaytxfee=0.001)", "sendmany", "", {X: 1, Y: 2, Z: 3})
send_pair("fundvault owner:manager 100 (-minrelaytxfee=0.001)", "fundvault", f"{OWN}:{MGR}", 100)
old_low = signed(spend(OLD[8][:2], [(OLD[8][2] - 20_000, X)]))
c, i = C.call("sendrawtransaction", old_low), I.call("sendrawtransaction", old_low)
compare("sendrawtransaction of an old coin paying 0.0002 (-minrelaytxfee=0.001)",
        ("ok", "txid") if c[0] == "ok" else c, ("ok", "txid") if i[0] == "ok" else i)

# --- -maxtxfee=0.0002: a send whose fee would pass it, and sendrawtransaction ------------
need_up(restart(["maxtxfee=0.0002"]), "with -maxtxfee=0.0002")
fee_fields("-maxtxfee=0.0002")
send_pair("sendtoaddress 10 (-maxtxfee=0.0002)", "sendtoaddress", X, 10)
send_pair("sendtoaddress 20000, many inputs (-maxtxfee=0.0002)", "sendtoaddress", Y, 20000)
over = signed(spend(OLD[9][:2], [(OLD[9][2] - 100_000, X)]))
c, i = C.call("sendrawtransaction", over), I.call("sendrawtransaction", over)
compare("sendrawtransaction paying 0.001 (-maxtxfee=0.0002)", ("ok", "txid") if c[0] == "ok" else c,
        ("ok", "txid") if i[0] == "ok" else i)
c, i = C.call("sendrawtransaction", over, True), I.call("sendrawtransaction", over, True)
compare("sendrawtransaction paying 0.001, allowhighfees (-maxtxfee=0.0002)", c, i)
# in the mempool now: sent again it is relayed, the fee not checked (rpcrawtransaction.cpp:875)
c, i = C.call("sendrawtransaction", over), I.call("sendrawtransaction", over)
compare("sendrawtransaction of that transaction again, in the mempool (-maxtxfee=0.0002)", c, i)
# a spend of its output, in the mempool only: its fee counts the mempool output
# (rpcrawtransaction.cpp:810-826)
if c[0] == "ok":
    child = signed(spend((c[1], 0), [(OLD[9][2] - 200_000, X)]))
    c, i = C.call("sendrawtransaction", child), I.call("sendrawtransaction", child)
    compare("sendrawtransaction spending a mempool output, paying 0.001 (-maxtxfee=0.0002)",
            ("ok", "txid") if c[0] == "ok" else c, ("ok", "txid") if i[0] == "ok" else i)
    c, i = C.call("sendrawtransaction", child, True), I.call("sendrawtransaction", child, True)
    compare("sendrawtransaction spending a mempool output, paying 0.001, allowhighfees (-maxtxfee=0.0002)", c, i)

# --- the fee options at start ------------------------------------------------------------
for option, values in (("paytxfee", ("0.001", "0", "1000", "abc")),
                       ("mintxfee", ("0.001", "0", "1000", "abc")),
                       ("minrelaytxfee", ("0.001", "10", "0", "abc")),
                       ("maxtxfee", ("0.5", "0", "10000", "abc"))):
    for value in values:
        marks = {n: log_marks(n) for n in (C, I)}
        c, i = restart([f"{option}={value}"])
        show_start = lambda s: "up" if s[0] == "up" else f"exit {s[1]} \"{s[2][:110]}\""
        row(f"start -{option}={value}", show_start(c), show_start(i),
            show_start(c) == show_start(i), (c, i))
        warned = [mentions(log_since(n, marks[n]), "set very high") for n in (C, I)]
        if any(warned):
            row(f"start -{option}={value}: the 'set very high' warning in the log",
                "yes" if warned[0] else "no", "yes" if warned[1] else "no", warned[0] == warned[1])
        if option == "paytxfee" and value == "0.001" and c[0] == i[0] == "up":
            fee_fields("-paytxfee=0.001")
            send_pair("sendtoaddress 10 (-paytxfee=0.001)", "sendtoaddress", X, 10)
        if option == "mintxfee" and value == "0.001" and c[0] == i[0] == "up":
            send_pair("sendtoaddress 10 (-mintxfee=0.001)", "sendtoaddress", X, 10)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
