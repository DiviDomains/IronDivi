#!/usr/bin/env python3
"""The debug and check start options of Divi Core's help (LicenseAndInfo.cpp:163-201),
divid and irondivid compared on regtest: whether each value starts the node, whether
the log calls the option unknown or unsupported, what can be seen of its effect, and
whether -help -help-debug lists it.

Both nodes keep one data directory with a wallet across their restarts; the
-loadblock runs use fresh ones. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs. Started by run.sh,
which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), os.path.abspath(sys.argv[4])
RPC_TIMEOUT = 60
START_TIMEOUT = 240
NODE_IP = "127.0.0.2"
INJECT = os.environ.get("CHECK_OPTIONS_INJECT", "")

OPTIONS = ["checkblockindex", "checkmempool", "checkpoints", "dropmessagestest", "fuzzmessagestest",
           "flushwallet", "maxsigcachesize", "printpriority"]
VALUES = [("=0", "0"), ("=1", "1"), ("with no value", ""), ("=-1", "-1"), ("=abc", "abc")]

# Rows where irondivid differs on purpose: (reason, shape)
HELP = ("divid's -help -help-debug prints every option, the debug ones among them (LicenseAndInfo.cpp:160-202); "
        "irondivid's -help is its own short summary of the common options, with no debug section "
        "(USAGE, bin/irondivid/src/main.rs:88-107) [by design]")
KNOWN = {f"-help -help-debug lists -{o}": (HELP, lambda c, i: c is True and i is False)
         for o in ["checkblockindex", "checkmempool", "checkpoints", "dropmessagestest", "fuzzmessagestest",
                   "flushwallet", "maxsigcachesize", "printpriority", "stopafterblockimport"]}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron):
    global fails
    if INJECT == name:
        iron = ["injected"]
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note}"[:700], flush=True)


def facts(name, fn):
    row(name, fn(C), fn(I))


def setup_failed(kind, value, tb):
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   setup (line {where}): {value}"[:400], flush=True)
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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, ports):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * ports
        self.rpcport = PORT_BASE + 2 * ports + 1
        self.index = index
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"co{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=co{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ]
        os.makedirs(os.path.join(self.dir, "home"))
        self.proc = None
        self.starts = 0

    def log_path(self):
        for p in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(p):
                return p
        return None

    def log_size(self):
        p = self.log_path()
        return os.path.getsize(p) if p else 0

    def log_since(self, offset):
        p = self.log_path()
        if not p:
            return ""
        with open(p, errors="replace") as f:
            f.seek(offset)
            return f.read()

    def start(self, extra=(), connect="connect=127.0.0.2:1", args=()):
        """('up',) once RPC answers, ('exit', code, the first stderr line naming an error)"""
        lines = self.base + ([connect] if connect else []) + list(extra)
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))
        self.starts += 1
        self.log_from = self.log_size()
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code, self.error_line())
            if self.call("getblockcount")[0] == "ok":
                return ("up",)
            time.sleep(0.25)
        return ("exit", "none within %d s" % START_TIMEOUT, self.error_line())

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "http")
        except (OSError, ValueError):
            return ("err", None, "no reply")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_exit(self, secs):
        """The exit code once the node stops by itself within `secs`, else 'still running'"""
        if self.proc is None:
            return "not running"
        try:
            code = self.proc.wait(timeout=secs)
            self.proc = None
            return code
        except subprocess.TimeoutExpired:
            return "still running"

    def stop(self):
        if self.proc is None:
            return
        self.call("stop")
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def mine(self, n):
        for _ in range(n):
            self.rpc("setgenerate", 1)


def start_both(extra=(), connect="connect=127.0.0.2:1", args=()):
    out = {}
    for n in NODES:
        o = n.start(extra, connect, args)
        out[n] = "up" if o[0] == "up" else [o[1], o[2]]
    return out


def stop_both():
    for n in NODES:
        n.stop()


def warned(n, option):
    """Whether the log since the start calls `option` unknown or unsupported"""
    text = n.log_since(n.log_from)
    return any(option in line and ("nknown option" in line or "not supported" in line)
               for line in text.splitlines())


C = Node("divid", DIVID, 0, 0)
I = Node("irondivid", IRONDIVID, 1, 1)
NODES = (C, I)

# --- -help -help-debug ------------------------------------------------------------------
for n in NODES:
    out = subprocess.run([n.binary, "-help", "-help-debug"], capture_output=True, text=True, timeout=60,
                         env=dict(os.environ, HOME=os.path.join(n.dir, "home")))
    n.help = out.stdout + out.stderr
for option in OPTIONS + ["stopafterblockimport"]:
    facts(f"-help -help-debug lists -{option}", lambda n, o=option: f"-{o}" in n.help)

# --- the first start makes the wallets and a chain ---------------------------------------
first = start_both()
row("start with no option", first[C], first[I])
for n in NODES:
    n.mine(30)
facts("height after the setup", lambda n: n.rpc("getblockcount"))
stop_both()

# --- every value of every option: the start and the log ----------------------------------
# A bare option is a command-line form: in the config file divid refuses a line
# without "=" (Settings.cpp ReadConfigFile)
def option_forms(options, value):
    if value:
        return [f"{o}={value}" for o in options], []
    return [], [f"-{o}" for o in options]


for label, value in VALUES:
    lines, args = option_forms(OPTIONS, value)
    out = start_both(lines, args=args)
    row(f"start with every option {label}", out[C], out[I])
    for option in OPTIONS:
        facts(f"log calls -{option} unknown or unsupported ({label})", lambda n, o=option: warned(n, o))
    stop_both()

# --- -stopafterblockimport: the import thread runs at every start, so the node stops
# right after it (init.cpp:686-728) -------------------------------------------------------------
def stopped(outcome):
    """A start with -stopafterblockimport, up or ended by itself: whether RPC
    answers before the stop is a race on both nodes, and so is divid's exit code
    (1 when the stop comes during its init, 0 after it; init.cpp:724-727)"""
    if outcome == "up" or outcome[0] in (0, 1):
        return "up or stopped"
    return ["exit", outcome[0], outcome[1]]


def stops(n, secs):
    """Whether the node has stopped by itself within `secs` (or before RPC answered)"""
    code = n.wait_exit(secs)
    return "stopped" if code in (0, 1, "not running") else code


for label, value in VALUES:
    lines, args = option_forms(["stopafterblockimport"], value)
    out = start_both(lines, args=args)
    row(f"-stopafterblockimport {label}: start", stopped(out[C]), stopped(out[I]))
    facts(f"-stopafterblockimport {label}: stopped within 60 s", lambda n: stops(n, 60))
    stop_both()

# With -loadblock of a block file divid wrote: the import, then the stop
blocks = os.path.join(WORK, "blocks.dat")
shutil.copy(os.path.join(C.dir, "regtest", "blocks", "blk00000.dat"), blocks)
LC = Node("divid-import", DIVID, 2, 2)
LI = Node("irondivid-import", IRONDIVID, 3, 3)
NODES = (LC, LI)
out = start_both(["disablewallet=1", f"loadblock={blocks}", "stopafterblockimport=1"])
row("-loadblock with -stopafterblockimport: start", stopped(out[LC]), stopped(out[LI]))
row("-loadblock with -stopafterblockimport: stopped within 120 s", stops(LC, 120), stops(LI, 120))
out = start_both(["disablewallet=1"])
row("-loadblock with -stopafterblockimport: start again", out[LC], out[LI])
row("-loadblock with -stopafterblockimport: height after the import", LC.rpc("getblockcount"),
    LI.rpc("getblockcount"))
stop_both()
NODES = (C, I)

# --- -checkmempool and -checkblockindex: up through sends, blocks and an
# invalidate/reconsider (init.cpp:795, BlockCheckingHelpers.cpp:162) ----------------------------
for label, lines in (("-checkmempool=1 -checkblockindex=1", ["checkmempool=1", "checkblockindex=1"]),
                     ("-checkmempool=0 -checkblockindex=0", ["checkmempool=0", "checkblockindex=0"])):
    out = start_both(lines)
    row(f"{label}: start", out[C], out[I])
    base = {n: n.rpc("getblockcount") for n in NODES}
    for n in NODES:
        for _ in range(3):
            n.rpc("sendtoaddress", n.rpc("getnewaddress"), 1)
        n.mine(2)
        tip = n.rpc("getbestblockhash")
        n.rpc("invalidateblock", tip)
        n.rpc("reconsiderblock", tip)
    facts(f"{label}: up after sends, blocks, invalidate and reconsider", lambda n: n.alive())
    facts(f"{label}: blocks added", lambda n: n.rpc("getblockcount") - base[n])
    facts(f"{label}: mempool after the blocks", lambda n: n.rpc("getmempoolinfo")["size"])
    stop_both()

# --- -printpriority: only in divid's help; no line when a block is made with a
# transaction in it ---------------------------------------------------------------------------
out = start_both(["printpriority=1"])
row("-printpriority=1: start", out[C], out[I])
for n in NODES:
    n.rpc("sendtoaddress", n.rpc("getnewaddress"), 1)
    n.mine(1)
facts("-printpriority=1: a log line with the priority of a transaction",
      lambda n: any("priority" in line.lower() and "fee" in line.lower()
                    for line in n.log_since(n.log_from).splitlines()))
stop_both()

# --- -dropmessagestest and -fuzzmessagestest at 1000: each starts, connects to the other
# node and stays up through a few blocks (no timing compared) ----------------------------------
for option in ("dropmessagestest", "fuzzmessagestest"):
    C.start([f"{option}=1000"], connect=None)
    I.start([f"{option}=1000"], connect=f"connect={NODE_IP}:{C.p2p}")
    wait_for(lambda: C.rpc("getconnectioncount") >= 1 and I.rpc("getconnectioncount") >= 1, 60)
    facts(f"-{option}=1000: connected to the other node", lambda n: n.rpc("getconnectioncount") >= 1)
    for n in NODES:
        n.mine(3)
    facts(f"-{option}=1000: up after a few blocks", lambda n: n.alive())
    stop_both()

for n in NODES:
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
