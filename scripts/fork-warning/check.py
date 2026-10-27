#!/usr/bin/env python3
"""Divi Core's fork warning, on divid and on irondivid. Two nodes compared,
divid A and irondivid A, take blocks from two divid miners: N mines the
nodes' own branch and M a branch 20 blocks long from the same fork. The nodes
move to M's branch, invalidate its first block, are restarted, and take
blocks from N: getinfo's and getmininginfo's "errors", safe mode, the log line
and -alertnotify are compared at each step, until the warning goes when the
tip is six blocks below M's, and after reconsiderblock. Every block is a
proof-of-work block (regtest's last is 100), so each is worth the same work.
Each row prints PASS (irondivid as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("FORK_WARNING_INJECT", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 120
SYNC_TIMEOUT = 120
BIND_RETRIES = 5
WARNING = ("Warning: We do not appear to fully agree with our peers! You may need to upgrade, "
           "or other nodes may need to upgrade.")
LOG_LINE = "CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain."

# Differences listed in README.md with divid's source line, one per row name:
# (reason, shape). shape takes the two values and is true only for the
# difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL.
KNOWN = {
}

fails = 0


def row(name, core, iron):
    global fails
    if name == INJECT:
        iron = {"injected": iron}
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    show = lambda v: json.dumps(v, sort_keys=True)[:200]
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


def info(text):
    print(f"#      {text}", flush=True)


def free_port():
    """A port nothing listens on now (the system picks it)"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.2", 0))
        return sock.getsockname()[1]


class Node:
    def __init__(self, name, binary, index, extra):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"fork{index}"
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.extra = list(extra)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0
        self.why = ""

    def write_conf(self):
        # connect= keeps a node from dialling anyone on its own; addnode onetry
        # still dials, and listen=1 takes the other side's dial
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1",
        ] + self.extra
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".new", path)

    def launch(self):
        self.starts += 1
        self.write_conf()
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def debug_log(self):
        """The node's debug.log (divid keeps it in regtest/)"""
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")):
            if os.path.exists(path):
                with open(path, errors="replace") as f:
                    return f.read()
        return ""

    def log_tail(self, n=15):
        lines = self.debug_log().splitlines()
        if not lines:
            try:
                with open(self.err, errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                pass
        return lines[-n:]

    def start(self):
        """True once RPC answers; a node whose ports are taken is started again
        on new ones; otherwise `why` says how it ended"""
        retries = BIND_RETRIES
        self.launch()
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                text = "\n".join(self.log_tail())
                if retries and ("Address already in use" in text or "Unable to bind" in text):
                    retries -= 1
                    self.p2p, self.rpcport = free_port(), free_port()
                    info(f"{self.name}: ports in use, starting again on {self.p2p}/{self.rpcport}")
                    self.launch()
                    continue
                self.why = f"exited with code {code}; last lines of its log:\n" + "\n".join(
                    "#     " + line for line in self.log_tail())
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        self.why = f"no RPC answer within {START_TIMEOUT} s"
        return False

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:150]}")
        return out[1]

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

    def dial(self, other):
        self.rpc("addnode", f"127.0.0.2:{other.p2p}", "onetry")


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


def need(ok, what):
    if not ok:
        print(f"FAIL   run: {what}", flush=True)
        sys.exit(255)


def start(*nodes):
    for n in nodes:
        need(n.start(), f"{n.name} did not start: {n.why}")


def mine(node, n):
    for _ in range(n):
        need(node.call("setgenerate", 1)[0] == "ok", f"{node.name} could not make a block")


def at(nodes, height):
    need(wait_for(lambda: all(n.rpc("getblockcount") == height for n in nodes), SYNC_TIMEOUT),
         f"{', '.join(n.name for n in nodes)} not at height {height}: "
         f"{[n.call('getblockcount') for n in nodes]}")


def outcome(node, method, *params):
    """A call's result, or its error as [code, message]"""
    out = node.call(method, *params)
    return out[1] if out[0] == "ok" else [out[1], out[2]]


def errors(node):
    """getinfo's and getmininginfo's "errors" (the status bar warning)"""
    out = {}
    for method in ("getinfo", "getmininginfo"):
        reply = outcome(node, method)
        out[method] = reply.get("errors") if isinstance(reply, dict) else reply
    return out


def notified(node):
    return os.path.exists(os.path.join(node.dir, "alertnotify.txt"))


M = Node("divid-M", DIVID, 0, [])
N = Node("divid-N", DIVID, 1, [])
C = Node("divid-A", DIVID, 2, [])
I = Node("irondivid-A", IRONDIVID, 3, [])
for n in (C, I):
    n.extra.append(f"alertnotify=echo %s >> {os.path.join(n.dir, 'alertnotify.txt')}")
PAIR = (C, I)


def both(name, fn):
    row(name, fn(C), fn(I))


# 1. One chain to height 60, then the network split by a restart
start(M, N, C, I)
for n in (N, C, I):
    n.dial(M)
need(wait_for(lambda: all(len(n.rpc("getpeerinfo")) > 0 for n in (N, C, I)), 60), "the nodes did not reach M")
mine(M, 60)
at((M, N, C, I), 60)
for n in (M, N, C, I):
    n.stop()
start(M, N, C, I)

# 2. N's branch of 2 to the pair, then N stops; M's branch of 20
mine(N, 2)
own = N.rpc("getbestblockhash")
for n in PAIR:
    n.dial(N)
at(PAIR, 62)
N.stop()
mine(M, 20)
long_61, long_tip = M.rpc("getblockhash", 61), M.rpc("getbestblockhash")
both("own branch: tip", lambda n: n.rpc("getbestblockhash") == own)

# 3. The pair takes M's branch
for n in PAIR:
    n.dial(M)
at(PAIR, 80)
both("long branch: tip", lambda n: n.rpc("getbestblockhash") == long_tip)
both("long branch: errors", errors)

# 4. Its first block invalidated: back on the own branch. The invalid block
# kept is that block, one block past the tip
both("invalidateblock of the long branch's first block", lambda n: outcome(n, "invalidateblock", long_61))
at(PAIR, 62)
both("invalidated: tip", lambda n: n.rpc("getbestblockhash") == own)
both("invalidated: errors", errors)

# 5. Restarted: the invalid block kept is now the long branch's tip, the most
# work of the blocks marked failed; nothing is checked before a block connects
for n in (M, C, I):
    n.stop()
start(C, I)
both("restarted: tip", lambda n: n.rpc("getbestblockhash") == own)
both("restarted: errors", errors)

# 6. N's next block: the long branch's tip is 17 blocks past it
start(N)
mine(N, 1)
for n in PAIR:
    n.dial(N)
at(PAIR, 63)
both("height 63: errors", errors)
both("height 63: getbalance (not okSafeMode)", lambda n: outcome(n, "getbalance"))
both("height 63: getblockcount (okSafeMode)", lambda n: outcome(n, "getblockcount"))
both("height 63: the log line", lambda n: LOG_LINE in n.debug_log())

# 7. Up to 73, seven blocks below the long branch's tip, then 74, six below
mine(N, 10)
at(PAIR, 73)
both("height 73: errors", errors)
lines_73 = {n.name: n.debug_log().count(LOG_LINE) for n in PAIR}
both("height 73: log lines since the restart", lambda n: lines_73[n.name])
mine(N, 1)
at(PAIR, 74)
both("height 74: errors", errors)
both("height 74: getbalance", lambda n: isinstance(outcome(n, "getbalance"), (int, float)))
both("height 74: no new log line", lambda n: n.debug_log().count(LOG_LINE) == lines_73[n.name])

# 8. reconsiderblock: the pair goes back to the long branch
both("reconsiderblock of the long branch's first block", lambda n: outcome(n, "reconsiderblock", long_61))
at(PAIR, 80)
both("reconsidered: tip", lambda n: n.rpc("getbestblockhash") == long_tip)
both("reconsidered: errors", errors)
both("-alertnotify run", notified)

for n in (M, N, C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
