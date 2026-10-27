#!/usr/bin/env python3
"""Low disk and failed writes, Divi Core divid and irondivid side by side:
each runs as a follower of one divid miner, under `ulimit -f` (a write past
that file size fails with EFBIG; SIGXFSZ is ignored so the write returns the
error), and the script records whether the node stops, what it prints, the
RPC replies on the way, and what a restart without the limit finds on disk.

Rows print PASS (same as divid), KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory and
stops the nodes.
"""

import base64
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
START_TIMEOUT = 120
# Bytes a limited node may still add to its largest file before a write fails
MARGIN_KB = int(os.environ.get("DISK_ERRORS_MARGIN_KB", "32"))
# Blocks mined at most while waiting for a limited node to hit its limit
MAX_BLOCKS = int(os.environ.get("DISK_ERRORS_MAX_BLOCKS", "4000"))
T0 = time.time()


def note(text):
    print(f"# [{time.time() - T0:6.1f}s] {text}", flush=True)


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


DIVID_RESTART = ("after the failed write divid exits through std::terminate: its shutdown flush throws "
                 "leveldb_error (leveldbwrapper.cpp:15-23) and nothing catches it, so its block files, block index "
                 "and coins are left at different points. Started again it crashes (SIGSEGV) after \"Checking all "
                 "blk files are present\", or refuses with \"Block database corruption detected!\" "
                 "(BlockIndexLoading.cpp:275), and comes up only with -reindex. irondivid starts on the chain it had")
KNOWN = {
    "blocks until the limit: restart without the limit": (
        DIVID_RESTART, lambda c, i: c.startswith("exit") and i == "up"),
    "start with the limit reached: restart without the limit": (
        DIVID_RESTART, lambda c, i: c.startswith("exit") and i == "up"),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def matches(shape, core, iron):
    try:
        return bool(shape(core, iron))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def row(name, core, iron):
    global fails
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note_ = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif matches(shape, core, iron):
            word, note_ = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note_ = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note_ = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note_}"[:900], flush=True)


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_tb(tb)
    print(f"FAIL   setup: {kind.__name__}: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- nodes -----------------------------------------------------------------------------

def used(path):
    """Bytes up to the last non-zero byte: a preallocated tail of zeros is not in use"""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        pos = size
        while pos > 0:
            step = min(1 << 20, pos)
            f.seek(pos - step)
            stripped = f.read(step).rstrip(b"\0")
            if stripped:
                return pos - step + len(stripped)
            pos -= step
    return 0


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"u{index}:{self.password}".encode()).decode()
        self.user = f"u{index}"
        self.dir = os.path.join(WORK, name)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra):
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
                 f"rpcpassword={self.password}", "rpcallowip=127.0.0.0/8", f"rpcbind={HOST}", f"bind={HOST}",
                 "server=1", "daemon=0", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
                 "printtoconsole=1"] + list(extra)
        os.makedirs(self.dir, exist_ok=True)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(node_ports.follow("\n".join(lines) + "\n"))

    def start(self, extra=(), limit_kb=None, args=()):
        """('up',), ('exit', code) or ('timeout',). The node's output goes
        through a pipe to a file this script writes, so no limit applies to it.
        A node that exits because a port is taken is started again on new ports."""
        retries = node_ports.BIND_RETRIES
        while True:
            outcome = self.start_once(extra, limit_kb, args)
            if outcome[0] == "exit" and retries:
                with open(self.out_path, errors="replace") as f:
                    taken = node_ports.bind_failure(self, f.read())
                if taken and node_ports.move_ports(self, self.dir):
                    retries -= 1
                    continue
            return outcome

    def start_once(self, extra, limit_kb, args):
        self.write_conf(extra)
        self.starts += 1
        self.out_path = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        out = open(self.out_path, "w")
        limit = f"ulimit -f {limit_kb}; " if limit_kb else ""
        # SIGXFSZ ignored: a write past the limit fails with EFBIG instead of killing the node
        script = f"trap '' XFSZ; {limit}d=$1; shift; exec \"$0\" -datadir=\"$d\" \"$@\""
        self.proc = subprocess.Popen(["bash", "-c", script, self.binary, self.dir, *args], cwd=self.dir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        proc = self.proc

        def pump():
            for line in proc.stdout:
                out.write(line.decode(errors="replace"))
                out.flush()
            out.close()

        self.pump = threading.Thread(target=pump, daemon=True)
        self.pump.start()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                self.pump.join(5)
                return ("exit", proc.returncode)
            if self.call("getblockcount", timeout=5)[0] == "ok":
                return ("up",)
            time.sleep(0.25)
        return ("timeout",)

    def call(self, method, *params, timeout=60):
        """('ok', result), ('err', code, message) or ('down',) when nothing answers"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "")
        except (urllib.error.URLError, OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out}")
        return out[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_exit(self, secs):
        try:
            self.proc.wait(secs)
        except subprocess.TimeoutExpired:
            pass
        if self.proc.poll() is not None:
            self.pump.join(5)
        return self.proc.poll()

    def stop(self):
        """The `stop` reply and the exit code (killed after 120 s: 'killed')"""
        if not self.alive():
            return None, (self.proc.returncode if self.proc else None)
        reply = self.call("stop", timeout=30)
        code = self.wait_exit(120)
        if code is None:
            self.proc.kill()
            self.proc.wait()
            self.pump.join(5)
            code = "killed"
        return reply, code

    def output(self):
        with open(self.out_path, errors="replace") as f:
            return f.read()

    def files(self):
        """(bytes in use, path) of every file in the datadir, largest first"""
        out = []
        for root, _, names in os.walk(self.dir):
            for n in names:
                p = os.path.join(root, n)
                if os.path.isfile(p) and not os.path.islink(p):
                    out.append((used(p), os.path.relpath(p, self.dir)))
        return sorted(out, reverse=True)


def mine(node, n):
    for _ in range(n):
        for _ in range(60):
            r = node.call("setgenerate", 1)
            if r[0] == "ok":
                break
            time.sleep(0.3)
        else:
            raise RuntimeError(f"{node.name} setgenerate: {r}")


def wait_height(node, height, secs=120):
    deadline = time.time() + secs
    while time.time() < deadline:
        if node.call("getblockcount", timeout=10) == ("ok", height):
            return True
        time.sleep(0.5)
    return False


# What a node prints when it gives up after a failed write: divid's AbortNode
# "*** <message>" (ValidationState.cpp:17-27), and lines naming the error
ERROR_LINE = re.compile(r"\*\*\*|error|fail|too large|space|abort|fatal|panic", re.I)


ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A line that names the failed write itself
NAMES_WRITE = re.compile(r"write|IO error|I/O error|too large|disk space", re.I)


def error_lines(text, limit=6):
    lines = [ANSI.sub("", ln).strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ERROR_LINE.search(ln)]
    # Lines every start prints, not about this
    noise = ("Failed to open file", "connect() to", "ERROR: Read", "rpcerror", "LoadSporksFromDB")
    return [ln[:200] for ln in lines if not any(n in ln for n in noise)][-limit:]


# --- set-up ----------------------------------------------------------------------------

M = Node("miner", DIVID, 0)
C = Node("divid", DIVID, 1)
I = Node("irondivid", IRONDIVID, 2)
PEER = [f"connect={HOST}:{PORT_BASE}"]
ALONE = [f"connect={HOST}:{PORT_BASE + 49}"]  # nothing listens there

if M.start() != ("up",):
    raise RuntimeError(f"miner did not start: {error_lines(M.output())}")
mine(M, 110)
for n in (C, I):
    out = n.start(PEER)
    if out != ("up",):
        raise RuntimeError(f"{n.name} did not start: {out} {error_lines(n.output())}")
    n.address = n.rpc("getnewaddress")
    M.rpc("sendtoaddress", n.address, 100)
mine(M, 2)
for n in (C, I):
    if not wait_height(n, M.rpc("getblockcount")):
        raise RuntimeError(f"{n.name} did not follow the miner")
    n.balance = n.rpc("getbalance")
    reply, code = n.stop()
    if code != 0:
        raise RuntimeError(f"{n.name} stop: {reply} exit {code}")
    shutil.copytree(n.dir, n.dir + ".template", symlinks=True)
note(f"set-up: miner at {M.rpc('getblockcount')}; balances divid {C.balance}, irondivid {I.balance}")
for n in (C, I):
    note(f"{n.name} files in use: " + ", ".join(f"{s} {p}" for s, p in n.files()[:6]))


def fresh(n):
    """The node's datadir back to the template"""
    shutil.rmtree(n.dir)
    shutil.copytree(n.dir + ".template", n.dir, symlinks=True)


def on_both(fn):
    """fn(node) on divid and irondivid at the same time"""
    out = [None, None]

    def run(k, n):
        try:
            out[k] = fn(n)
        except Exception as e:
            out[k] = {"error": f"{type(e).__name__}: {e}"[:300]}

    threads = [threading.Thread(target=run, args=(k, n)) for k, n in enumerate((C, I))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


def rows(case, core, iron, keys):
    for k in keys:
        row(f"{case}: {k}", core.get(k, "<none>"), iron.get(k, "<none>"))
    for n, facts in (("divid", core), ("irondivid", iron)):
        for k in sorted(set(facts) - set(keys)):
            note(f"{case}: {n} {k}: {facts[k]}")


def restart_unlimited(n, facts, before_height):
    """Start again with no limit and no peer: does it come up (or with
    -reindex), and what is on disk"""
    out = n.start(ALONE)
    facts["restart without the limit"] = out[0] if out[0] != "exit" else f"exit {out[1]}"
    if out != ("up",):
        facts["restart: what it printed"] = error_lines(n.output(), 4)
        n.stop()
        out = n.start(ALONE, args=("-reindex",))
        facts["restart with -reindex"] = out[0] if out[0] != "exit" else f"exit {out[1]}"
        if out == ("up",):
            # -reindex reads the block files back before it answers with the height it rebuilt
            time.sleep(5)
            last = None
            for _ in range(60):
                h = n.call("getblockcount")
                if h == last:
                    break
                last = h
                time.sleep(2)
    if n.alive():
        height = n.call("getblockcount")
        best = n.call("getbestblockhash")
        facts["height after restart"] = height[1] if height[0] == "ok" else height
        facts["height after restart, against the last height the node answered"] = (
            "same" if height == ("ok", before_height) else
            "lower" if height[0] == "ok" and isinstance(before_height, int) and height[1] < before_height else
            "higher" if height[0] == "ok" and isinstance(before_height, int) else "-")
        facts["best block after restart is the miner's block at that height"] = (
            best[0] == "ok" and height[0] == "ok" and M.call("getblockhash", height[1]) == ("ok", best[1]))
        bal = n.call("getbalance")
        facts["balance after restart"] = bal[1] if bal[0] == "ok" else bal
        txs = n.call("listtransactions", "*", 1000)
        facts["wallet transactions after restart"] = len(txs[1]) if txs[0] == "ok" else txs
        if getattr(n, "sent", None):
            facts["the send at the limit is in the wallet after restart"] = n.call("gettransaction", n.sent)[0] == "ok"
        n.stop()


# --- case 1: blocks until the limit, a send at it, then stop --------------------------

def limit_by_blocks(n):
    fresh(n)
    limit = n.files()[0][0] // 1024 + MARGIN_KB
    facts = {}
    note(f"{n.name}: limit {limit} KB")
    out = n.start(PEER, limit_kb=limit)
    if out != ("up",):
        return {"started under the limit": out}
    last, stalled_at, mined = n.call("getblockcount"), None, 0
    while mined < MAX_BLOCKS:
        target = M.rpc("getblockcount")
        time.sleep(2)
        h = n.call("getblockcount", timeout=20)
        if not n.alive():
            break
        if h[0] == "ok" and h[1] < target - 40:
            # Not keeping up with the miner: stopped taking blocks
            time.sleep(10)
            h2 = n.call("getblockcount", timeout=20)
            if h2 == h:
                stalled_at = h
                break
        last = h
        with mine_lock:
            mine(M, 20)
        mined += 20
    at_limit = sorted(p for s, p in n.files() if os.path.getsize(os.path.join(n.dir, p)) >= limit * 1024 - 8192)
    facts["a write failed (a file reached the limit)"] = bool(at_limit)
    note(f"{n.name}: files at the limit: {at_limit}; mined {mined}")
    facts["stopped on its own"] = not n.alive()
    if n.alive():
        n.wait_exit(20)
        facts["stopped on its own"] = not n.alive()
    if not n.alive():
        facts["exit code"] = n.proc.returncode
        facts["exit: signal"] = n.proc.returncode < 0
    facts["last height it answered"] = (last[1] if last[0] == "ok" else last) if stalled_at is None else stalled_at[1]
    facts["what it printed"] = error_lines(n.output())
    facts["printed a line naming the failed write"] = any(
        NAMES_WRITE.search(ln) for ln in error_lines(n.output(), 50))
    # At the limit: an RPC that reads, a wallet send, then stop
    gbc = n.call("getblockcount")
    facts["getblockcount at the limit"] = gbc[0] if gbc[0] != "err" else gbc
    n.sent = None
    send = n.call("sendtoaddress", M.address, 1)
    facts["sendtoaddress at the limit"] = ("txid" if send[0] == "ok" else send[0] if send[0] == "down"
                                           else ["error", send[1], send[2][:100]])
    if send[0] == "ok":
        n.sent = send[1]
    reply, code = n.stop()
    if reply is not None:
        facts["stop at the limit: reply"] = reply[0] if reply[0] != "err" else reply
        facts["stop at the limit: exit code"] = code
    restart_unlimited(n, facts, facts["last height it answered"])
    return facts


mine_lock = threading.Lock()
M.address = M.rpc("getnewaddress")
core, iron = on_both(limit_by_blocks)
rows("blocks until the limit", core, iron, [
    "a write failed (a file reached the limit)", "stopped on its own", "printed a line naming the failed write",
    "getblockcount at the limit", "sendtoaddress at the limit",
    "restart without the limit", "best block after restart is the miner's block at that height",
    "the send at the limit is in the wallet after restart"])


# --- case 2: start with the limit already reached --------------------------------------

def start_at_limit(n):
    fresh(n)
    largest, path = n.files()[0]
    limit = max(1, largest // 1024 // 2)
    note(f"{n.name}: start with limit {limit} KB, under half of {path} ({largest} bytes)")
    facts = {}
    # Alone at first, so the start itself is seen; then the miner's blocks
    out = n.start(ALONE, limit_kb=limit)
    facts["start under the limit"] = out[0] if out[0] != "exit" else "exit"
    if out == ("up",):
        n.call("addnode", f"{HOST}:{node_ports.now(PORT_BASE)}", "onetry")
        with mine_lock:
            mine(M, 5)
        n.wait_exit(60)
        facts["running 60 s after it is sent blocks"] = n.alive()
    facts["what it printed"] = error_lines(n.output())
    facts["printed a line naming the failed write"] = any(
        NAMES_WRITE.search(ln) for ln in error_lines(n.output(), 50))
    height = n.call("getblockcount")
    reply, code = n.stop()
    facts["exit code"] = code
    restart_unlimited(n, facts, height[1] if height[0] == "ok" else None)
    return facts


core, iron = on_both(start_at_limit)
rows("start with the limit reached", core, iron, [
    "start under the limit", "running 60 s after it is sent blocks", "printed a line naming the failed write",
    "restart without the limit",
    "best block after restart is the miner's block at that height", "balance after restart"])

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
for n in (C, I, M):
    if n.alive():
        n.stop()
sys.exit(min(fails, 254))
