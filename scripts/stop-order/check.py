#!/usr/bin/env python3
"""The order of a stop, divid against irondivid, on regtest: each is stopped
by RPC `stop` and by SIGTERM, and the run records, from the stop's start to
the process's exit,

- the files the stop writes, in the order of their mtimes, and the files it
  removes (the pid file), with when it saw them go;
- the log lines the stop writes, first to last;
- what an RPC call gets while the stop runs.

Divi Core's order is its Shutdown(): PrepareShutdown then MainShutdown
(init.cpp:356-418). Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs. Started by run.sh,
which owns the work directory and stops every node it lists.
"""

import base64
import ctypes
import ctypes.util
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import struct
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), os.path.abspath(sys.argv[4])
RPC_TIMEOUT = 60
START_TIMEOUT = 240
NODE_IP = "127.0.0.2"
INJECT = os.environ.get("STOP_ORDER_INJECT", "")

KNOWN = {}

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
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note}"[:900], flush=True)


def setup_failed(kind, value, tb):
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   setup (line {where}): {value}"[:400], flush=True)
    print("FAILS 1", flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def wait_for(fn, secs, step=0.1):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


def remember(pid):
    with open(os.path.join(WORK, "pids"), "a") as f:
        f.write(f"{pid}\n")


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"so{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=so{index}", f"rpcpassword={password}",
            "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1",
        ]
        os.makedirs(os.path.join(self.dir, "home"))
        self.proc = None
        self.starts = 0

    def netdir(self):
        """divid keeps its regtest files in <datadir>/regtest, irondivid in <datadir>"""
        return os.path.join(self.dir, "regtest") if self.binary == DIVID else self.dir

    def log(self):
        return os.path.join(self.netdir(), "debug.log")

    def start(self):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))
        self.starts += 1
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, \
                open(os.path.join(WORK, f"{self.name}.{self.starts}.err"), "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        remember(self.proc.pid)
        if not wait_for(lambda: self.proc.poll() is not None or self.call("getblockcount")[0] == "ok",
                        START_TIMEOUT, 0.25) or self.proc.poll() is not None:
            raise RuntimeError(f"{self.name} did not start (exit {self.proc.poll()})")

    def call(self, method, *params, timeout=RPC_TIMEOUT):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
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


C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
NODES = (C, I)


# --- one stop, observed ----------------------------------------------------------------------

# inotify, through libc: the kernel's order of the stop's file events, which
# mtimes (stamped on a clock of a few ms) cannot give
LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_TO, IN_CREATE, IN_DELETE = 0x2, 0x8, 0x80, 0x100, 0x200
IN_NONBLOCK = 0o4000


class Events:
    """The file events under a node's network directory, in order: (what, path)"""

    def __init__(self, root):
        self.root, self.fd, self.dirs, self.seen = root, LIBC.inotify_init1(IN_NONBLOCK), {}, []
        if self.fd < 0:
            raise RuntimeError("inotify_init1 failed")
        for d, _, _ in os.walk(root):
            self.watch(d)

    def watch(self, d):
        # IN_MODIFY too: a database appends to files it keeps open, which
        # gives no close event
        mask = IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE
        wd = LIBC.inotify_add_watch(self.fd, d.encode(), mask)
        if wd >= 0:
            self.dirs[wd] = d

    def drain(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            pos = 0
            while pos < len(data):
                wd, mask, _cookie, length = struct.unpack_from("iIII", data, pos)
                name = data[pos + 16:pos + 16 + length].split(b"\0", 1)[0].decode(errors="replace")
                pos += 16 + length
                path = os.path.relpath(os.path.join(self.dirs.get(wd, self.root), name), self.root)
                if mask & IN_CREATE and os.path.isdir(os.path.join(self.root, path)):
                    self.watch(os.path.join(self.root, path))
                what = ("written" if mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_TO)
                        else "removed" if mask & IN_DELETE else None)
                if what:
                    self.seen.append((what, path))

    def close(self):
        self.drain()
        os.close(self.fd)

def name_of(path):
    """A path as the order shows it: a file of a directory of many (a database)
    by its directory; a file written as <name>.new and renamed, by <name>"""
    parts = path.split(os.sep)
    name = parts[0] + "/" if len(parts) > 1 else parts[0]
    return name[:-4] if name.endswith(".new") else name


def observe(n, how):
    """Stop `n` by `how` ("rpc" or "sigterm"); what the stop did"""
    with open(n.log(), "rb") as f:
        f.seek(0, 2)
        log_at = f.tell()
    events = Events(n.netdir())
    answers = []
    done = threading.Event()

    def ask():
        # What an RPC call gets while the stop runs, each kind once, in order
        while not done.is_set():
            out = n.call("getblockcount", timeout=2)
            kind = "ok" if out[0] == "ok" else (f"error {out[1]}" if out[1] is not None else "no reply")
            if not answers or answers[-1] != kind:
                answers.append(kind)
            time.sleep(0.01)

    def follow():
        while not done.is_set():
            events.drain()
            time.sleep(0.002)

    reply = None
    if how == "rpc":
        reply = n.call("stop")
    else:
        os.kill(n.proc.pid, signal.SIGTERM)
    asker, follower = threading.Thread(target=ask), threading.Thread(target=follow)
    asker.start()
    follower.start()
    try:
        code = n.proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        code = "still running"
    done.set()
    asker.join()
    follower.join()
    events.close()
    n.proc = None
    # Each file, or database directory, at its first write; the pid file at its going
    order = []
    for what, path in events.seen:
        key = name_of(path)
        if key == "debug.log" or key.startswith("."):
            continue
        label = "(pid file removed)" if (what == "removed" and key == "divid.pid") else key
        if what == "removed" and label != "(pid file removed)":
            continue
        if label not in order:
            order.append(label)
    with open(n.log(), "rb") as f:
        f.seek(log_at)
        lines = f.read().decode(errors="replace").splitlines()
    return {"reply": reply, "code": code, "answers": answers, "order": order,
            "log": [strip_time(line) for line in lines if line.strip()]}


# What each file is, to compare the stop's order across the two: divid keeps
# its masternode list in mncache.dat and its wallet in wallet.dat (with its
# Berkeley DB log in database/); irondivid in mncache.dat (masternodes.list
# before B13's mncache work) and wallet/
ROLES = {
    "peers.dat": "peers.dat", "mncache.dat": "masternode list", "masternodes.list": "masternode list",
    "mnpayments.dat": "mnpayments.dat", "netfulfilled.dat": "netfulfilled.dat",
    "wallet.dat": "wallet", "database/": "wallet", "wallet/": "wallet",
    "chainstate/": "chain state", "(pid file removed)": "(pid file removed)",
}

# divid's lines that frame its stop and its StopNode (init.cpp:359, net.cpp:1476, init.cpp:417)
STOP_LINES = ["PrepareShutdown: In progress...", "StopNode()", "MainShutdown: done"]


def roles(order):
    out = []
    for name in order:
        role = ROLES.get(name)
        if role and role not in out:
            out.append(role)
    return out


def stop_lines(log):
    return [line for line in log if line.strip() in STOP_LINES]


def strip_time(line):
    """A log line without its time stamp"""
    return re.sub(r"^\S+\s+\S+\s+(?:\[[^\]]*\]\s+)?|^\d{4}-\d\d-\d\dT\S+\s+(?:\w+\s+)?", "", line)


def show(n, how, seen):
    print(f"# {n.name} {how}: files written, in order: {', '.join(seen['order']) or '-'}", flush=True)
    print(f"# {n.name} {how}: RPC while stopping: {' -> '.join(seen['answers'])}", flush=True)
    print(f"# {n.name} {how}: log ({len(seen['log'])} lines):", flush=True)
    for line in seen["log"][:60]:
        print(f"#     {line[:200]}", flush=True)


# --- the runs ------------------------------------------------------------------------------

for n in NODES:
    n.start()
    for _ in range(5):
        n.call("setgenerate", 1)
    n.call("getnewaddress")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

for how in ("rpc", "sigterm"):
    seen = {}
    for n in NODES:
        if n.proc is None:
            n.start()
            n.call("setgenerate", 1)
        # Something new for the stop to write
        n.call("getnewaddress")
        time.sleep(1)
        seen[n] = observe(n, how)
        show(n, how, seen[n])
    c, i = seen[C], seen[I]
    if how == "rpc":
        row("rpc stop: the reply", c["reply"], i["reply"])
    row(f"{how}: exit code", c["code"], i["code"])
    row(f"{how}: RPC while the stop runs", c["answers"], i["answers"])
    row(f"{how}: the pid file removed", "(pid file removed)" in c["order"], "(pid file removed)" in i["order"])
    both = set(roles(c["order"])) & set(roles(i["order"]))
    row(f"{how}: the order of what both write", [r for r in roles(c["order"]) if r in both],
        [r for r in roles(i["order"]) if r in both])
    row(f"{how}: divid's stop lines in the log, in order", stop_lines(c["log"]), stop_lines(i["log"]))
    row(f"{how}: the masternode list written at the stop", "masternode list" in roles(c["order"]),
        "masternode list" in roles(i["order"]))

for n in NODES:
    if n.proc is not None:
        n.call("stop")
        n.proc.wait(timeout=120)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
