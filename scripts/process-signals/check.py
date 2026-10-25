#!/usr/bin/env python3
"""divid and irondivid as processes, compared on regtest: SIGTERM and SIGINT
idle, during start, during -reindex and during -rescan; SIGHUP with debug.log
moved away; SIGPIPE; a second start on a data directory in use; the pid file;
and -daemon. Outcomes are compared, not timings.

Signals go only to the processes this script started, by their own pid. Each
row prints PASS (same as divid), KNOWN (a difference listed in README.md) or
FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory and
stops every node it lists.
"""

import base64
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), os.path.abspath(sys.argv[4])
RPC_TIMEOUT = 60
START_TIMEOUT = 240
NODE_IP = "127.0.0.2"
BLOCKS = 500
INJECT = os.environ.get("PROCESS_SIGNALS_INJECT", "")

KNOWN = {
    "second start: exit code": (
        "divid aborts once InitError has refused the lock (SIGABRT, init.cpp:850-861, :381; also KNOWN in "
        "scripts/start-errors); irondivid exits 1 with the same error", lambda c, i: c == -6 and i == 1),
    "SIGPIPE: still running": (
        "divid keeps SIGPIPE's default action, which ends the process, except on Solaris (init.cpp:1404-1406); "
        "irondivid ignores it, as Rust programs do, so a stray SIGPIPE does not kill the node [by design]",
        lambda c, i: c is False and i is True),
}

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
    def __init__(self, name, binary, index, shutdown_line):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"ps{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=ps{index}", f"rpcpassword={password}",
            "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1",
        ]
        self.shutdown_line = shutdown_line
        os.makedirs(os.path.join(self.dir, "home"))
        self.proc = None
        self.starts = 0

    def netdir(self):
        """Where the node keeps its regtest files: divid in <datadir>/regtest, irondivid in <datadir>"""
        return os.path.join(self.dir, "regtest") if self is C else self.dir

    def log(self):
        return os.path.join(self.netdir(), "debug.log")

    def write_conf(self, extra):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def launch(self, extra=(), args=(), cwd=None):
        self.write_conf(extra)
        self.starts += 1
        self.out = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        with open(self.out, "w") as o, open(self.err, "w") as e:
            proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=cwd or self.dir, env=env,
                                    stdout=o, stderr=e, start_new_session=True)
        remember(proc.pid)
        return proc

    def start(self, extra=(), args=()):
        self.proc = self.launch(extra, args)
        if not wait_for(lambda: self.proc.poll() is not None or self.call("getblockcount")[0] == "ok",
                        START_TIMEOUT, 0.25) or self.proc.poll() is not None:
            with open(self.err, errors="replace") as f:
                err = f.read()[-300:]
            raise RuntimeError(f"{self.name} did not start (exit {self.proc.poll()}): {err!r}")

    def call(self, method, *params, port=None):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{port or self.rpcport}/", data=body,
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

    def signal(self, sig):
        os.kill(self.proc.pid, sig)

    def wait_exit(self, secs=120):
        """The exit code (negative: the signal that ended it), or 'still running'"""
        try:
            code = self.proc.wait(timeout=secs)
        except subprocess.TimeoutExpired:
            return "still running"
        self.proc = None
        return code

    def stop(self):
        if self.proc is None:
            return
        self.call("stop")
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def state(self):
        return [self.rpc("getblockcount"), self.rpc("getbalance")]

    def log_ends_with_shutdown(self):
        try:
            with open(self.log(), errors="replace") as f:
                tail = f.read()[-4000:]
        except OSError:
            return "no debug.log"
        return self.shutdown_line in tail

    def first_error(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""


def pid_file(n, name="divid.pid"):
    return name if os.path.isabs(name) else os.path.join(n.netdir(), name)


def pid_text(n, path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def pid_shape(n, path, pid):
    """The pid file as compared: missing, or whether it names `pid` and ends in a newline"""
    text = pid_text(n, path)
    if text is None:
        return "missing"
    return {"names the process": text.strip() == str(pid), "ends with a newline": text.endswith("\n")}


C = Node("divid", DIVID, 0, "MainShutdown: done")
I = Node("irondivid", IRONDIVID, 1, "IronDivi shutdown complete")
NODES = (C, I)

# --- setup: a wallet and a chain of BLOCKS blocks ------------------------------------------
for n in NODES:
    n.start()
    while n.rpc("getblockcount") < BLOCKS:
        n.rpc("setgenerate", min(50, BLOCKS - n.rpc("getblockcount")))
facts("height after the setup", lambda n: n.rpc("getblockcount"))
before = {n: n.state() for n in NODES}

# --- the pid file while running, and after a clean stop (util.cpp:115-128, init.cpp:396,
# :1470) -----------------------------------------------------------------------------------
facts("pid file while running", lambda n: pid_shape(n, pid_file(n), n.proc.pid))

# --- SIGHUP: the next log write reopens debug.log (init.cpp:513-516, Logging.cpp:173-178) ---
for n in NODES:
    os.rename(n.log(), n.log() + ".moved")
    n.moved_size = os.path.getsize(n.log() + ".moved")
    n.signal(signal.SIGHUP)
time.sleep(1)
for n in NODES:
    n.rpc("setgenerate", 1)
time.sleep(2)
facts("SIGHUP: still running", lambda n: n.proc.poll() is None)
facts("SIGHUP: a new debug.log written", lambda n: os.path.exists(n.log()) and os.path.getsize(n.log()) > 0)
facts("SIGHUP: the moved log stopped growing",
      lambda n: os.path.getsize(n.log() + ".moved") - n.moved_size < 4096)
before = {n: n.state() for n in NODES}

# --- a second start on the data directory in use (init.cpp:850-861) ----------------------
for n in NODES:
    n.second = n.launch(args=[f"-rpcport={n.rpcport + 20}", f"-port={n.p2p + 20}"])
for n in NODES:
    try:
        n.second_code = n.second.wait(timeout=60)
    except subprocess.TimeoutExpired:
        n.second.kill()
        n.second_code = "still running"
facts("second start: exit code", lambda n: n.second_code)
facts("second start: error", lambda n: n.first_error().split(" data directory ")[0])
facts("second start: the first node still answers", lambda n: n.call("getblockcount")[0] == "ok")
facts("second start: the first node's pid file", lambda n: pid_shape(n, pid_file(n), n.proc.pid))

# --- SIGTERM and SIGINT when idle ---------------------------------------------------------------
for name, sig in (("SIGTERM", signal.SIGTERM), ("SIGINT", signal.SIGINT)):
    for n in NODES:
        if n.proc is None:
            n.start()
        n.signal(sig)
    facts(f"{name} idle: exit code", lambda n: n.wait_exit())
    facts(f"{name} idle: log ends with the shutdown line", lambda n: n.log_ends_with_shutdown())
    facts(f"{name} idle: pid file after the stop", lambda n: pid_shape(n, pid_file(n), 0))
    for n in NODES:
        n.start()
    facts(f"{name} idle: height and balance at the next start", lambda n: n.state() == before[n])

# --- SIGTERM and SIGINT during start, before RPC answers: init returns false
# (init.cpp:1536-1539, :1661), divid.cpp:180 --------------------------------------------------
for name, sig in (("SIGTERM", signal.SIGTERM), ("SIGINT", signal.SIGINT)):
    for n in NODES:
        n.stop()
    for n in NODES:
        n.proc = n.launch()
        path = pid_file(n)
        wait_for(lambda: pid_text(n, path) is not None, 60, 0.02)
        n.early = n.call("getblockcount")[0] != "ok"
        n.signal(sig)
    facts(f"{name} during start: signalled before RPC answered", lambda n: n.early)
    facts(f"{name} during start: exit code", lambda n: n.wait_exit())
    facts(f"{name} during start: pid file after the stop", lambda n: pid_shape(n, pid_file(n), 0))
    for n in NODES:
        n.start()
    facts(f"{name} during start: height and balance at the next start", lambda n: n.state() == before[n])

# --- SIGTERM during -reindex: the import thread runs after init (init.cpp:686-728) ----------
for name, sig in (("SIGTERM", signal.SIGTERM), ("SIGINT", signal.SIGINT)):
    for n in NODES:
        n.stop()
    for n in NODES:
        n.proc = n.launch(args=["-reindex"])
        wait_for(lambda: n.call("getblockcount")[0] == "ok", START_TIMEOUT, 0.02)
        n.signal(sig)
    facts(f"{name} during -reindex: exit code", lambda n: n.wait_exit())
    for n in NODES:
        n.start()
        wait_for(lambda: n.rpc("getblockcount") >= before[n][0], 180, 0.5)
    facts(f"{name} during -reindex: height and balance at the next start", lambda n: n.state() == before[n])

# --- SIGTERM during -rescan: the rescan runs in init, step 8 --------------------------------------
for n in NODES:
    n.stop()
for n in NODES:
    n.proc = n.launch(args=["-rescan"])
    path = pid_file(n)
    wait_for(lambda: pid_text(n, path) is not None, 60, 0.02)
    n.signal(signal.SIGTERM)
facts("SIGTERM during -rescan: exit code", lambda n: n.wait_exit())
for n in NODES:
    n.start()
facts("SIGTERM during -rescan: height and balance at the next start", lambda n: n.state() == before[n])

# --- the pid file after a kill, and at the next start --------------------------------------------
for n in NODES:
    n.killed_pid = n.proc.pid
    n.proc.kill()
    n.proc.wait()
    n.proc = None
facts("kill -9: pid file left", lambda n: pid_shape(n, pid_file(n), n.killed_pid))
for n in NODES:
    n.start()
facts("kill -9: the next start names its own pid", lambda n: pid_shape(n, pid_file(n), n.proc.pid))

# --- -pid=<relative> and -pid=<absolute> -------------------------------------------------------
for label, value in (("relative", "other.pid"), ("absolute", None)):
    for n in NODES:
        n.stop()
    for n in NODES:
        path = value or os.path.join(WORK, f"{n.name}-abs.pid")
        n.start(args=[f"-pid={path}"])
        n.pid_path = pid_file(n, path)
    facts(f"-pid={label}: the file while running", lambda n: pid_shape(n, n.pid_path, n.proc.pid))
    for n in NODES:
        n.stop()
    facts(f"-pid={label}: the file after a clean stop", lambda n: pid_shape(n, n.pid_path, 0))

# --- -daemon (divid.cpp:122-140) ------------------------------------------------------------------
for n in NODES:
    # From the work directory, so the child's working directory tells
    parent = n.launch(args=["-daemon"], cwd=WORK)
    n.parent_code = parent.wait(timeout=60)
    with open(n.out, errors="replace") as f:
        n.parent_out = f.read().splitlines()[:1]
    n.daemon_up = wait_for(lambda: n.call("getblockcount")[0] == "ok", START_TIMEOUT, 0.25)
    child = pid_text(n, pid_file(n))
    if child and child.strip().isdigit():
        remember(int(child.strip()))
        n.child_pid = int(child.strip())
facts("-daemon: the parent's exit code", lambda n: n.parent_code)
facts("-daemon: the parent's first line on stdout", lambda n: n.parent_out)
facts("-daemon: the child answers RPC", lambda n: n.daemon_up)
facts("-daemon: the child's working directory is the parent's",
      lambda n: os.readlink(f"/proc/{n.child_pid}/cwd") == WORK)
facts("-daemon: the child's stdout is the parent's", lambda n: os.readlink(f"/proc/{n.child_pid}/fd/1") == n.out)
for n in NODES:
    n.call("stop")
facts("-daemon: the child stops on stop",
      lambda n: wait_for(lambda: not os.path.exists(f"/proc/{n.child_pid}"), 120, 0.5))

# --- stderr of a start and a clean stop: divid writes there only its warnings and
# errors (InitWarning, InitError, noui.cpp:38-40), here the unencrypted wallet
# warning it gives at every start (init.cpp:1227-1232) ----------------------------------------
for n in NODES:
    n.start()
    n.stop()
facts("stderr of a start and a clean stop", lambda n: open(n.err, errors="replace").read().splitlines())

# --- SIGPIPE: divid keeps the default action except on Solaris (init.cpp:1404-1406) ---------
for n in NODES:
    n.start()
for n in NODES:
    n.signal(signal.SIGPIPE)
time.sleep(2)
facts("SIGPIPE: still running", lambda n: n.proc.poll() is None)
for n in NODES:
    if n.proc is not None and n.proc.poll() is None:
        n.stop()

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
