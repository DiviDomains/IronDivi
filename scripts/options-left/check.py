#!/usr/bin/env python3
"""The divid 3.0.0 options no other script compares, Divi Core divid and
irondivid side by side on regtest.

Each option is given as =0, =1, with no value, with a typical value and as
=abc. Each row starts both nodes with it, on a copy of a data directory that
holds a wallet and a 5-block chain, and compares what shows from outside:
whether the node starts (or its exit and first error line), the debug.log
lines that name the option, and the one effect the option has that a short
regtest run can show. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf; nothing secret goes on a command line.
"""

import base64
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
DEAD = PORT_BASE + 49  # each node's only -connect peer; nothing listens there
WORKERS = 6  # pairs of nodes run at once, on ports PORT_BASE .. PORT_BASE+4*WORKERS-1
RPC_TIMEOUT = 60
START_TIMEOUT = 240  # hp1 runs many builders at once
HEIGHT = 5
# The typical -mocktime: two days ahead, so a block made now takes it as its time
MOCK = int(time.time()) + 2 * 86400

# --- rows ------------------------------------------------------------------------------

HELP = ("divid's help prints every option, the debug ones with -help-debug (LicenseAndInfo.cpp:160-202); "
        "irondivid's -help is its own short summary of the common options, with no debug section (USAGE, "
        "bin/irondivid/src/main.rs; also KNOWN in scripts/check-options)")
ABORT = ("same error line; divid then aborts (SIGABRT) in the shutdown after this early InitError, before the "
         "chain state exists (init.cpp:381, ChainstateManager.cpp:102); irondivid exits 1 (as for -checklevel, "
         "KNOWN in scripts/chain-load-options, scripts/start-checks and scripts/restart-options)")
AIDS = ("a divid test aid for a part irondivid has but does not let an option change (bin/irondivid/src/main.rs "
        "UNSUPPORTED_OPTIONS): divid takes it without a word, irondivid names it as not supported "
        "(docs/divid-differences.md S2)")
PRUNED = ("divid's -prunewalletconfs rebuilds the wallet's transactions in memory without the fully spent ones of at "
         "least that many confirmations and logs the counts (wallet.cpp:1162-1239); irondivid's wallet keeps them "
         "all, and it names the option as not supported (UNSUPPORTED_OPTIONS)")
KNOWN = {
    "-help -help-debug: more options than -help": (HELP, lambda c, i: c == ("ok", True) and i == ("ok", False)),
}


def unsupported(option):
    return lambda c, i: c == ("ok", []) and i == ("ok", [f"WARNING: Option -{option} is not supported by irondivid; "
                                                         "ignored"])


def aborts(c, i):
    return (c[0] == i[0] == "ok" and c[1].startswith("exit -6 ") and i[1].startswith("exit 1 ")
            and c[1][len("exit -6 "):] == i[1][len("exit 1 "):])


def pruned(c, i):
    return c[0] == i[0] == "ok" and len(c[1]) == 1 and c[1][0][0] == c[1][0][1] and i[1] == []


FORM_LABELS = {"0": "=0", "1": "=1", None: "", "abc": "=abc"}


def labels(option, typical, forms):
    for form in forms:
        if form == "typical":
            if typical is not None:
                yield f"-{option}={typical}"
        else:
            yield f"-{option}{FORM_LABELS[form]}"

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:900], flush=True)


def show(v):
    if isinstance(v, tuple) and v and v[0] == "err":
        return f"error {v[1]} \"{str(v[2])[:120]}\""
    return json.dumps(v, default=str)[:300]


def compare(name, core, iron):
    row(name, show(core), show(iron), core == iron, (core, iron))


def setup_failed(kind, value, tb):
    import traceback
    where = traceback.extract_tb(tb)[-1]
    print(f"FAIL   setup: {value} (check.py:{where.lineno})"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed
PIDS_LOCK = threading.Lock()


def note_pid(pid):
    with PIDS_LOCK, open(os.path.join(WORK, "pids"), "a") as f:
        f.write(f"{pid}\n")


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, worker, core):
        self.name, self.binary, self.core = name, binary, core
        self.p2p = PORT_BASE + 4 * worker + (0 if core else 2)
        self.rpcport = self.p2p + 1
        self.user = f"left{worker}{name[0]}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.daemon_pid = None
        self.runs = 0
        self.dir = None
        self.tag = f"{name}.w{worker}"

    def fresh(self, tag, template=None):
        """A data directory for a row: a copy of the template, or empty"""
        self.dir = os.path.join(WORK, f"{self.name}.{tag}")
        if template:
            shutil.copytree(template, self.dir)
        else:
            os.makedirs(self.dir)

    def write_conf(self):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=1",
            "printtoconsole=0", "server=1", "listenonion=0", "discover=0", "staking=0",
            f"connect={HOST}:{DEAD}",
        ]
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def net_dir(self):
        return os.path.join(self.dir, "regtest") if self.core else self.dir

    def launch(self, *args):
        self.runs += 1
        base = os.path.join(WORK, f"{self.tag}.run{self.runs}")
        self.err = base + ".err"
        self.out = base + ".out"
        with open(self.out, "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=WORK,
                                         stdout=o, stderr=e, stdin=subprocess.DEVNULL, start_new_session=True,
                                         work=WORK)
        note_pid(self.proc.pid)

    def answers(self):
        try:
            return self.call("getblockcount")[0] == "ok"
        except Exception:
            return False

    def start(self, *args):
        """('up',) once RPC answers; ('detached',) when the started process
        exits 0 and a node it left behind answers (-daemon); else ('exit', code,
        first error line)"""
        self.launch(*args)
        self.daemon_pid = None
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                if code == 0:
                    return self.detached(deadline)
                return ("exit", code, self.error_line())
            if self.answers():
                return ("up",)
            time.sleep(0.25)
        return ("exit", f"none within {START_TIMEOUT} s", self.error_line())

    def detached(self, deadline):
        """After the started process exited 0: the node it left, by its pid file and RPC"""
        began = time.time()
        while time.time() < deadline:
            pid = self.pid_file()
            if pid:
                note_pid(pid)
                self.daemon_pid = pid
            if self.answers():
                return ("detached",)
            if not pid and time.time() > began + 20:
                break
            time.sleep(0.25)
        return ("exit", 0, self.error_line())

    def pid_file(self):
        try:
            with open(os.path.join(self.net_dir(), "divid.pid")) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def error_line(self):
        with open(self.err, errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        line = next((ln for ln in lines if ln.startswith("Error")), lines[0] if lines else "")
        for path in (os.path.join(self.dir, "regtest"), self.dir):
            line = line.replace(path, "<datadir>")
        return line

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
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
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def stop(self):
        if self.proc is None and self.daemon_pid is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        if self.proc is not None:
            try:
                self.proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None
        if self.daemon_pid is not None:
            for _ in range(360):
                try:
                    os.kill(self.daemon_pid, 0)
                except OSError:
                    break
                time.sleep(0.25)
            else:
                try:
                    os.kill(self.daemon_pid, 9)
                except OSError:
                    pass
            self.daemon_pid = None

    def debug_log(self):
        p = os.path.join(self.net_dir(), "debug.log")
        if not os.path.exists(p):
            return ""
        with open(p, errors="replace") as f:
            return f.read()

    def stdout(self):
        with open(self.out, errors="replace") as f:
            return f.read()


def pair(worker):
    return Node("divid", DIVID, worker, True), Node("irondivid", IRONDIVID, worker, False)


def both(c, i, fn):
    """fn(node) for both nodes at once"""
    out = {}
    ts = [threading.Thread(target=lambda n=n: out.__setitem__(n.name, fn(n))) for n in (c, i)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out["divid"], out["irondivid"]


# --- what a row shows ------------------------------------------------------------------------

def naming(log, option):
    """The debug.log lines that name -<option>, as their message only"""
    out = []
    for line in log.splitlines():
        if re.search(rf"-{re.escape(option)}(?![A-Za-z0-9_-])", line):
            # irondivid's lines start with a time and a level, divid's with a date and a time
            line = re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", "", line)
            out.append(re.sub(r"^\S+\s+(?:(?:INFO|WARN|ERROR|DEBUG)\s+\S+:\s+)", "", line).strip())
    return out


def outcome(o):
    if o[0] in ("up", "detached"):
        return o[0]
    return f"exit {o[1]} \"{o[2][:150]}\""


def mined(n):
    """A block made now: its version, and its time as -mocktime, now, or neither"""
    made = n.call("setgenerate", 1)
    if made[0] != "ok":
        return made
    block = n.rpc("getblock", n.rpc("getbestblockhash"))
    t = block["time"]
    when = "the -mocktime" if t == MOCK else "now" if abs(t - time.time()) < 900 else "other"
    return ("ok", {"version": block["version"], "time": when})


def safemode(n):
    """getinfo's errors, and getbalance (refused in divid's safe mode, rpcserver.cpp:1050-1054)"""
    info = n.call("getinfo")
    balance = n.call("getbalance")
    return ("ok", {"getinfo errors": info[1].get("errors") if info[0] == "ok" else info,
                   "getbalance": "ok" if balance[0] == "ok" else balance})


SCAN = re.compile(r"\b(Rescanning|Scanning)\.\.\. from height (\d+) to (\d+)")
PRUNE = re.compile(r"Pruned wallet transactions loaded to memory: Original (\d+) vs\. Current (\d+)")


def scan_lines(n, log):
    return [m.groups() for m in SCAN.finditer(log)]


def prune_lines(n, log):
    return [m.groups() for m in PRUNE.finditer(log)]


def console(n, log):
    """Whether the log went to stdout, and to debug.log"""
    return {"stdout": bool(n.stdout().strip()), "debug.log": bool(log.strip())}


# --- the options: (name, typical value or None, forms, effect while up, effect from the log) --------
# Forms: =0, =1, no value, the typical value, =abc. An option divid only reads
# as a boolean has no typical value apart from 1.
ALL = ("0", "1", None, "typical", "abc")
VAULT = "76a914" + "11" * 20 + "88ac"
OPTIONS = [
    # divid reads or lists these, and irondivid's lists name none of them
    ("accountlabels", None, ALL, None, None),
    ("activeversion", "70920", ALL, None, None),
    ("benchmark", None, ALL, None, None),
    ("blockversion", "7", ALL, mined, None),
    ("dblogsize", "100", ALL, None, None),
    ("debugnet", None, ALL, None, None),
    ("disablesafemode", None, ALL, safemode, None),
    ("force_rescan", None, ALL, None, scan_lines),
    ("help-debug", None, ALL, None, None),
    ("manual_fork", "1700000000", ALL, None, None),
    ("mocktime", str(MOCK), ALL, mined, None),
    ("nodebug", None, ALL, None, None),
    ("override_mnpayee", None, ALL, None, None),
    ("printcoinstake", None, ALL, None, None),
    ("printstakemodifier", None, ALL, None, None),
    ("privdb", None, ALL, None, None),
    ("prunewalletconfs", "30", ALL, None, prune_lines),
    ("recoverblockdb", None, ALL, None, None),
    ("safe_shutdown", None, ALL, None, None),
    ("socks", "5", ALL, None, None),
    ("stakeupdatetime", "60", ALL, None, None),
    ("testsafemode", None, ALL, safemode, None),
    ("tor", f"{HOST}:{DEAD}", ALL, None, None),
    ("whitelisted_vault", VAULT, ALL, None, None),
    ("windowtitle", "divi", ALL, None, None),
    # in irondivid's lists, compared by no script
    ("blockmaxsize", "250000", ALL, None, None),
    ("blockminsize", "1000", ALL, None, None),
    ("dns", None, ALL, None, None),
    # =1 and no value would map ports with UPnP: only the forms that turn it off
    ("upnp", None, ("0", "abc"), None, None),
    ("printtoconsole", None, ALL, None, console),
    ("daemon", None, ALL, None, None),
]


for _option, _typical, _forms, _during, _after in OPTIONS:
    for _label in labels(_option, _typical, _forms):
        if _option in ("accountlabels", "activeversion", "manual_fork", "override_mnpayee", "prunewalletconfs",
                       "stakeupdatetime", "whitelisted_vault"):
            KNOWN[f"{_label}: log lines naming -{_option}"] = (AIDS, unsupported(_option))
        if _option == "prunewalletconfs":
            KNOWN[f"{_label}: log lines"] = (PRUNED, pruned)
        if _option == "socks" or (_option == "tor" and _label not in ("-tor=0", "-tor=abc")):
            KNOWN[f"{_label}: start"] = (ABORT, aborts)


def arg(option, form, typical):
    if form is None:
        return f"-{option}"
    return f"-{option}={typical if form == 'typical' else form}"


# --- the cases, run WORKERS at a time ---------------------------------------------------------

TEMPLATE = {}
FREE = queue.Queue()


def run_case(tag, args, during=None, after=None):
    """Both nodes started with `args` on copies of the template: the outcome,
    the debug.log, and during(node) while it is up, after(node, log) once stopped"""
    c, i = FREE.get()
    try:
        for n in (c, i):
            n.fresh(tag, TEMPLATE[n.name])
            n.write_conf()

        def go(n):
            o = n.start(*args)
            extra = during(n) if during and o[0] in ("up", "detached") else None
            return o, extra

        res = both(c, i, go)
        both(c, i, lambda n: n.stop())
        out = []
        for n, (o, extra) in zip((c, i), res):
            log = n.debug_log()
            out.append({"start": outcome(o), "log": log, "during": extra,
                        "after": after(n, log) if after else None})
        for n in (c, i):
            shutil.rmtree(n.dir, ignore_errors=True)
        return out
    finally:
        FREE.put((c, i))


# --- the template: a wallet and a 5-block chain on each ---------------------------------------

c0, i0 = pair(0)
for n in (c0, i0):
    n.fresh("template")
    n.write_conf()
for n, o in zip((c0, i0), both(c0, i0, lambda n: n.start())):
    if o[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {o}")
print(f"# divid {c0.rpc('getinfo').get('version')}, irondivid {i0.rpc('getnetworkinfo').get('version')}", flush=True)
for n in (c0, i0):
    n.rpc("setgenerate", HEIGHT)
compare("the template's height", ("ok", c0.rpc("getblockcount")), ("ok", i0.rpc("getblockcount")))
both(c0, i0, lambda n: n.stop())
for n in (c0, i0):
    p = os.path.join(n.net_dir(), "debug.log")
    if os.path.exists(p):
        os.remove(p)
    TEMPLATE[n.name] = n.dir
for w in range(WORKERS):
    FREE.put(pair(w))

jobs = []  # (label, option, future)
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    jobs.append(("no option", None, None, pool.submit(run_case, "plain", [], safemode, scan_lines)))
    for option, typical, forms, during, after in OPTIONS:
        for k, form in enumerate(forms):
            if form == "typical" and typical is None:
                continue
            a = arg(option, form, typical)
            jobs.append((a, option, during, pool.submit(run_case, f"{option}.{k}", [a], during, after)))
    for label, args in (("-testsafemode -disablesafemode", ["-testsafemode", "-disablesafemode"]),
                        ("-testsafemode -disablesafemode=0", ["-testsafemode", "-disablesafemode=0"])):
        jobs.append((label, "testsafemode", safemode, pool.submit(run_case, label.replace(" ", ""), args, safemode)))

    for label, option, during, fut in jobs:
        c, i = fut.result()
        compare(f"{label}: start", ("ok", c["start"]), ("ok", i["start"]))
        if option:
            compare(f"{label}: log lines naming -{option}", ("ok", naming(c["log"], option)),
                    ("ok", naming(i["log"], option)))
        if during:
            compare(f"{label}: {during.__name__}", c["during"], i["during"])
        if c["after"] is not None or i["after"] is not None:
            compare(f"{label}: log {'lines' if isinstance(c['after'], list) else 'facts'}",
                    ("ok", c["after"]), ("ok", i["after"]))

# --- -help-debug adds divid's debug options to -help -----------------------------------------------


def help_lines(binary, *args):
    home = os.path.join(WORK, "home")
    os.makedirs(home, exist_ok=True)
    out = subprocess.run([binary, *args], capture_output=True, text=True, timeout=60,
                         env=dict(os.environ, HOME=home), cwd=WORK)
    return out.returncode, [ln for ln in out.stdout.splitlines() if ln.lstrip().startswith("-")]


plain_c, debug_c = help_lines(DIVID, "-help"), help_lines(DIVID, "-help", "-help-debug")
plain_i, debug_i = help_lines(IRONDIVID, "-help"), help_lines(IRONDIVID, "-help", "-help-debug")
compare("-help -help-debug: exit", ("ok", debug_c[0]), ("ok", debug_i[0]))
compare("-help -help-debug: more options than -help", ("ok", len(debug_c[1]) > len(plain_c[1])),
        ("ok", len(debug_i[1]) > len(plain_i[1])))

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
