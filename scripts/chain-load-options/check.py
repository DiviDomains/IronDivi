#!/usr/bin/env python3
"""The start options that load blocks or check the chain, Divi Core divid and
irondivid compared row by row on regtest.

divid mines a short chain and irondivid follows it; then each exports it, divid
as its own blk00000.dat, irondivid with --export-chain (a block file in divid's
format), and the two files must hold the same blocks. Each export is loaded with
each option into a fresh pair of data directories: -loadblock (one, several, a
missing file), bootstrap.dat in the data directory, -reindex with -loadblock,
-stopafterblockimport, and options divid does not have (-prune, -blocksonly,
-stopatheight, -assumevalid). On a node that holds the chain: -checkblocks,
-checklevel 0-4, -checkpoints, -dbcache and -par. Each row compares the start
(or its exit and first error line), the tip, getblockchaininfo, verifychain,
the files the import leaves and the start-up log lines. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf; nothing secret goes on a command line.
"""

import base64
import hashlib
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
DEAD = PORT_BASE + 49  # each node's only -connect peer; nothing listens there
RPC_TIMEOUT = 60
START_TIMEOUT = 240  # hp1 runs many builders at once
REGTEST_MAGIC = bytes.fromhex("a1cf7eac")
HEIGHT = 30

# --- rows ------------------------------------------------------------------------------


def pair(core, iron):
    return lambda c, i: c == core and i == iron


# The options divid does not have: it keeps them and says nothing (Settings.cpp:130-150);
# irondivid starts too and names them (docs/divid-differences.md S1)
UNKNOWN = ("not a divid 3.0.0 option: divid keeps it and says nothing (Settings.cpp:130-150); irondivid starts "
           "as well and logs \"Unknown option -<name>; ignored\" (docs/divid-differences.md S1) [by design]")


def unknown_line(option):
    return (UNKNOWN, pair(("ok", []), ("ok", [f"WARNING: Unknown option -{option}; ignored"])))


CHECKLEVEL = ("divid aborts (SIGABRT, exit -6) in the shutdown after this early InitError, before the chain state "
              "exists (init.cpp:381, ChainstateManager.cpp:102); irondivid prints the same error and exits 1 (also "
              "KNOWN in scripts/start-checks and scripts/restart-options)")


def checklevel_shape(c, i):
    m = re.match(r'exit -6 (".*")$', c[1]) if c[0] == "ok" else None
    return m is not None and i == ("ok", f"exit 1 {m.group(1)}")


PAR = ("divid starts that many script-check threads (TransactionInputChecker.cpp:16-26, init.cpp:801, capped at "
       "16, defaultValues.h:76) and logs nothing; irondivid checks scripts on the thread that checks the block and "
       "has no such threads, so it names -par as not supported (docs/divid-differences.md S2)")
REINDEX_FILE = ("divid reads its blocks again from each blocks/blk?????.dat and names each file (init.cpp:675); "
                "irondivid keeps its blocks in its chain database, with no blk files (scripts/restart-state: file "
                "blocks/), and builds its indexes again from it, so it names no file")


def without_file_lines(c, i):
    if c[0] != "ok" or i[0] != "ok":
        return False
    rest = [x for x in c[1] if x[0] != "reindexing a block file"]
    return rest != c[1] and rest == i[1]


KNOWN = {f"-checklevel={v}: start": (CHECKLEVEL, checklevel_shape) for v in range(5)}
KNOWN["-reindex with -loadblock: log lines"] = (REINDEX_FILE, without_file_lines)
for _v in ("0", "-1", "-100", "16", "17", "abc"):
    KNOWN[f"-par={_v}: log lines naming -par"] = (
        PAR, pair(("ok", []), ("ok", ["WARNING: Option -par is not supported by irondivid; ignored"])))
for _o in ("prune", "blocksonly", "stopatheight", "assumevalid"):
    KNOWN[f"-loadblock with -{_o}: log lines naming -{_o}"] = unknown_line(_o)
    KNOWN[f"-{_o} on a node with the chain: log lines naming -{_o}"] = unknown_line(_o)

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


def show(v):
    if isinstance(v, tuple) and v and v[0] == "err":
        return f"error {v[1]} \"{str(v[2])[:120]}\""
    return json.dumps(v, default=str)[:260]


def compare(name, core, iron):
    row(name, show(core), show(iron), core == iron, (core, iron))


def setup_failed(kind, value, tb):
    import traceback
    where = traceback.extract_tb(tb)[-1]
    print(f"FAIL   setup: {value} (check.py:{where.lineno})"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, core):
        self.name, self.binary, self.core = name, binary, core
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"chain{index}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.runs = 0
        self.dir = None

    def fresh(self, tag, template=None):
        self.dir = os.path.join(WORK, f"{self.name}.{tag}")
        if template:
            shutil.copytree(template, self.dir)
        else:
            os.makedirs(self.dir)

    def write_conf(self, connect=f"{HOST}:{DEAD}"):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=1",
            "daemon=0", "printtoconsole=0", "server=1", "listenonion=0", "discover=0", "staking=0",
            "dnsseed=0", f"connect={connect}",
        ]
        path = os.path.join(self.dir, "divi.conf")
        tmp = path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)

    def net_dir(self):
        return os.path.join(self.dir, "regtest") if self.core else self.dir

    def launch(self, *args):
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.run{self.runs}")
        self.err = base + ".err"
        self.out = base + ".out"
        with open(self.out, "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=WORK,
                                         stdout=o, stderr=e, stdin=subprocess.DEVNULL, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        self.log_from = self.log_size()

    def log_size(self):
        p = os.path.join(self.net_dir(), "debug.log")
        return os.path.getsize(p) if os.path.exists(p) else 0

    def start(self, *args):
        """('up',), ('exit', code, first error line) or ('exited', code) when it stops by itself once up"""
        self.launch(*args)
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
        return ("exit", f"none within {START_TIMEOUT} s", self.error_line())

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

    def exited(self, secs):
        """The exit code if the node stops by itself within secs, else None"""
        if self.proc is None:
            return None
        try:
            code = self.proc.wait(timeout=secs)
            self.proc = None
            return code
        except subprocess.TimeoutExpired:
            return None

    def log(self):
        """This run's debug.log (from where it stood at the launch) and what the node printed"""
        text = ""
        p = os.path.join(self.net_dir(), "debug.log")
        if os.path.exists(p):
            with open(p, errors="replace") as f:
                f.seek(self.log_from)
                text += f.read()
        for p in (self.out, self.err):
            if os.path.exists(p):
                with open(p, errors="replace") as f:
                    text += f.read()
        return text.replace(WORK, "<work>")


C = Node("divid", DIVID, 0, True)
I = Node("irondivid", IRONDIVID, 1, False)


def both(fn):
    out = {}
    ts = [threading.Thread(target=lambda n=n: out.__setitem__(n.name, fn(n))) for n in (C, I)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out["divid"], out["irondivid"]


# --- block files ---------------------------------------------------------------------------

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def records(path):
    """The blocks of a block file: magic, 4-byte size, block, as divid writes them"""
    with open(path, "rb") as f:
        data = f.read()
    out, off = [], 0
    while True:
        at = data.find(REGTEST_MAGIC, off)
        if at < 0 or at + 8 > len(data):
            return out
        n = int.from_bytes(data[at + 4:at + 8], "little")
        if n == 0 or at + 8 + n > len(data):
            return out
        out.append(data[at + 8:at + 8 + n])
        off = at + 8 + n


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# --- what a row shows ------------------------------------------------------------------------

# divid's start-up lines about loading and checking blocks (init.cpp:659, :675, :681, :705, :718, :721,
# :726; verifyDb.cpp:78), each with what is compared of it
LOG_LINES = [
    ("importing bootstrap.dat", r"Importing bootstrap\.dat\.\.\.", None),
    ("importing a blocks file", r"Importing blocks file (\S+)\.\.\.", 1),
    ("could not open a blocks file", r"Warning: Could not open blocks file (\S+)", 1),
    ("loaded from an external file", r"Loaded (\d+) blocks from external file", 1),
    ("reindexing a block file", r"Reindexing block file (blk\d+\.dat)\.\.\.", 1),
    ("reindexing finished", r"Reindexing finished", None),
    ("stopping after block import", r"Stopping after block import", None),
    ("verifying", r"Verifying last (-?\d+) blocks at level (\d)", 0),
]


def log_lines(node):
    """[tag, what] for each of divid's lines, in the order they come"""
    log = node.log()
    found = []
    for tag, pattern, group in LOG_LINES:
        for m in re.finditer(pattern, log):
            what = None if group is None else (m.group(0) if group == 0 else m.group(group))
            found.append((m.start(), [tag, what] if what is not None else [tag]))
    return [f for _, f in sorted(found)]


def naming(node, option):
    out = []
    for line in node.log().splitlines():
        if re.search(rf"-{option}\b", line) and "Verifying" not in line:
            # irondivid's lines start with a time and a level, divid's with a date and a time
            line = re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", "", line)
            out.append(re.sub(r"^\S+\s+(?:(?:INFO|WARN|ERROR|DEBUG)\s+\S+:\s+)", "", line).strip())
    return out


def outcome(o):
    if o[0] == "up":
        return "up"
    return f"exit {o[1]} \"{o[2][:150]}\""


def settled(node, secs=90):
    """The height once it has not changed for 3 s (an import runs after the start)"""
    last, since, deadline = None, time.time(), time.time() + secs
    while time.time() < deadline:
        out = node.call("getblockcount")
        h = out[1] if out[0] == "ok" else None
        if h != last:
            last, since = h, time.time()
        elif time.time() - since >= 3:
            return h
        time.sleep(0.5)
    return last


def chain_facts(node):
    info = node.rpc("getblockchaininfo")
    return {
        "height": node.rpc("getblockcount"),
        "best": node.rpc("getbestblockhash"),
        "info": {k: info.get(k) for k in ("chain", "blocks", "headers", "bestblockhash")},
        "verifychain 4 0": node.call("verifychain", 4, 0),
        "verifychain 4 5": node.call("verifychain", 4, 5),
    }


def boot_dir(node):
    """Where both look for bootstrap.dat: divid's GetDataDir(), <datadir>/regtest (init.cpp:699; irondivid
    reads it there too, bin/irondivid/src/main.rs core_network_dir)"""
    return os.path.join(node.dir, "regtest")


def files(node):
    """The import's files: bootstrap.dat and bootstrap.dat.old"""
    d = boot_dir(node)
    return sorted(f for f in os.listdir(d) if f.startswith("bootstrap")) if os.path.isdir(d) else []


# --- the chain: divid mines, irondivid follows; each exports it -------------------------------------

for n in (C, I):
    n.fresh("source")
C.write_conf()
I.write_conf(connect=f"{HOST}:{C.p2p}")
for n in (C, I):
    o = n.start()
    if o[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {o}")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
C.rpc("setgenerate", HEIGHT)  # as scripts/restart-state mines
deadline = time.time() + 120
while time.time() < deadline and not (C.rpc("getblockcount") == HEIGHT
                                      and I.rpc("getbestblockhash") == C.rpc("getbestblockhash")):
    time.sleep(0.5)
TIP = C.rpc("getbestblockhash")
if C.rpc("getblockcount") != HEIGHT or I.rpc("getbestblockhash") != TIP:
    raise RuntimeError(f"no common chain of {HEIGHT}: divid {C.rpc('getblockcount')}, irondivid "
                       f"{I.rpc('getblockcount')}")
both(lambda n: n.stop())

FROM_DIVID = os.path.join(WORK, "divid-blk00000.dat")
shutil.copyfile(os.path.join(C.net_dir(), "blocks", "blk00000.dat"), FROM_DIVID)
EXPORT = os.path.join(WORK, "irondivid-export")
ex = subprocess.run([IRONDIVID, f"-datadir={I.dir}", "--export-chain", "--export-start", "0", "--export-end",
                     str(HEIGHT), "--export-output", EXPORT], cwd=WORK, capture_output=True, text=True, timeout=300)
FROM_IRONDIVID = os.path.join(EXPORT, "bootstrap.dat")
if ex.returncode != 0 or not os.path.exists(FROM_IRONDIVID):
    raise RuntimeError(f"irondivid --export-chain: exit {ex.returncode} {ex.stderr[-200:]}")
a, b = records(FROM_DIVID), records(FROM_IRONDIVID)
compare("the two exports: blocks", ("ok", len(a)), ("ok", len(b)))
compare("the two exports: the same bytes, block by block", ("ok", True), ("ok", a == b))
MISSING = os.path.join(WORK, "no-such-file.dat")

# A data directory of each kind with the chain, for the checking rows
CHAINED = {"divid": C.dir, "irondivid": I.dir}


# --- loading: fresh data directories ------------------------------------------------------------

CASE = iter(range(1, 1000))


def load_row(name, args=(), bootstrap=None, stop_after=False, extra_rows=()):
    k = next(CASE)
    for n in (C, I):
        n.fresh(f"load{k}")
        n.write_conf()
        if bootstrap:
            os.makedirs(boot_dir(n), exist_ok=True)
            shutil.copyfile(bootstrap, os.path.join(boot_dir(n), "bootstrap.dat"))
    sums = {p: sha(p) for p in (FROM_DIVID, FROM_IRONDIVID)}

    def go(n):
        o = n.start(*args)
        if stop_after:
            # an import of 30 blocks can end, and the node with it, before RPC answers: the exit is what counts
            if o[0] == "exit":
                return o, ("exited", o[1]), None
            return o, ("exited", n.exited(90)), None
        if o[0] != "up":
            return o, None, None
        settled(n)
        return o, None, chain_facts(n)

    c, i = both(go)
    if not stop_after:
        compare(f"{name}: start", ("ok", outcome(c[0])), ("ok", outcome(i[0])))
    if stop_after:
        compare(f"{name}: stops by itself", ("ok", c[1]), ("ok", i[1]))
        logs = (log_lines(C), log_lines(I))
        for n in (C, I):
            n.stop()
        # started again with nothing: what it kept
        again = both(lambda n: (n.start(), settled(n), chain_facts(n)))
        compare(f"{name}: then a plain start, the chain", ("ok", again[0][2]), ("ok", again[1][2]))
        compare(f"{name}: log lines", ("ok", logs[0]), ("ok", logs[1]))
    else:
        if c[2] is not None and i[2] is not None:
            for key in c[2]:
                compare(f"{name}: {key}", ("ok", c[2][key]), ("ok", i[2][key]))
        compare(f"{name}: log lines", ("ok", log_lines(C)), ("ok", log_lines(I)))
    for option in extra_rows:
        compare(f"{name}: log lines naming -{option}", ("ok", naming(C, option)), ("ok", naming(I, option)))
    compare(f"{name}: bootstrap files", ("ok", files(C)), ("ok", files(I)))
    compare(f"{name}: the -loadblock files left as they were", ("ok", True),
            ("ok", all(sha(p) == s for p, s in sums.items())))
    both(lambda n: n.stop())


load_row("-loadblock=<divid's blk00000.dat>", [f"-loadblock={FROM_DIVID}"])
load_row("-loadblock=<irondivid's export>", [f"-loadblock={FROM_IRONDIVID}"])
load_row("-loadblock twice, both files", [f"-loadblock={FROM_DIVID}", f"-loadblock={FROM_IRONDIVID}"])
load_row("-loadblock=<a missing file>", [f"-loadblock={MISSING}"])
load_row("-loadblock=<a missing file> then divid's", [f"-loadblock={MISSING}", f"-loadblock={FROM_DIVID}"])
load_row("bootstrap.dat (divid's) in the data directory", bootstrap=FROM_DIVID)
load_row("bootstrap.dat (irondivid's) in the data directory", bootstrap=FROM_IRONDIVID)
load_row("bootstrap.dat and -loadblock", [f"-loadblock={FROM_IRONDIVID}"], bootstrap=FROM_DIVID)
load_row("-reindex with -loadblock", ["-reindex", f"-loadblock={FROM_DIVID}"])
load_row("-loadblock with -stopafterblockimport", [f"-loadblock={FROM_DIVID}", "-stopafterblockimport"],
         stop_after=True)
for option, value in (("prune", "550"), ("blocksonly", "1"), ("stopatheight", "5"), ("assumevalid", "0")):
    load_row(f"-loadblock with -{option}", [f"-loadblock={FROM_DIVID}", f"-{option}={value}"], extra_rows=[option])


# --- checking: a node that holds the chain --------------------------------------------------------

def check_row(name, args, option):
    k = next(CASE)
    for n in (C, I):
        n.fresh(f"check{k}", CHAINED[n.name])
        n.write_conf()

    def go(n):
        o = n.start(*args)
        facts = None
        if o[0] == "up":
            settled(n, 20)
            facts = {"height": n.rpc("getblockcount"), "best": n.rpc("getbestblockhash")}
        return o, facts

    c, i = both(go)
    compare(f"{name}: start", ("ok", outcome(c[0])), ("ok", outcome(i[0])))
    if c[1] is not None and i[1] is not None:
        compare(f"{name}: the chain", ("ok", c[1]), ("ok", i[1]))
    compare(f"{name}: verifying line", ("ok", [x for x in log_lines(C) if x[0] == "verifying"]),
            ("ok", [x for x in log_lines(I) if x[0] == "verifying"]))
    if option != "checklevel":  # the start row has the error line
        compare(f"{name}: log lines naming -{option}", ("ok", naming(C, option)), ("ok", naming(I, option)))
    both(lambda n: n.stop())


check_row("a plain start on the chain", [], "checkblocks")
for v in ("0", "1", "10", "-1", "abc", "1000"):
    check_row(f"-checkblocks={v}", [f"-checkblocks={v}"], "checkblocks")
for v in ("0", "1", "2", "3", "4"):
    check_row(f"-checklevel={v}", [f"-checklevel={v}"], "checklevel")
for v in ("0", "1"):
    check_row(f"-checkpoints={v}", [f"-checkpoints={v}"], "checkpoints")
for v in ("1", "4", "4096", "5000", "-5"):
    check_row(f"-dbcache={v}", [f"-dbcache={v}"], "dbcache")
for v in ("0", "-1", "-100", "16", "17", "abc"):
    check_row(f"-par={v}", [f"-par={v}"], "par")
for option, value in (("prune", "550"), ("blocksonly", "1"), ("stopatheight", "5"), ("assumevalid", "0")):
    check_row(f"-{option} on a node with the chain", [f"-{option}={value}"], option)

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
