#!/usr/bin/env python3
"""Refused starts and divi.conf reading, case by case, on a fresh Divi Core
divid and a fresh irondivid side by side: bad option values, conflicting
options, divi.conf forms, missing or unusable data directories, a second
instance on one data directory, and -?/-help/-version. Each case compares
whether the node starts, its exit code and the first error line it prints.
Each row prints PASS, KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf inside the work directory; no secret goes on a command line.
"""

import base64
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid gets this extra argument
# in the named case
INJECT = os.environ.get("START_ERRORS_INJECT", "")
RPC_TIMEOUT = 30
# How long a node may take to answer RPC, and how long one that neither
# answers nor exits is watched before it counts as running without RPC
START_TIMEOUT = 60
QUIET_TIMEOUT = 10

# Differences irondivid has on purpose or that come from divid's own failures,
# one per row name: (reason, shape). Each is listed in README.md with divid's
# source line. shape takes the two outcomes and is true only for the
# difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL.


def core_aborts(c, i):
    """The same error line; divid then aborts (SIGABRT), irondivid exits 1"""
    return c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2]


ABORT = ("same error; divid then aborts (SIGABRT) in the shutdown after this early InitError: "
         "PrepareShutdown's FlushStateToDisk (divi/src/init.cpp:381) asserts in ChainstateManager::Get "
         "(divi/src/ChainstateManager.cpp:102) before the chain state exists; irondivid exits 1", core_aborts)


def lock_shape(c, i):
    """divid's lock text with irondivid's product phrase; divid aborts as above"""
    return (c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1
            and c[2].replace("DIVI Core is probably", "Divi Core or irondivid is probably") == i[2])


def cookie_shape(c, i):
    """divid refuses for want of an rpcpassword (and aborts); irondivid goes on and refuses later"""
    return (c[0] == i[0] == "exit" and c[1] == -6 and "you must set an rpcpassword" in c[2]
            and i[1] == 1 and i[2].startswith("Error"))


COOKIE = ("without a readable divi.conf both run as mainnet; divid refuses to start for want of an "
          "rpcpassword (divi/src/rpcserver.cpp:655-680, chainparams.cpp:245) and aborts as after any early "
          "InitError; irondivid makes an RPC cookie instead (by design, crates/divi-rpc/src/auth_cookie.rs) and "
          "then refuses this regtest data directory as another network's (or names the unreadable file)",
          cookie_shape)


def name_shape(c, i):
    return (c[0] == i[0] and re.fullmatch(r"Divi Core Daemon version v\S+", c[1] or "") is not None
            and re.fullmatch(r"IronDivi Daemon version v\S+", i[1] or "") is not None)


NAMES = ("irondivid names itself and its version (IronDivi Daemon version v<irondivid's>) where divid prints "
         "Divi Core Daemon version v3.0.0 (divi/src/divid.cpp:70-85); same exit code", name_shape)

def leveldb_shape(c, i):
    """divid dies on its unreadable block index; irondivid refuses with exit 1"""
    return (c[0] == i[0] == "exit" and c[1] == -6 and c[2].startswith("EXCEPTION: 13leveldb_error")
            and i[1] == 1 and i[2].startswith("Error: Failed to open chain database"))


LEVELDB = ("divid dies on the uncaught leveldb_error of its unreadable block index (\"EXCEPTION: "
           "13leveldb_error\", SIGABRT; divi/src/init.cpp:1503-1531, divid.cpp AppInit's catch-all); irondivid "
           "refuses with exit 1 and the error", leveldb_shape)


def early_bind_files(c, i):
    """divid checks -bind in step 6, after its wallet backup; irondivid before it writes anything"""
    return c == ["backups +1"] and i == []


EARLY_BIND = ("divid resolves -bind in step 6 (divi/src/net.cpp:1806-1811), after its pid file and its wallet "
              "backup (init.cpp:1479); irondivid reads -bind with the other options, before it takes the lock, "
              "and makes no backup", early_bind_files)

KNOWN = {
    "start -maxtxfee=abc": ABORT,
    "start -maxtxfee=-1": ABORT,
    "start -maxtxfee=99999999999": ABORT,
    "start -externalip=garbage": ABORT,
    "start -onlynet=bogus": ABORT,
    "start -proxy=garbage": ABORT,
    "second instance on the same data directory": (
        "divid's text, with irondivid's product phrase (Divi Core or irondivid is probably already running, as "
        "irondivid's P2P bind error says); divid then aborts as after any early InitError "
        "(divi/src/init.cpp:850-862, :381)", lock_shape),
    "-conf=<a missing file>": COOKIE,
    "divi.conf unreadable": COOKIE,
    "-datadir=<a read-only directory>": (
        "divid dies on an uncaught boost::filesystem_error creating <datadir>/regtest (\"EXCEPTION: "
        "N5boost10filesystem16filesystem_errorE ... Permission denied\", divi/src/divid.cpp AppInit's catch-all "
        "rethrows, SIGABRT); irondivid refuses with exit 1 and the error",
        lambda c, i: c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and i[2].startswith("Error")),
    "the chain cannot be opened": LEVELDB,
    "the chain cannot be opened, -hdseed in divi.conf": LEVELDB,
    "the chain cannot be opened, no masternode.conf": LEVELDB,
    "-listen=1 -bind=garbage": ABORT,
    "-listen=1 -bind=garbage: files": EARLY_BIND,
    "-?: first line": NAMES,
    "-help: first line": NAMES,
    "--help: first line": NAMES,
    "-version: first line": NAMES,
    "--version: first line": NAMES,
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.template = os.path.join(WORK, name + ".template")
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"start{index}"
        self.password = secrets.token_hex(16)
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "listen=0", "dnsseed=0", "staking=0", f"connect=127.0.0.1:{PORT_BASE + 49}",
        ]
        os.makedirs(self.dir)
        self.proc = None
        self.runs = 0

    def write_conf(self, text, path=None):
        path = path or os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.chmod(path, 0o600)
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        return path

    def conf_text(self, extra=(), drop=()):
        lines = [ln for ln in self.lines if ln.split("=", 1)[0] not in drop]
        return "\n".join(lines + list(extra)) + "\n"

    def restore(self):
        """The data directory as the template left it (one clean start, stopped)"""
        for root, dirs, files in os.walk(self.dir):
            os.chmod(root, 0o700)
        shutil.rmtree(self.dir)
        shutil.copytree(self.template, self.dir)

    def launch(self, args, datadir=True):
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.{self.runs}")
        self.out, self.err = base + ".out", base + ".err"
        argv = [self.binary] + ([f"-datadir={self.dir}"] if datadir is True else []) + list(args)
        with open(self.out, "w") as o, open(self.err, "w") as e:
            proc = subprocess.Popen(argv, cwd=WORK, stdout=o, stderr=e, stdin=subprocess.DEVNULL,
                                    start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{proc.pid}\n")
        return proc

    def outcome(self, proc, ports, quiet=None):
        """('up', port) once RPC answers on one of `ports`; ('running',) when it
        neither answers nor exits; ('exit', code, first error line)"""
        quiet = quiet or QUIET_TIMEOUT
        deadline = time.time() + START_TIMEOUT
        quiet_since = None
        while time.time() < deadline:
            code = proc.poll()
            if code is not None:
                return ("exit", code, self.error_line())
            for port in ports:
                try:
                    if self.call("getblockcount", port=port)[0] == "ok":
                        return ("up", port)
                except Exception:
                    pass
            quiet_since = quiet_since or time.time()
            if time.time() - quiet_since > quiet and not self.rpc_listening(ports):
                return ("running",)
            time.sleep(0.25)
        return ("running",)

    def rpc_listening(self, ports):
        import socket
        for port in ports:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                return True
            except OSError:
                pass
        return False

    def error_line(self):
        """The first line on stderr that names an error, else the first line"""
        with open(self.err, errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        first = next((ln for ln in lines if ln.startswith(("Error", "error"))), lines[0] if lines else "")
        # The node's own paths, so the two lines compare: divid keeps regtest
        # data in a regtest/ folder of the data directory, irondivid in it
        for path, name in ((os.path.join(self.dir, "regtest"), "<datadir>"), (self.dir, "<datadir>"),
                           (os.path.join(WORK, self.name), "<work>/<node>"), (WORK, "<work>")):
            first = first.replace(path, name)
        return first

    def call(self, method, *params, port=None):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://127.0.0.1:{port or self.rpcport}/", data=body,
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

    def finish(self, proc, out, clean=False):
        """Stop a node the case left running: killed, as the next case starts
        from the template again (clean=True: by RPC or SIGTERM, for the template)"""
        if proc.poll() is None and not clean:
            proc.kill()
            proc.wait()
        if proc.poll() is None:
            if out[0] == "up":
                try:
                    self.call("stop", port=out[1])
                except Exception:
                    pass
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

    def log_has(self, pattern):
        for p in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log"), self.err):
            if os.path.exists(p):
                with open(p, errors="replace") as f:
                    if re.search(pattern, f.read()):
                        return True
        return False


def net_dir(n):
    return os.path.join(n.dir, "regtest") if n is C else n.dir


def wallet_path(n):
    return os.path.join(net_dir(n), "wallet.dat" if n is C else "wallet")


def snapshot(n):
    d = net_dir(n)
    backups = os.path.join(d, "backups")
    return {"backups": len(os.listdir(backups)) if os.path.isdir(backups) else 0,
            "moved": sum(1 for f in os.listdir(d) if f.endswith(".moved")) if os.path.isdir(d) else 0,
            "wallet": os.path.exists(wallet_path(n)),
            "mnconf": os.path.exists(os.path.join(d, "masternode.conf"))}


def made(n, before):
    """What a start did to the data directory, next to `before` (a snapshot):
    a wallet backup, the wallet moved for a restore, a wallet or masternode.conf made"""
    after = snapshot(n)
    out = []
    if after["backups"] > before["backups"]:
        out.append(f"backups +{after['backups'] - before['backups']}")
    if after["moved"] > before["moved"]:
        out.append("wallet moved")
    if after["wallet"] and not before["wallet"]:
        out.append("wallet made")
    if after["mnconf"] and not before["mnconf"]:
        out.append("masternode.conf made")
    return out


def show(o):
    if o[0] == "up":
        return "up" if o[1] in (C.rpcport, I.rpcport) else f"up on port {o[1] - PORT_BASE:+d}"
    if o[0] == "running":
        return "running, no RPC"
    return f"exit {o[1]} \"{o[2][:150]}\""


def same_outcome(c, i):
    if c[0] != i[0]:
        return False
    if c[0] == "exit":
        return c[1] == i[1] and c[2] == i[2]
    if c[0] == "up":
        return c[1] - C.rpcport == i[1] - I.rpcport
    return True


def case(name, args=(), extra=(), drop=(), conf=None, restore=True, alt_port=None, warn=None,
         setup=None, datadir=True, files=False):
    """Start both with the same case; compare the outcome, then stop them.
    args: argv after -datadir; extra/drop: divi.conf lines added or keys left
    out; conf: a function node -> divi.conf text; alt_port: another RPC port
    offset the node may answer on; warn: a pattern looked for in the log of a
    node that starts; setup: a function node -> argv list, run before the start;
    files: also compare what the start did to the data directory (made)."""
    results = {}

    def one(n):
        if restore:
            n.restore()
        n.write_conf(conf(n) if conf else n.conf_text(extra, drop))
        argv = list(args) if setup is None else setup(n)
        before = snapshot(n)
        if n is I and INJECT == name:
            argv = argv + [f"-datadir={os.path.join(WORK, 'injected-missing')}"]
        proc = n.launch(argv, datadir)
        ports = [n.rpcport] + ([n.rpcport + alt_port] if alt_port else [])
        o = n.outcome(proc, ports)
        log = n.log_has(warn) if warn else None
        n.finish(proc, o)
        results[n] = (o, log, made(n, before))

    # Both nodes at once: they share nothing but the work directory
    threads = [threading.Thread(target=one, args=(n,)) for n in (C, I)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    (c, lc, fc), (i, li, fi) = results[C], results[I]
    logs = [lc, li]
    row(name, show(c), show(i), same_outcome(c, i), (c, i))
    if warn:
        row(f"{name}: warns", logs[0], logs[1], logs[0] == logs[1], (c, i))
    if files:
        row(f"{name}: files", fc, fi, fc == fi, (fc, fi))
    return c, i


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)

# The template: one clean start (wallet and chain made), stopped
for n in (C, I):
    n.write_conf(n.conf_text())
    proc = n.launch([])
    o = n.outcome(proc, [n.rpcport])
    if o[0] != "up":
        print(f"FAIL   setup: {n.name} did not start: {show(o)}", flush=True)
        sys.exit(1)
    n.finish(proc, o, clean=True)
    shutil.copytree(n.dir, n.template)
print("# both nodes started once; each case starts from that data directory", flush=True)

# --- bad option values (divi/src/init.cpp, net.cpp, rpcserver.cpp) ---------------

case("normal start")
for opt in ("-port=abc", "-port=0", "-port=70000", "-rpcport=abc", "-rpcport=0", "-rpcport=70000",
            "-maxconnections=-1", "-maxconnections=abc", "-dbcache=0", "-dbcache=99999999",
            "-par=-100", "-par=abc", "-keypool=-1", "-paytxfee=abc", "-mintxfee=abc",
            "-maxtxfee=abc", "-maxtxfee=-1", "-maxtxfee=99999999999",
            "-bind=garbage", "-bind=300.1.1.1", "-externalip=garbage", "-onlynet=bogus",
            "-proxy=garbage", "-timeout=0", "-timeout=abc", "-banscore=0", "-bantime=-1",
            "-prune=550", "-nosuchoption", "-nosuchoption=1"):
    case(f"start {opt}", [opt])
case("start -rpcbind=garbage -rpcallowip=127.0.0.1", ["-rpcbind=garbage", "-rpcallowip=127.0.0.1"])
case("start -rpcallowip=garbage", ["-rpcallowip=garbage"])
case("start -rpcallowip=1.2.3.4/99", ["-rpcallowip=1.2.3.4/99"])

# --- conflicting options -----------------------------------------------------------

case("start -bind with -listen=0", ["-bind=127.0.0.1", "-listen=0"])
case("start -connect with -listen=1", setup=lambda n: ["-listen=1", f"-bind=127.0.0.1:{n.p2p + 40}"])
case("start -rpcbind without -rpcallowip", ["-rpcbind=127.0.0.1"], warn=r"rpcbind was ignored")
case("start -txindex=0 on an indexed data directory", ["-txindex=0"])
case("start -txindex=1", ["-txindex=1"])
case("start -server=0 (no RPC)", ["-server=0"])

# --- divi.conf -----------------------------------------------------------------------


def conf_with(*more, drop=()):
    return lambda n: n.conf_text(list(more), drop)


case("divi.conf: an unknown key", conf=conf_with("nosuchkey=1"))
case("divi.conf: spaces around =", conf=lambda n: n.conf_text(drop=("rpcport",)) +
     f"rpcport = {n.rpcport}\n")
case("divi.conf: a comment after the value", conf=lambda n: n.conf_text(drop=("rpcport",)) +
     f"rpcport={n.rpcport} # the RPC port\n")
case("divi.conf: a line that is a comment", conf=conf_with("# rpcport=1"))
case("divi.conf: a repeated key (first or last wins)", conf=lambda n: n.conf_text() +
     f"rpcport={n.rpcport + 10}\n", alt_port=10)
case("divi.conf: -rpcport on the command line over divi.conf",
     setup=lambda n: [f"-rpcport={n.rpcport + 10}"], alt_port=10)
case("divi.conf: a [section] line before a key", conf=lambda n: n.conf_text() +
     f"[main]\nrpcport={n.rpcport + 10}\n", alt_port=10)
case("divi.conf: a [regtest] section", conf=lambda n: n.conf_text(drop=("rpcport",)) +
     f"[regtest]\nrpcport={n.rpcport}\n", alt_port=None)
case("divi.conf: a line with no =", conf=conf_with("listen"))
case("divi.conf: a line with no = after the keys", conf=conf_with("justaword"))
case("divi.conf: an empty value", conf=conf_with("maxconnections="))
case("divi.conf: a key starting with -", conf=conf_with("-maxconnections=8"))
case("divi.conf: a boolean as no<key>", conf=conf_with("noserver=1"))
case("divi.conf: CRLF line ends", conf=lambda n: n.conf_text().replace("\n", "\r\n"))
case("divi.conf: no rpcpassword with RPC on", conf=conf_with(drop=("rpcpassword",)))
case("divi.conf: no rpcuser and no rpcpassword", conf=conf_with(drop=("rpcuser", "rpcpassword")))


def empty_conf(n):
    return ""


case("divi.conf: empty (options on the command line)", conf=empty_conf,
     setup=lambda n: ["-regtest", f"-port={n.p2p}", f"-rpcport={n.rpcport}", "-listen=0", "-dnsseed=0",
                      f"-connect=127.0.0.1:{PORT_BASE + 49}"])
case("-conf=<a missing file>", setup=lambda n: [f"-conf={os.path.join(WORK, 'missing.conf')}"])


def other_conf(n):
    path = os.path.join(WORK, f"{n.name}.other.conf")
    n.write_conf(n.conf_text(drop=("rpcport",)) + f"rpcport={n.rpcport + 10}\n", path)
    return [f"-conf={path}"]


case("-conf=<another file>", setup=other_conf, alt_port=10)


def relative_conf(n):
    n.write_conf(n.conf_text(drop=("rpcport",)) + f"rpcport={n.rpcport + 10}\n",
                 os.path.join(n.dir, "other.conf"))
    return ["-conf=other.conf"]


case("-conf=<a name relative to -datadir>", setup=relative_conf, alt_port=10)


def unreadable_conf(n):
    os.chmod(os.path.join(n.dir, "divi.conf"), 0)
    return []


case("divi.conf unreadable", setup=unreadable_conf)

# --- a start that fails part way: what it has done by then (init.cpp:1454-1598) --------


def unreadable_chain(n):
    """divid's block index, irondivid's chain database: neither opens"""
    with open(os.path.join(net_dir(n), "blocks", "index", "CURRENT") if n is C
              else os.path.join(n.dir, "chainstate", "CURRENT"), "w") as f:
        f.write("garbage")
    return []


def unreadable_chain_and(more):
    def setup(n):
        more(n)
        return unreadable_chain(n)
    return setup


def no_mnconf(n):
    os.remove(os.path.join(net_dir(n), "masternode.conf"))


def no_wallet(n):
    p = wallet_path(n)
    shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    return ["-masternode=1"]


# step 5's wallet backup, then step 7 fails
case("the chain cannot be opened", setup=unreadable_chain, files=True)
# step 4 moves the wallet for the restore (the seed in the 0600 divi.conf: BIP32 test vector 1)
case("the chain cannot be opened, -hdseed in divi.conf", extra=["hdseed=000102030405060708090a0b0c0d0e0f"],
     setup=unreadable_chain, files=True)
# step 10 reads masternode.conf, and makes it when missing
case("the chain cannot be opened, no masternode.conf", setup=unreadable_chain_and(no_mnconf), files=True)
# step 10 stops at -masternode without its entry, after step 8 made the wallet
case("-masternode=1 without its entry, no wallet", setup=no_wallet, files=True)
# step 6 resolves -bind on a node that listens
case("-listen=1 -bind=garbage", ["-listen=1", "-bind=garbage"], files=True)

# --- data directories ----------------------------------------------------------------

case("-datadir=<missing>", setup=lambda n: [f"-datadir={os.path.join(WORK, n.name + '.no-such-dir')}"],
     datadir=False)
afile = os.path.join(WORK, "a-file")
with open(afile, "w") as f:
    f.write("x\n")
case("-datadir=<a file>", setup=lambda n: [f"-datadir={afile}"], datadir=False)


def read_only(n):
    d = os.path.join(WORK, f"{n.name}.ro")
    if not os.path.exists(d):
        os.makedirs(d)
        n.write_conf(n.conf_text(), os.path.join(d, "divi.conf"))
    os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
    return [f"-datadir={d}"]


case("-datadir=<a read-only directory>", setup=read_only, datadir=False)

# A second instance on the same data directory (init.cpp:855-861)
outs = []
for n in (C, I):
    n.restore()
    n.write_conf(n.conf_text())
    first = n.launch([])
    o1 = n.outcome(first, [n.rpcport])
    second = n.launch([f"-rpcport={n.rpcport + 20}", f"-port={n.p2p + 20}"])
    # divid takes about 10 s to give up on the lock
    o2 = n.outcome(second, [n.rpcport + 20], quiet=40)
    n.finish(second, o2)
    n.finish(first, o1)
    outs.append((o1, o2))
row("second instance: the first starts", show(outs[0][0]), show(outs[1][0]),
    same_outcome(outs[0][0], outs[1][0]), (outs[0][0], outs[1][0]))
row("second instance on the same data directory", show(outs[0][1]), show(outs[1][1]),
    same_outcome(outs[0][1], outs[1][1]), (outs[0][1], outs[1][1]))

# --- -?, -help, -version (divid.cpp:70-85): exit code and first line --------------


def help_outcome(n, arg):
    proc = n.launch([arg])
    try:
        code = proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        # Not a help option: the node starts as with no option at all
        proc.kill()
        proc.wait()
        code = "running (a normal start)"
    with open(n.out, errors="replace") as f:
        first = next((ln.rstrip("\n") for ln in f if ln.strip()), "")
    return code, first


for arg in ("-?", "-help", "-h", "--help", "-version", "--version", "-V"):
    for n in (C, I):
        n.restore()
        n.write_conf(n.conf_text())
    c, i = help_outcome(C, arg), help_outcome(I, arg)
    row(f"{arg}: exit code", c[0], i[0], c[0] == i[0], (c, i))
    row(f"{arg}: first line", repr(c[1][:80]), repr(i[1][:80]), c[1] == i[1], (c, i))

for n in (C, I):
    ro = os.path.join(WORK, f"{n.name}.ro")
    if os.path.exists(ro):
        os.chmod(ro, 0o700)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
