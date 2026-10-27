#!/usr/bin/env python3
"""The masternode start options, row by row on a fresh Divi Core divid and a
fresh irondivid side by side: each row writes the same divi.conf and
masternode.conf for both, starts both on regtest with the same command line,
and compares whether the start succeeds (or the exact error it prints), then
the RPC replies that show the option's effect. Each row prints PASS, KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Every masternode key is a throwaway regtest key made here at run time; it goes
only into the test datadir's 0600 conf files and is never printed or put on a
command line. Started by run.sh, which owns the work directory and stops the
nodes.
"""

import base64
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row runs differently on irondivid
INJECT = os.environ.get("MN_OPTIONS_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120
# Loopback address the nodes bind to: the ports are inside the host's ephemeral
# range, where other programs' 127.0.0.1 sockets can hold them
HOST = "127.0.0.2"
# How long a node started without RPC must keep running to count as started
RUNNING = 6

# Differences irondivid has on purpose or has not closed yet, one per row name:
# (reason, shape). Each is listed in README.md with divid's source line. shape
# takes the two raw outcomes and is true only for the difference described, so
# a KNOWN row that matches divid, or differs in another way, is a FAIL.
def iron_refuses_masternode(c, i):
    return c[0] == "up" and i[0] == "exit" and "does not run as a masternode" in i[2]


RUNS_AS_MASTERNODE = (
    "the options are valid, so divid starts as a masternode (MasternodeModule.cpp:221-240); irondivid has no "
    "active masternode (no pings, no votes) and refuses the start with its own message once every check divid "
    "makes has passed", iron_refuses_masternode)
KNOWN = {
    "-masternode=mn1 and its entry: start": RUNS_AS_MASTERNODE,
    "-masternodeprivkey good over a bad entry key: start": RUNS_AS_MASTERNODE,
    "-masternodeaddr good: start": RUNS_AS_MASTERNODE,
    "-mnconf=<relative> and -masternode: start": RUNS_AS_MASTERNODE,
}

fails = 0


def row(name, core, iron, same, raw=None):
    """same: True when the two outcomes count as equal for this row; raw: the
    two outcomes, for the shape of a KNOWN difference"""
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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def number(digits):
    """A random number of `digits` digits, no leading zero: a TOML integer"""
    return str(secrets.choice("123456789")) + "".join(secrets.choice("0123456789") for _ in range(digits - 1))


class Node:
    def __init__(self, name, binary, index, case):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, case, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        # Numbers, so the base lines alone are a valid TOML document as well
        self.user, self.password = number(9), number(18)
        os.makedirs(self.dir)
        # divid keeps regtest data, masternode.conf among it, in <datadir>/regtest
        self.netdir = os.path.join(self.dir, "regtest") if binary == DIVID else self.dir
        os.makedirs(self.netdir, exist_ok=True)
        self.proc = None
        self.out = self.err = None

    def base(self):
        return [f"rpcuser={self.user}", f"rpcpassword={self.password}"]

    def write(self, text, name="divi.conf"):
        """A config file under the datadir, 0600"""
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(text.encode("utf-8"))
        return path

    def args(self, regtest=True, datadir=True):
        a = ([f"-datadir={self.dir}"] if datadir else []) + [f"-port={self.p2p}", f"-rpcport={self.rpcport}",
             f"-bind={HOST}", f"-rpcbind={HOST}", "-rpcallowip=127.0.0.0/8", "-listen=0",
             "-dnsseed=0", "-discover=0", "-staking=0", "-printtoconsole=0", "-daemon=0",
             # a small keypool: each row makes new wallets, and divid fills 1000 keys by default
             "-keypool=10"]
        return (["-regtest"] if regtest else []) + a

    def launch(self, args):
        self.out, self.err = self.dir + ".out", self.dir + ".err"
        # A home of its own, so a node started without -datadir keeps its
        # default data directory inside the run
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        os.makedirs(env["HOME"], exist_ok=True)
        with open(self.out, "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, args):
        """('up',) once RPC answers, or ('exit', code, first stderr line naming an error)"""
        self.launch(args)
        return self.wait_up()

    def wait_up(self):
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

    def start_without_rpc(self, args):
        """For a start whose config has no RPC password: ('running',) when the
        process is still up after RUNNING seconds, else ('exit', code, error)"""
        self.launch(args)
        return self.wait_running()

    def wait_running(self):
        deadline = time.time() + RUNNING
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code, self.error_line())
            time.sleep(0.25)
        return ("running",)

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}")
            except ValueError:
                return ("err", e.code, "HTTP %d" % e.code)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:160]}")
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
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def terminate(self):
        """Stop a node started without RPC"""
        if self.proc is None:
            return
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


def show_start(s):
    return s[0] if s[0] in ("up", "running") else f"exit {s[1]} \"{s[2][:110]}\""


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed




# --- throwaway regtest keys ---------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def new_key():
    """A compressed regtest private key (WIF, version 239), made here and
    written only into the test datadirs' conf files"""
    return b58check(bytes([239]) + secrets.token_bytes(32) + b"\x01")


# --- one row --------------------------------------------------------------------------

FAKE_TX = "11" * 32  # a collateral outpoint nobody has: the start checks do not look it up
case_number = 0


def show_out(out):
    if out[0] == "err":
        return f"error {out[1]} {json.dumps(str(out[2]).splitlines()[0] if out[2] else '')}"
    return json.dumps(out[1], sort_keys=True)


def case(name, conf=(), mnconf=None, mnconf_path=None, extra_args=(), probes=(), check=None):
    """Write `conf` lines into each node's divi.conf (with its RPC lines) and
    `mnconf` lines (a function of the node, for its own address) into its
    masternode.conf, or into `mnconf_path` (relative to the node's network
    folder; None for the default file), then start both and compare"""
    global case_number
    case_number += 1
    nodes = [Node("divid", DIVID, 0, f"case{case_number}"), Node("irondivid", IRONDIVID, 1, f"case{case_number}")]
    for n in nodes:
        n.write("\n".join(n.base() + list(conf)) + "\n")
        if mnconf is not None:
            target = os.path.join(n.netdir, mnconf_path or "masternode.conf")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(mnconf(n)) + "\n")
    for n in nodes:
        n.launch(n.args() + [a.replace("{net}", n.netdir) for a in extra_args])
    c, i = (n.wait_up() for n in nodes)
    if c[0] == "exit" and i[0] == "exit":
        same = c[1] == i[1] and c[2] == i[2]
    else:
        same = c[0] == i[0]
    row(f"{name}: start", show_start(c), show_start(i), same, (c, i))
    if c[0] == i[0] == "up":
        for label, method, params in probes:
            a, b = nodes[0].call(method, *params), nodes[1].call(method, *params)
            row(f"{name}: {label}", show_out(a), show_out(b), show_out(a) == show_out(b))
    if check:
        a, b = check(nodes[0]), check(nodes[1])
        row(f"{name}: {check.__name__}", json.dumps(a), json.dumps(b), a == b)
    for n in nodes:
        n.stop()


STATUS = ("getmasternodestatus", "getmasternodestatus", ())


def entry(alias="mn1", key=None):
    """A masternode.conf line for the node itself, with a new key"""
    return lambda n: [f"{alias} {HOST}:{n.p2p} {key or new_key()} {FAKE_TX} 0"]


# --- the rows -----------------------------------------------------------------------

# masternode.conf is read at every start, a masternode or not (MasternodeModule.cpp:210-226)
case("no masternode option, a valid masternode.conf", mnconf=entry(), probes=(STATUS,))
case("no masternode option, a masternode.conf line of three fields",
     mnconf=lambda n: [f"mn1 {HOST}:{n.p2p} {FAKE_TX}"])
case("no masternode option, a comment and an empty line in masternode.conf",
     mnconf=lambda n: ["# a comment", "", f"mn1 {HOST}:{n.p2p} {new_key()} {FAKE_TX} 0"], probes=(STATUS,))

# -masternode: txindex first, then the address, then the alias and the key (:221-240, :163-208)
case("-masternode=mn1 with -txindex=0", conf=["masternode=mn1", "txindex=0"], mnconf=entry())
case("-masternode=mn1 with -txindex=0 and no entry", conf=["masternode=mn1", "txindex=0"], mnconf=entry("other"))
case("-masternode=mn1 and its entry", conf=["masternode=mn1"], mnconf=entry(), probes=(STATUS,))
case("-masternode=mn1 and no entry for it", conf=["masternode=mn1"], mnconf=entry("other"))
case("-masternode=mn1 and no masternode.conf lines", conf=["masternode=mn1"], mnconf=lambda n: ["# none"])
case("-masternode= empty", conf=["masternode="], mnconf=entry(""))
case("-masternode=mn1, the entry's key not a key", conf=["masternode=mn1"], mnconf=entry(key="notakey"))
case("-masternode=mn1, a mainnet key in the entry", conf=["masternode=mn1"],
     mnconf=entry(key=b58check(bytes([212]) + secrets.token_bytes(32) + b"\x01")))

# -masternodeprivkey over the entry's key (:179)
case("-masternodeprivkey good over a bad entry key", conf=["masternode=mn1", f"masternodeprivkey={new_key()}"],
     mnconf=entry(key="notakey"), probes=(STATUS,))
case("-masternodeprivkey bad over a good entry key", conf=["masternode=mn1", "masternodeprivkey=notakey"],
     mnconf=entry())
case("-masternodeprivkey without -masternode", conf=["masternodeprivkey=notakey"], mnconf=entry(),
     probes=(STATUS,))

# -masternodeaddr (:197-208)
case("-masternodeaddr good", conf=["masternode=mn1", f"masternodeaddr={HOST}:53790"], mnconf=entry(),
     probes=(STATUS,))
case("-masternodeaddr not an address", conf=["masternode=mn1", "masternodeaddr=garbage"], mnconf=entry())
case("-masternodeaddr bad without -masternode", conf=["masternodeaddr=garbage"], mnconf=entry())


# -mnconf (masternodeconfig.cpp:33-38: relative to the network data folder)
def made(n, rel):
    return os.path.exists(os.path.join(n.netdir, rel))


def missing_made(n):
    """Whether the missing file was made, with divid's header"""
    path = os.path.join(n.netdir, "missing.conf")
    return open(path).read().startswith("# Masternode config file") if os.path.exists(path) else False


def default_untouched(n):
    """No default masternode.conf made beside a -mnconf file"""
    return os.path.exists(os.path.join(n.netdir, "masternode.conf"))


case("-mnconf=<relative> with a bad line", mnconf=lambda n: ["bad line"], mnconf_path="sub/mn.conf",
     extra_args=("-mnconf=sub/mn.conf",))
case("-mnconf=<relative> and -masternode", conf=["masternode=mn1"], mnconf=entry(), mnconf_path="sub/mn.conf",
     extra_args=("-mnconf=sub/mn.conf",), probes=(STATUS,), check=default_untouched)
case("-mnconf=<absolute> with a bad line", mnconf=lambda n: ["bad line"], mnconf_path="abs.conf",
     extra_args=("-mnconf={net}/abs.conf",))
case("-mnconf=<missing>", extra_args=("-mnconf=missing.conf",), check=missing_made)
case("no masternode.conf at all", check=lambda n: made(n, "masternode.conf"))

# -litemode and -budgetvotemode: only in divid's help (LicenseAndInfo.cpp:209, :226)
def warns_about_them(n):
    """Whether the node's log names the two options as unsupported (divid
    says nothing about options it does not read)"""
    text = ""
    for path in (os.path.join(n.netdir, "debug.log"), os.path.join(n.dir, "debug.log")):
        if os.path.exists(path):
            text += open(path, errors="replace").read()
    return "litemode is not supported" in text or "budgetvotemode is not supported" in text


case("-litemode=1 -budgetvotemode=auto", conf=["litemode=1", "budgetvotemode=auto"], probes=(STATUS,),
     check=warns_about_them)


# -mnconflock (MasternodeModule.cpp:454-466, init.cpp:1246-1258): a funded
# collateral in each node's own wallet, named in its masternode.conf
def lock_rows():
    nodes = [Node("divid", DIVID, 0, "lock"), Node("irondivid", IRONDIVID, 1, "lock")]
    for n in nodes:
        n.write("\n".join(n.base()) + "\n")
        need(n.start(n.args())[0] == "up", f"{n.name} did not start for the lock rows")
        n.rpc("setgenerate", 30)
        alloc = n.rpc("allocatefunds", "masternode", "mn1", "copper")
        n.collateral = {"txid": alloc["txhash"], "vout": alloc["vout"]}
        n.rpc("setgenerate", 1)
        n.stop()
    for label, lines_where, args in (
            ("-mnconflock default", "masternode.conf", ()),
            ("-mnconflock=1", "masternode.conf", ("-mnconflock=1",)),
            ("-mnconflock=0", "masternode.conf", ("-mnconflock=0",)),
            ("-mnconf=<relative> naming the collateral", "sub/mn.conf", ("-mnconf=sub/mn.conf",))):
        for n in nodes:
            for path in ("masternode.conf", "sub/mn.conf"):
                full = os.path.join(n.netdir, path)
                if os.path.exists(full):
                    os.remove(full)
            target = os.path.join(n.netdir, lines_where)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(f"mn1 {HOST}:{n.p2p} {new_key()} {n.collateral['txid']} {n.collateral['vout']}\n")
            need(n.start(n.args() + list(args))[0] == "up", f"{n.name} did not start: {label}")
        locked = [n.rpc("listlockunspent") for n in nodes]
        own = [[e == n.collateral for e in l] for l, n in zip(locked, nodes)]
        row(f"{label}: listlockunspent", json.dumps(own[0]), json.dumps(own[1]), own[0] == own[1])
        for n in nodes:
            n.stop()


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


lock_rows()

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
