#!/usr/bin/env python3
"""How divi.conf itself is read, row by row on a fresh Divi Core divid and a
fresh irondivid side by side: each row writes the same config file for both,
starts both on regtest with the same command line, and compares whether the
start succeeds (or the exact error it prints), then the values the file set,
seen through RPC. Each row prints PASS, KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row runs differently on irondivid
INJECT = os.environ.get("CONF_PARSE_INJECT", "")
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
def core_reads_a_directory(c, i):
    return c[0] == "running" and i[0] == "exit" and "Error reading configuration file" in i[2]


def core_aborts(c, i):
    return c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2]


ABORT = ("same message; divid then aborts (SIGABRT) in the shutdown after this early InitError, as in "
         "scripts/restart-options (divi/src/init.cpp:381, divi/src/ChainstateManager.cpp:102); irondivid exits 1",
         core_aborts)
KNOWN = {
    "a quoted value: start": ABORT,
    "a quoted value in a file that is also valid TOML: start": ABORT,
    "-conf=<a directory>: start": (
        "divid opens the directory as a stream, which reports no error, reads no line and runs without a "
        "config file (divi/src/Settings.cpp:186-205: only a stream that is not good() is taken as missing); "
        "irondivid says it cannot read the file and stops", core_reads_a_directory),
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
            self.proc = subprocess.Popen([self.binary, *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True)
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


# --- what a row looks at ----------------------------------------------------------

def relayfee(n):
    """-minrelaytxfee, a single value"""
    out = n.call("getnetworkinfo")
    return out[1].get("relayfee") if out[0] == "ok" else f"error {out[1]}"


def wallet(n):
    """-disablewallet, a boolean: getwalletinfo answers or is unavailable"""
    out = n.call("getwalletinfo")
    return "wallet" if out[0] == "ok" else f"no wallet ({out[1]})"


def added(n):
    """-addnode, a repeated option: the added nodes in order (net.cpp:1218)"""
    def listing():
        out = n.call("getaddednodeinfo", False)
        return [e.get("addednode") for e in out[1]] if out[0] == "ok" else f"error {out[1]}"
    deadline = time.time() + 10
    got = listing()
    while got == [] and time.time() < deadline:
        time.sleep(0.5)
        got = listing()
    return got


def chain(n):
    out = n.call("getblockchaininfo")
    return out[1].get("chain") if out[0] == "ok" else f"error {out[1]}"


# --- one row --------------------------------------------------------------------

case_number = 0


def case(name, body="", prefix="", extra_args=(), probes=(relayfee,), crlf=False, regtest=True,
         iron_body=None, setup=None, conf=None, without_rpc=False, check=None, datadir=True):
    """Write <prefix><base lines><body> as divi.conf in each fresh datadir (or
    as `conf`, a path under the datadir given with -conf), start both, compare
    the start, then each probe's value. setup(node) runs before the start;
    check(node) gives one more value to compare."""
    global case_number
    case_number += 1
    nodes = [Node("divid", DIVID, 0, f"case{case_number}"), Node("irondivid", IRONDIVID, 1, f"case{case_number}")]
    for n, b in zip(nodes, (body, body if iron_body is None else iron_body)):
        text = prefix + ("\n".join(n.base()) + "\n" if not without_rpc else "") + b.replace("{dir}", n.dir)
        if crlf:
            text = text.replace("\r\n", "\n").replace("\n", "\r\n")
        if setup:
            setup(n)
        if conf is None:
            n.write(text)
        elif conf is not False:
            n.write(text, conf)
    # Both start at once, each on its own ports
    for n in nodes:
        args = n.args(regtest, datadir) + [a.replace("{dir}", n.dir) for a in extra_args]
        n.launch(args + (["-server=0"] if without_rpc else []))
    outcomes = [n.wait_running() if without_rpc else n.wait_up() for n in nodes]
    c, i = outcomes
    if c[0] == "exit" and i[0] == "exit":
        same = c[1] == i[1] and c[2] == i[2]
    else:
        same = c[0] == i[0]
    row(f"{name}: start", show_start(c), show_start(i), same, (c, i))
    if c[0] == i[0] == "up":
        for probe in probes:
            a, b = probe(nodes[0]), probe(nodes[1])
            row(f"{name}: {probe.__name__}", json.dumps(a), json.dumps(b), a == b, (a, b))
    if check:
        a, b = check(nodes[0]), check(nodes[1])
        row(f"{name}: {check.__name__}", json.dumps(a), json.dumps(b), a == b, (a, b))
    for n in nodes:
        n.stop() if not without_rpc else n.terminate()
        n.stop()


# --- the rows -------------------------------------------------------------------

# A few lines of divid's format that are not TOML (a bare address), so a file
# holding them is read as divi.conf by irondivid too
NOT_TOML = "addnode=127.0.0.2:1\n"

case("default relay fee, nothing else in the file")
case("# comment lines and a # after a value",
     "# a comment\n#minrelaytxfee=0.0009\nminrelaytxfee=0.0002 # after the value\n" + NOT_TOML)
case("blank lines and spaces around the key, = and the value",
     "\n\n   minrelaytxfee   =   0.0003   \n\t\n" + NOT_TOML)
case("CRLF line ends", "minrelaytxfee=0.0004\n" + NOT_TOML, crlf=True)
case("a UTF-8 byte order mark before the first key", prefix="﻿minrelaytxfee=0.0004\n", body=NOT_TOML)
case("key= with an empty value", "disablewallet=\n" + NOT_TOML, probes=(wallet,))
case("nokey=1", "nodisablewallet=1\n" + NOT_TOML, probes=(wallet,))
case("nokey=0", "nodisablewallet=0\n" + NOT_TOML, probes=(wallet,))
case("key=0", "disablewallet=0\n" + NOT_TOML, probes=(wallet,))
case("-key=value spelled with a dash", "-minrelaytxfee=0.0005\n" + NOT_TOML,
     iron_body=("--minrelaytxfee=0.0005\n" + NOT_TOML) if INJECT == "dash" else None)
case("--key=value spelled with two dashes", "--minrelaytxfee=0.0005\n" + NOT_TOML)
case("a single-value key twice", "minrelaytxfee=0.0006\nminrelaytxfee=0.0007\n" + NOT_TOML)
case("a repeated key, and the same key on the command line",
     "addnode=127.0.0.2:11\naddnode=127.0.0.2:12\n", extra_args=("-addnode=127.0.0.2:10",), probes=(added,))
case("an unknown key", "nosuchoption=1\n" + NOT_TOML)
case("a [section] line", NOT_TOML + "[test]\nminrelaytxfee=0.0008\n")
case("a [section] line in a file that is also valid TOML", "[test]\nminrelaytxfee=0.0008\n")
case("a net.key prefix", "regtest.minrelaytxfee=0.0008\n" + NOT_TOML)
case("a quoted value", "minrelaytxfee=\"0.0002\"\n" + NOT_TOML)
case("a quoted value in a file that is also valid TOML", "minrelaytxfee=\"0.0002\"\n")
case("a value with = in it", NOT_TOML, prefix="rpcpassword=1=2\n",
     setup=lambda n: setattr(n, "password", "1=2"))
case("the same key in the file and on the command line", "minrelaytxfee=0.0002\n" + NOT_TOML,
     extra_args=("-minrelaytxfee=0.0003",))
case("-conf=<relative path>", "minrelaytxfee=0.0009\n" + NOT_TOML, conf="sub/other.conf",
     extra_args=("-conf=sub/other.conf",))


def made_in_other(n):
    """Where the node wrote its chain: the datadir the file names"""
    other = os.path.join(n.dir, "other")
    return sorted(os.listdir(other)) != [] if os.path.isdir(other) else "no folder"


case("datadir= in the file, read with -conf=<absolute path> and no -datadir",
     "datadir={dir}/other\n" + NOT_TOML, conf="file.conf", extra_args=("-conf={dir}/file.conf",), datadir=False,
     setup=lambda n: os.makedirs(os.path.join(n.dir, "other")), check=made_in_other)
case("regtest=1 in the file, not on the command line", "regtest=1\n" + NOT_TOML, regtest=False,
     probes=(chain, relayfee))
case("a very long line", "nosuchoption=" + "x" * 200000 + "\nminrelaytxfee=0.0002\n" + NOT_TOML)
case("-conf=<a directory>", conf=False, extra_args=("-conf={dir}",), without_rpc=True)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
