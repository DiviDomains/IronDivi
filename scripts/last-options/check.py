#!/usr/bin/env python3
"""The last start options divid takes, Divi Core divid and irondivid compared
row by row on regtest: -dbcache, -forcednsseed with -dnsseed and -connect
(with an empty and a non-empty peers.dat), -mining, -genproclimit and
-disablesystemnotifications, on the command line and in divi.conf.

Each row starts both nodes with the same options and compares what shows from
outside: whether the node starts (or its exit and first error line), the
debug.log lines that name the option, the DNS seed lines of debug.log, and
RPC replies. Regtest has no DNS seeds, so no lookup is made. Each row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit
code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf; nothing secret goes on a command line.
"""

import base64
import hashlib
import json
import os
import random
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
DEAD = PORT_BASE + 49  # the -connect peer of some rows; nothing listens there
RPC_TIMEOUT = 60
START_TIMEOUT = 120
REGTEST_MAGIC = bytes.fromhex("a1cf7eac")
PROTOCOL = 70920

# --- rows ------------------------------------------------------------------------------

KNOWN = {}

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
    return json.dumps(v, default=str)[:240]


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
        self.user = f"opts{index}"
        self.password = secrets.token_hex(16)
        self.proc = None
        self.runs = 0
        self.dir = None

    def fresh(self, tag, template=None):
        """A data directory for a row: a copy of the template, or empty"""
        self.dir = os.path.join(WORK, f"{self.name}.{tag}")
        if template:
            shutil.copytree(template, self.dir)
        else:
            os.makedirs(self.dir)

    def write_conf(self, extra=(), connect=False):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=1",
            "daemon=0", "printtoconsole=0", "server=1", "listenonion=0", "discover=0", "staking=0",
            # divid keeps a gossiped address only of a network it can reach
            # (NetworkLocalAddressHelpers.cpp:81-104); nothing dials it
            "externalip=1.0.0.255",
        ]
        if connect:
            lines.append(f"connect={HOST}:{DEAD}")
        lines += list(extra)
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

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code, first error line)"""
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

    def log(self):
        """debug.log of this run (and what the node printed), the data directory's path as <datadir>"""
        text = ""
        for p in (os.path.join(self.net_dir(), "debug.log"), self.out, self.err):
            if os.path.exists(p):
                with open(p, errors="replace") as f:
                    text += f.read()
        return text


C = Node("divid", DIVID, 0, True)
I = Node("irondivid", IRONDIVID, 1, False)


def both(fn):
    """fn(node) for both nodes at once"""
    out = {}
    ts = [threading.Thread(target=lambda n=n: out.__setitem__(n.name, fn(n))) for n in (C, I)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out["divid"], out["irondivid"]


# --- a raw peer ---------------------------------------------------------------------------

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def message(cmd, payload=b""):
    return REGTEST_MAGIC + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def net_addr(ip, port):
    return struct.pack("<Q", 1) + b"\0" * 10 + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def raw_peer(node, src):
    """An inbound peer from `src` that has done the handshake, or None"""
    try:
        s = socket.create_connection((HOST, node.p2p), timeout=10, source_address=(src, 0))
        sub = b"/last-options:1/"
        s.sendall(message("version", struct.pack("<iQq", PROTOCOL, 1, int(time.time())) + net_addr(HOST, node.p2p)
                          + net_addr(src, 0) + struct.pack("<Q", random.getrandbits(64)) + bytes([len(sub)]) + sub
                          + struct.pack("<i", 0) + b"\x01"))
        buf, seen, deadline = b"", set(), time.time() + 10
        while not {"version", "verack"} <= seen and time.time() < deadline:
            data = s.recv(65536)
            if not data:
                return None
            buf += data
            while len(buf) >= 24 and len(buf) >= 24 + struct.unpack("<I", buf[16:20])[0]:
                n = struct.unpack("<I", buf[16:20])[0]
                cmd = buf[4:16].rstrip(b"\0").decode(errors="replace")
                buf = buf[24 + n:]
                seen.add(cmd)
                if cmd == "version":
                    s.sendall(message("verack"))
        return s if {"version", "verack"} <= seen else None
    except OSError:
        return None


# --- what a row shows ------------------------------------------------------------------------

# The DNS seed lines of divid's log (net.cpp:1023-1035, :1059, :1449, :1684)
DNS_LINES = [
    ("disabled", r"DNS seeding disabled"),
    ("skipped", r"P2P peers available\. Skipped DNS seeding\."),
    ("loading", r"Loading addresses from DNS seeds \(could take a while\)"),
    ("found", r"\d+ addresses found from DNS seeds"),
    ("-connect sets -dnsseed=0", r"parameter interaction: -connect set -> setting -dnsseed=0"),
]


def dns_lines(node):
    log = node.log()
    return [tag for tag, pattern in DNS_LINES if re.search(pattern, log)]


def naming(node, option):
    """The log lines that name -<option> (a warning that it is ignored, a bad value), as their message only"""
    out = []
    for line in node.log().splitlines():
        if re.search(rf"-{option}\b", line):
            # irondivid's lines start with a time and a level, divid's with a time
            out.append(re.sub(r"^\S+\s+(?:(?:INFO|WARN|ERROR|DEBUG)\s+\S+:\s+)?", "", line).strip())
    return out


def outcome(o):
    if o[0] == "up":
        return "up"
    return f"exit {o[1]} \"{o[2][:150]}\""


TEMPLATE = {}


def run_case(tag, args=(), conf=(), connect=False, book=None, during=None, wait=0):
    """Start both nodes with the options of a row; `during(node)` runs while it is up; the log is read after
    `wait` seconds and the node stopped. The outcome of each, and during()'s"""
    for n in (C, I):
        n.fresh(tag, TEMPLATE[n.name])
        if book:
            os.makedirs(n.net_dir(), exist_ok=True)
            shutil.copyfile(book, os.path.join(n.net_dir(), "peers.dat"))
        n.write_conf(conf, connect=connect)

    def go(n):
        o = n.start(*args)
        extra = None
        if o[0] == "up":
            start = time.time()
            if during:
                extra = during(n)
            time.sleep(max(0, wait - (time.time() - start)))
        return o, extra

    c, i = both(go)
    both(lambda n: n.stop())
    return c, i


# --- the template: a started and stopped node of each; a peers.dat with addresses -----------------

for n in (C, I):
    n.fresh("template")
    n.write_conf(connect=True)
    o = n.start()
    if o[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {o}")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
# divid learns 10 public addresses; its peers.dat is the non-empty book of the
# rows below (irondivid reads divid's layout, crates/divi-network/src/addrbook.rs)
s = raw_peer(C, "127.0.1.1")
now = int(time.time()) - 3600
gossip = [(f"{11 + k}.{3 * k}.7.9", 51476) for k in range(10)]
s.sendall(message("addr", bytes([10]) + b"".join(struct.pack("<I", now) + net_addr(ip, p) for ip, p in gossip)))
time.sleep(2)
s.close()
both(lambda n: n.stop())
BOOK = os.path.join(WORK, "peers.dat.full")
shutil.copyfile(os.path.join(C.net_dir(), "peers.dat"), BOOK)
for n in (C, I):
    for f in ("peers.dat", "debug.log"):
        p = os.path.join(n.net_dir(), f)
        if os.path.exists(p):
            os.remove(p)
    TEMPLATE[n.name] = n.dir


def option_rows(option, value, where):
    """One start with -option=value on the command line or in divi.conf: the outcome and the lines naming it"""
    tag = f"{option}-{where}-{value}".replace("/", "_")
    if where == "cli":
        c, i = run_case(tag, args=[f"-{option}={value}"])
    else:
        c, i = run_case(tag, conf=[f"{option}={value}"])
    shown = f"-{option}={value}" if where == "cli" else f"{option}={value} in divi.conf"
    compare(f"{shown}: start", ("ok", outcome(c[0])), ("ok", outcome(i[0])))
    compare(f"{shown}: log lines naming -{option}", ("ok", naming(C, option)), ("ok", naming(I, option)))


# --- -dbcache (init.cpp:1030, :1046-1056: MiB, clamped to 4..4096, never refused) -----------------
for v in ("0", "3", "4", "100", "4096", "4097", "-1", "abc"):
    option_rows("dbcache", v, "cli")
option_rows("dbcache", "50", "conf")

# --- -mining, -genproclimit, -disablesystemnotifications: listed in help only --------------------
# (LicenseAndInfo.cpp:142, :186-187, :205; no code reads them)
for option, values in (("mining", ("1",)), ("genproclimit", ("-1", "0", "4")), ("disablesystemnotifications", ("1",))):
    for v in values:
        option_rows(option, v, "cli")
    option_rows(option, values[-1], "conf")

# --- -forcednsseed with -dnsseed and -connect (net.cpp:1015-1030, :1448-1450, :1683-1685) ---------
# The DNS seed thread runs unless -dnsseed=0 (which -connect soft-sets); with a
# non-empty book and no -forcednsseed it waits 11 s and skips the seeds if two
# peers are connected by then. Regtest has no seeds: "0 addresses found".
# A non-empty book is only planted with -connect, so nothing it holds is dialled.


def two_peers(n):
    peers = [raw_peer(n, f"127.0.1.{k}") for k in (2, 3)]
    time.sleep(13)
    up = sum(p is not None for p in peers)
    for p in peers:
        if p:
            p.close()
    return up


DNS_CASE = iter(range(1, 100))


def dns_row(name, args=(), connect=False, book=None, during=None, early=False):
    c, i = run_case(f"dns{next(DNS_CASE)}", args=args, connect=connect, book=book,
                    during=during, wait=4 if early else 14)
    compare(f"{name}: start", ("ok", outcome(c[0])), ("ok", outcome(i[0])))
    if during:
        compare(f"{name}: raw peers up", ("ok", c[1]), ("ok", i[1]))
    when = "after 4 s" if early else "after 14 s"
    compare(f"{name}: DNS seed lines {when}", ("ok", dns_lines(C)), ("ok", dns_lines(I)))
    compare(f"{name}: log lines naming -forcednsseed", ("ok", naming(C, "forcednsseed")),
            ("ok", naming(I, "forcednsseed")))


dns_row("empty book")
dns_row("empty book, -dnsseed=0", args=["-dnsseed=0"])
dns_row("empty book, -forcednsseed=1", args=["-forcednsseed=1"])
dns_row("empty book, -forcednsseed=0", args=["-forcednsseed=0"])
dns_row("empty book, -dnsseed=0 -forcednsseed=1", args=["-dnsseed=0", "-forcednsseed=1"])
dns_row("empty book, -connect", connect=True)
dns_row("empty book, -connect -dnsseed=1", args=["-dnsseed=1"], connect=True)
dns_row("empty book, -connect -forcednsseed=1", args=["-forcednsseed=1"], connect=True)
dns_row("book, -connect -dnsseed=1, at 4 s", args=["-dnsseed=1"], connect=True, book=BOOK, early=True)
dns_row("book, -connect -dnsseed=1", args=["-dnsseed=1"], connect=True, book=BOOK)
dns_row("book, -connect -dnsseed=1, two peers", args=["-dnsseed=1"], connect=True, book=BOOK, during=two_peers)
dns_row("book, -connect -dnsseed=1 -forcednsseed=1, at 4 s", args=["-dnsseed=1", "-forcednsseed=1"],
        connect=True, book=BOOK, early=True)
dns_row("book, -connect -dnsseed=1 -forcednsseed=1, two peers", args=["-dnsseed=1", "-forcednsseed=1"],
        connect=True, book=BOOK, during=two_peers)
dns_row("book, -connect", connect=True, book=BOOK)
c, i = run_case("forcednsseed-conf", conf=["forcednsseed=1", "dnsseed=1"], connect=True, book=BOOK, wait=4)
compare("forcednsseed=1 dnsseed=1 in divi.conf, book, -connect: DNS seed lines after 4 s",
        ("ok", dns_lines(C)), ("ok", dns_lines(I)))

print(f"# rows: {sum(counts.values())}  PASS {counts['PASS']}  KNOWN {counts['KNOWN']}  FAIL {counts['FAIL']}",
      flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
