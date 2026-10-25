#!/usr/bin/env python3
"""-forcestart, -sysperms, -rpcthreads, -alerts and -alertnotify on Divi Core
divid and irondivid side by side on regtest, each on a chain of its own.

For each option the visible result is compared: how a node starts after a
kill -9 (plain, with -forcestart, with -reindex), the modes of the files it
makes, how many RPC connections it serves at once, what it does with a raw
peer's badly signed alert, and the -alertnotify command it runs for the
"version is obsolete" warning that blocks of a newer version raise. Each row
prints PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random and kept in each node's 0600 divi.conf. The
-alertnotify command only writes a marker file inside the node's own data
directory.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's outcome of the named
# row is changed before it is compared
INJECT = os.environ.get("START_RPC_OPTIONS_INJECT", "")
HOST = os.environ.get("START_RPC_OPTIONS_HOST", "127.0.0.2")
RPC_TIMEOUT = 60
START_TIMEOUT = 180
# The umask the nodes are started with, so "the system default" is known
UMASK = 0o022


def corruption_refused(c, i):
    """divid refuses with its block or coin database check, irondivid starts"""
    return c[0] == "exit" and "corruption detected" in c[2] and i[0] == "up"


# Differences irondivid has on purpose: (reason, shape(divid, irondivid)). A
# KNOWN row that starts to match divid is a FAIL, so the list stays true; rows
# in MAY_MATCH may also match (divid's outcome there depends on what it had
# flushed when it was killed).
KNOWN = {
    "after kill -9: plain start": (
        "divid refuses: its block index or coin database is behind its best block after the kill "
        "(BlockIndexLoading.cpp:267-285); irondivid writes each block's chain state in one batch and starts at "
        "its last whole block", corruption_refused),
    "after kill -9: -forcestart": (
        "both start; divid skips its checks and starts from what its coin database had flushed before the kill "
        "(here less than it had mined), irondivid from its last whole block, which is all of it",
        lambda c, i: c[0] == i[0] == "up" and c[1] < i[1]),
    "modes made with -sysperms (wallet on)": (
        "the same error; divid then aborts (SIGABRT, exit -6) in the shutdown after this early InitError, as "
        "scripts/start-errors records; irondivid exits 1",
        lambda c, i: isinstance(c, str) and isinstance(i, str) and c.startswith("exit -6 ")
        and i == "exit 1 " + c[len("exit -6 "):]),
    "regtest alert signed with the alert key": (
        "not sent: a valid alert needs the regtest alert key's private half (chainparams.cpp:392), which no test "
        "has", None),
}
MAY_MATCH = {"after kill -9: plain start"}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same and name in MAY_MATCH:
            word, note = "PASS", ""
        elif same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape is None or raw is None or shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


def compare(name, c, i, show=str, same=None):
    if INJECT == name:
        i = ("injected", i)
    ok = (same or (lambda a, b: a == b))(c, i)
    row(name, show(c), show(i), ok, (c, i))


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.core = binary == DIVID
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"so{index}"
        self.password = secrets.token_hex(16)
        self.dirs = 0
        self.proc = None

    def fresh(self, extra=()):
        """A new, empty data directory with this node's divi.conf"""
        self.dirs += 1
        self.dir = os.path.join(WORK, f"{self.name}-{self.dirs}")
        os.makedirs(self.dir)
        os.chmod(self.dir, 0o700)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}", "listen=1",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", f"connect={HOST}:{PORT_BASE + 49}",
        ] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        return self.dir

    def launch(self, *args):
        self.runs = getattr(self, "runs", 0) + 1
        base = os.path.join(WORK, f"{self.name}.{self.runs}")
        self.err = base + ".err"
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, stdout=o,
                                         stderr=e, stdin=subprocess.DEVNULL, start_new_session=True,
                                         preexec_fn=lambda: os.umask(UMASK))
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        return self.proc

    def outcome(self):
        """('up',) once RPC answers, ('exit', code, first error line), or
        ('running',) when it neither answers nor exits"""
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                return ("exit", code, self.error_line())
            try:
                if self.call("getblockcount", timeout=5)[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.25)
        return ("running",)

    def error_line(self):
        with open(self.err, errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        first = next((ln for ln in lines if re.search(r"(?i)error", ln)), lines[0] if lines else "")
        return first.replace(self.dir, "<datadir>")

    def call(self, method, *params, timeout=RPC_TIMEOUT):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
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
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
        return out[1]

    def stop(self, rpc=True):
        """Stop by RPC, else SIGTERM; kill after a minute"""
        if self.proc is None or self.proc.poll() is not None:
            return
        if rpc:
            try:
                self.call("stop", timeout=10)
            except Exception:
                pass
        try:
            self.proc.wait(timeout=60 if rpc else 1)
        except subprocess.TimeoutExpired:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def kill(self):
        self.proc.kill()
        self.proc.wait()

    def start_up(self, *args):
        self.launch(*args)
        out = self.outcome()
        if out[0] != "up":
            raise RuntimeError(f"{self.name} did not start ({' '.join(args)}): {show_outcome(out)}")


def show_outcome(o):
    if o[0] == "up":
        return "up" if len(o) == 1 else f"up, height {o[1]}"
    if o[0] == "running":
        return "running, no RPC"
    if o[0] == "exit":
        return f"exit {o[1]} \"{o[2][:150]}\""
    return str(o)


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


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
BOTH = (C, I)


def each(fn):
    """fn(node) on divid, then irondivid: (divid's, irondivid's)"""
    return tuple(fn(n) for n in BOTH)


# --- -forcestart: the start after an unprepared stop -------------------------------------

def killed_template(n):
    """A data directory left by a kill -9 right after 30 blocks were mined"""
    n.fresh()
    n.start_up()
    n.rpc("setgenerate", 30)
    n.kill()
    template = n.dir + ".killed"
    shutil.copytree(n.dir, template)
    return template


def start_copy(n, template, *args):
    """Start a copy of `template` with `args`: the outcome, with the height when up"""
    n.dirs += 1
    n.dir = os.path.join(WORK, f"{n.name}-{n.dirs}")
    shutil.copytree(template, n.dir)
    n.launch(*args)
    out = n.outcome()
    if out[0] == "up":
        out = ("up", n.rpc("getblockcount"))
    return out


def same_start(c, i):
    """The same outcome; when both are up, the same height"""
    return c[0] == i[0] and (c[0] != "exit" or c[1:] == i[1:]) and (c[0] != "up" or c[1] == i[1])


print(f"# divid {subprocess.run([DIVID, '-version'], capture_output=True, text=True).stdout.splitlines()[0]}",
      flush=True)
templates = each(killed_template)
for label, args in (("plain start", ()), ("-forcestart", ("-forcestart",)), ("-reindex", ("-reindex",)),
                    ("-forcestart -reindex", ("-forcestart", "-reindex"))):
    outs = []
    for n, template in zip(BOTH, templates):
        outs.append(start_copy(n, template, *args))
        n.stop()
    compare(f"after kill -9: {label}", outs[0], outs[1], show_outcome, same_start)
# After a clean stop, -forcestart changes nothing
outs = []
for n, template in zip(BOTH, templates):
    start_copy(n, template, "-reindex")
    n.stop()
    n.launch("-forcestart")
    out = n.outcome()
    outs.append(("up", n.rpc("getblockcount")) if out[0] == "up" else out)
    n.stop()
compare("after a clean stop: -forcestart", outs[0], outs[1], show_outcome, same_start)


# --- -sysperms: the modes of what a node makes ----------------------------------------------

def modes(n):
    """The modes of the files and of the directories the node made in its data
    directory (divi.conf is the script's)"""
    files, dirs = set(), set()
    for root, ds, fs in os.walk(n.dir):
        for d in ds:
            dirs.add(oct(os.stat(os.path.join(root, d)).st_mode & 0o777))
        for f in fs:
            if os.path.join(root, f) != os.path.join(n.dir, "divi.conf"):
                p = os.path.join(root, f)
                if not os.path.islink(p):
                    files.add(oct(os.stat(p).st_mode & 0o777))
    return {"files": sorted(files), "dirs": sorted(dirs)}


def made_modes(n, *args):
    n.fresh()
    n.launch(*args)
    out = n.outcome()
    if out[0] != "up":
        n.stop(rpc=False)
        return show_outcome(out)
    n.rpc("getblockcount")
    n.stop()
    return modes(n)


print(f"# nodes started with umask {UMASK:03o}", flush=True)
for label, args in (("default", ()), ("-sysperms=0", ("-sysperms=0",)), ("-disablewallet", ("-disablewallet",)),
                    ("-sysperms -disablewallet", ("-sysperms", "-disablewallet")),
                    ("-sysperms (wallet on)", ("-sysperms",))):
    c, i = each(lambda n: made_modes(n, *args))
    compare(f"modes made with {label}", c, i, lambda v: json.dumps(v))


# --- -rpcthreads: how many connections are served at once ----------------------------------

def open_held(n):
    """A keep-alive connection that has had one call answered, and is kept open"""
    s = socket.create_connection((HOST, n.rpcport), timeout=10)
    if not answer(s, n, 10):
        s.close()
        return None
    return s


def request(n):
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": "getblockcount", "params": []})
    auth = base64.b64encode(f"{n.user}:{n.password}".encode()).decode()
    return (f"POST / HTTP/1.1\r\nHost: {HOST}\r\nAuthorization: Basic {auth}\r\nContent-Type: text/plain\r\n"
            f"Connection: keep-alive\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()


def answer(s, n, secs, send=True):
    """Whether a call on `s` is answered within `secs`"""
    if send:
        s.sendall(request(n))
    s.settimeout(secs)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            part = s.recv(4096)
            if not part:
                return False
            data += part
        head, rest = data.split(b"\r\n\r\n", 1)
        size = int(re.search(rb"(?i)content-length:\s*(\d+)", head).group(1))
        while len(rest) < size:
            part = s.recv(4096)
            if not part:
                return False
            rest += part
        return b'"result"' in rest
    except (socket.timeout, OSError, AttributeError):
        return False


def threads_case(n, threads):
    """With `threads` connections held open: is one more answered, and is it
    answered once one of them closes"""
    n.fresh()
    n.launch(*([] if threads is None else [f"-rpcthreads={threads}"]))
    held = []
    if threads is not None and threads <= 0:
        # No RPC thread: the node starts, but no call is answered
        time.sleep(10)
        alive = n.proc.poll() is None
        s = socket.create_connection((HOST, n.rpcport), timeout=10)
        got = answer(s, n, 5)
        s.close()
        n.stop(rpc=False)
        return {"running": alive, "a call answered": got}
    if n.outcome()[0] != "up":
        n.stop(rpc=False)
        return {"started": False}
    want = 4 if threads is None else threads
    for _ in range(want - 1):
        held.append(open_held(n))
    s = socket.create_connection((HOST, n.rpcport), timeout=10)
    below = answer(s, n, 5)
    held.append(s)
    extra = socket.create_connection((HOST, n.rpcport), timeout=10)
    at_limit = answer(extra, n, 5)
    held[0].close()
    after_close = at_limit or answer(extra, n, 10, send=False)
    extra.close()
    for h in held[1:]:
        if h:
            h.close()
    n.stop()
    return {f"{want} held, the {want}th answered": below, f"one more answered while {want} are held": at_limit,
            "answered once one closes": after_close}


for threads in (None, 1, 2, 0, -1):
    label = "default" if threads is None else f"-rpcthreads={threads}"
    c, i = each(lambda n: threads_case(n, threads))
    compare(f"rpc connections with {label}", c, i, lambda v: json.dumps(v))


# --- a raw peer ------------------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
AGENT = b"/start-rpc-options:1/"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def varbytes(b):
    return compact(len(b)) + b


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def netaddr(port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(HOST) + struct.pack(">H", port)


def read_message(sock):
    def exactly(k):
        out = b""
        while len(out) < k:
            part = sock.recv(k - len(out))
            if not part:
                raise EOFError
            out += part
        return out
    head = exactly(24)
    size = struct.unpack("<I", head[16:20])[0]
    return head[4:16].rstrip(b"\0").decode(), exactly(size)


def peer(n):
    """A raw peer that has done the version handshake with `n`"""
    sock = socket.create_connection((HOST, n.p2p), timeout=10)
    version = (struct.pack("<iQq", 70920, 1, int(time.time())) + netaddr(n.p2p) + netaddr(0)
               + secrets.token_bytes(8) + varbytes(AGENT) + struct.pack("<i", 0) + b"\x01")
    sock.sendall(message("version", version))
    got = set()
    deadline = time.time() + 15
    while got != {"version", "verack"} and time.time() < deadline:
        command, payload = read_message(sock)
        if command == "version":
            sock.sendall(message("verack"))
        if command in ("version", "verack"):
            got.add(command)
    if got != {"version", "verack"}:
        raise RuntimeError(f"no handshake with {n.name}")
    return sock


def drain(sock, secs):
    """Answer pings for `secs` seconds; False once the node has closed the connection"""
    deadline = time.time() + secs
    while time.time() < deadline:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            command, payload = read_message(sock)
        except socket.timeout:
            break
        except (EOFError, ConnectionError):
            return False
        if command == "ping":
            sock.sendall(message("pong", payload))
    return True


# --- -alerts: a badly signed alert from a raw peer --------------------------------------------

def bad_alert():
    """An alert in effect for an hour, for every version, signed with a key that is not the alert key"""
    now = int(time.time())
    unsigned = (struct.pack("<iqqii", 1, now + 3600, now + 3600, 1000 + secrets.randbelow(1000), 0) + compact(0)
                + struct.pack("<ii", 0, 999999) + compact(0) + struct.pack("<i", 1)
                + varbytes(b"") + varbytes(b"test alert") + varbytes(b""))
    signature = bytes.fromhex("3044022000" + "11" * 31 + "022000" + "22" * 31)
    return varbytes(unsigned) + varbytes(signature)


def our_banscore(n):
    for p in n.rpc("getpeerinfo"):
        if p.get("subver") == AGENT.decode():
            return p.get("banscore")
    return "not connected"


def alert_case(n, *args):
    n.fresh()
    n.start_up(*args)
    sock = peer(n)
    drain(sock, 1)
    alert = bad_alert()
    sock.sendall(message("alert", alert))
    drain(sock, 2)
    once = our_banscore(n)
    sock.sendall(message("alert", alert))
    drain(sock, 2)
    twice = our_banscore(n)
    sock.close()
    n.stop()
    return {"banscore after one bad alert": once, "after the same alert again": twice}


for label, args in (("default", ()), ("-alerts=0", ("-alerts=0",)), ("-alerts=1", ("-alerts=1",))):
    c, i = each(lambda n: alert_case(n, *args))
    compare(f"bad alert with {label}", c, i, lambda v: json.dumps(v))
row("regtest alert signed with the alert key", "not sent", "not sent", False)


# --- -alertnotify: blocks of a newer version --------------------------------------------------

TARGET = 0x7fffff * 2 ** (8 * (0x20 - 3))


def script_num_push(h):
    """CScript() << h"""
    if h == 0:
        return b"\x00"
    if 1 <= h <= 16:
        return bytes([0x50 + h])
    raw = h.to_bytes((h.bit_length() + 8) // 8, "little")
    return bytes([len(raw)]) + raw


def pow_block(prev_hash, height, when, version):
    """A proof-of-work block on `prev_hash` (hex) of `version`, paying nothing"""
    coinbase = (struct.pack("<i", 1) + compact(1) + bytes(32) + b"\xff\xff\xff\xff"
                + varbytes(script_num_push(height) + b"\x00\x00") + b"\xff\xff\xff\xff"
                + compact(1) + struct.pack("<q", 0) + varbytes(b"\x51") + struct.pack("<I", 0))
    root = sha256d(coinbase)
    prev = bytes.fromhex(prev_hash)[::-1]
    for nonce in range(1 << 32):
        header = (struct.pack("<i", version) + prev + root + struct.pack("<III", when, 0x207fffff, nonce)
                  + bytes(32))
        h = sha256d(header)
        if int.from_bytes(h, "little") <= TARGET:
            return header + compact(1) + coinbase + compact(0), h[::-1].hex()
    raise RuntimeError("no nonce")


def notify_case(n, count, version, notify):
    """`count` blocks of `version` from a raw peer on genesis: the height, the
    node's warning, and what the -alertnotify command wrote"""
    n.fresh()
    marker = os.path.join(n.dir, "alert-marker")
    n.start_up(*([f"-alertnotify=echo %s > {marker}"] if notify else []))
    prev = n.rpc("getblockhash", 0)
    sock = peer(n)
    start = int(time.time()) - count - 60
    for k in range(count):
        block, prev = pow_block(prev, k + 1, start + k, version)
        sock.sendall(message("block", block))
    wait_for(lambda: n.rpc("getblockcount") == count, 60)
    drain(sock, 1)
    sock.close()
    if notify:
        wait_for(lambda: os.path.exists(marker), 10)
    written = open(marker, errors="replace").read() if os.path.exists(marker) else None
    out = {"height": n.rpc("getblockcount"), "getinfo errors": n.rpc("getinfo").get("errors"),
           "getmininginfo errors": n.rpc("getmininginfo").get("errors")}
    if notify:
        out["-alertnotify wrote"] = written
    n.stop()
    return out


for label, count, version, notify in (("52 blocks of version 5, -alertnotify", 52, 5, True),
                                      ("50 blocks of version 5, -alertnotify", 50, 5, True),
                                      ("52 blocks of version 4, -alertnotify", 52, 4, True),
                                      ("52 blocks of version 5, no -alertnotify", 52, 5, False)):
    c, i = each(lambda n: notify_case(n, count, version, notify))
    compare(f"{label}", c, i, lambda v: json.dumps(v))

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
