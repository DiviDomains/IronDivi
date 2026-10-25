#!/usr/bin/env python3
"""The RPC server of Divi Core divid and of irondivid under concurrent load,
compared case by case.

Both nodes run on one regtest chain with the same options (irondivid restored from
divid's phrase, so both wallets own the same coins). Each case is run against both
nodes and prints PASS (the same outcome as divid, and a good one), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory and in irondivid's environment; RPC passwords are made by
the run and live only in memory and in each node's divi.conf (mode 0600).
"""

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
START_TIMEOUT = 120
# A call is "answered" when its reply comes within this many seconds
ANSWER_SECS = 3

# Differences irondivid has on purpose, by row name; each is listed in README.md
# with divid's source line. A KNOWN row whose outcome starts to match divid is a
# FAIL, so the list stays true.
THREADS = ("divid serves -rpcthreads connections at a time, each to its end, keep-alive "
           "included (rpcserver.cpp:578-622, :756, :1000-1033); irondivid serves each "
           "connection on its own task and accepts -rpcthreads without using it")
CS_MAIN = ("divid runs a call its table does not mark thread-safe only while it holds cs_main, which it "
           "tries for every 50 ms (rpcserver.cpp:1072-1096): keypoolrefill (rpcserver.cpp:442) holds it while it "
           "makes the keys, so getblockcount (rpcserver.cpp:345) waits for the long call; irondivid runs calls "
           "side by side and its chain reads take no wallet or miner lock")
KNOWN = {
    "a short call while a long call runs": CS_MAIN,
    "rpcthreads=1: a short call while a long call runs": THREADS + "; and " + CS_MAIN,
    "rpcthreads=1: a call while another client holds its connection open": THREADS,
    "rpcthreads=2: a call while two clients hold their connections open": THREADS,
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, good):
    """`good`: the two outcomes are the same and as they should be"""
    global fails
    if name in KNOWN:
        word = "FAIL" if core == iron else "KNOWN"
        note = ("  [listed as KNOWN but now matches divid: update README.md]" if word == "FAIL"
                else "  [known: " + KNOWN[name] + "]")
    else:
        word, note = ("PASS" if good else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


# --- HTTP on raw sockets ---------------------------------------------------------------

def request(auth, body, headers=(), version="1.1"):
    data = json.dumps(body).encode()
    lines = [f"POST / HTTP/{version}", "Host: 127.0.0.1", f"Authorization: Basic {auth}",
             "Content-Type: application/json", f"Content-Length: {len(data)}"] + list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + data


def read_reply(sock, timeout):
    """(status, headers with lower-case names, body) or ('eof'|'timeout'|'reset', ...)"""
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                return ("eof", {}, data)
            data += chunk
        head, body = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get("content-length", "0"))
        while len(body) < n:
            chunk = sock.recv(65536)
            if not chunk:
                return ("eof", headers, body)
            body += chunk
        return (status, headers, body[:n])
    except socket.timeout:
        return ("timeout", {}, data)
    except (ConnectionResetError, BrokenPipeError):
        return ("reset", {}, data)


def state_after(sock, secs):
    """What the server does with an open connection within `secs`"""
    sock.settimeout(secs)
    try:
        return "closed" if sock.recv(1) == b"" else "data"
    except socket.timeout:
        return "open"
    except (ConnectionResetError, BrokenPipeError):
        return "reset"


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env, self.index = name, binary, env, index
        self.base_conf = list(extra_conf)
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"load{index}:{password}".encode()).decode()
        self.wrong = base64.b64encode(f"load{index}:{password}x".encode()).decode()
        self._password = password
        os.makedirs(self.dir)
        self.proc = None
        self.log = None
        self.start([])

    def write_conf(self, options):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=load{self.index}", f"rpcpassword={self._password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ] + self.base_conf + list(options)
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self, options):
        self.write_conf(options)
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.rpcport), timeout=10)

    def call(self, method, *params, timeout=60, auth=None):
        """One call on its own connection: (status, reply JSON or None)"""
        try:
            s = self.connect()
        except OSError:
            return ("refused", None)
        try:
            s.sendall(request(auth or self.auth, {"method": method, "params": list(params), "id": 1},
                              ["Connection: close"]))
            status, _, body = read_reply(s, timeout)
        except OSError:
            return ("reset", None)
        finally:
            s.close()
        try:
            return (status, json.loads(body))
        except ValueError:
            return (status, None)

    def rpc(self, method, *params, timeout=120):
        status, reply = self.call(method, *params, timeout=timeout)
        if not reply or reply.get("error"):
            raise RuntimeError(f"{self.name} {method}: {status} {reply}")
        return reply["result"]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            if self.call("getblockcount", timeout=5)[0] == 200:
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        self.call("stop", timeout=10)
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 60)


def restart(options):
    """Both nodes again with `options` added to divi.conf"""
    for n in (C, I):
        n.stop()
    for n in (C, I):
        n.start(options)
        if not n.wait_ready():
            print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s with {options}", flush=True)
            sys.exit(1)
    if not synced():
        print("FAIL   restart: irondivid did not reconnect to divid", flush=True)
        sys.exit(1)


# --- the nodes -----------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
C.rpc("setgenerate", 25)
if not synced():
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)

# The read calls each client makes, and each node's one-at-a-time replies
HASH5 = C.rpc("getblockhash", 5)
ADDR = C.rpc("getnewaddress")
MIX = [("getblockcount", []), ("getbestblockhash", []), ("getblockhash", [5]), ("getblock", [HASH5]),
       ("getblockheader", [HASH5]), ("getdifficulty", []), ("validateaddress", [ADDR]),
       ("gettxoutsetinfo", []), ("help", ["getblock"])]


def baseline(node):
    out = {}
    for method, params in MIX:
        status, reply = node.call(method, *params)
        out[(method, json.dumps(params))] = (status, reply)
    return out


# --- the cases -----------------------------------------------------------------------

def parallel(node, n, rounds=3):
    """n clients, each on one keep-alive connection, making the mix `rounds` times.
    'ok' when every reply equals the one-at-a-time reply"""
    base = baseline(node)
    problems = []
    lock = threading.Lock()

    def client(k):
        try:
            s = node.connect()
        except OSError as e:
            with lock:
                problems.append(f"refused ({e.__class__.__name__})")
            return
        try:
            for r in range(rounds):
                for method, params in MIX:
                    try:
                        s.sendall(request(node.auth, {"method": method, "params": params, "id": 1}))
                    except OSError:
                        s.close()
                        s = node.connect()
                        s.sendall(request(node.auth, {"method": method, "params": params, "id": 1}))
                    status, headers, body = read_reply(s, 60)
                    try:
                        got = (status, json.loads(body))
                    except ValueError:
                        got = (status, None)
                    if got != base[(method, json.dumps(params))]:
                        with lock:
                            problems.append(f"{method}: {got[0]}")
                    if headers.get("connection", "").lower() == "close":
                        s.close()
                        s = node.connect()
        finally:
            s.close()

    threads = [threading.Thread(target=client, args=(k,)) for k in range(n)]
    t = time.time()
    for th in threads:
        th.start()
    for th in threads:
        th.join(240)
    lost = sum(th.is_alive() for th in threads)
    after = node.call("getblockcount")[0] == 200
    if lost:
        problems.append(f"{lost} clients without all replies")
    if not after:
        problems.append("no answer afterwards")
    secs = time.time() - t
    return ("ok" if not problems else "; ".join(sorted(set(problems)))[:120]), secs


def keep_alive(node, calls=5):
    s = node.connect()
    seen = []
    for k in range(calls):
        s.sendall(request(node.auth, {"method": "getblockcount", "params": [], "id": k}))
        status, headers, _ = read_reply(s, 10)
        seen.append(f"{status}/{headers.get('connection', '-').lower()}")
    left = state_after(s, 1)
    s.close()
    return " ".join(seen) + f" then {left}"


def connection_close(node, version="1.1", headers=("Connection: close",)):
    s = node.connect()
    s.sendall(request(node.auth, {"method": "getblockcount", "params": [], "id": 1}, list(headers), version))
    status, h, _ = read_reply(s, 10)
    left = state_after(s, 2)
    s.close()
    return f"{status}/{h.get('connection', '-').lower()} then {left}"


def stalled(node):
    """A client that sent half a request and one that sent nothing; then four calls
    from others; then what the node does with the two sockets within 5 s"""
    half = node.connect()
    whole = request(node.auth, {"method": "getblockcount", "params": [], "id": 1})
    half.sendall(whole[:len(whole) // 2])
    idle = node.connect()
    answered = sum(node.call("getblockcount", timeout=ANSWER_SECS)[0] == 200 for _ in range(4))
    out = f"{answered}/4 answered; half-request socket {state_after(half, 5)}, idle socket {state_after(idle, 0.5)}"
    half.close()
    idle.close()
    return out


def burst(node, n=48):
    """n connections opened at once, each sending one call"""
    socks, results = [], []
    lock = threading.Lock()
    for _ in range(n):
        try:
            socks.append(node.connect())
        except OSError:
            results.append("refused")

    def one(s):
        try:
            s.sendall(request(node.auth, {"method": "getblockcount", "params": [], "id": 1}, ["Connection: close"]))
            status = read_reply(s, 60)[0]
        except OSError:
            status = "reset"
        with lock:
            results.append(status)
        s.close()

    threads = [threading.Thread(target=one, args=(s,)) for s in socks]
    for th in threads:
        th.start()
    for th in threads:
        th.join(120)
    tally = {}
    for r in results:
        tally[r] = tally.get(r, 0) + 1
    return ", ".join(f"{k}: {v}" for k, v in sorted(tally.items(), key=str))


def wrong_credentials(node, n=32):
    statuses = []
    lock = threading.Lock()

    def one():
        status = node.call("getblockcount", auth=node.wrong, timeout=60)[0]
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(120)
    tally = {}
    for s in statuses:
        tally[s] = tally.get(s, 0) + 1
    right = node.call("getblockcount", timeout=ANSWER_SECS * 10)[0]
    return ", ".join(f"{k}: {v}" for k, v in sorted(tally.items(), key=str)) + f"; then right credentials: {right}"


def stalled_later(node, secs=40):
    """What the node does within `secs` with a half request, and with a
    keep-alive connection left idle after a reply"""
    half = node.connect()
    whole = request(node.auth, {"method": "getblockcount", "params": [], "id": 1})
    half.sendall(whole[:len(whole) // 2])
    idle = node.connect()
    idle.sendall(whole)
    read_reply(idle, 10)
    result = {}

    def watch(name, sock):
        t = time.time()
        state = state_after(sock, secs)
        result[name] = state if state == "open" else f"{state} after {int(time.time() - t) // 5 * 5}-{int(time.time() - t) // 5 * 5 + 5} s"

    threads = [threading.Thread(target=watch, args=("half request", half)),
               threading.Thread(target=watch, args=("idle keep-alive", idle))]
    for th in threads:
        th.start()
    for th in threads:
        th.join(secs + 10)
    half.close()
    idle.close()
    return f"half request: {result.get('half request')}; idle keep-alive: {result.get('idle keep-alive')} (watched {secs} s)"


def held_connections(node, held):
    """`held` clients each make one call and keep their keep-alive connection open;
    is a call from another client answered within ANSWER_SECS?"""
    socks = []
    for _ in range(held):
        s = node.connect()
        s.sendall(request(node.auth, {"method": "getblockcount", "params": [], "id": 1}))
        read_reply(s, 10)
        socks.append(s)
    answered = node.call("getblockcount", timeout=ANSWER_SECS)[0] == 200
    for s in socks:
        s.close()
    later = node.call("getblockcount", timeout=30)[0] == 200
    return f"{'answered' if answered else 'not answered'} within {ANSWER_SECS} s; after they close: {'answered' if later else 'not answered'}"


LONG_CALL = ("keypoolrefill", 3000)
long_secs = {}
short_secs = {}


def long_and_short(node, tag):
    """A long call (keypoolrefill, keys made one by one) in flight, then
    getblockcount: does the short call come back before the long one?"""
    done = {}
    method, size = LONG_CALL
    size += len(long_secs) * 500  # a larger pool each time, so each call makes keys

    def long_call():
        t = time.time()
        node.call(method, size, timeout=300)
        done["long"] = time.time()
        long_secs[f"{tag} {node.name}"] = done["long"] - t

    th = threading.Thread(target=long_call)
    th.start()
    time.sleep(0.3)
    sent = time.time()
    node.call("getblockcount", timeout=300)
    done["short"] = time.time()
    short_secs[f"{tag} {node.name}"] = done["short"] - sent
    th.join(300)
    return "short first" if done.get("short", 1e18) < done.get("long", 0) else "short after the long call"


def stop_mid_call(node):
    """8 clients calling in a loop; stop; every client gets replies or a clean end,
    the node exits, and its exit code"""
    stop_flag = threading.Event()
    outcomes = []
    lock = threading.Lock()

    def client():
        bad = None
        while not stop_flag.is_set():
            status, _ = node.call("gettxoutsetinfo", timeout=30)
            if status == "timeout":
                bad = "hung"
                break
            if status != 200:
                break
        with lock:
            outcomes.append(bad or "clean")

    threads = [threading.Thread(target=client) for _ in range(8)]
    for th in threads:
        th.start()
    time.sleep(1)
    status, reply = node.call("stop", timeout=30)
    t = time.time()
    try:
        code = node.proc.wait(timeout=60)
        exited = f"exited {code} in {'<' if time.time() - t < 30 else '>='}30 s"
    except subprocess.TimeoutExpired:
        exited = "still running after 60 s"
        node.proc.kill()
        node.proc.wait()
    stop_flag.set()
    for th in threads:
        th.join(60)
    node.log.close()
    hung = sum(o == "hung" for o in outcomes) + sum(th.is_alive() for th in threads)
    return f"stop {status}; {exited}; clients: {8 - hung} clean, {hung} hung"


# --- default options -----------------------------------------------------------------

for n in (1, 4, 16, 64):
    c, ct = parallel(C, n)
    i, it = parallel(I, n)
    row(f"{n} parallel clients, the mix 3 times each", f"{c} ({ct:.1f} s)", f"{i} ({it:.1f} s)",
        c == i == "ok")
c, i = keep_alive(C), keep_alive(I)
row("5 calls on one HTTP/1.1 connection", c, i, c == i)
c, i = connection_close(C), connection_close(I)
row("Connection: close", c, i, c == i)
c, i = connection_close(C, "1.0", ()), connection_close(I, "1.0", ())
row("HTTP/1.0 without keep-alive", c, i, c == i)
c, i = connection_close(C, "1.0", ("Connection: keep-alive",)), connection_close(I, "1.0", ("Connection: keep-alive",))
row("HTTP/1.0 with Connection: keep-alive", c, i, c == i)
c, i = stalled(C), stalled(I)
row("a half request and an idle connection, then others' calls", c, i, c == i)
c = long_and_short(C, "default")
i = long_and_short(I, "default")
row("a short call while a long call runs", c, i, c == i)
results = {}
watchers = [threading.Thread(target=lambda n=n: results.__setitem__(n.name, stalled_later(n))) for n in (C, I)]
for th in watchers:
    th.start()
for th in watchers:
    th.join(120)
c, i = results.get("divid"), results.get("irondivid")
row("a stalled client and an idle keep-alive connection, over 40 s", c, i, c == i)
c, i = burst(C), burst(I)
row("48 connections opened at once, one call each", c, i, c == i)
c, i = wrong_credentials(C), wrong_credentials(I)
row("32 clients with wrong credentials at once, then right ones", c, i, c == i)

# --- -rpcthreads=1 and =2 ------------------------------------------------------------

restart(["rpcthreads=1"])
c, i = held_connections(C, 1), held_connections(I, 1)
row("rpcthreads=1: a call while another client holds its connection open", c, i, c == i)
c = long_and_short(C, "rpcthreads=1")
i = long_and_short(I, "rpcthreads=1")
row("rpcthreads=1: a short call while a long call runs", c, i, c == i)
restart(["rpcthreads=2"])
c, i = held_connections(C, 1), held_connections(I, 1)
row("rpcthreads=2: a call while one client holds its connection open", c, i, c == i)
c, i = held_connections(C, 2), held_connections(I, 2)
row("rpcthreads=2: a call while two clients hold their connections open", c, i, c == i)
c, ct = parallel(C, 16)
i, it = parallel(I, 16)
row("rpcthreads=2: 16 parallel clients, the mix 3 times each", f"{c} ({ct:.1f} s)", f"{i} ({it:.1f} s)",
    c == i == "ok")

# --- -rpckeepalive=0 -----------------------------------------------------------------

restart(["rpckeepalive=0"])
c, i = connection_close(C, "1.1", ()), connection_close(I, "1.1", ())
row("rpckeepalive=0: an HTTP/1.1 call", c, i, c == i)
c, i = connection_close(C, "1.1", ("Connection: keep-alive",)), connection_close(I, "1.1", ("Connection: keep-alive",))
row("rpckeepalive=0: an HTTP/1.1 call with Connection: keep-alive", c, i, c == i)
c, ct = parallel(C, 16)
i, it = parallel(I, 16)
row("rpckeepalive=0: 16 parallel clients, the mix 3 times each", f"{c} ({ct:.1f} s)", f"{i} ({it:.1f} s)",
    c == i == "ok")

# --- stop while clients are mid-call -------------------------------------------------

c = stop_mid_call(C)
i = stop_mid_call(I)
row("stop while 8 clients are mid-call", c, i, c == i and "exited 0" in c)

print("# long call (" + " ".join(map(str, LONG_CALL)) + "+) seconds: " +
      ", ".join(f"{k} {v:.1f}" for k, v in long_secs.items()) + "; short call seconds: " +
      ", ".join(f"{k} {v:.1f}" for k, v in short_secs.items()), flush=True)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
