#!/usr/bin/env python3
"""The RPC HTTP layer of Divi Core divid and irondivid, compared reply by reply.

The same raw HTTP request is sent to both nodes over a socket of its own: no
credentials or wrong ones, other HTTP methods and paths, empty, malformed and
oversized bodies, batches, request objects with odd id/method/params/jsonrpc,
RPC errors, keep-alive, and a client -rpcallowip refuses. Each row compares the
status line, the headers that matter (Content-Type, WWW-Authenticate,
Connection) and the body, and prints PASS (same as divid), KNOWN (a difference
listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. RPC
passwords are made at random for each run and kept in each node's 0600
divi.conf; the Authorization header is built in memory and never printed.
"""

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# gets a changed body before it is compared
INJECT = os.environ.get("HTTP_REPLIES_INJECT", "")
# Loopback address the nodes bind to (127.0.0.2 keeps clear of other programs'
# clients on 127.0.0.1 when the ports are inside the host's ephemeral range)
HOST = os.environ.get("HTTP_REPLIES_HOST", "127.0.0.1")
# A local address outside 127.0.0.0/8, for the -rpcallowip refusal rows
# (detected when not given; the rows are left out when there is none)
OUTSIDE = os.environ.get("HTTP_REPLIES_OUTSIDE_IP", "")
START_TIMEOUT = 120
READ_TIMEOUT = 20
# divid reads at most MAX_SIZE bytes of body (serialize.h:34, rpcprotocol.cpp:218-220)
MAX_SIZE = 0x02000000

# Differences irondivid has on purpose, one per row name. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
# Each entry: the reason, and irondivid's reply as the row expects it (the
# compared parts of it): a KNOWN row whose irondivid reply is anything else
# is a FAIL too.
NOT_ALLOWED = {"status": "405 Method Not Allowed", "content-type": "text/plain",
               "www-authenticate": "(none)", "connection": "close", "body": ("text", "Method Not Allowed")}
KNOWN = {
    "401 replies: Connection header": (
        "divid writes its 401 as an HTTP/1.0 reply with no Connection header and closes the connection "
        "(rpcprotocol.cpp:85-108); irondivid's HTTP server closes a connection only after a reply that says "
        "Connection: close, so it says it. Both close (the 'closed after' rows).",
        {"connection": "close"}),
    "PUT": (
        "divid closes the connection without a reply to a method other than GET or POST "
        "(rpcprotocol.cpp:150-152); irondivid's HTTP server answers every request: 405, then closes",
        NOT_ALLOWED),
    "HEAD": ("as for PUT", dict(NOT_ALLOWED, body=("text", ""))),
    "PUT without credentials": ("as for PUT", NOT_ALLOWED),
    "path /wallet/w1": (
        "irondivid serves JSON-RPC on /wallet/<name> too (irondivi-cli -rpcwallet, bin/irondivi-cli/src/main.rs); "
        "divid serves / only (rpcserver.cpp:1019-1031)",
        {"status": "200 OK", "content-type": "application/json", "www-authenticate": "(none)",
         "connection": "close", "body": ("json", {"result": 0, "error": None, "id": 1})}),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, iron_view=None):
    global fails
    known = KNOWN.get(name)
    if known:
        reason, expected = known
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif iron_view is not None and iron_view != expected:
            word, note = "FAIL", f"  [differs from the KNOWN reply {expected}]"
        else:
            word, note = "KNOWN", "  [known: " + reason + "]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"replies{index}"
        self.password = secrets.token_hex(16)
        self.host = HOST
        os.makedirs(self.dir)
        self.proc = None
        self.log = None

    def auth(self, user=None, password=None):
        u = self.user if user is None else user
        p = self.password if password is None else password
        return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()

    def start(self, extra_conf=None, host=None):
        self.host = host or HOST
        # divid takes -rpcbind only with an -rpcallowip (rpcserver.cpp:685-690);
        # 127.0.0.1 is allowed anyway (rpcserver.cpp:634)
        extra_conf = ["rpcallowip=127.0.0.1"] if extra_conf is None else extra_conf
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={self.host}", "daemon=0", "printtoconsole=0", "server=1", "discover=0",
            "listenonion=0", "listen=0", f"bind={HOST}", "dnsseed=0", "staking=0",
            f"connect={HOST}:{PORT_BASE + 49}",
        ] + list(extra_conf)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                r = exchange(self, [post(self, rpc_body("getblockcount"))])[0]
                if r and r["status"] == 200:
                    return True
            except OSError:
                pass
            time.sleep(0.5)
        return False

    def stop(self):
        try:
            exchange(self, [post(self, rpc_body("stop"))])
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # The stop call was refused (a client -rpcallowip refuses): SIGTERM
            self.proc.terminate()
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- raw HTTP -------------------------------------------------------------------

def rpc_body(method, params=(), **extra):
    obj = {"method": method, "params": list(params), "id": 1}
    obj.update(extra)
    return json.dumps(obj)


def request(node, method="POST", path="/", body="", auth=True, version="HTTP/1.1",
            headers=None, content_length=None):
    """The bytes of one HTTP request; auth True is the node's own credentials,
    a string is sent as the Authorization header, None sends none"""
    if isinstance(body, str):
        body = body.encode()
    lines = [f"{method} {path} {version}", f"Host: {node.host}"]
    h = {"Content-Type": "application/json"}
    if auth is True:
        h["Authorization"] = node.auth()
    elif isinstance(auth, str):
        h["Authorization"] = auth
    h.update(headers or {})
    h["Content-Length"] = str(len(body) if content_length is None else content_length)
    lines += [f"{k}: {v}" for k, v in h.items() if v is not None]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def post(node, body, **kw):
    return request(node, body=body, **kw)


class Reader:
    def __init__(self, sock):
        self.sock, self.buf, self.eof = sock, b"", False

    def fill(self):
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            data = b""
            self.eof = True
        except OSError:
            data = b""
        if not data:
            self.eof = True
        self.buf += data
        return bool(data)

    def response(self):
        """One response, or None if the connection closed (or went quiet) first"""
        while b"\r\n\r\n" not in self.buf:
            if self.eof or not self.fill():
                return None
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ", 2)
        version, status = parts[0], int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        if "content-length" in headers:
            n = int(headers["content-length"])
            while len(self.buf) < n and not self.eof:
                self.fill()
            body, self.buf = self.buf[:n], self.buf[n:]
        else:
            while not self.eof:
                self.fill()
            body, self.buf = self.buf, b""
        return {"version": version, "status": status, "reason": reason, "headers": headers,
                "body": body.decode("utf-8", "replace")}

    def closed(self):
        """True when the server closes the connection within a moment"""
        self.sock.settimeout(2)
        try:
            data = self.sock.recv(1)
        except socket.timeout:
            return False
        except OSError:
            return True
        if data:
            self.buf += data
            return False
        return True


def exchange(node, requests, source=None, gap=0.0):
    """Send the requests one after the other on one connection; the responses
    (None where none came) and whether the server closed the connection after"""
    sock = socket.create_connection((node.host, node.rpcport), timeout=READ_TIMEOUT,
                                    source_address=(source, 0) if source else None)
    reader = Reader(sock)
    out = []
    try:
        for req in requests:
            try:
                sock.sendall(req)
            except OSError:
                out.append(None)
                continue
            r = reader.response()
            out.append(r)
            time.sleep(gap)
        out.append(reader.closed())
    finally:
        sock.close()
    return out


# --- how replies are compared ------------------------------------------------------

def help_first_line(v):
    """divid answers a call it cannot run with its help text as a -1 error: such
    messages are compared by their first line (the other replies scripts compare
    the help texts themselves)"""
    if isinstance(v, list):
        return [help_first_line(x) for x in v]
    if isinstance(v, dict):
        e = v.get("error")
        if isinstance(e, dict) and e.get("code") == -1 and "\n" in str(e.get("message", "")).strip():
            v = dict(v, error=dict(e, message=e["message"].strip().split("\n")[0]))
    return v


def body_view(r):
    """The body as JSON when it is JSON, else as text"""
    try:
        return ("json", help_first_line(json.loads(r["body"])))
    except ValueError:
        return ("text", r["body"].strip())


def view(r, parts):
    if r is None:
        return {"reply": "none (connection closed)"}
    v = {}
    if "status" in parts:
        v["status"] = f"{r['status']} {r['reason']}"
    if "version" in parts:
        v["version"] = r["version"]
    for h in ("content-type", "www-authenticate", "connection"):
        if h in parts:
            v[h] = r["headers"].get(h, "(none)")
    if "body" in parts:
        v["body"] = body_view(r)
    return v


def first_difference(a, b, path="$"):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if a != b or type(a) is not type(b):
        return f"{path}: {json.dumps(a)[:80]} vs {json.dumps(b)[:80]}"
    return None


def short(v):
    if "reply" in v:
        return v["reply"]
    s = v.get("status", "")
    if "body" in v:
        kind, b = v["body"]
        b = json.dumps(b)[:90] if kind == "json" else repr(b[:60])
        s += f" {b}"
    return s


PARTS = ("status", "content-type", "www-authenticate", "connection", "body")


def compare(name, core, iron, parts=PARTS):
    """core/iron: one response each (or None)"""
    if INJECT and INJECT == name and iron is not None:
        iron = dict(iron, body=iron["body"] + "injected")
    a, b = view(core, parts), view(iron, parts)
    d = first_difference(a, b)
    row(name, short(a), d or short(b), d is None, b)


def both(name, make, parts=PARTS, source=None):
    """One request (built per node by `make`) on a connection of its own"""
    c = exchange(C, [make(C)], source)[0]
    i = exchange(I, [make(I)], source)[0]
    compare(name, c, i, parts)
    return c, i


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
for n in (C, I):
    n.start()
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)

close = {"Connection": "close"}
good = rpc_body("getblockcount")

# Credentials (rpcserver.cpp:936-956, rpcprotocol.cpp:85-108). The Connection
# header of the 401 is compared once, on a row of its own
NO_CONN = tuple(p for p in PARTS if p != "connection")
c401, i401 = both("no Authorization header", lambda n: post(n, good, auth=None, headers=close), NO_CONN)
both("wrong user", lambda n: post(n, good, auth=n.auth(user="nobody"), headers=close), NO_CONN)
both("wrong password", lambda n: post(n, good, auth=n.auth(password="wrong"), headers=close), NO_CONN)
both("not Basic", lambda n: post(n, good, auth="Bearer abc", headers=close), NO_CONN)
both("lowercase basic", lambda n: post(n, good, auth=n.auth().replace("Basic ", "basic "), headers=close), NO_CONN)
both("Basic with no credentials", lambda n: post(n, good, auth="Basic ", headers=close), NO_CONN)
compare("401 replies: Connection header", c401, i401, ("connection",))


def delay(node, auth):
    t = time.time()
    exchange(node, [post(node, good, auth=auth, headers=close)])
    return time.time() - t


# divid sleeps 250 ms before it refuses a wrong password (rpcserver.cpp:948-952)
for name, make in (("wrong password: delay before the reply", lambda n: n.auth(password="wrong")),
                   ("no Authorization header: no delay", lambda n: None)):
    c, i = delay(C, make(C)), delay(I, make(I))
    sort = lambda s: ">=0.2s" if s >= 0.2 else "<0.2s"
    row(name, f"{sort(c)} ({c * 1000:.0f}ms)", f"{sort(i)} ({i * 1000:.0f}ms)", sort(c) == sort(i))

# HTTP methods and paths (rpcprotocol.cpp:138-160, rpcserver.cpp:1000-1033)
both("GET with a request body", lambda n: request(n, "GET", body=good, headers=close))
both("PUT", lambda n: request(n, "PUT", body=good, headers=close))
both("HEAD", lambda n: request(n, "HEAD", body="", headers=close))
both("path /x", lambda n: post(n, good, path="/x", headers=close))
both("path /x without credentials", lambda n: post(n, good, path="/x", auth=None, headers=close))
both("PUT without credentials", lambda n: request(n, "PUT", body=good, auth=None, headers=close))
both("path /wallet/w1", lambda n: post(n, good, path="/wallet/w1", headers=close))
both("path with a query /?a=1", lambda n: post(n, good, path="/?a=1", headers=close))
both("no Content-Type", lambda n: post(n, good, headers=dict(close, **{"Content-Type": None})))
both("Content-Type text/plain", lambda n: post(n, good, headers=dict(close, **{"Content-Type": "text/plain"})))

# Bodies (rpcserver.cpp:958-997)
both("empty body", lambda n: post(n, "", headers=close))
both("invalid JSON", lambda n: post(n, "{bad", headers=close))
both("JSON with trailing text", lambda n: post(n, good + "x", headers=close))
both("a number", lambda n: post(n, "5", headers=close))
both("a string", lambda n: post(n, '"getblockcount"', headers=close))
both("null", lambda n: post(n, "null", headers=close))

# Batches (rpcserver.cpp:924-933)
both("batch of two", lambda n: post(n, json.dumps([{"method": "getblockcount", "id": 1},
                                                    {"method": "getbestblockhash", "id": "b"}]), headers=close))
both("empty batch", lambda n: post(n, "[]", headers=close))
both("batch with bad members", lambda n: post(n, json.dumps([{"method": "getblockcount", "id": 1}, 5,
                                                             {"id": 3}, {"method": 7, "id": 4},
                                                             {"method": "nosuchmethod", "id": 5},
                                                             {"method": "getblockhash", "params": [99], "id": 6}]),
                                              headers=close))
both("nested batch", lambda n: post(n, "[[]]", headers=close))

# The request object (rpcserver.cpp:874-904)
for name, body in (
    ("id missing", json.dumps({"method": "getblockcount", "params": []})),
    ("id null", json.dumps({"method": "getblockcount", "params": [], "id": None})),
    ("id string", json.dumps({"method": "getblockcount", "params": [], "id": "abc"})),
    ("id number 1.5", '{"method":"getblockcount","params":[],"id":1.5}'),
    ("id object", json.dumps({"method": "getblockcount", "params": [], "id": {"a": [1]}})),
    ("method missing", json.dumps({"params": [], "id": 1})),
    ("method null", json.dumps({"method": None, "id": 1})),
    ("method a number", json.dumps({"method": 5, "id": 1})),
    ("params missing", json.dumps({"method": "getblockcount", "id": 1})),
    ("params null", json.dumps({"method": "getblockcount", "params": None, "id": 1})),
    ("params an object", json.dumps({"method": "getblockcount", "params": {"a": 1}, "id": 1})),
    ("params a string", json.dumps({"method": "getblockcount", "params": "x", "id": 1})),
    ("jsonrpc 1.0", json.dumps({"jsonrpc": "1.0", "method": "getblockcount", "params": [], "id": 1})),
    ("jsonrpc 2.0", json.dumps({"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1})),
    ("jsonrpc absent", json.dumps({"method": "getblockcount", "params": [], "id": 1})),
    ("duplicate keys, the last wins?", '{"method":"nosuchmethod","method":"getblockcount","id":1}'),
):
    both(name, lambda n, b=body: post(n, b, headers=close))

# RPC errors and their HTTP status (rpcserver.cpp:500-511)
for name, body in (
    ("unknown method (-32601)", rpc_body("nosuchmethod")),
    ("RPC error -8", rpc_body("getblockhash", [99])),
    ("RPC error -1 (help)", rpc_body("getblockcount", ["x"])),
    ("RPC error -3", rpc_body("getblockhash", ["x"])),
    ("RPC error -5", rpc_body("getblock", ["00" * 32])),
):
    both(name, lambda n, b=body: post(n, b, headers=close))

# Keep-alive (rpcprotocol.cpp:239-245, rpcserver.cpp:1014-1017): HTTP/1.1 keeps the
# connection, HTTP/1.0 and "Connection: close" close it; an error reply closes it


def on_one_connection(name, reqs, parts=("status", "connection", "body")):
    c, i = exchange(C, [r(C) for r in reqs]), exchange(I, [r(I) for r in reqs])
    for k in range(len(reqs)):
        compare(f"{name}: reply {k + 1}", c[k], i[k], parts)
    row(f"{name}: closed after", c[-1], i[-1], c[-1] == i[-1])


on_one_connection("keep-alive, two requests", [lambda n: post(n, good), lambda n: post(n, good)])
on_one_connection("HTTP/1.0, two requests", [lambda n: post(n, good, version="HTTP/1.0"),
                                              lambda n: post(n, good, version="HTTP/1.0")])
on_one_connection("Connection: close, then a second request", [lambda n: post(n, good, headers=close),
                                                               lambda n: post(n, good)])
on_one_connection("an RPC error, then a second request", [lambda n: post(n, rpc_body("getblockhash", [99])),
                                                          lambda n: post(n, good)])
on_one_connection("wrong password, then a second request", [lambda n: post(n, good, auth=n.auth(password="w")),
                                                            lambda n: post(n, good)], ("status", "body"))
on_one_connection("HTTP/1.0 with keep-alive", [lambda n: post(n, good, version="HTTP/1.0",
                                                             headers={"Connection": "keep-alive"}),
                                                lambda n: post(n, good)])

# Body size: divid takes up to MAX_SIZE (32 MiB) and reads no body above it
big = " " * (3 * 1024 * 1024) + good
both("3 MiB body (whitespace, then a request)", lambda n: post(n, big, headers=close))
big_batch = json.dumps([{"method": "getblockcount", "id": k} for k in range(60000)])
both(f"batch of 60000 requests ({len(big_batch) // 1024} KiB)", lambda n: post(n, big_batch, headers=close))
both("Content-Length above 32 MiB, no body sent", lambda n: post(n, "", content_length=MAX_SIZE + 1,
                                                                   headers=close))

# A client on another loopback address is allowed (rpcserver.cpp:634-635)
if HOST.startswith("127."):
    other = "127.0.0.3" if HOST == "127.0.0.2" else "127.0.0.2"
    both(f"client on {other}", lambda n: post(n, good, headers=close), source=other)

# -rpcallowip refuses a client outside the allowed subnets (rpcserver.cpp:612-616)
if not OUTSIDE:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 9))
        OUTSIDE = probe.getsockname()[0]
        probe.close()
    except OSError:
        OUTSIDE = ""
if OUTSIDE and not OUTSIDE.startswith("127."):
    for n in (C, I):
        n.stop()
    # Only 192.0.2.1 (TEST-NET) besides the loopback is allowed; both listen on OUTSIDE
    for n in (C, I):
        n.start(["rpcallowip=192.0.2.1"], host=OUTSIDE)
    deadline = time.time() + START_TIMEOUT
    while time.time() < deadline:
        try:
            if all(exchange(n, [post(n, good, headers=close)], OUTSIDE)[0] is not None for n in (C, I)):
                break
        except OSError:
            pass
        time.sleep(0.5)
    both(f"client on {OUTSIDE}, not in -rpcallowip", lambda n: post(n, good, headers=close), source=OUTSIDE)
    both(f"client on {OUTSIDE}, not in -rpcallowip, no credentials",
         lambda n: post(n, good, auth=None, headers=close), source=OUTSIDE)
else:
    print("# no local address outside 127.0.0.0/8: -rpcallowip refusal rows left out", flush=True)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
