#!/usr/bin/env python3
"""Proxy, onion, Tor control, -dns and -upnp options on Divi Core divid and on
irondivid, case by case: whether each node starts (exit code and first error
line), getnetworkinfo's networks and localaddresses, and what local stand-ins
saw. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Every node and stand-in binds to 127.0.0.1; nothing leaves the host. The
stand-ins, made here, one set per node:
- a SOCKS5 proxy (and a second one for -onion): logs the methods offered, the
  credentials' shape and the CONNECT target, then refuses the connection;
- a fake Tor control port: answers PROTOCOLINFO, AUTHENTICATE, AUTHCHALLENGE
  and ADD_ONION as Tor does and logs the commands, secrets masked;
- a plain TCP listener the -dns cases name by host name, logging accepts.

No -upnp=1 case is started: this divid is built with miniupnpc, and its port
mapping would send SSDP to the LAN (README.md). The -torpassword is made
at random by the run and kept only in the node's 0600 divi.conf in the work
directory, never on a command line. RPC
passwords are random per run, in the same 0600 divi.conf files.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import hmac
import json
import os
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("PROXY_TOR_INJECT", "")
# Run only the cases whose name holds this text (for a rerun of one case)
ONLY = os.environ.get("PROXY_TOR_ONLY", "")
HOST = "127.0.0.1"
RPC_TIMEOUT = 30
# divid took over 60 s to answer RPC once in a full run on a loaded host
START_TIMEOUT = 180
# How long a started node is left to dial its proxy, Tor control port or
# added node before it is looked at
SETTLE = 5
SERVICE_ID = "abcdefghij234567"  # a well-formed v2 onion service id, no one's
PRIVATE_KEY = "RSA1024:" + base64.b64encode(b"not a key, a stand-in's reply").decode()
SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"

# Rows divid's own build keeps from being run here, or differences listed in
# README.md with divid's source line. A KNOWN row that starts to match divid is
# a FAIL, so the list stays true.
UPNP = ("not started on either node: this divid is built with miniupnpc (USE_UPNP set, -help says 'default: 0'), "
        "so -upnp=1 would send SSDP to the LAN. From the source, divid maps the listening port in a thread "
        "(MapPort, net.cpp:1454, :989-1007; ThreadMapPort :908-985) and, with -discover, adds the IGD's external "
        "address as a local address")
ABORT = ("same error; divid then aborts (SIGABRT, exit -6) in the shutdown after this early InitError, irondivid "
         "exits 1 (as scripts/start-errors lists)")
KNOWN = {
    **{f"{case} (divid aborts after the error)": ABORT
       for case in ("-proxy=localhost:<socks> -dns=0", "-proxy=notahost.invalid", "-proxy=127.0.0.1:99999",
                    "-onion=notahost.invalid", "-onion=localhost:<onion socks> -dns=0",
                    "-externalip=localhost -dns=0")},
    "-upnp=1: not started": UPNP,
    "-upnp=1 -proxy=<socks> (the proxy turns it off unless set): not started":
        UPNP + "; -proxy soft-sets -upnp=0 only when -upnp is not given (net.cpp:1690-1700), so an explicit "
        "-upnp=1 still maps",
}

fails = 0


def row(name, core, iron, same):
    global fails
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    line = f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"
    print(line.replace("\n", "\\n")[:400], flush=True)


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None"""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return f"{path}.{k} only on {'irondivid' if k in b else 'divid'}"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path}: {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    return None if a == b else f"{path}: {json.dumps(a)[:80]} vs {json.dumps(b)[:80]}"


def port_free(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((HOST, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


# --- stand-ins ------------------------------------------------------------------------

class Listener:
    """A TCP server on 127.0.0.1:port running `serve(conn, log)` per connection"""

    def __init__(self, port, serve):
        self.port, self.serve, self.log, self.conns = port, serve, [], []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        deadline = time.time() + 10
        while True:
            try:
                self.sock.bind((HOST, port))
                break
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.2)
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.stopped = False
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stopped:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns.append(conn)
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        conn.settimeout(10)
        try:
            self.serve(conn, self.log)
        except (OSError, ValueError, IndexError):
            pass
        finally:
            conn.close()

    def close(self):
        self.stopped = True
        self.thread.join()
        self.sock.close()
        for conn in self.conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()


def recv_exact(conn, n):
    b = b""
    while len(b) < n:
        part = conn.recv(n - len(b))
        if not part:
            raise OSError("closed")
        b += part
    return b


def socks5(conn, log):
    """RFC 1928/1929: log the methods offered, the credentials' shape, the
    CONNECT target, then answer 'connection refused'"""
    ver, n = recv_exact(conn, 2)
    methods = sorted(recv_exact(conn, n))
    entry = {"methods": methods}
    if 2 in methods:
        conn.sendall(bytes([5, 2]))
        ver, ulen = recv_exact(conn, 2)
        user = recv_exact(conn, ulen).decode(errors="replace")
        plen = recv_exact(conn, 1)[0]
        password = recv_exact(conn, plen).decode(errors="replace")
        # Core writes two rand32() values with %i, so either may be negative
        number = lambda t: t.lstrip("-").isdigit()
        entry["credentials"] = "two decimal numbers" if number(user) and number(password) else "other"
        conn.sendall(bytes([1, 0]))
    else:
        conn.sendall(bytes([5, 0]))
    ver, cmd, _, atyp = recv_exact(conn, 4)
    if atyp == 1:
        dest = socket.inet_ntoa(recv_exact(conn, 4))
    elif atyp == 4:
        dest = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
    else:
        dest = recv_exact(conn, recv_exact(conn, 1)[0]).decode(errors="replace")
    port = struct.unpack(">H", recv_exact(conn, 2))[0]
    entry["connect"] = [{1: "ipv4", 3: "domain", 4: "ipv6"}.get(atyp, atyp), dest, port]
    log.append(entry)
    conn.sendall(bytes([5, 5, 0, 1]) + bytes(6))


def accept_only(conn, log):
    log.append("connection")


class TorControl:
    """A fake Tor control port offering `methods`; logs each command, the
    AUTHENTICATE argument masked as what it matched"""

    def __init__(self, port, methods, password=None, cookie_file=None):
        self.methods, self.password, self.cookie_file = methods, password, cookie_file
        self.cookie = secrets.token_bytes(32)
        if cookie_file:
            with open(cookie_file, "wb") as f:
                f.write(self.cookie)
        self.server = Listener(port, self.serve)
        self.log = self.server.log

    def serve(self, conn, log):
        log.append("connected")
        buf = b""
        client_nonce = server_nonce = None
        while True:
            while b"\r\n" not in buf:
                part = conn.recv(4096)
                if not part:
                    return
                buf += part
            line, buf = buf.split(b"\r\n", 1)
            line = line.decode(errors="replace")
            word = line.split(" ", 1)[0]
            arg = line[len(word) + 1:]
            if word == "PROTOCOLINFO":
                log.append(line)
                cookie = f' COOKIEFILE="{self.cookie_file}"' if self.cookie_file else ""
                conn.sendall(f"250-PROTOCOLINFO 1\r\n250-AUTH METHODS={self.methods}{cookie}\r\n"
                             f"250-VERSION Tor=\"0.4.8.0\"\r\n250 OK\r\n".encode())
            elif word == "AUTHCHALLENGE":
                log.append("AUTHCHALLENGE SAFECOOKIE <client nonce>")
                client_nonce = bytes.fromhex(arg.split(" ")[1])
                server_nonce = secrets.token_bytes(32)
                server_hash = hmac.new(SERVER_KEY, self.cookie + client_nonce + server_nonce, hashlib.sha256)
                conn.sendall(f"250 AUTHCHALLENGE SERVERHASH={server_hash.hexdigest()} "
                             f"SERVERNONCE={server_nonce.hex()}\r\n".encode())
            elif word == "AUTHENTICATE":
                if not arg:
                    shown = "AUTHENTICATE"
                elif self.password is not None and arg == f'"{self.password}"':
                    shown = "AUTHENTICATE <the configured password>"
                elif client_nonce is not None and arg.lower() == hmac.new(
                        CLIENT_KEY, self.cookie + client_nonce + server_nonce, hashlib.sha256).hexdigest():
                    shown = "AUTHENTICATE <the SAFECOOKIE response>"
                else:
                    shown = "AUTHENTICATE <something else>"
                log.append(shown)
                ok = shown != "AUTHENTICATE <something else>"
                conn.sendall(b"250 OK\r\n" if ok else b"515 Authentication failed\r\n")
            elif word == "ADD_ONION":
                key, rest = (arg.split(" ", 1) + [""])[:2]
                log.append(f"ADD_ONION {'NEW:RSA1024' if key == 'NEW:RSA1024' else ('<the saved key>' if key == PRIVATE_KEY else '<other key>')} {rest}")
                conn.sendall(f"250-ServiceID={SERVICE_ID}\r\n250-PrivateKey={PRIVATE_KEY}\r\n250 OK\r\n".encode())
            else:
                log.append(word)
                conn.sendall(b"510 Unrecognized command\r\n")

    def close(self):
        self.server.close()


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary, self.index = name, binary, index
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        # stand-in ports of this node
        self.socks, self.onion, self.torctl, self.target = (PORT_BASE + 10 + index, PORT_BASE + 12 + index,
                                                            PORT_BASE + 14 + index, PORT_BASE + 16 + index)
        self.user = f"proxytor{index}"
        self.password = secrets.token_hex(16)
        # a throwaway -torpassword, made here; it goes only into this node's
        # 0600 divi.conf
        self.tor_password = secrets.token_urlsafe(18)
        self.runs = 0

    def fresh(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)

    def write_conf(self, extra):
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
                 f"rpcpassword={self.password}", "daemon=0", "printtoconsole=0", "server=1", "dnsseed=0",
                 "staking=0", "discover=0", f"bind={HOST}", f"rpcbind={HOST}", f"rpcallowip={HOST}",
                 "listenonion=0"]
        keys = {e.split("=", 1)[0] for e in extra}
        lines = [ln for ln in lines if ln.split("=", 1)[0] not in keys] + list(extra)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self, args):
        self.runs += 1
        base = os.path.join(WORK, f"{self.name}.{self.runs}")
        self.err = base + ".err"
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"] + list(args), cwd=WORK, stdout=o,
                                         stderr=e, stdin=subprocess.DEVNULL, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                return ("exit", code, self.error_line())
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.25)
        return ("running, no RPC",)

    def error_line(self):
        with open(self.err, errors="replace") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        return next((ln for ln in lines if ln.startswith(("Error", "error"))), lines[0] if lines else "")

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
        return ("err", err.get("code"), err.get("message", "")) if err else ("ok", reply.get("result"))

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.call("stop")
            except Exception:
                pass
            try:
                self.proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def named(self, v):
        """Replace this node's own ports with their roles, so replies compare"""
        roles = {self.socks: "<socks>", self.onion: "<onion socks>", self.torctl: "<tor control>",
                 self.target: "<target>", self.p2p: "<p2p>", self.rpcport: "<rpc>"}
        if isinstance(v, dict):
            return {k: self.named(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.named(x) for x in v]
        if isinstance(v, int) and not isinstance(v, bool) and v in roles:
            return roles[v]
        if isinstance(v, str):
            for port, role in roles.items():
                v = v.replace(str(port), role)
        return v


C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)


def outcome_text(o):
    return o[0] if o[0] != "exit" else f"exit {o[1]} \"{o[2][:150]}\""


def case(name, extra=(), args=(), tor=None, restart=False, socks=False, onion=False, target=False):
    """Start both nodes with the case's divi.conf lines `extra` (each node's own
    ports put in for {socks} {onion} {torctl} {target}) and command-line
    `args`; compare the start, getnetworkinfo's networks and localaddresses and
    each stand-in's log. tor: (methods, password, cookie) of the fake control
    port; restart: start again on the same datadir (the case before left it)"""
    if ONLY and ONLY not in name:
        return
    results = {}

    def one(n):
        fill = lambda s: s.format(socks=n.socks, onion=n.onion, torctl=n.torctl, target=n.target)
        stand = {}
        if socks:
            stand["socks"] = Listener(n.socks, socks5)
        if onion:
            stand["onion socks"] = Listener(n.onion, socks5)
        if target:
            stand["target"] = Listener(n.target, accept_only)
        if tor:
            methods, password, cookie = tor[:3]
            stand["tor control"] = TorControl(n.torctl, methods, password(n) if callable(password) else password,
                                              os.path.join(WORK, f"{n.name}.cookie") if cookie else None)
        try:
            if not restart:
                n.fresh()
            n.write_conf([fill(e) for e in extra] + (tor[3](n) if tor and len(tor) > 3 else []))
            # an error line names the node's own stand-in port: its role instead
            o = tuple(n.named(list(n.start([fill(a) for a in args]))))
            info = None
            if o[0] == "up":
                # time to dial a stand-in; a case with none only needs the start
                time.sleep(SETTLE if stand else 1)
                ni = n.call("getnetworkinfo")
                info = n.named({"networks": ni[1]["networks"], "localaddresses": ni[1]["localaddresses"]}) \
                    if ni[0] == "ok" else ni
            n.stop()
            logs = {k: n.named(v.log) for k, v in stand.items()}
        finally:
            for v in stand.values():
                v.close()
        results[n] = (o, info, logs)

    started = time.time()
    threads = [threading.Thread(target=one, args=(n,)) for n in (C, I)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if len(results) != 2:
        row(f"{name}: the case ran", "-", "-", False)
        return
    print(f"#      {name}: {time.time() - started:.0f} s", flush=True)
    (oc, ic, lc), (oi, ii, li) = results[C], results[I]
    if INJECT == name:
        ii = {"injected": True}
    same_start = oc[0] == oi[0] and (oc[0] != "exit" or oc[1:] == oi[1:])
    if oc[0] == oi[0] == "exit" and oc[1] == -6 and oi[1] == 1 and oc[2] == oi[2]:
        # divid aborts (SIGABRT) in the shutdown after an early InitError, as
        # scripts/start-errors lists; the error is the same
        row(f"{name} (divid aborts after the error)", outcome_text(oc), outcome_text(oi), False)
        return
    row(name, outcome_text(oc), outcome_text(oi), same_start)
    if oc[0] == oi[0] == "up":
        for part in ("networks", "localaddresses"):
            a, b = (ic or {}).get(part), (ii or {}).get(part)
            d = first_difference(a, b)
            row(f"{name}: {part}", json.dumps(a)[:120], d or json.dumps(b)[:120], d is None)
    for k in sorted(set(lc) | set(li)):
        a, b = dedupe(lc.get(k, [])), dedupe(li.get(k, []))
        row(f"{name}: {k} saw", json.dumps(a)[:200], json.dumps(b)[:200], a == b)


def dedupe(log):
    """A stand-in's log with repeats of the same entry (reconnects) counted once"""
    out = []
    for e in log:
        if e not in out:
            out.append(e)
    return out


# --- the cases --------------------------------------------------------------------------

need = [PORT_BASE + k for k in (0, 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 17, 49)]
busy = [p for p in need if not port_free(p)]
if busy:
    print(f"FAIL   setup: ports in use on {HOST}: {busy}; choose another port base", flush=True)
    sys.exit(1)
print(f"# ports {PORT_BASE}..{PORT_BASE + 49} on {HOST}", flush=True)

case("defaults (-listenonion=0)")
case("-upnp=0", ["upnp=0"])
# -proxy
case("-proxy=<socks>", ["proxy=127.0.0.1:{socks}"], socks=True)
case("-proxy=<socks> -listen=1", ["proxy=127.0.0.1:{socks}", "listen=1"], socks=True)
case("-proxy=<socks> -addnode=127.0.0.1:<target>", ["proxy=127.0.0.1:{socks}", "addnode=127.0.0.1:{target}"],
     socks=True, target=True)
case("-proxy=<socks> -proxyrandomize=0 -addnode=127.0.0.1:<target>",
     ["proxy=127.0.0.1:{socks}", "proxyrandomize=0", "addnode=127.0.0.1:{target}"], socks=True, target=True)
case("-proxy=<socks> -addnode=localhost:<target> (a host name, given to the proxy)",
     ["proxy=127.0.0.1:{socks}", "addnode=localhost:{target}"], socks=True, target=True)
# An onion peer, by its .onion name: no off-host dial can follow from it
case("-proxy=<socks> -addnode=<an onion name>", ["proxy=127.0.0.1:{socks}", f"addnode={SERVICE_ID}.onion:{{target}}"],
     socks=True)
case("-proxy=localhost:<socks>", ["proxy=localhost:{socks}"], socks=True)
case("-proxy=localhost:<socks> -dns=0", ["proxy=localhost:{socks}", "dns=0"], socks=True)
case("-proxy=127.0.0.1 (no port)", ["proxy=127.0.0.1"])
case("-proxy=0", ["proxy=0"])
case("-proxy= (empty)", ["proxy="])
case("-noproxy", [], args=["-noproxy"])
case("-proxy=notahost.invalid", ["proxy=notahost.invalid"])
case("-proxy=127.0.0.1:99999", ["proxy=127.0.0.1:99999"])
case("-proxyrandomize=0 alone", ["proxyrandomize=0"])
# -onion
case("-onion=<onion socks>", ["onion=127.0.0.1:{onion}"], onion=True)
case("-proxy=<socks> -onion=<onion socks>", ["proxy=127.0.0.1:{socks}", "onion=127.0.0.1:{onion}"], socks=True,
     onion=True)
case("-proxy=<socks> -onion=0", ["proxy=127.0.0.1:{socks}", "onion=0"], socks=True)
case("-proxy=<socks> -noonion", ["proxy=127.0.0.1:{socks}"], args=["-noonion"], socks=True)
case("-onion=<onion socks> -addnode=<an onion name>", ["onion=127.0.0.1:{onion}",
                                                      f"addnode={SERVICE_ID}.onion:{{target}}"], onion=True)
case("-proxy=<socks> -onion=<onion socks> -addnode=<an onion name>",
     ["proxy=127.0.0.1:{socks}", "onion=127.0.0.1:{onion}", f"addnode={SERVICE_ID}.onion:{{target}}"], socks=True,
     onion=True)
case("-onion=0 alone", ["onion=0"])
case("-onion=notahost.invalid", ["onion=notahost.invalid"])
case("-onion=localhost:<onion socks> -dns=0", ["onion=localhost:{onion}", "dns=0"], onion=True)
case("-onion=<onion socks> -proxyrandomize=0", ["onion=127.0.0.1:{onion}", "proxyrandomize=0"], onion=True)
# Tor control (-listenonion, -torcontrol, -torpassword)
TORCTL = ["listen=1", "listenonion=1", "torcontrol=127.0.0.1:{torctl}"]
case("tor control, NULL auth", TORCTL, tor=("NULL", None, False))
case("tor control, NULL auth, restart (the saved key)", TORCTL, tor=("NULL", None, False), restart=True)
case("tor control, NULL auth, -onion=<onion socks>", TORCTL + ["onion=127.0.0.1:{onion}"], tor=("NULL", None, False),
     onion=True)
case("tor control, HASHEDPASSWORD, -torpassword in divi.conf", TORCTL,
     tor=("HASHEDPASSWORD", lambda n: n.tor_password, False, lambda n: [f"torpassword={n.tor_password}"]))
case("tor control, HASHEDPASSWORD, no -torpassword", TORCTL, tor=("HASHEDPASSWORD", None, False))
case("tor control, SAFECOOKIE", TORCTL, tor=("COOKIE,SAFECOOKIE", None, True))
case("tor control, COOKIE only", TORCTL, tor=("COOKIE", None, True))
case("tor control, NULL auth, -listenonion=0", ["listen=1", "listenonion=0", "torcontrol=127.0.0.1:{torctl}"],
     tor=("NULL", None, False))
case("tor control, NULL auth, -listen=0", ["listen=0", "listenonion=1", "torcontrol=127.0.0.1:{torctl}"],
     tor=("NULL", None, False))
case("tor control, -torcontrol at a port nothing listens on", ["listen=1", "listenonion=1",
                                                              f"torcontrol=127.0.0.1:{PORT_BASE + 49}"])
# -dns: a host name for -addnode and -connect, resolved or not
case("-addnode=localhost:<target>", ["addnode=localhost:{target}"], target=True)
case("-addnode=localhost:<target> -dns=0", ["addnode=localhost:{target}", "dns=0"], target=True)
case("-connect=localhost:<target>", ["connect=localhost:{target}"], target=True)
case("-connect=localhost:<target> -dns=0", ["connect=localhost:{target}", "dns=0"], target=True)
case("-externalip=localhost -dns=0", ["externalip=localhost", "dns=0"])
case("-dns=0 alone", ["dns=0"])
# -upnp=1 is not started on either node (module docstring); its rows are KNOWN
for name in ("-upnp=1", "-upnp=1 -proxy=<socks> (the proxy turns it off unless set)"):
    row(f"{name}: not started", "not started", "not started", False)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
