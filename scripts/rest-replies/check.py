#!/usr/bin/env python3
"""REST replies of Divi Core divid and irondivid, compared status, Content-Type and body.

Both nodes sit on one regtest chain (irondivid dials divid) with -rest=1 and
-txindex=1. Every path divid serves (rest.cpp: /rest/tx/, /rest/block/,
/rest/block/notxdetails/) is asked in each format (.json, .hex, .bin) and with
each error divid answers, plus the paths divid does not serve, without any
credentials (divid's REST needs none). Then both restart with -rest=0 and the
paths are asked again. ZMQ topics are listed as KNOWN rows (README.md).

Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory and
stops the nodes. The RPC passwords live only in the 0600 divi.conf files and in
memory.
"""

import base64
import http.client
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's body of the named row is
# changed before it is compared
INJECT = os.environ.get("REST_REPLIES_INJECT", "")
# A directory to write both replies of every compared row to (for looking into a
# FAIL); nothing is written without it
DUMP = os.environ.get("REST_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

ZMQ_REASON = ("irondivid has no ZMQ publisher (-zmqpub* are unsupported options); not compared: "
              "a ZMQ subscriber needs pyzmq, which is not in the standard library")
# Differences irondivid has on purpose, one per row name, each listed in
# README.md. A KNOWN row that starts to match divid is a FAIL.
KNOWN = {f"zmq {t}": ZMQ_REASON for t in ("hashblock", "hashtx", "rawblock", "rawtx")}

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.password = secrets.token_hex(16)
        self.user = f"replies{index}"
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        os.makedirs(self.dir)
        self.write_conf(extra_conf, rest=True)
        self.log = None
        self.start()

    def write_conf(self, extra_conf, rest):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0", "txindex=1", f"rest={1 if rest else 0}",
        ] + list(extra_conf)
        self.extra_conf = extra_conf
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
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

    def http(self, path, method="GET"):
        """(status, Content-Type, body bytes) of a request without credentials"""
        conn = http.client.HTTPConnection("127.0.0.1", self.rpcport, timeout=RPC_TIMEOUT)
        try:
            conn.request(method, path, body=b"" if method == "POST" else None,
                         headers={"Connection": "close"})
            r = conn.getresponse()
            return (r.status, r.getheader("Content-Type", ""), r.read())
        except (http.client.HTTPException, OSError) as e:
            return (0, "", f"no reply: {type(e).__name__}".encode())
        finally:
            conn.close()

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def restart(self, rest):
        self.stop()
        self.write_conf(self.extra_conf, rest)
        self.start()


# --- how replies are compared ------------------------------------------------------

def first_difference(a, b, path="$"):
    """Where two JSON values first differ, or None. Reals are compared as each
    node writes them (the text of the number); members in any order (irondivid
    writes them in name order, docs/divid-differences.md)."""
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
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def body_difference(ctype, a, b):
    """Where two bodies differ, or None: JSON field by field (and both ending in a
    newline, as divid's), anything else byte for byte"""
    if ctype.startswith("application/json"):
        try:
            ja = json.loads(a, parse_float=str)
            jb = json.loads(b, parse_float=str)
        except ValueError:
            return None if a == b else "body is not JSON on one node"
        d = first_difference(ja, jb)
        if d:
            return d
        if a.endswith(b"\n") != b.endswith(b"\n"):
            return "trailing newline differs"
        return None
    if a == b:
        return None
    for n, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return f"bodies differ at byte {n} ({len(a)} vs {len(b)} bytes)"
    return f"bodies differ in length ({len(a)} vs {len(b)} bytes)"


def short(r):
    status, ctype, body = r
    # printable text as is, any other byte as \xNN, so the output stays text
    text = "".join(chr(b) if 32 <= b < 127 else ("\\r" if b == 13 else "\\n" if b == 10 else f"\\x{b:02x}")
                   for b in body[:50])
    return f"{status} {ctype or '-'} {len(body)}B \"{text}\""


def compare(name, path, method="GET"):
    core, iron = C.http(path, method), I.http(path, method)
    if INJECT and INJECT == name:
        iron = (iron[0], iron[1], iron[2] + b"x")
    if DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        for who, r in (("divid", core), ("irondivid", iron)):
            with open(os.path.join(DUMP, f"{safe}.{who}"), "wb") as f:
                f.write(f"{r[0]} {r[1]}\n".encode() + r[2])
    if core[0] != iron[0]:
        d = f"status {iron[0]}"
    elif core[1] != iron[1]:
        d = f"Content-Type {iron[1] or '-'}"
    else:
        d = body_difference(core[1], core[2], iron[2])
    row(name, short(core), d or short(iron), d is None)


# --- the chain ----------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print("FAIL   start: divid did not answer", flush=True)
    sys.exit(1)
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{C.p2p}"])
if not I.wait_ready():
    print("FAIL   start: irondivid did not answer", flush=True)
    sys.exit(1)


def synced(timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        mine = I.call("getbestblockhash")
        if mine[0] == "ok" and mine[1] == C.rpc("getbestblockhash"):
            return True
        time.sleep(0.5)
    return False


def in_mempool(node, txid, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = node.call("getrawmempool")
        if out[0] == "ok" and txid in out[1]:
            return True
        time.sleep(0.5)
    return False


C.rpc("setgenerate", 30)
addr = C.rpc("getnewaddress")
confirmed = C.rpc("sendtoaddress", addr, 12.5)
C.rpc("setgenerate", 1)
unconfirmed = C.rpc("sendtoaddress", addr, 3.25)
if not synced() or not in_mempool(I, unconfirmed):
    print("FAIL   setup: irondivid did not follow divid's chain and mempool", flush=True)
    sys.exit(1)
tip = C.rpc("getbestblockhash")
genesis = C.rpc("getblockhash", 0)
coinbase = C.rpc("getblock", tip)["tx"][0]
unknown = "ab" * 32


def rows(p):
    for f in ("json", "hex", "bin"):
        compare(f"{p}tx confirmed .{f}", f"/rest/tx/{confirmed}.{f}")
        compare(f"{p}tx in the mempool .{f}", f"/rest/tx/{unconfirmed}.{f}")
        compare(f"{p}tx coinbase .{f}", f"/rest/tx/{coinbase}.{f}")
        compare(f"{p}block tip .{f}", f"/rest/block/{tip}.{f}")
        compare(f"{p}block notxdetails tip .{f}", f"/rest/block/notxdetails/{tip}.{f}")
    compare(f"{p}block genesis .json", f"/rest/block/{genesis}.json")
    compare(f"{p}block notxdetails genesis .json", f"/rest/block/notxdetails/{genesis}.json")
    compare(f"{p}tx uppercase hash .json", f"/rest/tx/{confirmed.upper()}.json")
    compare(f"{p}tx by POST .json", f"/rest/tx/{confirmed}.json", "POST")
    # errors, in divid's order: hash, then lookup, then format
    compare(f"{p}tx bad hash", "/rest/tx/xyz.json")
    compare(f"{p}tx short hash", f"/rest/tx/{confirmed[:63]}.json")
    compare(f"{p}tx unknown txid", f"/rest/tx/{unknown}.json")
    compare(f"{p}tx wrong format", f"/rest/tx/{confirmed}.xml")
    compare(f"{p}tx missing extension", f"/rest/tx/{confirmed}")
    compare(f"{p}tx empty extension", f"/rest/tx/{confirmed}.")
    compare(f"{p}tx two extensions", f"/rest/tx/{confirmed}.json.hex")
    compare(f"{p}tx with a query", f"/rest/tx/{confirmed}.json?x=1")
    compare(f"{p}tx bad hash and wrong format", "/rest/tx/xyz.xml")
    compare(f"{p}tx unknown txid and wrong format", f"/rest/tx/{unknown}.xml")
    compare(f"{p}block bad hash", "/rest/block/xyz.json")
    compare(f"{p}block unknown hash", f"/rest/block/{unknown}.json")
    compare(f"{p}block wrong format", f"/rest/block/{tip}.xml")
    compare(f"{p}block missing extension", f"/rest/block/{tip}")
    compare(f"{p}block notxdetails unknown hash", f"/rest/block/notxdetails/{unknown}.json")
    # paths newer Bitcoin releases serve and divid 3.0.0 does not
    compare(f"{p}headers", f"/rest/headers/5/{tip}.json")
    compare(f"{p}chaininfo", "/rest/chaininfo.json")
    compare(f"{p}mempool info", "/rest/mempool/info.json")
    compare(f"{p}mempool contents", "/rest/mempool/contents.json")
    compare(f"{p}getutxos one outpoint", f"/rest/getutxos/checkmempool/{confirmed}-0.json")
    compare(f"{p}getutxos several outpoints", f"/rest/getutxos/{confirmed}-0/{confirmed}-1/{coinbase}-0.json")
    many = "/".join(f"{confirmed}-{n}" for n in range(16))
    compare(f"{p}getutxos too many outpoints", f"/rest/getutxos/{many}.json")
    compare(f"{p}rest root", "/rest/")
    compare(f"{p}not a rest path", "/foo")


rows("rest=1: ")

# The same paths with -rest=0 (divid's default)
for n in (C, I):
    n.restart(rest=False)
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   restart: {n.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
compare("rest=0: tx confirmed .json", f"/rest/tx/{confirmed}.json")
compare("rest=0: block tip .hex", f"/rest/block/{tip}.hex")
compare("rest=0: block notxdetails tip .bin", f"/rest/block/notxdetails/{tip}.bin")
compare("rest=0: tx unknown txid", f"/rest/tx/{unknown}.json")
compare("rest=0: not a rest path", "/foo")

# ZMQ: not compared (README.md)
for t in ("hashblock", "hashtx", "rawblock", "rawtx"):
    row(f"zmq {t}", "topic published with -zmqpub" + t, "no such option", False)

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
