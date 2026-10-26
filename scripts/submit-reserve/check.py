#!/usr/bin/env python3
"""submitblock, getblocktemplate and reservebalance, Divi Core divid and
irondivid compared call by call on regtest.

Divi Core 3.0.0 has none of the three (its command table, rpcserver.cpp:329-460):
each is "Method not found" and `help` calls it an unknown command. The script
still sends what a miner or staker would, so a node that took one of them would
show it: the tip block as `getblock <hash> false` gives it, and that block with
its nonce, its merkle root or its coinbase output changed, an oversized and a
malformed argument; getblocktemplate in its modes; and every reservebalance
form. Around them it compares getblockcount, getchaintips and getstakingstatus,
also after a restart.

Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs. Started by run.sh, which owns the work directory and
stops the nodes.
"""

import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), os.path.abspath(sys.argv[4])
RPC_TIMEOUT = 60
START_TIMEOUT = 240
NODE_IP = "127.0.0.2"
INJECT = os.environ.get("SUBMIT_RESERVE_INJECT", "")

# Rows where irondivid differs on purpose: (reason, shape)
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron):
    global fails
    if INJECT == name:
        iron = ["injected"]
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note}"[:700], flush=True)


def show(out):
    """A reply as compared: the result, or the error code and message"""
    return {"result": out[1]} if out[0] == "ok" else {"error": [out[1], out[2]]}


def both(name, method, *params):
    row(name, show(C.call(method, *params)), show(I.call(method, *params)))


def facts(name, fn):
    row(name, fn(C), fn(I))


def setup_failed(kind, value, tb):
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   setup (line {where}): {value}"[:400], flush=True)
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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"sr{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=sr{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1", "debug=rpc",
        ]
        os.makedirs(os.path.join(self.dir, "home"))
        self.proc = None

    def start(self):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        with open(os.path.join(WORK, f"{self.name}.out"), "w") as o, \
                open(os.path.join(WORK, f"{self.name}.err"), "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not wait_for(lambda: self.call("getblockcount")[0] == "ok", START_TIMEOUT):
            raise RuntimeError(f"{self.name} did not start")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
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
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def mine(self, n):
        for _ in range(n):
            self.rpc("setgenerate", 1)



# --- blocks, altered here ----------------------------------------------------------------

def compact_at(b, off):
    """(value, size) of the compact size at b[off]"""
    first = b[off]
    if first < 0xfd:
        return first, 1
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    return int.from_bytes(b[off + 1:off + 1 + size], "little"), 1 + size


def coinbase_value_offset(b):
    """Where the first output value of the block's first transaction starts"""
    off = 80
    _, n = compact_at(b, off)
    off += n + 4                       # the transaction count, then the version
    _, n = compact_at(b, off)
    off += n + 36                      # the input count, then the prevout
    length, n = compact_at(b, off)
    off += n + length + 4              # scriptSig and sequence
    _, n = compact_at(b, off)
    return off + n                     # past the output count


def flip(b, off):
    b = bytearray(b)
    b[off] ^= 0xff
    return bytes(b)


def tip_block(n):
    return bytes.fromhex(n.rpc("getblock", n.rpc("getbestblockhash"), False))


def tips(n):
    """getchaintips as the heights and statuses of the tips"""
    return sorted((t["height"], t["status"]) for t in n.rpc("getchaintips"))


def staking(n):
    s = n.rpc("getstakingstatus")
    return {k: s.get(k) for k in ("walletunlocked", "staking_balance", "enoughcoins")}


# --- start -----------------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
NODES = (C, I)
for n in NODES:
    n.start()
    n.mine(25)
facts("height after the setup", lambda n: n.rpc("getblockcount"))
before = {n: (n.rpc("getblockcount"), tips(n)) for n in NODES}

# --- submitblock (divid: Method not found) ------------------------------------------------
both("help submitblock", "help", "submitblock")
for label, make in (
    ("the tip block again", lambda b: b),
    ("the tip block with its nonce changed", lambda b: flip(b, 76)),
    ("the tip block with its merkle root changed", lambda b: flip(b, 36)),
    ("the tip block with its coinbase output changed", lambda b: flip(b, coinbase_value_offset(b))),
    ("the tip block naming an unknown parent", lambda b: flip(b, 4)),
):
    row(f"submitblock: {label}", show(C.call("submitblock", make(tip_block(C)).hex())),
        show(I.call("submitblock", make(tip_block(I)).hex())))
both("submitblock: a block over 2 MB", "submitblock", "00" * 2_100_000)
both("submitblock: not hex", "submitblock", "zz")
both("submitblock: one byte", "submitblock", "00")
both("submitblock: no argument", "submitblock")
row("submitblock: the tip block with a second argument",
    show(C.call("submitblock", tip_block(C).hex(), {"workid": "x"})),
    show(I.call("submitblock", tip_block(I).hex(), {"workid": "x"})))
facts("getblockcount after the submitblock calls", lambda n: n.rpc("getblockcount") - before[n][0])
facts("getchaintips after the submitblock calls", lambda n: tips(n) == before[n][1])

# --- getblocktemplate (divid: Method not found) ------------------------------------------
both("help getblocktemplate", "help", "getblocktemplate")
both("getblocktemplate", "getblocktemplate")
both("getblocktemplate mode template", "getblocktemplate", {"mode": "template"})
row("getblocktemplate mode proposal", show(C.call("getblocktemplate", {"mode": "proposal", "data": tip_block(C).hex()})),
    show(I.call("getblocktemplate", {"mode": "proposal", "data": tip_block(I).hex()})))
both("getblocktemplate mode nonsense", "getblocktemplate", {"mode": "nonsense"})

# --- reservebalance (divid: Method not found; getstakingstatus has no reserve,
# enoughcoins is staking_balance > 0, rpcmisc.cpp:1059-1066) ---------------------------------
facts("getstakingstatus before reservebalance", staking)
both("help reservebalance", "help", "reservebalance")
both("reservebalance", "reservebalance")
both("reservebalance true 100", "reservebalance", True, 100)
both("reservebalance true", "reservebalance", True)
both("reservebalance false", "reservebalance", False)
both("reservebalance false 100", "reservebalance", False, 100)
both("reservebalance true -1", "reservebalance", True, -1)
both("reservebalance true abc", "reservebalance", True, "abc")
both("reservebalance true above the balance", "reservebalance", True, 100_000_000)
both("reservebalance true 100, then reservebalance", "reservebalance", True, 100)
both("reservebalance (shown after setting)", "reservebalance")
facts("getstakingstatus after reservebalance true 100", staking)
for n in NODES:
    n.stop()
for n in NODES:
    n.start()
both("reservebalance after a restart", "reservebalance")
facts("getstakingstatus after a restart", staking)
facts("getblockcount after a restart", lambda n: n.rpc("getblockcount") - before[n][0])

for n in NODES:
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
