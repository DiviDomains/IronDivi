#!/usr/bin/env python3
"""Wallet writes that fail on a running node, Divi Core divid and irondivid
side by side. Each daemon runs alone on regtest with its own chain. While it
runs, the soft file size limit of its process is lowered to one byte with
prlimit (SIGXFSZ is ignored from the start, so a write past the limit fails
with EFBIG), then raised again. The method is scripts/disk-errors' `ulimit -f`,
applied to a running node, so the chain is not written meanwhile and only the
wallet's writes fail.

Rows compare the RPC replies (code and message), whether a log line names the
failed write, whether the node stays up, and the balance and transactions
after a restart. Rows print PASS (same as divid), KNOWN (a difference listed
in README.md) or FAIL. Exit code = FAILs. Started by run.sh, which owns the
work directory and stops the nodes.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
START_TIMEOUT = 120
# Blocks each node mines for itself: 100 to mature, and enough to spend
BLOCKS = 110
T0 = time.time()

# A log line that names a wallet write which failed: divid's AddToWallet
# (wallet.cpp:1271-1274) or CDB::Rewrite (db.cpp), irondivid's wallet
FAILED_WRITE = re.compile(r"Unable to write|Failed to rewrite|Failed to (store|save|encrypt)")


def note(text):
    print(f"# [{time.time() - T0:6.1f}s] {text}", flush=True)


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


HALF_ENCRYPTED = ("divid encrypts its keys in memory first and does not undo that when a later write fails "
                  "(wallet.cpp:960-1030), so the wallet it runs on is encrypted in memory and unencrypted on disk, "
                  "as the restart row shows. irondivid leaves the wallet as it was")
SHORT_POOL = ("divid's writes inside its encryption transaction go through and the keypool top-up after it "
              "(wallet.cpp:1011-1015) derives a key whose write fails: deriveNewChildKey throws "
              "(wallet.cpp:2359-2360) and the RPC server answers with its text. irondivid fails at its first write. "
              "Copying divid would mean copying when Berkeley DB writes its log")
KNOWN = {
    "encryptwallet with a full keypool: the wallet's state while it runs on": (
        HALF_ENCRYPTED, pair("locked", "unencrypted")),
    "encryptwallet with a keypool one short: the wallet's state while it runs on": (
        HALF_ENCRYPTED, pair("unlocked", "unencrypted")),
    "encryptwallet with a keypool one short: a log line names the failed write": (
        SHORT_POOL + "; divid's RPC server answers with the exception's text and logs nothing (rpcserver.cpp:1107-1108)",
        pair(False, True)),
    "encryptwallet with a keypool one short: encryptwallet": (
        SHORT_POOL, pair(["err", -1, "loadCryptedHDChain: WriteCryptedHDChain failed"],
                         ["err", -16, "Error: Failed to encrypt the wallet."])),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def matches(shape, core, iron):
    try:
        return bool(shape(core, iron))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return False


def row(name, core, iron):
    global fails
    same = core == iron
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note_ = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif matches(shape, core, iron):
            word, note_ = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note_ = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note_ = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note_}"[:900], flush=True)


def setup_failed(kind, value, tb):
    import traceback
    traceback.print_tb(tb)
    print(f"FAIL   setup: {kind.__name__}: {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- nodes -----------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, case):
        self.name, self.binary = name, binary
        # each case's nodes have the same ports: the ones a node of an earlier case was moved to
        self.p2p = node_ports.now(PORT_BASE + 2 * index)
        self.rpcport = node_ports.now(PORT_BASE + 2 * index + 1)
        self.password = secrets.token_hex(16)
        self.user = f"u{index}"
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.dir = os.path.join(WORK, case, name)
        self.case = case
        self.proc = None
        self.starts = 0

    def write_conf(self):
        # connect= to a port with nothing on it: no peers, no address lookups
        lines = ["regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
                 f"rpcpassword={self.password}", "rpcallowip=127.0.0.0/8", f"rpcbind={HOST}", f"bind={HOST}",
                 "server=1", "daemon=0", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
                 "printtoconsole=1", f"connect={HOST}:{PORT_BASE + 4}"]
        os.makedirs(self.dir, exist_ok=True)
        path = os.path.join(self.dir, "divi.conf")
        if os.path.exists(path):
            os.remove(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(node_ports.follow("\n".join(lines) + "\n"))

    def start(self):
        """('up',), ('exit', code) or ('timeout',). The node's output goes
        through a pipe to a file this script writes, so no limit applies to it.
        A node that exits because a port is taken is started again on new ports."""
        retries = node_ports.BIND_RETRIES
        while True:
            outcome = self.start_once()
            if outcome[0] == "exit" and retries:
                with open(self.out_path, errors="replace") as f:
                    taken = node_ports.bind_failure(self, f.read())
                if taken and node_ports.move_ports(self, self.dir):
                    retries -= 1
                    continue
            return outcome

    def start_once(self):
        self.write_conf()
        self.starts += 1
        self.out_path = os.path.join(WORK, f"{self.case}.{self.name}.{self.starts}.out")
        out = open(self.out_path, "w")
        # SIGXFSZ ignored: a write past the limit fails with EFBIG instead of killing the node
        script = "trap '' XFSZ; d=$1; shift; exec \"$0\" -datadir=\"$d\""
        self.proc = subprocess.Popen(["bash", "-c", script, self.binary, self.dir], cwd=self.dir,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        proc = self.proc

        def pump():
            for line in proc.stdout:
                out.write(line.decode(errors="replace"))
                out.flush()
            out.close()

        self.pump = threading.Thread(target=pump, daemon=True)
        self.pump.start()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if proc.poll() is not None:
                self.pump.join(5)
                return ("exit", proc.returncode)
            if self.call("getblockcount", timeout=5)[0] == "ok":
                return ("up",)
            time.sleep(0.25)
        return ("timeout",)

    def call(self, method, *params, timeout=60):
        """('ok', result), ('err', code, message) or ('down',) when nothing answers"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "")
        except (urllib.error.URLError, OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out}")
        return out[1]

    def limit(self, soft):
        """Set the soft file size limit of the running node (bytes, or 'unlimited')"""
        subprocess.run(["prlimit", f"--pid={self.proc.pid}", f"--fsize={soft}:unlimited"], check=True)

    def output_since(self, mark):
        with open(self.out_path, errors="replace") as f:
            f.seek(mark)
            return f.read()

    def mark(self):
        return os.path.getsize(self.out_path)

    def stop(self):
        """The exit code, or 'killed' when it did not stop within 90 s"""
        self.call("stop")
        try:
            self.proc.wait(90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return "killed"
        self.pump.join(5)
        return self.proc.returncode

    def mine(self, n):
        for _ in range(n):
            self.rpc("setgenerate", 1)


# --- what each node does ---------------------------------------------------------------

def shape(reply, kind=None):
    """A reply with what differs between two nodes (txids, addresses) left out"""
    if reply[0] == "ok" and kind == "txid":
        return ["ok", "txid" if re.fullmatch(r"[0-9a-f]{64}", str(reply[1])) else reply[1]]
    if reply[0] == "ok" and kind == "address":
        return ["ok", "address" if isinstance(reply[1], str) and len(reply[1]) > 25 else reply[1]]
    return list(reply)


def up(n):
    return n.call("getblockcount")[0] == "ok"


def prepare(n):
    started = n.start()
    if started != ("up",):
        raise RuntimeError(f"{n.name} did not start: {started}")
    n.mine(BLOCKS)
    n.rpc("keypoolrefill")
    return n.rpc("getnewaddress")


def send_case(n, seen):
    """Sends and new keys while the wallet's writes fail (wallet.cpp:1271-1274,
    :2346-2347, :2158-2163), then once they work again"""
    target = prepare(n)
    n.rpc("keypoolrefill")
    mark = n.mark()
    n.limit(1)
    seen["getnewaddress with a full keypool"] = n.call("getnewaddress")
    n.limit("unlimited")
    seen["keypoolrefill once writes work again"] = n.call("keypoolrefill")
    n.limit(1)
    seen["sendtoaddress with a full keypool"] = n.call("sendtoaddress", target, 10)
    seen["getnewaddress after the send"] = n.call("getnewaddress")
    seen["setaccount after the send"] = n.call("setaccount", target, "lbl")
    seen["up while writes fail"] = up(n)
    n.limit("unlimited")
    seen["sendtoaddress once writes work again"] = n.call("sendtoaddress", target, 11)
    seen["a block once writes work again"] = n.call("setgenerate", 1)[0]
    seen["a log line names the failed write"] = bool(FAILED_WRITE.search(n.output_since(mark)))
    seen["exit code of the stop"] = n.stop()
    seen["restart"] = n.start()
    seen["balance after the restart"] = n.call("getbalance")
    sends = [(t.get("category"), t.get("amount")) for t in n.rpc("listtransactions", "*", 1000)
             if t.get("txid") in (seen["sendtoaddress with a full keypool"][1:2] +
                                  seen["sendtoaddress once writes work again"][1:2])]
    seen["the two sends after the restart"] = sorted(sends)
    got = seen["getnewaddress with a full keypool"]
    seen["the key handed out with a full keypool is the wallet's after the restart"] = (
        n.rpc("validateaddress", got[1]).get("ismine") if got[0] == "ok" else got)
    seen["exit code of the last stop"] = n.stop()


def encrypt_case(n, seen, full_pool):
    """encryptwallet while the wallet's writes fail (wallet.cpp:1005-1007,
    :1025-1028; rpcwallet.cpp:2729-2730). prepare() leaves the keypool one
    key short"""
    prepare(n)
    if full_pool:
        n.rpc("keypoolrefill")
    mark = n.mark()
    n.limit(1)
    seen["encryptwallet"] = n.call("encryptwallet", secrets.token_hex(12))
    seen["up after encryptwallet"] = up(n)
    seen["the wallet's state while it runs on"] = n.rpc("getwalletinfo").get("encryption_status")
    n.limit("unlimited")
    seen["a log line names the failed write"] = bool(FAILED_WRITE.search(n.output_since(mark)))
    seen["exit code of the stop"] = n.stop()
    seen["restart"] = n.start()
    info = n.rpc("getwalletinfo")
    seen["the wallet's state after the restart"] = info.get("encryption_status")
    seen["balance after the restart"] = info.get("balance")
    seen["getnewaddress after the restart"] = n.call("getnewaddress")
    seen["exit code of the last stop"] = n.stop()


SHAPES = {
    "getnewaddress with a full keypool": "address",
    "sendtoaddress with a full keypool": "txid",
    "getnewaddress after the send": "address",
    "sendtoaddress once writes work again": "txid",
    "getnewaddress after the restart": "address",
}


def run_case(label, case):
    note(f"{label}: starting both daemons")
    nodes = (Node("divid", DIVID, 0, label), Node("irondivid", IRONDIVID, 1, label))
    seen = ({}, {})
    errors = [None, None]

    def go(i):
        try:
            case(nodes[i], seen[i])
        except Exception as e:  # reported as a row below
            errors[i] = f"{type(e).__name__}: {e}"

    threads = [threading.Thread(target=go, args=(i,)) for i in (0, 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for n in nodes:
        if n.proc is not None and n.proc.poll() is None:
            n.stop()
    if errors[0] or errors[1]:
        row(f"{label}: the case ran to its end", errors[0] or "yes", errors[1] or "yes")
    keys = list(seen[0]) + [k for k in seen[1] if k not in seen[0]]
    for key in keys:
        core, iron = seen[0].get(key, "not reached"), seen[1].get(key, "not reached")
        if isinstance(core, tuple):
            core = shape(core, SHAPES.get(key))
        if isinstance(iron, tuple):
            iron = shape(iron, SHAPES.get(key))
        row(f"{label}: {key}", core, iron)


run_case("send", send_case)
run_case("encryptwallet with a full keypool", lambda n, seen: encrypt_case(n, seen, True))
run_case("encryptwallet with a keypool one short", lambda n, seen: encrypt_case(n, seen, False))
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
