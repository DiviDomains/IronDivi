#!/usr/bin/env python3
"""Divi Core divid's start-up chain check (VerifyChain, -checkblocks,
-checklevel), -resync and -par next to irondivid, case by case: a short regtest
chain is built once, then each case starts each daemon on a fresh copy of its
datadir, damaged or not, with the options of the case, and compares the start
result, the exit code, the error it prints, and what is on disk after.

Only copies made here are damaged. Each row prints PASS (same as divid), KNOWN
(a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The wallet
phrase lives only in memory, in an RPC reply and in irondivid's environment; it is
never printed or put on a command line.
"""

import base64
import hashlib
import json
import re
import shutil
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK, DAMAGE = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
LEVEL = ("irondivid's start check reads each block, its hash, merkle root and parent link, decodes its undo data, "
         "and undoes the tip blocks in memory against the coins as divid's level 3 does "
         "(crates/divi-storage/src/chain.rs verify_recent_blocks, verify_utxo_set_at_tip); it does not run level 4, "
         "connecting those blocks again (verifyDb.cpp:122-157). It logs divid's 'Verifying last N blocks at level 4', "
         "then 'Verified the last N blocks in M ms' instead of 'No coin database inconsistencies'")
CHECKLEVEL = ("same message; divid then aborts (SIGABRT) in the shutdown after this early InitError, before the "
              "chain state exists (init.cpp:381, ChainstateManager.cpp:102); irondivid exits 1 (also KNOWN in "
              "scripts/restart-options)")
PAR = ("-par sets divid's script check threads (init.cpp:801, TransactionInputChecker.cpp:16-26) and it logs "
       "the count (init.cpp:965); irondivid checks scripts on the block's own thread, accepts -par and logs that "
       "it is not used. What is accepted is the same: the row above checks a block still connects")


def checklevel_shape(c, i):
    return (c[0] == i[0] == "ok" and c[1][0] == i[1][0] == "exit" and c[1][1] == -6 and i[1][1] == 1
            and c[1][2] == i[1][2])


def par_shape(c, i):
    return (c[0] == i[0] == "ok" and len(c[1]["threads line"]) == 1 and not c[1]["not supported"]
            and i[1] == {"threads line": [], "not supported": True})


KNOWN = {
    "the log's 'No coin database inconsistencies' line (undamaged, default)": (LEVEL, pair(("ok", True), ("ok", False))),
}
for v in ("4", "3", "0"):
    KNOWN[f"an undamaged copy, -checklevel={v}"] = (CHECKLEVEL, checklevel_shape)
for v in ("0", "1", "-1", "17"):
    KNOWN[f"-par={v}: the log"] = (PAR, par_shape)

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:120]}\""
    return json.dumps(out[1])[:160]


def compare(name, core, iron):
    """Same outcome: for an error the same code and text, for a result the same value"""
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(name, core, iron)
    return core, iron


def facts(name, fn):
    """A row of what each node shows, from fn(node)"""
    c, i = ("ok", fn(C)), ("ok", fn(I))
    compare(name, c, i)
    return c[1], i[1]


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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, env=None, datadir=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = datadir or os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"sc{index}:{password}".encode()).decode()
        self.base = [
            f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=sc{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ]
        os.makedirs(self.dir, exist_ok=True)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def start(self, extra=("regtest=1",)):
        """('up',) once RPC answers, or ('exit', code, the first stderr line naming an error)"""
        self.write_conf(extra)
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.err = base + ".err"
        env = dict(os.environ, **self.env) if self.env else None
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
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

    def error_line(self):
        with open(self.err, errors="replace") as f:
            for line in f:
                if line.startswith("Error"):
                    return line.rstrip("\n")
        return ""

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

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

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


def restart(extra=("regtest=1",)):
    for n in (C, I):
        n.stop()
    out = C.start(extra), I.start(extra)
    for n, o in zip((C, I), out):
        if o[0] != "up":
            print(f"FAIL   setup: {n.name} did not start with {list(extra)}: {o}", flush=True)
            sys.exit(1)


# --- the chain both copies start from --------------------------------------------------

HEIGHT = 130
ISOLATED = ["regtest=1", "connect=127.0.0.2:1", "listen=0"]
C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
# Both wallets from one phrase: past the last work block a mined block is a
# stake, and each wallet then holds the same coins
if C.start(["regtest=1"])[0] != "up":
    print("FAIL   setup: divid did not start", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I.env = {"WALLET_MNEMONIC": phrase}
del phrase
if I.start(["regtest=1", f"connect={NODE_IP}:{C.p2p}"])[0] != "up":
    print("FAIL   setup: irondivid did not start", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
C.rpc("setgenerate", HEIGHT)
if not wait_for(lambda: I.rpc("getblockcount") == HEIGHT, 120):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
TIP = C.rpc("getbestblockhash")
for n in (C, I):
    n.stop()


def net_dir(node_dir):
    """Where the chain lives: <datadir>/regtest for divid, the datadir for irondivid"""
    sub = os.path.join(node_dir, "regtest")
    return sub if os.path.isdir(sub) else node_dir


def chain_files(node_dir):
    return sorted(os.listdir(net_dir(node_dir)))


print(f"# divid's chain folders: {chain_files(C.dir)}", flush=True)
print(f"# irondivid's chain folders: {chain_files(I.dir)}", flush=True)


# --- damage, on copies only ------------------------------------------------------------

def records(path, trailer=0):
    """(offset of the data, its length) of each record of a blk/rev file: magic, length,
    data, then `trailer` bytes (a rev record's 32-byte checksum)"""
    out = []
    with open(path, "rb") as f:
        data = f.read()
    pos = 0
    while pos + 8 <= len(data):
        if data[pos:pos + 4] == b"\0\0\0\0":
            break
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        out.append((pos + 8, size))
        pos += 8 + size + trailer
    return out


def flip(path, offset):
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 0xff]))


def damage_divid(copy, height, kind):
    blocks = os.path.join(copy, "regtest", "blocks")
    if kind in ("block-bad", "block-missing"):
        recs = records(os.path.join(blocks, "blk00000.dat"))
        start, size = recs[height]  # one chain, written in height order from genesis
        if kind == "block-bad":
            flip(os.path.join(blocks, "blk00000.dat"), start + 120)  # in the first transaction
        else:
            with open(os.path.join(blocks, "blk00000.dat"), "r+b") as f:
                f.seek(start)
                f.write(b"\0" * size)
    elif kind == "undo-bad":
        recs = records(os.path.join(blocks, "rev00000.dat"), trailer=32)
        start, size = recs[height - 1]  # undo data from block 1 on; then a 32-byte checksum
        flip(os.path.join(blocks, "rev00000.dat"), start + size + 31)


def damage_iron(copy, height, kind):
    out = subprocess.run([DAMAGE, os.path.join(copy, "chainstate"), str(height), kind],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"damage_block {kind} at {height}: {out.stderr.strip()[:200]}")


COPIES = iter(range(1, 1000))


def copy_of(node):
    path = os.path.join(WORK, f"{node.name}-copy{next(COPIES)}")
    shutil.copytree(node.dir, path)
    return path


def log_text(datadir):
    for p in (os.path.join(datadir, "regtest", "debug.log"), os.path.join(datadir, "debug.log")):
        if os.path.exists(p):
            with open(p, errors="replace") as f:
                return f.read()
    return ""


def start_on(node, path, extra, keep=False):
    """Start `node`'s binary on the copy at `path` with `extra` divi.conf lines; the outcome,
    the log text it wrote and, with keep, the running Node"""
    index = 2 if node is C else 3
    n = Node(f"{node.name}-on-{os.path.basename(path)}", node.binary, index, datadir=path, env=node.env)
    mark = len(log_text(path))
    out = n.start(list(extra))
    text = log_text(path)[mark:]
    if keep:
        return out, text, n
    n.stop()
    return out, text, None


def outcome(out):
    return out if out[0] == "up" else ("exit", out[1], out[2])


def case(name, kind=None, height=None, extra=()):
    """Damage a copy of each datadir (or none), start each with `extra`; one row of the outcomes"""
    got = {}
    for node, damage in ((C, damage_divid), (I, damage_iron)):
        path = copy_of(node)
        if kind:
            damage(path, height, kind)
        out, text, _ = start_on(node, path, ISOLATED + list(extra))
        got[node] = outcome(out), text
        shutil.rmtree(path, ignore_errors=True)
    compare(name, ("ok", got[C][0]), ("ok", got[I][0]))
    return got


# --- 1. the check at start (init.cpp:1116, verifyDb.cpp:66-167) ------------------------
got = case("an undamaged copy, -checkblocks not given")
verifying = {n: re.findall(r"Verifying last (\d+) blocks at level (\d+)", got[n][1]) for n in (C, I)}
compare("the log's 'Verifying last N blocks at level L' (undamaged, default)", ("ok", verifying[C]), ("ok", verifying[I]))
done = {n: bool(re.search(r"No coin database inconsistencies in last \d+ blocks", got[n][1])) for n in (C, I)}
compare("the log's 'No coin database inconsistencies' line (undamaged, default)", ("ok", done[C]), ("ok", done[I]))

for kind in ("block-bad", "block-missing", "undo-bad"):
    for depth_name, height in (("the tip", HEIGHT), ("5 below the tip", HEIGHT - 5)):
        case(f"{kind} at {depth_name}, -checkblocks not given", kind, height)
# -checkblocks=100: divid checks the blocks down to tip-100 (verifyDb.cpp:83-90)
case("block-bad at tip-100, -checkblocks not given (100)", "block-bad", HEIGHT - 100)
case("block-bad at tip-101, -checkblocks not given (100)", "block-bad", HEIGHT - 101)
for value in ("5", "0", "-1", "200", "abc"):
    case(f"block-bad at height 10, -checkblocks={value}", "block-bad", 10, [f"checkblocks={value}"])
case("block-bad at tip-5, -checkblocks=5", "block-bad", HEIGHT - 5, ["checkblocks=5"])
case("block-bad at tip-6, -checkblocks=5", "block-bad", HEIGHT - 6, ["checkblocks=5"])
case("block-bad at height 1, -checkblocks=0", "block-bad", 1, ["checkblocks=0"])
# the genesis block is never checked (verifyDb.cpp:83: a block with no parent)
case("block-bad at height 0 (genesis), -checkblocks=0", "block-bad", 0, ["checkblocks=0"])

# -checklevel is refused whatever its value (init.cpp:782-784)
for value in ("4", "3", "0"):
    case(f"an undamaged copy, -checklevel={value}", extra=[f"checklevel={value}"])


# --- 2. -par: script check threads (init.cpp:801, TransactionInputChecker.cpp:16-26) ----
for value in ("0", "1", "-1", "17"):
    row_out = {}
    for node in (C, I):
        path = copy_of(node)
        out, text, n = start_on(node, path, ISOLATED + [f"par={value}"], keep=True)
        height = None
        if out[0] == "up":
            mined = n.call("setgenerate", 1)
            height = n.rpc("getblockcount") if mined[0] == "ok" else show(mined)
            n.stop()
            if mined[0] != "ok":
                print(f"# {node.name} -par={value} setgenerate: {show(mined)}; log: "
                      + " | ".join(log_text(path).strip().splitlines()[-4:])[:600], flush=True)
        row_out[node] = (outcome(out), height,
                         re.findall(r"Using (\d+) threads for script verification", text),
                         "par" in text.lower() and "not supported" in text.lower())
        shutil.rmtree(path, ignore_errors=True)
    compare(f"-par={value}: start, then a block mined", ("ok", row_out[C][:2]), ("ok", row_out[I][:2]))
    compare(f"-par={value}: the log", ("ok", {"threads line": row_out[C][2], "not supported": row_out[C][3]}),
            ("ok", {"threads line": row_out[I][2], "not supported": row_out[I][3]}))


# --- 3. -resync: the chain folders removed, the wallet and conf kept (init.cpp:901-930, :1480-1483)
SOURCE = Node("divid", DIVID, 0)  # the original divid, which the resynced copies sync from
if SOURCE.start(["regtest=1", "listen=1"])[0] != "up":
    print("FAIL   setup: divid did not start again", flush=True)
    sys.exit(1)
# divid's chain folders (init.cpp:905-907); irondivid's chain database, transaction
# index and blocks folder
CHAIN = {"blocks", "chainstate", "sporks", "txindex"}
res = {}
for node in (C, I):
    path = copy_of(node)
    where = net_dir(path)
    before = sorted(os.listdir(where))
    for entry in before:
        if os.path.isdir(os.path.join(where, entry)):
            open(os.path.join(where, entry, "sentinel"), "w").close()
    out, text, n = start_on(node, path, ["regtest=1", f"connect={NODE_IP}:{SOURCE.p2p}", "listen=0", "resync=1"],
                            keep=True)
    kept = {e for e in os.listdir(where) if os.path.exists(os.path.join(where, e, "sentinel"))}
    dirs = {e for e in before if os.path.isdir(os.path.join(where, e))}
    synced = out[0] == "up" and wait_for(lambda: n.rpc("getbestblockhash") == TIP, 90)
    if n.proc:
        n.stop()
    res[node] = {"start": outcome(out),
                 "every chain folder cleared": all(d not in kept for d in dirs & CHAIN),
                 "every other folder kept": all(d in kept for d in dirs - CHAIN),
                 "synced again to the tip": synced,
                 "wallet kept": any(os.path.exists(os.path.join(where, w)) for w in ("wallet.dat", "wallet")),
                 "conf kept": os.path.exists(os.path.join(path, "divi.conf")),
                 "logged": bool(re.search(r"-resync: folder deleted|Deleting blockchain folders", text))}
    print(f"# {node.name} -resync: folders before {before}, after {sorted(os.listdir(where))}", flush=True)
    shutil.rmtree(path, ignore_errors=True)
for key in ("start", "every chain folder cleared", "every other folder kept", "synced again to the tip", "wallet kept", "conf kept", "logged"):
    compare(f"-resync: {key}", ("ok", res[C][key]), ("ok", res[I][key]))
SOURCE.stop()

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
