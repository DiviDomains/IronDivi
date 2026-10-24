#!/usr/bin/env python3
"""Start-up options and restarts, run step by step on a fresh Divi Core divid
and a fresh irondivid side by side: -txindex switched with and without
-reindex, -minrelaytxfee (units, refused values), sporks across a restart,
-sporkkey, and the error a failed start prints on stderr. Then irondivid's
--export-chain, which divid does not have, against its expected outcome.
Each row prints PASS, KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row runs differently on irondivid
INJECT = os.environ.get("RESTART_OPTIONS_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose or has not closed yet, one per row name:
# (reason, shape). Each is listed in README.md with divid's source line. shape
# takes the two raw outcomes and is true only for the difference described, so
# a KNOWN row that matches divid, or differs in another way, is a FAIL.


def core_aborts(c, i):
    return c[0] == i[0] == "exit" and c[1] == -6 and i[1] == 1 and c[2] == i[2]


ABORT = ("same message; divid then aborts (SIGABRT) in the shutdown after this early InitError: "
         "PrepareShutdown's FlushStateToDisk (divi/src/init.cpp:381) asserts in ChainstateManager::Get "
         "(divi/src/ChainstateManager.cpp:102) before the chain state exists; irondivid exits 1", core_aborts)
KNOWN = {
    "start -minrelaytxfee=0": ABORT,
    "start -minrelaytxfee=0.0": ABORT,
    "start -minrelaytxfee=abc": ABORT,
    "start -minrelaytxfee=-0.0001": ABORT,
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


def iron_row(name, expected, got):
    """A row with no divid counterpart: irondivid against the expected outcome"""
    global fails
    word = "PASS" if expected == got else "FAIL"
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  expected={expected}  irondivid={got}  [irondivid only]", flush=True)


def not_run(name, why):
    print(f"KNOWN  {name}  not run  [known: {why}]", flush=True)


class Node:
    def __init__(self, name, binary, index):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"restart{index}:{password}".encode()).decode()
        self.conf = os.path.join(self.dir, "divi.conf")
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=restart{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "listen=0", "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ]
        os.makedirs(self.dir)
        self.write_conf()
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        """divi.conf, 0600; extra lines are for one start only (a key never goes on argv)"""
        tmp = self.conf + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines + list(extra)) + "\n")
        os.replace(tmp, self.conf)

    def launch(self, *args):
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.out, self.err = base + ".out", base + ".err"
        with open(self.out, "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code, first stderr line naming an error)"""
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


# --- how outcomes are compared ---------------------------------------------------

def show(out, kind="ok"):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\""
    v = out[1]
    if kind == "hex":
        return "hex" if isinstance(v, str) and v else f"ok {type(v).__name__}"
    if kind == "txid":
        return "txid" if isinstance(v, str) and len(v) == 64 else f"ok {type(v).__name__}"
    if kind == "value":
        return json.dumps(v, sort_keys=True)
    return "ok"


def compare(name, core, iron, kind="ok", message=True):
    """Same outcome (ok/error), same error code, and the same message when
    divid's is a fixed text (message=True)"""
    a, b = show(core, kind), show(iron, kind)
    if core[0] == "err" and iron[0] == "err":
        same = core[1] == iron[1] and (not message or core[2] == iron[2])
    else:
        same = a == b
    row(name, a, b, same, (core, iron))


def show_start(s):
    return "up" if s[0] == "up" else f"exit {s[1]} \"{s[2][:110]}\""


def starts(name, *args, iron_args=None, message=True):
    """Start both with the same options; same outcome, exit code and stderr error line"""
    c = C.start(*args)
    i = I.start(*(args if iron_args is None else iron_args))
    if c[0] == "exit" and i[0] == "exit":
        same = c[1] == i[1] and (not message or c[2] == i[2])
    else:
        same = c[0] == i[0]
    row(name, show_start(c), show_start(i), same, (c, i))
    return c, i


def stop_both():
    for n in (C, I):
        n.stop()


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
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


# --- transactions the index rows look up -----------------------------------------

def spend(node, utxo, fee_sat, dest):
    """Sign and send one coin to dest, paying fee_sat; returns (outcome, raw hex)"""
    amount = round((round(utxo["amount"] * 1e8) - fee_sat) / 1e8, 8)
    raw = node.rpc("createrawtransaction", [{"txid": utxo["txid"], "vout": utxo["vout"]}], {dest: amount})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign its own coin")
    return node.call("sendrawtransaction", signed["hex"]), signed["hex"]


def spent_and_unspent(node):
    """T1 spends a mature coin to one output; T2 spends T1's only output. T1 is
    then fully spent (found only through the transaction index), T2 is not."""
    addr = node.rpc("getnewaddress")
    coins = sorted(node.rpc("listunspent"), key=lambda u: (u["txid"], u["vout"]))
    sent, t1_hex = spend(node, coins[0], 100000, addr)
    need(sent[0] == "ok", f"{node.name} T1: {sent}")
    t1 = sent[1]
    node.rpc("setgenerate", 1)
    sent, t2_hex = spend(node, {"txid": t1, "vout": 0, "amount": round(coins[0]["amount"] - 0.001, 8)}, 100000, addr)
    need(sent[0] == "ok", f"{node.name} T2: {sent}")
    t2 = sent[1]
    # Two small coins: spent one block later they have too little priority to
    # go free (divi/src/MempoolConsensus.cpp:255-259), so the fee floor decides
    small = [node.rpc("getnewaddress"), node.rpc("getnewaddress")]
    rest = round((round(coins[1]["amount"] * 1e8) - 100000) / 1e8 - 0.02, 8)
    raw = node.rpc("createrawtransaction", [{"txid": coins[1]["txid"], "vout": coins[1]["vout"]}],
                   {small[0]: 0.01, small[1]: 0.01, addr: rest})
    signed = node.rpc("signrawtransaction", raw)
    t3 = node.rpc("sendrawtransaction", signed["hex"])
    node.rpc("setgenerate", 1)
    outs = node.rpc("decoderawtransaction", signed["hex"])["vout"]
    smalls = [{"txid": t3, "vout": o["n"], "amount": o["value"]} for o in outs if o["value"] == 0.01]
    need(len(smalls) == 2, f"{node.name} small coins: {outs}")
    return {"t1": t1, "t1_hex": t1_hex, "t2": t2, "t2_hex": t2_hex, "addr": addr, "small": smalls}


def lookups(name):
    """getrawtransaction of the fully spent T1 and of the unspent T2"""
    c, i = C.call("getrawtransaction", C.tx["t1"]), I.call("getrawtransaction", I.tx["t1"])
    compare(f"{name}: getrawtransaction of a spent tx", c, i, kind="hex")
    if c[0] == "ok" and i[0] == "ok":
        row(f"{name}: spent tx hex is the tx sent", c[1] == C.tx["t1_hex"], i[1] == I.tx["t1_hex"],
            (c[1] == C.tx["t1_hex"]) == (i[1] == I.tx["t1_hex"]))
    c, i = C.call("getrawtransaction", C.tx["t2"]), I.call("getrawtransaction", I.tx["t2"])
    compare(f"{name}: getrawtransaction of an unspent tx", c, i, kind="hex")


def kept_height(name):
    """After a restart: the same chain (height and tip) as before it"""
    ok = []
    for n in (C, I):
        ok.append(wait_for(lambda: n.rpc("getbestblockhash") == n.tip, 120))
    row(f"{name}: chain kept", "same tip" if ok[0] else "other tip", "same tip" if ok[1] else "other tip",
        ok[0] == ok[1])


# --- keys made here, so nobody holds them ----------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


# --- the run ---------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)

# 1. A fresh datadir without the transaction index
starts("start -txindex=0 on a fresh datadir", "-txindex=0")
need(C.proc and I.proc, "a node did not start")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)
for n in (C, I):
    n.rpc("setgenerate", 25)
    n.tx = spent_and_unspent(n)
    n.tip = n.rpc("getbestblockhash")
lookups("-txindex=0")
both_info = [n.call("getnetworkinfo") for n in (C, I)]
compare("default relay fee: getnetworkinfo relayfee", *[("ok", o[1].get("relayfee")) if o[0] == "ok" else o for o in both_info],
        kind="value")
sporks = [n.call("spork", "show") for n in (C, I)]
compare("spork show (no spork signed on this chain)", *sporks, kind="value")
stop_both()

# 2. Switching the index on: refused without -reindex, built with it
if INJECT == "txindex-refusal":
    starts("restart -txindex=1 without -reindex", "-txindex=1", iron_args=("-txindex=1", "-reindex"))
    I.stop()
else:
    starts("restart -txindex=1 without -reindex", "-txindex=1")
starts("restart -txindex=1 -reindex", "-txindex=1", "-reindex")
need(C.proc and I.proc, "a node did not start with -reindex")
kept_height("-txindex=1 -reindex")
lookups("-txindex=1 after -reindex")
compare("spork show after a restart", *[n.call("spork", "show") for n in (C, I)], kind="value")
row("spork show after a restart is the one before it",
    C.call("spork", "show") == sporks[0], I.call("spork", "show") == sporks[1],
    (C.call("spork", "show") == sporks[0]) == (I.call("spork", "show") == sporks[1]))
stop_both()

# 3. The index stays on across a plain restart, and -txindex defaults to on
starts("restart with -txindex left at its default (on)")
need(C.proc and I.proc, "a node did not restart")
kept_height("default -txindex")
lookups("default -txindex")
stop_both()

# 4. Switching it off: refused without -reindex, done with it
starts("restart -txindex=0 without -reindex", "-txindex=0")
starts("restart -txindex=0 -reindex", "-txindex=0", "-reindex")
need(C.proc and I.proc, "a node did not start with -txindex=0 -reindex")
kept_height("-txindex=0 -reindex")
lookups("-txindex=0 after -reindex")
stop_both()
starts("restart with -txindex left at its default after it was switched off")
stop_both()

# 5. -minrelaytxfee: amounts not above zero, or not amounts, stop the start
for value in ("0", "0.0", "abc", "-0.0001"):
    starts(f"start -minrelaytxfee={value}", "-txindex=0", f"-minrelaytxfee={value}")
    stop_both()

# A floor of 1500 satoshis per kB: a one-in one-out tx of about 190 bytes needs
# about 285. Kept per kB, not rounded to whole satoshis per byte.
starts("start -minrelaytxfee=0.000015", "-txindex=0", "-minrelaytxfee=0.000015")
need(C.proc and I.proc, "a node did not start with -minrelaytxfee=0.000015")
kept_height("-minrelaytxfee=0.000015")
compare("-minrelaytxfee=0.000015: getnetworkinfo relayfee",
        *[("ok", n.rpc("getnetworkinfo").get("relayfee")) for n in (C, I)], kind="value")
compare("-minrelaytxfee=0.000015: getinfo relayfee",
        *[("ok", n.rpc("getinfo").get("relayfee")) for n in (C, I)], kind="value")
under = [spend(n, n.tx["small"][0], 200, n.tx["addr"])[0] for n in (C, I)]
compare("-minrelaytxfee=0.000015: sendrawtransaction paying 200 satoshis", *under, kind="txid")
over = [spend(n, n.tx["small"][1], 400, n.tx["addr"])[0] for n in (C, I)]
compare("-minrelaytxfee=0.000015: sendrawtransaction paying 400 satoshis", *over, kind="txid")
stop_both()

# 6. -sporkkey with a key made here: it is not the regtest spork key
wif = b58check(bytes([239]) + secrets.token_bytes(32) + b"\x01")
for n in (C, I):
    n.write_conf([f"sporkkey={wif}"])
del wif
starts("start -sporkkey=<a key that is not the spork key>", "-txindex=0")
stop_both()
for n in (C, I):
    n.write_conf()
not_run("spork set on regtest and kept across a restart",
        "regtest uses testnet's spork key (divi/src/chainparams.cpp:443, CRegTestParams derives from "
        "CTestNetParams at :457) and its private key is not public, so no spork can be signed here; "
        "covered by crates/divi-node/tests/spork_restart.rs")

# 7. The chain after all restarts, then irondivid's --export-chain
starts("restart after the refused starts", "-txindex=0")
need(C.proc and I.proc, "a node did not restart")
kept_height("after the refused starts")
height = I.rpc("getblockcount")
hashes = [I.rpc("getblockhash", h) for h in range(height + 1)]
stop_both()


def listing(top):
    """Every file and its size and time, outside chainstate/: opening the chain
    database lets the database replay its own log there, as a node start does"""
    out = []
    for d, dirs, files in os.walk(top):
        if d == top and "chainstate" in dirs:
            dirs.remove("chainstate")
        for f in files:
            p = os.path.join(d, f)
            st = os.stat(p)
            out.append((os.path.relpath(p, top), st.st_size, st.st_mtime_ns))
    return sorted(out)


def export(datadir, start, end, outdir, *extra):
    p = subprocess.run([IRONDIVID, f"-datadir={datadir}", *extra, "--export-chain",
                        "--export-start", str(start), "--export-end", str(end), "--export-output", outdir],
                       cwd=WORK, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return p.returncode, p.stderr.decode(errors="replace")


before = listing(I.dir)
out = os.path.join(WORK, "export")
code, err = export(I.dir, 0, height, out)
iron_row("--export-chain 0..tip of a synced datadir: exit code", 0, code)
got = []
for h in range(height + 1):
    try:
        with open(os.path.join(out, "blocks", f"{h:08}.json")) as f:
            got.append(json.load(f)["hash"])
    except (OSError, ValueError, KeyError):
        got.append(None)
iron_row("--export-chain: one file per height, each the node's block hash",
         f"{height + 1} blocks match", f"{sum(a == b for a, b in zip(got, hashes))} blocks match")
try:
    with open(os.path.join(out, "manifest.json")) as f:
        m = json.load(f)
    m = {k: m.get(k) for k in ("chain", "block_count", "tip_hash", "export_complete")}
except (OSError, ValueError):
    m = "no manifest.json"
iron_row("--export-chain: manifest", {"chain": "regtest", "block_count": height + 1, "tip_hash": hashes[-1],
                                      "export_complete": True}, m)
iron_row("--export-chain: nothing written into the datadir outside chainstate/, no blocks/ folder",
         "unchanged, no blocks/",
         f"{'unchanged' if listing(I.dir) == before else 'changed'}, "
         f"{'blocks/ made' if os.path.exists(os.path.join(I.dir, 'blocks')) else 'no blocks/'}")

past = os.path.join(WORK, "past")
code, err = export(I.dir, 0, height + 1, past)
iron_row("--export-chain past the tip: refused, nothing written",
         "exit 1, 'above the chain height', no output",
         f"exit {code}, {repr('above the chain height') if 'above the chain height' in err else 'other error'}, "
         f"{'output made' if os.path.exists(past) else 'no output'}")

empty = os.path.join(WORK, "empty")
os.makedirs(empty)
nothing = os.path.join(WORK, "nothing")
code, err = export(empty, 0, 10, nothing, "-regtest")
named = f"No chain database in {os.path.join(empty, 'chainstate')}" in err
iron_row("--export-chain of an empty datadir: refused, names chainstate/, writes nothing",
         "exit 1, names chainstate/, datadir empty, no output",
         f"exit {code}, {'names chainstate/' if named else 'other error'}, "
         f"{'datadir empty' if not os.listdir(empty) else 'datadir written'}, "
         f"{'output made' if os.path.exists(nothing) else 'no output'}")

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
