#!/usr/bin/env python3
"""Compare irondivid's mining and mempool RPC replies with Divi Core 3.0.0's
divid on regtest. Both nodes share one chain and one mempool; each call is made
on both and printed as one row: SAME, DIFFERS (with both replies) or ABSENT
(divid answers, irondivid does not have the method). A wrong argument count
is answered with the method's help in both; those replies are SAME when the
code and the usage line agree. A DIFFERS row that is a difference kept on
purpose names its row of docs/divid-differences.md. The exit code is the
number of rows that are neither SAME nor kept.

Usage: compare.py <irondivid> <divid-bin-dir> <port-base> <workdir>"""
import base64
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVI_BIN, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
CORE, IRON = PORT_BASE, PORT_BASE + 2
AUTH = "Basic " + base64.b64encode(b"test:test").decode()
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# A coinstake (vin[0] not null, vout[0] empty, two outputs or more) nobody can
# sign a block for: its second output is OP_TRUE
COINSTAKE = ("01000000" "01" + "22" * 32 + "00000000" "00" "ffffffff"
             "02" "0000000000000000" "00" "00e1f50500000000" "01" "51" "00000000")


def call(port, method, params):
    """(result, error) of one call; error is {"code", "message"} or None"""
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", body, {"Authorization": AUTH})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            reply = json.load(r)
    except urllib.error.HTTPError as e:
        reply = json.load(e)
    except (OSError, http.client.HTTPException) as e:
        return None, {"code": None, "message": f"no reply ({type(e).__name__})"}
    return reply.get("result"), reply.get("error")


def rpc(port, method, *params):
    result, error = call(port, method, list(params))
    if error:
        raise RuntimeError(f"{port} {method} {params}: {error}")
    return result


def wait(what, check, secs=180):
    end = time.time() + secs
    while time.time() < end:
        try:
            if check():
                return
        except Exception:
            pass
        time.sleep(1)
    sys.exit(f"timed out: {what}")


def kind(v):
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object", type(None): "null"}[type(v)]


def differences(a, b, path="result"):
    """Where b (irondivid) differs from a (divid): names, types, then values"""
    if kind(a) != kind(b):
        return [f"{path}: {kind(a)} vs {kind(b)}"]
    if isinstance(a, dict):
        out = [f"{path}.{k}: only in divid" for k in sorted(a.keys() - b.keys())]
        out += [f"{path}.{k}: only in irondivid" for k in sorted(b.keys() - a.keys())]
        for k in sorted(a.keys() & b.keys()):
            out += differences(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{path}: {len(a)} items vs {len(b)}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += differences(x, y, f"{path}[{i}]")
        return out
    return [] if a == b else [f"{path}: {json.dumps(a)} vs {json.dumps(b)}"]


def hashes(v):
    """A block hash, or a list of them, as a placeholder: each node mines its own"""
    if isinstance(v, str) and HEX64.match(v):
        return "<block hash>"
    if isinstance(v, list):
        return [hashes(x) for x in v]
    return v


def mempool_view(v):
    """Txid lists in a set order (divid's map order is not meaningful); entry
    times are each node's own clock"""
    if isinstance(v, list):
        return sorted(v)
    if isinstance(v, dict):
        return {t: {k: x for k, x in e.items() if k != "time"} if isinstance(e, dict) else e
                for t, e in v.items()}
    return v


ROWS = []
NOTES = []

# Differences kept on purpose, each a row of docs/divid-differences.md
KEPT = {
    "getmempoolinfo []": "R13",
    f'generateblock [{{"coinstake": "{COINSTAKE}"}}] (proof of stake)': "R14",
}


def same_usage(method, a, b):
    """A wrong argument count is answered with the method's help, whose
    wording is each program's own: the replies agree when both start with the
    same usage line"""
    if not (a and b and "\n" in a and "\n" in b):
        return False
    usage = a.split("\n", 1)[0]
    return usage.startswith(method) and usage == b.split("\n", 1)[0]


def synced():
    wait("same tip", lambda: rpc(CORE, "getbestblockhash") == rpc(IRON, "getbestblockhash"))


def row(method, params, norm=lambda v: v, mines=False, iron_params=None, label=""):
    """`mines`: each node mines in turn, after the other's block reached it.
    `iron_params`: what irondivid is given instead, where each node needs its
    own (a transaction only one block can hold)"""
    core = call(CORE, method, params)
    if mines:
        synced()
    iron = call(IRON, method, params if iron_params is None else iron_params)
    if mines:
        synced()
    label = f"{method} {json.dumps(params)}{label}"
    core_err, iron_err = core[1], iron[1]
    if iron_err and iron_err.get("code") == -32601 and not (core_err and core_err.get("code") == -32601):
        ROWS.append(("ABSENT", label, core, iron, []))
        return
    if core_err or iron_err:
        same = bool(core_err and iron_err) and core_err.get("code") == iron_err.get("code") \
            and (core_err.get("message") == iron_err.get("message")
                 or same_usage(method, core_err.get("message"), iron_err.get("message")))
        why = [] if same else [f"error: {json.dumps(core_err)} vs {json.dumps(iron_err)}"]
    else:
        why = differences(norm(core[0]), norm(iron[0]))
    if why and label in KEPT:
        why.append(f"kept: docs/divid-differences.md {KEPT[label]}")
    ROWS.append(("SAME" if not why else "DIFFERS", label, core, iron, why))




# --- nodes ---------------------------------------------------------------
os.makedirs(f"{WORK}/core")
os.makedirs(f"{WORK}/iron")
with open(f"{WORK}/core/divi.conf", "w") as f:
    f.write("rpcuser=test\nrpcpassword=test\n")
pids = open(f"{WORK}/pids", "a")


def start(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pids.write(f"{p.pid}\n")
    pids.flush()
    return p


def start_core():
    p = start([f"{DIVI_BIN}/divid", "-regtest", f"-datadir={WORK}/core", f"-port={CORE + 1}",
               f"-rpcport={CORE}", "-listen=1", "-bind=127.0.0.1", "-server=1",
               "-printtoconsole=0"])
    wait("divid RPC", lambda: rpc(CORE, "getblockcount") >= 0)
    return p


core_proc = start_core()
rpc(CORE, "setgenerate", 30)
start([IRONDIVID, "--regtest", "--datadir", f"{WORK}/iron", "--rpcport", str(IRON),
       "--port", str(IRON + 1), "--bind", "127.0.0.1", "--staking=false",
       "--connect", f"127.0.0.1:{CORE + 1}", "--rpcuser", "test", "--rpcpassword", "test"])
wait("irondivid at 30", lambda: rpc(IRON, "getblockcount") == 30)
synced()

# --- one mempool on both: coin ages 1..9, fees from 3,000 sat to 0.5 DIVI, a
# chained child, one prioritised ----------------------------------------------
unspent = rpc(CORE, "listunspent")


def coin_at(height):
    u = next(u for u in unspent if u["confirmations"] == 31 - height)
    return u["txid"], u["vout"], round(u["amount"] * 1e8)


def spend(coin, fee):
    to = rpc(CORE, "getnewaddress")
    raw = rpc(CORE, "createrawtransaction", [{"txid": coin[0], "vout": coin[1]}],
              {to: round((coin[2] - fee) / 1e8, 8)})
    return rpc(CORE, "sendrawtransaction", rpc(CORE, "signrawtransaction", raw)["hex"])


txs = [spend(coin_at(1), 3_000), spend(coin_at(2), 4_000), spend(coin_at(9), 1_000_000)]
parent = spend(coin_at(7), 3_000)
value = round(rpc(CORE, "getrawtransaction", parent, 1)["vout"][0]["value"] * 1e8)
child = spend((parent, 0, value), 50_000_000)
prioritised = spend(coin_at(8), 3_000)
txs += [parent, child, prioritised]
wait("irondivid mempool", lambda: set(rpc(IRON, "getrawmempool")) == set(txs))
unknown = "11" * 32


USED = set()


def signed_tx(_node=None):
    """A transaction of divid's wallet, signed and not sent, each from another
    mature coin, so each block that takes one is valid"""
    coin = next(u for u in sorted(rpc(CORE, "listunspent"), key=lambda u: -u["confirmations"])
                if u["confirmations"] >= 21 and (u["txid"], u["vout"]) not in USED)
    USED.add((coin["txid"], coin["vout"]))
    to = rpc(CORE, "getnewaddress")
    raw = rpc(CORE, "createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}],
              {to: round(coin["amount"] - 0.001, 8)})
    return rpc(CORE, "signrawtransaction", raw)["hex"]



# --- calls ---------------------------------------------------------------
row("getmininginfo", [])
row("getmininginfo", ["x"])
row("getmempoolinfo", [])
row("getmempoolinfo", [1])
row("getrawmempool", [], mempool_view)
row("getrawmempool", [False], mempool_view)
row("getrawmempool", [True], mempool_view)
row("getrawmempool", [1], mempool_view)
row("getrawmempool", ["true"], mempool_view)
row("getrawmempool", [True, 1], mempool_view)
row("prioritisetransaction", [prioritised, 0.0, 100_000_000_000_000])
row("prioritisetransaction", [unknown, 5.5, 1000])
row("prioritisetransaction", [prioritised])
row("prioritisetransaction", [prioritised, 0.0])
row("prioritisetransaction", ["zz", 0.0, 1000])
row("prioritisetransaction", [prioritised, 0.0, "1000"])
row("prioritisetransaction", [prioritised, "x", 1000])
row("prioritisetransaction", [prioritised, 0.0, 1000, 1])
row("getrawmempool", [True], mempool_view)
for absent in ("getblocktemplate", "getnetworkhashps", "generate", "getblocksubsidy",
               "getblockpayments", "submitblock", "getgenerate", "gethashespersec"):
    row(absent, [])
row("setgenerate", [])
row("setgenerate", [0])
row("setgenerate", [-1])
row("setgenerate", ["1"])
row("setgenerate", [True])
row("setgenerate", [1, 1])
# Mines one block on each node in turn; the other follows before the next call
row("setgenerate", [1], hashes, mines=True)
row("getmininginfo", [])
row("getmempoolinfo", [])
row("generateblock", ["x"], hashes)
row("generateblock", [{}, 1], hashes)
row("generateblock", [{"extratx": "x"}], hashes)
row("generateblock", [{"coinstake": "zz"}], hashes)
row("generateblock", [{"extratx": ["zz"]}], hashes)
row("generateblock", [{"extratx": [1]}], hashes)
row("generateblock", [{"ignoreMempool": 1}], hashes)
row("generateblock", [{"blockBitsShift": 1.5}], hashes)
row("generateblock", [{"coinstake": signed_tx(CORE)}], hashes)
row("generateblock", [{"blockBitsShift": 0}], hashes, mines=True)
row("generateblock", [{"blockBitsShift": 1}], hashes, mines=True)
row("generateblock", [{"extratx": [signed_tx(CORE)]}], hashes, mines=True,
    iron_params=[{"extratx": [signed_tx(IRON)]}])
row("generateblock", [{"extratx": [signed_tx(CORE)], "ignoreMempool": True}], hashes, mines=True,
    iron_params=[{"extratx": [signed_tx(IRON)], "ignoreMempool": True}])
row("generateblock", [{}], hashes, mines=True)
row("generateblock", [], hashes, mines=True)
row("generateblock", [{"ignoreMempool": True}], hashes, mines=True)
row("setgenerate", [2], hashes, mines=True)
row("getmininginfo", [])

# A custom coinstake on a proof-of-work block: divid stops answering here. It
# is started again on the same data directory for the rest of the run
row("generateblock", [{"coinstake": COINSTAKE}], hashes)
time.sleep(5)
if core_proc.poll() is not None:
    NOTES.append(f"divid exited (code {core_proc.returncode}) after generateblock with a custom "
                 "coinstake on a proof-of-work block; started again on the same data directory")
    core_proc = start_core()
synced()
row("getblockcount", [])

# --- past the last proof-of-work block: irondivid's coins from the blocks it
# mined above are mature by then ----------------------------------------------
rpc(CORE, "setgenerate", 105 - rpc(CORE, "getblockcount"))
synced()
row("setgenerate", [1], hashes, mines=True)
row("generateblock", [], hashes, mines=True)
row("generateblock", [{"ignoreMempool": True}], hashes, mines=True)
row("generateblock", [{"blockBitsShift": 0}], hashes, mines=True)
row("generateblock", [{"blockBitsShift": 1}], hashes, mines=True)
row("generateblock", [{"extratx": [signed_tx(CORE)]}], hashes, mines=True,
    iron_params=[{"extratx": [signed_tx(IRON)]}])
row("getmininginfo", [])
# Last, in case divid stops answering here too
row("generateblock", [{"coinstake": COINSTAKE}], hashes, label=" (proof of stake)")
time.sleep(5)
if core_proc.poll() is not None:
    NOTES.append(f"divid exited (code {core_proc.returncode}) after generateblock with a custom "
                 "coinstake on a proof-of-stake block")

# --- table ---------------------------------------------------------------
for status, label, core, iron, why in ROWS:
    print(f"{status:8} {label}")
    if status != "SAME":
        for w in why:
            print(f"           {w}")
        print(f"           divid:     {json.dumps(core[1] or core[0])[:400]}")
        print(f"           irondivid: {json.dumps(iron[1] or iron[0])[:400]}")
for n in NOTES:
    print(f"note: {n}")
counts = {s: sum(1 for r in ROWS if r[0] == s) for s in ("SAME", "DIFFERS", "ABSENT")}
kept = sum(1 for r in ROWS if r[1] in KEPT and r[0] == "DIFFERS")
print(f"\n{len(ROWS)} calls: " + ", ".join(f"{n} {s}" for s, n in counts.items())
      + f" ({kept} of the DIFFERS kept on purpose)")
# The exit code counts what is neither the same nor a kept difference
sys.exit(min(counts["DIFFERS"] - kept + counts["ABSENT"], 254))
