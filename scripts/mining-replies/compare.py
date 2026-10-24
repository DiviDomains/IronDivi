#!/usr/bin/env python3
"""Compare irondivid's mining and mempool RPC replies with Divi Core 3.0.0's
divid on regtest. Both nodes share one chain and one mempool; each call is made
on both and printed as one row: SAME, DIFFERS (with both replies) or ABSENT
(divid answers, irondivid does not have the method). The exit code is the
number of rows that are not SAME.

Usage: compare.py <irondivid> <divid-bin-dir> <port-base> <workdir>"""
import base64
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


def call(port, method, params):
    """(result, error) of one call; error is {"code", "message"} or None"""
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", body, {"Authorization": AUTH})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            reply = json.load(r)
    except urllib.error.HTTPError as e:
        reply = json.load(e)
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


def synced():
    wait("same tip", lambda: rpc(CORE, "getbestblockhash") == rpc(IRON, "getbestblockhash"))


def row(method, params, norm=lambda v: v, mines=False):
    """`mines`: each node mines in turn, after the other's block reached it"""
    core = call(CORE, method, params)
    if mines:
        synced()
    iron = call(IRON, method, params)
    if mines:
        synced()
    label = f"{method} {json.dumps(params)}"
    core_err, iron_err = core[1], iron[1]
    if iron_err and iron_err.get("code") == -32601 and not (core_err and core_err.get("code") == -32601):
        ROWS.append(("ABSENT", label, core, iron, []))
        return
    if core_err or iron_err:
        same = bool(core_err and iron_err) and core_err.get("code") == iron_err.get("code") \
            and core_err.get("message") == iron_err.get("message")
        why = [] if same else [f"error: {json.dumps(core_err)} vs {json.dumps(iron_err)}"]
    else:
        why = differences(norm(core[0]), norm(iron[0]))
    ROWS.append(("SAME" if not why else "DIFFERS", label, core, iron, why))




# --- nodes ---------------------------------------------------------------
os.makedirs(f"{WORK}/core")
os.makedirs(f"{WORK}/iron")
with open(f"{WORK}/core/divi.conf", "w") as f:
    f.write("rpcuser=test\nrpcpassword=test\n")
pids = open(f"{WORK}/pids", "a")
for core, cmd in (
    (True, [f"{DIVI_BIN}/divid", "-regtest", f"-datadir={WORK}/core", f"-port={CORE + 1}",
     f"-rpcport={CORE}", "-listen=1", "-bind=127.0.0.1", "-server=1", "-printtoconsole=0"]),
    (False, [IRONDIVID, "--regtest", "--datadir", f"{WORK}/iron", "--rpcport", str(IRON),
     "--port", str(IRON + 1), "--bind", "127.0.0.1", "--staking=false",
     "--connect", f"127.0.0.1:{CORE + 1}", "--rpcuser", "test", "--rpcpassword", "test"]),
):
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pids.write(f"{p.pid}\n")
    pids.flush()
    if core:
        wait("divid RPC", lambda: rpc(CORE, "getblockcount") >= 0)
        rpc(CORE, "setgenerate", 30)
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
row("generateblock", [{}], hashes, mines=True)
row("generateblock", [], hashes, mines=True)
row("generateblock", [{"ignoreMempool": True}], hashes, mines=True)
row("setgenerate", [2], hashes, mines=True)
row("getmininginfo", [])

# --- table ---------------------------------------------------------------
for status, label, core, iron, why in ROWS:
    print(f"{status:8} {label}")
    if status != "SAME":
        for w in why:
            print(f"           {w}")
        print(f"           divid:     {json.dumps(core[1] or core[0])[:400]}")
        print(f"           irondivid: {json.dumps(iron[1] or iron[0])[:400]}")
counts = {s: sum(1 for r in ROWS if r[0] == s) for s in ("SAME", "DIFFERS", "ABSENT")}
print(f"\n{len(ROWS)} calls: " + ", ".join(f"{n} {s}" for s, n in counts.items()))
sys.exit(min(counts["DIFFERS"] + counts["ABSENT"], 254))
