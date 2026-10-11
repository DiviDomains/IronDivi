#!/usr/bin/env python3
"""RPC parity harness: call the same RPCs on a C++ divid and an irondivid, diff the results.

Runs on a host that can reach both nodes (stdlib only). Reads credentials from the
nodes' conf files, never prints them. Mutating methods are only ever called with
deliberately invalid arguments (error-path comparison), never with real values.

    rpc_parity.py --cpp-conf ~/.divi-testnet/divi.conf --cpp-port 51475 \
                  --rust-conf ~/divi-audit/irondivi.conf --rust-port 52800 --out parity.json

Per call it records: ok/error on each side, error codes, and a structural signature
(keys + JSON types, recursively). For deterministic read-only calls it also compares
values exactly. `report.py` turns the JSON into the markdown matrix.
"""
import argparse
import base64
import json
import sys
import urllib.request


def read_conf(path):
    cfg = {}
    for line in open(path):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"')
    return cfg


class Node:
    def __init__(self, conf, port, name):
        c = read_conf(conf)
        self.url = f"http://127.0.0.1:{port}/"
        tok = base64.b64encode(f"{c.get('rpcuser','')}:{c.get('rpcpassword','')}".encode()).decode()
        self.hdr = {"Authorization": "Basic " + tok, "Content-Type": "application/json"}
        self.name = name

    def call(self, method, params):
        body = json.dumps({"jsonrpc": "1.0", "id": "p", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, self.hdr)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:  # divid answers errors with HTTP 4xx/5xx + JSON body
            try:
                d = json.loads(e.read().decode())
            except Exception:
                return {"ok": False, "code": f"http{e.code}", "msg": str(e)}
        except Exception as e:  # connection problems, timeouts
            return {"ok": False, "code": "transport", "msg": str(e)}
        if d.get("error"):
            return {"ok": False, "code": d["error"].get("code"), "msg": d["error"].get("message", "")[:200]}
        return {"ok": True, "result": d.get("result")}


def sig(v):
    """Structural signature: dict -> {key: sig}, list -> [sig of first element], scalar -> type."""
    if isinstance(v, dict):
        return {k: sig(x) for k, x in sorted(v.items())}
    if isinstance(v, list):
        return [sig(v[0])] if v else []
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if v is None:
        return "null"
    return "str"


def diff_sig(a, b, path=""):
    """Differences between C++ signature a and Rust signature b."""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in a:
            if k not in b:
                out.append(f"missing in Rust: {path}{k}")
            else:
                out += diff_sig(a[k], b[k], f"{path}{k}.")
        for k in b:
            if k not in a:
                out.append(f"extra in Rust: {path}{k}")
    elif isinstance(a, list) and isinstance(b, list):
        if a and b:
            out += diff_sig(a[0], b[0], f"{path}[].")
        # an empty list on either side carries no shape information
    elif a != b:
        # int vs float is a real difference for JSON consumers; report it
        out.append(f"type {path.rstrip('.') or '<root>'}: C++ {json.dumps(a)} vs Rust {json.dumps(b)}")
    return out


# method -> (kind, [arg sets]).  kind: "read" = compare shape (+value if exact), "exact" = values must
# match, "mutating" = only invalid-arg error path is exercised.  {…} placeholders come from fixtures.
READ = {
    "getinfo": [[]], "help": [[], ["getblock"]], "getnetworkinfo": [[]], "getconnectioncount": [[]],
    "getnettotals": [[]], "getpeerinfo": [[]], "getaddednodeinfo": [[True], [True, "1.2.3.4"]],
    "listbanned": [[]], "ping": [[]],
    "getblockchaininfo": [[]], "getblockcount": [[]], "getbestblockhash": [[]], "getdifficulty": [[]],
    "getchaintips": [[]], "getmempoolinfo": [[]], "getrawmempool": [[], [True]],
    "gettxoutsetinfo": [[]], "getlotteryblockwinners": [[], [1000]], "verifychain": [[0, 1]],
    "getmininginfo": [[]],
    "getblockhash": [[1000], [0]],
    "getblock": [["{HASH1}"], ["{HASH1}", True], ["{HASH1}", False], ["{HASH1}", 2]],
    "getblockheader": [["{HASH1}"], ["{HASH1}", False]],
    "gettxout": [["{TXID1}", 0], ["{TXID1}", 0, True]],
    "getrawtransaction": [["{TXID1}"], ["{TXID1}", 1], ["{TXID1}", True]],
    "decoderawtransaction": [["{RAWTX1}"]],
    "decodescript": [["{SCRIPT1}"]],
    "validateaddress": [["{ADDR1}"], ["notanaddress"]],
    "createmultisig": [[1, ["{PUBKEY1}"]]],
    "verifymessage": [["{ADDR1}", "AAAA", "hello"]],
    "getmasternodecount": [[]], "getmasternodestatus": [[]], "getmasternodewinners": [[], [5]],
    "listmasternodes": [[], ["xyzzy"]], "listmnbroadcasts": [[]], "spork": [["show"], ["active"]],
    "mnsync": [["status"]],
    # verifymasternodesetup is NOT called: on C++ divid 3.0.0 it trips an assert in CRPCTable::execute and aborts the daemon.
    "getwalletinfo": [[]], "getbalance": [[], ["*"], ["*", 1]], "getunconfirmedbalance": [[]],
    "getnewaddress": [[]], "getrawchangeaddress": [[]], "getstakingstatus": [[]],
    "listunspent": [[], [0, 9999999]], "listtransactions": [[], ["*", 5]],
    "listsinceblock": [[], ["{HASH1}"]], "listaccounts": [[], [0]],
    "listreceivedbyaddress": [[], [0, True]], "listreceivedbyaccount": [[], [0, True]],
    "listlockunspent": [[]], "getcoinavailability": [[]], "gettransaction": [["{TXID1}"]],
    "getreceivedbyaddress": [["{ADDR1}"]], "getaccount": [["{ADDR1}"]],
    "getaddressesbyaccount": [[""]], "getaccountaddress": [[""]], "getreceivedbyaccount": [[""]],
}

# Mutating/dangerous: called ONLY with a bogus argument so the call fails validation, never executes.
MUTATING = [
    "addnode", "ban", "clearbanned_SKIP", "stop_SKIP", "setgenerate", "prioritisetransaction",
    "invalidateblock", "reconsiderblock", "setmocktime", "reverseblocktransactions",
    "createrawtransaction", "sendrawtransaction", "signrawtransaction", "signtransactionwithaddresskey_SKIP",  # C++ 3.0.0 daemon dies on a no-arg call (silent exit, no assert text)
   
    "addmultisigaddress", "addvault", "removevault", "fundvault", "debitvaultbyname", "reclaimvaultfunds",
    "backupwallet", "bip38decrypt", "bip38paperwallet", "dumpprivkey", "encryptwallet", "importaddress",
    "importprivkey", "keypoolrefill_SKIP", "loadwallet", "lockunspent", "sendfrom", "sendmany",
    "sendtoaddress", "setaccount", "signmessage", "walletpassphrase", "walletpassphrasechange",
    "broadcaststartmasternode", "importmnbroadcast", "setupmasternode", "signmnbroadcast", "startmasternode",
]


def subst(v, fx):
    if isinstance(v, str) and v.startswith("{") and v.endswith("}"):
        return fx[v[1:-1]]
    if isinstance(v, list):
        return [subst(x, fx) for x in v]
    return v


def fixtures(cpp):
    fx = {}
    h1 = cpp.call("getblockhash", [1000])["result"]
    blk = cpp.call("getblock", [h1])["result"]
    fx["HASH1"] = h1
    txid = blk["tx"][0]
    fx["TXID1"] = txid
    raw = cpp.call("getrawtransaction", [txid])
    fx["RAWTX1"] = raw["result"] if raw["ok"] else "00"
    dec = cpp.call("decoderawtransaction", [fx["RAWTX1"]])["result"]
    vout = dec["vout"][-1]["scriptPubKey"]
    fx["SCRIPT1"] = vout["hex"]
    fx["ADDR1"] = (vout.get("addresses") or ["notanaddress"])[0]
    pk = cpp.call("validateaddress", [fx["ADDR1"]])
    fx["PUBKEY1"] = ((pk["result"] or {}).get("pubkey")) or "02" + "11" * 32
    return fx


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpp-conf", required=True)
    ap.add_argument("--cpp-port", required=True, type=int)
    ap.add_argument("--rust-conf", required=True)
    ap.add_argument("--rust-port", required=True, type=int)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    cpp, rust = Node(a.cpp_conf, a.cpp_port, "cpp"), Node(a.rust_conf, a.rust_port, "rust")
    fx = fixtures(cpp)
    rows = []

    def record(method, kind, args):
        c, r = cpp.call(method, args), rust.call(method, args)
        row = {"method": method, "kind": kind, "args": args, "cpp_ok": c["ok"], "rust_ok": r["ok"]}
        if c["ok"] and r["ok"]:
            row["diffs"] = diff_sig(sig(c["result"]), sig(r["result"]))
            row["value_equal"] = c["result"] == r["result"]
            if not row["value_equal"]:
                row["cpp_sample"] = json.dumps(c["result"])[:400]
                row["rust_sample"] = json.dumps(r["result"])[:400]
            if c["result"] in ([], {}, None, "") or r["result"] in ([], {}, None, ""):
                row["shape_unverified"] = True
        else:
            row["cpp_err"] = None if c["ok"] else [c["code"], c["msg"]]
            row["rust_err"] = None if r["ok"] else [r["code"], r["msg"]]
        rows.append(row)

    for method, argsets in READ.items():
        for args in argsets:
            record(method, "read", subst(args, fx))
    for method in MUTATING:
        if method.endswith("_SKIP"):
            continue
        record(method, "mutating-badargs", ["__bad__"])
        record(method, "mutating-noargs", [])
    json.dump({"fixtures": {k: v[:80] for k, v in fx.items()}, "rows": rows}, open(a.out, "w"), indent=1)
    print(f"wrote {len(rows)} rows to {a.out}")


if __name__ == "__main__":
    sys.exit(main())
