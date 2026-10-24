#!/usr/bin/env python3
"""The RPC calls BasicSwap's Divi interface makes, in the order it makes
them, against a fresh regtest irondivid: one PASS/FAIL line per call, the
reply checked for the fields and types BasicSwap reads. Exit code = FAILs.

Started by run.sh, which owns the datadir root and stops the nodes.
Words, passphrases and seeds are never printed.
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request

IRONDIVID, PORT_BASE, WORK = sys.argv[1], int(sys.argv[2]), sys.argv[3]
RPC_TIMEOUT = 60
START_TIMEOUT = 120

fails = 0


def report(ok, name, detail=""):
    global fails
    if not ok:
        fails += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)
    return ok


class RpcError(Exception):
    pass


class Node:
    """A regtest irondivid started the way BasicSwap starts divid
    (basicswap/bin/run.py startDaemon: <bin> -datadir=<dir> [opts], cwd <dir>)"""

    def __init__(self, name, index, extra_conf, args=()):
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.auth = base64.b64encode(f"test{index}:test_pass{index}".encode()).decode()
        os.makedirs(self.dir)
        conf = os.path.join(self.dir, "divi.conf")
        # tests/basicswap/extended/test_divi.py prepareDataDir
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=test{index}", f"rpcpassword=test_pass{index}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0",
            "listenonion=0", "bind=127.0.0.1", "debug=1", "debugexclude=libevent",
            "addressindex=1", "txindex=1",
        ] + list(extra_conf)
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = open(os.path.join(self.dir, "core_stdout.log"), "w")
        self.proc = subprocess.Popen(
            [IRONDIVID, f"-datadir={self.dir}", *args],
            cwd=self.dir, stdout=self.log, stderr=subprocess.STDOUT,
        )
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def post(self, body):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.rpcport}/", data=json.dumps(body).encode(),
            headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            # Core answers RPC errors with HTTP 500 and the JSON body
            return json.loads(e.read())

    def rpc(self, method, params=()):
        # BasicSwap's make_rpc_func sends jsonrpc 1.0 bodies
        reply = self.post({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)})
        if reply.get("error"):
            raise RpcError(f"{reply['error'].get('code')} {reply['error'].get('message', '')[:80]}")
        return reply.get("result")

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                self.rpc("getblockchaininfo")
                return True
            except Exception:
                time.sleep(0.5)
        return False

    def stop(self):
        try:
            self.rpc("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()
        return self.proc.returncode


# --- reply shapes -------------------------------------------------------------

def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_num(v):
    return (isinstance(v, (int, float))) and not isinstance(v, bool)


def is_hex64(v):
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def is_hex(v):
    return isinstance(v, str) and len(v) > 0 and len(v) % 2 == 0 and all(c in "0123456789abcdef" for c in v)


TYPES = {"int": is_int, "num": is_num, "str": lambda v: isinstance(v, str),
         "hex64": is_hex64, "hex": is_hex, "bool": lambda v: isinstance(v, bool),
         "list": lambda v: isinstance(v, list), "dict": lambda v: isinstance(v, dict)}


def shape(obj, fields):
    """None if obj has every field with its type, else what is wrong"""
    if not isinstance(obj, dict):
        return f"not an object: {type(obj).__name__}"
    for key, t in fields.items():
        if key not in obj:
            return f"no {key}"
        if not TYPES[t](obj[key]):
            return f"{key} is {type(obj[key]).__name__}, not {t}"
    return None


def check(name, fn, needs=()):
    """Run one check; fn returns None (pass) or what is wrong. A check that
    needs what an earlier one failed to produce fails as such."""
    missing = [n for n in needs if n not in state]
    if missing:
        return report(False, name, f"needs {', '.join(missing)} from an earlier check")
    try:
        problem = fn()
    except RpcError as e:
        problem = f"error {e}"
    except Exception as e:  # a missing field, a refused connection
        problem = f"{type(e).__name__}: {str(e)[:80]}"
    return report(problem is None, name, problem or "")


def bip39_seed(words, passphrase):
    norm = lambda s: unicodedata.normalize("NFKD", s).encode()
    return hashlib.pbkdf2_hmac("sha512", norm(words), norm("mnemonic" + passphrase), 2048).hex()


# --- the run --------------------------------------------------------------------

state = {}

# 1. New words with -mnemonicpassphrase (Divi Core GenerateNewHDChain): the
#    wallet seed is the words + that passphrase. Started as bin/prepare.py
#    initialise_wallets starts divid.
passphrase = secrets.token_hex(16)
seeder = Node("seeder", 0, [f"mnemonicpassphrase={passphrase}"],
              ["-noconnect", "-nodnsseed", "-nolisten"])
if report(seeder.wait_ready(), "start: -noconnect -nodnsseed -nolisten, mnemonicpassphrase= only"):
    def passphrase_start():
        hd = seeder.rpc("dumphdinfo")
        bad = shape(hd, {"mnemonic": "str", "mnemonicpassphrase": "str", "hdseed": "str"})
        if bad:
            return bad
        # Kept whatever the result: the swap node is seeded from these words
        # and pays this wallet's address
        state["words"] = hd["mnemonic"]
        state["foreign_addr"] = seeder.rpc("getnewaddress")
        if len(hd["mnemonic"].split()) != 24:
            return "not 24 new words"
        if hd["mnemonicpassphrase"] != passphrase:
            return "the wallet does not carry the passphrase"
        if hd["hdseed"] != bip39_seed(hd["mnemonic"], passphrase):
            return "seed is not words + passphrase"
        return None
    check("dumphdinfo: new words + -mnemonicpassphrase make the seed", passphrase_start)
    check("getconnectioncount: 0 with -noconnect", lambda: None if seeder.rpc("getconnectioncount") == 0 else "connected")
seeder.stop()

# 2. The swap node: prepareDataDir's divi.conf plus the seed prepare.py
#    writes as mnemonic= (interface/divi/core.py getWalletInitDaemonArgs)
words = state.get("words")
node = Node("node", 1, [f"mnemonic={words}"] if words else [])
if not report(node.wait_ready(), "start: irondivid -datadir=<dir> with BasicSwap's divi.conf"):
    print(f"FAILS {fails + 1}")
    sys.exit(fails + 1)


def network_info():
    # divid's version is CLIENT_VERSION_STR, a string (rpcnet.cpp:369)
    r = node.rpc("getnetworkinfo")
    return shape(r, {"version": "str", "relayfee": "num"}) or (
        None if r["relayfee"] >= 0.0001 else f"relayfee {r['relayfee']} < 0.0001")


def blockchain_info():
    r = node.rpc("getblockchaininfo")
    bad = shape(r, {"chain": "str", "blocks": "int", "headers": "int", "bestblockhash": "hex64"})
    if bad:
        return bad
    if "verificationprogress" in r and not is_num(r["verificationprogress"]):
        return "verificationprogress is not a number"
    return None if r["headers"] >= r["blocks"] else "headers < blocks"


def wallet_info_unencrypted():
    r = node.rpc("getwalletinfo")
    return shape(r, {"balance": "num"}) or (
        "unlocked_until on an unencrypted wallet" if "unlocked_until" in r else None)


def seed_id():
    hd = node.rpc("dumphdinfo")
    if not isinstance(hd.get("mnemonic"), str):
        return "no mnemonic"
    return None if words and hd["mnemonic"] == words else "the wallet is not the divi.conf mnemonic"


check("getnetworkinfo: version (divid: a string), relayfee >= 0.0001", network_info)
check("getblockchaininfo: chain, blocks, headers, bestblockhash", blockchain_info)
check("getwalletinfo: balance, no unlocked_until (unencrypted)", wallet_info_unencrypted)
check("listlockunspent: array", lambda: None if isinstance(node.rpc("listlockunspent"), list) else "not an array")
check("dumphdinfo: the mnemonic= seed (checkExpectedSeed)", seed_id)


def generate(n):
    def f():
        r = node.rpc("setgenerate", [n])
        if not isinstance(r, list) or len(r) != n or not all(is_hex64(h) for h in r):
            return f"not {n} block hashes: {str(r)[:60]}"
        state[f"mined{n}"] = True
        return None
    return f


check("setgenerate 101: 101 block hashes", generate(101))
check("getblockcount: 101", lambda: None if node.rpc("getblockcount") == 101 else f"{node.rpc('getblockcount')}")
check("getwalletinfo: spendable balance > 0", lambda: None if node.rpc("getwalletinfo")["balance"] > 0 else "no balance",
      needs=["mined101"])


def new_address():
    a = node.rpc("getnewaddress")
    if not isinstance(a, str):
        return "not a string"
    v = node.rpc("validateaddress", [a])
    state["addr"] = a
    return shape(v, {"isvalid": "bool", "ismine": "bool"}) or (None if v["ismine"] else "not ismine")


check("getnewaddress + validateaddress: ismine", new_address)


def smart_fee():
    r = node.rpc("estimatesmartfee", [2])
    return shape(r, {"feerate": "num"}) or (None if r["feerate"] >= 0.0001 else f"feerate {r['feerate']} < 0.0001")


check("estimatesmartfee 2: feerate >= 0.0001", smart_fee)


def unspent():
    r = node.rpc("listunspent")
    if not isinstance(r, list) or not r:
        return "empty"
    for u in r:
        bad = shape(u, {"txid": "hex64", "vout": "int", "amount": "num", "address": "str"})
        if bad:
            return bad
        if "spendable" in u and not isinstance(u["spendable"], bool):
            return "spendable is not bool"
    state["coin"] = max(r, key=lambda u: u["amount"])
    return None


check("listunspent: txid, vout, amount, address", unspent, needs=["mined101"])


def lock_and_check():
    c = state["coin"]
    inp = [{"txid": c["txid"], "vout": c["vout"]}]
    if node.rpc("lockunspent", [False, inp]) is not True:
        return "lockunspent false did not return true"
    out = node.rpc("gettxout", [c["txid"], c["vout"]])
    bad = shape(out, {"value": "num"})
    if bad:
        return f"gettxout {bad}"
    locked = node.rpc("listlockunspent")
    return None if any(l.get("txid") == c["txid"] and l.get("vout") == c["vout"] for l in locked) else "not listed as locked"


check("lockunspent false + gettxout value + listlockunspent", lock_and_check, needs=["coin"])


def raw_send():
    c = state["coin"]
    change = node.rpc("getrawchangeaddress")
    if not isinstance(change, str):
        return "getrawchangeaddress not a string"
    pay = 10.0
    change_amount = round(c["amount"] - pay - 0.001, 8)
    raw = node.rpc("createrawtransaction", [[{"txid": c["txid"], "vout": c["vout"]}],
                                            {state["addr"]: pay, change: change_amount}])
    if not is_hex(raw):
        return "createrawtransaction not hex"
    signed = node.rpc("signrawtransaction", [raw])
    bad = shape(signed, {"hex": "hex", "complete": "bool"})
    if bad or not signed["complete"]:
        return f"signrawtransaction {bad or 'not complete'}"
    dec = node.rpc("decoderawtransaction", [raw])
    if not dec["vin"] or shape(dec["vin"][0], {"txid": "hex64", "vout": "int"}):
        return "decoderawtransaction vin"
    txid = node.rpc("sendrawtransaction", [signed["hex"]])
    if not is_hex64(txid):
        return "sendrawtransaction not a txid"
    state["raw_txid"] = txid
    return None


check("getrawchangeaddress, createrawtransaction, signrawtransaction, decoderawtransaction, sendrawtransaction",
      raw_send, needs=["coin", "addr"])
check("lockunspent true: unlock",
      lambda: None if node.rpc("lockunspent", [True, [{"txid": state["coin"]["txid"], "vout": state["coin"]["vout"]}]]) is True else "not true",
      needs=["coin"])


def raw_tx():
    txid = state["raw_txid"]
    v = node.rpc("getrawtransaction", [txid, 1])
    bad = shape(v, {"txid": "hex64", "vout": "list", "vin": "list"})
    if bad:
        return f"verbose {bad}"
    h = node.rpc("getrawtransaction", [txid, 0])
    h2 = node.rpc("getrawtransaction", [txid])
    return None if is_hex(h) and h == h2 else "non-verbose not hex"


check("getrawtransaction txid 1 / 0 / none (mempool)", raw_tx, needs=["raw_txid"])


def withdraw():
    txid = node.rpc("sendtoaddress", [state["addr"], 12.5])
    state["send_txid"] = txid
    if not is_hex64(txid):
        return "not a txid"
    watch = state.get("foreign_addr")
    if not watch:
        return "no foreign address from the first node"
    watch_txid = node.rpc("sendtoaddress", [watch, 3.0])
    if is_hex64(watch_txid):
        state["watch_txid"] = watch_txid
    return None if "watch_txid" in state else "send to watch address not a txid"


check("sendtoaddress: txid (amount as a JSON number)", withdraw, needs=["mined101", "addr", "foreign_addr"])


def watch_only():
    watch = state["foreign_addr"]
    node.rpc("importaddress", [watch, "swap", True])
    v = node.rpc("validateaddress", [watch])
    return shape(v, {"ismine": "bool", "iswatchonly": "bool"}) or (
        None if v["iswatchonly"] and not v["ismine"] else "not watch-only")


check("importaddress + validateaddress: iswatchonly", watch_only, needs=["foreign_addr"])
check("setgenerate 1: 1 block hash", generate(1))


def address_utxos():
    tip = node.rpc("getblockcount")
    for addr, txid, sats in [(state["addr"], state["send_txid"], 1250000000),
                             (state["foreign_addr"], state["watch_txid"], 300000000)]:
        r = node.rpc("getaddressutxos", [{"addresses": [addr]}])
        if not isinstance(r, list):
            return "not an array"
        rows = [u for u in r if isinstance(u, dict) and u.get("txid") == txid]
        if not rows:
            return f"sent output not listed for {addr[:6]}..."
        u = rows[0]
        bad = shape(u, {"address": "str", "txid": "hex64", "outputIndex": "int",
                        "script": "hex", "satoshis": "int", "height": "int"})
        if bad:
            return bad
        if u["satoshis"] != sats or u["height"] != tip:
            return f"satoshis {u['satoshis']} height {u['height']}"
    return None


check("getaddressutxos {addresses}: address, txid, outputIndex, script, satoshis, height", address_utxos,
      needs=["send_txid", "watch_txid", "mined1"])


def confirmed_tx():
    r = node.rpc("gettransaction", [state["send_txid"]])
    bad = shape(r, {"confirmations": "int", "blockhash": "hex64"})
    return bad or (None if r["confirmations"] >= 1 else "unconfirmed")


check("gettransaction: confirmations, blockhash", confirmed_tx, needs=["send_txid", "mined1"])


def block_by_height():
    h = node.rpc("getblockcount")
    bh = node.rpc("getblockhash", [h])
    if not is_hex64(bh):
        return "getblockhash not a hash"
    b = node.rpc("getblock", [bh, True])
    bad = shape(b, {"hash": "hex64", "height": "int", "time": "int",
                    "previousblockhash": "hex64", "tx": "list"})
    if bad:
        return bad
    if b["height"] != h or not all(is_hex64(t) for t in b["tx"]):
        return "height or tx list"
    return None


check("getblockhash + getblock hash true: hash, height, time, previousblockhash, tx", block_by_height,
      needs=["mined101"])


def median_time():
    bh = node.rpc("getbestblockhash")
    if not is_hex64(bh):
        return "getbestblockhash not a hash"
    return shape(node.rpc("getblockheader", [bh]), {"time": "int", "previousblockhash": "hex64"})


check("getbestblockhash + getblockheader: time, previousblockhash", median_time, needs=["mined101"])


def sign_with_key():
    coins = [u for u in node.rpc("listunspent") if u["amount"] > 1]
    c = coins[0]
    wif = node.rpc("dumpprivkey", [c["address"]])
    raw = node.rpc("createrawtransaction", [[{"txid": c["txid"], "vout": c["vout"]}],
                                            {state["addr"]: round(c["amount"] - 0.001, 8)}])
    r = node.rpc("signrawtransaction", [raw, [], [wif]])
    bad = shape(r, {"hex": "hex", "complete": "bool"})
    return bad or (None if r["complete"] else "not complete")


check("signrawtransaction hex [] [wif]: complete (signTxWithKey)", sign_with_key, needs=["mined101", "addr"])


def no_jsonrpc_member():
    r = node.post({"method": "getblockcount", "params": [], "id": 1})
    return None if is_int(r.get("result")) and not r.get("error") else f"reply {str(r)[:60]}"


check("request without a jsonrpc member: answered", no_jsonrpc_member)

# Wallet encryption: encryptWallet, isWalletEncrypted/Locked, unlockWallet, lockWallet
wallet_pass = secrets.token_hex(16)


def encrypt():
    node.rpc("encryptwallet", [wallet_pass])
    if not node.wait_ready():
        return "node stopped answering after encryptwallet"
    r = node.rpc("getwalletinfo")
    if not is_int(r.get("unlocked_until")):
        return "no unlocked_until on an encrypted wallet"
    return None if r["unlocked_until"] <= 0 else "encrypted wallet not locked"


def unlock():
    node.rpc("walletpassphrase", [wallet_pass, 100000000])
    r = node.rpc("getwalletinfo")
    if not (is_int(r.get("unlocked_until")) and r["unlocked_until"] > 0):
        return "unlocked_until not > 0"
    return seed_id()


def lock():
    node.rpc("walletlock")
    r = node.rpc("getwalletinfo")
    return None if is_int(r.get("unlocked_until")) and r["unlocked_until"] <= 0 else "not locked"


check("encryptwallet + getwalletinfo: unlocked_until 0 (locked)", encrypt)
check("walletpassphrase pw 100000000: unlocked_until > 0, seed unchanged", unlock)
check("walletlock + getwalletinfo: unlocked_until 0", lock)
check("stop: the node exits", lambda: None if node.stop() is not None else "still running")

print(f"FAILS {fails}")
sys.exit(fails)
