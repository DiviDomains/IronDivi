#!/usr/bin/env python3
"""Wallet RPCs on an encrypted HD wallet that is locked, unlocked for staking
only, or not encrypted, on Divi Core divid and on irondivid restored from the
same phrase, compared row by row: key handouts with the keypool full and
empty, the calls that need the keys, a wrong passphrase, and setgenerate where
the stake coin is on an imported (non-HD) key.

One divid and one irondivid, not connected, each mining its own regtest chain
with the same calls. Each row is one call on both; compared are its outcome
(success, or the error code and text), the block count after it and the
wallet's state (getwalletinfo's balances, transaction count, keypool size and
encryption status, and whether it is unlocked). A row that differs is a FAIL;
exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrase, the wallet passphrase and the imported key live only in memory, in RPC
requests and in irondivid's environment; they are never printed or put on a
command line.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 300
START_TIMEOUT = 180
# A small keypool, so a locked wallet runs out of keys within a few calls
KEYPOOL = 3
PASSPHRASE = secrets.token_hex(16)
LAST_POW_BLOCK = 100  # regtest (chainparams.cpp, nLastPOWBlock)
# A folder to copy both debug.logs to at the end
LOGS = os.environ.get("LOCKED_WALLET_RPCS_LOGS", "")

# Rows where divid's behaviour is accidental and irondivid keeps its own:
# row name -> reason with the Core line
KNOWN = {}


def log(line):
    print(line, flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"lw{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=lw{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=0",
            f"bind={HOST}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            f"keypool={KEYPOOL}",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.start()

    def start(self):
        out = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        out.close()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                break
            if self.call("getblockcount")[0] == "ok":
                return
            time.sleep(0.25)
        raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s; exit {self.proc.poll()}")

    def call(self, method, *params):
        """('ok', result), ('err', code, message), or ('down',)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=str)
            except ValueError:
                return ("err", e.code, "HTTP")
        except (OSError, ValueError):
            return ("down",)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1:]}"[:300])
        return out[1]

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def outcome(out):
    """What is compared of a call's answer: ok, or the error code and text"""
    if out[0] == "ok":
        return ["ok"]
    if out[0] == "down":
        return ["down"]
    return ["error", out[1], out[2]]


def state(node):
    """The wallet and chain after a row"""
    info = node.rpc("getwalletinfo")
    # The total, not its split into mature and immature: each side stakes
    # other coins (their values follow the txids), so which stake outputs are
    # still immature differs while the sum agrees
    total = round(float(info.get("balance", 0)) + float(info.get("immature_balance", 0)), 8)
    return {
        "blocks": node.rpc("getblockcount"),
        "balance + immature": f"{total:.8f}",
        "txcount": info.get("txcount"),
        "keypoolsize": info.get("keypoolsize"),
        "encryption_status": info.get("encryption_status"),
        "unlocked": bool(info.get("unlocked_until")),
    }


fails = 0


def row(name, method, *params, mask=None, each=None, expect=None):
    """One call on both nodes and the comparison. `each(node)` gives the
    parameters per node instead of `params`. `expect(node)` gives the outcome
    each node must give when it depends on the node's own txids: then each node
    is checked against its own and the two outcomes are not compared. `mask`
    names state keys left out of the comparison."""
    global fails
    results = []
    for node in NODES:
        out = node.call(method, *(each(node) if each else params))
        results.append((outcome(out), state(node)))
    (c_out, c_state), (i_out, i_state) = results
    if mask:
        for key in mask:
            c_state.pop(key, None)
            i_state.pop(key, None)
    diff = []
    if expect:
        wanted = [expect(node) for node in NODES]
        if c_out[:2] != wanted[0][:2]:
            diff.append(f"divid outcome (its lowest stake coin gives {wanted[0][1]})")
        if i_out[:2] != wanted[1][:2]:
            diff.append(f"irondivid outcome (its lowest stake coin gives {wanted[1][1]})")
    elif c_out != i_out:
        diff.append("outcome")
    diff += [k for k in c_state if c_state[k] != i_state.get(k)]
    shown = " ".join(str(x) for x in c_out) if c_out[0] != "ok" else "ok"
    if not diff:
        log(f"PASS   {name:44} {shown} | blocks {c_state['blocks']} keypool {c_state['keypoolsize']} "
            f"{c_state['encryption_status']}")
        return
    known = KNOWN.get(name)
    tag = "KNOWN " if known else "FAIL  "
    if not known:
        fails += 1
    log(f"{tag} {name:44} differs: {', '.join(diff)}" + (f"  [{known}]" if known else ""))
    log(f"#   outcome: divid {json.dumps(c_out)} irondivid {json.dumps(i_out)}")
    log(f"#   state:   divid {json.dumps(c_state)}")
    log(f"#            irondivid {json.dumps(i_state)}")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def wif(secret):
    """A compressed regtest WIF (prefix 239, chainparams.cpp, testnet's)"""
    data = bytes([239]) + secret + b"\x01"
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def stake_set(node):
    """Divi Core's stake set, in its order (std::set<StakableCoin>, by
    outpoint; StakableCoin.h:20-23): spendable, unlocked coins at least 10
    deep, a coinstake output at least 20 (wallet.cpp:1433-1462). It is used at
    height 100, where the wallet holds no coinstake output yet."""
    coins = [u for u in node.rpc("listunspent", 10) if u.get("spendable", True)]
    # uint256's order is the number's, so the txid's hex as shown
    return sorted(coins, key=lambda u: (u["txid"], u["vout"]))


def main():
    global NODES
    log(f"# locked-wallet-rpcs: keypool={KEYPOOL}")
    c = Node("divid", DIVID, 0, [])
    phrase = c.rpc("dumphdinfo")["mnemonic"]
    i = Node("irondivid", IRONDIVID, 1, ["debug=1"], env={"WALLET_MNEMONIC": phrase})
    del phrase
    NODES = [c, i]

    # Not encrypted (rpcwallet.cpp:2596-2597, :2676-2677)
    row("unencrypted: walletlock", "walletlock")
    row("unencrypted: walletpassphrase", "walletpassphrase", PASSPHRASE, 10)

    # Coins, all from work blocks, so none of this needs a stake: 60 blocks, an
    # imported key that gets the whole mature balance, then blocks up to 100.
    # At 100 the wallet's stake set is the imported coin and the HD coinbases
    # of heights 1 to 80 (wallet.cpp:1433-1462)
    row("unencrypted: 60 work blocks", "setgenerate", 60)
    key = wif(secrets.token_bytes(32))
    row("unencrypted: importprivkey (no rescan)", "importprivkey", key, "imported", False)
    imported = c.rpc("getaddressesbyaccount", "imported")[0]
    row("unencrypted: the imported key's address", "getaccount", imported)
    row("unencrypted: the whole mature balance to the imported key", "sendtoaddress",
        each=lambda node: [imported, float(node.rpc("getbalance", "*", 1)), "sweep_funds"])
    row(f"unencrypted: work blocks up to {LAST_POW_BLOCK}", "setgenerate", LAST_POW_BLOCK - 60)

    row("encryptwallet", "encryptwallet", PASSPHRASE)

    # Locked: keys from the keypool (rpcwallet.cpp:296-307, :566-573), none topped up
    row("locked: getnewaddress, keypool full", "getnewaddress")
    row("locked: getrawchangeaddress, keypool full", "getrawchangeaddress")
    for k in range(KEYPOOL):
        row(f"locked: getnewaddress #{k + 2}", "getnewaddress")
    for k in range(KEYPOOL):
        row(f"locked: getrawchangeaddress #{k + 2}", "getrawchangeaddress")
    row("locked: keypoolrefill", "keypoolrefill")
    row("locked: keypoolrefill 10", "keypoolrefill", 10)
    # The calls that need the keys (EnsureWalletIsUnlocked, rpcserver.cpp:1124-1128)
    row("locked: dumpprivkey (imported)", "dumpprivkey", imported)
    row("locked: dumphdinfo", "dumphdinfo")
    row("locked: dumpwallet", "dumpwallet", os.path.join(WORK, "dump-locked.txt"))
    row("locked: importprivkey", "importprivkey", wif(secrets.token_bytes(32)), "", False)
    row("locked: signmessage (imported)", "signmessage", imported, "a message")
    row("locked: sendtoaddress", "sendtoaddress", imported, 1)
    row("locked: walletpassphrase, wrong passphrase", "walletpassphrase", PASSPHRASE + "x", 10)

    # Stakes on the locked wallet. divid tries its stake set in outpoint order
    # and signs with the first kernel's key: a key of the HD seed throws in
    # GetKey (-1), an imported key fails to sign (-25)
    def lowest_kind(node):
        first = stake_set(node)[0]
        kind = "imported" if first["address"] == imported else "HD"
        return ["error", -25] if kind == "imported" else ["error", -1]
    row("locked: a stake block, HD and imported coins", "setgenerate", 1, expect=lowest_kind)

    def lock_all_but_imported(node):
        others = [{"txid": u["txid"], "vout": u["vout"]} for u in node.rpc("listunspent", 1)
                  if u["address"] != imported]
        node.rpc("lockunspent", False, others)
    for node in NODES:
        lock_all_but_imported(node)
    # What the stake rows below start from, for reading a FAIL
    for node in NODES:
        status = node.rpc("getstakingstatus")
        coins = [u for u in node.rpc("listunspent", 0) if u["address"] == imported]
        log(f"#   {node.name}: staking_balance {status.get('staking_balance')}, mintablecoins "
            f"{status.get('mintablecoins')}; imported coins {len(coins)}, confirmations "
            f"{sorted(u['confirmations'] for u in coins)}; locked {len(node.rpc('listlockunspent'))}")
    row("locked: a stake block, only the imported coin", "setgenerate", 1)
    row("locked: generateblock, only the imported coin", "generateblock", {})

    # Staking only: the keys unlocked, the calls that need a full unlock refused
    row("walletpassphrase staking only", "walletpassphrase", PASSPHRASE, 3000, True)
    row("staking only: a stake block, only the imported coin", "setgenerate", 1)
    for node in NODES:
        node.rpc("lockunspent", True)
    row("staking only: getnewaddress", "getnewaddress")
    row("staking only: getrawchangeaddress", "getrawchangeaddress")
    row("staking only: keypoolrefill", "keypoolrefill")
    row("staking only: dumpprivkey (imported)", "dumpprivkey", imported)
    row("staking only: dumphdinfo", "dumphdinfo")
    row("staking only: dumpwallet", "dumpwallet", os.path.join(WORK, "dump-staking.txt"))
    row("staking only: importprivkey", "importprivkey", wif(secrets.token_bytes(32)), "", False)
    row("staking only: signmessage (imported)", "signmessage", imported, "a message")
    row("staking only: sendtoaddress", "sendtoaddress", imported, 1)
    row("staking only: walletpassphrase, wrong passphrase", "walletpassphrase", PASSPHRASE + "x", 10)
    row("staking only: walletpassphrase staking only again", "walletpassphrase", PASSPHRASE, 10, True)
    row("staking only: a stake block", "setgenerate", 1)
    row("walletlock", "walletlock")
    row("locked again: getnewaddress", "getnewaddress")

    log(f"FAILS {fails}")
    for node in NODES:
        node.stop()
    if LOGS:
        import shutil
        os.makedirs(LOGS, exist_ok=True)
        for node in NODES:
            for path in (os.path.join(node.dir, "regtest", "debug.log"), os.path.join(node.dir, "debug.log")):
                if os.path.exists(path):
                    shutil.copy(path, os.path.join(LOGS, f"{node.name}.log"))
    sys.exit(min(fails, 254))


NODES = []
if __name__ == "__main__":
    main()
