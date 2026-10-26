#!/usr/bin/env python3
"""setgenerate on an encrypted HD wallet that is locked, unlocked, or unlocked
for staking only, on Divi Core divid and on irondivid restored from the same
phrase, compared row by row.

One divid and one irondivid, not connected, each mining its own regtest chain
with the same steps (the same block counts, so the same heights). Each row is
one call on both; compared are its outcome (success, or the error code and
text), the block count after it and the wallet's state (getwalletinfo's
balances, transaction count, keypool size and encryption status, and whether
it is unlocked). A row that differs is a FAIL; exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrase and the wallet passphrase live only in memory, in RPC requests and in
irondivid's environment; they are never printed or put on a command line.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
HOST = "127.0.0.2"
RPC_TIMEOUT = 300
START_TIMEOUT = 180
# A small keypool, so a locked wallet runs out of keys within a few blocks
KEYPOOL = 3
PASSPHRASE = secrets.token_hex(16)
LAST_POW_BLOCK = 100  # regtest (chainparams.cpp, nLastPOWBlock)

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
        self.auth = base64.b64encode(f"ls{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=ls{index}", f"rpcpassword={password}",
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
    return {
        "blocks": node.rpc("getblockcount"),
        "balance": info.get("balance"),
        "immature_balance": info.get("immature_balance"),
        "txcount": info.get("txcount"),
        "keypoolsize": info.get("keypoolsize"),
        "encryption_status": info.get("encryption_status"),
        "unlocked": bool(info.get("unlocked_until")),
    }


fails = 0


def row(name, method, *params, mask=None):
    """One call on both nodes and the comparison. `mask` names state keys
    left out of the comparison (with the reason in the row's line)"""
    global fails
    results = []
    for node in NODES:
        out = node.call(method, *params)
        results.append((outcome(out), state(node)))
    (c_out, c_state), (i_out, i_state) = results
    if mask:
        for key in mask:
            c_state.pop(key, None)
            i_state.pop(key, None)
    diff = []
    if c_out != i_out:
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


def main():
    global NODES
    log(f"# locked-stake: keypool={KEYPOOL}")
    c = Node("divid", DIVID, 0, [])
    phrase = c.rpc("dumphdinfo")["mnemonic"]
    i = Node("irondivid", IRONDIVID, 1, [], env={"WALLET_MNEMONIC": phrase})
    del phrase
    NODES = [c, i]

    row("encryptwallet", "encryptwallet", PASSPHRASE)
    for node in NODES:
        if node.call("getblockcount")[0] == "down":
            node.proc.wait(timeout=120)
            node.start()
    # Work blocks: a locked wallet pays each to a keypool key (CoinMinter.cpp:145-148)
    row("locked: a work block, keys in the keypool", "setgenerate", 1)
    row("locked: generateblock, a work block", "generateblock", {})
    row(f"locked: {2 * KEYPOOL} work blocks, the keypool runs out", "setgenerate", 2 * KEYPOOL)
    row("locked: a work block, the keypool empty", "setgenerate", 1)
    row("getnewaddress, locked and the keypool empty", "getnewaddress")
    row("walletpassphrase (fully)", "walletpassphrase", PASSPHRASE, 3000)
    height = c.rpc("getblockcount")
    row(f"unlocked: work blocks up to {LAST_POW_BLOCK}", "setgenerate", LAST_POW_BLOCK - height)
    row("unlocked: a stake block", "setgenerate", 1)
    row("walletlock", "walletlock")
    # A stake block signs with the stake coin's key (PoSTransactionCreator.cpp:368-371),
    # which a locked HD wallet derives from its encrypted seed (wallet.cpp:540-545)
    row("locked: a stake block", "setgenerate", 1)
    row("locked: a stake block again", "setgenerate", 1)
    row("locked: generateblock, a stake block", "generateblock", {})
    row("locked: getnewaddress", "getnewaddress")
    # Staking only: the keys are unlocked, sends are not (wallet.cpp:777-806)
    row("walletpassphrase staking only", "walletpassphrase", PASSPHRASE, 3000, True)
    row("staking only: a stake block", "setgenerate", 1)
    row("staking only: two stake blocks", "setgenerate", 2)
    # One new address on each, so both keypools move alike; both send to divid's
    to = c.rpc("getnewaddress")
    i.rpc("getnewaddress")
    row("staking only: a send", "sendtoaddress", to, 1)
    row("walletpassphrase staking only again", "walletpassphrase", PASSPHRASE, 3000, True)
    row("walletlock after staking only", "walletlock")
    row("locked: a stake block after staking only", "setgenerate", 1)
    # A full unlock that ends reverts to staking only when it was staking only before
    row("walletpassphrase staking only, then fully for 2 s", "walletpassphrase", PASSPHRASE, 3000, True)
    row("walletpassphrase fully for 2 s", "walletpassphrase", PASSPHRASE, 2)
    time.sleep(4)
    row("after the 2 s: a stake block", "setgenerate", 1)

    log(f"FAILS {fails}")
    for node in NODES:
        node.stop()
    sys.exit(min(fails, 254))


NODES = []
if __name__ == "__main__":
    main()
