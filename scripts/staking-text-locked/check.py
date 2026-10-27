#!/usr/bin/env python3
"""Staking replies of Divi Core divid and irondivid in four wallet states.

Both nodes run with -staking=1 on their own regtest chain, mine the same 120 blocks
and then go through the same states: not encrypted; encrypted and locked after a
restart; unlocked for staking only; fully unlocked. In each state it compares
getstakingstatus, getinfo's "staking status" text, getmininginfo's staking fields
and the wallet's encryption_status. irondivid's own "staking status text" is
compared with divid's words for the same thing, getinfo's "staking status". Each
row prints PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The wallet
passphrase lives only in memory; it is never printed, written to a file or put on
a command line.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's value of the named row is
# changed before it is compared
INJECT = os.environ.get("STAKING_TEXT_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name ending. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {
    "getstakingstatus: fields divid lacks":
        "\"staking status text\", the staking state in words, kept as an extra field (divid getstakingstatus, "
        "rpcmisc.cpp:1037-1080, has the bool only)",
}

fails = 0


def row(name, core, iron):
    global fails
    if INJECT and name == INJECT:
        iron = ["injected", iron]
    same = core == iron
    reason = next((r for k, r in KNOWN.items() if name.endswith(": " + k)), None)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core, sort_keys=True)}  irondivid={json.dumps(iron, sort_keys=True)}{note}"[:600], flush=True)


class Node:
    def __init__(self, name, binary, port):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p, self.rpcport = port, port + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"staking:{password}".encode()).decode()
        os.makedirs(self.dir, mode=0o700)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", "rpcuser=staking", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "listen=0", "discover=0", "listenonion=0", "dnsseed=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "staking=1",
        ]
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = None

    def start(self):
        out = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        out.close()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is None and self.call("getblockcount")[0] == "ok":
                return
            time.sleep(0.5)
        print(f"FAIL   {self.name} did not start", flush=True)
        sys.exit(255)

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except OSError as e:
            return ("err", None, str(e))
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            print(f"FAIL   {self.name} {method}: {out[1]} {out[2][:160]}", flush=True)
            sys.exit(255)
        return out[1]

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def state(nodes, name):
    d, i = nodes
    ds, is_ = d.rpc("getstakingstatus"), i.rpc("getstakingstatus")
    extra = sorted(set(is_) - set(ds))
    row(f"{name}: getstakingstatus", ds, {k: v for k, v in is_.items() if k in ds})
    row(f"{name}: getstakingstatus: fields divid lacks", [], extra)
    # divid's words for its staking state are getinfo's (rpcmisc.cpp:154-155)
    row(f"{name}: staking status text", d.rpc("getinfo").get("staking status"), is_.get("staking status text"))
    row(f"{name}: getinfo staking status", d.rpc("getinfo").get("staking status"), i.rpc("getinfo").get("staking status"))
    dm, im = d.rpc("getmininginfo"), i.rpc("getmininginfo")
    row(f"{name}: getmininginfo staking fields",
        {k: v for k, v in dm.items() if "stak" in k.lower()}, {k: v for k, v in im.items() if "stak" in k.lower()})
    row(f"{name}: encryption_status",
        d.rpc("getwalletinfo").get("encryption_status"), i.rpc("getwalletinfo").get("encryption_status"))


nodes = [Node("divid", DIVID, PORT_BASE), Node("irondivid", IRONDIVID, PORT_BASE + 2)]
for node in nodes:
    node.start()
for node in nodes:
    node.rpc("setgenerate", 120)
time.sleep(3)
state(nodes, "not encrypted")

passphrase = secrets.token_hex(16)
for node in nodes:
    node.rpc("encryptwallet", passphrase)
for node in nodes:
    node.stop()
for node in nodes:
    node.start()
time.sleep(3)
state(nodes, "locked after a restart")

for node in nodes:
    node.rpc("walletpassphrase", passphrase, 0, True)
time.sleep(3)
state(nodes, "unlocked for staking only")

for node in nodes:
    node.rpc("walletlock")
    node.rpc("walletpassphrase", passphrase, 600)
time.sleep(3)
state(nodes, "fully unlocked")

for node in nodes:
    node.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
