#!/usr/bin/env python3
"""Wallet start options, run step by step on a fresh Divi Core divid and a
fresh irondivid side by side: -wallet (new and existing), -rescan,
-salvagewallet, -spendzeroconfchange, -keypool, -upgradewallet,
-zapwallettxes, -sendfreetransactions, -txconfirmtarget, -disablewallet, and
backupwallet restored on the same daemon and on the other one. Each row prints
PASS, KNOWN (a difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row runs differently on irondivid
INJECT = os.environ.get("WALLET_START_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose or has not closed yet, one per row name:
# (reason, shape). Each is listed in README.md with divid's source line. shape
# takes the two raw outcomes and is true only for the difference described, so
# a KNOWN row that matches divid, or differs in another way, is a FAIL.
def core_refuses_folder(c, i):
    return c[0] == "exit" and "Unexpected wallet filename" in c[2] and i[0] == "up"


KNOWN = {
    "start -wallet=sub/x.dat": (
        "divid takes only a file name in its datadir, as its Berkeley DB environment is the datadir "
        "(divi/src/init.cpp:866-871); irondivid's wallet is a folder of its own and -wallet names that "
        "folder, inside the datadir when relative (docs/divid-differences.md S5, W1)", core_refuses_folder),
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


class Node:
    def __init__(self, name, binary, index, wallet_sub):
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        # Where -wallet=<name> lives: divid's network folder, irondivid's datadir
        self.wallets = os.path.join(self.dir, wallet_sub) if wallet_sub else self.dir
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"wstart{index}:{password}".encode()).decode()
        self.conf = os.path.join(self.dir, "divi.conf")
        self.lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=wstart{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "listen=0", "bind=127.0.0.1", "dnsseed=0", "staking=0",
        ]
        os.makedirs(self.dir)
        tmp = self.conf + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.lines) + "\n")
        os.replace(tmp, self.conf)
        self.proc = None
        self.starts = 0

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


def both(name, method, *params, kind="ok", message=True):
    compare(name, C.call(method, *params), I.call(method, *params), kind=kind, message=message)


def value(name, fn):
    """fn(node) on both, compared as values"""
    compare(name, ("ok", fn(C)), ("ok", fn(I)), kind="value")


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


def started(name, *args, **kw):
    """starts(), and the run cannot go on without both nodes"""
    c, i = starts(name, *args, **kw)
    need(c[0] == i[0] == "up", f"a node did not start for: {name}")


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


def setup_failed(kind, value_, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value_}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def amount(v):
    return f"{float(v):.8f}"


def balance(n):
    return amount(n.rpc("getbalance"))


def mine(n, blocks):
    n.rpc("setgenerate", blocks)


def wallet_txids(n):
    return sorted({t["txid"] for t in n.rpc("listtransactions", "*", 1000) if "txid" in t})


# --- the run ---------------------------------------------------------------------

C = Node("divid", DIVID, 0, "regtest")
I = Node("irondivid", IRONDIVID, 1, None)

# 1. A fresh datadir: coins, a labelled address, two keys with coins whose
# private keys later go into other wallets without a rescan
started("fresh start, default wallet")
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getinfo').get('version')}", flush=True)
for n in (C, I):
    mine(n, 30)
    n.labelled = n.rpc("getnewaddress", "lbl")
    n.k1, n.k2 = n.rpc("getnewaddress"), n.rpc("getnewaddress")
    n.rpc("sendtoaddress", n.k1, 7)
    n.rpc("sendtoaddress", n.k2, 8)
    # Two blocks over the sends: a new wallet's first scan starts at the tip
    # it was made at, inclusive (wallet.cpp:263, :285-302), so those blocks
    # must lie below it
    mine(n, 3)
    # Throwaway regtest keys, passed over RPC only and never printed
    n.wif1, n.wif2 = n.rpc("dumpprivkey", n.k1), n.rpc("dumpprivkey", n.k2)
    n.default_balance = balance(n)
    n.default_txids = wallet_txids(n)
value("default wallet: walletversion", lambda n: n.rpc("getwalletinfo").get("walletversion"))
stop_both()

# 2. -wallet=<new name>: a new wallet in the datadir; a key imported without a
# rescan shows no coins until a start with -rescan
started("start -wallet=other.dat (a new wallet)", "-wallet=other.dat")
value("-wallet=other.dat: made in the datadir", lambda n: os.path.exists(os.path.join(n.wallets, "other.dat")))
value("-wallet=other.dat: a new wallet's balance", balance)
value("-wallet=other.dat: not the default wallet's addresses",
      lambda n: n.rpc("validateaddress", n.labelled).get("ismine"))
compare("importprivkey without a rescan", C.call("importprivkey", C.wif1, "", False),
        I.call("importprivkey", I.wif1, "", False))
value("after importprivkey without a rescan: balance", balance)
for n in (C, I):
    n.zc_addr = n.rpc("getnewaddress")
stop_both()

started("restart -wallet=other.dat (the existing wallet)", "-wallet=other.dat")
value("-wallet=other.dat again: balance, no rescan", balance)
value("-wallet=other.dat again: the imported key is still there", lambda n: n.rpc("validateaddress", n.k1).get("ismine"))
stop_both()

if INJECT == "rescan":
    started("restart -wallet=other.dat -rescan", "-wallet=other.dat", "-rescan", iron_args=("-wallet=other.dat",))
else:
    started("restart -wallet=other.dat -rescan", "-wallet=other.dat", "-rescan")
value("-rescan: balance (the imported key's 7 found)", balance)
value("-rescan: coins", lambda n: len(n.rpc("listunspent")))
stop_both()

# 3. -salvagewallet: divid only sets -rescan (init.cpp:763-766)
started("start -wallet=salvage.dat (a new wallet)", "-wallet=salvage.dat")
compare("importprivkey without a rescan (second key)", C.call("importprivkey", C.wif2, "", False),
        I.call("importprivkey", I.wif2, "", False))
stop_both()
started("restart -wallet=salvage.dat", "-wallet=salvage.dat")
value("-wallet=salvage.dat: balance, no rescan", balance)
stop_both()
started("restart -wallet=salvage.dat -salvagewallet", "-wallet=salvage.dat", "-salvagewallet")
value("-salvagewallet: balance (the imported key's 8 found)", balance)
stop_both()
for n in (C, I):
    del n.wif1, n.wif2

# 4. The default wallet is unchanged by the other wallets; it pays 10 to other.dat
started("restart, default wallet")
row("default wallet: balance as before", "same" if balance(C) == C.default_balance else "changed",
    "same" if balance(I) == I.default_balance else "changed",
    (balance(C) == C.default_balance) == (balance(I) == I.default_balance))
for n in (C, I):
    n.rpc("sendtoaddress", n.zc_addr, 10)
    mine(n, 1)
    n.default_balance = balance(n)
    n.default_txids = wallet_txids(n)
stop_both()

# 5. -spendzeroconfchange: other.dat holds a confirmed 7 and 10. It pays 9.5 out
# of the 10, leaving about 0.5 of unconfirmed change; a send of 7.2 then needs
# that change (divid: AvailableCoins with fOnlyConfirmed = !-spendzeroconfchange,
# wallet.cpp:1848)
started("start -wallet=other.dat -spendzeroconfchange=0", "-wallet=other.dat", "-spendzeroconfchange=0")
for n in (C, I):
    need(wait_for(lambda: balance(n) == amount(17), 60), f"{n.name} other.dat did not see the 10 sent to it")
both_paid = [n.call("sendtoaddress", n.labelled, 9.5) for n in (C, I)]
compare("-spendzeroconfchange=0: pay 9.5 out of the confirmed 10", *both_paid, kind="txid")
compare("-spendzeroconfchange=0: a send of 7.2 that needs the unconfirmed change",
        C.call("sendtoaddress", C.labelled, 7.2), I.call("sendtoaddress", I.labelled, 7.2), kind="txid")
stop_both()
started("restart -wallet=other.dat -spendzeroconfchange=1", "-wallet=other.dat", "-spendzeroconfchange=1")
compare("-spendzeroconfchange=1: the same send of 7.2",
        C.call("sendtoaddress", C.labelled, 7.2), I.call("sendtoaddress", I.labelled, 7.2), kind="txid")
stop_both()

# 6. -keypool=<n>: the keypool target of a new wallet, and of a later top-up
started("start -wallet=keypool.dat -keypool=5 (a new wallet)", "-wallet=keypool.dat", "-keypool=5")
value("-keypool=5: keypoolsize of the new wallet", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))
for n in (C, I):
    n.rpc("getnewaddress")
value("-keypool=5: keypoolsize after getnewaddress", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))
stop_both()
started("restart -wallet=keypool.dat -keypool=8", "-wallet=keypool.dat", "-keypool=8")
value("-keypool=8: keypoolsize at the start", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))
both("-keypool=8: keypoolrefill", "keypoolrefill")
value("-keypool=8: keypoolsize after keypoolrefill", lambda n: n.rpc("getwalletinfo").get("keypoolsize"))
stop_both()

# 7. -upgradewallet: on an existing wallet, and on a new one
started("restart -upgradewallet, default wallet", "-upgradewallet")
value("-upgradewallet: walletversion of the existing wallet", lambda n: n.rpc("getwalletinfo").get("walletversion"))
stop_both()
c, i = starts("start -wallet=upgrade.dat -upgradewallet (a new wallet)", "-wallet=upgrade.dat", "-upgradewallet")
if c[0] == i[0] == "up":
    value("-upgradewallet: walletversion of a new wallet", lambda n: n.rpc("getwalletinfo").get("walletversion"))
stop_both()

# 8. -zapwallettxes=1 and =2 (not an option of divid 3.0.0): which
# transactions and labels survive
for z in ("1", "2"):
    started(f"restart -zapwallettxes={z}, default wallet", f"-zapwallettxes={z}")
    row(f"-zapwallettxes={z}: wallet transactions kept",
        wallet_txids(C) == C.default_txids, wallet_txids(I) == I.default_txids,
        (wallet_txids(C) == C.default_txids) == (wallet_txids(I) == I.default_txids))
    value(f"-zapwallettxes={z}: label kept", lambda n: n.rpc("getaccount", n.labelled))
    value(f"-zapwallettxes={z}: balance kept", lambda n: balance(n) == n.default_balance)
    stop_both()

# 9. -sendfreetransactions and -txconfirmtarget: the fee a send pays
started("restart, default wallet (fee without options)")
for n in (C, I):
    n.plain_fee = n.rpc("gettransaction", n.rpc("sendtoaddress", n.labelled, 1))["fee"]
value("fee of a 1 DIVI send to the wallet itself", lambda n: amount(n.plain_fee))
stop_both()
started("restart -sendfreetransactions=1 -txconfirmtarget=10", "-sendfreetransactions=1", "-txconfirmtarget=10")
for n in (C, I):
    n.opt_fee = n.rpc("gettransaction", n.rpc("sendtoaddress", n.labelled, 1))["fee"]
value("-sendfreetransactions=1 -txconfirmtarget=10: fee of the same send", lambda n: amount(n.opt_fee))
stop_both()

# 10. backupwallet, restored on the same daemon and given to the other one
started("restart, default wallet (backup)")
for n in (C, I):
    n.backup = os.path.join(WORK, f"{n.name}-backup.dat")
    n.balance_at_backup = balance(n)
compare("backupwallet <file>", C.call("backupwallet", C.backup), I.call("backupwallet", I.backup))
both("dumpwallet <file>", "dumpwallet", os.path.join(WORK, "dump.txt"))
both("importwallet <file>", "importwallet", os.path.join(WORK, "dump.txt"))
stop_both()


def place(src, dst):
    if os.path.isdir(src):
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)


for n in (C, I):
    place(n.backup, os.path.join(n.wallets, "restored.dat"))
started("start -wallet=restored.dat (its own backup)", "-wallet=restored.dat")
value("restored backup: balance as at the backup", lambda n: balance(n) == n.balance_at_backup)
value("restored backup: label", lambda n: n.rpc("getaccount", n.labelled))
stop_both()
place(I.backup, os.path.join(C.wallets, "cross.dat"))
place(C.backup, os.path.join(I.wallets, "cross.dat"))
starts("start -wallet=cross.dat (the other daemon's backup)", "-wallet=cross.dat", message=False)
stop_both()

# 11. -wallet with a folder in its name (divid: init.cpp:866-871)
starts("start -wallet=sub/x.dat", "-wallet=sub/x.dat")
stop_both()

# 12. -disablewallet: which wallet calls answer what
started("start -disablewallet", "-disablewallet")
for method, params in (("getbalance", []), ("getnewaddress", []), ("getwalletinfo", []), ("listunspent", []),
                       ("sendtoaddress", [C.labelled, 1]), ("backupwallet", [os.path.join(WORK, "b2.dat")]),
                       ("dumpprivkey", [C.labelled]), ("keypoolrefill", []), ("dumpwallet", ["x"])):
    both(f"-disablewallet: {method}", method, *params)
value("-disablewallet: getinfo has no wallet members",
      lambda n: sorted(k for k in n.rpc("getinfo") if k in ("balance", "walletversion", "keypoolsize")))
compare("-disablewallet: validateaddress still has ismine",
        ("ok", "ismine" in C.rpc("validateaddress", C.labelled)), ("ok", "ismine" in I.rpc("validateaddress", I.labelled)),
        kind="value")
stop_both()

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
