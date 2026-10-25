#!/usr/bin/env python3
"""Start options and replies of Divi Core divid's wallet that no other script
compares, next to irondivid on regtest, each on fresh single nodes (no peers,
no blocks beyond genesis):

- -hdseed with -mnemonic and/or -mnemonicpassphrase, and an -hdseed that is not
  hex, alone and with -mnemonic (init.cpp:945-951, wallet.cpp:2286-2313): the
  wallet made (dumphdinfo, the first getnewaddress) and the log lines;
- on an encrypted, locked wallet with -keypool=1: walletpassphrase with one and
  with four arguments, walletlock with one (rpcwallet.cpp:2575, :2669), sendmany
  from the account "*" (rpcwallet.cpp:276-277, :1718), getnewaddress until the
  pool runs out and then getaccountaddress of a new account (:347-348);
- -disablewallet's log line "Wallet disabled!" (init.cpp:1547).

Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL; the run ends with FAILS <n>, the exit code.

The seed, the words, the BIP39 passphrase and the wallet passphrase are made
in the run (the words by a throwaway divid wallet) and go only into the run's
own 0600 divi.conf files or over RPC. None is printed or put on a command line:
rows say "the seed", "the words", "empty" or "other".
"""

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("HDSEED_MNEMONIC_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape); none at present
KNOWN = []

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def first_difference(core, iron):
    """Where two long texts first part, as the row is cut at 260 characters"""
    c, i = show(core, cut=None), show(iron, cut=None)
    if len(c) <= 260 and len(i) <= 260:
        return ""
    k = next((n for n, (a, b) in enumerate(zip(c, i)) if a != b), min(len(c), len(i)))
    return f"  [first difference at {k}: divid ...{c[max(0, k - 40):k + 60]}... irondivid ...{i[max(0, k - 40):k + 60]}...]"


def show(v, cut=260):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if cut is None else text[:cut]


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = known(name)
    if listed:
        reason, shape = listed
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
        note += first_difference(core, iron)
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


class Node:
    """A node on `datadir` (made with a divi.conf when new)"""

    def __init__(self, name, binary, index, extra_conf=(), env=None, datadir=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = datadir or os.path.join(WORK, name)
        self.starts = 0
        self.proc = None
        if not os.path.exists(os.path.join(self.dir, "divi.conf")):
            os.makedirs(self.dir, exist_ok=True)
            password = secrets.token_hex(16)
            user = "hm" + secrets.token_hex(4)
            lines = [
                "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
                f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
                "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "dnsseed=0",
                "staking=0", "allowunencryptedwallet=1",
            ] + list(extra_conf)
            fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(lines) + "\n")
        self.read_conf()

    def read_conf(self):
        conf = dict(l.split("=", 1) for l in open(os.path.join(self.dir, "divi.conf")).read().split("\n") if "=" in l)
        self.rpcport = int(conf["rpcport"])
        self.auth = base64.b64encode(f"{conf['rpcuser']}:{conf['rpcpassword']}".encode()).decode()

    def set_conf(self, key, value):
        """Replace (or add) one line of divi.conf"""
        path = os.path.join(self.dir, "divi.conf")
        lines = [l for l in open(path).read().split("\n") if l and not l.startswith(key + "=")]
        lines.append(f"{key}={value}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.read_conf()

    def launch(self, *args):
        self.starts += 1
        self.out = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        env = dict(os.environ, **self.env) if self.env else None
        with open(self.out, "w") as o:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=o, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def start(self, *args):
        """('up',) once RPC answers, or ('exit', code)"""
        self.log_from = {p: size(p) for p in self.logs()}
        self.launch(*args)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code)
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except Exception:
                pass
            time.sleep(0.5)
        return ("exit", "none within %d s" % START_TIMEOUT)

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None

    def logs(self):
        return [os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log")]

    def new_log(self):
        """The log written since the last start"""
        text = ""
        for p in self.logs():
            try:
                with open(p, errors="replace") as f:
                    f.seek(self.log_from.get(p, 0))
                    text += f.read()
            except OSError:
                pass
        return text

    def stderr(self):
        with open(self.out, errors="replace") as f:
            return f.read()

    def tail(self, n=4):
        lines = []
        for path in [self.out] + self.logs() if self.starts else self.logs():
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return 0


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
    print(f"FAIL   setup: {value}"[:300], flush=True)
    for n in globals().get("NODES", ()):
        t = n.tail()
        if t:
            print(f"#      {n.name}: {t}"[:700], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed



def outcome(out, value=lambda v: v):
    if out[0] == "err":
        return {"error": out[1], "message": out[2]}
    return {"ok": value(out[1])}


def amount(v):
    return None if v is None else round(float(v), 8)



# divid's help examples name sample addresses and hashes; irondivid's texts
# write them "diviaddress" and "hash" (scripts/help-replies/README.md). The help
# texts are compared with that done, as help-replies compares them.
SAMPLE_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{40,}(?![0-9A-Za-z])")
SAMPLE_B58 = re.compile(r"(?<![0-9A-Za-z])(?=[1-9A-HJ-NP-Za-km-z]*\d)(?=[1-9A-HJ-NP-Za-km-z]*[A-Za-z])"
                        r"[1-9A-HJ-NP-Za-km-z]{26,35}(?![0-9A-Za-z])")


def helped(out):
    """outcome() of a call answered with its help text, samples written as irondivid writes them"""
    o = outcome(out)
    if "message" in o:
        o["message"] = SAMPLE_B58.sub("diviaddress", SAMPLE_HEX.sub("hash", o["message"]))
    return o


def both_rows(name, got):
    for k in sorted(got["divid"].keys() | got["irondivid"].keys()):
        row(f"{name}: {k}", got["divid"].get(k), got["irondivid"].get(k))


def pair(label, extra_conf=()):
    """A fresh divid and irondivid with these divi.conf lines"""
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40]
    return [Node(f"{slug}-divid", DIVID, 0, extra_conf), Node(f"{slug}-irondivid", IRONDIVID, 1, extra_conf)]


def done(n):
    n.stop()
    shutil.rmtree(n.dir, ignore_errors=True)


PREFER = "can't use -hdseed and -mnemonic/-mnemonicpassphrase together, will prefer -seed"
INCORRECT = "Incorrect seed, generating random one instead"

# --- the throwaway values ------------------------------------------------------------
# Valid words from a throwaway divid wallet; a hex seed and a BIP39 passphrase
w = Node("words-divid", DIVID, 0)
if w.start()[0] != "up":
    raise RuntimeError(f"the words node did not start: {w.tail()}")
WORDS = w.rpc("dumphdinfo")["mnemonic"]
done(w)
SEED = secrets.token_hex(32)
PP = secrets.token_hex(8)
print(f"# divid and irondivid, ports {PORT_BASE}..{PORT_BASE + 3}", flush=True)


def kind(value, mine, name):
    if not value:
        return "empty"
    return name if value == mine else "other"


def seed_case(label, lines):
    """Start each binary with these lines on a fresh datadir"""
    got, first = {}, {}
    for n in pair(label, lines):
        out = n.start()
        if out[0] != "up":
            got[n.binary == DIVID and "divid" or "irondivid"] = {"start": "exit", "exit code": out[1]}
            done(n)
            continue
        info = n.rpc("dumphdinfo")
        addr = n.rpc("getnewaddress")
        log = n.new_log()
        who = "divid" if n.binary == DIVID else "irondivid"
        g = {"start": "up",
             "dumphdinfo hdseed": kind(info.get("hdseed"), SEED, "the seed"),
             "dumphdinfo mnemonic": kind(info.get("mnemonic"), WORDS, "the words"),
             "dumphdinfo mnemonicpassphrase": kind(info.get("mnemonicpassphrase"), PP, "the passphrase"),
             f"log: {PREFER}": PREFER in log,
             f"log: {INCORRECT}": INCORRECT in log}
        first[who] = addr
        # From the seed or the words the first address is known; a random wallet's is not
        g["first getnewaddress"] = ("the same as the other's" if g["dumphdinfo hdseed"] == "the seed"
                                    or g["dumphdinfo mnemonic"] == "the words" else "random")
        got[who] = g
        done(n)
    if len(first) == 2 and got["divid"].get("first getnewaddress") == "the same as the other's":
        if first["divid"] != first["irondivid"]:
            got["irondivid"]["first getnewaddress"] = "another address"
    both_rows(label, got)


# --- -hdseed with -mnemonic ------------------------------------------------------------
# A hex -hdseed with -mnemonic, -mnemonicpassphrase or both: those are dropped
# and logged (init.cpp:945-951); the wallet comes from the seed (wallet.cpp:2288-2294)
seed_case("hdseed=<hex> mnemonic=<words>", [f"hdseed={SEED}", f"mnemonic={WORDS}"])
seed_case("hdseed=<hex> mnemonicpassphrase=<p>", [f"hdseed={SEED}", f"mnemonicpassphrase={PP}"])
seed_case("hdseed=<hex> mnemonic=<words> mnemonicpassphrase=<p>",
          [f"hdseed={SEED}", f"mnemonic={WORDS}", f"mnemonicpassphrase={PP}"])
# Not hex: logged, then the words or a new random wallet (wallet.cpp:2295-2300)
seed_case("hdseed=nothex mnemonic=<words>", ["hdseed=nothex", f"mnemonic={WORDS}"])
seed_case("hdseed=nothex", ["hdseed=nothex"])

# --- an encrypted wallet ------------------------------------------------------------------
PASS = secrets.token_hex(12)
nodes = pair("encrypted", ["keypool=1"])
got = {"divid": {}, "irondivid": {}}
for n in nodes:
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
    n.rpc("encryptwallet", PASS)
    if not wait_for(lambda: n.rpc("getwalletinfo").get("encryption_status") == "locked", 60):
        raise RuntimeError(f"{n.name} is not locked after encryptwallet")
    who = "divid" if n.binary == DIVID else "irondivid"
    g = got[who]
    payee = n.rpc("getaddressesbyaccount", "")[0]
    # Counted only on an encrypted wallet (rpcwallet.cpp:2575, :2669)
    g["walletpassphrase <passphrase> (one argument)"] = helped(n.call("walletpassphrase", PASS))
    g["walletpassphrase <passphrase> 60 false x (four arguments)"] = helped(
        n.call("walletpassphrase", PASS, 60, False, "x"))
    g["walletlock x"] = helped(n.call("walletlock", "x"))
    g["then: encryption status"] = n.rpc("getwalletinfo").get("encryption_status")
    # The account is read before the lock is checked (rpcwallet.cpp:1718, :1727)
    g['locked: sendmany "*" {<own address>: 1}'] = outcome(n.call("sendmany", "*", {payee: 1}))
    # The pool is topped up only while unlocked; then it runs out (:306-307, :347-348)
    g["locked: getnewaddress until the pool is empty"] = [
        "ok" if o[0] == "ok" else o[1] for o in (n.call("getnewaddress") for _ in range(4))]
    g['locked, pool empty: getaccountaddress "fresh"'] = outcome(n.call("getaccountaddress", "fresh"))
    done(n)
both_rows("encrypted, locked, -keypool=1", got)

# --- -disablewallet -----------------------------------------------------------------------
got = {}
for n in pair("disablewallet", ["disablewallet=1"]):
    out = n.start()
    who = "divid" if n.binary == DIVID else "irondivid"
    got[who] = {"start": out[0], "log: Wallet disabled!": "Wallet disabled!" in n.new_log()}
    done(n)
both_rows("-disablewallet", got)

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
