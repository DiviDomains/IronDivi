#!/usr/bin/env python3
"""The wallet repair and upgrade start options of Divi Core divid and of
irondivid, side by side on regtest: -salvagewallet, -rescan, -upgradewallet and
-upgradewallet=<n>, -zapwallettxes=1 and =2 (not options of divid 3.0.0),
-disablewallet, -dbloadfailexit, and wallets with a record that cannot be read.

Setup: S, a divid that mines and pays; C, a divid wallet; and I, an irondivid
restored from C's phrase (WALLET_MNEMONIC), so C and I hold the same keys. The
twins get receives, a send, a stake, a vault S owns and they manage, a label
and a locked coin. Then both stop, and each start option runs on fresh copies
of their datadirs, one copy at a time and alone (no peers): the start (exit
code, its error line on stderr), the wallet's views (getwalletinfo,
getbalance, listtransactions, listlockunspent, the label, the vault), the
log lines that name the option or the wallet's load, and the files the start
left. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Records are damaged only in throwaway copies of divid's wallet.dat; the
throwaway regtest key this needs is made here, sent over RPC only and never
printed. C's phrase lives only in memory, in an RPC reply and in irondivid's
environment.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("WALLET_REPAIR_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300
EXIT_TIMEOUT = 180

# Differences listed in README.md: (rows, reason, shape)
UNKNOWN_OPTION = ("divid keeps an option it does not know and says nothing (Settings.cpp:130-150); irondivid "
                  "logs `Unknown option -<name>; ignored` (docs/divid-differences.md S1). -zapwallettxes is "
                  "not an option of divid 3.0.0")
KNOWN = [(lambda n: n.startswith("-zapwallettxes") and n.endswith(": log lines"), UNKNOWN_OPTION,
          lambda c, i: set(c) <= set(i) and set(i) - set(c) == {"an unknown-option line"})]

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


def show(v):
    return json.dumps(v, sort_keys=True, default=str)[:260]


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
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


def divid_row(name, expected, got):
    """A row only divid runs (its wallet.dat can be damaged in place), against
    the outcome divid's code gives; irondivid's is pinned by
    bin/irondivid/tests/wallet_repair.rs"""
    global fails
    word = "PASS" if expected == got else "FAIL"
    if INJECT and INJECT == name:
        word = "FAIL"
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  expected={show(expected)}  divid={show(got)}  [divid only]", flush=True)


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
            user = "wr" + secrets.token_hex(4)
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
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                         stdout=o, stderr=o, start_new_session=True, work=WORK)
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

# --- the wallets ---------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}", "vault=1"])
if C.start()[0] != "up":
    raise RuntimeError(f"C did not start: {C.tail()}")
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}", "vault=1"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if I.start()[0] != "up":
    raise RuntimeError(f"I did not start: {I.tail()}")
NODES = [S, C, I]
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(n=1, node=None):
    node = node or S
    for _ in range(n):
        out = node.call("setgenerate", 1)
        if out[0] != "ok":
            tip = node.rpc("getblock", node.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            node.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


def shared_address(label=""):
    a = C.rpc("getnewaddress", label)
    I.rpc("setaccount", a, label)
    return a


# C mines blocks 51-100, so the twins hold deep coinbases to stake with
mine(50)
mine(50, node=C)
mine(10)
# Receives: coins from S to the twins' addresses
for _ in range(4):
    S.rpc("sendtoaddress", shared_address(), 250)
LABELLED = shared_address("savings")
S.rpc("sendtoaddress", LABELLED, 30)
mine(1)
# A send from the twins (made by C, seen by I)
C.rpc("sendtoaddress", S.rpc("getnewaddress"), 12)
mine(1)
# A vault S owns and the twins manage
MANAGER = shared_address()
VAULT = f"{S.rpc('getnewaddress')}:{MANAGER}"
FUNDING = S.rpc("fundvault", VAULT, 100)["txhash"]
mine(1)
for n in TWINS:
    n.rpc("addvault", VAULT, FUNDING)
# A stake: C's wallet makes a proof-of-stake block (a kernel may take a few
# seconds of the clock to find)
for _ in range(10):
    if C.call("setgenerate", 1)[0] == "ok":
        break
    time.sleep(3)
else:
    raise RuntimeError("C could not stake")
if not synced():
    raise RuntimeError("the nodes did not follow C's stake")
row("setup: the stake is in both wallets",
    any(e.get("category", "").startswith("stake") for e in C.rpc("listtransactions", "*", 1000)),
    any(e.get("category", "").startswith("stake") for e in I.rpc("listtransactions", "*", 1000)))
# A locked coin
COIN = sorted(C.rpc("listunspent"), key=lambda u: (u["txid"], u["vout"]))[0]
for n in TWINS:
    n.rpc("lockunspent", False, [{"txid": COIN["txid"], "vout": COIN["vout"]}])
mine(2)
TIP = S.rpc("getblockcount")
for n in NODES:
    n.stop()

# --- what a start shows ----------------------------------------------------------------


def amount(v):
    return None if v is None else round(float(v), 8)


def views(n):
    """The wallet as the RPC calls show it"""
    v = {}
    info = n.call("getwalletinfo")
    v["getwalletinfo"] = ({k: (amount(info[1].get(k)) if k == "balance" else info[1].get(k))
                           for k in ("walletversion", "balance", "txcount", "keypoolsize")}
                          if info[0] == "ok" else {"error": info[1], "message": info[2]})
    bal = n.call("getbalance")
    v["getbalance"] = amount(bal[1]) if bal[0] == "ok" else {"error": bal[1]}
    lt = n.call("listtransactions", "*", 1000)
    v["listtransactions"] = (sorted((e.get("category"), amount(e.get("amount")), e.get("txid")) for e in lt[1])
                             if lt[0] == "ok" else {"error": lt[1]})
    lk = n.call("listlockunspent")
    v["listlockunspent"] = (sorted((c["txid"], c["vout"]) for c in lk[1]) if lk[0] == "ok" else {"error": lk[1]})
    acc = n.call("getaccount", LABELLED)
    v["label"] = acc[1] if acc[0] == "ok" else {"error": acc[1]}
    ca = n.call("getcoinavailability")
    v["vault coins"] = (amount(ca[1].get("Stakable")) if ca[0] == "ok" else {"error": ca[1]})
    return v


LOG_LINES = {
    "salvagewallet sets rescan": "parameter interaction: -salvagewallet=1 -> setting -rescan=1",
    "errors in the wallet's load": "Errors detected during wallet loading",
    "the noncritical warning": "Warning: error reading wallet.dat!",
    "a downgrade refused": "Unable to downgrade wallet version",
    "a full rescan": "Rescanning... from height",
    "an unknown-option line": "Unknown option -",
    "the encrypt warning": "Make sure to encrypt your wallet",
}


def log_lines(n):
    text = n.new_log()
    return sorted(k for k, line in LOG_LINES.items() if line in text)


def error_line(n):
    for line in n.stderr().splitlines():
        if line.startswith("Error") or line.startswith("Warning: Warning"):
            return line
    return ""


def tree(path):
    """What a start may leave: the entries of the start-up backups folder and
    any .bak file, wherever they are (a node's chain and wallet folders aside)"""
    out = set()
    for root, dirs, files in os.walk(path):
        names = files + dirs
        dirs[:] = [d for d in dirs if d not in ("blocks", "chainstate", "txindex", "database", "wallet")
                   and not d.startswith("wallet.")]
        rel = os.path.relpath(root, path)
        for name in names:
            p = os.path.normpath(os.path.join(rel, name))
            if os.path.basename(root) == "backups" or name.endswith(".bak"):
                out.add(p)
    return out


def left(n, before):
    """The kinds of entries a start added: start-up backups, .bak files"""
    kinds = set()
    for a in tree(n.dir) - before:
        kinds.add(".bak file" if a.endswith(".bak") else "a start-up backup")
    return sorted(kinds)


copies = 0


def copy_of(n):
    global copies
    copies += 1
    dest = os.path.join(WORK, f"{n.name}-copy{copies}")
    shutil.copytree(n.dir, dest)
    c = Node(f"{n.name}-copy{copies}", n.binary, 1 if n is C else 2, env=n.env, datadir=dest)
    # alone: no peers
    c.set_conf("connect", "0")
    return c


def drop_conf(n, key):
    path = os.path.join(n.dir, "divi.conf")
    lines = [l for l in open(path).read().split("\n") if l and not l.startswith(key + "=")]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def started(name, *args, prepare=None, view=True):
    """The same start on a copy of each twin's datadir, one at a time"""
    got = {}
    for twin in TWINS:
        c = copy_of(twin)
        if prepare:
            prepare(c)
        before = tree(c.dir)
        outcome = c.start(*args)
        if outcome[0] == "up":
            time.sleep(2)
            wait_for(lambda: c.rpc("getblockcount") == TIP, 30)
            g = {"start": "up", "views": views(c) if view else None}
            c.stop()
        else:
            g = {"start": "exit", "exit code": outcome[1], "error line": error_line(c)}
        g["log lines"] = log_lines(c)
        g["left"] = left(c, before)
        got[twin.name] = g
        shutil.rmtree(c.dir)
    cg, ig = got[C.name], got[I.name]
    for k in cg.keys() | ig.keys():
        if k == "views" and cg.get(k) and ig.get(k):
            for v in cg[k]:
                row(f"{name}: {v}", cg[k][v], ig[k].get(v))
        else:
            row(f"{name}: {k}", cg.get(k), ig.get(k))
    return got


# --- each start option, on a copy ---------------------------------------------------------
started("a plain restart")
started("-rescan", "-rescan")
started("-salvagewallet", "-salvagewallet")
started("-salvagewallet -rescan=0", "-salvagewallet", "-rescan=0")
started("-upgradewallet", "-upgradewallet")
started("-upgradewallet=10500 on this wallet", "-upgradewallet=10500")
started("-upgradewallet=1000 on this wallet", "-upgradewallet=1000")
started("-zapwallettxes=1", "-zapwallettxes=1")
started("-zapwallettxes=2", "-zapwallettxes=2")
started("-zapwallettxes=1 -rescan", "-zapwallettxes=1", "-rescan")
started("-disablewallet", "-disablewallet")
started("-disablewallet -rescan", "-disablewallet", "-rescan")
started("-disablewallet -salvagewallet", "-disablewallet", "-salvagewallet")
started("-dbloadfailexit=1 on a good wallet", "-dbloadfailexit=1")
# Without -allowunencryptedwallet (the other starts have it): the warning
started("without -allowunencryptedwallet", prepare=lambda c: drop_conf(c, "allowunencryptedwallet"))

# -upgradewallet on a new wallet (fresh datadirs, no phrase): the versions it takes
for value in ("1000", "10500", "60000", "120200", "3000000"):
    got = {}
    for twin, binary, index in ((C, DIVID, 1), (I, IRONDIVID, 2)):
        n = Node(f"new-{twin.name}-{value}", binary, index, ["listen=0", "connect=0"])
        outcome = n.start(f"-upgradewallet={value}")
        if outcome[0] == "up":
            g = {"start": "up", "walletversion": n.rpc("getwalletinfo").get("walletversion")}
            n.stop()
        else:
            g = {"start": "exit", "exit code": outcome[1], "error line": error_line(n)}
        g["log lines"] = log_lines(n)
        got[twin.name] = g
        shutil.rmtree(n.dir)
    for k in got[C.name].keys() | got[I.name].keys():
        row(f"a new wallet with -upgradewallet={value}: {k}", got[C.name].get(k), got[I.name].get(k))

# --- a record that cannot be read (divid's wallet.dat, on throwaway copies) ----------------
# A transaction record: its serialized transaction made unreadable (the input
# count read as 2^64-1)
c0 = copy_of(C)
c0.set_conf("connect", "0")
if c0.start()[0] != "up":
    raise RuntimeError(f"a copy of C did not start: {c0.tail()}")
SEND = next(e["txid"] for e in c0.rpc("listtransactions", "*", 1000) if e.get("category") == "send")
SEND_HEX = c0.rpc("gettransaction", SEND)["hex"]
# A key record: a throwaway regtest key made here, imported over RPC only
A58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = A58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


SECRET = secrets.token_bytes(32)
payload = bytes([239]) + SECRET + b"\x01"
c0.rpc("importprivkey", b58(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]), "", False)
del payload
c0.stop()
KEYED = c0.dir


def damage(path, find, at, flip):
    """Every copy of the record in wallet.dat (a Berkeley DB file can keep an
    older copy in a free page)"""
    wallet = os.path.join(path, "regtest", "wallet.dat")
    data = bytearray(open(wallet, "rb").read())
    i = data.find(find)
    if i < 0:
        raise RuntimeError("the record to damage is not in wallet.dat")
    while i >= 0:
        data[i + at] = flip(data[i + at])
        i = data.find(find, i + 1)
    with open(wallet, "wb") as f:
        f.write(bytes(data))


def damaged_start(name, find, at, flip, *args):
    global copies
    copies += 1
    dest = os.path.join(WORK, f"damaged{copies}")
    shutil.copytree(KEYED, dest)
    damage(dest, find, at, flip)
    n = Node(f"damaged{copies}", DIVID, 1, datadir=dest)
    before = tree(n.dir)
    outcome = n.start(*args)
    g = {"start": outcome[0]}
    if outcome[0] == "up":
        wait_for(lambda: SEND in [e["txid"] for e in n.rpc("listtransactions", "*", 1000)], 30)
        g["the damaged send back"] = SEND in [e["txid"] for e in n.rpc("listtransactions", "*", 1000)]
        g["stderr"] = error_line(n)
        n.stop()
    else:
        g["exit code"] = outcome[1]
        g["error line"] = error_line(n)
    g["log lines"] = log_lines(n)
    # Divi Core 3.0.0 never calls its salvage (CDBEnv::Verify is given no
    # recover function, DatabaseWrapper.cpp:24), so no wallet.<time>.bak
    g["a .bak file left"] = ".bak file" in left(n, before)
    shutil.rmtree(dest)
    return g


WARNING = ("Warning: Warning: error reading wallet.dat! All keys read correctly, but transaction data or "
           "address book entries might be missing or incorrect.")
tx_bytes = bytes.fromhex(SEND_HEX)
g = damaged_start("tx", tx_bytes, 4, lambda b: 0xFF)
divid_row("a damaged transaction record", {
    "start": "up", "the damaged send back": True, "stderr": WARNING,
    "log lines": ["a full rescan", "errors in the wallet's load", "the noncritical warning"], "a .bak file left": False}, g)
g = damaged_start("tx", tx_bytes, 4, lambda b: 0xFF, "-salvagewallet")
divid_row("a damaged transaction record, -salvagewallet", {
    "start": "up", "the damaged send back": True, "stderr": WARNING,
    "log lines": ["a full rescan", "errors in the wallet's load", "salvagewallet sets rescan", "the noncritical warning"],
    "a .bak file left": False}, g)
g = damaged_start("tx", tx_bytes, 4, lambda b: 0xFF, "-dbloadfailexit=1")
divid_row("a damaged transaction record, -dbloadfailexit=1", {
    "start": "exit", "exit code": 1, "error line": WARNING,
    "log lines": ["errors in the wallet's load", "the noncritical warning"], "a .bak file left": False}, g)
g = damaged_start("key", SECRET, 5, lambda b: b ^ 1)
divid_row("a damaged key record", {
    "start": "exit", "exit code": 1, "error line": "Error: Error loading wallet.dat: Wallet corrupted",
    "log lines": ["errors in the wallet's load"], "a .bak file left": False}, g)
g = damaged_start("key", SECRET, 5, lambda b: b ^ 1, "-salvagewallet")
divid_row("a damaged key record, -salvagewallet (no salvage, no .bak)", {
    "start": "exit", "exit code": 1, "error line": "Error: Error loading wallet.dat: Wallet corrupted",
    "log lines": ["errors in the wallet's load", "salvagewallet sets rescan"], "a .bak file left": False}, g)
del SECRET

print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
