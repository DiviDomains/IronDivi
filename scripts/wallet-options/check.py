#!/usr/bin/env python3
"""Wallet options Divi Core divid reads, and irondivid with them: -vault_min,
-txconfirmtarget, -sendfreetransactions, -createwalletbackups and
-monthlybackups.

Three nodes on one regtest chain: S, a divid wallet that mines and sends; C, a
divid wallet; and I, an irondivid restored from C's phrase, so C and I own the
same coins. Each option is set on both twins at its default and at one or two
other values, and what it changes is compared: the coins counted stakable, the
fee of the same send and whether a send goes without a fee, the backups made
at start (count and names) and the monthly backup a day after start on mock
time. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. C's
phrase lives only in memory, in an RPC reply and in irondivid's environment;
it is never printed or put on a command line. Every backup is made inside the
nodes' own datadirs under the work directory.
"""

import base64
import datetime
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
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import member_order  # noqa: E402  (scripts/lib: the order check the replies scripts share)
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("WALLET_OPTIONS_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180

# Differences listed in README.md, one per row name: (reason, shape). shape
# takes the two values and is true only for the difference described, so a
# KNOWN row that differs in another way is a FAIL.
KNOWN = {}
# Rows whose name starts with one of these, likewise
KNOWN_PREFIX = {
    "backup base name": ("divid's wallet is the file wallet.dat, irondivid's the folder wallet, and a backup takes "
                         "the wallet's name (docs/divid-differences.md W1, W2)",
                         lambda c, i: c == ["wallet.dat"] and i == ["wallet"]),
}

fails = 0


def known(name):
    if name in KNOWN:
        return KNOWN[name]
    return next((r for p, r in KNOWN_PREFIX.items() if name.startswith(p)), None)


def row(name, core, iron, same):
    global fails
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
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    text = lambda v: json.dumps(v, sort_keys=True, default=str)[:220]
    print(f"{word:<5}  {name}  divid={text(core)}  irondivid={text(iron)}{note}", flush=True)


def order_row(name, core, iron):
    """A reply's member and item order next to divid's: PASS, or ORDER (a
    kind of FAIL)"""
    global fails
    if INJECT and INJECT == name:
        iron = {"injected": True, **iron} if isinstance(iron, dict) else iron
        moved = "order injected"
    else:
        moved = member_order.difference(core, iron)
    if moved is None:
        print(f"PASS   {name}  same order", flush=True)
    else:
        fails += 1
        print(f"ORDER  {name}  {moved}"[:400], flush=True)


def both(name, fn):
    """A row of fn(node) for C and I"""
    c, i = fn(C), fn(I)
    row(name, c, i, c == i)
    return c, i


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        password = secrets.token_hex(16)
        user = "opts" + name.replace("-", "")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
            f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self, *args):
        self.mark_logs()
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name} {method}: {e}") from None
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def raw_call(self, method, *params):
        """The reply text as sent, to see the members' order"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
            # json.loads keeps the members in the order they were sent
            return json.loads(r.read())

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def tail(self, n=4):
        lines = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "debug.log"),
                     os.path.join(self.dir, "regtest", "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def restart(self, *args):
        self.stop()
        self.start(*args)
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer after a restart: {self.tail()}")

    def find_dir(self, name):
        """The folder `name` under this node's datadir"""
        for root, dirs, _ in os.walk(self.dir):
            if name in dirs:
                return os.path.join(root, name)
        return None

    def entries(self, name):
        d = self.find_dir(name)
        return sorted(os.listdir(d)) if d else None

    def option_warnings(self, options):
        """Lines of this run's log that name one of the options"""
        found = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "regtest", "debug.log"),
                     os.path.join(self.dir, "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            text = text[self.log_from.get(path, 0):]
            found += [o for o in options if re.search(rf"-{o}\b.*(ignored|not supported|nknown)", text)]
        return sorted(set(found))

    def mark_logs(self):
        """Where this start's log lines begin"""
        self.log_from = {}
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "regtest", "debug.log"),
                     os.path.join(self.dir, "debug.log")):
            try:
                self.log_from[path] = os.path.getsize(path)
            except OSError:
                self.log_from[path] = 0


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

S = Node("divid-sender", DIVID, 0, ["listen=1"])
if not S.wait_ready():
    print(f"FAIL   start: divid sender did not answer: {S.tail()}", flush=True)
    sys.exit(1)
TWIN_CONF = ["listen=0", f"connect={HOST}:{S.p2p}", "vault=1"]
C = Node("divid-wallet", DIVID, 1, TWIN_CONF)
if not C.wait_ready():
    print(f"FAIL   start: divid wallet did not answer: {C.tail()}", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid-wallet", IRONDIVID, 2, TWIN_CONF, env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid wallet did not answer: {I.tail()}", flush=True)
    sys.exit(1)
NODES = (S, C, I)
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(n=1):
    for _ in range(n):
        out = S.call("setgenerate", 1)
        if out[0] != "ok":
            tip = S.rpc("getblock", S.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            S.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


def seen(txid):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in TWINS), 60)


def shared_address():
    """A new address of C that its twin has in its address book too"""
    a = C.rpc("getnewaddress")
    I.rpc("setaccount", a, "")
    return a


def restart_twins(*args):
    for n in TWINS:
        n.restart(*args)
    if not synced():
        raise RuntimeError(f"the twins did not reconnect after a restart with {args}")


def dec(v):
    return Decimal(str(v)) if v is not None else None


def text(v):
    """An amount as a plain decimal, however the node formats it"""
    return format(dec(v).normalize(), "f") if v is not None else None


# --- coins: S mines, then pays the twins twelve coins of 50 --------------------------
mine(110)
X = shared_address()
for _ in range(12):
    S.rpc("sendtoaddress", X, 50)
mine(1)
both("twins' balance", lambda n: text(n.rpc("getbalance")))

# --- -vault_min (AvailableUtxoCollector.cpp:22, AvailableUtxoCalculator.cpp:22-27) ----
# Vaults S owns and the twins manage, of 100 and 1000
OWNER = S.rpc("getnewaddress")
MANAGER = shared_address()
VAULT = f"{OWNER}:{MANAGER}"
funded = [S.rpc("fundvault", VAULT, amount)["txhash"] for amount in (100, 1000)]
mine(1)
for amount, txid in zip((100, 1000), funded):
    both(f"addvault of the {amount} vault", lambda n: n.call("addvault", VAULT, txid)[0])


def availability(n):
    a = n.rpc("getcoinavailability")
    return {k: text(a.get(k)) for k in ("Stakable", "Spendable", "Vaulted")}


both("getcoinavailability, -vault_min not given", availability)
order_row("getcoinavailability, -vault_min not given: member order", C.raw_call("getcoinavailability")["result"],
          I.raw_call("getcoinavailability")["result"])
for value in ("500", "1000", "2000", "-5"):
    restart_twins(f"-vault_min={value}")
    both(f"getcoinavailability, -vault_min={value}", availability)
    order_row(f"getcoinavailability, -vault_min={value}: member order",
              C.raw_call("getcoinavailability")["result"], I.raw_call("getcoinavailability")["result"])

# --- -txconfirmtarget, -sendfreetransactions (LicenseAndInfo.cpp:135, :143) ----------
PAYEE = S.rpc("getnewaddress")


def send_fee(n):
    """Fee and size of a 10 DIVI send from n, mined before the next"""
    txid = n.rpc("sendtoaddress", PAYEE, 10)
    if not seen(txid):
        raise RuntimeError(f"{n.name}'s send did not reach both twins")
    t = n.rpc("gettransaction", txid)
    mine(1)
    # The size is not compared: a signature is 71 or 72 bytes at random
    return {"fee": text(t.get("fee")), "zero fee": dec(t.get("fee")) == 0}


for args in ((), ("-txconfirmtarget=1",), ("-txconfirmtarget=25",), ("-sendfreetransactions=1",),
             ("-sendfreetransactions=0",), ("-sendfreetransactions=1", "-txconfirmtarget=25")):
    restart_twins(*args)
    both(f"10 DIVI send, {' '.join(args) or 'neither given'}: fee, zero fee", send_fee)
    both(f"{' '.join(args) or 'neither given'}: an option warning in the log",
         lambda n: n.option_warnings(("txconfirmtarget", "sendfreetransactions")))


# --- -createwalletbackups (init.cpp:124, :933-941; WalletBackupCreator.cpp) -----------
# A backup is named after the wallet with the UTC minute appended, and none is
# made under a name already there: the twins start in the same minute, and
# each start's backups are renamed after it so the next start has its name
# free.
SUFFIX = re.compile(r"^(.*)\.(\d{4}-\d\d-\d\d-\d\d-\d\d)$")
# A renamed backup keeps the wallet's name before its last dot, as divid
# counts only `<wallet file>.*` (FilteredBoostFileSystem.cpp:35-56)
KEPT = re.compile(r"^(.*)\.(\d{4}-\d\d-\d\d-\d\d-\d\d)-k\w+$")
# A file in each folder that is no backup of the wallet: divid never counts or
# removes it
NOTE = "notes.txt"


def same_minute():
    """Wait until both twins can restart before the minute turns"""
    wait_for(lambda: datetime.datetime.now(datetime.timezone.utc).second < 25, 70)


def backups(n, folder):
    """Count, the time suffixes and the base names of a backup folder"""
    names = n.entries(folder)
    if names is None:
        return {"folder": "absent"}
    made = [SUFFIX.match(x) for x in names]
    return {"backups": sum(1 for x in names if KEPT.match(x) or SUFFIX.match(x)),
            "new": sorted(m.group(2) for m in made if m), "notes.txt": NOTE in names}


def base_names(n, folder):
    return sorted({SUFFIX.match(x).group(1) for x in n.entries(folder) or [] if SUFFIX.match(x)})


def keep_names(n, folder, step):
    d = n.find_dir(folder)
    for x in os.listdir(d) if d else []:
        if SUFFIX.match(x):
            os.rename(os.path.join(d, x), os.path.join(d, f"{x}-k{step}"))


for n in TWINS:
    n.stop()
    for folder in ("backups", "monthlyBackups"):
        d = n.find_dir(folder)
        if d:
            shutil.rmtree(d)
            os.makedirs(d)
            with open(os.path.join(d, NOTE), "w") as f:
                f.write("not a backup\n")
step = 0
for args in (("-createwalletbackups=2",),) * 3 + (("-createwalletbackups=0",), ("-createwalletbackups=-1",), ()):
    step += 1
    what = " ".join(args) or "-createwalletbackups not given"
    same_minute()
    for n in TWINS:
        n.start(*args)
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not start with {args}: {n.tail()}")
    for n in TWINS:
        n.stop()
    for folder in ("backups", "monthlyBackups"):
        both(f"start {step}, {what}: {folder}/", lambda n: backups(n, folder))
        if step == 1:
            both(f"backup base name in {folder}/", lambda n: base_names(n, folder))
        for n in TWINS:
            keep_names(n, folder, step)
for n in TWINS:
    n.start()
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start again: {n.tail()}")
if not synced():
    raise RuntimeError("the twins did not reconnect")

# --- -monthlybackups (init.cpp:1284; LegacyWalletDatabaseEndpointFactory.cpp:75-121) --
# A day after start, on mock time on regtest, a backup in monthlyBackups/ when
# the newest there is 30 days old, named by the mock time; -monthlybackups of
# them kept; 0 or less leaves the check off.
for value, days in (("1", 31), ("0", 62), ("3", 93)):
    restart_twins(f"-monthlybackups={value}")
    before = {n.name: backups(n, "monthlyBackups") for n in TWINS}
    mock = int(time.time()) + days * 86400
    for n in TWINS:
        n.rpc("setmocktime", mock)
    expected = datetime.datetime.fromtimestamp(mock, datetime.timezone.utc).strftime("%Y-%m-%d-%H-%M")
    # divid makes it at once when woken; give both time, then compare
    wait_for(lambda: all(expected in backups(n, "monthlyBackups").get("new", []) for n in TWINS), 20)
    time.sleep(2)

    def monthly(n):
        b = backups(n, "monthlyBackups")
        return {"backups": b.get("backups"), "made on the mock date": expected in b.get("new", []),
                "backups before": before[n.name].get("backups"), "notes.txt": b.get("notes.txt")}

    both(f"-monthlybackups={value}, clock {days} days ahead: monthlyBackups/", monthly)
    for n in TWINS:
        keep_names(n, "monthlyBackups", f"m{value}")

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
