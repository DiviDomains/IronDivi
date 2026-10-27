#!/usr/bin/env python3
"""The keypool's log lines and numbers of Divi Core divid next to
irondivid's when a wallet write fails, on one regtest chain.

S, a divid, mines and pays; C, a divid wallet; I, an irondivid wallet, both
new, with -keypool=2. C and I start with SIGXFSZ ignored and their output
going through a pipe to a file this script writes. For each case the soft
file size limit of the running wallet is lowered to one byte with prlimit,
so a wallet write fails with EFBIG, the call is made, and the limit is
raised again; no block is mined meanwhile. The method is
scripts/wallet-write-failures'.

Rows compare the reply, the keypool lines the call logged, and the pool after
it; then, once writes work, the lines of the next getnewaddress (whose top-up
numbers the next key one past the newest in the pool) and the HD child index
of each address handed out. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

No key or passphrase is printed or put on a command line.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
INJECT = os.environ.get("KEYPOOL_FAILURES_INJECT", "")
HOST = "127.0.0.150"
RPC_TIMEOUT = 120
START_TIMEOUT = 300



def skipped_children(c, i):
    """divid's child indices rise with gaps where irondivid's run on one by one"""
    return (len(c) == len(i) and c != i and all(a[0] == b[0] for a, b in zip(c, i))
            and all(b[1] > a[1] for a, b in zip(c, c[1:]))
            and all(b[1] == a[1] + 1 for a, b in zip(i, i[1:])))


SKIPPED = ("divid's deriveNewChildKey moves its HD chain's counter on in memory before the write that fails "
           "(wallet.cpp:483-511, loadHDChain at :2339-2347), so the child it could not write is never handed out; "
           "irondivid's keypool is the children from its next index on, and it derives that child again once "
           "writes work. The keypool numbers, sizes and lines are the same")
ENCRYPT = ("divid's writes inside its encryption transaction go through, and the keypool top-up after it "
           "(wallet.cpp:1011-1015) throws from the derivation (wallet.cpp:2359-2360); irondivid fails at its first "
           "write and answers as divid does when its top-up has nothing to write (rpcwallet.cpp:2729-2730), as "
           "scripts/wallet-write-failures lists")
# Differences listed in README.md: name -> (reason, shape)
KNOWN = {
    "the HD child index of each address handed out": (SKIPPED, skipped_children),
    "a restart: the HD child index of the next addresses": (
        SKIPPED + "; after a restart divid's counter is the one its last written key left",
        lambda c, i: len(c) == len(i) and all(a[1] > b[1] for a, b in zip(c, i))),
    "encryptwallet while writes fail: reply": (
        ENCRYPT, lambda c, i: c == {"error": -1, "message": "loadCryptedHDChain: WriteCryptedHDChain failed"}
        and i == {"error": -16, "message": "Error: Failed to encrypt the wallet."}),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def show(v):
    text = json.dumps(v, sort_keys=True, default=str)
    return text if os.environ.get("KEYPOOL_FAILURES_WIDE") else text[:300]


def row(name, core, iron):
    global fails
    same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


class Node:
    """A node on its own datadir. A wallet (`piped`) runs with SIGXFSZ ignored
    and its output piped to a file, so a lowered limit never applies to it"""

    def __init__(self, name, binary, index, extra_conf=(), piped=False):
        self.name, self.binary, self.piped = name, binary, piped
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        self.starts = 0
        self.proc = None
        os.makedirs(self.dir, exist_ok=True)
        password = secrets.token_hex(16)
        user = "kf" + secrets.token_hex(4)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={user}",
            f"rpcpassword={password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "daemon=0", f"printtoconsole={1 if piped else 0}", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", "allowunencryptedwallet=1",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.auth = base64.b64encode(f"{user}:{password}".encode()).decode()

    def start(self):
        """('up',) once RPC answers, or ('exit', code)"""
        self.starts += 1
        self.out = os.path.join(WORK, f"{self.name}.{self.starts}.out")
        if self.piped:
            out = open(self.out, "w")
            # SIGXFSZ ignored: a write past the limit fails with EFBIG instead of killing the node
            script = "trap '' XFSZ; d=$1; shift; exec \"$0\" -datadir=\"$d\""
            self.proc = subprocess.Popen(["bash", "-c", script, self.binary, self.dir], cwd=self.dir,
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            proc = self.proc

            def pump():
                for line in proc.stdout:
                    out.write(line.decode(errors="replace"))
                    out.flush()
                out.close()

            self.pump = threading.Thread(target=pump, daemon=True)
            self.pump.start()
        else:
            with open(self.out, "w") as o:
                self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                             stdout=o, stderr=o, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                self.proc = None
                return ("exit", code)
            try:
                if self.call("getblockcount")[0] == "ok":
                    return ("up",)
            except RuntimeError:
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

    def limit(self, soft):
        """Set the soft file size limit of the running node (bytes, or 'unlimited')"""
        subprocess.run(["prlimit", f"--pid={self.proc.pid}", f"--fsize={soft}:unlimited"], check=True)

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except RuntimeError:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        if self.piped:
            self.pump.join(5)
        self.proc = None

    def tail(self, n=4):
        try:
            with open(self.out, errors="replace") as f:
                lines = [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
        except (OSError, AttributeError):
            return ""
        return " | ".join(lines)[-500:]


def wait_for(fn, secs):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except RuntimeError:
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


def mark(n):
    try:
        return os.path.getsize(n.out)
    except OSError:
        return 0


def since(n, at):
    with open(n.out, errors="replace") as f:
        f.seek(at)
        return f.read()


def settled(n, at, secs=2):
    """The output since `at`, once it has stopped growing"""
    last, still = None, 0
    deadline = time.time() + 30
    while time.time() < deadline:
        text = since(n, at)
        still = still + 1 if text == last else 0
        if still >= secs * 4:
            break
        last = text
        time.sleep(0.25)
    return since(n, at)


KEYPOOL = re.compile(r"keypool (?:added key -?\d+, size=\d+, internal=\d|reserve -?\d+|keep -?\d+|return -?\d+)")


def keypool(text):
    return KEYPOOL.findall(text)


def outcome(out):
    """A reply, with what differs between the wallets (an address, a txid) left out"""
    if out[0] == "err":
        return {"error": out[1], "message": out[2]}
    v = out[1]
    if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v):
        return {"ok": "txid"}
    if isinstance(v, str) and len(v) > 25:
        return {"ok": "address"}
    return {"ok": v}


def child(n, address):
    """The HD child index of one of the wallet's addresses, from validateaddress's hdkeypath"""
    path = n.rpc("validateaddress", address).get("hdkeypath", "")
    m = re.fullmatch(r"m/44'/\d+'/\d+'/([01])/(\d+)", path)
    return [int(m.group(1)), int(m.group(2))] if m else path


# --- the wallets ---------------------------------------------------------------------
S = Node("divid-miner", DIVID, 0, ["listen=1"])
if S.start()[0] != "up":
    raise RuntimeError(f"S did not start: {S.tail()}")
WALLET_CONF = ["listen=0", f"connect={HOST}:{S.p2p}", "keypool=2"]
C = Node("divid-wallet", DIVID, 1, WALLET_CONF, piped=True)
I = Node("irondivid-wallet", IRONDIVID, 2, WALLET_CONF, piped=True)
TWINS = (C, I)
NODES = [S, C, I]
first = {}
for n in TWINS:
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
    first[n.name] = settled(n, 0)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
row("a new wallet's first start: keypool lines", keypool(first[C.name]), keypool(first[I.name]))


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(k=1):
    for _ in range(k):
        out = S.call("setgenerate", 1)
        if out[0] != "ok":
            tip = S.rpc("getblock", S.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            S.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


handed = {C.name: [], I.name: []}


def probe(name):
    """Once writes work: the next getnewaddress's keypool lines (its top-up
    numbers the new key one past the newest in the pool) and the pool's size"""
    got = {}
    for n in TWINS:
        at = mark(n)
        address = n.rpc("getnewaddress")
        handed[n.name].append(address)
        got[n.name] = {"keypool lines": keypool(settled(n, at)),
                       "keypoolsize": n.rpc("getwalletinfo").get("keypoolsize")}
    for k in got[C.name]:
        row(f"{name}, then getnewaddress once writes work: {k}", got[C.name][k], got[I.name][k])


def failing(name, call, before=None):
    """`call` with the wallet's writes failing: its reply, the keypool lines it
    logged, the pool's size after it, whether the node stays up"""
    got = {}
    for n in TWINS:
        if before:
            before(n)
        at = mark(n)
        n.limit(1)
        try:
            reply = n.call(*call(n))
        finally:
            n.limit("unlimited")
        got[n.name] = {"reply": outcome(reply), "keypool lines": keypool(settled(n, at))}
        up = wait_for(lambda: n.call("getblockcount")[0] == "ok", 10)
        got[n.name]["up"] = up
        got[n.name]["keypoolsize"] = n.rpc("getwalletinfo").get("keypoolsize") if up else None
    for k in got[C.name]:
        row(f"{name} while writes fail: {k}", got[C.name][k], got[I.name][k])


# Each case starts with the pool one key short, as each getnewaddress leaves
# it (its top-up runs before it takes the oldest key, wallet.cpp:2122-2156),
# so the call's top-up derives a key whose write fails
probe("the first start")
failing("getnewaddress", lambda n: ("getnewaddress",))
probe("getnewaddress")
failing("keypoolrefill 3", lambda n: ("keypoolrefill", 3))
probe("keypoolrefill 3")

mine(110)
funded = {}
for n in TWINS:
    a, b = n.rpc("getnewaddress"), n.rpc("getnewaddress")
    handed[n.name] += [a, b]
    funded[n.name] = {10: (S.rpc("sendtoaddress", a, 10), a), 20: (S.rpc("sendtoaddress", b, 20), b)}
mine(2)
probe("the funding")
PAYEE = S.rpc("getnewaddress")


def only(coin):
    """Lock every coin of the wallet but the funding of `coin`"""
    def go(n):
        txid, address = funded[n.name][coin]
        n.rpc("lockunspent", True)
        others = [{"txid": u["txid"], "vout": u["vout"]} for u in n.rpc("listunspent", 0)
                  if not (u["txid"] == txid and u.get("address") == address)]
        if others:
            n.rpc("lockunspent", False, others)
    return go


failing("sendtoaddress <payee> 1 from the coin of 10 (with change)", lambda n: ("sendtoaddress", PAYEE, 1),
        before=only(10))
probe("the send with change")
failing('sendtoaddress <payee> 1 "sweep_funds" from the coin of 20 (no change)',
        lambda n: ("sendtoaddress", PAYEE, 1, "sweep_funds"), before=only(20))
probe("the send without change")
for n in TWINS:
    n.rpc("lockunspent", True)

# The HD child index of each address handed out so far, and of the next few:
# a derivation whose write fails has already moved divid's chain counter on in
# memory (wallet.cpp:483-511, :2339-2347)
for n in TWINS:
    for _ in range(4):
        handed[n.name].append(n.rpc("getnewaddress"))
both_children = {n.name: [child(n, a) for a in handed[n.name]] for n in TWINS}
row("the HD child index of each address handed out", both_children[C.name], both_children[I.name])

# A restart: the pool and its numbers as the wallet file has them
got = {}
for n in TWINS:
    n.stop()
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start again: {n.tail()}")
    got[n.name] = keypool(settled(n, 0))
if not synced():
    raise RuntimeError("the twins did not catch up")
row("a restart: keypool lines", got[C.name], got[I.name])
probe("a restart")
for n in TWINS:
    for _ in range(3):
        handed[n.name].append(n.rpc("getnewaddress"))
both_children = {n.name: [child(n, a) for a in handed[n.name][-4:]] for n in TWINS}
row("a restart: the HD child index of the next addresses", both_children[C.name], both_children[I.name])

# Last, as divid's wallet is then encrypted in memory only (wallet.cpp:960-1030,
# scripts/wallet-write-failures)
failing("encryptwallet", lambda n: ("encryptwallet", secrets.token_hex(12)))

# walletpassphrase tops the pool up once the wallet is unlocked
# (rpcwallet.cpp:2617-2620). After a restart (the failed encryption left
# nothing on disk) the wallet is encrypted with writes working, and a locked
# getnewaddress, which does not top up, leaves the pool one key short
PASS = secrets.token_hex(12)
for n in TWINS:
    n.stop()
    if n.start()[0] != "up":
        raise RuntimeError(f"{n.name} did not start again: {n.tail()}")
    n.rpc("encryptwallet", PASS)
    if not wait_for(lambda: n.rpc("getwalletinfo").get("encryption_status") == "locked", 30):
        raise RuntimeError(f"{n.name} is not locked after encryptwallet")
    n.rpc("getnewaddress")
failing("walletpassphrase <passphrase> 60", lambda n: ("walletpassphrase", PASS, 60))
for k in ("encryption_status", "unlocked_until"):
    row(f"walletpassphrase <passphrase> 60 while writes fail: then getwalletinfo {k}",
        C.rpc("getwalletinfo").get(k), I.rpc("getwalletinfo").get(k))
del PASS
# The wallet is unlocked and its pool still one key short
failing("getnewaddress on an unlocked encrypted wallet", lambda n: ("getnewaddress",))
probe("getnewaddress on an unlocked encrypted wallet")

print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
