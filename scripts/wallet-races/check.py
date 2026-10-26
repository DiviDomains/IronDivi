#!/usr/bin/env python3
"""Wallet calls that overlap each other, the unlock timer and new blocks, on
Divi Core divid and irondivid.

A divid miner (M) and two wallet nodes from one phrase, divid (C) and irondivid
(I), share one regtest chain; two more nodes, a divid and an irondivid with
-keypool=4, sit beside them for the keypool case. Each case runs as a turn on C
and then as the same turn on I: M funds the wallet with fresh coins, a block
confirms them, and then many clients call the node at once (threads released
together by a barrier). Every turn is checked on its own: no coin spent twice,
every accepted send in the mempool or a block, no send in the wallet that the
caller was not given, each refusal one of divid's. Where divid's outcome does not
depend on timing (it runs one wallet call at a time, under cs_main), the two
turns' outcomes are compared too. After each turn a block settles it and both
wallets must agree on the balance, the coins and the transaction list. Each row
prints PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
wallet passphrase is made at random into a 0600 file in the work directory; it
goes only into RPC request bodies, never onto a command line or into the output.
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
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: the named row's irondivid side is
# changed before it is compared
INJECT = os.environ.get("WALLET_RACES_INJECT", "")
HOST = os.environ.get("WALLET_RACES_HOST", "127.0.0.2")
RPC_TIMEOUT = 120
START_TIMEOUT = 180
SYNC_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name, each listed in
# README.md with divid's source line; a KNOWN row that matches divid is a FAIL
KNOWN = {}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}
T0 = time.time()


def row(name, core, iron, same):
    global fails
    if INJECT and INJECT == name:
        iron, same = "injected", False
    reason = KNOWN.get(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    counts[word] += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:900], flush=True)


def passphrase_file():
    path = os.path.join(WORK, "passphrase.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"wallet": secrets.token_hex(16)}, f)
    with open(path) as f:
        return json.load(f)["wallet"]


PASS = passphrase_file()


class Node:
    def __init__(self, name, binary, index, extra, env=None, listen=False, connect=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"wr{index}"
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            "listen=1" if listen else "listen=0", "rpcthreads=16",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0", f"connect={connect or f'{HOST}:{PORT_BASE + 49}'}",
        ] + list(extra)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                     start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer within {START_TIMEOUT} s")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message); amounts come back as Decimal"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=Decimal)
        except urllib.error.HTTPError as e:
            try:
                reply = json.loads(e.read() or b"{}", parse_float=Decimal)
            except ValueError:
                return ("err", e.code, "HTTP")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:160]}")
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

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   setup (check.py:{where}): {value}"[:400], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def wait_until(what, test, limit=SYNC_TIMEOUT):
    deadline = time.time() + limit
    while time.time() < deadline:
        if test():
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {what}")


# --- concurrent calls -------------------------------------------------------------------------

class Call:
    """One call made from its own thread: the reply and when it was sent and answered"""

    def __init__(self, method, params, delay=0.0):
        self.method, self.params, self.delay = method, params, delay
        self.start = self.end = None
        self.out = None


def race(node, calls, extra=()):
    """Every call from its own thread, released together by a barrier (a call's
    delay after the release staggers it); `extra` are functions run alongside,
    each given the barrier. Returns the calls with their replies"""
    barrier = threading.Barrier(len(calls) + len(extra))

    def one(c):
        barrier.wait()
        if c.delay:
            time.sleep(c.delay)
        c.start = time.time()
        try:
            c.out = node.call(c.method, *c.params)
        except Exception as e:  # a connection the node dropped
            c.out = ("err", "none", f"no reply: {type(e).__name__}")
        c.end = time.time()

    threads = [threading.Thread(target=one, args=(c,)) for c in calls]
    threads += [threading.Thread(target=f, args=(barrier,)) for f in extra]
    for t in threads:
        t.start()
    for t in threads:
        t.join(RPC_TIMEOUT + 30)
    if any(t.is_alive() for t in threads):
        raise RuntimeError(f"{node.name}: a racing call did not return")
    return calls


def kind(out):
    """A reply's kind: ok, or the code and the message without its numbers"""
    if out[0] == "ok":
        return "ok"
    return f"{out[1]} " + re.sub(r"[0-9]+(\.[0-9]+)?", "N", out[2])


def tally(calls):
    t = {}
    for c in calls:
        t[kind(c.out)] = t.get(kind(c.out), 0) + 1
    return dict(sorted(t.items()))


# --- the nodes --------------------------------------------------------------------------------

M = Node("miner", DIVID, 0, [], listen=True)
MINER = f"{HOST}:{M.p2p}"
C = Node("divid", DIVID, 1, [], connect=MINER)
PHRASE_ENV = {"WALLET_MNEMONIC": C.rpc("dumphdinfo")["mnemonic"]}
I = Node("irondivid", IRONDIVID, 2, [], env=PHRASE_ENV, connect=MINER)
KC = Node("divid-keypool", DIVID, 3, ["keypool=4"])
KI = Node("irondivid-keypool", IRONDIVID, 4, ["keypool=4"])
del PHRASE_ENV
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# The shared wallet's address the coins are sent to, and where its sends go
FUND = C.rpc("getnewaddress")
if not I.rpc("validateaddress", FUND).get("ismine"):
    raise RuntimeError("irondivid's wallet does not hold the key of divid's first address")
DEST = M.rpc("getnewaddress")
DEST2 = M.rpc("getnewaddress")


def tips_equal():
    tips = {n.rpc("getbestblockhash") for n in (M, C, I)}
    return len(tips) == 1


def mine(n=1):
    M.rpc("setgenerate", n)
    wait_until("one tip on the three nodes", tips_equal)


wait_until("both wallet nodes connected to the miner", lambda: M.rpc("getconnectioncount") >= 2)
mine(60)


def settle():
    """Every mempool transaction of the wallet nodes mined, the wallets caught up"""
    def relayed():
        pool = set(M.rpc("getrawmempool"))
        return all(set(n.rpc("getrawmempool")) <= pool for n in (C, I))
    wait_until("the wallet nodes' transactions on the miner", relayed)
    mine(1)
    wait_until("empty mempools", lambda: not C.rpc("getrawmempool") and not I.rpc("getrawmempool"))


ENCRYPTED = {"on": False}


def sweep(node):
    """Every coin the wallet holds paid away to the miner in one transaction,
    so that each turn starts from the same coins: only those it is funded with"""
    left = node.rpc("listunspent", 0)
    total = sum((u["amount"] for u in left), Decimal(0))
    fee = Decimal("0.0005") + Decimal("0.00002") * len(left)
    if total < fee + Decimal("0.01"):
        return
    if ENCRYPTED["on"]:
        node.rpc("walletpassphrase", PASS, 0)
    raw = node.rpc("createrawtransaction", [{"txid": u["txid"], "vout": u["vout"]} for u in left],
                   {DEST2: float(total - fee)})
    signed = node.rpc("signrawtransaction", raw)
    if not signed.get("complete"):
        raise RuntimeError(f"{node.name}: the sweep could not be signed")
    node.rpc("sendrawtransaction", signed["hex"])
    if ENCRYPTED["on"]:
        node.rpc("walletlock")
    settle()


def fund(amounts, node=None):
    """Coins of these amounts to the shared wallet, one transaction each, mined;
    with `node`, what the wallet held before is swept away first"""
    if node is not None:
        sweep(node)
    # The miner's change is unconfirmed until the next block: at most 30 sends a block
    txids = []
    for k in range(0, len(amounts), 30):
        txids += [M.rpc("sendtoaddress", FUND, float(a)) for a in amounts[k:k + 30]]
        settle()
    return txids


def coins(node, txids):
    """The wallet's unspent outputs of these transactions"""
    want = set(txids)
    return [u for u in node.rpc("listunspent") if u["txid"] in want]


def unspent_total(node):
    return sum((u["amount"] for u in node.rpc("listunspent")), Decimal(0))


def wallet_sends(node):
    return {t["txid"] for t in node.rpc("listtransactions", "*", 100000) if t.get("category") == "send"}


def tx_inputs(node, txid):
    raw = node.rpc("gettransaction", txid)["hex"]
    return [(v["txid"], v["vout"]) for v in node.rpc("decoderawtransaction", raw)["vin"]]


def send_checks(node, calls, before_sends, allowed):
    """What must hold after a race of sends on `node`, whatever the timing.
    Returns the problems found (empty: all held) and the accepted txids"""
    problems = []
    accepted = []
    for c in calls:
        if c.out[0] == "ok":
            accepted.append(c.out[1])
        elif kind(c.out) not in allowed:
            problems.append(f"{c.method} refused as {c.out[1]} {c.out[2][:80]!r}")
    if len(set(accepted)) != len(accepted):
        problems.append("one txid handed to two callers")
    pool = set(node.rpc("getrawmempool"))
    seen = {}
    for txid in accepted:
        tx = node.call("gettransaction", txid)
        if tx[0] != "ok":
            problems.append(f"accepted {txid[:12]} not in the wallet")
            continue
        if txid not in pool and tx[1].get("confirmations", 0) < 1:
            problems.append(f"accepted {txid[:12]} neither in the mempool nor in a block")
        for prev in tx_inputs(node, txid):
            if prev in seen:
                problems.append(f"coin {prev[0][:12]}:{prev[1]} spent by {seen[prev][:12]} and {txid[:12]}")
            seen[prev] = txid
    extra = wallet_sends(node) - before_sends - set(accepted)
    if extra:
        problems.append(f"{len(extra)} send(s) in the wallet no caller was given: {sorted(extra)[0][:12]}…")
    return problems, accepted, seen


def settled_checks(node, before_total, accepted):
    """After the turn is mined: the coins left are the coins before less what
    the accepted sends paid out, and getbalance says the same"""
    problems = []
    paid = Decimal(0)
    for txid in accepted:
        # A send's amount includes its fee (both programs)
        paid += node.rpc("gettransaction", txid)["amount"]
    total = unspent_total(node)
    if total != before_total + paid:
        problems.append(f"listunspent {total} != {before_total} {paid:+}")
    balance = node.rpc("getbalance")
    if Decimal(balance) != total:
        problems.append(f"getbalance {balance} != listunspent {total}")
    return problems


def agree_row(name):
    """Both wallets, one phrase on one chain, after a settle: the same balance,
    coins and transactions"""
    def view(n):
        return {
            "balance": str(n.rpc("getbalance")),
            "coins": sorted((u["txid"], u["vout"], str(u["amount"])) for u in n.rpc("listunspent")),
            "transactions": sorted((t["txid"], t.get("category"), str(t.get("amount")), t.get("vout", -1))
                                   for t in n.rpc("listtransactions", "*", 100000)),
        }
    c, i = view(C), view(I)
    diff = [k for k in c if c[k] != i[k]]
    row(name, f"balance {c['balance']}, {len(c['coins'])} coins, {len(c['transactions'])} entries",
        f"balance {i['balance']}, {len(i['coins'])} coins, {len(i['transactions'])} entries"
        + (f" (differs: {', '.join(diff)})" if diff else ""), not diff)


def turns(case, body, compare_outcome=True):
    """`body(node)` on C, then on I. It returns (outcome, problems); the
    outcome is compared when divid's does not depend on timing, the problems
    must be none on both"""
    out = {}
    for n in (C, I):
        outcome, problems = body(n)
        out[n.name] = (outcome, problems)
        settle()
    (co, cp), (io, ip) = out["divid"], out["irondivid"]
    if compare_outcome:
        row(f"{case}: outcome", json.dumps(co), json.dumps(io), co == io)
    else:
        print(f"#      {case}: outcome  divid={json.dumps(co)}  irondivid={json.dumps(io)}", flush=True)
    row(f"{case}: checks", "; ".join(cp) or "all held", "; ".join(ip) or "all held", not cp and not ip)
    agree_row(f"{case}: both wallets agree afterwards")


# --- 1. parallel sendtoaddress that need more than the balance --------------------------------

def overdraw(n_coins, n_sends):
    def body(node):
        fund([10] * n_coins, node)
        before, sends = unspent_total(node), wallet_sends(node)
        calls = race(node, [Call("sendtoaddress", [DEST, 9.9]) for _ in range(n_sends)])
        problems, accepted, _ = send_checks(node, calls, sends, {
            "-6 Insufficient funds: N(total requested) is greater than N(total available)",
            "-4 Insufficient funds to meet coin selection algorithm requirements.",
        })
        settle()
        problems += settled_checks(node, before, accepted)
        return tally(calls), problems
    return body


turns("8 parallel sendtoaddress, 5 coins", overdraw(5, 8))
turns("32 parallel sendtoaddress, 20 coins", overdraw(20, 32))


# --- 2. sendmany and sendtoaddress on the same few coins ---------------------------------------

def mixed(node):
    fund([10] * 3, node)
    before, sends = unspent_total(node), wallet_sends(node)
    calls = []
    for k in range(3):
        calls.append(Call("sendtoaddress", [DEST, 4.0]))
        calls.append(Call("sendmany", ["", {DEST: 2.0, DEST2: 2.0}]))
    race(node, calls)
    problems, accepted, _ = send_checks(node, calls, sends, {
        "-6 Insufficient funds: N(total requested) is greater than N(total available)",
        "-4 Insufficient funds to meet coin selection algorithm requirements.",
        "-6 Account has insufficient funds",
    })
    settle()
    problems += settled_checks(node, before, accepted)
    return {"accepted": len(accepted), "refused": sorted({kind(c.out) for c in calls if c.out[0] != "ok"})}, problems


turns("3 sendtoaddress and 3 sendmany, 3 coins", mixed)


# --- 3. getnewaddress from 16 clients, -keypool=4 ----------------------------------------------

def keypool_turn(label, per_client):
    out = {}
    for n in (KC, KI):
        calls = race(n, [Call("getnewaddress", []) for _ in range(16 * per_client)])
        addresses = [c.out[1] for c in calls if c.out[0] == "ok"]
        problems = []
        if len(set(addresses)) != len(addresses):
            problems.append(f"{len(addresses) - len(set(addresses))} address(es) handed out twice")
        for a in set(addresses):
            if not n.rpc("validateaddress", a).get("ismine"):
                problems.append(f"{a} is not the wallet's")
                break
        info = n.rpc("getwalletinfo")
        out[n.name] = ({"replies": tally(calls), "keypoolsize": info.get("keypoolsize")}, problems)
    (co, cp), (io, ip) = out["divid-keypool"], out["irondivid-keypool"]
    row(f"getnewaddress, {label}: outcome", json.dumps(co), json.dumps(io), co == io)
    row(f"getnewaddress, {label}: checks", "; ".join(cp) or "all held", "; ".join(ip) or "all held",
        not cp and not ip)


keypool_turn("64 from 16 clients, unencrypted", 4)
for n in (KC, KI):
    r = n.call("encryptwallet", PASS)
    if r[0] != "ok":
        raise RuntimeError(f"{n.name} encryptwallet: {r[1:]}")
    if n.proc.poll() is not None:
        n.start()
keypool_turn("16 from 16 clients, locked", 1)
for n in (KC, KI):
    n.rpc("walletpassphrase", PASS, 0)
keypool_turn("64 from 16 clients, unlocked", 4)


# --- 4. blocks mined while sends and reads run ------------------------------------------------

def reply_problems(method, params, reply, ceiling):
    """What a single reply must say of itself. The sends only pay out, so no
    reply may count more than `ceiling`, the wallet's coins before the race"""
    p = []
    if method == "listunspent":
        outs = [(u["txid"], u["vout"]) for u in reply]
        if len(set(outs)) != len(outs):
            p.append(f"listunspent {params} lists a coin twice")
        minconf = params[0] if params else 1
        if any(u.get("confirmations", 0) < minconf for u in reply):
            p.append(f"listunspent {params} lists a coin under its minconf")
        total = sum((u["amount"] for u in reply), Decimal(0))
        if total > ceiling:
            p.append(f"listunspent {params} counts {total}, more than the {ceiling} before the race")
    elif method in ("getbalance", "getunconfirmedbalance"):
        if Decimal(reply) < 0 or Decimal(reply) > ceiling:
            p.append(f"{method} {reply} (before the race {ceiling})")
    elif method == "listtransactions":
        keys = [(t.get("txid"), t.get("category"), t.get("vout"), str(t.get("amount"))) for t in reply]
        if len(set(keys)) != len(keys):
            p.append("listtransactions lists an entry twice")
        for t in reply:
            if t.get("confirmations", 0) > 0 and not t.get("blockhash"):
                p.append("listtransactions: a confirmed entry with no block")
                break
    return p


def with_blocks(node):
    fund([10] * 16, node)
    before, sends = unspent_total(node), wallet_sends(node)
    ceiling = before + node.rpc("getunconfirmedbalance")
    done = threading.Event()
    reads = []

    def reader(barrier):
        barrier.wait()
        while not done.is_set():
            for method, params in (("listunspent", []), ("listunspent", [0]), ("getbalance", []),
                                   ("getunconfirmedbalance", []), ("listtransactions", ["*", 1000])):
                out = node.call(method, *params)
                reads.append((method, params, out))

    def miner(barrier):
        barrier.wait()
        for _ in range(5):
            time.sleep(0.2)
            M.call("setgenerate", 1)

    calls = [Call("sendtoaddress", [DEST, 4.0], delay=0.15 * (k % 8)) for k in range(16)]
    readers = [reader] * 3

    race_threads = threading.Thread(target=lambda: race(node, calls, extra=readers + [miner]))
    # The readers run until the sends are done
    race_threads.start()
    while any(c.end is None for c in calls):
        time.sleep(0.05)
        if not race_threads.is_alive():
            break
    done.set()
    race_threads.join(RPC_TIMEOUT + 60)
    problems, accepted, _ = send_checks(node, calls, sends, {
        "-6 Insufficient funds: N(total requested) is greater than N(total available)",
        "-4 Insufficient funds to meet coin selection algorithm requirements.",
    })
    bad = [r for r in reads if r[2][0] != "ok"]
    if bad:
        problems.append(f"{len(bad)} read(s) refused, e.g. {bad[0][0]} {bad[0][2][1:]}")
    for method, params, out in reads:
        if out[0] == "ok":
            for p in reply_problems(method, params, out[1], ceiling):
                if p not in problems:
                    problems.append(p)
    wait_until("one tip on the three nodes", tips_equal)
    settle()
    problems += settled_checks(node, before, accepted)
    return {"reads": len(reads), "accepted": len(accepted)}, problems


turns("16 sends and 3 readers while 5 blocks come", with_blocks, compare_outcome=False)


# --- 5. lockunspent while sends run -----------------------------------------------------------

def outpoint(u):
    return {"txid": u["txid"], "vout": u["vout"]}


def with_locks(node):
    txids = fund([10] * 8, node)
    mine_ = sorted(coins(node, txids), key=lambda u: (u["txid"], u["vout"]))
    l1, l2, l3 = mine_[0:2], mine_[2:4], mine_[4:6]
    problems = []
    # Before the locks: listunspent leaves locked coins out
    before, sends = unspent_total(node), wallet_sends(node)
    for group in (l1, l3):
        if node.call("lockunspent", False, [outpoint(u) for u in group]) != ("ok", True):
            problems.append("lockunspent before the race refused")
    marks = {}
    lists = []

    def locker(barrier):
        barrier.wait()
        time.sleep(0.05)
        a = time.time()
        r2 = node.call("lockunspent", False, [outpoint(u) for u in l2])
        marks["l2"] = (a, time.time(), r2)
        time.sleep(0.05)
        a = time.time()
        r3 = node.call("lockunspent", True, [outpoint(u) for u in l3])
        marks["l3"] = (a, time.time(), r3)
        for _ in range(5):
            lists.append(node.call("listlockunspent"))

    calls = race(node, [Call("sendtoaddress", [DEST, 4.0], delay=0.03 * k) for k in range(8)], extra=[locker])
    p, accepted, spent = send_checks(node, calls, sends, {
        "-6 Insufficient funds: N(total requested) is greater than N(total available)",
        "-4 Insufficient funds to meet coin selection algorithm requirements.",
    })
    problems += p
    for key in ("l2", "l3"):
        if marks[key][2] != ("ok", True):
            problems.append(f"lockunspent during the race: {marks[key][2]}")
    by_txid = {c.out[1]: c for c in calls if c.out[0] == "ok"}
    key = lambda u: (u["txid"], u["vout"])  # noqa: E731
    for u in l1:
        if key(u) in spent:
            problems.append(f"a coin locked throughout was spent by {spent[key(u)][:12]}")
    for u in l2:
        s = spent.get(key(u))
        if s and by_txid[s].start > marks["l2"][1]:
            problems.append("a coin was spent by a send made after its lock was answered")
    for u in l3:
        s = spent.get(key(u))
        if s and by_txid[s].end < marks["l3"][0]:
            problems.append("a coin was spent by a send answered before its unlock was asked")
    for out in lists:
        if out[0] != "ok" or not {key(u) for u in l1} <= {(x["txid"], x["vout"]) for x in out[1]}:
            problems.append(f"listlockunspent during the race lacks a coin locked throughout: {out[1:]}"[:160])
            break
    final = node.rpc("listlockunspent")
    want = sorted(key(u) for u in l1 + l2)
    if sorted((x["txid"], x["vout"]) for x in final) != want:
        problems.append("listlockunspent afterwards is not the coins locked before and during the race")
    node.rpc("lockunspent", True)
    settle()
    problems += settled_checks(node, before, accepted)
    return {"locked afterwards": len(final)}, problems


turns("8 sends while coins are locked and unlocked", with_locks)


# --- 6. walletlock and the unlock timer while sends run ---------------------------------------

for n in (C, I):
    r = n.call("encryptwallet", PASS)
    if r[0] != "ok":
        raise RuntimeError(f"{n.name} encryptwallet: {r[1:]}")
    if n.proc.poll() is not None:
        n.start()
wait_until("both wallet nodes connected to the miner again", lambda: M.rpc("getconnectioncount") >= 2)
ENCRYPTED["on"] = True

LOCKED_ALLOWED = {
    "-13 Error: Please enter the wallet passphrase with walletpassphrase first.",
    "-4 Error: Wallet locked, unable to create transaction!",
}


# Sends of 9.5 from coins of 0.25 take some forty inputs each, so that signing
# lasts long enough for a lock to land in the middle of one

def with_walletlock(node):
    fund([0.25] * 320, node)
    node.rpc("walletpassphrase", PASS, 600)
    before, sends = unspent_total(node), wallet_sends(node)
    locked = {}

    def locker(barrier):
        barrier.wait()
        time.sleep(0.03)
        locked["reply"] = node.call("walletlock")

    calls = race(node, [Call("sendtoaddress", [DEST, 9.5], delay=0.01 * k) for k in range(8)], extra=[locker])
    problems, accepted, _ = send_checks(node, calls, sends, LOCKED_ALLOWED)
    if locked["reply"] != ("ok", None):
        problems.append(f"walletlock: {locked['reply']}")
    status = node.rpc("getwalletinfo").get("encryption_status")
    if status != "locked":
        problems.append(f"encryption_status {status} after walletlock")
    settle()
    problems += settled_checks(node, before, accepted)
    return tally(calls), problems


def with_timeout(node):
    fund([1] * 120, node)
    before, sends = unspent_total(node), wallet_sends(node)
    unlocked_at = time.time()
    node.rpc("walletpassphrase", PASS, 1)
    calls = race(node, [Call("sendtoaddress", [DEST, 9.5], delay=0.1 * k) for k in range(12)])
    problems, accepted, _ = send_checks(node, calls, sends, LOCKED_ALLOWED)
    late = [c for c in calls if c.out[0] == "ok" and c.start > unlocked_at + 1.5]
    if late:
        problems.append(f"{len(late)} send(s) made 1.5 s or more after a 1 s unlock were accepted")
    status = node.rpc("getwalletinfo").get("encryption_status")
    if status != "locked":
        problems.append(f"encryption_status {status} after the timer")
    settle()
    problems += settled_checks(node, before, accepted)
    return tally(calls), problems


turns("8 sends of forty inputs with a walletlock among them", with_walletlock, compare_outcome=False)
turns("12 sends of ten inputs spread over a 1 s unlock", with_timeout, compare_outcome=False)


# --- 7. a restart right after a race ---------------------------------------------------------

def restart_view(n):
    return {
        "balance": str(n.rpc("getbalance")),
        "unconfirmed": str(n.rpc("getunconfirmedbalance")),
        "coins": sorted((u["txid"], u["vout"], str(u["amount"])) for u in n.rpc("listunspent", 0)),
    }


def pools_equal():
    pools = [set(n.rpc("getrawmempool")) for n in (M, C, I)]
    return pools[0] == pools[1] == pools[2]


fund([10] * 8, C)
views = {}
for n in (C, I):
    n.rpc("walletpassphrase", PASS, 0)
    race(n, [Call("sendtoaddress", [DEST, 4.0]) for _ in range(4)])
    # The other wallet must know these sends before it makes its own
    wait_until("one mempool on the three nodes", pools_equal)
for n in (C, I):
    views[n.name] = restart_view(n)
for n in (C, I):
    n.stop()
for n in (C, I):
    n.start()
wait_until("both wallet nodes connected to the miner after the restart", lambda: M.rpc("getconnectioncount") >= 2)
after = {}
for n in (C, I):
    v = restart_view(n)
    after[n.name] = v
same = {name: views[name] == after[name] for name in views}
row("a restart right after 4 sends: balances and coins as before the stop",
    "same" if same["divid"] else f"before {views['divid']['balance']}/{views['divid']['unconfirmed']}, "
    f"after {after['divid']['balance']}/{after['divid']['unconfirmed']}",
    "same" if same["irondivid"] else f"before {views['irondivid']['balance']}/{views['irondivid']['unconfirmed']}, "
    f"after {after['irondivid']['balance']}/{after['irondivid']['unconfirmed']}",
    same["divid"] and same["irondivid"])
settle()
agree_row("after the restart and a block: both wallets agree")

for n in (I, C, KI, KC, M):
    n.stop()
print(f"# ran for {int(time.time() - T0)} s", flush=True)
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
