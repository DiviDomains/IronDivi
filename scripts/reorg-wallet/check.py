#!/usr/bin/env python3
"""What the wallets do when the chain reorganises, on Divi Core divid and on irondivid.

Five nodes: divid's owner wallet (it mines the first branch) and manager wallet
(-vault=1), an irondivid owner and manager restored from the same two phrases,
and a second divid miner holding the owner's keys (restored from the owner's
phrase), which mines the second branch while it is cut off from the others.
Both managers and owners run -walletnotify. Each round puts a branch on the
four wallet nodes, lets the second miner build a longer one, joins them, and
compares both wallets of each pair (balances, unspent coins, transactions,
vault views, staking status, mempool) and the -walletnotify log. Rounds: a
payment the new branch drops by a double spend; a chain of three transactions
across three blocks whose first the new branch drops; blocks staked by the
owner that are orphaned; a vault funding dropped and a coinstake of the
manager's vault orphaned. Then a kill of both managers and the start after it.
Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases and keys live only in memory, in an RPC reply, in irondivid's
environment and in the work directory's wallet files and divi.conf (mode 0600);
they are never printed or put on a command line.
"""

import base64
import fnmatch
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
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("REORG_WALLET_INJECT", "")
DUMP = os.environ.get("REORG_WALLET_DUMP", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
VAULT_COIN = 500           # each vault coin funded

KNOWN = {
    "start after a kill (divid with -reindex): manager -walletnotify calls":
        "by design: divid scans from the wallet's best block, which it writes only when it flushes its state "
        "(FlushChainState.cpp:50-53: at a clean stop, a disconnected block, a new block file, or on a timer), so after "
        "a kill and -reindex it scans, and tells of, every wallet transaction since then; irondivid saves its scan "
        "height with each block and starts from the last one (scripts/start-rescan)",
    "start after a kill: the managers start":
        "by design: divid's block index is flushed only when its state is (FlushChainState.cpp:25-52), so a kill -9 "
        "after new blocks leaves a best block that the index does not hold, and after an unprepared shutdown it "
        "stops with \"Block database corruption detected\" (BlockIndexLoading.cpp:262-276); irondivid writes each "
        "block with the chain state and starts (scripts/unclean-stop)",
    "*getcoinavailability: fields divid lacks":
        "total_vaults and vaults, kept as extra fields (divid getcoinavailability, rpcwallet.cpp:818-987, has "
        "Vaulted, Stakable, Spendable); also KNOWN in scripts/vault-replies",
    "*getstakingstatus: fields divid lacks":
        "\"staking status text\", the string irondivid gave before the field became a bool, kept for older "
        "callers (docs/rpc-parity-audit.md: getstakingstatus; divid: rpcmisc.cpp:1059-1076)",
    "*getstakingstatus mnsync (divid's masternode sync not finished)":
        "open: true, as irondivid has no masternode sync and counts it finished; divid gives false on a "
        "regtest node with no masternodes (rpcmisc.cpp:1068; the same gap as mnsync status in scripts/net-replies)",
}

EXTRA = {
    "getcoinavailability": {"total_vaults", "vaults"},
    "getstakingstatus": {"staking status text"},
}
extra_seen = {}

MOMENT = {"timereceived", "time", "blocktime"}
NOTES = {"comment", "to", "FromAccount"}

fails = 0


def known(name):
    if name in KNOWN:
        return KNOWN[name]
    for pattern, reason in KNOWN.items():
        if fnmatch.fnmatchcase(name, pattern):
            return reason
    return None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:500], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = os.path.join(WORK, name)
        password = secrets.token_hex(16)
        user = "records" + name.replace("-", "")
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
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}", *args], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
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


# --- how replies are compared ------------------------------------------------------

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None"""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if a != b:
        return f"{path}: {json.dumps(a)[:70]} vs {json.dumps(b)[:70]}"
    return None


def short(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:90]}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:70]


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return [dict(v[0], amount="0.12345678")] + v[1:]
    if isinstance(v, dict):
        return dict(v, injected=True)
    return "injected"


def compare(name, core, iron, drop=MOMENT | NOTES, order=None, mask=None, extra=None):
    """Same outcome; for a result the same fields and values (except `drop`); list
    items sorted by `order` when given; `mask` rewrites both replies first;
    `extra` names the call whose EXTRA fields are taken out of irondivid's reply"""
    if INJECT and INJECT == name and iron[0] == "ok":
        iron = ("ok", inject(iron[1]))
    if extra and iron[0] == "ok" and isinstance(iron[1], dict):
        found = EXTRA[extra] & set(iron[1])
        extra_seen.setdefault(extra, set()).update(found)
        iron = ("ok", {k: v for k, v in iron[1].items() if k not in found})
    if core[0] == "err" or iron[0] == "err":
        row(name, short(core), short(iron), core[0] == iron[0] and core[1:] == iron[1:])
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if mask:
        a, b = mask(a), mask(b)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:90]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divid": a, "irondivid": b}, f, indent=1, sort_keys=True)
    row(name, short(core), d or short(iron), d is None)


def masked(v, names=None):
    """64-hex strings (txids, block hashes) replaced, so two nodes' own
    transactions compare by shape; `names` maps known strings to their roles"""
    names = names or {}
    if isinstance(v, dict):
        return {k: masked(x, names) for k, x in v.items()}
    if isinstance(v, list):
        return [masked(x, names) for x in v]
    if isinstance(v, str):
        if v in names:
            return names[v]
        if HEX64.match(v):
            return "<hash>"
    return v


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


def NOTIFY(name):
    """-walletnotify: the txid appended to a log of the node's own"""
    return f"walletnotify=echo %s >> {WORK}/notify-{name}.log"


# --- the nodes -----------------------------------------------------------------------

CO = Node("divid-owner", DIVID, 0, ["listen=1", NOTIFY("divid-owner")])
if not CO.wait_ready():
    print(f"FAIL   start: divid owner did not answer: {CO.tail()}", flush=True)
    sys.exit(1)
CM = Node("divid-manager", DIVID, 1, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1", NOTIFY("divid-manager")])
if not CM.wait_ready():
    print(f"FAIL   start: divid manager did not answer: {CM.tail()}", flush=True)
    sys.exit(1)
owner_phrase, manager_phrase = CO.rpc("dumphdinfo")["mnemonic"], CM.rpc("dumphdinfo")["mnemonic"]
IO = Node("irondivid-owner", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{CO.p2p}", NOTIFY("irondivid-owner")],
          env={"WALLET_MNEMONIC": owner_phrase})
IM = Node("irondivid-manager", IRONDIVID, 3, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1", NOTIFY("irondivid-manager")],
          env={"WALLET_MNEMONIC": manager_phrase})
SECOND = Node("divid-second", DIVID, 4, ["listen=1", f"mnemonic={owner_phrase}"])
del owner_phrase, manager_phrase
for n in (IO, IM, SECOND):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer: {n.tail()}", flush=True)
        sys.exit(1)
NODES = (CO, CM, IO, IM)
PAIRS = (("owner", CO, IO), ("manager", CM, IM))
SECOND.rpc("addnode", f"{HOST}:{CO.p2p}", "onetry")
print(f"# divid {CO.rpc('getinfo').get('version')}, irondivid {IO.rpc('getnetworkinfo').get('version')}", flush=True)


ACTIVE = list(NODES)      # the nodes that are running; the managers are stopped for a while


def tips():
    return [n.rpc("getbestblockhash") for n in ACTIVE]


def synced(secs=120):
    return wait_for(lambda: len(set(tips())) == 1, secs)


def mine(n=1, node=None, follow=None):
    """n blocks from `node` (default the first miner); then the `follow` nodes
    (default the four wallet nodes) must have its tip"""
    node = node or CO
    for _ in range(n):
        out = node.call("setgenerate", 1)
        if out[0] != "ok":
            # divid stakes from the clock back: let it pass the tip, then again
            tip = node.rpc("getblock", node.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            node.rpc("setgenerate", 1)
    follow = list(follow if follow is not None else ACTIVE)
    if not wait_for(lambda: len({x.rpc("getbestblockhash") for x in [node] + follow}) == 1, 120):
        raise RuntimeError("the nodes did not follow the chain")


def seen_by_all(txid):
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in ACTIVE), 60)


def shared_address(node, twin):
    """A new address of `node` that its twin has in its address book too (as in
    scripts/vault-replies)"""
    address = node.rpc("getnewaddress")
    twin.rpc("setaccount", address, "")
    return address


mine(101)
MGR = shared_address(CM, IM)
DEST = shared_address(CO, IO)
OWNERS = [shared_address(CO, IO) for _ in range(3)]
VAULTS = [f"{o}:{MGR}" for o in OWNERS]
NAMES = {MGR: "<manager>", DEST: "<dest>"}
for k, o in enumerate(OWNERS):
    NAMES[o] = f"<owner {k + 1}>"
FUNDS = {}      # funding txid -> "vault k coin c"


def role_of(node, spk):
    addrs = spk.get("addresses", [])
    kind = spk.get("type", "")
    if kind == "vault" or (len(addrs) == 2 and kind != "multisig"):
        return "vault " + ":".join(NAMES.get(a, "<other>") for a in addrs)
    if addrs and addrs[0] in NAMES:
        return NAMES[addrs[0]]
    if not addrs:
        return kind or "<none>"
    return "<other address>"


def coinstake(node, height):
    """The coinstake of the block at `height`: its inputs (which funding coin)
    and its outputs (role, value), and the reward it takes"""
    block = node.rpc("getblock", node.rpc("getblockhash", height))
    tx = node.rpc("getrawtransaction", block["tx"][1], 1)
    ins, in_total = [], 0
    for v in tx["vin"]:
        prev = node.rpc("getrawtransaction", v["txid"], 1)
        value = prev["vout"][v["vout"]]["value"]
        in_total += round(float(value) * 1e8)
        ins.append((FUNDS.get(v["txid"], "<other coin>"), str(value)))
    outs, out_total = [], 0
    for v in tx["vout"]:
        outs.append((role_of(node, v.get("scriptPubKey", {})), str(v["value"])))
        out_total += round(float(v["value"]) * 1e8)
    return {"inputs": sorted(ins), "outputs": outs, "outputs minus inputs": (out_total - in_total) / 1e8}


def stake_reward(height):
    """What divid's staker adds to the staked coin at `height`: the stake and
    masternode parts of the block value (masternodes deprecated on regtest), the
    block value less the lottery part (LegacyBlockSubsidies.cpp:15-28, :45-90;
    regtest: subsidy halving every 100 blocks, chainparams.cpp:481), in satoshis"""
    subsidy = max(1250 - 100 * max(height // 100 - 1, 0), 250) * 100_000_000
    rest = subsidy - (50 * 100_000_000 if height >= 101 else 0)
    return rest * 38 // 100 + rest * 45 // 100


def special(height):
    """A lottery (every 10th from 101) or treasury (every 50th from 102) block
    (chainparams.cpp:490-493, LegacyBlockSubsidies.cpp:92-102)"""
    return (height >= 101 and height % 10 == 0) or (height >= 102 and height % 50 == 0)


def shape(view, height):
    """A coinstake as roles: which coins, the output roles, and whether the
    vault output is the inputs plus divid's stake reward for the height"""
    cs = view.get("coinstake")
    if not cs:
        return view
    ins = sum(round(float(v) * 1e8) for _, v in cs["inputs"])
    vault = sum(round(float(v) * 1e8) for r, v in cs["outputs"] if r.startswith("vault"))
    return generic({"inputs": [c for c, _ in cs["inputs"]],
                    "output roles": [r for r, _ in cs["outputs"]],
                    "vault output is the inputs plus the stake reward for the height": vault == ins + stake_reward(height),
                    "accepted by all four nodes": view.get("accepted by all four nodes"),
                    "staking status right after": view.get("staking status right after")})


def generic(v):
    """A round's own vault and coins named the same way in either round"""
    if isinstance(v, dict):
        return {k: generic(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [generic(x) for x in v]
    if isinstance(v, str):
        return re.sub(r"<owner [0-9]>", "<owner of the round>", re.sub(r"vault [0-9] coin", "vault coin", v))
    return v


def status(when, pairs=None, stale=False):
    """getstakingstatus on each twin pair: every member and value, then the
    members' order as sent"""
    p = f"{when}: " if when else ""
    for side, c, i in (pairs or PAIRS):
        cs, is_ = c.call("getstakingstatus"), i.call("getstakingstatus")
        # "staking status" says whether the node tried to stake in the last
        # moments (divid HasRecentlyAttemptedToGenerateProofOfStake): compared
        # right after each manager's own setgenerate instead
        drop = {"mnsync", "staking status"} | ({"staking_balance", "enoughcoins"} if stale and side == "manager" else set())
        compare(f"{p}{side} getstakingstatus", cs, is_, drop=drop, extra="getstakingstatus")
        if stale and side == "manager" and cs[0] == is_[0] == "ok":
            for n in (c, i):
                print(f"#   {n.name}: Stakable {n.rpc('getcoinavailability')['Stakable']}, vaults "
                      f"{json.dumps(n.rpc('getcoinavailability', True)['Stakable']['AllVaults'])[:300]}", flush=True)
            pick = lambda o: {k: o[1][k] for k in ("staking_balance", "enoughcoins")}
            row(f"{p}manager getstakingstatus staking_balance and enoughcoins (divid's cached balance)",
                json.dumps(pick(cs)), json.dumps(pick(is_)), pick(cs) == pick(is_))
        if cs[0] == is_[0] == "ok":
            a, b = cs[1].get("mnsync"), is_[1].get("mnsync")
            name = f"{p}{side} getstakingstatus mnsync" + ("" if a == b else " (divid's masternode sync not finished)")
            row(name, a, b, a == b)
        order_c = list(c.raw_call("getstakingstatus")["result"])
        order_i = [k for k in i.raw_call("getstakingstatus")["result"] if k in order_c]
        row(f"{p}{side} getstakingstatus: member order", ",".join(order_c), ",".join(order_i), order_c == order_i)
    for call in ("getstakingstatus",):
        found = extra_seen.pop(call, set())
        row(f"{p}getstakingstatus: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


def views(when, pairs=None, stale=False):
    # Coin age counts whole seconds (wallet.cpp:1477, regtest minimum 0): a
    # coin a wallet took in during the last second is not mintable yet, and the
    # two wallets may take the same coin in a fraction of a second apart. Wait
    # so that the views compare state, not that moment.
    time.sleep(2)
    p = f"{when}: "
    txkey = lambda e: (e.get("txid", ""), e.get("vout", 0), e.get("category", ""), str(e.get("amount", "")))
    for side, c, i in (pairs or PAIRS):
        q = f"{p}{side} "
        for args in ([], ["*", 1, True], ["*", 0]):
            compare(f"{q}getbalance {json.dumps(args)}", c.call("getbalance", *args), i.call("getbalance", *args))
        # Each account's balance (divid GetAccountBalance, rpcwallet.cpp:383-415:
        # credits at minconf or deeper, less debits and fees, leaving out an
        # immature transaction and a conflicted one, at depth < 0), the default
        # one and every one either wallet has
        accounts = {""}
        for n in (c, i):
            got = n.call("listaccounts", 0)
            if got[0] == "ok" and isinstance(got[1], dict):
                accounts |= set(got[1])
        for account in sorted(accounts):
            for minconf in (1, 0):
                compare(f"{q}getbalance {json.dumps(account)} {minconf}", c.call("getbalance", account, minconf),
                        i.call("getbalance", account, minconf))
        for minconf in (1, 0):
            compare(f"{q}listaccounts {minconf}", c.call("listaccounts", minconf), i.call("listaccounts", minconf))
        compare(f"{q}getunconfirmedbalance", c.call("getunconfirmedbalance"), i.call("getunconfirmedbalance"))
        compare(f"{q}listunspent", c.call("listunspent"), i.call("listunspent"),
                order=lambda u: (u.get("txid", ""), u.get("vout", 0)), drop=MOMENT | {"ischange", "solvable"})
        compare(f"{q}listtransactions * 100 0 true", c.call("listtransactions", "*", 100, 0, True),
                i.call("listtransactions", "*", 100, 0, True), order=txkey)
        for what, txid in TXS:
            cg, ig = c.call("gettransaction", txid, True), i.call("gettransaction", txid, True)
            # Which transactions this view finds conflicted (depth < 0), for the
            # account balance rows above
            if cg[0] == "ok" and isinstance(cg[1], dict) and cg[1].get("confirmations", 0) < 0:
                ic = ig[1].get("confirmations") if ig[0] == "ok" and isinstance(ig[1], dict) else ig[0]
                print(f"# {q}conflicted: {what} {txid[:8]}, confirmations divid {cg[1]['confirmations']}, "
                      f"irondivid {ic}", flush=True)
            if stale and side == "manager" and what.startswith("vault 1 coin") and cg[0] == ig[0] == "ok":
                compare(f"{q}gettransaction of {what} {txid[:8]}", cg, ig, drop=MOMENT | NOTES | {"amount"})
                row(f"{q}gettransaction of {what} amount (divid's cached credit)", cg[1]["amount"], ig[1]["amount"],
                    cg[1]["amount"] == ig[1]["amount"])
            else:
                compare(f"{q}gettransaction of {what} {txid[:8]}", cg, ig)
        compare(f"{q}getcoinavailability", c.call("getcoinavailability"), i.call("getcoinavailability"),
                extra="getcoinavailability")
        compare(f"{q}getcoinavailability true", c.call("getcoinavailability", True),
                i.call("getcoinavailability", True), mask=sort_txids, extra="getcoinavailability")
        cw, iw = c.call("getwalletinfo"), i.call("getwalletinfo")
        if cw[0] == iw[0] == "ok":
            compare(f"{q}getwalletinfo", cw, ("ok", {k: v for k, v in iw[1].items() if k in cw[1]}))
        else:
            compare(f"{q}getwalletinfo", cw, iw)
    found = extra_seen.pop("getcoinavailability", set())
    row(f"{p}getcoinavailability: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)
    status(when, pairs, stale)


def sort_txids(v):
    if isinstance(v, dict):
        return {k: sorted(x) if k == "txids" and isinstance(x, list) else sort_txids(x) for k, x in v.items()}
    if isinstance(v, list):
        return sorted((sort_txids(x) for x in v), key=lambda e: json.dumps(e, sort_keys=True))
    return v


def stake(node, what):
    """One block from `node` (a manager) with setgenerate; the coinstake, and
    whether every node accepts the block"""
    while special(node.rpc("getblockcount") + 1):
        mine(1)
    height = node.rpc("getblockcount")
    tip = node.rpc("getblock", node.rpc("getbestblockhash"))
    wait_for(lambda: time.time() > tip["time"] + 2, 120)
    out = None
    for _ in range(10):
        out = node.call("setgenerate", 1)
        if out[0] == "ok":
            break
        time.sleep(2)
    if out[0] != "ok":
        return {"error": short(out)}, height + 1
    staking_now = node.rpc("getstakingstatus").get("staking status")
    accepted = synced()
    view = coinstake(node, height + 1)
    print(f"#   {what}, block {height + 1}: {json.dumps(view)}"[:900], flush=True)
    return {"coinstake": view, "accepted by all four nodes": accepted,
            "staking status right after": staking_now}, height + 1


# --- the steps -------------------------------------------------------------------------

TXS = []        # (what, txid): every transaction the views read back with gettransaction


def fund(k, what, amount=VAULT_COIN, node=None, running=None):
    reply = (node or CO).rpc("fundvault", VAULTS[k], amount)
    txid = reply["txhash"] if isinstance(reply, dict) else reply
    FUNDS[txid] = what
    TXS.append((what, txid))
    if not wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in (running or NODES)), 60):
        raise RuntimeError(f"{what} did not reach every node")
    return txid


def add_both(k, txid, what):
    compare(f"addvault {what}: reply", CM.call("addvault", VAULTS[k], txid), IM.call("addvault", VAULTS[k], txid))


def remove_both(k, what):
    compare(f"removevault {what}: reply", CM.call("removevault", VAULTS[k]), IM.call("removevault", VAULTS[k]))


def connected(nodes):
    """Every node has a peer: getstakingstatus says haveconnections, and a node
    that has none yet would differ for that moment only"""
    if not wait_for(lambda: all(n.rpc("getconnectioncount") >= 1 for n in nodes), 120):
        raise RuntimeError("the nodes did not reconnect")


def note_scans(nodes):
    """Where each manager's start-up scan began (for reading a difference)"""
    for n in nodes:
        if n not in (CM, IM):
            continue
        found = []
        for path in (os.path.join(n.dir, "regtest", "debug.log"), os.path.join(n.dir, "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    found = [l.strip()[-100:] for l in f if "canning..." in l and "%" not in l or "atch-up scan: blocks" in l][-2:]
            except OSError:
                pass
        print(f"#   {n.name} start-up scan: {' | '.join(found)}", flush=True)


def restart_all(*args, nodes=None):
    nodes = nodes or NODES
    for n in nodes:
        n.stop()
    for n in nodes:
        n.start(*args)
    for n in nodes:
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not answer after a restart {' '.join(args)}: {n.tail()}")
    connected(nodes)
    if not wait_for(lambda: len(set(tips())) == 1, 300):
        raise RuntimeError("the nodes did not agree on the tip after a restart " + " ".join(args))
    note_scans(nodes)


def kind_of(node):
    return "irondivid" if node.binary == IRONDIVID else "divid"


def wallet_path(node):
    return os.path.join(node.dir, "wallet") if kind_of(node) == "irondivid" else os.path.join(node.dir, "regtest", "wallet.dat")


def backup(node, tag):
    """backupwallet into a folder of its own; the copy is what a user restores"""
    dest = os.path.join(WORK, f"bk-{tag}-{node.name}")
    os.makedirs(dest)
    node.rpc("backupwallet", dest)
    found = os.listdir(dest)
    if not found:
        raise RuntimeError(f"backupwallet of {node.name} left nothing in {dest}")
    return os.path.join(dest, found[0])


def restore_all(copies, nodes):
    """Stop the nodes, put each copy where its wallet is, start them"""
    for n in nodes:
        n.stop()
    for n in nodes:
        target = wallet_path(n)
        if os.path.isdir(target):
            shutil.rmtree(target)
        elif os.path.exists(target):
            os.unlink(target)
        if os.path.isdir(copies[n.name]):
            shutil.copytree(copies[n.name], target)
        else:
            shutil.copyfile(copies[n.name], target)
    for n in nodes:
        n.start()
    for n in nodes:
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not answer after starting from a backup: {n.tail()}")
    connected(nodes)
    if not wait_for(lambda: len(set(tips())) == 1, 300):
        raise RuntimeError("the nodes did not agree on the tip after starting from a backup")
    note_scans(nodes)




# --- -walletnotify -----------------------------------------------------------------------

NMARK = {}


def notify_log(node):
    try:
        with open(os.path.join(WORK, f"notify-{node.name}.log")) as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:
        return []


def label(txid):
    """A transaction as a reader wants it: what it is and where the chain has it"""
    named = {t: w for w, t in TXS}
    if txid in named:
        return named[txid]
    out = CO.call("getrawtransaction", txid, 1)
    if out[0] != "ok":
        return "not in the chain"
    raw = out[1]
    kind = "coinbase" if "coinbase" in raw["vin"][0] else ("coinstake" if raw["vout"][0]["value"] == 0 else "tx")
    where = ""
    if raw.get("blockhash"):
        blk = CO.rpc("getblock", raw["blockhash"])
        where = f", block {blk['height']} position {blk['tx'].index(txid)}"
    return f"{kind}, {raw.get('confirmations', 0)} confirmations{where}"


def notify_mark():
    """What was notified so far is not part of the next start"""
    time.sleep(3)
    for n in NODES:
        NMARK[n.name] = len(notify_log(n))


MADE_HERE = set()    # txids the divid owner made itself: told once more there, at its commit


def notify_rows(when):
    """The -walletnotify calls since the mark, on each pair: how many, and for
    which transactions (a transaction notified twice counts twice)"""
    time.sleep(4)
    got, seq = {}, {}
    for n in NODES:
        log = notify_log(n)
        seq[n.name] = [t[:6] for t in log[NMARK.get(n.name, 0):]]
        got[n.name] = sorted(log[NMARK.get(n.name, 0):])
        NMARK[n.name] = len(log)
    show = lambda l: f"{len(l)} calls, {len(set(l))} transactions"
    for side, c, i in PAIRS:
        lc, li = list(got[c.name]), got[i.name]
        if c is CO:
            for t in MADE_HERE:
                if t in lc and lc.count(t) > li.count(t):
                    lc.remove(t)
        row(f"{when}: {side} -walletnotify calls", show(lc), show(li), lc == li)
        if lc != li:
            only_c = {t[:8]: (lc.count(t), li.count(t)) for t in sorted(set(lc) | set(li)) if lc.count(t) != li.count(t)}
            only_i = ""
            print(f"#   {side} order on divid {seq[c.name]} on irondivid {seq[i.name]}", flush=True)
            for t in sorted(set(lc) | set(li)):
                if lc.count(t) != li.count(t):
                    print(f"#     {t[:8]}: {label(t)}: divid {lc.count(t)}, irondivid {li.count(t)}", flush=True)
            print(f"#   {side} -walletnotify, calls on divid and on irondivid where they differ: {only_c}", flush=True)


def cycle(when, *args):
    """Stop all four, start them (with `args`), then the notify log and the views"""
    notify_mark()
    restart_all(*args)
    notify_rows(when)
    views(when)


def pay(what, node, address, amount):
    txid = node.rpc("sendtoaddress", address, amount)
    TXS.append((what, txid))
    if not wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in ACTIVE), 60):
        raise RuntimeError(f"{what} did not reach every node")
    return txid


# --- the rounds ------------------------------------------------------------------------

def pools(when):
    """The mempools of each pair: the same transactions (a dropped payment may
    or may not be put back and rebroadcast)"""
    for side, c, i in PAIRS:
        a, b = sorted(c.rpc("getrawmempool")), sorted(i.rpc("getrawmempool"))
        named = {t: w for w, t in TXS}
        show = lambda l: ", ".join(named.get(t, t[:8]) for t in l) or "empty"
        row(f"{when}: {side} mempool", show(a), show(b), a == b)


def isolate_second():
    """The second miner without a peer: it keeps the chain it has"""
    SECOND.stop()
    SECOND.start()
    if not SECOND.wait_ready():
        raise RuntimeError(f"divid-second did not come back: {SECOND.tail()}")
    if SECOND.rpc("getconnectioncount") != 0:
        raise RuntimeError("divid-second has a peer")
    if SECOND.rpc("getbestblockhash") != CO.rpc("getbestblockhash"):
        raise RuntimeError("divid-second is not at the tip")


def join_second():
    """The second miner dials the first: its longer branch wins everywhere"""
    SECOND.rpc("addnode", f"{HOST}:{CO.p2p}", "onetry")
    if not wait_for(lambda: len({n.rpc("getbestblockhash") for n in list(NODES) + [SECOND]}) == 1, 180):
        for n in (CO, SECOND):
            print(f"#   {n.name} chain tips: {json.dumps(n.rpc('getchaintips'))[:600]}", flush=True)
        raise RuntimeError("the nodes did not agree after the branches met: " + ", ".join(
            f"{n.name} {n.rpc('getblockcount')}" for n in list(NODES) + [SECOND]))
    time.sleep(2)


def spend_raw(node, inputs, outputs):
    """A transaction of `node`'s wallet keys spending exactly `inputs`"""
    ins = [{"txid": t, "vout": v} for t, v in inputs]
    return node.rpc("signrawtransaction", node.rpc("createrawtransaction", ins, outputs))["hex"]


def plain_coin(minimum):
    for u in CO.rpc("listunspent"):
        if u["scriptPubKey"].startswith("76a914") and float(u["amount"]) >= minimum and u["confirmations"] > 40:
            return u
    raise RuntimeError("no plain coin")


FEE = 0.001


def reorg_round(name, branch_a, branch_b):
    """branch_a puts blocks on the first miner's chain, branch_b builds a longer
    one on the second miner; then they meet. The views and the -walletnotify log
    are compared before, on branch A, and after."""
    print(f"# round: {name}", flush=True)
    isolate_second()
    notify_mark()
    views(f"{name}: before")
    branch_a()
    notify_rows(f"{name}: on branch A")
    views(f"{name}: on branch A")
    pools(f"{name}: on branch A")
    notify_mark()
    branch_b()
    join_second()
    notify_rows(f"{name}: after the reorg")
    views(f"{name}: after the reorg")
    pools(f"{name}: after the reorg")


mine(101)
first = {}
for k in (0, 1):
    first[k] = fund(k, f"vault {k + 1} coin 1")
mine(1)
add_both(0, first[0], "vault 1")
add_both(1, first[1], "vault 2")
mine(25)
pay("plain coin for the manager", CO, MGR, 20)
mine(1)
if not wait_for(lambda: SECOND.rpc("getbestblockhash") == CO.rpc("getbestblockhash"), 60):
    raise RuntimeError("divid-second is not at the tip")

# 1. a payment that the new branch drops by a double spend
state = {}


def a1():
    c = plain_coin(100)
    state["coin"] = c
    amount = round(float(c["amount"]) - FEE, 8)
    raw = spend_raw(CO, [(c["txid"], c["vout"])], {MGR: amount})
    state["p"] = CO.rpc("sendrawtransaction", raw)
    TXS.append(("payment the new branch drops", state["p"]))
    wait_for(lambda: all(state["p"] in n.rpc("getrawmempool") for n in ACTIVE), 60)
    mine(2)


def b1():
    c = state["coin"]
    raw = spend_raw(SECOND, [(c["txid"], c["vout"])], {DEST: round(float(c["amount"]) - FEE, 8)})
    state["q"] = SECOND.rpc("sendrawtransaction", raw)
    TXS.append(("double spend on the new branch", state["q"]))
    mine(4, SECOND, follow=[])


reorg_round("double spend", a1, b1)

# 2. a chain of three transactions in three blocks; the new branch drops the first,
# so the other two lose their input
def a2():
    c = plain_coin(100)
    state["coin2"] = c
    change = [shared_address(CO, IO) for _ in range(2)]
    amount = float(c["amount"])
    a_out = {MGR: 3, change[0]: round(amount - 3 - FEE, 8)}
    a_tx = CO.rpc("sendrawtransaction", spend_raw(CO, [(c["txid"], c["vout"])], a_out))
    TXS.append(("chain a", a_tx))
    wait_for(lambda: all(a_tx in n.rpc("getrawmempool") for n in ACTIVE), 60)
    mine(1)
    a_raw = CO.rpc("getrawtransaction", a_tx, 1)
    ch = next(v["n"] for v in a_raw["vout"] if change[0] in v["scriptPubKey"].get("addresses", []))
    left = float(a_raw["vout"][ch]["value"])
    b_tx = CO.rpc("sendrawtransaction", spend_raw(CO, [(a_tx, ch)], {MGR: 4, change[1]: round(left - 4 - FEE, 8)}))
    TXS.append(("chain b", b_tx))
    wait_for(lambda: all(b_tx in n.rpc("getrawmempool") for n in ACTIVE), 60)
    mine(1)
    b_raw = CO.rpc("getrawtransaction", b_tx, 1)
    ch = next(v["n"] for v in b_raw["vout"] if change[1] in v["scriptPubKey"].get("addresses", []))
    left = float(b_raw["vout"][ch]["value"])
    c_tx = CO.rpc("sendrawtransaction", spend_raw(CO, [(b_tx, ch)], {MGR: 5, DEST: round(left - 5 - FEE, 8)}))
    TXS.append(("chain c", c_tx))
    wait_for(lambda: all(c_tx in n.rpc("getrawmempool") for n in ACTIVE), 60)
    mine(1)


def b2():
    c = state["coin2"]
    raw = spend_raw(SECOND, [(c["txid"], c["vout"])], {DEST: round(float(c["amount"]) - FEE, 8)})
    TXS.append(("double spend of the chain's first", SECOND.rpc("sendrawtransaction", raw)))
    mine(5, SECOND, follow=[])


reorg_round("chain of three", a2, b2)

# 3. blocks staked by the owner are orphaned, nothing else of the wallets' in them
def a3():
    mine(3)


def b3():
    SECOND.rpc("sendtoaddress", DEST, 1)
    mine(4, SECOND, follow=[])


reorg_round("orphaned stakes", a3, b3)

# 4. a vault funding the new branch drops, and a coinstake of the manager's vault
# is orphaned
def a4():
    reply = CO.rpc("fundvault", VAULTS[0], 50)
    txid = reply["txhash"] if isinstance(reply, dict) else reply
    FUNDS[txid] = "vault 1 coin the new branch drops"
    MADE_HERE.add(txid)
    TXS.append(("vault funding the new branch drops", txid))
    state["vfund"] = txid
    wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in ACTIVE), 60)
    mine(1)
    # the manager stakes a block of its vault coins on this branch
    tip = CM.rpc("getblock", CM.rpc("getbestblockhash"))
    wait_for(lambda: time.time() > tip["time"] + 2, 60)
    while special(CM.rpc("getblockcount") + 1):
        mine(1)
    plain = [{"txid": u["txid"], "vout": u["vout"]} for u in CM.rpc("listunspent") if u["scriptPubKey"].startswith("76a914")]
    if plain:
        CM.rpc("lockunspent", False, plain)
    for _ in range(10):
        out = CM.call("setgenerate", 1)
        if out[0] == "ok":
            break
        time.sleep(2)
    if plain:
        CM.rpc("lockunspent", True, plain)
    if not synced():
        raise RuntimeError("the nodes did not follow the manager's block")


def b4():
    raw_in = CO.rpc("getrawtransaction", state["vfund"], 1)["vin"]
    inputs = [(v["txid"], v["vout"]) for v in raw_in]
    total = sum(float(CO.rpc("getrawtransaction", t, 1)["vout"][n]["value"]) for t, n in inputs)
    TXS.append(("double spend of the vault funding", SECOND.rpc("sendrawtransaction", spend_raw(SECOND, inputs, {DEST: round(total - FEE, 8)}))))
    mine(5, SECOND, follow=[])


reorg_round("vault", a4, b4)

# 5. both managers killed with blocks and payments behind them, then started
notify_mark()
for k in range(4):
    pay(f"payment before the kill {k + 1}", CO, MGR, 2)
    mine(1)
views("before the kill")
notify_mark()
for n in (CM, IM):
    n.proc.kill()
    n.proc.wait()
    n.log.close()
IM.start()
CM.start()
reindexed = False
if not IM.wait_ready():
    raise RuntimeError(f"irondivid-manager did not answer after the kill: {IM.tail()}")
if not CM.wait_ready():
    # divid's block index is not on disk after a kill: it stops and asks for -reindex
    # (BlockIndexLoading.cpp:262-276); irondivid starts
    reason = "Failed to find best block in block index" if "best block" in CM.tail(8) else CM.tail()[:80]
    row("start after a kill: the managers start", f"divid stops: {reason}", "irondivid starts", False)
    CM.log.close()
    CM.start("-reindex")
    reindexed = True
    if not CM.wait_ready():
        raise RuntimeError(f"divid-manager did not answer after -reindex: {CM.tail()}")
connected(ACTIVE)
wait_for(lambda: len(set(tips())) == 1, 300)
notify_rows("start after a kill" + (" (divid with -reindex)" if reindexed else ""))
views("start after a kill" + (" (divid with -reindex)" if reindexed else ""))

for n in list(NODES) + [SECOND]:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
