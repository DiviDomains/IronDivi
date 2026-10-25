#!/usr/bin/env python3
"""What vaults and their records do across the life of a wallet, on Divi Core
divid and on irondivid.

Four nodes on one regtest chain: divid's owner wallet (it mines) and manager
wallet (-vault=1), and an irondivid owner and manager restored from the same two
phrases, so each irondivid wallet holds the same keys as its divid twin and sees
the same vault coins. Three vaults (one removed with removevault, one kept, one
never added), then, one after the other: removevault, a restart, -rescan,
-reindex, -zapwallettxes=1 and =2, backupwallet and a start from the copy (made
after removevault, and made before it), dumpwallet into fresh wallets with
importwallet, and vaults funded while the managers are down. After each step the
replies of each twin pair are compared (balances, unspent coins, transactions,
coin availability, wallet info, staking status), and at a few points each
manager stakes a block to see which vaults it stakes. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases and keys live only in memory, in an RPC reply, in irondivid's
environment and in the work directory's wallet files; they are never printed or
put on a command line.
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
INJECT = os.environ.get("VAULT_RECORDS_INJECT", "")
DUMP = os.environ.get("VAULT_RECORDS_DUMP", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
VAULT_COIN = 500           # each vault coin funded

KNOWN = {
    "*getcoinavailability: fields divid lacks":
        "total_vaults and vaults, kept as extra fields (divid getcoinavailability, rpcwallet.cpp:818-987, has "
        "Vaulted, Stakable, Spendable); also KNOWN in scripts/vault-replies",
    "*getstakingstatus: fields divid lacks":
        "\"staking status text\", the string irondivid gave before the field became a bool, kept for older "
        "callers (docs/rpc-parity-audit.md: getstakingstatus; divid: rpcmisc.cpp:1059-1076)",
    "*: manager gettransaction of vault 1 coin * amount (divid's cached credit)":
        "by design: divid keeps each transaction's credit in CachedTransactionDeltasCalculator "
        "(CachedTransactionDeltasCalculator.cpp:108-118), filled before removevault and not cleared by it "
        "(wallet.cpp:707-716), so gettransaction still counts the removed vault's coin until the next start; "
        "irondivid works the amount out from the wallet as it is, as it does after that start",
    "*: manager getstakingstatus staking_balance and enoughcoins (divid's cached balance)":
        "by design: divid keeps each transaction's balance in CachedUtxoBalanceCalculator "
        "(CachedUtxoBalanceCalculator.cpp:11-32), filled before removevault and not cleared by it "
        "(wallet.cpp:707-716), so the staking balance still counts the removed vault's coins until the next "
        "start; irondivid's agrees with listunspent and getcoinavailability, which divid also gives without the vault",
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


# --- the nodes -----------------------------------------------------------------------

CO = Node("divid-owner", DIVID, 0, ["listen=1"])
if not CO.wait_ready():
    print(f"FAIL   start: divid owner did not answer: {CO.tail()}", flush=True)
    sys.exit(1)
CM = Node("divid-manager", DIVID, 1, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1"])
if not CM.wait_ready():
    print(f"FAIL   start: divid manager did not answer: {CM.tail()}", flush=True)
    sys.exit(1)
owner_phrase, manager_phrase = CO.rpc("dumphdinfo")["mnemonic"], CM.rpc("dumphdinfo")["mnemonic"]
IO = Node("irondivid-owner", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{CO.p2p}"],
          env={"WALLET_MNEMONIC": owner_phrase})
IM = Node("irondivid-manager", IRONDIVID, 3, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1"],
          env={"WALLET_MNEMONIC": manager_phrase})
del owner_phrase, manager_phrase
for n in (IO, IM):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer: {n.tail()}", flush=True)
        sys.exit(1)
NODES = (CO, CM, IO, IM)
PAIRS = (("owner", CO, IO), ("manager", CM, IM))
print(f"# divid {CO.rpc('getinfo').get('version')}, irondivid {IO.rpc('getnetworkinfo').get('version')}", flush=True)


ACTIVE = list(NODES)      # the nodes that are running; the managers are stopped for a while


def tips():
    return [n.rpc("getbestblockhash") for n in ACTIVE]


def synced(secs=120):
    return wait_for(lambda: len(set(tips())) == 1, secs)


def mine(n=1):
    for _ in range(n):
        out = CO.call("setgenerate", 1)
        if out[0] != "ok":
            # divid stakes from the clock back: let it pass the tip, then again
            tip = CO.rpc("getblock", CO.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            CO.rpc("setgenerate", 1)
    if not synced():
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
        compare(f"{q}listunspent", c.call("listunspent"), i.call("listunspent"),
                order=lambda u: (u.get("txid", ""), u.get("vout", 0)), drop=MOMENT | {"ischange", "solvable"})
        compare(f"{q}listtransactions * 100 0 true", c.call("listtransactions", "*", 100, 0, True),
                i.call("listtransactions", "*", 100, 0, True), order=txkey)
        for what, txid in TXS:
            cg, ig = c.call("gettransaction", txid, True), i.call("gettransaction", txid, True)
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


def plain_send(when):
    """The manager wallets spend plain coins of their own. The owner pays a coin
    of 30 to the manager key (it holds no other plain coin, so a stake can only
    choose between vaults) and the manager sends part of it on, divid's manager
    with one coin and then irondivid's with another"""
    c = i = None
    for node in (CM, IM):
        txid = CO.rpc("sendtoaddress", MGR, 30)
        TXS.append((f"plain coin {node.name} {when}", txid))
        seen_by_all(txid)
        mine(1)
        out = node.call("sendtoaddress", DEST, 10)
        if out[0] == "ok":
            seen_by_all(out[1])
        if node is CM:
            c = out
        else:
            i = out
        mine(1)
    compare(f"{when}: manager sendtoaddress of a plain coin", c, i, mask=lambda v: masked(v, NAMES))


def vault_names(node, txid, vouts=None):
    """The vaults (by their owner) that a transaction's outputs, or the given
    outputs, pay"""
    raw = node.rpc("getrawtransaction", txid, 1)
    out = set()
    for n, v in enumerate(raw["vout"]):
        if vouts is not None and n not in vouts:
            continue
        r = role_of(node, v.get("scriptPubKey", {}))
        if r.startswith("vault"):
            out.add(r)
    return out


def stake_probe(when, compare_vault1):
    """Each manager stakes one block, divid's first. Compared: whether the
    block is accepted by all and whether the coinstake spends a coin of vault 1.
    Which vault a manager picks among those it may stake is not fixed, so vault
    1 is asked about only when it is the one vault left to stake or the one that
    must not be staked"""
    seen = []
    for node in (CM, IM):
        mine(25)
        # plain coins out of the way (locked coins are not staked): a manager
        # may stake a plain coin or a vault coin, and the two do not choose alike
        plain = [{"txid": u["txid"], "vout": u["vout"]} for u in node.rpc("listunspent")
                 if u["scriptPubKey"].startswith("76a914")]
        if plain:
            node.rpc("lockunspent", False, plain)
        view, height = stake(node, node.name)
        if plain:
            node.rpc("lockunspent", True, plain)
        if "coinstake" in view:
            block = node.rpc("getblock", node.rpc("getblockhash", height))
            cs = node.rpc("getrawtransaction", block["tx"][1], 1)
            spends = set()
            for v in cs["vin"]:
                spends |= vault_names(node, v["txid"], {v["vout"]})
            vault1 = f"vault {NAMES[OWNERS[0]]}:<manager>"
            view = {"stakes a coin of vault 1": vault1 in spends,
                    "accepted by all four nodes": view.get("accepted by all four nodes")}
        seen.append(view)
        print(f"#   {when}, {node.name}: {json.dumps(view)}"[:600], flush=True)
    keep = lambda v: {k: x for k, x in v.items() if compare_vault1 or k != "stakes a coin of vault 1"}
    compare(f"{when}: the managers' stakes", ("ok", keep(seen[0])), ("ok", keep(seen[1])))


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


# Setup: plain coins for the managers, three vaults. Vault 1 gets removed; vault 2
# stays registered all along; vault 3 is funded but never added.
mine(101)
mine(1)
first = {}
for k in (0, 1):
    first[k] = fund(k, f"vault {k + 1} coin 1")
mine(1)
fund(2, "vault 3 coin 1")
mine(1)
add_both(0, first[0], "vault 1")
add_both(1, first[1], "vault 2")
# a second coin after addvault, seen as it arrives
for k in (0, 1):
    fund(k, f"vault {k + 1} coin 2")
mine(1)
mine(25)
views("registered")
copies0 = {n.name: backup(n, "registered") for n in NODES}
print("# backupwallet taken with vaults 1 and 2 registered", flush=True)

# 1. a restart, vaults registered: nothing may change
restart_all()
views("registered, after a restart")
plain_send("registered")

# 2. removevault, then every way the wallet comes back. Each block removes vault 1
# again first, so it starts from a removed vault whatever the one before did.
remove_both(0, "vault 1")
views("after removevault", stale=True)
plain_send("after removevault")
stake_probe("after removevault", True)
remove_both(0, "vault 1 again")
views("after removevault again", stale=True)

for what, args in (("a restart", ()), ("-rescan", ("-rescan",)), ("-reindex", ("-reindex",)),
                   ("-zapwallettxes=1", ("-zapwallettxes=1",)), ("-zapwallettxes=2", ("-zapwallettxes=2",))):
    remove_both(0, f"vault 1 before {what}")
    restart_all(*args)
    views(f"removed, after {what}")
plain_send("removed, after the restarts")
# a start brings vault 1 back; vault 2 out of the way, only vault 1 can be staked
remove_both(1, "vault 2 before the stake")
stake_probe("after the restarts, only vault 1 left", True)

# 3. backupwallet of a wallet with vault 1 removed, started from the copy
remove_both(0, "vault 1 before the backup")
copies1 = {n.name: backup(n, "removed") for n in NODES}
mine(2)
restore_all(copies1, NODES)
views("removed, started from its own backup")

# 4. started from the copy made while vault 1 was registered
remove_both(0, "vault 1 before the old copy")
restore_all(copies0, NODES)
views("removed, started from the copy made before removevault")
remove_both(1, "vault 2 before the stake")
stake_probe("started from the copy made before removevault, only vault 1 left", True)

# 5. Divi Core 3.0.0 has no dumpwallet or importwallet (rpcserver.cpp:420-464): the
# manager key goes into fresh wallets with dumpprivkey and importprivkey
remove_both(0, "vault 1 before importprivkey")
FM = Node("divid-fresh", DIVID, 4, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1"])
FI = Node("irondivid-fresh", IRONDIVID, 5, ["listen=0", f"connect={HOST}:{CO.p2p}", "vault=1"])
for n in (FM, FI):
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not start: {n.tail()}")
FRESH = (FM, FI)
if not wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES + FRESH}) == 1, 120):
    raise RuntimeError("the fresh nodes did not sync")
manager_key = CM.rpc("dumpprivkey", MGR)
imports = [n.call("importprivkey", manager_key, "", True) for n in FRESH]
del manager_key
compare("importprivkey of the manager key: reply", imports[0], imports[1])
views("fresh wallets with the manager key", pairs=(("fresh manager", FM, FI),))
# The funding coin of vault 2 was staked long ago. irondivid refuses to add a vault
# with a spent funding output; divid adds it. Add with a fresh coin.
newcoin = fund(1, "vault 2 coin for the fresh wallets")
# two blocks, so the coin is not in the last block when the managers stop: divid
# scans its last block again at every start (wallet.cpp:258-269), irondivid starts
# above the last block it scanned
mine(2)
for n in (CM, IM):
    print(f"#   {n.name}: the coin paid to removed vault 2 {'is' if n.call('gettransaction', newcoin)[0] == 'ok' else 'is not'} in the wallet", flush=True)
FRESH_PAIR = (("fresh manager", FM, FI),)
compare("addvault vault 2 on the fresh wallets: reply", FM.call("addvault", VAULTS[1], newcoin),
        FI.call("addvault", VAULTS[1], newcoin))
views("fresh wallets after addvault", pairs=FRESH_PAIR)
restart_all(nodes=FRESH)
views("fresh wallets after a restart", pairs=FRESH_PAIR)
restart_all("-rescan", nodes=FRESH)
views("fresh wallets after -rescan", pairs=FRESH_PAIR)
for n in FRESH:
    n.stop()

# 6. vaults funded while the managers are down
remove_both(0, "vault 1 before the managers stop")
for n in (CM, IM):
    n.stop()
    ACTIVE.remove(n)
down = [fund(k, f"vault {k + 1} funded while the managers were down", node=CO, running=(CO, IO)) for k in (0, 1, 2)]
TXS_DOWN = down
mine(3)
for n in (CM, IM):
    n.start()
for n in (CM, IM):
    if not n.wait_ready():
        raise RuntimeError(f"{n.name} did not answer: {n.tail()}")
    ACTIVE.append(n)
connected(ACTIVE)
note_scans((CM, IM))
if not wait_for(lambda: len(set(tips())) == 1, 300):
    raise RuntimeError("the managers did not catch up")
views("funded while the managers were down")
add_both(2, down[2], "vault 3 (never added) with its funding from the downtime")
mine(1)
views("vault 3 added")
remove_both(1, "vault 2 before the stake")
remove_both(2, "vault 3 before the stake")
stake_probe("after the downtime, only vault 1 left", True)

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
