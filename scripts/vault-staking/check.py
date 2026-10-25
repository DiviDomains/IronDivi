#!/usr/bin/env python3
"""Vaults staking for their owner, on Divi Core divid and on irondivid.

Four nodes on one regtest chain: divid's owner wallet (it mines) and manager
wallet (-vault=1), and an irondivid owner and manager restored from the same two
phrases, so each irondivid wallet holds the same keys as its divid twin and sees
the same vault coins. Each manager stakes vault coins in turn with setgenerate:
divid's manager a first vault, irondivid's manager a second vault funded the
same way, so the two coinstakes can be compared amount for amount; every node
must accept every block. Around that: the staking status, the wallet views of
each twin pair, the owner's withdrawals, removevault, a restart and -reindex of
the managers, and a locked manager unlocked for staking only. Each row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
phrases and the passphrase live only in memory, in an RPC reply and in
irondivid's environment; they are never printed or put on a command line.
"""

import base64
import fnmatch
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("VAULT_STAKING_INJECT", "")
DUMP = os.environ.get("VAULT_STAKING_DUMP", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 180
COIN_VALUE = 1000          # each vault coin funded
COINS_PER_VAULT = 3        # in separate transactions, so a stake can combine them

KNOWN = {
    "*getcoinavailability: fields divid lacks":
        "total_vaults and vaults, kept as extra fields (divid getcoinavailability, rpcwallet.cpp:818-987, has "
        "Vaulted, Stakable, Spendable); also KNOWN in scripts/vault-replies",
    "*getstakingstatus: fields divid lacks":
        "\"staking status text\", the string irondivid gave before the field became a bool, kept for older "
        "callers (docs/rpc-parity-audit.md: getstakingstatus; divid: rpcmisc.cpp:1059-1076)",
    "*getstakingstatus mnsync (divid's masternode sync not finished)":
        "open: true, as irondivid has no masternode sync and counts it finished; divid gives false on a "
        "regtest node with no masternodes (rpcmisc.cpp:1068; the same gap as mnsync status in scripts/net-replies)",
    "*: manager listtransactions * 100 0 true (a removed vault's records)":
        "open: after removevault divid still lists the records of the removed vault's coins until it restarts "
        "(removevault drops the script from memory only, wallet.cpp:707-716; the transactions stay in mapWallet); "
        "irondivid drops them at once; as in scripts/vault-replies",
    "after the managers *: removevault vault [12] again (divid manages it again)":
        "open: divid's removevault drops the vault script from memory only (wallet.cpp:707-716), and a "
        "restart or -reindex reads it back from the wallet file, so divid manages the vault again and "
        "removes it again (true); irondivid removed it for good (false); as in scripts/vault-replies",
    "locked manager: setgenerate":
        "divid's locked wallet throws from key derivation (CWallet::GetKey, wallet.cpp:544) and the RPC layer "
        "returns that text as -1; irondivid answers -25 \"failed to generate a valid block\", as divid does "
        "when no stake is found (rpcmining.cpp:110)",
    "*getstakingstatus: member order":
        "members in name order, not in divid's insertion order (docs/divid-differences.md R6)",
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
        user = "staking" + name.replace("-", "")
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


def tips():
    return [n.rpc("getbestblockhash") for n in NODES]


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
    return wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in NODES), 60)


def shared_address(node, twin):
    """A new address of `node` that its twin has in its address book too (as in
    scripts/vault-replies)"""
    address = node.rpc("getnewaddress")
    twin.rpc("setaccount", address, "")
    return address


mine(101)
MGR = shared_address(CM, IM)
DEST = shared_address(CO, IO)
OWNERS = [shared_address(CO, IO) for _ in range(4)]
VAULTS = [f"{o}:{MGR}" for o in OWNERS]
NAMES = {MGR: "<manager>", DEST: "<dest>"}
for k, o in enumerate(OWNERS):
    NAMES[o] = f"<owner {k + 1}>"
FUNDS = {}      # funding txid -> "vault k coin c"
# Set once a vault the managers held coin records of is removed (divid keeps
# those records, irondivid drops them)
REMOVED_WITH_RECORDS = False


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


def status(when):
    """getstakingstatus on each twin pair: every member and value, then the
    members' order as sent"""
    p = f"{when}: " if when else ""
    for side, c, i in PAIRS:
        cs, is_ = c.call("getstakingstatus"), i.call("getstakingstatus")
        # "staking status" says whether the node tried to stake in the last
        # moments (divid HasRecentlyAttemptedToGenerateProofOfStake): compared
        # right after each manager's own setgenerate instead
        compare(f"{p}{side} getstakingstatus", cs, is_, drop={"mnsync", "staking status"}, extra="getstakingstatus")
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


def views(when, since=None):
    # Coin age counts whole seconds (wallet.cpp:1477, regtest minimum 0): a
    # coin a wallet took in during the last second is not mintable yet, and the
    # two wallets may take the same coin in a fraction of a second apart. Wait
    # so that mintablecoins compares state, not that moment.
    time.sleep(2)
    p = f"{when}: "
    txkey = lambda e: (e.get("txid", ""), e.get("vout", 0), e.get("category", ""), str(e.get("amount", "")))
    for side, c, i in PAIRS:
        q = f"{p}{side} "
        for args in ([], ["*", 1, True], ["*", 0]):
            compare(f"{q}getbalance {json.dumps(args)}", c.call("getbalance", *args), i.call("getbalance", *args))
        compare(f"{q}listunspent", c.call("listunspent"), i.call("listunspent"),
                order=lambda u: (u.get("txid", ""), u.get("vout", 0)), drop=MOMENT | {"ischange", "solvable"})
        lt_name = f"{q}listtransactions * 100 0 true"
        if side == "manager" and REMOVED_WITH_RECORDS:
            lt_name += " (a removed vault's records)"
        compare(lt_name, c.call("listtransactions", "*", 100, 0, True),
                i.call("listtransactions", "*", 100, 0, True), order=txkey)
        if since:
            compare(f"{q}listsinceblock", c.call("listsinceblock", since, 1, True),
                    i.call("listsinceblock", since, 1, True), order=txkey)
        compare(f"{q}getcoinavailability", c.call("getcoinavailability"), i.call("getcoinavailability"),
                extra="getcoinavailability")
    found = extra_seen.pop("getcoinavailability", set())
    row(f"{p}getcoinavailability: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)
    status(when)


def fund_vault(k, owner):
    """Fund vault k with COINS_PER_VAULT coins of COIN_VALUE, each in its own
    transaction from `owner`; the first confirmed before both managers add the
    vault with it"""
    txids = []
    for c in range(COINS_PER_VAULT):
        reply = owner.rpc("fundvault", VAULTS[k], COIN_VALUE)
        txid = reply["txhash"] if isinstance(reply, dict) else reply
        FUNDS[txid] = f"vault {k + 1} coin {c + 1}"
        if not seen_by_all(txid):
            raise RuntimeError(f"the funding of vault {k + 1} did not reach every node")
        txids.append(txid)
        if c == 0:
            mine(1)
            compare(f"vault {k + 1}: addvault", CM.call("addvault", VAULTS[k], txid),
                    IM.call("addvault", VAULTS[k], txid))
    mine(1)
    return txids


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

status("before any vault")
compare("refused: addvault of a vault with an unknown funding", CM.call("addvault", VAULTS[0], "11" * 32),
        IM.call("addvault", VAULTS[0], "11" * 32))
compare("refused: removevault of an unknown vault", CM.call("removevault", VAULTS[2]),
        IM.call("removevault", VAULTS[2]))

# Round 1: vault 1, funded by divid's owner, staked by divid's manager
mark = CO.rpc("getbestblockhash")
fund_vault(0, CO)
compare("vault 1: addvault again", CM.call("addvault", VAULTS[0], next(iter(FUNDS))),
        IM.call("addvault", VAULTS[0], next(iter(FUNDS))))
mine(25)
views("vault 1 funded and mature", since=mark)
mark = CO.rpc("getbestblockhash")
first, h1 = stake(CM, "divid's manager")
print(f"# round 1: divid's manager staked block {h1}", flush=True)
row(f"block {h1} (divid's manager, vault 1) accepted by all four nodes", "-",
    first.get("accepted by all four nodes", first.get("error")), first.get("accepted by all four nodes") is True)
views("after divid's manager staked", since=mark)

# Round 2: both managers drop vault 1; vault 2 funded the same way by
# irondivid's owner and staked by irondivid's manager
compare("removevault vault 1", CM.call("removevault", VAULTS[0]), IM.call("removevault", VAULTS[0]))
compare("removevault vault 1 again", CM.call("removevault", VAULTS[0]), IM.call("removevault", VAULTS[0]))
mark = CO.rpc("getbestblockhash")
fund_vault(1, IO)
mine(25)
views("vault 2 funded and mature", since=mark)
mark = CO.rpc("getbestblockhash")
second, h2 = stake(IM, "irondivid's manager")
print(f"# round 2: irondivid's manager staked block {h2}", flush=True)
row(f"block {h2} (irondivid's manager, vault 2) accepted by all four nodes", "-",
    second.get("accepted by all four nodes", second.get("error")), second.get("accepted by all four nodes") is True)
compare(f"irondivid's manager stakes vault 2 (block {h2}) as divid's staked vault 1 (block {h1})",
        ("ok", shape(first, h1)), ("ok", shape(second, h2)))
if h1 // 100 == h2 // 100:
    compare(f"the two stakes' amounts (blocks {h1} and {h2}, one subsidy period)",
            ("ok", generic(first)), ("ok", generic(second)))
row("the stake after removevault spends no coin of vault 1", "-",
    json.dumps(second.get("coinstake", {}).get("inputs", []))[:200],
    not any("vault 1" in c for c, _ in second.get("coinstake", {}).get("inputs", [])))
views("after irondivid's manager staked", since=mark)

# The owner takes coins out of vault 2 while it is managed, then all of it
# after the managers dropped it. Each side's call needs a confirmed coin of its
# own, so vault 2 gets two more first.
for c in range(2):
    reply = CO.rpc("fundvault", VAULTS[1], 500)
    txid = reply["txhash"] if isinstance(reply, dict) else reply
    FUNDS[txid] = f"vault 2 extra coin {c + 1}"
    seen_by_all(txid)
mine(1)
step = lambda what, c, i: compare(what, c, i, mask=lambda v: masked(v, NAMES))
d = CO.call("debitvaultbyname", VAULTS[1], DEST, 100)
if d[0] == "ok":
    seen_by_all(d[1])
i = IO.call("debitvaultbyname", VAULTS[1], DEST, 100)
if i[0] == "ok":
    seen_by_all(i[1])
step("debitvaultbyname part of a managed vault", d, i)
mine(1)
r = CO.call("reclaimvaultfunds", DEST, 100)
if r[0] == "ok":
    seen_by_all(r[1])
s = IO.call("reclaimvaultfunds", DEST, 100)
if s[0] == "ok":
    seen_by_all(s[1])
step("reclaimvaultfunds part", r, s)
mine(1)
views("after the owner took part out")
compare("removevault vault 2", CM.call("removevault", VAULTS[1]), IM.call("removevault", VAULTS[1]))
REMOVED_WITH_RECORDS = True
sweep = CO.call("debitvaultbyname", VAULTS[1], DEST, 1, "sweep_funds")
if sweep[0] == "ok":
    seen_by_all(sweep[1])
mine(1)
compare("debitvaultbyname sweep_funds of a removed vault: what is left in it",
        ("ok", CO.rpc("getcoinavailability")), ("ok", IO.rpc("getcoinavailability")), extra="getcoinavailability")
extra_seen.pop("getcoinavailability", None)
views("after the owner swept vault 2")

# Vault 3 for the restarts and the locked manager
mark = CO.rpc("getbestblockhash")
fund_vault(2, CO)
mine(25)
views("vault 3 funded and mature", since=mark)

def remove_again(when):
    # divid shows a removed vault's records until it restarts; once the vault
    # is removed again after the restart, both show none
    global REMOVED_WITH_RECORDS
    REMOVED_WITH_RECORDS = False
    for k in (0, 1):
        c, i = CM.call("removevault", VAULTS[k]), IM.call("removevault", VAULTS[k])
        name = f"{when}: removevault vault {k + 1} again"
        if c != i:
            name += " (divid manages it again)"
        compare(name, c, i)


for n in (CM, IM):
    n.restart()
if not synced():
    raise RuntimeError("the managers did not reconnect after the restart")
remove_again("after the managers restarted")
views("after the managers restarted")
for n in (CM, IM):
    n.restart("-reindex")
if not wait_for(lambda: len(set(tips())) == 1, 300):
    raise RuntimeError("the managers did not finish -reindex")
remove_again("after the managers -reindex")
views("after the managers -reindex")

# Locked: both managers encrypted with one throwaway passphrase
passphrase = secrets.token_hex(16)
for n in (CM, IM):
    n.call("encryptwallet", passphrase)
for n in (CM, IM):
    # divid stops after encryptwallet (rpcwallet.cpp encryptwallet); start it again
    if n.proc.poll() is not None or n.call("getwalletinfo")[0] != "ok":
        n.proc.wait(timeout=90)
        n.log.close()
        n.start()
        if not n.wait_ready():
            raise RuntimeError(f"{n.name} did not come back after encryptwallet")
synced()
remove_again("after the managers restarted for encryptwallet")
status("manager locked")
compare("locked manager: setgenerate", CM.call("setgenerate", 1), IM.call("setgenerate", 1))
synced()
for n in (CM, IM):
    n.rpc("walletpassphrase", passphrase, 600, True)
del passphrase
status("manager unlocked for staking only")
mark = CO.rpc("getbestblockhash")
third, h3 = stake(CM, "divid's manager, staking only")
print(f"# staking only: divid's manager staked block {h3}", flush=True)
row(f"block {h3} (divid's staking-only manager, vault 3) accepted by all four nodes", "-",
    third.get("accepted by all four nodes", third.get("error")), third.get("accepted by all four nodes") is True)
views("after divid's staking-only manager staked", since=mark)
compare("removevault vault 3 (staking only)", CM.call("removevault", VAULTS[2]), IM.call("removevault", VAULTS[2]))
fund_vault(3, IO)
mine(25)
mark = CO.rpc("getbestblockhash")
fourth, h4 = stake(IM, "irondivid's manager, staking only")
print(f"# staking only: irondivid's manager staked block {h4}", flush=True)
row(f"block {h4} (irondivid's staking-only manager, vault 4) accepted by all four nodes", "-",
    fourth.get("accepted by all four nodes", fourth.get("error")), fourth.get("accepted by all four nodes") is True)
compare(f"staking-only: irondivid's manager stakes vault 4 (block {h4}) as divid's staked vault 3 (block {h3})",
        ("ok", shape(third, h3)), ("ok", shape(fourth, h4)))
views("after irondivid's staking-only manager staked", since=mark)

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
