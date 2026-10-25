#!/usr/bin/env python3
"""Chain state other than the wallet across a reorganisation, on Divi Core divid
and on irondivid. Two sides, each a divid bridge with a divid and an irondivid
behind it (dialling it); the sides are split by a restart and joined by
`addnode onetry`. Competing branches of 1, 6 and 25 blocks (past the 20 blocks
of coin maturity, in proof of work) are built on the two sides and joined; after
each join the pair behind each bridge is compared: getblockchaininfo,
getchaintips, getbestblockhash, gettxoutsetinfo, the lottery
winners and the superblock payees, and which blocks each node then takes. Cases:
plain forks; a lottery and a treasury height in the dropped branch; a vault
funding dropped and a vault coinstake orphaned; a spork 13 whose value differs
between the sides; a spork 15 held by one side. Sporks are put in each node's
own spork database before it starts (nobody holds the regtest spork key), as in
scripts/spork-consensus. Each row prints PASS (irondivid as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import hashlib
import struct
import threading
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("REORG_STATE_INJECT", "")
# For looking into a difference: both replies of every row that differs
DUMP = os.environ.get("REORG_STATE_DUMP", "")
RPC_TIMEOUT = 120
START_TIMEOUT = 120
SYNC_TIMEOUT = 120
SPORK_SEED = os.path.join(os.path.dirname(IRONDIVID), "spork-seed")
SIGNED_AT = 1000
# A node that cannot bind its ports is started again on new ones, this often
BIND_RETRIES = 5

# Differences listed in README.md with divid's source line, one per row name:
# (reason, shape). shape takes the two raw outcomes and is true only for the
# difference described, so a KNOWN row that matches divid, or differs in another
# way, is a FAIL.
LAST_DIFF = set()


def only(*paths):
    """Both are results, and the fields that differ are some of `paths`"""
    return lambda c, i: c[0] == i[0] == "ok" and LAST_DIFF and LAST_DIFF <= set(paths)


KNOWN = {
}

fails = 0


def row(name, core, iron, same, raw=None):
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
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    if DUMP and not same and raw is not None:
        os.makedirs(DUMP, exist_ok=True)
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:90]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"row": name, "divid": raw[0], "irondivid": raw[1]}, f, indent=1, sort_keys=True)
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def free_port():
    """A port nothing listens on now (the system picks it)"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.2", 0))
        return sock.getsockname()[1]



# --- sporks put in a node's own database before it starts --------------------------------

def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def _crc32c_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc32c_table()


def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def leveldb_varint(n):
    out = b""
    while n >= 0x80:
        out += bytes([n & 0x7F | 0x80])
        n >>= 7
    return out + bytes([n])


def seed_core(net_dir, sporks):
    """divid's `sporks` LevelDB with `sporks` in it: a directory holding only a
    write-ahead log, which LevelDB makes a database of when it creates the rest
    (scripts/spork-consensus)"""
    path = os.path.join(net_dir, "sporks")
    os.makedirs(path)
    records = b""
    for spork_id, value in sporks:
        text = value.encode()
        key = struct.pack("<i", spork_id)
        spork = (struct.pack("<i", spork_id) + compact(len(text)) + text + struct.pack("<q", SIGNED_AT)
                 + compact(65) + b"\x1f" * 65)
        records += b"\x01" + leveldb_varint(len(key)) + key + leveldb_varint(len(spork)) + spork
    batch = struct.pack("<QI", 1, len(sporks)) + records
    crc = crc32c(b"\x01" + batch)
    crc = ((((crc >> 15) | (crc << 17)) & 0xFFFFFFFF) + 0xA282EAD8) & 0xFFFFFFFF
    with open(os.path.join(path, "000003.log"), "wb") as f:
        f.write(struct.pack("<IHB", crc, len(batch), 1) + batch)


class Node:
    def __init__(self, name, binary, index, extra):
        """extra: divi.conf lines; a callable is evaluated at each start, so a
        line naming another node's port follows that node to new ports"""
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"reorg{index}"
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.extra = list(extra)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0
        self.why = ""

    def seed(self, sporks):
        """Put `sporks` [(id, value)] in this node's spork database; before its first start"""
        if self.binary == DIVID:
            seed_core(os.path.join(self.dir, "regtest"), sporks)
        else:
            for spork_id, value in sporks:
                subprocess.run([SPORK_SEED, self.dir, str(spork_id), value, str(SIGNED_AT)], check=True)

    def write_conf(self):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
        ] + [line() if callable(line) else line for line in self.extra]
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".new", path)

    def launch(self, env):
        self.starts += 1
        self.write_conf()
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        full_env = dict(os.environ, **(env or {}))
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=full_env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def log_tail(self, n=15):
        """The last lines of the node's debug.log (divid keeps it in regtest/),
        or of its stderr when there is none"""
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log"), self.err):
            try:
                with open(path, errors="replace") as f:
                    lines = f.read().splitlines()
                if lines:
                    return lines[-n:]
            except OSError:
                pass
        return []

    def start(self, env=None):
        """True once RPC answers. A node that exits at once because a port is
        taken is started again on new ports; otherwise `why` says how it ended:
        its exit code and the last 15 lines of its debug.log"""
        retries = BIND_RETRIES
        self.launch(env)
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                tail = self.log_tail()
                text = "\n".join(tail)
                if retries and ("Address already in use" in text or "Unable to bind" in text):
                    retries -= 1
                    old = (self.p2p, self.rpcport)
                    self.p2p, self.rpcport = free_port(), free_port()
                    print(f"# {self.name}: ports {old[0]}/{old[1]} in use, starting again on "
                          f"{self.p2p}/{self.rpcport}", flush=True)
                    self.launch(env)
                    continue
                self.why = f"exited with code {code}; last lines of its log:\n" + "\n".join(
                    "#     " + line for line in tail)
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        self.why = f"no RPC answer within {START_TIMEOUT} s; last lines of its log:\n" + "\n".join(
            "#     " + line for line in self.log_tail())
        return False

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
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:150]}")
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


# --- how replies are compared ------------------------------------------------------

def kind(v):
    if v is None:
        return "null"
    return {bool: "bool", int: "int", float: "number", str: "string", list: "array", dict: "object"}[type(v)]


def flatten(v, vary, path=""):
    out = {}
    if isinstance(v, dict):
        out[path or "."] = "object"
        for k, x in v.items():
            out.update(flatten(x, vary, f"{path}.{k}"))
    elif isinstance(v, list):
        out[path or "."] = f"array[{len(v)}]"
        for i, x in enumerate(v):
            out.update(flatten(x, vary, f"{path}[{i}]"))
    else:
        leaf = path.rsplit(".", 1)[-1]
        out[path or "."] = f"<{kind(v)}>" if leaf in vary else (kind(v), v)
    return out


def differences(a, b):
    return [(k, a.get(k, "absent"), b.get(k, "absent")) for k in sorted(set(a) | set(b))
            if a.get(k, "absent") != b.get(k, "absent")]


def leaf(x):
    return x if isinstance(x, str) else f"{x[1]!r}"[:70]


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{str(out[2]).splitlines()[0][:90] if out[2] else ''}\""
    return json.dumps(out[1], sort_keys=True)[:140]


def compare(name, c, i, vary=()):
    """Same outcome; for an error the same code and message; for a result
    every field's name, JSON type and value, except the values in `vary`"""
    LAST_DIFF.clear()
    if name == INJECT:
        i = ("ok", {"injected": True, "reply": i[1]}) if i[0] == "ok" else ("err", (i[1] or 0) + 1, i[2])
    if c[0] == "err" and i[0] == "err":
        row(name, show(c), show(i), c[1] == i[1] and c[2] == i[2], (c, i))
    elif c[0] == "ok" and i[0] == "ok":
        d = differences(flatten(c[1], set(vary)), flatten(i[1], set(vary)))
        LAST_DIFF.update(k for k, _, _ in d)
        if not d:
            row(name, show(c), "same", True, (c, i))
        else:
            row(name, "; ".join(f"{k}={leaf(x)}" for k, x, _ in d[:5]),
                "; ".join(f"{k}={leaf(y)}" for k, _, y in d[:5]) + (f" (+{len(d) - 5} more)" if len(d) > 5 else ""),
                False, (c, i))
    else:
        row(name, show(c), show(i), False, (c, i))


# Fields irondivid adds to a reply on purpose (scripts/chain-replies): left out of the comparison
EXTRA = {
    "getblockchaininfo": {"fullhistorypeers", "lastblockfetch", "mediantime", "pruned", "pruneheight",
                          "snapshotbase", "warnings", "winnersstripheight"},
    "getblock": {"mediantime", "nTx"},
    "gettxoutsetinfo": {"bogosize"},
    "getcoinavailability": {"total_vaults", "vaults"},
    "getstakingstatus": {"staking status text"},
}


def pair(name, core_node, iron_node, method, *params, vary=(), fix=None):
    """The same call on a divid and an irondivid; `fix` normalises a result
    (e.g. sorts a list whose order is not part of the reply's meaning)"""
    c, i = core_node.call(method, *params), iron_node.call(method, *params)
    if i[0] == "ok" and isinstance(i[1], dict) and method in EXTRA:
        i = ("ok", {k: v for k, v in i[1].items() if k not in EXTRA[method]})
    if fix is not None:
        c = ("ok", fix(c[1])) if c[0] == "ok" else c
        i = ("ok", fix(i[1])) if i[0] == "ok" else i
    compare(name, c, i, vary)
    return c, i


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


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind_, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


# --- keeping the sporks off the wire ------------------------------------------------------
#
# A node holding a spork it was given in its own database offers it to the peers that
# ask, and a peer refuses it: the signature is not the network's. So every link goes
# through a relay that passes everything but the spork messages (scripts/spork-consensus).

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class SporkFilter(threading.Thread):
    """Relays `listen` to the node `target()` returns, message by message, without the spork messages"""

    def __init__(self, listen, target):
        super().__init__(daemon=True)
        self.target = target
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.2", listen))
        self.server.listen(8)
        self.start()

    def run(self):
        while True:
            try:
                client, _ = self.server.accept()
                upstream = socket.create_connection(("127.0.0.2", self.target()), timeout=10)
            except OSError:
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            for src, dst, drop, zero in ((client, upstream, ("getsporks", "spork"), False),
                                         (upstream, client, ("spork",), True)):
                threading.Thread(target=self.pump, args=(src, dst, drop, zero), daemon=True).start()

    @staticmethod
    def pump(src, dst, drop, zero):
        try:
            while True:
                head = b""
                while len(head) < 24:
                    part = src.recv(24 - len(head))
                    if not part:
                        raise EOFError
                    head += part
                size = struct.unpack("<I", head[16:20])[0]
                payload = b""
                while len(payload) < size:
                    part = src.recv(size - len(payload))
                    if not part:
                        raise EOFError
                    payload += part
                command = head[4:16].rstrip(b"\0").decode(errors="replace")
                if command in drop:
                    continue
                if zero and command == "sporkcount":
                    payload = bytes(4)
                    head = head[:16] + struct.pack("<I", 4) + sha256d(payload)[:4]
                dst.sendall(head + payload)
        except (OSError, EOFError):
            pass
        finally:
            for sock in (src, dst):
                try:
                    sock.close()
                except OSError:
                    pass


# --- the six nodes: side L (bridge C1; C3 and I1 behind it), side R (C2; C4, I2) -------
# The wallet nodes C3, C4, I1, I2 hold one wallet and run -vault=1.

C1 = Node("bridge-L", DIVID, 0, ["listen=1"])
I1 = Node("irondivid-L", IRONDIVID, 1, ["listen=0", "vault=1", lambda: f"connect=127.0.0.2:{PORT_BASE + 12}"])
C2 = Node("bridge-R", DIVID, 2, ["listen=1"])
I2 = Node("irondivid-R", IRONDIVID, 3, ["listen=0", "vault=1", lambda: f"connect=127.0.0.2:{PORT_BASE + 14}"])
C3 = Node("divid-L", DIVID, 4, ["listen=0", "vault=1", lambda: f"connect=127.0.0.2:{PORT_BASE + 13}"])
C4 = Node("divid-R", DIVID, 5, ["listen=0", "vault=1", lambda: f"connect=127.0.0.2:{PORT_BASE + 15}"])
# the relays: into bridge L (two), into bridge R (two), and across (R's bridge dials L's)
for _port, _target in ((12, lambda: C1.p2p), (13, lambda: C1.p2p), (14, lambda: C2.p2p), (15, lambda: C2.p2p),
                       (16, lambda: C1.p2p)):
    SporkFilter(PORT_BASE + _port, _target)
ALL = (C1, I1, C2, I2, C3, C4)
BRIDGES = (C1, C2)
# The divid and the irondivid behind each bridge
PAIRS = (("L", C3, I1), ("R", C4, I2))


def connected_within_sides():
    return (all(n.rpc("getconnectioncount") >= 1 for n in (I1, I2, C3, C4))
            and all(b.rpc("getconnectioncount") >= 2 for b in BRIDGES))


def join():
    """One link across the split: divid R dials divid L once"""
    C2.rpc("addnode", f"127.0.0.2:{PORT_BASE + 16}", "onetry")
    need(wait_for(lambda: C1.rpc("getconnectioncount") >= 3, 60), "the sides did not connect")


def split():
    """Restart all six: no node dials across, so the sides are apart"""
    for n in (I1, I2, C3, C4, C1, C2):
        n.stop()
    for n in (C1, C2, C3, C4, I1, I2):
        need(n.start(), f"{n.name} did not start again: {n.why}")
    need(wait_for(connected_within_sides, 60), "a side did not connect again")
    need(C1.rpc("getconnectioncount") == 2 and C2.rpc("getconnectioncount") == 2, "the sides are still joined")


def tip(n):
    return n.rpc("getbestblockhash")


def one_tip(secs=SYNC_TIMEOUT):
    return wait_for(lambda: len({tip(n) for n in ALL}) == 1, secs)


def mine(node, n):
    """n blocks from `node`, one at a time: divid looks for a stake time back from
    the clock, so a refused call waits until the clock passes the tip and tries again"""
    hashes = []
    for _ in range(n):
        for attempt in range(12):
            out = node.call("setgenerate", 1)
            if out[0] == "ok":
                hashes += out[1] if isinstance(out[1], list) else []
                break
            tip_time = node.rpc("getblock", node.rpc("getbestblockhash"))["time"]
            wait_for(lambda: time.time() > tip_time + 2, 30)
        else:
            st = node.call("getstakingstatus")
            raise RuntimeError(f"{node.name} could not make a block at height {node.rpc('getblockcount') + 1}: {out}; "
                               f"{json.dumps(st[1])[:300]}; balance {node.rpc('getbalance')}, "
                               f"{len(node.rpc('listunspent'))} coins")
    return hashes


def tips_sorted(v):
    return sorted(v, key=lambda t: (-t.get("height", 0), t.get("hash", ""))) if isinstance(v, list) else v


def chain_rows(label):
    """The tip on every node, and getchaintips of each side's two nodes"""
    hashes = {n.name: tip(n) for n in ALL}
    core = {hashes[n.name] for n in (C1, C2, C3, C4)}
    iron = {hashes[n.name] for n in (I1, I2)}
    row(f"{label}: one tip on all six nodes", f"{len(core)} tip(s)", f"{len(iron)} tip(s)",
        len(set(hashes.values())) == 1)
    for side, c, i in PAIRS:
        pair(f"{label}: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"{label}: getblockcount ({side})", c, i, "getblockcount")
        pair(f"{label}: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)


def mempool_rows(label):
    for side, c, i in PAIRS:
        pair(f"{label}: getrawmempool ({side})", c, i, "getrawmempool", fix=lambda v: sorted(v))


TX_VARY = {"time", "timereceived"}


def wallet_rows(label, txids, since):
    """The shared wallet on the divid and the irondivid behind bridge L"""
    for i in (I1,):
        for t, txid in txids:
            pair(f"{label}: gettransaction {t} (L)", C3, i, "gettransaction", txid, vary=TX_VARY)
        pair(f"{label}: getbalance (L)", C3, i, "getbalance")
        pair(f"{label}: listsinceblock <losing tip> (L)", C3, i, "listsinceblock", since,
             vary=TX_VARY, fix=lambda v: dict(v, transactions=sorted(
                 v.get("transactions", []), key=lambda x: (x.get("txid", ""), x.get("category", ""),
                                                           x.get("vout", 0)))) if isinstance(v, dict) else v)


def is_pos(node, block_hash):
    """A proof-of-stake block: its second transaction is a coinstake (first
    output empty)"""
    txs = node.rpc("getblock", block_hash).get("tx", [])
    if len(txs) < 2:
        return False
    raw = node.call("getrawtransaction", txs[1], 1)
    return raw[0] == "ok" and raw[1]["vout"][0].get("value") == 0


def spend(node, coin, dest, fee=0.001):
    amount = round(coin["amount"] - fee, 8)
    raw = node.rpc("createrawtransaction", [{"txid": coin["txid"], "vout": coin["vout"]}], {dest: amount})
    signed = node.rpc("signrawtransaction", raw)
    need(signed.get("complete"), f"{node.name} could not sign")
    return node.rpc("sendrawtransaction", signed["hex"])


# --- what is compared after a join ---------------------------------------------------------

BC_VARY = {"verificationprogress"}


def state_rows(label):
    """The pair behind each bridge: chain info, tips, best block, UTXO set totals
    and the block template"""
    for side, c, i in PAIRS:
        pair(f"{label}: getblockchaininfo ({side})", c, i, "getblockchaininfo", vary=BC_VARY)
        pair(f"{label}: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)
        pair(f"{label}: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"{label}: gettxoutsetinfo ({side})", c, i, "gettxoutsetinfo")


def winners_rows(label, first, last):
    """The lottery winners of heights first..last on the pair behind each bridge"""
    for side, c, i in PAIRS:
        for h in range(first, last + 1):
            if h > c.rpc("getblockcount"):
                break
            pair(f"{label}: getlotteryblockwinners {h} ({side})", c, i, "getlotteryblockwinners", h)


def block_rows(label, heights):
    """The blocks at `heights` of the pair behind each bridge: header, transactions,
    and the coinstake's outputs"""
    for side, c, i in PAIRS:
        for h in heights:
            if h > c.rpc("getblockcount"):
                break
            pair(f"{label}: getblock {h} ({side})", c, i, "getblock", c.rpc("getblockhash", h))


# --- the cases ----------------------------------------------------------------------------

def height():
    return C3.rpc("getblockcount")


def advance_to(h):
    """The joined network, one tip, grown to height h by irondivid R"""
    need(one_tip(), "the nodes do not share a tip")
    if height() < h:
        mine(I2, h - height())
        need(one_tip(), f"the nodes did not follow to height {h}")


FORK = [0]        # the height the last fork_case forked at


def fork_case(label, fork, depth_l, depth_r, miner_l=None, miner_r=None, in_l=None, in_r=None, converge=True):
    """Both sides at `fork`; side L adds depth_l blocks, side R depth_r; they meet.
    in_l / in_r run on their side before its blocks are made."""
    miner_l, miner_r = miner_l or C3, miner_r or I2
    advance_to(fork)
    FORK[0] = height()
    split()
    print(f"# {label}: fork at {fork}, side L {depth_l} blocks, side R {depth_r}", flush=True)
    if in_l:
        in_l()
    if depth_l:
        mine(miner_l, depth_l)
    need(wait_for(lambda: tip(C1) == tip(C3) == tip(I1), 90), f"{label}: side L did not agree")
    if in_r:
        in_r()
    if depth_r:
        mine(miner_r, depth_r)
    need(wait_for(lambda: tip(C2) == tip(C4) == tip(I2), 90), f"{label}: side R did not agree")
    lost = tip(C1)
    join()
    if converge:
        need(one_tip(180), f"{label}: the nodes did not agree after the join: " + ", ".join(
            f"{n.name} {n.rpc('getblockcount')} {tip(n)[:8]}" for n in ALL) + " tips " + "; ".join(
            f"{n.name} {[(t['height'], t['hash'][:8], t['status']) for t in n.rpc('getchaintips')[:3]]}" for n in (C3, I1)))
    else:
        time.sleep(25)
    time.sleep(2)
    return lost


# --- start: one network, one wallet, the sporks of each side --------------------------------

# Two runs of the network (REORG_STATE_UNIVERSE=1, 2; run.sh makes both): a node that holds a
# spork the other side lacks cannot follow the other side past the next block that spork
# changes, so each spork case ends in a split network and has a network of its own.
UNIVERSE = int(os.environ.get("REORG_STATE_UNIVERSE", "1"))
SPORK15 = (10014, "2000;200")
SPORK13_L = (10012, "50;30;10;5;5;300")
SPORK13_R = (10012, "45;30;10;10;5;300")
if UNIVERSE == 1:
    L_SPORKS, R_SPORKS = [SPORK15], []
else:
    L_SPORKS, R_SPORKS = [SPORK13_L], [SPORK13_R]
for n in (C1, I1, C3):
    n.seed(L_SPORKS)
for n in (C2, I2, C4):
    n.seed(R_SPORKS)
for n in (C1, C2, C3, C4):
    need(n.start(), f"{n.name} did not start: {n.why}")
phrase = C3.rpc("dumphdinfo")["mnemonic"]
need(I1.start({"WALLET_MNEMONIC": phrase}), f"irondivid L did not start: {I1.why}")
need(I2.start({"WALLET_MNEMONIC": phrase}), f"irondivid R did not start: {I2.why}")
del phrase
print(f"# divid {C1.rpc('getinfo').get('version')}, irondivid {I1.rpc('getnetworkinfo').get('version')}", flush=True)
need(wait_for(connected_within_sides, 60), "a side did not connect: " + ", ".join(f"{n.name} {n.rpc('getconnectioncount')}" for n in ALL))
join()
mine(C3, 25)
need(one_tip(), "the nodes did not follow divid L's first 25 blocks")
# The owner of the vaults below is divid L's bridge: coins for it from the shared wallet
L_ADDR = C1.rpc("getnewaddress")
for _ in range(3):
    C3.rpc("sendtoaddress", L_ADDR, 1000)
need(wait_for(lambda: len(C1.rpc("getrawmempool")) >= 3, 30), "the owner did not see the payments")
mine(C3, 1)
need(one_tip(), "the nodes did not follow the payments")
need(wait_for(lambda: I1.rpc("getbalance") == C3.rpc("getbalance") and I2.rpc("getbalance") > 0, 60),
     "the irondivid wallets did not find divid's coins")
for side, c, i in PAIRS:
    pair(f"spork show ({side})", c, i, "spork", "show")
pair("getblocktemplate (divid 3.0.0 has none)", C3, I1, "getblocktemplate")

if UNIVERSE == 1:
    # --- 1. proof of work: depth 1, 6 and 25 (past the 20 blocks of coin maturity) -----------------

    for depth in (1, 6, 25):
        fork_case(f"PoW depth {depth}", height(), depth, depth + 1)
        row(f"PoW depth {depth}: the longer side won", "", "", tip(C3) == tip(I2))
        state_rows(f"PoW depth {depth}")
    advance_to(110)

    # --- 2. proof of stake: depth 1 and 6 ---------------------------------------------------------

    for depth in (1, 6):
        fork_case(f"PoS depth {depth}", height(), depth, depth + 1)
        row(f"PoS depth {depth}: the longer side won", "", "", tip(C3) == tip(I2))
        state_rows(f"PoS depth {depth}")

    # --- 3. a lottery height and a treasury height inside the dropped branch --------------------------

    advance_to(143)
    lost = fork_case("lottery and treasury at 150", 144, 6, 7)
    row("lottery and treasury at 150: the longer side won", "", "", tip(C3) == tip(I2) and tip(C3) != lost)
    state_rows("lottery and treasury at 150")
    winners_rows("lottery and treasury at 150", 140, 152)
    block_rows("lottery and treasury at 150", [149, 150, 151])
    # the block each kind makes next, at the next lottery heights, taken by all
    advance_to(159)
    mine(C3, 1)
    row("block 160 (lottery) made by divid is taken by all six", "", "", one_tip(60))
    winners_rows("after block 160", 158, 171)
    block_rows("after block 160", [160])
    state_rows("after block 160")

    # --- 4. vault coinstake, a stake on a coin whose funding is dropped, a vault funding dropped ---------

    state = {}
    WALLET = (C3, I1, I2)        # the nodes that hold the shared wallet
    OWN = C1.rpc("getnewaddress")
    MGR = C3.rpc("getnewaddress")
    for n in (I1, I2):
        n.rpc("setaccount", MGR, "")
    VAULT = f"{OWN}:{MGR}"


    def txid_of(reply):
        return reply["txhash"] if isinstance(reply, dict) else reply


    def spread(txid, nodes):
        need(wait_for(lambda: all(txid in n.rpc("getrawmempool") for n in nodes), 30), "a payment did not spread")


    def lock_all_but(node, keep_txids):
        """Lock every coin of `node`'s wallet except those of `keep_txids`; returns what was locked"""
        locked = [{"txid": u["txid"], "vout": u["vout"]} for u in node.rpc("listunspent") if u["txid"] not in keep_txids]
        if locked:
            node.rpc("lockunspent", False, locked)
        return locked


    def unlock(node, locked):
        if locked:
            node.rpc("lockunspent", True, locked)


    advance_to(160)
    fund = txid_of(C1.rpc("fundvault", VAULT, 500))
    spread(fund, (C1, C3, I1, I2))
    mine(I2, 21)
    need(one_tip(), "the nodes did not follow the vault funding")
    for n in WALLET:
        r = n.call("addvault", VAULT, fund)
        print(f"#   addvault on {n.name}: {r[0]}", flush=True)
    pair("addvault on the wallet nodes: getcoinavailability (L)", C3, I1, "getcoinavailability")


    def wallet_views(label):
        """The shared wallet on divid L and irondivid L, which saw the same branch"""
        for what in ("getbalance", "getcoinavailability", "getstakingstatus"):
            pair(f"{label}: {what} (L)", C3, I1, what, vary={"staking status", "mnsync"})
        pair(f"{label}: listunspent (L)", C3, I1, "listunspent",
             fix=lambda v: sorted(({k: x for k, x in u.items() if k not in ("ischange", "solvable")} for u in v),
                                  key=lambda u: (u["txid"], u["vout"])))


    # 4a. a vault coinstake in the dropped branch: side L's manager stakes the vault coin alone
    def vault_stake():
        locked = lock_all_but(C3, set())
        out = C3.call("setgenerate", 1)
        unlock(C3, locked)
        print(f"#   divid L stakes the vault coin: {out[0]}", flush=True)
        state["vault_block"] = tip(C3)


    lost = fork_case("vault coinstake in the dropped branch", height(), 2, 4, in_l=vault_stake)
    row("vault coinstake in the dropped branch: the longer side won", "", "", tip(C3) == tip(I2) and tip(C3) != lost)
    held = state.get("vault_block")
    if held:
        blk = C3.rpc("getblock", held)
        stake = C3.rpc("getrawtransaction", blk["tx"][1], 1)
        in_vault = any(len(v["scriptPubKey"].get("addresses", [])) == 2 for v in stake["vout"])
        row("vault coinstake in the dropped branch: the dropped block paid a vault, and left the chain",
            "", "", in_vault and blk.get("confirmations", 0) <= 0)
    state_rows("vault coinstake in the dropped branch")
    wallet_views("vault coinstake in the dropped branch")

    # 4b. a stake on a coin whose own funding is in the dropped branch
    state = {}


    def stake_funded_coin():
        paid = C3.rpc("getnewaddress")
        I1.rpc("setaccount", paid, "")
        state["pay"] = txid_of(C1.rpc("sendtoaddress", paid, 1000))
        spread(state["pay"], (C1, C3, I1))
        mine(C3, 1)
        locked = lock_all_but(C3, {state["pay"]})
        out = C3.call("setgenerate", 1)
        unlock(C3, locked)
        print(f"#   divid L stakes the coin its own branch funded: {out[0]}", flush=True)


    lost = fork_case("stake on a coin funded in the dropped branch", height(), 1, 4, in_l=stake_funded_coin)
    row("stake on a coin funded in the dropped branch: the longer side won", "", "", tip(C3) == tip(I2) and tip(C3) != lost)
    state_rows("stake on a coin funded in the dropped branch")
    wallet_views("stake on a coin funded in the dropped branch")

    # 4c. a vault funding in the dropped branch, and the vault staked there
    def fund_and_stake_vault():
        state["vfund"] = txid_of(C1.rpc("fundvault", VAULT, 300))
        spread(state["vfund"], (C1, C3, I1))
        mine(C3, 1)
        for n in (C3, I1):
            r = n.call("addvault", VAULT, state["vfund"])
            print(f"#   addvault of the dropped funding on {n.name}: {r[0]}", flush=True)
        locked = lock_all_but(C3, set())
        out = C3.call("setgenerate", 1)
        unlock(C3, locked)
        print(f"#   divid L stakes the vault: {out[0]}", flush=True)


    lost = fork_case("vault funding in the dropped branch", height(), 1, 4, in_l=fund_and_stake_vault)
    row("vault funding in the dropped branch: the longer side won", "", "", tip(C3) == tip(I2) and tip(C3) != lost)
    state_rows("vault funding in the dropped branch")
    wallet_views("vault funding in the dropped branch")



# --- 5. universe 1, sporks: a spork 15 held by side L only (block value from 200) -----------------------

if UNIVERSE == 1:
    lost = fork_case("spork 15 on side L only, across 200", 194, 12, 13)
    row("spork 15 on side L only: the branches cross 200", "", "", FORK[0] + 12 > 200 > FORK[0])
    row("spork 15 on side L only: the longer side (R) won", "", "", tip(C3) == tip(I2) and tip(C3) != lost)
    state_rows("spork 15 on side L only")
    winners_rows("spork 15 on side L only", 199, 202)
    block_rows("spork 15 on side L only", [200, 201, 205])
    for side, c, i in PAIRS:
        pair(f"spork 15 on side L only: spork active ({side})", c, i, "spork", "active")
    # side R goes on; side L, holding spork 15, stops where the rules it holds refuse side R's block
    mine(I2, 50)
    time.sleep(30)
    print(f"# after side R grew: side L at {C3.rpc('getblockcount')}, side R at {C4.rpc('getblockcount')}", flush=True)
    for side, c, i in PAIRS:
        pair(f"spork 15 on side L only, side R grown: getblockcount ({side})", c, i, "getblockcount")
        pair(f"spork 15 on side L only, side R grown: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"spork 15 on side L only, side R grown: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)
        pair(f"spork 15 on side L only, side R grown: getblockchaininfo ({side})", c, i, "getblockchaininfo", vary=BC_VARY)
        pair(f"spork 15 on side L only, side R grown: gettxoutsetinfo ({side})", c, i, "gettxoutsetinfo")
    winners_rows("spork 15 on side L only, side R grown", 207, 212)

# --- 6. universe 2: a spork 13 whose value differs between the sides (from 300); side L is longer --------

else:
    advance_to(294)
    lost = fork_case("spork 13 differing, side L longer, across 300", 294, 8, 7, converge=False)
    print(f"# side L at {C3.rpc('getblockcount')} {tip(C3)[:12]}, side R at {C4.rpc('getblockcount')} {tip(C4)[:12]}", flush=True)
    for side, c, i in PAIRS:
        pair(f"spork 13 differing: getblockcount ({side})", c, i, "getblockcount")
        pair(f"spork 13 differing: getbestblockhash ({side})", c, i, "getbestblockhash")
        pair(f"spork 13 differing: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)
        pair(f"spork 13 differing: getblockchaininfo ({side})", c, i, "getblockchaininfo", vary=BC_VARY)
        pair(f"spork 13 differing: gettxoutsetinfo ({side})", c, i, "gettxoutsetinfo")
    winners_rows("spork 13 differing", 298, 304)
    block_rows("spork 13 differing", [299, 300, 301])
    # and side R, longer, on its own
    mine(I2, 4)
    time.sleep(10)
    for side, c, i in PAIRS:
        pair(f"spork 13 differing, side R grown: getchaintips ({side})", c, i, "getchaintips", fix=tips_sorted)
        pair(f"spork 13 differing, side R grown: getbestblockhash ({side})", c, i, "getbestblockhash")


for n in ALL:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
