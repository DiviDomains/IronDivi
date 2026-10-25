#!/usr/bin/env python3
"""Peer bans, mock time and the raw calls left over, Divi Core divid and
irondivid compared case by case: ban, listbanned and clearbanned with raw
peers, an automatic ban at -banscore and -bantime, bans across a restart,
setmocktime and the times it moves, getinvalid, and
signtransactionwithaddresskey.

Both nodes run on regtest, not connected to each other; raw peers made here
connect to each from their own loopback addresses (127.0.0.11 and up), one
address per case. Both wallets come from the same phrase. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment; it is never
printed or put on a command line.
"""

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
def banlist_ips(c, i):
    """The addresses divid's text list and irondivid's array name, or None"""
    if c[0] != "ok" or i[0] != "ok" or not isinstance(c[1], dict) or not isinstance(i[1], list):
        return None
    text = c[1].get("banned:")
    if not isinstance(text, str) or not (text.startswith("[\n") and text.endswith("]")):
        return None
    core = sorted(line.rstrip(",") for line in text[2:-1].split("\n") if line)
    return core, sorted(b.get("address") for b in i[1])


BANLIST = ("divid answers {\"banned:\": \"<text list>\"} (rpcmisc.cpp:1023-1030, PeerBanningService.cpp:23-34), "
           "with no ban times; irondivid an array of {address, ban_created, banned_until, ban_reason}, the same "
           "addresses (docs/rpc-parity-audit.md: listbanned; also KNOWN in scripts/net-replies) [by design]",
           lambda c, i: (lambda ips: ips is not None and ips[0] == ips[1])(banlist_ips(c, i)))
BAN_IP = ("divid compares the address given with each peer's ip:port text, so it never finds a connected peer "
          "(net.cpp:395-407) and nothing is banned; irondivid bans that peer (also KNOWN in scripts/net-replies) "
          "[by design]")
STOI = ("divid reads each peer's sub-version as four numbers with std::stoi, which throws on this one "
        "(net.cpp:359-376), so the call fails as -1 \"stoi\"; irondivid leaves that peer alone and bans the "
        "outdated ones")
KNOWN = {
    "ban of the peer's address 127.0.0.11": (BAN_IP, pair(("ok", {"Banned": "Could not find matching node to ban"}),
                                                          ("ok", {"Banned": "127.0.0.11"}))),
    "the peer 127.0.0.11 after its ban": (BAN_IP, pair(("ok", "up"), ("ok", "closed"))),
    "getconnectioncount (after ban 127.0.0.11)": (BAN_IP, pair(("ok", 1), ("ok", 0))),
    "getpeerinfo addresses (after ban 127.0.0.11)": (BAN_IP, pair(("ok", ["127.0.0.11"]), ("ok", []))),
    "listbanned (after ban 127.0.0.11)": (BAN_IP + "; the list's form as listbanned below",
                                          lambda c, i: banlist_ips(c, i) == ([], ["127.0.0.11"])),
    "raw peer from 127.0.0.11 again": (BAN_IP, pair(("ok", "up"), ("ok", "refused"))),
    "ban outdated with a '/IronDivi:0.2.6/' peer": (STOI, pair(("err", -1, "stoi"), ("ok", {"Banned": []}))),
    "ban outdated with a '/bans:1.2.3.4/' peer": (STOI, pair(("err", -1, "stoi"), ("ok", {"Banned": []}))),
    "getinvalid key order": (
        "irondivid writes every JSON object's keys in name order (serde_json without preserve_order, "
        "Cargo.toml:67); divid in the order rpcblockchain.cpp:716-719 adds them. JSON objects are unordered "
        "(RFC 8259 section 4)",
        pair(("ok", ["addresses_with_invalid", "total_unspent", "total_minted", "total_valid_used"]),
             ("ok", ["addresses_with_invalid", "total_minted", "total_unspent", "total_valid_used"]))),
}

fails = 0
counts = {"PASS": 0, "KNOWN": 0, "FAIL": 0}


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN, but now the same as divid]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS" if same else "FAIL"), ""
    counts[word] += 1
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:600], flush=True)


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{out[2][:120]}\""
    return json.dumps(out[1])[:160]


def compare(name, core, iron):
    """Same outcome: for an error the same code and text, for a result the same value"""
    row(name, show(core), show(iron), core == iron, (core, iron))


def both(name, method, *params):
    core, iron = C.call(method, *params), I.call(method, *params)
    compare(name, core, iron)
    return core, iron


def facts(name, fn):
    """A row of what each node shows, from fn(node)"""
    c, i = ("ok", fn(C)), ("ok", fn(I))
    compare(name, c, i)
    return c[1], i[1]


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"bans{index}:{password}".encode()).decode()
        self.base = [
            f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=bans{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1",
        ]
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0

    def write_conf(self, extra=()):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base + list(extra)) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))

    def start(self, extra=("regtest=1",)):
        """('up',) once RPC answers, or ('exit', code, the first stderr line naming an error)"""
        self.write_conf(extra)
        self.starts += 1
        base = os.path.join(WORK, f"{self.name}.{self.starts}")
        self.err = base + ".err"
        env = dict(os.environ, **self.env) if self.env else None
        with open(base + ".out", "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
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
        req = urllib.request.Request(f"http://{NODE_IP}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

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


def restart(extra=("regtest=1",)):
    for n in (C, I):
        n.stop()
    out = C.start(extra), I.start(extra)
    for n, o in zip((C, I), out):
        if o[0] != "up":
            print(f"FAIL   setup: {n.name} did not start with {list(extra)}: {o}", flush=True)
            sys.exit(1)


# --- a raw p2p peer ----------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])


def message(command, payload=b""):
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + check + payload


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


class Peer:
    """A raw peer from its own loopback address. `state` is 'up' after the
    handshake, 'refused' when the connection is refused or closed before it,
    or 'closed' once the node drops it."""

    def __init__(self, node, src, subver="Divi Core: 3.0.0.0", version=70920):
        self.node, self.src, self.version = node, src, version
        self.subver = subver.encode()
        self.sock = None
        self.state = self.connect()

    def version_payload(self):
        return (struct.pack("<iQq", self.version, 1, int(time.time())) + netaddr(NODE_IP, self.node.p2p)
                + netaddr(self.src, 0) + secrets.token_bytes(8) + compact(len(self.subver)) + self.subver
                + struct.pack("<i", 0) + b"\x01")

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.bind((self.src, 0))
            self.sock.connect((NODE_IP, self.node.p2p))
            self.port = self.sock.getsockname()[1]
            self.sock.sendall(message("version", self.version_payload()))
            got_version = got_verack = False
            deadline = time.time() + 10
            while not (got_version and got_verack) and time.time() < deadline:
                command, payload = self.read()
                if command == "version":
                    got_version = True
                    n = payload[80]  # the subver, after version, services, time, two addresses, nonce
                    self.node_subver = payload[81:81 + n].decode(errors="replace")
                    self.sock.sendall(message("verack"))
                elif command == "verack":
                    got_verack = True
            return "up" if got_version and got_verack else "refused"
        except (OSError, EOFError):
            return "refused"

    def read(self):
        head = self.recv(24)
        command = head[4:16].rstrip(b"\0").decode()
        size = struct.unpack("<I", head[16:20])[0]
        return command, self.recv(size)

    def recv(self, n):
        out = b""
        while len(out) < n:
            part = self.sock.recv(n - len(out))
            if not part:
                raise EOFError
            out += part
        return out

    def send(self, command, payload=b""):
        try:
            self.sock.sendall(message(command, payload))
        except OSError:
            self.state = "closed"

    def pump(self, secs=1.0):
        """Read for `secs`, answering pings; 'closed' if the node drops the connection"""
        if self.state != "up":
            return self.state
        deadline = time.time() + secs
        while time.time() < deadline:
            self.sock.settimeout(max(0.05, deadline - time.time()))
            try:
                command, payload = self.read()
            except socket.timeout:
                break
            except (OSError, EOFError):
                self.state = "closed"
                break
            if command == "ping":
                self.send("pong", payload)
        return self.state

    def close(self):
        if self.sock:
            self.sock.close()
        self.state = "closed"


def peer_ips(node):
    return sorted(p["addr"].rsplit(":", 1)[0] for p in node.rpc("getpeerinfo"))


def peers_rows(what):
    """getconnectioncount and the peers' addresses, after `what`"""
    both(f"getconnectioncount ({what})", "getconnectioncount")
    facts(f"getpeerinfo addresses ({what})", peer_ips)


def peer_pair(src, **kw):
    """One raw peer to each node from `src`; a row of whether each got in"""
    return Peer(C, src, **kw), Peer(I, src, **kw)


def connect_row(name, src, **kw):
    pc, pi = peer_pair(src, **kw)
    compare(name, ("ok", pc.state), ("ok", pi.state))
    return pc, pi


def dropped_row(name, pc, pi, secs=3.0):
    compare(name, ("ok", pc.pump(secs)), ("ok", pi.pump(secs)))


def listbanned_row(what, name=None):
    name = name or f"listbanned ({what})"
    if name not in KNOWN:
        KNOWN[name] = BANLIST
    both(name, "listbanned")


# --- transactions, serialized here ------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SAT = 100_000_000


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text):
    n = 0
    for ch in text:
        n = n * 58 + B58.index(ch)
    return n.to_bytes(25, "big")


def p2pkh(address):
    return bytes.fromhex("76a914") + b58decode(address)[1:21] + bytes.fromhex("88ac")


def push(b):
    return bytes([len(b)]) + b


def serialize(vin, vout, locktime=0, version=1):
    """vin: (txid, n, scriptSig bytes); vout: (satoshis, script bytes)"""
    b = struct.pack("<i", version) + compact(len(vin))
    for txid, n, script in vin:
        b += bytes.fromhex(txid)[::-1] + struct.pack("<I", n) + compact(len(script)) + script + b"\xff" * 4
    b += compact(len(vout))
    for value, script in vout:
        b += struct.pack("<q", value) + compact(len(script)) + script
    return (b + struct.pack("<I", locktime)).hex()


# --- start -----------------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
for n in (C,):
    if n.start()[0] != "up":
        print(f"FAIL   setup: {n.name} did not start", flush=True)
        sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I.env = {"WALLET_MNEMONIC": phrase}
del phrase
if I.start(["regtest=1", f"connect={NODE_IP}:{C.p2p}"])[0] != "up":
    print("FAIL   setup: irondivid did not start", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)

# --- signtransactionwithaddresskey (rpcrawtransaction.cpp:566-599) --------------------------
# One chain: divid mines and pays a coin to an address of its wallet, which
# irondivid's wallet (the same phrase) holds too. Not called here, as each would
# read past the arguments or the inputs in divid: fewer than 3 arguments (divid
# exits; docs/rpc-parity-audit.md), an empty transaction, an input index past the
# inputs or negative.
C.rpc("setgenerate", 25)
A = C.rpc("getnewaddress")
I.rpc("setaccount", A, "")
coin_txid = C.rpc("sendtoaddress", A, 10)
C.rpc("setgenerate", 1)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 120):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
coin_tx = C.rpc("getrawtransaction", coin_txid, 1)
coin_n = next(o["n"] for o in coin_tx["vout"] if A in o["scriptPubKey"].get("addresses", []))
pubkey = bytes.fromhex(C.rpc("validateaddress", A)["pubkey"])
STRANGER = b58check(b58decode(A)[:1] + secrets.token_bytes(20))
spend_a = serialize([(coin_txid, coin_n, b"")], [(9 * SAT, p2pkh(STRANGER))])
other = serialize([(secrets.token_hex(32), 0, b"")], [(SAT, p2pkh(STRANGER))])
two_in = serialize([(secrets.token_hex(32), 0, b""), (secrets.token_hex(32), 1, b"")], [(SAT, p2pkh(STRANGER))])
signed_a = both("signtransactionwithaddresskey of a spend of the address's coin", "signtransactionwithaddresskey",
                spend_a, A, 0)
both("signtransactionwithaddresskey of a transaction not spending the address", "signtransactionwithaddresskey",
     other, A, 0)
both("signtransactionwithaddresskey of input 1 with one output (SIGHASH_SINGLE)", "signtransactionwithaddresskey",
     two_in, A, 1)
both("signtransactionwithaddresskey with a fourth argument", "signtransactionwithaddresskey", other, A, 0, "x")
both("signtransactionwithaddresskey with an address not in the wallet", "signtransactionwithaddresskey",
     other, STRANGER, 0)
both("signtransactionwithaddresskey with a malformed address", "signtransactionwithaddresskey",
     other, "notanaddress", 0)
both("signtransactionwithaddresskey with a number for the address", "signtransactionwithaddresskey", other, 5, 0)
both("signtransactionwithaddresskey with hex 'zz'", "signtransactionwithaddresskey", "zz", A, 0)
both("signtransactionwithaddresskey with odd hex 'abc'", "signtransactionwithaddresskey", "abc", A, 0)
both("signtransactionwithaddresskey with hex not a transaction", "signtransactionwithaddresskey", "00", A, 0)
both("signtransactionwithaddresskey with a text input index", "signtransactionwithaddresskey", other, A, "0")
both("signtransactionwithaddresskey with a number for the hex", "signtransactionwithaddresskey", 5, A, 0)
# The signature is over a <pubkey> OP_CHECKSIG script with SIGHASH_SINGLE, so it
# does not spend the P2PKH coin
c, i = signed_a
if c[0] == i[0] == "ok":
    for k, (node, out) in enumerate(((C, c), (I, i))):
        sig = bytes.fromhex(out[1].split()[0]) if out[1] else b""
        tx = serialize([(coin_txid, coin_n, push(sig) + push(pubkey))], [(9 * SAT, p2pkh(STRANGER))])
        if k == 0:
            core = node.call("sendrawtransaction", tx)
        else:
            iron = node.call("sendrawtransaction", tx)
    compare("sendrawtransaction with that signature and the pubkey", core, iron)

# both alone from here: no peer but the raw ones made here
I.stop()
if I.start()[0] != "up":
    print("FAIL   setup: irondivid did not start alone", flush=True)
    sys.exit(1)
if not wait_for(lambda: C.rpc("getconnectioncount") == 0, 30):
    print("FAIL   setup: divid still has a peer", flush=True)
    sys.exit(1)

# --- ban: the arguments ------------------------------------------------------------------
listbanned_row("at start")
both("ban with no argument", "ban")
both("ban with two arguments", "ban", "192.0.2.1", "192.0.2.2")
both("ban with a number", "ban", 5)

# --- ban: one peer connected ---------------------------------------------------------------
p1 = connect_row("raw peer from 127.0.0.11 connects", "127.0.0.11")
print(f"# subver: divid {p1[0].node_subver!r}, irondivid {p1[1].node_subver!r}", flush=True)
peers_rows("one raw peer")
both("ban of the peer's address 127.0.0.11", "ban", "127.0.0.11")
dropped_row("the peer 127.0.0.11 after its ban", *p1)
peers_rows("after ban 127.0.0.11")
listbanned_row("after ban 127.0.0.11")
connect_row("raw peer from 127.0.0.11 again", "127.0.0.11")
# irondivid's ban of 127.0.0.11 is lifted so the two lists agree again
I.rpc("clearbanned")
both("ban of 127.0.0.11 with its port", "ban", f"127.0.0.11:{p1[0].port}")
both("ban of an address with no peer, 192.0.2.30", "ban", "192.0.2.30")
both("ban of a malformed address", "ban", "not-an-address")
both("ban of 999.1.1.1", "ban", "999.1.1.1")
both("ban of an IPv6 address, ::1", "ban", "::1")
both("ban of [::1]", "ban", "[::1]")
both("ban of an empty string", "ban", "")
listbanned_row("after the bans of no peer")

# --- ban outdated --------------------------------------------------------------------------
both("ban outdated with no peer outdated", "ban", "outdated")
fresh = connect_row("raw peer 'Divi Core: 3.0.0.0' from 127.0.0.12 connects", "127.0.0.12")
both("ban outdated with a 3.0.0.0 peer", "ban", "outdated")
dropped_row("the 3.0.0.0 peer after ban outdated", *fresh)
old = connect_row("raw peer 'Divi Core: 2.4.0.0' from 127.0.0.13 connects", "127.0.0.13",
                  subver="Divi Core: 2.4.0.0")
facts("getpeerinfo subver of the 2.4.0.0 peer",
      lambda n: [p.get("subver") for p in n.rpc("getpeerinfo") if p["addr"].startswith("127.0.0.13:")])
c, i = C.call("ban", "outdated"), I.call("ban", "outdated")
# divid lists the peer as ip:port (CAddress::ToString, net.cpp:385)
norm = lambda out, peer: (out[0], {"Banned": [a.replace(f":{peer.port}", ":<port>") for a in out[1]["Banned"]]}) \
    if out[0] == "ok" and isinstance(out[1], dict) and isinstance(out[1].get("Banned"), list) else out
compare("ban outdated with a 2.4.0.0 peer", norm(c, old[0]), norm(i, old[1]))
dropped_row("the 2.4.0.0 peer after ban outdated", *old)
listbanned_row("after ban outdated")
connect_row("raw peer from 127.0.0.13 again, after ban outdated", "127.0.0.13", subver="Divi Core: 2.4.0.0")
connect_row("raw peer 'Divi Core: 3.0.0.0' from 127.0.0.13", "127.0.0.13")
both("clearbanned", "clearbanned")
listbanned_row("after clearbanned")
# divid reads each peer's subver after ": " (from its second character when there
# is none), as four numbers split at the dots (net.cpp:359-376); std::stoi throws
# on a part that does not start with a number
for k, sv in enumerate(("/IronDivi:0.2.6/", "/bans:1.2.3.4/", "x2.0.0.0")):
    src = f"127.0.0.{14 + k}"
    odd = connect_row(f"raw peer {sv!r} from {src} connects", src, subver=sv)
    c, i = C.call("ban", "outdated"), I.call("ban", "outdated")
    compare(f"ban outdated with a {sv!r} peer", norm(c, odd[0]), norm(i, odd[1]))
    dropped_row(f"the {sv!r} peer after ban outdated", *odd, secs=1.0)
    for p in odd:
        p.close()
listbanned_row("after the odd subvers")
both("clearbanned after the odd subvers", "clearbanned")
connect_row("raw peer from 127.0.0.13 after clearbanned", "127.0.0.13")
listbanned_row("", name="listbanned with one argument")
both("listbanned with two arguments", "listbanned", "x", "y")
both("clearbanned with one argument", "clearbanned", "x")
both("clearbanned with two arguments", "clearbanned", "x", "y")

# --- misbehaviour: an addr message of 1001 addresses costs 20 (main.cpp:528-531), a
# second version message 1 (main.cpp:358-362) -------------------------------------------
BIG_ADDR = compact(1001) + b"".join(struct.pack("<I", int(time.time())) + netaddr(f"10.1.{k // 250}.{k % 250 + 1}", 8333)
                                    for k in range(1001))


def banscore(node, peer):
    return [p.get("banscore") for p in node.rpc("getpeerinfo") if p["addr"] == f"{peer.src}:{peer.port}"]


def misbehave(what, src, count, setting, command="addr"):
    """`count` bad messages from a raw peer at `src`; rows of the peer's state
    and banscore, the ban list, and whether the address gets in again"""
    pc, pi = connect_row(f"raw peer from {src} connects ({setting})", src)
    for _ in range(count):
        for p in (pc, pi):
            if command == "addr":
                p.send("addr", BIG_ADDR)
            else:
                p.send("version", p.version_payload())
    dropped_row(f"the peer after {what} ({setting})", pc, pi)
    c = banscore(C, pc) if pc.state == "up" else "gone"
    i = banscore(I, pi) if pi.state == "up" else "gone"
    compare(f"getpeerinfo banscore after {what} ({setting})", ("ok", c), ("ok", i))
    listbanned_row(f"after {what} ({setting})")
    again = connect_row(f"raw peer from {src} again after {what} ({setting})", src)
    for p in (pc, pi) + again:
        p.close()
    return again


misbehave("4 addr messages of 1001", "127.0.0.20", 4, "default -banscore")
misbehave("5 addr messages of 1001", "127.0.0.21", 5, "default -banscore")
for setting, extra in (("-banscore=1", ["banscore=1"]), ("-banscore=1000", ["banscore=1000"]),
                       ("-bantime=1", ["bantime=1"]), ("-bantime=60", ["bantime=60"])):
    restart(["regtest=1"] + extra)
    if setting == "-banscore=1":
        misbehave("a second version message", "127.0.0.22", 1, setting, command="version")
    else:
        misbehave("5 addr messages of 1001", f"127.0.0.{23 + len(setting)}", 5, setting)
# the ban's end, moved past with setmocktime
now = int(time.time())
both("setmocktime 120 s ahead (-bantime=60)", "setmocktime", now + 120)
connect_row("raw peer from 127.0.0.33 after setmocktime 120 s ahead (-bantime=60)", "127.0.0.33")
both("setmocktime 0 (-bantime=60)", "setmocktime", 0)

# --- bans across a restart: divid keeps them in memory only (PeerBanningService.cpp:7) -----
restart()
old = connect_row("raw peer 'Divi Core: 2.4.0.0' from 127.0.0.40 connects", "127.0.0.40",
                  subver="Divi Core: 2.4.0.0")
c, i = C.call("ban", "outdated"), I.call("ban", "outdated")
compare("ban outdated before a restart", norm(c, old[0]), norm(i, old[1]))
listbanned_row("before a restart")
restart()
listbanned_row("after a restart")
facts("a ban list file in the datadir after a restart",
      lambda n: sorted(f for f in os.listdir(os.path.join(n.dir, "regtest") if os.path.isdir(os.path.join(n.dir, "regtest"))
                                                else n.dir) if "ban" in f.lower()))
connect_row("raw peer from 127.0.0.40 after a restart", "127.0.0.40")

# --- getinvalid (rpcblockchain.cpp:687-725): one summary, always zero ------------------
c, i = both("getinvalid", "getinvalid")
compare("getinvalid key order", ("ok", list(c[1][0])) if c[0] == "ok" else c,
        ("ok", list(i[1][0])) if i[0] == "ok" else i)
both("getinvalid all", "getinvalid", "all")
both("getinvalid with a number", "getinvalid", 5)
both("getinvalid with two arguments", "getinvalid", "all", "x")
tip = C.rpc("getbestblockhash")
if I.rpc("getbestblockhash") == tip:
    both("invalidateblock of the tip", "invalidateblock", tip)
    both("getinvalid after invalidateblock", "getinvalid")
    both("getinvalid all after invalidateblock", "getinvalid", "all")
    both("getblockcount after invalidateblock", "getblockcount")
    both("reconsiderblock of it", "reconsiderblock", tip)
    both("getinvalid after reconsiderblock", "getinvalid")
    both("getblockcount after reconsiderblock", "getblockcount")
else:
    row("invalidateblock of the tip", "-", "-", False)

# --- setmocktime (rpcmisc.cpp:526-541) ----------------------------------------------------
both("setmocktime with no argument", "setmocktime")
both("setmocktime with two arguments", "setmocktime", 1, 2)
both("setmocktime with text", "setmocktime", "abc")
both("setmocktime with 1.5", "setmocktime", 1.5)
both("setmocktime -5", "setmocktime", -5)
both("setmocktime 0", "setmocktime", 0)


def times_at(mock, src):
    """What each node shows with the clock set to `mock`: a new raw peer's
    conntime, lastsend and lastrecv, and the time of a block mined then, each
    less `mock`; timeoffset from getinfo"""
    def probe(node):
        peer = Peer(node, src)
        peer.pump(1.0)
        info = next((p for p in node.rpc("getpeerinfo") if p["addr"] == f"{src}:{peer.port}"), {})
        node.rpc("setgenerate", 1)
        block = node.rpc("getblock", node.rpc("getbestblockhash"))
        peer.close()
        return {"conntime": info.get("conntime", 0) - mock, "lastsend": info.get("lastsend", 0) - mock,
                "lastrecv": info.get("lastrecv", 0) - mock, "block time": block["time"] - mock,
                "getinfo timeoffset": node.rpc("getinfo").get("timeoffset")}
    return probe


now = int(time.time())
for label, mock, src in (("a day ahead", now + 86400, "127.0.0.50"), ("a minute ahead", now + 60, "127.0.0.51")):
    both(f"setmocktime {label}", "setmocktime", mock)
    facts(f"times with the clock {label}", times_at(mock, src))
both("setmocktime 0 again", "setmocktime", 0)
facts("times with the clock back (block time later than the mocked one)",
      lambda n: n.rpc("getblock", n.rpc("getbestblockhash"))["time"] <= int(time.time()) + 86400)

# setmocktime outside regtest: the same refusal (rpcmisc.cpp:536-537)
TC, TI = Node("divid-testnet", DIVID, 2), Node("irondivid-testnet", IRONDIVID, 3)
if TC.start(("testnet=1",))[0] == "up" and TI.start(("testnet=1",))[0] == "up":
    compare("setmocktime on testnet", TC.call("setmocktime", 5), TI.call("setmocktime", 5))
else:
    row("setmocktime on testnet", "-", "-", False)
for n in (TC, TI):
    n.stop()

# --- signtransactionwithaddresskey with the wallet locked ---------------------------------
# divid stops after encryptwallet; irondivid keeps running, locked (docs/rpc-parity-audit.md)
passphrase = secrets.token_hex(16)
for n in (C, I):
    n.call("encryptwallet", passphrase)
del passphrase
wait_for(lambda: not C.alive(), 60)
C.proc = None
if C.start()[0] != "up":
    print("FAIL   setup: divid did not start after encryptwallet", flush=True)
    sys.exit(1)
both("signtransactionwithaddresskey with the wallet locked", "signtransactionwithaddresskey", spend_a, A, 0)
both("signtransactionwithaddresskey with the wallet locked, an address not in it", "signtransactionwithaddresskey",
     spend_a, STRANGER, 0)

for n in (C, I):
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
