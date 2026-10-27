#!/usr/bin/env python3
"""Masternode broadcasts (mnb), pings (mnp) and payment votes (mnw) on the
wire, Divi Core divid and irondivid compared message by message.

Both nodes run on regtest, not connected to each other. Each mines its own
chain and pays copper collaterals to a collateral key this script makes; the
script then builds good and bad messages for its throwaway masternodes, signs
them itself and sends the same ones (bar the collateral txids) to both nodes
from raw peers. For each message it compares what the node took
(listmasternodes, getmasternodewinners), what it relayed to a second raw peer
and sent back to the sender, the sender's banscore and whether it was dropped.
Each row prints PASS (same as divid), KNOWN (a difference listed in README.md)
or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The
collateral and masternode keys are made here at random, live only in this
process's memory, and are never printed, written or put on a command line.
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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), os.path.abspath(sys.argv[4])
RPC_TIMEOUT = 60
START_TIMEOUT = 120
NODE_IP = "127.0.0.2"
PROTOCOL = 70920
# A ranked voter must be 25 minutes old on regtest (masternode-payments.cpp:557-558)
VOTER_AGE = 25 * 60 + 60
INJECT = os.environ.get("MN_MESSAGES_INJECT", "")


# --- rows ------------------------------------------------------------------------------

def pair(core, iron):
    """A KNOWN shape: divid gives exactly `core` and irondivid exactly `iron`"""
    return lambda c, i: c == core and i == iron


# Rows where irondivid differs on purpose: (reason, shape); shape is true only
# for the difference described, so a KNOWN row that matches divid, or differs in
# another way, is a FAIL
KNOWN = {}

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
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:700], flush=True)


def compare(name, core, iron):
    if INJECT == name:
        iron = ["injected"]
    row(name, json.dumps(core), json.dumps(iron), core == iron, (core, iron))


def setup_failed(kind, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    import traceback
    where = traceback.extract_tb(tb)[-1].lineno if tb else "?"
    print(f"FAIL   setup (line {where}): {value}"[:400], flush=True)
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


# --- hashes, keys and signatures ---------------------------------------------------------

def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# RIPEMD-160: hashlib's comes from OpenSSL, which may not have it (as scripts/superblocks)
_R1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
       3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
       4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
_R2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
       15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
       12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
_S1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
       11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
       9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
_S2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
       9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
       8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
_K1 = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]
M32 = 0xffffffff


def _f(j, x, y, z):
    return [x ^ y ^ z, (x & y) | (~x & z), (x | ~y) ^ z, (x & z) | (y & ~z), x ^ (y | ~z)][j] & M32


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def ripemd160(msg):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + (8 * len(msg)).to_bytes(8, "little")
    for o in range(0, len(msg), 64):
        x = [int.from_bytes(msg[o + 4 * i:o + 4 * i + 4], "little") for i in range(16)]
        a1, b1, c1, d1, e1 = h
        a2, b2, c2, d2, e2 = h
        for j in range(80):
            r = j // 16
            t = (_rol((a1 + _f(r, b1, c1, d1) + x[_R1[j]] + _K1[r]) & M32, _S1[j]) + e1) & M32
            a1, e1, d1, c1, b1 = e1, d1, _rol(c1, 10), b1, t
            t = (_rol((a2 + _f(4 - r, b2, c2, d2) + x[_R2[j]] + _K2[r]) & M32, _S2[j]) + e2) & M32
            a2, e2, d2, c2, b2 = e2, d2, _rol(c2, 10), b2, t
        h = [(h[1] + c1 + d2) & M32, (h[2] + d1 + e2) & M32, (h[3] + e1 + a2) & M32, (h[4] + a1 + b2) & M32,
             (h[0] + b1 + c2) & M32]
    return b"".join(v.to_bytes(4, "little") for v in h)


assert ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def hash160(b):
    return ripemd160(hashlib.sha256(b).digest())


# secp256k1
P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return x, (lam * (p[0] - x) - p[1]) % P


def _mul(k, p=G):
    out = None
    while k:
        if k & 1:
            out = _add(out, p)
        p = _add(p, p)
        k >>= 1
    return out


class Key:
    """A throwaway secp256k1 key made at random; its secret is never shown"""

    def __init__(self):
        self._d = secrets.randbelow(N - 1) + 1
        x, y = _mul(self._d)
        self.pub = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
        self.h160 = hash160(self.pub)

    def __repr__(self):
        return "Key(<hidden>)"

    def _sign(self, z):
        while True:
            k = secrets.randbelow(N - 1) + 1
            R = _mul(k)
            r = R[0] % N
            s = pow(k, N - 2, N) * (z + r * self._d) % N
            if r and s:
                recid = (R[1] & 1) | (2 if R[0] >= N else 0)
                if s > N // 2:
                    s, recid = N - s, recid ^ 1
                return r, s, recid

    def sign_message(self, message):
        """CObfuScationSigner::SignMessage: a compact signature over the magic and the
        message (obfuscation.cpp:45-58)"""
        r, s, recid = self._sign(int.from_bytes(dsha(varbytes(b"DarkNet Signed Message:\n") + varbytes(message)),
                                                "big"))
        return bytes([27 + recid + 4]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def sign_der(self, digest):
        r, s, _ = self._sign(int.from_bytes(digest, "big"))

        def num(v):
            b = v.to_bytes(33, "big").lstrip(b"\0")
            return b"\x02" + bytes([len(b) + (b[0] >= 0x80)]) + (b"\0" if b[0] >= 0x80 else b"") + b
        body = num(r) + num(s)
        return b"\x30" + bytes([len(body)]) + body


# --- serialization ---------------------------------------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def varbytes(b):
    return compact(len(b)) + b


def p2pkh_script(h160):
    return bytes.fromhex("76a914") + h160 + bytes.fromhex("88ac")


def p2pkh_asm(h160):
    return f"OP_DUP OP_HASH160 {h160.hex()} OP_EQUALVERIFY OP_CHECKSIG"


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + dsha(payload)[:4]
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


def address(h160):
    """A regtest P2PKH address (chainparams.cpp:426, regtest takes testnet's prefixes)"""
    return b58check(bytes([139]) + h160)


def txin(txid_hex, n, script_sig=b"", seq=0xffffffff):
    return bytes.fromhex(txid_hex)[::-1] + struct.pack("<I", n) + varbytes(script_sig) + struct.pack("<I", seq)


def txin_string(txid_hex, n, script_sig=b""):
    """CTxIn::ToString with the script empty or as hex (the bare inputs these messages carry)"""
    return f"CTxIn(COutPoint({txid_hex}, {n}), scriptSig={script_sig.hex()[:24]})"


def service(ip, port):
    return bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


class Ping:
    """CMasternodePing (MasternodePing.h:31-37, MasternodePing.cpp:9-29)"""

    def __init__(self, coll, block_hash, sig_time, key):
        self.txid, self.n = coll
        self.block_hash, self.sig_time = block_hash, sig_time
        self.signature = key.sign_message(self.message())

    def message(self):
        return (txin_string(self.txid, self.n) + self.block_hash + str(self.sig_time)).encode()

    def encode(self):
        return (txin(self.txid, self.n) + bytes.fromhex(self.block_hash)[::-1] + struct.pack("<q", self.sig_time)
                + varbytes(self.signature))

    def hash(self):
        return dsha(txin(self.txid, self.n) + struct.pack("<q", self.sig_time))


class Broadcast:
    """CMasternodeBroadcast (masternode.h:147-166, masternode.cpp:241-261)"""

    def __init__(self, coll, addr, sig_time, ping, coll_key, mn_key, signer=None, protocol=PROTOCOL, tier=0,
                 script_sig=b""):
        self.txid, self.n = coll
        self.addr, self.sig_time, self.ping = addr, sig_time, ping
        self.pub_coll, self.pub_mn = coll_key.pub, mn_key.pub
        self.protocol, self.tier, self.script_sig = protocol, tier, script_sig
        self.signature = (signer or coll_key).sign_message(self.message())

    def message(self):
        ip, port = self.addr
        return f"{ip}:{port}{self.sig_time}".encode() + self.pub_coll + self.pub_mn + str(self.protocol).encode()

    def encode(self):
        return (txin(self.txid, self.n, self.script_sig) + service(*self.addr) + varbytes(self.pub_coll)
                + varbytes(self.pub_mn) + varbytes(self.signature) + struct.pack("<qi", self.sig_time, self.protocol)
                + self.ping.encode() + struct.pack("<i", self.tier))

    def hash(self):
        return dsha(struct.pack("<q", self.sig_time) + varbytes(self.pub_coll))


class Winner:
    """CMasternodePaymentWinner as mnw carries it (MasternodePaymentWinner.h:59-80,
    MasternodePaymentWinner.cpp:38-77)"""

    def __init__(self, coll, height, payee_h160, key):
        self.txid, self.n = coll
        self.height, self.payee = height, p2pkh_script(payee_h160)
        self.signature = key.sign_message(f"{self.txid}-{self.n}{height}{p2pkh_asm(payee_h160)}".encode())

    def encode(self):
        return txin(self.txid, self.n) + struct.pack("<i", self.height) + varbytes(self.payee) + varbytes(
            self.signature)

    def hash(self):
        return dsha(varbytes(self.payee) + struct.pack("<i", self.height) + bytes.fromhex(self.txid)[::-1]
                    + struct.pack("<I", self.n))


# --- the nodes -------------------------------------------------------------------------

class Node:
    def __init__(self, name, binary, index):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"mnm{index}:{password}".encode()).decode()
        self.base = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=mnm{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0", "listen=1",
            f"bind={NODE_IP}", f"rpcbind={NODE_IP}", "rpcallowip=127.0.0.0/8", "dnsseed=0", "staking=0",
            "connect=127.0.0.2:1", "debug=masternode", "debug=mnpayments",
        ]
        os.makedirs(os.path.join(self.dir, "home"))
        self.proc = None
        # Names for the hashes of the messages sent to this node, for the relay rows
        self.names = {}
        self.coll = {}

    def start(self):
        tmp = os.path.join(self.dir, "divi.conf.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(self.base) + "\n")
        os.replace(tmp, os.path.join(self.dir, "divi.conf"))
        env = dict(os.environ, HOME=os.path.join(self.dir, "home"))
        with open(os.path.join(WORK, f"{self.name}.out"), "w") as o, \
                open(os.path.join(WORK, f"{self.name}.err"), "w") as e:
            self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                         stdout=o, stderr=e, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")
        if not wait_for(lambda: self.call("getblockcount")[0] == "ok", START_TIMEOUT):
            raise RuntimeError(f"{self.name} did not start")

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

    def mine(self, n):
        for _ in range(n):
            self.rpc("setgenerate", 1)

    def block_hash(self, depth):
        return self.rpc("getblockhash", self.rpc("getblockcount") - depth)

    def block_time(self, height):
        return self.rpc("getblock", self.rpc("getblockhash", height))["time"]


# --- a raw p2p peer ----------------------------------------------------------------------

MAGIC = bytes([0xa1, 0xcf, 0x7e, 0xac])
INV_NAMES = {7: "inv mnw", 14: "inv mnb", 15: "inv mnp"}


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def netaddr(ip, port):
    return struct.pack("<Q", 1) + bytes(10) + b"\xff\xff" + socket.inet_aton(ip) + struct.pack(">H", port)


class Peer:
    """A raw peer from its own loopback address. `state` is 'up' after the
    handshake, 'refused' when it does not get in, 'closed' once dropped; `got`
    holds the messages read since the last `take`."""

    def __init__(self, node, src):
        self.node, self.src = node, src
        self.sock = None
        self.got = []
        self.state = self.connect()

    def connect(self):
        sub = b"/mn-messages:1.0/"
        payload = (struct.pack("<iQq", PROTOCOL, 1, int(time.time())) + netaddr(NODE_IP, self.node.p2p)
                   + netaddr(self.src, 0) + secrets.token_bytes(8) + varbytes(sub) + struct.pack("<i", 0) + b"\x01")
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.bind((self.src, 0))
            self.sock.connect((NODE_IP, self.node.p2p))
            self.port = self.sock.getsockname()[1]
            self.sock.sendall(message("version", payload))
            got_version = got_verack = False
            deadline = time.time() + 10
            while not (got_version and got_verack) and time.time() < deadline:
                command, _ = self.read()
                if command == "version":
                    got_version = True
                    self.sock.sendall(message("verack"))
                elif command == "verack":
                    got_verack = True
            return "up" if got_version and got_verack else "refused"
        except (OSError, EOFError):
            return "refused"

    def read(self):
        head = self.recv(24)
        size = struct.unpack("<I", head[16:20])[0]
        return head[4:16].rstrip(b"\0").decode(), self.recv(size)

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

    def pump(self, secs):
        """Read for `secs`, answering pings"""
        deadline = time.time() + secs
        while self.state == "up" and time.time() < deadline:
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
            self.got.append((command, payload))
        return self.state

    def take(self):
        """What the node sent of these messages since the last take, named: the
        masternode invs, the masternode messages and a dseg naming a collateral"""
        out = []
        for command, payload in self.got:
            if command == "inv":
                count, off = payload[0], 1
                for k in range(count):
                    kind = struct.unpack("<I", payload[off + 36 * k:off + 36 * k + 4])[0]
                    h = payload[off + 36 * k + 4:off + 36 * k + 36]
                    if kind in INV_NAMES:
                        out.append(f"{INV_NAMES[kind]} {self.node.names.get(h, 'other')}")
            elif command in ("mnb", "mnp", "mnw"):
                h = MESSAGE_HASH[command](payload)
                out.append(f"{command} {self.node.names.get(h, 'other')}")
            elif command == "dseg":
                txid = payload[:32][::-1].hex()
                if txid != "00" * 32:
                    out.append(f"dseg {next((k for k, v in self.node.coll.items() if v[0] == txid), 'other')}")
        self.got = []
        return sorted(out)

    def close(self):
        if self.sock:
            self.sock.close()
        self.state = "closed"


def _mnb_hash(p):
    # sigTime and pubKeyCollateralAddress, after vin, addr and the key's length
    off = 36 + 1 + p[36] + 4 + 18
    klen = p[off]
    key = p[off:off + 1 + klen]
    rest = off + 1 + klen
    rest += 1 + p[rest]          # pubKeyMasternode
    rest += 1 + p[rest]          # signature
    return dsha(p[rest:rest + 8] + key)


def _mnp_hash(p):
    vin_len = 36 + 1 + p[36] + 4
    return dsha(p[:vin_len] + p[vin_len + 32:vin_len + 40])


def _mnw_hash(p):
    vin_len = 36 + 1 + p[36] + 4
    height = p[vin_len:vin_len + 4]
    plen = p[vin_len + 4]
    return dsha(p[vin_len + 4:vin_len + 5 + plen] + height + p[:36])


MESSAGE_HASH = {"mnb": _mnb_hash, "mnp": _mnp_hash, "mnw": _mnw_hash}


def banscore(node, peer):
    for p in node.rpc("getpeerinfo"):
        if p["addr"] == f"{peer.src}:{peer.port}":
            return p.get("banscore")
    return "gone"


def ask_for(n, kind, h, command):
    """getdata for one item from the second peer: 'the item', 'notfound', 'another'
    or 'no reply' (main.cpp:165-212, :322-345)"""
    w = n.watch
    w.pump(0.3)
    w.take()
    w.send("getdata", compact(1) + struct.pack("<I", kind) + h)
    w.pump(3)
    got = [(c, p) for c, p in w.got if c in (command, "notfound")]
    w.take()
    if not got:
        return "no reply"
    c, p = got[0]
    if c == "notfound":
        return "notfound"
    return "the item" if MESSAGE_HASH[command](p) == h else "another"


def unknown_getdata_rows():
    for kind, command, what in ((14, "mnb", "broadcast"), (15, "mnp", "ping"), (7, "mnw", "vote")):
        compare(f"getdata for an unknown {what}: reply", ask_for(C, kind, b"\xab" * 32, command),
                ask_for(I, kind, b"\xab" * 32, command))


# --- start -----------------------------------------------------------------------------

C = Node("divid", DIVID, 0)
I = Node("irondivid", IRONDIVID, 1)
NODES = (C, I)
for n in NODES:
    n.start()

# The keys: collateral, masternode, and a stranger's, all throwaway
KC, KM, KX = Key(), Key(), Key()
COLL_ADDRESS = address(KC.h160)

next_ip = [11]


def new_ip():
    next_ip[0] += 1
    if next_ip[0] > 250:
        raise RuntimeError("out of source addresses")
    return f"127.0.0.{next_ip[0]}"


def send_rows(name, build, probe=None, settle=4.0, watchers=None):
    """Send what build(node) returns ((command, payload, hash name)) from a new raw
    peer to each node, then rows of: what the node took (probe(node)), the
    sender's banscore, whether the sender was dropped, what a second peer was
    sent, and what the sender got back"""
    src = new_ip()
    out = {}
    for n in NODES:
        w = watchers[n]
        w.pump(0.3)
        w.take()
        a = Peer(n, src)
        if a.state != "up":
            raise RuntimeError(f"raw peer {src} did not get into {n.name}")
        command, payload, label = build(n)
        n.names[MESSAGE_HASH[command](payload)] = label
        a.send(command, payload)
        end = time.time() + settle
        while time.time() < end:
            a.pump(0.2)
            w.pump(0.2)
        out[n] = {
            "taken": probe(n) if probe else None,
            "banscore": banscore(n, a),
            "sender": a.state,
            "relayed": w.take(),
            "back": a.take(),
        }
        a.close()
    for what, label in (("taken", "taken"), ("banscore", "banscore of the sender"),
                        ("sender", "the sender"), ("relayed", "sent to another peer"),
                        ("back", "sent back to the sender")):
        if what == "taken" and probe is None:
            continue
        compare(f"{name}: {label}", out[C][what], out[I][what])
    return src


# --- before the chain is synced: divid reads no masternode message until its
# tip is less than ten minutes old (MasternodeModule.cpp:371-382,
# MasternodeHelpers.cpp:27-64) --------------------------------------------------------------
for n in NODES:
    n.watch = Peer(n, "127.0.0.10")
WATCH = {n: n.watch for n in NODES}
T0 = int(time.time())


def early_mnb(n):
    coll = ("ab" * 32, 0)
    ping = Ping(coll, "00" * 32, T0, KM)
    return "mnb", Broadcast(coll, (NODE_IP, n.p2p), T0, ping, KC, KM, signer=KX).encode(), "early"


send_rows("a broadcast with a bad signature, the tip not recent", early_mnb, watchers=WATCH)

# --- the chain and the collaterals --------------------------------------------------------
for n in NODES:
    n.mine(31)


def pay_collateral(n, name):
    txid = n.rpc("sendtoaddress", COLL_ADDRESS, 100)
    tx = n.rpc("decoderawtransaction", n.rpc("gettransaction", txid)["hex"])
    vout = next(o["n"] for o in tx["vout"] if COLL_ADDRESS in o.get("scriptPubKey", {}).get("addresses", []))
    n.coll[name] = (txid, vout)


def spend_collateral(n, name):
    """Spend the collateral `name` back to the node's wallet, signed here with the
    collateral key"""
    txid, vout = n.coll[name]
    pay = p2pkh_script(b58decode(n.rpc("getnewaddress"))[1:21])
    outs = compact(1) + struct.pack("<q", 99_90000000) + varbytes(pay)

    def tx(script):
        return struct.pack("<i", 1) + compact(1) + txin(txid, vout, script) + outs + struct.pack("<I", 0)
    digest = dsha(tx(p2pkh_script(KC.h160)) + struct.pack("<I", 1))
    signed = tx(varbytes(KC.sign_der(digest) + b"\x01") + varbytes(KC.pub))
    n.rpc("sendrawtransaction", signed.hex())


for n in NODES:
    for name in ("mn1", "spare", "spent"):
        pay_collateral(n, name)
    n.mine(1)
    coll_height = n.rpc("getblockcount")
    n.mine(14)
    # The block that gives the collateral its 15th confirmation (masternodeman.cpp:213-227)
    n.conf_time = n.block_time(coll_height + 14)
    spend_collateral(n, "spent")
    n.mine(123 - n.rpc("getblockcount"))
    pay_collateral(n, "young")
    n.mine(3)
compare("height after the setup", C.rpc("getblockcount"), I.rpc("getblockcount"))


def sig_now():
    """A broadcast time no earlier than either node's 15th-confirmation block, whose
    time runs ahead of the clock when blocks are mined in a burst
    (masternodeman.cpp:221-227)"""
    return max([int(time.time())] + [n.conf_time + 1 for n in NODES])


def listed(coll_name):
    """The masternode of `coll_name` as listmasternodes shows it: status and the
    ping it was last seen with"""
    def probe(n):
        txid, vout = n.coll[coll_name]
        for e in n.rpc("listmasternodes"):
            if e["txhash"] == txid and e["outidx"] == vout:
                return [e["status"], SEEN.get(e["lastseen"], "lastseen other")]
        return "not listed"
    return probe


SEEN = {}


def mnb_for(coll_name, sig_time, ping_time, ping_depth=2, ping_block=None, ping_key=None, label=None, **kw):
    def build(n):
        coll = n.coll[coll_name]
        block = ping_block or n.block_hash(ping_depth)
        ping = Ping(coll, block, ping_time, ping_key or KM)
        mnb = Broadcast(coll, (NODE_IP, n.p2p), sig_time, ping, kw.get("coll_key", KC), KM, signer=kw.get("signer"),
                        protocol=kw.get("protocol", PROTOCOL), tier=kw.get("tier", 0),
                        script_sig=kw.get("script_sig", b""))
        n.names[ping.hash()] = (label or coll_name) + " ping"
        return "mnb", mnb.encode(), label or coll_name
    return build


# --- broadcasts (CMasternodeMan::ProcessBroadcast, masternodeman.cpp:420-502) --------------
now = int(time.time())
MN1_TIME = sig_now()
MN1_PING = now - 3000           # old enough that a ping now is not too early
SEEN[MN1_PING] = "ping of the broadcast"
send_rows("a good broadcast", mnb_for("mn1", MN1_TIME, MN1_PING, label="mn1"), listed("mn1"), watchers=WATCH)
send_rows("the same broadcast again", mnb_for("mn1", MN1_TIME, MN1_PING, label="mn1"), listed("mn1"),
          watchers=WATCH)

# getdata for it from the second peer: the broadcast as it was sent (main.cpp:193-195)
good = {}
for n in NODES:
    mnb = Broadcast(n.coll["mn1"], (NODE_IP, n.p2p), MN1_TIME, Ping(n.coll["mn1"], n.block_hash(2), MN1_PING, KM),
                    KC, KM)
    good[n] = ask_for(n, 14, mnb.hash(), "mnb")
compare("getdata for the broadcast: reply", good[C], good[I])
unknown_getdata_rows()

# A newer broadcast of the same masternode within five minutes of the last is
# not taken (masternodeman.cpp:51-55, :288-303); the entry keeps its ping
SEEN[MN1_PING + 60] = "ping of the newer broadcast"
send_rows("a newer broadcast within five minutes", mnb_for("mn1", MN1_TIME + 60, MN1_PING + 60, label="mn1 newer"),
          listed("mn1"), watchers=WATCH)
# An older one is refused (masternodeman.cpp:277-282)
send_rows("an older broadcast", mnb_for("mn1", MN1_TIME - 60, MN1_PING, label="mn1 older"), listed("mn1"),
          watchers=WATCH)

now = sig_now()
spare = listed("spare")
send_rows("a broadcast signed two hours ahead", mnb_for("spare", int(time.time()) + 7200, now - 60), spare, watchers=WATCH)
send_rows("a broadcast of tier 7", mnb_for("spare", now, now - 60, tier=7), spare, watchers=WATCH)
send_rows("a broadcast of protocol 70914", mnb_for("spare", now, now - 60, protocol=70914), spare, watchers=WATCH)
send_rows("a broadcast whose input has a scriptSig", mnb_for("spare", now, now - 60, script_sig=b"\x51"), spare,
          watchers=WATCH)
send_rows("a broadcast with a bad signature", mnb_for("spare", now, now - 60, signer=KX), spare, watchers=WATCH)
send_rows("a broadcast whose collateral pays another key", mnb_for("spare", now, now - 60, coll_key=KX), spare,
          watchers=WATCH)
send_rows("a broadcast of a collateral with 3 confirmations", mnb_for("young", now, now - 60), listed("young"),
          watchers=WATCH)
send_rows("a broadcast of a spent collateral", mnb_for("spent", now, now - 60), listed("spent"), watchers=WATCH)


def before_conf(n):
    return mnb_for("spare", n.conf_time - 1000, now - 60)(n)


send_rows("a broadcast signed before its collateral's 15th confirmation", before_conf, spare, watchers=WATCH)
send_rows("a broadcast whose ping has a bad signature", mnb_for("spare", now, now - 60, ping_key=KX), spare,
          watchers=WATCH)
send_rows("a broadcast whose ping is signed two hours ahead", mnb_for("spare", now, now + 7200), spare,
          watchers=WATCH)
send_rows("a broadcast whose ping names an unknown block", mnb_for("spare", now, now - 60, ping_block="cd" * 32),
          spare, watchers=WATCH)
send_rows("a broadcast whose ping names a block 30 deep", mnb_for("spare", now, now - 60, ping_depth=30), spare,
          watchers=WATCH)


# --- pings (CMasternodeMan::ProcessPing, CheckAndUpdatePing, masternodeman.cpp:309-375, :504-534)
def ping_for(coll_name, sig_time, depth=2, key=None, block=None, label="ping"):
    def build(n):
        p = Ping(n.coll[coll_name], block or n.block_hash(depth), sig_time, key or KM)
        return "mnp", p.encode(), label
    return build


mn1 = listed("mn1")
now = int(time.time())
PING1 = now
SEEN[PING1] = "the good ping"
send_rows("a good ping", ping_for("mn1", PING1, label="good ping"), mn1, watchers=WATCH)

# A ping's hash is its input and time (MasternodePing.cpp:23-29), so the same ping
# signed again is the same ping
send_rows("the same ping again", ping_for("mn1", PING1, label="good ping"), mn1, watchers=WATCH)


compare("getdata for the ping: reply",
        *(ask_for(n, 15, Ping(n.coll["mn1"], n.block_hash(2), PING1, KM).hash(), "mnp") for n in NODES))
send_rows("a ping a minute after the last", ping_for("mn1", PING1 + 60, label="early ping"), mn1, watchers=WATCH)
send_rows("a ping with a bad signature", ping_for("mn1", PING1 + 600, key=KX, label="bad ping"), mn1,
          watchers=WATCH)
send_rows("a ping signed two hours ahead", ping_for("mn1", PING1 + 7200, label="future ping"), mn1, watchers=WATCH)
send_rows("a ping signed two hours ago", ping_for("mn1", PING1 - 7200, label="past ping"), mn1, watchers=WATCH)
send_rows("a ping naming an unknown block", ping_for("mn1", PING1 + 700, block="cd" * 32, label="ping unknown block"),
          mn1, watchers=WATCH)
send_rows("a ping naming a block 30 deep", ping_for("mn1", PING1 + 800, depth=30, label="ping deep block"), mn1,
          watchers=WATCH)
send_rows("a ping of a masternode not in the list", ping_for("spare", PING1, label="ping unknown masternode"),
          listed("spare"), watchers=WATCH)


# --- payment votes (CMasternodePayments::ProcessMasternodeWinners,
# CheckMasternodeWinnerCandidate, masternode-payments.cpp:203-267, :283-331) ---------------
def winners_at(height):
    def probe(n):
        for e in n.rpc("getmasternodewinners", "30"):
            if e.get("nHeight") == height:
                return e.get("winner")
        return "no such height"
    return probe


def vote(coll_name, height_ahead, payee=None, key=None, label="vote"):
    def build(n):
        w = Winner(n.coll[coll_name], n.rpc("getblockcount") + height_ahead, payee or KC.h160, key or KM)
        return "mnw", w.encode(), label
    return build


def height_ahead(k):
    return C.rpc("getblockcount") + k


for n in NODES:
    n.mine(1)
compare("height before the votes", C.rpc("getblockcount"), I.rpc("getblockcount"))
h = height_ahead(3)
send_rows("a vote of a masternode younger than 25 minutes", vote("mn1", 3, label="young vote"), winners_at(h),
          watchers=WATCH)
send_rows("a vote of a masternode not in the list", vote("young", 4, label="vote unknown masternode"),
          winners_at(h + 1), watchers=WATCH)
send_rows("a vote for a height 30 ahead", vote("mn1", 30, label="far vote"), watchers=WATCH)

# Wait until the masternode may vote, mining a block a minute so both tips stay recent
while time.time() < MN1_TIME + VOTER_AGE:
    for n in NODES:
        n.mine(1)
    for n in NODES:
        n.watch.pump(min(60.0, max(0.0, MN1_TIME + VOTER_AGE - time.time())) / 2)
        n.watch.take()
compare("height after the wait", C.rpc("getblockcount"), I.rpc("getblockcount"))
compare("mnsync status: currentMasternodeSyncStatus",
        C.rpc("mnsync", "status").get("currentMasternodeSyncStatus"),
        I.rpc("mnsync", "status").get("currentMasternodeSyncStatus"))

h = height_ahead(5)
send_rows("a good vote", vote("mn1", 5, label="good vote"), winners_at(h), watchers=WATCH)


compare("getdata for the vote: reply",
        *(ask_for(n, 7, Winner(n.coll["mn1"], h, KC.h160, KM).hash(), "mnw") for n in NODES))
send_rows("the same vote again", vote("mn1", 5, label="good vote"), winners_at(h), watchers=WATCH)
send_rows("a second payee from the same masternode", vote("mn1", 5, payee=KX.h160, label="second vote"),
          winners_at(h), watchers=WATCH)
send_rows("a vote with a bad signature", vote("mn1", 6, key=KX, label="bad vote"), winners_at(h + 1),
          watchers=WATCH)
send_rows("a vote for a payee not in the queue", vote("mn1", 7, payee=KX.h160, label="vote other payee"),
          winners_at(h + 2), watchers=WATCH)

# A newer broadcast more than five minutes after the last updates the entry and
# is relayed (masternodeman.cpp:288-307)
now = int(time.time())
SEEN[now - 30] = "ping of the later broadcast"
LATER = sig_now()
send_rows("a newer broadcast after five minutes", mnb_for("mn1", LATER, now - 30, label="mn1 later"), mn1,
          watchers=WATCH)
# It updates the entry and is announced, but is not kept as seen, so a peer that
# asks for it gets notfound (masternodeman.cpp:288-307)
compare("getdata for the newer broadcast: reply",
        *(ask_for(n, 14, Broadcast(n.coll["mn1"], (NODE_IP, n.p2p), LATER,
                                   Ping(n.coll["mn1"], n.block_hash(2), now - 30, KM), KC, KM).hash(), "mnb")
          for n in NODES))

# The votes outlive a restart: divid writes them to mnpayments.dat at its stop
# and reads them back at its start, its masternode list being kept too
# (init.cpp:376, MasternodeModule.cpp:269-297)
voted_at = {n.name: [winners_at(x)(n) for x in (h, h + 1, h + 2)] for n in NODES}
for n in NODES:
    n.stop()
for n in NODES:
    n.start()
again = {n.name: [winners_at(x)(n) for x in (h, h + 1, h + 2)] for n in NODES}
compare("after a restart: the winners at the voted heights", again["divid"], again["irondivid"])
compare("after a restart: the same winners as before the stop",
        again["divid"] == voted_at["divid"], again["irondivid"] == voted_at["irondivid"])

for n in NODES:
    n.stop()
print(f"# rows: {counts['PASS']} PASS, {counts['KNOWN']} KNOWN, {counts['FAIL']} FAIL", flush=True)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
