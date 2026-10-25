#!/usr/bin/env python3
"""Write the superblocks of a divid chain for crates/divi-storage/tests/real_superblocks.rs.

    real-dump.py <divid datadir> <out> [network]

The datadir's divi.conf gives the RPC port, user and password (rpcbind or
rpcconnect for the host, default 127.0.0.1). Run divid on a copy of a chain
with -disablewallet, connect=0 and listen=0: the dump only reads. network is
mainnet (default) or testnet.

Each line of <out>: <height> <block hex> <winner scripts at height - 1, hex,
comma separated, or ->. getlotteryblockwinners gives each winner's script as
its destinations, ':' joined (rpclottery.cpp:70-80):
- two destinations: a staking vault, STAKING_VAULT(owner, vault)
  (StakingVaultScript.cpp:9-12);
- one P2SH address: its P2SH script;
- one key: P2PKH, or P2PK when the cycle's own coinstakes show that key's
  ticket was P2PK. A lottery winner's script is its coinstake's vout[1]
  (LotteryWinnersCalculator.cpp:47-60). The cycle is scanned only for a key
  the lottery block does not pay as P2PKH.
Prints heights and counts only, never an address or a script.
"""

import base64
import hashlib
import json
import sys
import urllib.request

DATADIR, OUT = sys.argv[1], sys.argv[2]
NETWORK = sys.argv[3] if len(sys.argv) > 3 else "mainnet"
# chainparams.cpp: lottery and treasury cycles, P2PKH and P2SH address versions
LOTTERY_CYCLE, TREASURY_CYCLE, P2PKH, P2SH = {
    "mainnet": (10080, 10081, 30, 13), "testnet": (200, 201, 139, 19)}[NETWORK]
SWITCH = LOTTERY_CYCLE * TREASURY_CYCLE
COIN = 10 ** 8

conf = dict(l.strip().split("=", 1) for l in open(f"{DATADIR}/divi.conf") if "=" in l and not l.startswith("#"))
HOST = conf.get("rpcconnect", conf.get("rpcbind", "127.0.0.1"))
URL = f"http://{HOST}:{conf['rpcport']}/"
AUTH = "Basic " + base64.b64encode(f"{conf['rpcuser']}:{conf['rpcpassword']}".encode()).decode()


def batch(calls):
    body = json.dumps([{"id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls)]).encode()
    req = urllib.request.Request(URL, body, {"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        replies = sorted(json.load(r), key=lambda x: x["id"])
    for x in replies:
        if x.get("error"):
            raise SystemExit(f"{calls[x['id']][0]}: {x['error']}")
    return [x["result"] for x in replies]


def rpc(method, *params):
    return batch([(method, list(params))])[0]


# --- the lottery and treasury heights (SuperblockHeightValidator.cpp:6-34) ---

def is_lottery(h):
    return h % LOTTERY_CYCLE == 0 if h < SWITCH else (h - SWITCH) % LOTTERY_CYCLE == 0


def is_treasury(h):
    return h % TREASURY_CYCLE == 0 if h < SWITCH else is_lottery(h - 1)


# --- RIPEMD-160: hashlib's comes from OpenSSL, which may not have it ---

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


# --- addresses, scripts and blocks ---

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def decode_address(address):
    """(version, hash160)"""
    n = 0
    for c in address:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(25, "big")
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise SystemExit("an address with a bad checksum")
    return raw[0], raw[1:21]


def p2pkh(key_hash):
    return "76a914" + key_hash.hex() + "88ac"


def p2pk_key_hash(script):
    """hash160 of the key of a P2PK script, else None"""
    b = bytes.fromhex(script)
    if len(b) in (35, 67) and b[0] == len(b) - 2 and b[-1] == 0xac:
        return ripemd160(hashlib.sha256(b[1:-1]).digest())
    return None


def varint(b, i):
    n = b[i]
    if n < 0xfd:
        return n, i + 1
    w = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]
    return int.from_bytes(b[i + 1:i + 1 + w], "little"), i + 1 + w


def coinstake_outputs(block_hex):
    """(value, script hex) of each output of tx[1]"""
    raw = bytes.fromhex(block_hex)
    i = 80 + (32 if int.from_bytes(raw[:4], "little") > 3 else 0)  # v4 headers carry an accumulator
    _, i = varint(raw, i)
    for _ in range(2):
        i += 4
        nin, i = varint(raw, i)
        for _ in range(nin):
            i += 36
            n, i = varint(raw, i)
            i += n + 4
        nout, i = varint(raw, i)
        outs = []
        for _ in range(nout):
            value = int.from_bytes(raw[i:i + 8], "little")
            n, i = varint(raw, i + 8)
            outs.append((value, raw[i:i + n].hex()))
            i += n
        i += 4
    return outs


def cycle_p2pk_tickets(height, key_hashes):
    """P2PK coinstake payees (vout[1]) of the given keys in the cycle before the lottery block at height"""
    found = {}
    first = max(1, height - LOTTERY_CYCLE)
    for start in range(first, height, 500):
        hashes = batch([("getblockhash", [h]) for h in range(start, min(start + 500, height))])
        for block in batch([("getblock", [x, False]) for x in hashes]):
            outs = coinstake_outputs(block)
            if len(outs) > 1:
                key = p2pk_key_hash(outs[1][1])
                if key in key_hashes:
                    found.setdefault(key, set()).add(outs[1][1])
    return found


def winner_scripts(height, block_hex):
    winners = rpc("getlotteryblockwinners", height - 1)["Lottery Candidates"]
    scripts, single_keys = [], {}
    for k, w in enumerate(winners):
        parts = [decode_address(a) for a in w["Address"].split(":")]
        if len(parts) == 2 and parts[0][0] == parts[1][0] == P2PKH:
            scripts.append("6314" + parts[0][1].hex() + "67b914" + parts[1][1].hex() + "6878a988ac")
        elif len(parts) == 1 and parts[0][0] == P2SH:
            scripts.append("a914" + parts[0][1].hex() + "87")
        elif len(parts) == 1 and parts[0][0] == P2PKH:
            scripts.append(p2pkh(parts[0][1]))
            single_keys[k] = parts[0][1]
        else:
            raise SystemExit(f"winner {k} at {height - 1}: {len(parts)} destinations of a form not handled")
    if not is_lottery(height) or is_treasury(height):
        return scripts
    outs = {s for _, s in coinstake_outputs(block_hex)}
    unpaid = {key: k for k, key in single_keys.items() if scripts[k] not in outs}
    if unpaid:
        tickets = cycle_p2pk_tickets(height, set(unpaid))
        for key, k in unpaid.items():
            got = tickets.get(key, set())
            if len(got) == 1:
                scripts[k] = next(iter(got))
            print(f"# {height}: winner {k} not paid as P2PKH; P2PK tickets of its key in the cycle: {len(got)}",
                  flush=True)
    return scripts


tip = rpc("getblockcount")
heights = [h for h in range(1, tip + 1) if is_lottery(h) or is_treasury(h)]
with open(OUT, "w") as f:
    for h in heights:
        block = rpc("getblock", rpc("getblockhash", h), False)
        f.write(f"{h} {block} {','.join(winner_scripts(h, block)) or '-'}\n")
print(f"# {NETWORK} tip {tip}: {len(heights)} superblock heights to {heights[-1] if heights else None}")
