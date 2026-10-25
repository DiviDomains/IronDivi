# Relay-policy options next to Divi Core

`run.sh` compares how Divi Core 3.0.0 `divid` and irondivid take or refuse the same raw transactions under the
relay-policy options divid's mempool reads (`MempoolConsensus.cpp`):

| option | what divid does |
|---|---|
| `-permitbaremultisig` | default on: a bare multisig output (up to 3 keys) is standard; off: 64 `bare-multisig` |
| `-datacarrier`, `-datacarriersize` | the largest standard OP_META output script is `-datacarriersize` bytes (603), or 0 with `-datacarrier=0`; larger: 64 `scriptpubkey` |
| `-relaypriority` | default on: below the relay fee, a transaction needs coin-age priority, else 66 `insufficient priority` |
| `-limitfreerelay` | free transactions from peers, at most this many thousand bytes a minute (30) in a decaying window; over it: 66 `rate limited free transaction` |

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, and the difference is listed below with the reason;
- `FAIL`: differs and should not, or a `KNOWN` row that now matches divid (the list below is out of date).

The run ends with `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted, or over 10 minutes).

```sh
scripts/relay-policy/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/relay-policy/run.sh target/release ~/divi-3.0.0/bin 54150 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2. The setup's three nodes use them all; the
  copies use the first four. `<port-base>+9` is used as a peer that does not exist.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about two minutes and is stopped after 10 minutes. However it ends, every node is stopped and
every directory deleted. Needs bash and python3 (standard library only).

**Switches:**

- `RELAY_POLICY_INJECT=<row name>` changes irondivid's reply of that row before it is compared, so the row FAILs.
- `RELAY_POLICY_DUMP=<dir>` writes both replies of every row that is not PASS into `<dir>`.

## Setup

1. A miner divid makes the chain and pays divid's wallet:
   - 80 old coins of 100 DIVI, 25 blocks before the end. A free spend of one has priority to spare: 100 DIVI × 26
     blocks / its size is far over `AllowFreeThreshold`, 1440 × COIN / 250 (`MemPoolEntry.h:18-40`).
   - One young coin of 1 DIVI, a block old: a free spend of it has too little priority.
2. **divid signs the transactions** (`signrawtransaction`), each spending a coin of its own:
   - bare multisig outputs 1-of-1, 1-of-2, 2-of-2, 1-of-3, 2-of-3, 3-of-3 and 1-of-4, of no one's keys (1G..4G);
   - OP_META outputs of 1 (OP_META alone), 40, 41, 603, 604, 1000 and 1001 bytes of script, and two OP_META outputs;
   - a paying transaction (0.001 DIVI fee);
   - free (fee 0) spends of an old coin and of the young coin;
   - a batch of 60 free spends of old coins, for the rate limiter.
3. All three nodes stop. divid's and irondivid's datadirs are kept as templates. irondivid's wallet plays no part;
   only its chain is used.

## Option sets and rows

Each option set gets two passes, each on fresh copies of both datadirs started with those options, listening, and
with no peers of their own:

1. **`sendrawtransaction`** (Core's `fLimitFree` false: no rate limit). Rows per transaction:
   - the reply (a txid, or the error code and message);
   - whether it is in the mempool.

   Then the 60 free transactions (how many are taken), and the whole mempool.
2. **A raw p2p peer** (`fLimitFree` true) relays every transaction, then the batch, on one connection. Rows per
   transaction:
   - the peer's `reject` (code and reason, or none);
   - whether it is in the mempool.

   Then how many of the 60 are taken, the reject reasons they get, and whether the peer stays connected.

The option sets are:

- the defaults;
- `-permitbaremultisig=0`;
- `-datacarrier=0`;
- `-datacarriersize=40`;
- `-datacarriersize=1000`;
- `-datacarrier=0 -datacarriersize=1000`;
- `-relaypriority=0`;
- `-limitfreerelay=0` (no free transaction from a peer is taken);
- `-limitfreerelay=1` (10,000 bytes: the first 53 free transactions from a peer, about 191 bytes each, then a
  refusal).

## KNOWN differences

None: no row differs from divid.

Core paths are under `divi/src/` of the Divi Core source at v3.0.0 (commit 9e2f76c).
