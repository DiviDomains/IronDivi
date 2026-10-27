# Mempool limits and what survives a restart, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` miner on regtest and two followers of it, a `divid` and an irondivid. The
miner signs and sends raw transactions of its own coins, relays them to both followers, and the script reaches each
of the mempool limits divid has (and checks the ones it does not have) on purpose. It compares the answers, the
mempool contents, and each follower's next block. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 20 minutes).

```sh
scripts/mempool-limits/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mempool-limits/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (the miner's p2p and RPC, then divid's, then
  irondivid's). `<port-base>+49` must have nothing listening: a follower started alone is pointed at it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end (kept with
  `KEEP=1`).
- `MEMPOOL_LIMITS_CHAIN` (50): the length of the unconfirmed chain; `MEMPOOL_LIMITS_FANOUT` (200): the outputs of the
  wide transaction and the spends of them.

A run takes about 2 minutes and is stopped after 20. However it ends, every node is stopped. Needs bash and python3
(standard library only). RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`;
every key is a throwaway of the run's own wallets.

Run with divid in both places (a directory whose `irondivid` is a link to `divid`), every row gives the same answer
on both sides; the one KNOWN row then prints FAIL ("listed as KNOWN, but now the same as divid"), and nothing else
does.

## Set-up

The miner mines 110 blocks, sends each follower ten coins of 100 DIVI and itself forty coins of 100 DIVI, and mines
25 more. Then all three stop and their data directories are kept as templates. Each part below starts from fresh
copies, with both followers connected to the miner only, so they are not peers of each other.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0.

| part | rows (each compared between the two followers) |
|---|---|
| what the mempool shows | a paying transaction (0.001 DIVI fee), a free one of an old coin (taken on priority), and a child of the paying one: every field of `getrawmempool true` (`size`, `fee`, `height`, `startingpriority`, `currentpriority` (whole numbers), `depends`, `time` within 60 s) and their order (`rpcblockchain.cpp:118-140`); `getrawmempool`; `getmempoolinfo` `size` and `bytes` (`:569-574`) |
| `sendrawtransaction` | of a transaction the mempool holds, without and with `allowhighfees`: the txid again (divid relays it again, `rpcrawtransaction.cpp:862-899`); a second spend of a mempool coin: -25 with no text (`MempoolConsensus.cpp:304-314`). The fee cap and the reject texts are compared by `scripts/fee-estimate` |
| expiry | the clock moved 15 days on (`setmocktime`): the three are still in the mempool. divid has no expiry: the entry time is kept only for `getrawmempool` (`MemPoolEntry.h:14`) |
| a long chain | 50 transactions, each spending the one before, all unconfirmed: all 50 taken; the last one `depends` on the one before. divid has no limit on chains (`MempoolConsensus.cpp:325-351` reads inputs through the mempool's view, with no count or size check) |
| a wide fan-out | a transaction of 200 outputs and 200 spends of them: all 201 taken; `getmempoolinfo` with everything in |
| the next block | the miner stops; each follower mines one block from its own mempool: how many transactions it takes from the mempool, how many are left, and that both take the same ones |
| a restart | a transaction the miner relays and a wallet send of each follower; then a clean stop, or a `kill -9`, and a start with no peer: what the mempool holds. divid keeps no mempool file and puts back only its wallet's unconfirmed transactions (`init.cpp:1262-1275`), so after either the mempool holds the node's own wallet send only. Before the stop both mempools held the same |

## Not covered here

- Free and low-fee relay (`-limitfreerelay`, the rate limiter, `-minrelaytxfee`, priority, `-relaypriority`):
  `scripts/relay-policy`.
- Orphans (`-maxorphantx`, the 5000-byte limit, the parent arriving, a restart): `scripts/orphans`.
- `sendrawtransaction`'s fee cap with and without `allowhighfees`, and its reject texts: `scripts/fee-estimate`.
- A wallet's unconfirmed transactions after a restart, and their relay: `scripts/tx-relay`.
- A size cap: divid has none (`MempoolConsensus.cpp:415-416` stores every transaction that passes the checks;
  `txmempool.cpp:70-89` `addUnchecked` checks no size). irondivid has one, 300 MB (KNOWN below), which a regtest run
  cannot reach.

## KNOWN differences

- `getmempoolinfo keys`: irondivid adds `usage`, `maxmempool` and `mempoolminfee` (`docs/divid-differences.md`
  R13; also KNOWN in `scripts/net-counters`). divid gives `size` and `bytes` only (`rpcblockchain.cpp:569-574`).
- Not run: irondivid keeps its mempool under 300 MB (`crates/divi-node/src/config.rs` `MempoolConfig::max_size`,
  no option sets it). Past it, a transaction is taken only if the ones paying a lower fee rate, each with its
  descendants, free enough room (`crates/divi-node/src/mempool.rs` `make_room_for`; `docs/divid-differences.md` M1);
  divid has no cap and grows until memory runs out. It is kept as a memory guard and cannot be reached on regtest in
  a run of minutes.
