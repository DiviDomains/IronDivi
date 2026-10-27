# A wallet's unconfirmed sends across a restart, next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` miner on regtest and two followers of it, a `divid` and an irondivid. Each
follower sends a chain of unconfirmed transactions, and sends a coin the miner then spends elsewhere while the
follower is down. Each is stopped cleanly or killed (`kill -9`), started again, and its mempool and wallet replies are
compared. Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason;
- `FAIL`: differs and should not, a `KNOWN` row that differs in another way, or a `KNOWN` row that now matches
  divid (the list below is out of date).

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 20 minutes).

```sh
scripts/mempool-restart/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/mempool-restart/run.sh target/release ~/divi-3.0.0/bin 54250 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+5` on 127.0.0.2 (the miner's p2p and RPC, then divid's, then
  irondivid's). `<port-base>+49` must have nothing listening: a follower started alone is pointed at it.
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end (kept with
  `KEEP=1`).
- `MEMPOOL_RESTART_CHAIN` (3): the length of the chain of sends.

A run takes about 3 minutes and is stopped after 20. However it ends, every node is stopped. Needs bash and python3
(standard library only). RPC passwords are made at random for each run and kept in each node's 0600 `divi.conf`;
every key is a throwaway of the run's own wallets, and the one key the miner imports is never printed.

## Set-up

The miner mines 110 blocks, sends each follower three coins of 100 DIVI and mines 25 more. Then all three stop and
their data directories are kept as templates; each case starts from fresh copies.

## Rows

Core paths are under `divi/src/` of the Divi Core source at v3.0.0.

| case | rows (each compared between the two followers) |
|---|---|
| a chain of sends, then a clean stop or a kill | every coin but one locked; a `sendtoaddress` of 1 DIVI to the miner, then two more sends each spending the change of the one before (made raw, signed by the wallet and sent with `sendrawtransaction`: divid's coin selection does not take unconfirmed change). Before: `gettransaction` (confirmations, amount, fee, in the mempool), `listtransactions` entries of the sends, `getbalance`. After the stop or kill and a start with no peer: the mempool (which of its own sends, none of the other follower's, nothing else), `gettransaction`, `listtransactions`, `time` and `timereceived` unchanged, `getbalance` unchanged, `getmempoolinfo` size. divid keeps no mempool file and puts back every wallet transaction that is in neither a block nor the mempool (`init.cpp:1262-1275`, `MerkleTxConfirmationNumberCalculator.cpp:48-53`). Then back with the miner, which mines a block: `gettransaction`, the mempool size |
| a send spent elsewhere while the node is down, a clean stop or a kill | the followers run alone, so the miner never hears of the sends; the miner imports the key of the follower's one unlocked coin; the follower sends twice (the second spends the first's change), then stops or is killed; the miner spends that coin to itself and mines it; the follower starts with the miner as its peer and follows. `gettransaction` of both sends (divid: confirmations -1, not in the mempool), `listtransactions`, `getbalance` now and with the sends still unconfirmed, `listunspent` count. Then another start with no peer: the wallet offers the sends again and the mempool refuses them: `gettransaction`, the mempool size |

## Not covered here

- A relayed (not the wallet's) transaction across a restart, a long chain, expiry and the next block:
  `scripts/mempool-limits`.
- The wallet's sends after a restart reaching other nodes, and mempool rebroadcast: `scripts/tx-relay`; the
  rebroadcast timer and its choice of transactions are unit tests in `crates/divi-node/src/rebroadcast.rs`.
- Orphans across a restart: `scripts/orphans`.
- The size cap: divid has none; irondivid's (300 MB) is `docs/divid-differences.md` M1, pinned by unit tests in
  `crates/divi-node/src/mempool.rs`.

## KNOWN differences

None.

## Proving a difference is caught

`MEMPOOL_RESTART_INJECT=<row name>` changes irondivid's outcome of that row, e.g.
`MEMPOOL_RESTART_INJECT='chain (kill) and a start with no peer: the mempool'`: that row prints `FAIL` and the run
exits 1.
