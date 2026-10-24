# The orphan transaction pool next to Divi Core

`run.sh` starts a Divi Core 3.0.0 `divid` and an irondivid on regtest, both with wallets made from the same phrase
and the same coins. It feeds each the same transactions from raw peers, and compares what each does with
transactions whose parents it does not have yet (orphans).

A node's orphan pool is seen only from outside:
- the mempool once a parent arrives;
- whether the node answers an `inv` with a `getdata`;
- what it announces to a second raw peer that only listens;
- the sending peer's `banscore` and connection;
- the `-debug=mempool` log lines (`stored orphan tx`, `ignoring large orphan tx`, `accepted orphan tx`,
  `invalid orphan tx`, `removed orphan tx`, `mapOrphan overflow`, `Erased <n> orphan tx from peer`). A row checks
  which of them appear and how often a txid is named in a `stored` line.

The Divi Core code is `divi/src/OrphanTransactions.cpp`, `divi/src/main.cpp:705-813` (the `tx` message) and
`divi/src/main.cpp:140-144` (AlreadyHave). irondivid's is `crates/divi-node/src/orphans.rs`, `accept_orphans` and the
relay handler in `crates/divi-node/src/node.rs`, and `crates/divi-network/src/relay.rs`.

Each row prints one line:

- `PASS`: same as divid;
- `KNOWN`: differs, in exactly the way listed below with the reason (none at present);
- `FAIL`: differs and should not.

The run ends with `# rows: ...` and `FAILS <n>`; the exit code is the number of FAILs (255: usage error, interrupted,
or over 10 minutes).

```sh
scripts/orphans/run.sh <irondivid-bin-dir> <core-bin-dir> <port-base> [root]

# for example, with a release build of this tree
cargo build --release -p irondivid
scripts/orphans/run.sh target/release ~/divi-3.0.0/bin 54100 /var/tmp
```

- `<irondivid-bin-dir>` holds `irondivid`; `<core-bin-dir>` holds Divi Core's `divid`.
- `<port-base>`: ports `<port-base>` to `<port-base>+3` on 127.0.0.2 (divid p2p and RPC, then irondivid's).
- `[root]`: a fresh directory is made under it (default `$TMPDIR`, else `/tmp`) and deleted at the end.

A run takes about four and a half minutes and is stopped after 10. However it ends, both nodes are stopped and their
directories deleted. Needs bash and python3 (standard library only). RPC passwords are made at random for each run
and kept in the 0600 `divi.conf`. The wallet phrase is read from divid's `dumphdinfo` and handed to irondivid in its
environment (`WALLET_MNEMONIC`); it is never printed or put on a command line.

## Nodes, coins and peers

- **Setup:** divid mines 30 blocks, pays 1 DIVI to each of 220 of its addresses in one transaction, and mines it.
  irondivid follows that chain. Then irondivid is restarted with no peer.
- **Coins:** both nodes have the same 220 coins, and the same coinbase one block deep, too young to spend (regtest
  coinbases mature after 20 blocks).
- **Transactions:** built here and signed by divid's `signrawtransaction`, with the parents given as `prevtxs`. Each
  pays a 0.001 DIVI fee. The same bytes go to both nodes.
- **Peers:** each case sends from its own loopback address (127.0.1.10 and up). A watcher peer from 127.0.0.90 on
  each node only listens: what it is sent is what the node announces.

## Rows

| case | what is compared (each on both nodes) |
|---|---|
| a child, then its parent | nothing announced while the child is held; then both in the mempool and both announced (`main.cpp:733-734`, `:760-762`) |
| a chain of three, last first | the same for three |
| two children of one parent, then the parent | the same for three |
| a child of two parents: one arrives, then the other | after the first parent only that parent; after the second, the child too |
| the same orphan twice, then its parent | kept once: one `stored` line names it (`OrphanTransactions.cpp:47-48`); both in the mempool |
| orphans of 5000 and 5001 bytes (one unknown input, 140 outputs, a push-only scriptSig of the needed length) | 5000 is kept: a second peer's `inv` of it gets no `getdata` (AlreadyHave). 5001 is not (`ignoring large orphan tx`, `OrphanTransactions.cpp:52-61`): the `inv` gets a `getdata`. Neither is announced |
| a transaction the mempool refused (it pays out more than its input) | not announced; an `inv` of it gets a `getdata` again: AlreadyHave is the mempool and the orphans only |
| an `inv` of a transaction never seen | a `getdata` |
| one sender goes before its parent comes, another stays | the gone peer's orphan is erased (`EraseOrphansFor`, `NodeState.cpp:41`): only the other child enters with the parents |
| an orphan with a bad signature (an output changed after signing), then its parent | the parent enters and is announced; the orphan does not; its sender scores 100 and is dropped (a local peer is not banned); the parent's sender stays at 0 (`main.cpp:760-776`) |
| an orphan that also spends a coinbase one block deep, then its parent | the parent enters; the orphan is removed (`removed orphan tx`) with no score |
| an orphan that also spends a coin a mempool transaction spends, then its parent | the parent enters; the orphan was never kept: the mempool's conflict check comes before the missing input (no `stored` line); no score |
| an orphan whose parent comes by `sendrawtransaction` and then a block | `sendrawtransaction` takes the parent and leaves the orphan held (only a relayed parent resolves orphans); the block does not take it either; the child sent again enters the mempool, since a `tx` message always goes to the mempool |
| a restart between an orphan and its parent | after the parent only the parent is in the mempool: the pool is kept in memory only |
| `-maxorphantx` 0, 1, not given (100), -5, abc: limit+5 orphans (10 for -5 and abc), then all their parents | how many parents and children reach the mempool, and whether `mapOrphan overflow` is logged. Eviction is random, so counts are compared. A value below 0 and a text both keep none (`main.cpp:790`: `std::max(0, GetArg)`, `atoi64("abc")` is 0) |
