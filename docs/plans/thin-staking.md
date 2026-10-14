# Thin staking ("staking shim") — design

Goal: a machine that keeps staking coins but does **not** carry gigabytes of blockchain.
Testnet/stagenet only until Bert signs off. Nothing here has been deployed.

## 1. How IronDivi stakes today, and what it costs on disk

* `crates/divi-node/src/staker.rs` runs a staking loop inside `irondivid`. Each attempt takes the
  wallet's mature UTXOs, hashes a kernel against the tip's **stake modifier** and the difficulty
  (`get_next_bits`), and if it wins builds and submits a block. It reads only the **block index**
  (headers, modifiers) and the **UTXO set**. It does not read block bodies.
* The same process validates and relays everything, so it also keeps the full history.
* Disk, measured (read-only) on `dnsdivi` mainnet node: `chainstate` (one RocksDB holding blocks,
  undo, block index, UTXO, spent index, masternodes) **7.7 GB**, `txindex` **740 MB**,
  `wallet` ~10 MB. Total **8.4 GB**. C++ Divi on hp3 for comparison: blocks 4.4 GB + chainstate 283 MB.
* Not measured: the per-column-family split on mainnet. That split decides how much pruning
  can ever save, so it is step 0 of the build plan.

## 2. What already exists: `expire` (block-expiry pruning)

Already built (`docs/block-expiry-pruning.md`): `--expire 0` discards block bodies and undo data
older than the last 2,880 blocks and never touches headers, UTXOs or indexes. The chainstate stays
complete, so staking is unaffected by design. Status: tests pass, a testnet node followed the tip
at `expire=0`, and a live staking test is running on hp3 (another lane; not touched here).
Measured saving on testnet is only **~7%** (864 M vs 926 M) because testnet blocks are tiny;
mainnet saving is unmeasured. Not covered by pruning: block index, UTXO set, txindex, spent index.

## 3. Options

| | Approach | Disk (estimate) | Trust | Code |
|---|---|---|---|---|
| A | **Pruned staking** (`expire=0`, plus `txindex` off) | Mainnet: bodies+undo go; index + UTXO + wallet stay. Likely low single-digit GB; **must measure** | None — full local validation | ~0 (done) |
| B | **Snapshot bootstrap + prune**: start from a checkpointed UTXO set + headers instead of syncing genesis | Same disk as A, but minutes not days to start | Trust the snapshot source (can be verified against a hash baked in a release) | Medium: export exists (`divi-storage/src/export.rs`); add import + checkpoint |
| C | **Cold staking / delegation** | Does not shrink the staking machine | Owner holds spend key offline | Not supported here (verify) |
| D | **True shim**: headers-only, own-wallet UTXOs, remote full node for chain data | Tens of MB: headers (~150 B x height) + wallet | Remote can lie about tip/modifier | Large: new crate |

**Cold staking (C):** makes the *owner* thin and offline, not the staker. It combines with A or D
but is not an answer by itself. I did not find cold-staking support in the staker; vault staking
(`create_vault_coinstake_tx`) is the nearest thing and should be reviewed before promising it.

**Shim (D) details.** What a stake attempt actually needs:
1. Tip header + its stake modifier. Divi's modifier chains forward from the previous modifier and
   the prior block's coinstake kernel, so a client can start from a trusted checkpoint modifier and
   follow forward with only recent blocks.
2. Difficulty (`nBits`) for the next block: needs recent headers.
3. Its **own** coin data (prevout hash/index, amount, block time): the wallet already knows these.
4. Submit the finished block to a peer or the remote node.
It does **not** need the global UTXO set or old bodies. Trust cost: a lying remote can feed a fake
tip, so the shim stakes on a fork and wastes attempts. It cannot spend the coins elsewhere (the
coinstake pays the wallet's own address), so the loss is missed rewards, not funds. Mitigations:
check header PoW/PoS linkage ourselves, ask 2+ remotes (fleet hp hosts), pin a checkpoint.
What breaks: cannot relay blocks or serve peers, cannot fully validate incoming blocks, reorg
handling is limited to the headers it holds, no mempool/fee estimation locally.

## 4. Recommendation

1. **Ship A now** as the supported "thin" mode: it needs no new consensus-sensitive code, is
   already merged, and keeps full validation. Add a `thin` convenience profile
   (`expire=0`, txindex/addressindex/spentindex off) and document real mainnet numbers.
2. **Then B** to remove the multi-day first sync, which is the real pain on a thin machine.
3. **D only if** A+B still leave Bert with a footprint he will not accept. It is a different
   product (a light client) with a different trust model and deserves its own review.

This keeps the thinnest *reliable* option first and avoids building a light client until the cheap
route is measured and found short.

## 5. Proposed config surface (A, with B later)

* `thin = true` / `--thin` / `IRONDIVI_THIN`: implies `expire=0`, indexes off. Explicit
  `--expire` still wins.
* Later: `--bootstrap-snapshot <url|file> --snapshot-sha256 <hash>`.
* `getstakingstatus` gains `pruned` and `pruneheight` so staking-while-pruned is observable.

## 6. Build and test plan (testnet only)

0. Measure per-column-family size on a mainnet-sized datadir (RocksDB property
   `rocksdb.estimate-live-data-size` per CF, read-only copy). Decide if A is thin enough.
1. Finish the live hp3 test: a coinstake block produced at `expire=0` with `pruned:true`.
2. Implement the `thin` profile + status fields + tests; verify restart and reorg inside the
   2,880-block floor on testnet.
3. Snapshot import (B): round-trip export/import on testnet, compare UTXO hash.
4. Only on a go-ahead: shim prototype against one fleet node, read-only first (follows tip, no
   submit), then testnet staking.
Hard limits: no mainnet, no deletes of chain data on live hosts, no deploys without Bert's go.
