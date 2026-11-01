# Thin staking ("staking shim") — design

Goal: a machine that keeps staking coins but does **not** carry gigabytes of blockchain.
Testnet/stagenet only until Human signs off. Nothing here has been deployed.

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
3. **D only if** A+B still leave Human with a footprint he will not accept. It is a different
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
Hard limits: no mainnet, no deletes of chain data on live hosts, no deploys without Human's go.

## 7. Human's direction (2026-10-14): `--expire 30d` as a trust window

Human's idea: give `--expire 30d` and the node stops validating ancient history. It accepts the chain
the network gives it, as long as it holds 30 days of history that it can cross-check against other
nodes. This is option **E** and replaces "B then D" as the leading design.

How it would work:
1. **Start**: connect to k independent peers (default 4, incl. fleet hosts). Fetch headers, then a
   UTXO snapshot as of (tip − window). Accept the snapshot only if a majority of peers report the
   same snapshot hash and the same header at that height.
2. **Window**: from the snapshot forward, validate every block fully (consensus, kernel, UTXO),
   exactly as today. Bodies older than the window are expired (existing `expire` machinery).
3. **Stake**: unchanged. Needs only index + UTXO + wallet.
4. **Safety**: refuse to stake if fewer than k peers agree on the tip, or the tip is behind.

Honest limits to settle before building:
* Divi headers do not commit to the UTXO set, and PoS headers alone prove no work (the kernel
  needs the coinstake tx). So "proved against other nodes" means **agreement of peers**, not a
  cryptographic proof. A network-wide eclipse of the node could feed it a fake chain. Cost is missed
  or orphaned rewards, not stolen coins (a coinstake pays the wallet's own address).
* The P2P protocol has no snapshot message. Add one, or serve snapshots over HTTPS from the fleet
  (simpler, same trust model: hash cross-checked among peers).
* Reorgs deeper than the window cannot be handled; the existing 2,880-block floor stays.

Build order: (1) measure mainnet size split, (2) snapshot export/import on testnet, (3) multi-peer
agreement check, (4) `--expire <window>` + `--trust-peers` start path, (5) testnet staking proof.
No code written yet.

## 8. Measured: mainnet size split (2026-10-14, read-only)

Method: a small RocksDB tool opened the live `dnsdivi` mainnet node's `chainstate` as a **secondary
(read-only, no lock, no writes to the datadir)** and read `rocksdb.total-sst-files-size` and
`estimate-num-keys` per column family. Chain height about 3.83 M. Sizes are on-disk (compressed).

| Column family | Size | ~Keys | Pruned by `expire`? |
|---|---|---|---|
| `block_index` (headers + stake modifiers + index data) | **4,231 MB** | 3.83 M | No |
| `blocks` (bodies) | 2,678 MB | 4.10 M | **Yes** |
| `undo` | 762 MB | 4.26 M | **Yes** |
| `utxo` | 390 MB | 8.91 M | No (needed) |
| everything else (`metadata`, `masternodes`, `spent_index`, `default`) | ~0 | | |
| **chainstate total** | **8,061 MB** | | |
| `txindex` (separate DB) | 740 MB | | No (can be turned off) |
| `wallet` | ~10 MB | | No |

What this changes:
* `expire` removes only `blocks` + `undo` = **3.44 GB (43% of chainstate)**. A pruned mainnet datadir is
  about **5.0 GB** (4.6 GB chainstate + 740 MB txindex), or **4.6 GB** with `txindex` off. The thin
  floor today is therefore ~4.6 GB, not "tens of MB".
* The biggest single item is **`block_index`: 4.2 GB, about 1.1 KB per block**, more than the bodies. A
  bare Divi header is ~150 B, so there is roughly 7x of headroom. Cause not yet investigated (likely
  extra per-block fields or uncompressed/duplicated data). Slimming it is the largest remaining win and
  is independent of the trust-window question.
* The `utxo` set is small (390 MB), so a snapshot start (section 7) would move ~0.4 GB plus the
  headers it needs, not 8 GB.
* The 30-day window by itself does not change these numbers: bodies/undo for 30 days are only ~25 MB
  (3.44 GB / 3.8 M blocks x 43,200 blocks).

Revised recommendation order: (1) investigate and shrink `block_index` (read the serialization in
`divi-storage/src/block_index.rs`), (2) `thin` profile (expire + indexes off), (3) snapshot start.
Held for Human's pick of approach: snapshot export/import and any shim work.

## 9. Why `block_index` is ~1 KB per block (investigated 2026-10-14)

Method: read-only secondary open of the live mainnet `block_index` column family; iterated every
entry and parsed the serialization (`BlockIndex::to_bytes`, `divi-storage/src/block_index.rs`).
Correction to §8: the chain is at **4,258,903 blocks**, not 3.83 M (the RocksDB key count was an
estimate). The per-block cost is therefore ~990 B including the height->hash entry, not 1.1 KB.

Measured, per block (4.26 M entries):
* Value entry: 4,012 MB raw, **average 942 B**. Height->hash entry: 5-byte key, ~37 B (158 MB total).
* Fixed fields (hash, prev, merkle root, time, bits, nonce, accumulator, chain work, status, file
  position, stake modifier): **~210 B**. Every entry carries the 32 B accumulator.
* **`lottery_winners`: ~650-700 B per block, about 70% of the entry.** 4,252,366 of 4,258,903 entries
  (99.8%) hold the full list of 11 winner records, each a 32 B tx hash plus a payment script
  (~26 B). The list is copied forward into every block's index (`update_lottery_winners`,
  `chain.rs`), so it is stored 4.26 M times though it changes only when a stake qualifies.
* The data is poorly compressible (hashes), so on-disk size (4,231 MB) is close to the raw size.

Who needs old copies? `is_payment_script_vetoed_for_lottery` reads winners at only three heights,
one block before each of the last 3 lottery blocks (cycle 10,080 blocks), so everything older than
~30,240 blocks (~21 days) plus the 2,880-block reorg floor is dead weight. The staking path does not
read winners at all.

### Fix (built; see "Implementation and testnet result" below)
Extend the expire pass: for heights below `tip - max(window, 3*10,080 + 2,880)`, rewrite the
index entry with an empty winners list (decoder already accepts a zero count), then compact
`block_index`. Reversible in the sense that nothing consensus-relevant is lost; winners for old
blocks are never read. Saves about 650 B x ~4.2 M = **~2.7 GB**.
A new-node variant stores winners only as a per-block delta or only for recent blocks.

### Resulting mainnet footprint (estimate, to be confirmed on a testnet-sized run first)
| State | chainstate | + txindex | Total |
|---|---|---|---|
| Today (full) | 8.06 GB | 0.74 GB | 8.4 GB |
| `expire` only (bodies + undo gone) | 4.62 GB | 0.74 GB | ~5.4 GB (4.6 GB, index off) |
| `expire` + winner stripping | ~1.9 GB | 0.74 GB | ~2.6 GB (**~1.9 GB**, index off) |
Remaining after both: ~1.3 GB block_index (fixed fields) + 0.4 GB UTXO + ~0.2 GB height map.
Further option: drop `accumulator` (32 B/block, 140 MB) for old v4 blocks; small, skip for now.

### Implementation and testnet result
Built in `divi-storage` (`strip_lottery_winners_to`, `winners_strip_cutoff`), run from the expire
pass, and exposed as `winnersstripheight` in `getblockchaininfo`. Winners are kept for
`3*cycle + 1 + 2880` blocks below the tip, and the cutoff never exceeds the body-prune cutoff, so it
is inert unless `expire` is on. Only the lottery list is emptied; `height`, `hash` and every other
field are unchanged. Side-chain entries are untouched. Test: `test_prune_strips_old_lottery_winners_only`.

Live run (hp1, copy of an unpruned testnet datadir at tip 349,676, `--testnet --expire 0`):
* chainstate 970 MB -> 201 MB right after the pass -> **105 MB** after compaction settled. This
  figure is bodies + undo + winners together; the winners share was not isolated on testnet.
* `winnersstripheight` 345,743 -> 346,195 = tip - 3,481 (3*200 + 1 + 2,880), as designed, and it
  advances with the tip. Zero ERROR lines; a stop/restart came back clean at the same watermark.
* Testnet cycle is 200, so the keep window is 3,481 blocks. Mainnet (10,080) keeps 33,121 blocks.
Mainnet figures above remain estimates.

## 10. Thin staking nodes backed by full-history nodes (revised 2026-10-14)
Direction from Human: run one or more full nodes that keep all history, and make staking nodes thin.
The thin node still validates; the full node is a helper whose answers are checked, not a trusted oracle.

### Correction to the first draft of this section
The first draft said a stripped winners list could be rebuilt by replaying one lottery cycle of
blocks, and proposed a custom `NODE_FULL_HISTORY` service bit. Both were wrong:
* A winners list depends on the previous three cycles' lists (the payment-script veto), so one
  cycle of blocks is not enough to rebuild it.
* A rebuild is not needed. Consensus reads winners lists only at (a) the parent block, (b) height
  L-1 for each lottery height L, and (c) `lastLottery - cycle*k - 1` for k = 0..2, plus
  `start - 1` in the first cycle. Everything except the recent window is a "terminal" height
  (the block just before a lottery block). Terminal lists are now **never stripped** (about 420 lists,
  ~300 KB on mainnet), so forward validation never needs an old list. `Chain::is_winners_terminal_height`.
* Nodes that stripped with the earlier build (for example the hp1 test copy) had terminals removed;
  re-sync or import a snapshot made by the fixed build.

### What full-history peers are for
Serving old block bodies: `getblock` below `pruneheight`, wallet rescans, and a thin node that needs a
block it already pruned. The thin node checks every fetched block against its own header chain
(hash, merkle root) before using it; a lying peer can withhold a block but cannot make the thin
node accept a wrong one.

### Service flags (BIP 159)
`NODE_NETWORK` (bit 0) means "has every block". `NODE_NETWORK_LIMITED` (bit 10) means "pruned,
recent blocks only". A pruning node (`expire` on, or `pruneheight > 0`) now advertises only bit 10.
This fixed a live bug where pruned nodes claimed bit 0 and then answered `notfound`.
C++ divid peers set bit 0, so they count as full-history peers with no new bit.
Checked 2026-10-14: `getpeerinfo` on the hp3 testnet node showed every C++ peer (DIVI Core 3.0.0.0) with `services` 0x5 (bits 0 and 2), so none uses bit 10 and all count as full-history.
`PeerManager::full_history_peers()` lists peers with bit 0.

### Built (unit-tested; RPC `getblock` caller live-tested)
`divi-node/src/history_fetch.rs`: `HistoryFetcher::fetch_block(hash, merkle_root)` asks
`full_history_peers()` in turn, 20 s timeout each, accepts only a block whose hash and merkle root
match what our index says, and returns `NoFullPeers`/`NotAvailable` otherwise (never guesses). The node
message loop hands matching `Block`/`NotFound` replies to it before normal sync handling.
`Node::history_fetcher()` exposes it. Peers are added with `addnode`/`connect`, or with `--fullnode`
/ `fullnode=` (same as `addnode`, a named way to say "keep this full-history node connected"; the peer's
service flags, not the option, decide whether it counts as full).
RPC `getblock` for a height at or below `pruneheight` asks the fetcher (`BlockFetcher` trait in
`divi-rpc`, implemented by `HistoryFetcher`) and still returns the pruned-data error if no verified
block comes back.

### Work remaining
1. Done 2026-10-14: `rescanblockchain` fetches pruned blocks through the same path. It checks the first block of the range before clearing wallet data, so a rescan with no full peer is refused and the wallet is left alone. Live: hp1 rescanned heights 100-110 via hp3; with no peer it refused.
2. Prefer `NODE_NETWORK` peers when choosing sync peers.
3. Done: `getblockchaininfo` reports `fullhistorypeers` and `lastblockfetch` (live-checked), and a
   failed fetch logs a warning. No separate startup warning: peers are not connected at startup.
   Item 2 done: `order_retry_peers` puts full-history peers ahead of pruned ones (failed peers still last, announcer/assigned peer still first); unit-tested, not distinguishable live with a single peer.
4. Done 2026-10-14 on testnet: a snapshot-imported hp1 node (pruneheight 346,981) with
   `--connect` to the unstripped hp3 node returned block 100 over `getblock`; the same node with no
   reachable peer returned the pruned-data error (code -5). The fetched block's hex was byte-identical
   to the same `getblock` on hp3. A peer that sends bad data is unit-tested only. Note: if a full
   peer is connected but silent, `getblock` waits up to 20 s per full peer before returning the error.

### Trade-offs
* The network needs a few full nodes on purpose; if every operator goes thin, history is lost.
* An isolated thin node can still stake inside its kept window but cannot serve or rescan old blocks.

## 11. Chain-state snapshots (built 2026-10-14, testnet)
A new thin node can start from a downloaded chain-state snapshot instead of syncing from genesis.

### Format
A directory: `MANIFEST.json` plus `chainstate/`, a RocksDB checkpoint already thinned with
`Expire::Minimum` rules (old bodies and undo removed, old winners stripped, terminals kept). The
manifest has format, network, tip height and hash, prune/strip watermarks, every file's size and
SHA-256, and a `root_hash` over all of it. The root hash is the one value an operator compares or
publishes. The wallet and txindex are never included.

### Commands
* `irondivid --export-snapshot DIR` (node stopped; source untouched). Prints the root hash.
* `irondivid --import-snapshot DIR [--snapshot-root HEX]` installs into an empty or missing
  chainstate. Verifies the root hash and every file hash while copying into a temporary
  directory, opens it, checks the tip equals the manifest, records `snapshot_base`, then renames into
  place. Any failure leaves nothing behind. Undo = delete the chainstate directory.
* `getblockchaininfo.snapshotbase` shows `{height, hash}` of the imported tip.

### Trust model
Divi headers commit to no UTXO set, so the UTXO set in a snapshot is trusted, not proven. Only the
tip's place on the chain can be checked against other nodes. This matches the trust direction in §7.
All blocks after the snapshot tip are fully validated. The staker refuses to stake while the tip is at or below the
snapshot base, so the first staked block sits on at least one fully validated block. A wallet on a
snapshot-bootstrapped node has no history before the snapshot tip (the catch-up scan logs an error). Distribution is operator-driven (no P2P snapshot message);
publishing root hashes from several independent operators is how trust is built.

### Testnet result
Export from a copy of the hp3 `prune-base` chainstate (tip 349,861): 190 MB snapshot. Wrong
`--snapshot-root` refused; correct import succeeded; the imported node started with
`pruneheight 346981`, `winnersstripheight 346380`, `snapshotbase` = the tip. Unit tests cover roundtrip,
tampered file, wrong network, wrong hash and non-empty destination.
