# Block-expiry pruning (`expire`)

A node can stake and validate without keeping the full chain. With `expire` set,
IronDivi discards block bodies and undo data older than a retention window.
The block index (all headers), the UTXO set, the tx index and the other indexes
are never touched, so the chainstate is always complete.

## Configuration

Three surfaces, standard precedence: **CLI flag > environment variable > conf file > default**.

| Surface | Name | Example |
|---|---|---|
| CLI flag | `--expire <value>` | `irondivid --expire 30d` |
| Environment | `IRONDIVI_EXPIRE` | `IRONDIVI_EXPIRE=30d` |
| Conf file (`irondivi.conf`) | `expire` | `expire = "30d"` |

Pass negative values with `=` or as the next argument (`--expire -1`, `--expire=-1` both work).
An invalid value from any surface is a startup error, not a warning.

## Value grammar

`<integer><unit>`, case-sensitive, lowercase, no spaces.

| Suffix | Meaning | Seconds |
|---|---|---|
| `s` | seconds | 1 |
| `m` | **minutes** | 60 |
| `h` | hours | 3600 |
| `d` | days | 86400 |
| `w` | weeks | 604800 |
| `mo` | **months** (fixed 30 days) | 2592000 |
| `y` | years (fixed 365 days) | 31536000 |

`m` is always minutes and months are always `mo`, so no letter means both.
A unitless number is accepted only as `-1` or `0`; any other bare number (e.g. `30`) is rejected
so it can never silently mean 30 seconds.

## Special values

* `-1` (default): never expire. Full chain is kept; pruning is disabled.
* `0`: keep the **minimum** needed to keep staking and validating: the most
  recent `MIN_BLOCKS_TO_KEEP` blocks (reorg safety floor) and nothing older.
  It is not an empty datadir: headers, UTXO set and indexes remain.
* `N<unit>`: keep blocks whose header time is within `[now - duration, now]`.

## Safety floor

Whatever the setting, bodies and undo data are never removed for the last
`MIN_BLOCKS_TO_KEEP` (2880 = about 2 days at 60 s) blocks. IronDivi, like C++
Divi, has no max-reorg-depth rule, so the floor is the practical reorg bound.
Pruning also never goes above the wallet's `last_scan_height`, so wallet state
cannot be lost to pruning.

## What is pruned and how

A `prune_height` watermark lives in the metadata column family. A pass deletes
`blocks` and `undo` entries for heights `watermark+1..=cutoff` (resolved through the
height mapping) in chunked batches and advances the watermark. A background task runs a pass once a minute, starting after the wallet catch-up scan at startup.

Deleting a body does not free its disk space until RocksDB compacts the column
family. A full compaction rewrites every retained body, so a pass does not run one
for each block it prunes. Two more metadata watermarks record how far the
compactions have caught up: `compacted_prune_height` for `blocks` and `undo`, and
`compacted_winners_strip_height` for `block_index`. A pass compacts a column family
once at least `EXPIRY_COMPACTION_DEBT` heights (= `MIN_BLOCKS_TO_KEEP`, 2880) are
owed. Then it advances that watermark, and it does so only after the compaction
returns.

* Steady state (about one block a minute): one compaction about every 2 days
  instead of one a minute. Until then the space held is at most what the floor's
  own bodies and undo data take, and RocksDB's background compaction often frees it
  earlier.
* Catch-up (`expire` enabled on a full datadir, or a long time offline): the first
  pass owes thousands of heights and compacts at once.
* Restarts: the owed heights are stored in the metadata column family, so a restart
  keeps them. A datadir pruned by an older release has no compacted watermark. Its
  first pass compacts once and records the watermark. Older releases ignore the
  keys.
* `--export-snapshot`: the export compacts `blocks`, `undo` and `block_index`
  unconditionally after its own pass and before it hashes any file, so a snapshot
  never ships deleted bodies, whatever its source owed.

## Behavior with pruned data

* Consensus: validation uses the UTXO set and block index only. Kernel lookup
  for blocks at or below `prune_height` is accepted from the index without a body check.
* `getblockheader` (verbose): works for every height (served from the block index). Raw hex (`verbose=false`) of a pruned version-4+ block is unavailable, because the index does not store the accumulator checkpoint; it returns the "pruned data" error.
* `getblock` for a pruned block: clean "Block not available (pruned data)" error.
* `getrawtransaction` / `gettransaction` for a transaction in a pruned block: "No such transaction" (as in Bitcoin Core pruning); transactions still in the mempool or in kept blocks work.
* `getblockchaininfo`: `"pruned": true`, `"pruneheight": N`.
* P2P: `getdata` for a pruned block is answered with `notfound`.
  The node still advertises `NODE_NETWORK` (peers that require it would refuse us).
* Wallet: no rescan below `pruneheight`. A catch-up scan that needs a missing block fails loudly.

## Limitations

* A pruned node cannot serve old blocks to peers, and cannot rescan history below `pruneheight`.
* Changing `expire` from a value back to `-1` does not restore deleted blocks; resync to get them.
* Side-chain (stale) block bodies are not pruned; only blocks on the active chain are.
* A wallet discovers its coins by scanning block bodies. Load the wallet and let it
  catch up **before** enabling `expire`: a wallet first loaded on an already-pruned
  node cannot see coins below `pruneheight`. Pruning never passes the wallet's scanned
  height (live blocks advance it), so enabling `expire` on a caught-up wallet is safe.
* IronDivi has no reindex; a pruned datadir can only be resynced from scratch.
