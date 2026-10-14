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
height mapping) in chunked batches, advances the watermark, and compacts those
column families so disk space is actually reclaimed. Passes run after connecting
blocks (at most once per 100 blocks) and once at startup after the wallet catch-up scan.

## Behavior with pruned data

* Consensus: validation uses the UTXO set and block index only. Kernel lookup
  for blocks at or below `prune_height` is accepted from the index without a body check.
* `getblockheader`: works for every height (served from the block index).
* `getblock` for a pruned block: clean "Block not available (pruned data)" error.
* `getrawtransaction` / `gettransaction` for a transaction in a pruned block: "No such transaction" (as in Bitcoin Core pruning); transactions still in the mempool or in kept blocks work.
* `getblockchaininfo`: `"pruned": true`, `"pruneheight": N`.
* P2P: `getdata` for a pruned block is answered with `notfound`.
  The node still advertises `NODE_NETWORK` (peers that require it would refuse us).
* Wallet: no rescan below `pruneheight`. A catch-up scan that needs a missing block fails loudly.

## Limitations

* A pruned node cannot serve old blocks to peers, and cannot rescan history below `pruneheight`.
* Changing `expire` from a value back to `-1` does not restore deleted blocks; resync to get them.
