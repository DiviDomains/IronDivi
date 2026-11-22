# Swap spend scans: bounded passes and persisted cursors (H2)

Review finding S10. The ZEC compact-block scan and the BTC/LTC Esplora block-scan fallback
(an endpoint without `/tx/:id/outspend`) read at most `MAX_SCAN_BLOCKS` (200) blocks per
call. Before H2, `find_spend` returned `None` for "no spend in these 200 blocks" and every
engine read started again from the lock height (maker: from `maker_leg_scan_from`). A spend
mined more than 200 blocks after the lock was never seen. The worst case was a taker who
claimed the maker leg late: the maker never learned the preimage and could lose both legs.

## Contract

`ChainBackend::scan_spend(outpoint, from_height, resume) -> SpendScan` is one pass:

| Answer | Meaning |
| --- | --- |
| `Spent(info)` | a spend, with the same checks as `find_spend` |
| `NotYet { through: Some(mark), complete }` | no spend from `from_height` through `mark` (height and block hash); `complete` only if `mark` is the tip |
| `NotYet { through: None, complete: true }` | an index or full-range answer covering the whole chain (DIVI, EVM, mock, BTC/LTC outspend index) |
| `NotYet { through: None, complete: false }` | nothing usable was read (for example, an indexed spender is not served yet) |
| `Reorged` | the block at `resume` is no longer on the best chain, or the tip is below it |

The default implementation reports a missing spend as incomplete. Adapters that can
establish coverage report it explicitly. DIVI checks block identities, parent links,
transaction lists, mempool entries and the scan endpoint. EVM needs a funding receipt,
the lock event and usable responses to both spend-log queries to establish absence.

- ZEC counts only the run of consecutive heights the server returned. If it names a spender
  it cannot serve in full, the mark stops before that block.
- With quorum reads, BTC keeps the lower of the two endpoints' marks, or no mark when they
  read different blocks at the same height. A reorg seen by either endpoint is a reorg.
- LTC (`crosscheck_before_claim`) cross-checks a spend or a pass that reached the tip, as
  before. A pass that stopped short of the tip is not cross-checked, because the indexed
  source would report a later spend as a disagreement and hold every pass.

## Cursor

The engine's four spend reads go through `divi_swap::spend_cursor`:

- maker `revealed_preimage`
- maker `taker_leg_refund`
- taker `maker_leg_refunded`
- taker `taker_leg_lost`

When a corrected starting height precedes the saved coverage, the engine rescans from that height. Older cursors without coverage metadata also start fresh. Otherwise the read resumes at the saved mark's height, so the mark's block is read again and its hash
is checked in the same request. On `Reorged`, the read restarts from the lock in the same
call. A `None` from a read means "not seen yet": the funded-recovery paths (preimage
learning, refund after locktime) wait or refund as before. Holds (`hold::scan_spend`) apply
to each pass exactly as they applied to `find_spend`.

Cursors are JSON documents in the existing `docs` table:

- kind `spend_cursor`
- id `{maker|taker}/{maker_leg|taker_leg}/{swap_id}`
- fields: `outpoint`, `floor`, `through { height, hash }`, `complete`, `reorgs`

They are deleted when the swap reaches a terminal state. A cursor for another outpoint is
ignored. An unreadable cursor means a read from the lock; a failed write fails the step.

## Compatibility and rollback

- No table, column or `STORE_SCHEMA_VERSION` change; no quote, offer or amount change.
- A database without cursors (from an older binary) is read from the lock, as before.
- Rollback: run the previous binary. It never reads `spend_cursor` documents and scans from
  the lock exactly as before. Leftover rows are harmless. To remove them anyway:
  `DELETE FROM docs WHERE kind = 'spend_cursor';`

## Release-note text

> Swap spend watching on ZEC, and on BTC/LTC endpoints without an outspend index, now
> resumes where the last read stopped and survives restarts and shallow reorgs. A claim or
> refund mined more than 200 blocks after its lock is now seen. No database migration is
> needed, and downgrading is safe.

(`RELEASE-NOTES.md` is left to the release owner, to avoid conflicts with other lanes.)
