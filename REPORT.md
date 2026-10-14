# Block-expiry pruning: report

User documentation: `docs/block-expiry-pruning.md`.

## Status

Built, tested, pushed. **Live staking at `expire=0` is DEFERRED, pending the 1Password broker.**
It is not demonstrated and must not be described as proven.

## Config

| Surface | Name |
|---|---|
| CLI | `--expire <value>` |
| Environment | `IRONDIVI_EXPIRE` |
| Conf file | `expire = "30d"` (or the integers `0` / `-1`) |

Precedence: CLI > env > conf > default. An invalid value is a startup error.

## Suffixes

`s` seconds, `m` minutes, `h` hours, `d` days, `w` weeks, `mo` months (30 d), `y` years (365 d).
Lowercase, case-sensitive. A bare number is valid only as `-1` or `0`.

## Values

* `-1` (default): never expire.
* `0`: keep the last 2880 blocks (about 2 days) of bodies and undo data, nothing older.
  Headers, UTXO set and indexes are always kept.
* `N<unit>`: keep a time window, never below the 2880-block floor or the wallet's scanned height.

## Evidence

* Tests pass on hp3 for divi-storage, divi-rpc, divi-node and irondivid; clippy clean.
* Throwaway testnet node at `expire=0`, genesis to tip (348,687): 0 kernel/ancestor errors, 0 ERROR lines,
  clean restart (`pruned:true`, `pruneheight` 345,807), kept following the tip.
* `getblock` on a pruned block: clean "pruned data" error. Verbose `getblockheader`: works at every height.
* Disk: chainstate 864M pruned vs 926M unpruned at the same height (about 7%). Testnet blocks are tiny;
  mainnet saving is unmeasured.
* Not run live: `getrawtransaction` on a pruned tx; the wallet-floor path (nodes ran `--disablewallet`; unit-tested only).

## Deferred: staking at `expire=0`

* **Why:** needs a fresh testnet wallet on hp3 funded with a few hundred tDIVI. Regtest cannot bootstrap
  (`generateblock` / `setgenerate` are not implemented). The only coin sources are the dnsdivi testnet
  node wallets (SSH to dnsdivi currently refused: the SSH key agent will not sign) and the hp2 swap
  wallet (excluded: its node leaks the recovery phrase in process args).
* **Decision (Bert):** wait for the 1Password broker, then finish in a later session.
* **To finish:** with the broker up, send about 200 tDIVI from a dnsdivi testnet node wallet to a fresh
  hp3 wallet, run it at `IRONDIVI_EXPIRE=0` once the wallet has caught up, wait for maturity, and confirm
  a coinstake block produced by that node (or staker attempts on matured UTXOs with 0 errors while
  `pruned:true`). Testnet difficulty is about 8,700, so a small balance may take a long time to win.
* **Supporting argument only (not proof):** the staker does no block-body reads and consensus uses only
  the UTXO set and block index.

## Limitations

* Raw `getblockheader <hash> false` on pruned v4+ blocks is unavailable.
* A pruned node still advertises `NODE_NETWORK` and answers `notfound` for old blocks.
* Side-chain bodies are not pruned. No reindex exists; a pruned datadir can only be resynced.
* Load the wallet and let it catch up before enabling `expire`.

## Commits

74ac0d8 feature, d484f14 docs, 8c77192 (does not compile), dcc35b8 (fixes 8c77192), 8e431c0 docs,
9f2a81b lint and doc cleanup.

## Leftovers

`~/prune-test` and `~/prune-base` on hp3 (about 2.2G) are stopped and safe to delete.
Production dnsdivi / hp1 / hp2 were never touched; expiry is not enabled anywhere real.

## NEEDS HUMAN
- ~~Monero STAGENET atomic swap, parked 2026-10-14 on `secret-broker serve`.~~ **Resolved
  2026-10-14:** Bert started the broker; the swap ran end to end on stagenet (0.01 sXMR → 50 tDIVI,
  outcome `redeemed`). Txids in `docs/plans/swap-poc/RESULTS.md`. Stagenet only; mainnet is a separate decision.
