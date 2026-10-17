## RESTART NOTE (refreshed 2026-10-17 ~10:00 EDT) — XMR enablement task (spec: orchestrator `specs/xmr-addition.md`)

**Task (Bert):** add XMR to the Divi AtomicSwap effort. IronDivi is Tier 1 (adaptor engine + XMR backend present): VERIFY & ENABLE only; no HTLC port; no mainnet, no spend, no deploy; seed never touched.

**Done and verified**
- XMR registered at every coin-set point (checked in source): `Chain::Xmr` + `Chain::ALL` (`crates/divi-swap/src/types.rs`), `ChainParams::builtin` `Chain::Xmr => (10, 1800)` (`crates/divi-swap/src/config.rs:59`), `[xmr]` `XmrSection` + `serves()` + `xmr_engine_needed` (`bin/divi-swapd/src/config.rs`), CLI `--counter-chain xmr` with `--xmr-*` flags (`bin/divi-swap/src/main.rs`), mock offer `divi-xmr-stagenet`.
- Rate-table gap closed (`a6ae46e`, fmt `9e599a5`, pushed): the mock price match had `_ =>` (ZEC's price) so any unlisted coin inherited it. Now `mock_divi_per_coin(Chain)` is an exhaustive const match (Divi, Btc, Ltc, Zec, Usdc, Xmr) used by `mock_counter_offers`, `mock_xmr_offers` and the BTC offers; test `every_chain_has_its_own_mock_rate`. Placeholder prices only (XMR 5,000 DIVI, USDC 100 DIVI, rest unchanged). hp3: `divi-swapd` + `divi-swap` tests all pass, clippy clean, rustfmt applied.
- Offline refund AND punish on this HEAD (hp3): `crates/divi-swap-xmr` engine tests 13/13 (`taker_walks_away_after_locking_xmr_both_refund`, `taker_never_locks_xmr_maker_refunds`, `maker_stalls_after_xmr_lock_taker_punishes`, `a_re_encoded_tx_cancel_still_refunds_and_reveals_s_m`, ...); `divi-swapd` `e2e_xmr` 3/3 (`e2e_mock_xmr_refund`).
- hp2 `~/swap-lanes/xmr` fast-forwarded 220dcb0 -> 9e599a5 (hp2's `origin` is the local bare `~/swap-lanes/IronDivi.git`, which I pushed to). Its uncommitted work (status/xmr.md section + `xmr_live_final.rs`) was kept via stash, pop, and a manual both-sides merge; `stash@{0}` (`pre-ff-xmr-lane`) is still there as a backup.

**NOT done: live stagenet re-run of refund + punish against the shared stagenet address (`59DDm3zb...Q9wP5AF`, item `divi_xmr_swap_stagenet`).** Reason: `secret get` of the taker's wallet-rpc credential returned nothing on 2026-10-17 (the broker has 5 queued 1Password calls from another session waiting for a human), so a live taker cannot start. That is a pause, not a bug; nothing was bypassed. Evidence that stands in the meantime: `git diff 5481207 HEAD` over `divi-swap-xmr`, `swap-adaptor`, `swap-chain-xmr`, `swap-chain-divi`, `bin/divi-swap` is empty, so the engine is byte-identical to the build that passed refund (tests 2-3) and punish (test 4) live on stagenet 2026-10-16. Do not describe the live re-run as repeated.

**Resume (when Bert approves the 1Password dialog / broker is clear):**
1. `secret-broker status`; a `secret get --name taker-xmr-wallet-rpc-username --op-ref "op://global_secret_store/IronDivi Swap POC - taker-xmr-wallet-rpc/username"` must print a value (never echo it).
2. Tunnels (Mac): maker API 18482 is up; also `ssh -N -L 38088:127.0.0.1:38088 hp2`.
3. Refund: `tools/swap-poc/xmr-soak.sh --taker-bin ~/.cache/divi-swap-c1-5481207/<bin> --scenario lock-only --count 1 --out DIR`, wait past `t_cancel`, then `--resume DIR`. Set `XMR_TAKER_SWEEP=59DDm3zbhM1FVcWo9PJJJEZaTv79jH4sD2vsoQrjiChDY1HCwnLuJjr9NKMWFGk1FwQnfMc1GHyQfeMwA3cMR5z1Q9wP5AF` so refunds sweep to the shared address (public address only; no seed needed).
4. Punish: private hp2 maker, `tools/swap-poc/c1-punish-step.sh` (about 4 h). Never touch the dnsdivi maker or deploy.
5. Record txids here and in `docs/plans/swap-poc/RESULTS.md`; then ready.

**Parked NEEDS HUMAN:** the 1Password approval above; the older items below (snapshot channel, mainnet decision, usdc-lane transcript, hp1/hp3 cleanup). Mainnet stays off.

**Thin-staking test (unrelated, still running on hp3):** pruned node `~/prune-test`, recorder heartbeats alive through 2026-10-17 12:50Z, no win yet. Its older restart note follows unchanged.

---

## Earlier restart note: thin staking (refreshed 2026-10-16 ~14:30 EDT, for a fresh session; uncommitted on purpose)

**What I was doing:** Thin staking (helpers + snapshot, testnet only). All code is done, committed and pushed (origin/main `2f23118` for `--fullnode`, `96fc6d3` for this report's checklist). The only open engineering item is proving a *pruned* node wins a stake.

**Done and verified:** see "Thin staking: acceptance checklist" below. Built and live-tested on testnet: winner stripping, snapshot export/import plus staking gate, `HistoryFetcher` used by `getblock` and `rescanblockchain`, full-history peer preference in sync (unit test only), `--fullnode`/`fullnode=` (unit test, clippy, fmt on hp1).

**IN FLIGHT right now (all on hp3, none depend on this session):**
1. Pruned stake test: node `irondivid --testnet --datadir /home/bshuler/prune-test` (`IRONDIVI_EXPIRE=0`, binary `~/bin/irondivid`, ~105k tDIVI, "Staking Active"), started ~2026-10-16 16:25Z. Expect about one win per day.
2. Recorder `~/prune-test/recorder.sh` (nohup setsid): hourly heartbeat plus win capture into `~/prune-test/stake-wins.log`. Only the 16:50Z heartbeat was seen at last check (next due 17:50Z).
3. `prune-base` node (`~/prune-base`, port 52497) from `~/bin/irondivid`: the reference chain view for confirming a win.
4. **Monitor `bogxd9lat` (latest; earlier ones `bmfxrcrbv`, `b4hl77ivh` expired; Mac side, dies with the session, expires every 30 min). Re-arm with** Monitor, timeout_ms 1800000, command:
   `ssh -o ServerAliveInterval=30 hp3 'tail -n0 -F ~/prune-test/stake-wins.log' 2>&1 | grep -E --line-buffered "MATCH|DEAD|Connection|closed"`
   Do NOT add `| cut` (it block-buffers and swallows the one event you need). Each re-arm loses the gap, so also read `ssh hp3 'tail -20 ~/prune-test/stake-wins.log'` on resume.

**How a fresh session resumes:**
1. `ssh hp3 'tail -20 ~/prune-test/stake-wins.log; pgrep -af "irondivid --testnet"; pgrep -af recorder.sh'`. If prune-test is DEAD, restart with `IRONDIVI_EXPIRE=0 nohup setsid ~/bin/irondivid --testnet --datadir /home/bshuler/prune-test --printtoconsole >> ~/prune-test/node.log 2>&1 < /dev/null &` (script pattern: `~/stake1.sh`); if the recorder is gone, `cd ~/prune-test && nohup setsid ./recorder.sh > recorder.out 2>&1 < /dev/null &`.
2. Re-arm the Monitor above.
3. If `stake-wins.log` has a MATCH, check the acceptance criteria in the checklist: `pruned:true` at that time, the coinstake block hash present on `prune-base` with 6+ confirmations, and the coinstake input belongs to the prune-test wallet. Only then tick the item and update the "Staking at expire=0" section.
4. No win after several days: the one real question for Bert is whether to fund more tDIVI to shorten the wait.
5. Build/test rules: never compile on the Mac; scripts via the Write tool, scp, `ssh hpN 'bash script'`; sync with `rsync -rlpc`. Push with `PATH=/opt/homebrew/bin:$PATH git push origin main`; commit as Bert Shuler, no AI attribution.

**Parked NEEDS HUMAN:** snapshot distribution channel and root-hash publisher; who runs full-history nodes; mainnet decision; delete or redact the recovery phrase copy in the usdc lane's transcript on hp2; cleanup of `hp1:~/thin` and the temporary hp3 binary only on Bert's written go-ahead (never touch hp3 `~/prune-test` data).

**Uncommitted work:** none in the repo apart from this note. I did not commit, push or run anything touching 1Password.

---

# Block-expiry pruning: report

User documentation: `docs/block-expiry-pruning.md`.

## Status

Built, tested, pushed. **Live staking at `expire=0` is NOT yet demonstrated:** attempts run clean, no stake was won in about 7 hours
(expected at this weight). Do not describe it as proven.

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

## Staking at `expire=0`: attempts verified, no stake won (not proven)

* (First run; the wallet now shows about 105,000 tDIVI staking balance on restart 2026-10-16, so the current run is weaker than this one.) Broker came up; a fresh hp3 testnet wallet was funded with 205,000 tDIVI (3 UTXOs) from a testnet wallet
  (the hp2 swap wallet was not used). The node ran at `IRONDIVI_EXPIRE=0` and was `pruned:true`
  (`pruneheight` 346,883 at block 349,763) with `getstakingstatus` = "Staking Active".
* About 7 hours, 1,440+ staking attempts hashing all matured UTXOs: 0 setup failures, 0 errors, 0 modifier
  mismatches. **Zero stakes won.** The staker log summary hard-codes "0 success"; the real markers are
  "Hashproof SUCCESS" / "Found valid stake", and none appeared.
* Control: an unpruned wallet node with 100,000 tDIVI ran about 3 hours, also with zero wins.
* Why zero is expected: testnet difficulty is about 8,033, so network stake weight is about
  d*2^20/60, roughly 140M tDIVI. 205k is about 0.15% of that, or about 0.3 expected wins per 3 hours
  and under 1 over the whole run. A win needs days of runtime. The test is statistically too weak to
  show either success or failure.
* So: the staker runs correctly on a pruned node and nothing points at a pruning problem, but **a staked
  block from a pruned node has not been observed.** Supporting argument only: the staker does no
  block-body reads and consensus uses only the UTXO set and block index.
* To close it: leave a pruned wallet node running for days (or hold far more testnet coins) until it
  stakes, then confirm the coinstake block.

## Limitations

* Raw `getblockheader <hash> false` on pruned v4+ blocks is unavailable.
* A pruned node still advertises `NODE_NETWORK` and answers `notfound` for old blocks.
* Side-chain bodies are not pruned. No reindex exists; a pruned datadir can only be resynced.
* Load the wallet and let it catch up before enabling `expire`.

## Commits

74ac0d8 feature, d484f14 docs, 8c77192 (does not compile), dcc35b8 (fixes 8c77192), 8e431c0 docs,
9f2a81b lint and doc cleanup.

## Leftovers

`~/prune-test` and `~/prune-base` on hp3 (about 2.2G) are stopped and safe to delete (the pruned wallet holds the testnet coins; keep them).
Production dnsdivi / hp1 / hp2 were never touched; expiry is not enabled anywhere real.

## NEEDS HUMAN
- ~~Monero STAGENET atomic swap, parked 2026-10-14 on `secret-broker serve`.~~ **Resolved
  2026-10-14:** Bert started the broker; the swap ran end to end on stagenet (0.01 sXMR → 50 tDIVI,
  outcome `redeemed`). Txids in `docs/plans/swap-poc/RESULTS.md`. Stagenet only; mainnet is a separate decision.
- XMR swap C1 (cancel ransom): **full fix built and deployed to the stagenet maker** (Bert: option 3). dnsdivi runs `1841a12` since 2026-10-15 16:29Z. §7 tests: 5a/5b/7 PASS on a private Divi regtest, 1 (5/5 happy swaps redeemed), 2-3 (all 4 timed-out swaps cancelled and refunded, both lock-only takers got their XMR back) 4 (punish: a silent maker loses the DIVI to the taker, 2026-10-15 23:17Z) and 6 PASS live. **All §7 tests pass.** The soak found and fixed a maker stall (a77ec9d) and the C8 panic (1841a12). It also found that high-S signatures relay on Divi, so any node can malleate. Details: `docs/plans/swap-poc/status/xmr.md` "C1 full fix on stagenet". **Ruling 2026-10-15: you reviewed `xmr-c1-design.md` and chose option A, the full fix** (interim hardening first, Lindell-2017 2P-ECDSA for J, exhaustive presign over all 120 staker variants). Gap analysis and closure: `xmr-c1-design.md` §9. Only real gap was J (cggmp21). **Closed in code:** J is now Lindell-2017, built on the audited primitives cggmp21 already uses (paillier-zk, fast-paillier), with the taker generating the proof parameters and a wide mask. Both are mandatory fixes. ZenGo `multi-party-ecdsa` was dropped: its proof is unsound and it no longer compiles. All unit tests pass. **Deployed** to the stagenet maker 2026-10-16 03:13Z (sha `8391f72f…`); the §7 rerun on this build **passes**: test 1 (5/5 redeemed), 2-3 (4/4 refunded via `J`, both lock-only takers swept their XMR back), 4 (punish: Tx_punish `ced1572d…` paid the taker 2026-10-16 12:22Z, no refund) and 6. **The new build passes stagenet.** Mainnet is still off (allow_mainnet off, no Phase D/B4) until you say go. I treated the interim step as covered by the full build (its punish branch is live; the signature it withheld no longer exists). Say so if you want it built separately. The 120-variant presign is complete. **Mainnet stayed blocked until the new build passed stagenet; it now has, and mainnet stays off until your explicit go.** The hp2 root `divid` mnemonic fix is done (next bullet).
- hp2 recovery phrase (Bert-approved): **fixed 2026-10-16.** `divi-testnet-node2` now reads it from a root-only 0600 `divi.conf`; `ps`, cmdline, environ and `docker inspect` show 0 matches; wallet addresses and balance unchanged; no rotation; about 6 min downtime. No reuse with real value found (all hp2 divid are testnet/regtest). **Needs a decision:** a copy sits in the usdc lane's Claude transcript on hp2 (path in `docs/plans/swap-poc/status/xmr.md`); delete or redact it?

## Thin staking: helpers + snapshot (2026-10-14)
Built on testnet: pruned nodes advertise `NODE_NETWORK_LIMITED` only (live bug fix); terminal lottery-winner
lists are never stripped; snapshot export/import (`--export-snapshot`, `--import-snapshot`, `snapshotbase` in
getblockchaininfo), live-tested hp3 copy -> hp1. Design doc §10 corrected, §11 added. `HistoryFetcher` (fetch + verify a pruned block from a full-history peer) built, unit-tested, and called from RPC `getblock` below `pruneheight` (live: hp1 fetched block 100 from hp3, byte-identical; refused with the peer gone; a silent full peer makes getblock wait up to 20 s per peer); not yet called from wallet rescan; no separate `fullnode=` option (use `addnode`). Live: snapshot-imported hp1 node synced forward past the snapshot tip and pruned cleanly. Earlier stripped test copies predate the terminals fix.

## Thin staking design (2026-10-14)
Design doc: `docs/plans/thin-staking.md`. Recommendation: ship pruned staking (`expire=0`) as the
thin mode, add snapshot bootstrap, build a true remote-node shim only if still needed.
Mainnet CF split measured (doc §8). Lottery-winner stripping built and validated on testnet (hp1 copy,
970 MB -> 105 MB with expire 0; clean restart, 0 errors). Not deployed anywhere real. ELI5 page published as an Artifact.
## NEEDS HUMAN
* Snapshot distribution channel: where do operators download snapshots, and do you want root hashes published (and by whom)?
* Who runs the full-history (`NODE_NETWORK`) nodes, so thin nodes have something to fetch from?
* Mainnet decision on `expire` + snapshots (everything so far is testnet only).

## Thin staking: status notes (2026-10-14)
* Snapshot staking gate built: a snapshot-imported node does not stake until its tip is past the snapshot base (live-checked on hp1).
* `--fullnode` / `fullnode=` added 2026-10-16 as a static-peer alias; the `NODE_NETWORK` service flag still decides which peers count as full.
* `HistoryFetcher` is used by RPC `getblock` and live-tested on testnet; `getblockchaininfo` now shows `fullhistorypeers` and `lastblockfetch`; `rescanblockchain` uses the fetch (live-tested, refuses without wiping the wallet when no full peer); sync peer choice prefers full-history peers (unit-tested). Doc §10 work list is complete. Note: the hp3 prune-base node now runs from `~/bin/irondivid` (the old build dir was gone).
* A wallet on a snapshot-bootstrapped node has no history before the snapshot tip.

## Thin staking: acceptance checklist (reconciled against the brief, 2026-10-16)
Status is only [x] with evidence. Anything open is either running or under NEEDS HUMAN.
- [x] How IronDivi stakes today + disk footprint (doc §1–§3)
- [x] Options with trade-offs and a recommendation (doc §4–§7)
- [x] Design doc in repo (`docs/plans/thin-staking.md`)
- [x] Bert asked which approach to build; chose helpers + snapshot
- [x] Mainnet size split measured (doc §8, read-only)
- [x] Winner stripping on testnet (970 MB -> 105 MB), ELI5 artifact
- [x] Full-node helpers: `getblock`, rescan, sync-peer preference (live-tested except peer preference: unit test only)
- [x] Snapshot export/import + staking gate (live hp3 -> hp1)
- [ ] **Pruned node wins a stake** — RUNNING since 2026-10-16 ~16:25Z on hp3 `~/prune-test` (expire=0, ~105k tDIVI, Staking Active). Expected about one win per day (105k of ~140M weight), so days, not hours.
  * Recorder on hp3 (`~/prune-test/recorder.sh`, nohup setsid): appends hourly heartbeats (node alive/DEAD) and, on a stake marker, the log line plus `pruned`/`pruneheight`/best hash to `~/prune-test/stake-wins.log`.
  * **Acceptance for "proven":** (a) `stake-wins.log` shows the marker with `pruned:true` and `pruneheight` > 0; (b) the coinstake block hash is in the main chain as seen by a different process (hp3 `prune-base`), with 6+ confirmations; (c) the block's coinstake input belongs to the prune-test wallet. Until all three hold, this stays open.
- [x] `--fullnode` / `fullnode=` option (static peer; unit-tested on hp1, clippy + fmt clean)
- [x] Bad-data peer and full-peer preference: unit-tested only, by decision. A live bad-data test needs a hostile peer we would have to build, and the testnet cannot show peer preference. Said plainly, not claimed live.
- [ ] Cleanup of hp1 `~/thin` and the temporary hp3 binary (only on Bert's say-so)
- [ ] NEEDS HUMAN: snapshot distribution, who runs full nodes, mainnet decision
