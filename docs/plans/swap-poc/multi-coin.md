# Multi-coin swaps — master plan

Follow-on to `docs/plans/atomic-swap-poc.md` §7. DIVI↔BTC is done both ways on testnet
(`RESULTS.md`). This plan adds the other coins **in parallel**, one lane per coin.

## Where the work runs

- **Lanes run on hp2** (32 cores, 94 GB), not the Mac. Each lane is a Claude session on hp2,
  visible as an Avada pane on the Mac (the pane is just `ssh -t hp2 …`, so the laptop does no
  building or model work). Lanes build and test with plain `cargo` on hp2.
- Lane checkouts: `hp2:~/swap-lanes/<coin>`, cloned from the mirror `hp2:~/swap-lanes/IronDivi.git`
  (the orchestrator pushes `main` there after every landing).
- **Lanes never commit.** Signing needs 1Password, which only the Mac has. A lane marks a seam
  ready with `- ready_to_land: <one-line commit subject>` in its status file; the orchestrator
  runs `tools/swap-poc/hp2-land.sh <coin>`, which copies the lane's diff to the Mac, commits it
  signed, pushes GitHub and the mirror. The lane then runs `tools/swap-poc/lane-sync.sh` to
  pick up `main`.
- **No secrets on hp2.** Lanes build and prove everything on mocks, public testnet APIs
  (read-only), and throwaway keys. Live runs with funded keys are the orchestrator's, on the Mac,
  through `secret get`.

## Waves

| # | What | Who | Done when |
|---|------|-----|-----------|
| 0 | This plan; crate scaffolds (`swap-chain-ltc`, `swap-chain-zec`, `swap-chain-evm`); lane briefs + check scripts; hp2 mirror and lane checkouts | orchestrator | committed on `main` |
| 1a | **LTC** backend: `swap-chain-ltc`, P2WSH HTLC over litecoinspace Esplora (testnet) | lane `ltc` | `check-ltc.sh` |
| 1b | **ZEC** backend: transparent P2SH HTLC, v5 tx + ZIP-244 sighash; step 0 is the API feasibility check | lane `zec` | `check-zec.sh` |
| 1c | **USDC**: Solidity HTLC (Sepolia / Base Sepolia) + Rust client in `swap-chain-evm`, plus a written proposal for fitting account chains into the engine | lane `usdc` | `check-usdc.sh` |
| 1d | **XMR**: adaptor-signature swap design + the DIVI bare-txid fix it depends on | lane `xmr` | `check-xmr.sh` |
| 1e | **Engine generalization**: DIVI ↔ any counter chain (`Chain::{Ltc,Zec,Usdc}`, counter chain on the offer, per-chain confirmations/timeouts); old persisted state still loads | orchestrator | `divi-swap` green, mock e2e for each new chain |
| 2 | Wire each backend into `divi-swapd` / `divi-swap` (offers `ltc-divi-testnet`, `zec-divi-testnet`); mock e2e per coin, both directions | lanes + orchestrator | `e2e.sh --backend mock` per offer |
| 3 | **Live** per coin, serial (timelocks set the wall clock): happy, case C, case D, both directions; txids verified on explorers | orchestrator (Mac, 1Password) | `RESULTS.md` sections, artifact updated |
| 4 | Redeploy the dnsdivi maker with the new offers (after the BTC reverse chaos finishes) | orchestrator | health + offers on dnsdivi |

Waves 1a–1e run at the same time. Wave 2 for a coin starts when its 1x and 1e are both landed.

## Honest scope per coin

- **LTC** — same script and SegWit shapes as BTC; low risk. Live needs tLTC.
- **ZEC** — transparent HTLCs are standard Bitcoin script, but Zcash transactions are v5 with
  ZIP-244 signature hashing, and the testnet API surface (raw tx, broadcast, block scan) has to
  be proven first. Medium risk. Live needs testnet ZEC (TAZ).
- **USDC** — account-based: no UTXOs, the HTLC is a contract call, the preimage is read from an
  event. It does not fit `ChainBackend` as is (`Outpoint`, block-scanning `find_spend`). Wave 1c
  delivers the contract, its tests, a client, and a proposal (map onto the trait, or a second
  trait); the orchestrator decides before wave 2. Live needs Sepolia ETH (gas) + test USDC.
- **XMR** — no scripts on Monero; needs an adaptor-signature protocol (the COMIT/Farcaster
  design) with DLEQ proofs across ed25519/secp256k1. This wave produces the design and the DIVI
  prerequisite fix, not a live swap. Live XMR is a later plan.

## Keys and coins

- New 1Password items, one per role, created from the Mac when a coin reaches wave 3 (the vault
  write needs a human dialog; batched, one item per coin holding all its keys).
- Each coin gets its **own DIVI maker/taker keys** so live runs for different coins never fight
  over the same DIVI coins, and never collide with the BTC keys.
- Testnet coins are kept, never swept back.

## Status

Per lane: `docs/plans/swap-poc/status/<coin>.md`. Orchestrator: `status/orchestrator.md`,
section "Multi-coin".
