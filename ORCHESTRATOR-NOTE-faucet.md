# Orchestrator note (2026-10-11 ~16:45 EDT): ZEC testnet funding

- fauzec.com paid 1 TAZ (txid 9cf8c2203229ef9577857439452c22b63ba0981b3419ba02dce98a05d7049814),
  but it was mined at height 4,474,361 on a chain whose tip is ~4,474,400 (75 s blocks):
  the pre-NU7 fork. testnet.zec.rocks (what swap-chain-zec uses) is at ~4,489,857 (25 s blocks,
  NU7 active since 4,465,026). The faucet's coins do not exist on the NU7 chain.
- So there are still no spendable TAZ on the chain we target. Live ZEC tests stay blocked on funding.
- Do not switch the crate to a pre-NU7 server; NU7 is the real testnet.
- Useful if you need it: record in status/zec.md that funding is the blocker (blocked-on-human),
  and keep working on anything that does not need coins.
