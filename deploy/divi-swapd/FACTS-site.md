# FACTS: third-party claims on the IronDivi Swaps website

One row per published fact about a product we do not control. "Could not verify" is a verdict; "assumed" is not.

| claim | verdict | source | what the page now says |
|---|---|---|---|
| Free DIVI test coins are available from `https://services.divi.domains/testnet/faucet` | URL verified 2026-10-22: `curl -IL` gives 301 to `/testnet/faucet/` then 200. Whether the faucet hands out coins right now: could not verify (not tried; the lane has no wallet) | the spec, `docs/plans/atomic-swap-poc.md` section 9; `curl -IL https://services.divi.domains/testnet/faucet` | "Free DIVI test coins: <faucet link>" (how-to-swap and faq). The page does not promise an amount or availability. |
| Test networks named: Bitcoin signet, Litecoin testnet, Zcash testnet, Monero stagenet | taken from this repo's own configs and live offers (`divi-btc-testnet`, `ltc-divi-testnet`, `divi-zec-testnet`, `divi-xmr-stagenet`), not from a third party; no faucet for them is named or linked | `crates/divi-swap/src/config.rs`, live `https://divi.cx/swap/offers` 2026-10-22 | "you need test coins on that chain too"; no link given |
