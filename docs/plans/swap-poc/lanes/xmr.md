# Lane xmr — design + DIVI prerequisite

Read `_hp2.md` and `_common.md` first. You own `docs/plans/swap-poc/xmr-design.md`,
`docs/plans/swap-poc/status/xmr.md`, and **only the bare-txid fix** in `crates/divi-rpc/`
(minimal diff, with tests).

1. **Prerequisite.** `crates/divi-rpc/src/wallet.rs` (around line 1255) echoes the txid as
   `baretxid`. Work out what DIVI's C++ node returns for `baretxid` (the txid computed without
   signatures — check the Divi Core source if it is in this repo or vendored, else document the
   definition you rely on), implement it correctly, and add tests that pin the value for a
   signed transaction (txid ≠ baretxid). Adaptor-signature swaps need the bare txid to be stable
   under signing; explain in the design doc why.
2. **Design** `docs/plans/swap-poc/xmr-design.md`: a DIVI↔XMR adaptor-signature swap modelled on
   the COMIT / Farcaster BTC↔XMR protocol: roles, message flow, DIVI-side scripts (2-of-2
   + timelocked cancel/refund/punish paths — check which of these DIVI's script and tx rules
   allow, e.g. relative locktimes/CSV availability on DIVI, and SegWit absence), the
   cross-group DLEQ proof (ed25519 ↔ secp256k1), which Rust crates to use (pin candidates:
   `monero-serai`, `curve25519-dalek`, a DLEQ implementation) and their maturity, Monero
   stagenet infrastructure (public nodes, wallet RPC), failure cases, and a staged build plan
   with acceptance tests. End with `## Risks` and `## Recommendation`.

**Acceptance** (`tools/swap-poc/check-xmr.sh`): `divi-rpc` green; a test named
`baretxid_differs_from_txid_for_signed_tx`; design doc has the sections `## Protocol`,
`## DIVI scripts`, `## DLEQ`, `## Crates`, `## Stagenet`, `## Build plan`, `## Risks`,
`## Recommendation`.
