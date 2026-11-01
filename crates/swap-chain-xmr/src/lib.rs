// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI-side transaction building for the DIVI<->XMR adaptor-signature swap
//! (`docs/plans/swap-poc/xmr-design.md`): the `Tx_lock`/`Tx_cancel`-shaped 2-of-2 P2SH
//! output and presigned spends of it ([`multisig`], build-plan step 2), proving the
//! `nLockTime` schedule (not CSV/CLTV — see its docs) is enforced; and the bridge from a
//! `swap-adaptor` ECDSA adaptor signature into a DIVI scriptSig ([`adaptor_bridge`]),
//! proving a completed adaptor signature satisfies `OP_CHECKMULTISIG` exactly like a
//! plain one. The cross-group DLEQ lives in `swap-adaptor`. [`monero_key_share`] is the
//! Monero side's build-plan step 6: an additive 2-of-2 spend-key share bound to a
//! `swap-adaptor` DLEQ secret. [`monero_dkg`] (test-only) is a PedPoP/FROST reference
//! test only — not this swap's actual key-generation path, see [`monero_key_share`]'s
//! docs for why. [`swap_templates`] is build-plan step 7: the full
//! `Tx_redeem`/`Tx_refund`/`Tx_punish` set with the corrected signer/completer roles.
//! [`monero_sweep`] is the final step: spending the Monero 2-of-2 output once one party
//! holds the combined full private spend key. [`live_rpc`] is the shared RPC glue every
//! live example (`examples/xmr_live.rs`, `examples/xmr_live_refund.rs`) needs to talk to
//! a public restricted Monero node and the DIVI testnet proxy. [`timelocks`] is the
//! built-in `t_cancel`/`t_refund`/`t_punish` safety scheme the mainnet-readiness review
//! found missing: a safe default margin schedule plus an ordering validator.
//! [`monero_chain`] is the multichain lane's asked-for public live Monero API --
//! send/scan/sweep against a (spend pub, view secret) address, moved out of
//! `examples/xmr_live.rs` so `divi-swap-xmr`'s own `MoneroChain` implementation can
//! reuse it instead of reimplementing wallet-RPC digest auth and decoy selection.
//! [`divi_chain`] is the other half of that same `- needs:`: a live `DiviChain` body
//! reusing `swap-chain-divi`'s own `Wallet`/`FeePolicy`/broadcast-classification
//! machinery, generalized to fund an arbitrary script instead of only an HTLC's.

pub mod adaptor_bridge;
pub mod divi_chain;
pub mod live_rpc;
pub mod lock_scripts;
pub mod monero_chain;
pub mod monero_key_share;
pub mod monero_sweep;
pub mod multisig;
pub mod swap_templates;
pub mod timelocks;

#[cfg(test)]
mod happy_path_e2e;
#[cfg(test)]
mod monero_dkg;
#[cfg(test)]
mod refund_path_e2e;
#[cfg(test)]
mod role_swap_e2e;
#[cfg(test)]
mod stagenet_rpc;
#[cfg(test)]
mod tests;
