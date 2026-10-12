// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! `UsdcBackend`: [`divi_swap::ChainBackend`] over [`crate::EvmHtlcClient`] (Option A of
//! `docs/plans/swap-poc/usdc-design.md`).
//!
//! Shape decisions (see the design doc for the full reasoning):
//! - `Outpoint` = `{ txid: lock tx hash, vout: 0 }`. The swap id is never recomputed from
//!   `vout`; it is always read back from the `Locked` log of the funding tx.
//! - `build_funding` ensures the ERC-20 allowance eagerly (broadcasting an `approve` and
//!   waiting for it, outside the write-ahead path) and returns only the `lock` call as the
//!   signed-not-broadcast `Funding`.
//! - `build_claim`/`build_refund` sign locally without touching the network: they fetch a
//!   nonce and fee estimate, build and sign a [`alloy::consensus::TxEnvelope`] with this
//!   backend's wallet, and return its RLP bytes. `broadcast` is the only method that sends
//!   anything.
//! - A `Claimed` log's preimage rides in `SpendInfo.witness` as a single 32-byte item;
//!   `SpendInfo::extract_preimage` finds it unmodified.
//! - The engine's `Amount` is always "1e8 per coin"; USDC has 6 decimals, so the conversion
//!   factor is exactly 100. An amount that is not a whole multiple of 100 cannot be
//!   represented on chain and is rejected rather than rounded (rounding would make the
//!   on-chain lock smaller than the counterparty's quoted amount and read as "underfunded").

use alloy::eips::{BlockNumberOrTag, Encodable2718};
use alloy::network::{EthereumWallet, NetworkTransactionBuilder, TransactionBuilder};
use alloy::primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use secp256k1::{PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey};

use divi_swap::api::Direction;
use divi_swap::{
    Amount, Chain, ChainBackend, Funding, HtlcParams, LockedOutput, Outpoint, SignedTx, SpendInfo,
    SwapError, Txid,
};

use crate::client::{connect_provider, swap_id, EvmHtlcClient};
use crate::contract::{IErc20, IErc20Htlc};

type Result<T> = std::result::Result<T, SwapError>;

/// Engine "sats" (1e8 per coin) per USDC base unit (1e6 per coin): `1e8 / 1e6`.
const ENGINE_PER_USDC_UNIT: u64 = 100;

/// Convert an engine [`Amount`] to USDC base units. Fails if `amount` is not a whole
/// multiple of [`ENGINE_PER_USDC_UNIT`] — USDC's 6 decimals cannot represent the remainder,
/// and silently rounding would lock less than a counterparty's quote expects.
pub fn amount_to_usdc_units(amount: Amount) -> Result<U256> {
    if !amount.to_sat().is_multiple_of(ENGINE_PER_USDC_UNIT) {
        return Err(SwapError::InvalidParams(format!(
            "{amount} is not a whole number of USDC base units (engine sats must be a \
             multiple of {ENGINE_PER_USDC_UNIT})"
        )));
    }
    Ok(U256::from(amount.to_sat() / ENGINE_PER_USDC_UNIT))
}

/// Convert USDC base units back to an engine [`Amount`]. Fails only on overflow.
pub fn usdc_units_to_amount(units: U256) -> Result<Amount> {
    let units: u64 = units
        .try_into()
        .map_err(|_| SwapError::Other("USDC amount exceeds u64 base units".into()))?;
    units
        .checked_mul(ENGINE_PER_USDC_UNIT)
        .map(Amount::from_sat)
        .ok_or_else(|| SwapError::Other("USDC amount overflows engine sats".into()))
}

/// Whether a maker holding `eth_wei`/`usdc_units` can actually serve an offer trading
/// `direction`, regardless of the offer's own `enabled` flag: below either floor, the maker
/// would accept a swap it cannot lock or claim, stranding the taker until a refund.
/// `divi-usdc-sepolia`-shaped offers (maker sells DIVI it already holds, `taker_pays_btc`)
/// only need gas to claim the taker's USDC lock; `usdc-divi-sepolia`-shaped ones (maker
/// sells USDC, `taker_pays_divi`) need USDC collateral too. Pure — no network — so it is
/// unit-testable without anvil; `UsdcBackend::gas_and_token_balance` is the only part of
/// this check that actually touches a chain.
pub fn usdc_offer_is_fundable(
    direction: Direction,
    eth_wei: U256,
    usdc_units: U256,
    min_eth_wei: u128,
    min_usdc_units: u64,
) -> bool {
    let has_gas = eth_wei >= U256::from(min_eth_wei);
    match direction {
        Direction::TakerPaysBtc => has_gas,
        Direction::TakerPaysDivi => has_gas && usdc_units >= U256::from(min_usdc_units),
    }
}

/// The Ethereum address a compressed secp256k1 pubkey signs from.
fn eth_address_from_pubkey(pubkey: &[u8; 33]) -> Result<Address> {
    let pk = Secp256k1PublicKey::from_slice(pubkey)
        .map_err(|e| SwapError::InvalidParams(format!("bad pubkey: {e}")))?;
    let uncompressed = pk.serialize_uncompressed();
    let hash = keccak256(&uncompressed[1..]); // drop the 0x04 prefix
    Ok(Address::from_slice(&hash[12..]))
}

/// The HTLC's expected ERC-20 `receiver`/`sender` (claim/refund) addresses.
fn htlc_addresses(htlc: &HtlcParams) -> Result<(Address, Address)> {
    Ok((
        eth_address_from_pubkey(&htlc.refund_pubkey)?, // sender: refunded to this address
        eth_address_from_pubkey(&htlc.claim_pubkey)?,  // receiver: paid on claim
    ))
}

/// A non-retryable RPC rejection that nonetheless means "this exact transaction (same
/// hash) already reached the chain" — broadcasting it again must look like success, no
/// further check needed.
fn is_already_known(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("already known") || m.contains("already imported")
}

/// A non-retryable RPC rejection that means *some* transaction already occupies this
/// nonce — but, unlike [`is_already_known`], not necessarily *this* one. The common case is
/// genuinely safe (our own earlier broadcast already mined, and the chain caught up between
/// retries — the write-ahead design here only ever signs a claim/refund once and keeps
/// rebroadcasting the identical bytes, so nothing else should normally touch this nonce).
/// But it is not the only case: a stale read from a load-balanced public RPC, or the same
/// key used by a second process at once (both explicitly against this lane's own
/// conventions, but not impossible), can mean a *different* transaction took the nonce —
/// then this signed transaction can never land under any nonce, ever, and claiming success
/// would make the engine wait forever for a confirmation that can't come. `broadcast` below
/// disambiguates by checking whether *this* transaction's own hash was the one mined.
fn is_nonce_conflict(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("nonce too low") || m.contains("replacement transaction underpriced")
}

/// Whether an RPC error's message means the EVM reverted the call — a genuine, permanent
/// rejection (e.g. `claim()` with the wrong preimage) — as opposed to a transport-level
/// failure (429/502/503 from a public RPC provider, a timeout) that happened to occur
/// while estimating gas or sending a transaction. Mirrors `broadcast`'s own check below.
fn is_revert(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("revert")
}

/// [`ChainBackend`] for USDC on an EVM chain (Sepolia, Base Sepolia, or anvil in tests),
/// over one deployed `Erc20Htlc` and one ERC-20 token.
#[derive(Clone)]
pub struct UsdcBackend {
    client: EvmHtlcClient,
    wallet: EthereumWallet,
    token: Address,
    compressed_pubkey: [u8; 33],
}

impl std::fmt::Debug for UsdcBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsdcBackend")
            .field("address", &self.client.address())
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

impl UsdcBackend {
    /// `htlc` is the deployed `Erc20Htlc` address, `token` the ERC-20 (USDC) address.
    pub fn new(
        rpc_url: &str,
        key: PrivateKeySigner,
        htlc: Address,
        token: Address,
    ) -> Result<Self> {
        let sk = Secp256k1SecretKey::from_slice(key.to_bytes().as_slice())
            .map_err(|e| SwapError::Other(format!("bad signing key: {e}")))?;
        let secp = secp256k1::Secp256k1::new();
        let compressed_pubkey = sk.public_key(&secp).serialize();
        let address = key.address();
        let wallet = EthereumWallet::from(key.clone());
        let provider = connect_provider(rpc_url, key)?;
        Ok(Self {
            client: EvmHtlcClient::new(provider, address, htlc),
            wallet,
            token,
            compressed_pubkey,
        })
    }

    /// This backend's own ETH (gas) and `self.token` (USDC) balances — e.g. to check a
    /// maker is actually funded before serving an offer that would need to sign a
    /// transaction on this chain.
    pub async fn gas_and_token_balance(&self) -> Result<(U256, U256)> {
        let address = self.client.address();
        let eth = self
            .client
            .provider()
            .get_balance(address)
            .await
            .map_err(|e| SwapError::Transient(format!("get_balance: {e}")))?;
        let usdc = self.client.token_balance(self.token, address).await?;
        Ok((eth, usdc))
    }

    /// Sign (but do not send) a call to the HTLC contract from this backend's key.
    async fn sign_htlc_call<C: alloy::sol_types::SolCall + Send + Sync>(
        &self,
        call: &C,
    ) -> Result<SignedTx> {
        self.sign_call(self.client.htlc_address(), call).await
    }

    async fn sign_call<C: alloy::sol_types::SolCall + Send + Sync>(
        &self,
        to: Address,
        call: &C,
    ) -> Result<SignedTx> {
        let provider = self.client.provider();
        let from = self.client.address();
        let nonce = provider
            .get_transaction_count(from)
            .pending()
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_count: {e}")))?;
        let chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| SwapError::Transient(format!("get_chain_id: {e}")))?;
        let probe = TransactionRequest::default()
            .with_from(from)
            .with_to(to)
            .with_call(call)
            .with_chain_id(chain_id)
            .with_nonce(nonce);
        let gas = provider.estimate_gas(probe.clone()).await.map_err(|e| {
            // `eth_estimateGas` is how a revert (e.g. `claim()` with the wrong preimage)
            // is usually caught, before ever broadcasting — a genuine, permanent
            // rejection. But this same call just as easily fails on a transport-level
            // hiccup (429/502/503 from a public RPC provider, a timeout, a "still
            // syncing" node) with no revert involved at all; only the former should be
            // permanent.
            let msg = format!("estimate_gas: {e}");
            if is_revert(&msg) {
                SwapError::Rejected(msg)
            } else {
                SwapError::Transient(msg)
            }
        })?;
        let fees = provider
            .estimate_eip1559_fees()
            .await
            .map_err(|e| SwapError::Transient(format!("estimate_eip1559_fees: {e}")))?;
        let tx = probe
            .with_gas_limit(gas + gas / 5) // 20% headroom over the current-state estimate
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
        let envelope = tx
            .build(&self.wallet)
            .await
            .map_err(|e| SwapError::Other(format!("sign transaction: {e}")))?;
        let raw = envelope.encoded_2718();
        let txid = Txid((*envelope.tx_hash()).into());
        Ok(SignedTx { txid, raw })
    }
}

#[allow(clippy::double_must_use)]
#[async_trait]
impl ChainBackend for UsdcBackend {
    fn chain(&self) -> Chain {
        Chain::Usdc
    }

    fn pubkey(&self) -> [u8; 33] {
        self.compressed_pubkey
    }

    async fn tip_height(&self) -> Result<u64> {
        self.client
            .provider()
            .get_block_number()
            .await
            .map_err(|e| SwapError::Transient(format!("get_block_number: {e}")))
    }

    /// The latest block's timestamp: the same quantity `Erc20Htlc`'s own
    /// `block.timestamp >= timelock` check compares against (see the design doc).
    async fn median_time_past(&self) -> Result<u32> {
        let block = self
            .client
            .provider()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|e| SwapError::Transient(format!("get_block_by_number: {e}")))?
            .ok_or_else(|| SwapError::Transient("no latest block".into()))?;
        Ok(block.header.timestamp as u32)
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        htlc.validate()?;
        let units = amount_to_usdc_units(amount)?;
        let (sender, receiver) = htlc_addresses(htlc)?;
        if sender != self.client.address() {
            return Err(SwapError::InvalidParams(
                "backend key is not the HTLC refund (sender) key".into(),
            ));
        }
        let allowance = self
            .client
            .token_allowance(
                self.token,
                self.client.address(),
                self.client.htlc_address(),
            )
            .await?;
        if allowance < units {
            self.client
                .provider()
                .clone()
                .send_transaction(
                    TransactionRequest::default()
                        .with_from(self.client.address())
                        .with_to(self.token)
                        .with_call(&IErc20::approveCall {
                            spender: self.client.htlc_address(),
                            amount: units,
                        }),
                )
                .await
                .map_err(|e| {
                    // Some ERC-20s legitimately revert a non-zero -> non-zero approve,
                    // but most failures sending/confirming this are transport-level
                    // (429/502/503/timeout), same reasoning as `estimate_gas` above.
                    let msg = format!("send approve: {e}");
                    if is_revert(&msg) {
                        SwapError::Rejected(msg)
                    } else {
                        SwapError::Transient(msg)
                    }
                })?
                .get_receipt()
                .await
                .map_err(|e| SwapError::Transient(format!("await approve receipt: {e}")))?;
        }
        let hashlock = B256::from(htlc.hash);
        let timelock = U256::from(htlc.locktime);
        let tx = self
            .sign_htlc_call(&IErc20Htlc::lockCall {
                token: self.token,
                amount: units,
                receiver,
                hashlock,
                timelock,
            })
            .await?;
        Ok(Funding {
            outpoint: Outpoint {
                txid: tx.txid,
                vout: 0,
            },
            tx,
            amount,
        })
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        _at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        htlc.validate()?;
        let (sender, receiver) = htlc_addresses(htlc)?;
        if receiver != self.client.address() {
            return Err(SwapError::InvalidParams(
                "backend key is not the HTLC claim key".into(),
            ));
        }
        let units = amount_to_usdc_units(amount)?;
        let id = swap_id(
            sender,
            receiver,
            self.token,
            units,
            B256::from(htlc.hash),
            U256::from(htlc.locktime),
        );
        self.sign_htlc_call(&IErc20Htlc::claimCall {
            id,
            preimage: B256::from(*preimage),
        })
        .await
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        _at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        htlc.validate()?;
        let (sender, receiver) = htlc_addresses(htlc)?;
        if sender != self.client.address() {
            return Err(SwapError::InvalidParams(
                "backend key is not the HTLC refund key".into(),
            ));
        }
        let units = amount_to_usdc_units(amount)?;
        let id = swap_id(
            sender,
            receiver,
            self.token,
            units,
            B256::from(htlc.hash),
            U256::from(htlc.locktime),
        );
        self.sign_htlc_call(&IErc20Htlc::refundCall { id }).await
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        match self.client.provider().send_raw_transaction(&tx.raw).await {
            Ok(_) => Ok(tx.txid),
            Err(e) if is_already_known(&e.to_string()) => Ok(tx.txid),
            Err(e) if is_nonce_conflict(&e.to_string()) => {
                // Confirm it was *our* transaction that took the nonce before calling this
                // success — see `is_nonce_conflict`'s doc comment for why that is not
                // guaranteed just because the node rejected a resend this way.
                let hash = B256::from(tx.txid.0);
                let mined = self
                    .client
                    .provider()
                    .get_transaction_receipt(hash)
                    .await
                    .map_err(|e| SwapError::Transient(format!("get_transaction_receipt: {e}")))?;
                match mined {
                    Some(_) => Ok(tx.txid),
                    None => Err(SwapError::Rejected(format!(
                        "nonce conflict and {} was never mined — a different transaction \
                         took this nonce (stale RPC view, or this key in use elsewhere): {e}",
                        tx.txid
                    ))),
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if is_revert(&msg) {
                    Err(SwapError::Rejected(msg))
                } else {
                    Err(SwapError::Transient(msg))
                }
            }
        }
    }

    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let hash = B256::from(txid.0);
        if let Some(receipt) = self
            .client
            .provider()
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_receipt: {e}")))?
        {
            let Some(block_number) = receipt.block_number else {
                return Ok(Some(0));
            };
            let tip = self.tip_height().await?;
            return Ok(Some((tip.saturating_sub(block_number) + 1) as u32));
        }
        let pending = self
            .client
            .provider()
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_by_hash: {e}")))?;
        Ok(pending.map(|_| 0))
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let hash = B256::from(at.txid.0);
        let Some(receipt) = self
            .client
            .provider()
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_receipt: {e}")))?
        else {
            return Ok(None);
        };
        let Some(block_number) = receipt.block_number else {
            return Ok(None);
        };
        let mut locked = None;
        for log in receipt.inner.logs() {
            if log.address() != self.client.htlc_address() {
                continue;
            }
            if let Ok(decoded) = log.log_decode::<IErc20Htlc::Locked>() {
                locked = Some(decoded.inner.data);
                break;
            }
        }
        let Some(locked) = locked else {
            return Ok(None);
        };
        let (want_sender, want_receiver) = htlc_addresses(htlc)?;
        let hashlock_matches = FixedBytes::<32>(htlc.hash) == locked.hashlock;
        if locked.sender != want_sender
            || locked.receiver != want_receiver
            || locked.token != self.token
            || !hashlock_matches
            || locked.timelock != U256::from(htlc.locktime)
        {
            return Ok(None);
        }
        let tip = self.tip_height().await?;
        let confirmations = (tip.saturating_sub(block_number) + 1) as u32;
        let amount = usdc_units_to_amount(locked.amount)?;
        Ok(Some(LockedOutput {
            amount,
            confirmations,
        }))
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let hash = B256::from(outpoint.txid.0);
        let Some(receipt) = self
            .client
            .provider()
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_receipt: {e}")))?
        else {
            return Ok(None);
        };
        let mut id = None;
        for log in receipt.inner.logs() {
            if log.address() != self.client.htlc_address() {
                continue;
            }
            if let Ok(decoded) = log.log_decode::<IErc20Htlc::Locked>() {
                id = Some(decoded.inner.data.id);
                break;
            }
        }
        let Some(id) = id else {
            return Ok(None);
        };

        let from_block = BlockNumberOrTag::Number(from_height);
        let claimed = Filter::new()
            .address(self.client.htlc_address())
            .event_signature(IErc20Htlc::Claimed::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(BlockNumberOrTag::Latest);
        for log in self
            .client
            .provider()
            .get_logs(&claimed)
            .await
            .map_err(|e| SwapError::Transient(format!("get_logs Claimed: {e}")))?
        {
            let Some(txid) = log.transaction_hash else {
                continue;
            };
            let height = log.block_number;
            if let Ok(decoded) = log.log_decode::<IErc20Htlc::Claimed>() {
                if decoded.inner.data.id == id {
                    return Ok(Some(SpendInfo {
                        txid: Txid(txid.0),
                        input_index: 0,
                        height,
                        script_sig: Vec::new(),
                        witness: vec![decoded.inner.data.preimage.to_vec()],
                    }));
                }
            }
        }

        let refunded = Filter::new()
            .address(self.client.htlc_address())
            .event_signature(IErc20Htlc::Refunded::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(BlockNumberOrTag::Latest);
        for log in self
            .client
            .provider()
            .get_logs(&refunded)
            .await
            .map_err(|e| SwapError::Transient(format!("get_logs Refunded: {e}")))?
        {
            let Some(txid) = log.transaction_hash else {
                continue;
            };
            let height = log.block_number;
            if let Ok(decoded) = log.log_decode::<IErc20Htlc::Refunded>() {
                if decoded.inner.data.id == id {
                    return Ok(Some(SpendInfo {
                        txid: Txid(txid.0),
                        input_index: 0,
                        height,
                        script_sig: Vec::new(),
                        witness: Vec::new(),
                    }));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(hex_str: &str) -> [u8; 33] {
        let mut out = [0u8; 33];
        hex::decode_to_slice(hex_str, &mut out).expect("33-byte compressed pubkey");
        out
    }

    /// `docs/plans/swap-poc/funding.md`: the taker/maker swap keys' Sepolia addresses,
    /// derived from the same compressed pubkeys the BTC lane already published on-chain
    /// (`RESULTS.md` Wave 0 — public data, no secret involved). If this ever disagrees with
    /// `funding.md`, the lane brief says to stop and report it, not to just update the test.
    #[test]
    fn matches_funding_md_addresses() {
        let taker_pubkey =
            pubkey("03a7f9cfee27410046ac906b13c2500672b2930584da9693ce69f9f0a81a5f22f5");
        let maker_pubkey =
            pubkey("02d05bd358a1efd8e5aa9c82c10d0e2c0ce67c1e5a984f02684724df28a343a7dd");
        assert_eq!(
            eth_address_from_pubkey(&taker_pubkey).unwrap().to_string(),
            "0x4bb95b0cD0AC55556D96D7E850a5090Cc450D60C"
        );
        assert_eq!(
            eth_address_from_pubkey(&maker_pubkey).unwrap().to_string(),
            "0x995669a244d511542ca314e4068c754E3F555bd2"
        );
    }

    /// `broadcast`'s idempotency check (geth's wording for a tx already in its own
    /// mempool, or parity/besu's "already imported") — the EVM analog of BTC's "already
    /// in mempool"/"already in block chain" handling. No direct test existed for this
    /// before (only indirectly, via the nonce-conflict anvil tests).
    #[test]
    fn already_known_recognizes_geth_and_parity_wording() {
        assert!(is_already_known(
            "already known: Transaction already known on this node"
        ));
        assert!(is_already_known("Transaction already imported"));
        assert!(!is_already_known("execution reverted: wrong preimage"));
    }

    #[test]
    fn nonce_conflict_recognizes_both_wordings() {
        assert!(is_nonce_conflict("nonce too low: next nonce 5, tx nonce 3"));
        assert!(is_nonce_conflict("replacement transaction underpriced"));
        assert!(!is_nonce_conflict("execution reverted"));
    }

    /// A genuine on-chain revert (e.g. `claim()` with the wrong preimage) must stay a
    /// permanent rejection; a transport-level failure (429/502/503 from a public RPC
    /// provider, a timeout) hitting the exact same call (`estimate_gas`, `send_raw_
    /// transaction`, the `approve` send) must not — it has no "revert" in it at all.
    #[test]
    fn revert_detection_distinguishes_from_transport_failures() {
        assert!(is_revert("execution reverted: wrong preimage"));
        assert!(is_revert(
            "server returned an error response: error code 3: execution reverted"
        ));
        assert!(!is_revert("error sending request: connection reset"));
        assert!(!is_revert("HTTP error 503: Service Unavailable"));
        assert!(!is_revert("deadline has elapsed"));
    }

    #[test]
    fn usdc_unit_conversion_round_trips_and_rejects_dust() {
        assert_eq!(
            amount_to_usdc_units(Amount::from_sat(10_000_000)).unwrap(),
            U256::from(100_000u64)
        );
        assert_eq!(
            usdc_units_to_amount(U256::from(100_000u64)).unwrap(),
            Amount::from_sat(10_000_000)
        );
        assert!(amount_to_usdc_units(Amount::from_sat(1)).is_err());
    }

    const TEN_USDC: u64 = 10_000_000; // 6 decimals
    const POINT_01_ETH: u128 = 10_000_000_000_000_000; // 18 decimals

    #[test]
    fn divi_usdc_offer_needs_only_gas() {
        // taker_pays_btc: the maker sells DIVI it already holds, and only claims the
        // taker's USDC lock — no USDC collateral of its own needed, at any balance.
        assert!(usdc_offer_is_fundable(
            Direction::TakerPaysBtc,
            U256::from(POINT_01_ETH),
            U256::ZERO,
            POINT_01_ETH,
            TEN_USDC,
        ));
        assert!(!usdc_offer_is_fundable(
            Direction::TakerPaysBtc,
            U256::from(POINT_01_ETH - 1),
            U256::from(u64::MAX),
            POINT_01_ETH,
            TEN_USDC,
        ));
    }

    #[test]
    fn usdc_divi_offer_needs_gas_and_usdc_collateral() {
        // taker_pays_divi: the maker sells USDC, so it needs both the gas floor and the
        // USDC floor — either one short is enough to refuse it.
        assert!(usdc_offer_is_fundable(
            Direction::TakerPaysDivi,
            U256::from(POINT_01_ETH),
            U256::from(TEN_USDC),
            POINT_01_ETH,
            TEN_USDC,
        ));
        assert!(!usdc_offer_is_fundable(
            Direction::TakerPaysDivi,
            U256::from(POINT_01_ETH - 1),
            U256::from(TEN_USDC),
            POINT_01_ETH,
            TEN_USDC,
        ));
        assert!(!usdc_offer_is_fundable(
            Direction::TakerPaysDivi,
            U256::from(POINT_01_ETH),
            U256::from(TEN_USDC - 1),
            POINT_01_ETH,
            TEN_USDC,
        ));
    }

    #[test]
    fn usdc_offer_fundability_is_exact_at_the_floor() {
        // Exactly at the floor counts as fundable (>=, not >) on both axes.
        assert!(usdc_offer_is_fundable(
            Direction::TakerPaysDivi,
            U256::from(POINT_01_ETH),
            U256::from(TEN_USDC),
            POINT_01_ETH,
            TEN_USDC,
        ));
    }
}
