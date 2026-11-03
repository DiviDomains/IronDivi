// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
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
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use secp256k1::{PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey};

use divi_swap::api::Direction;
use divi_swap::{
    Amount, Chain, ChainBackend, FeeBump, Funding, HtlcParams, LockedOutput, Outpoint, SignedTx,
    SpendInfo, SwapError, Txid,
};

use crate::client::{connect_provider, swap_id, EvmHtlcClient};
use crate::contract::{IErc20, IErc20Htlc};
use crate::quorum;

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
/// retries — the write-ahead design rebroadcasts identical bytes, and the only other thing
/// it signs at a claim's nonce is a same-nonce replacement of it, `FeeBump::SameNonce`, so
/// either the message means another version of the same claim holds the nonce or nothing
/// of ours should touch it).
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
    min_lock_gas_wei: U256,
    /// A second node `htlc_output`, `find_spend`, `confirmations` and `median_time_past`
    /// also ask ([`UsdcBackend::with_quorum_rpc`]); `None` reads the one node only.
    quorum: Option<DynProvider>,
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
            min_lock_gas_wei: U256::ZERO,
            quorum: None,
        })
    }

    /// The EVM address this backend signs from.
    pub fn address(&self) -> Address {
        self.client.address()
    }

    /// The ETH this key must hold before [`ChainBackend::spendable`] reports its USDC: a
    /// funding is an `approve` plus a `lock`, both paid in gas. Defaults to zero (no floor).
    pub fn with_min_lock_gas_wei(mut self, wei: u128) -> Self {
        self.min_lock_gas_wei = U256::from(wei);
        self
    }

    /// Ask a second node, at `rpc_url`, the reads a claim or refund rests on: `htlc_output`,
    /// `find_spend`, `confirmations` and `median_time_past`. Off unless called; without it
    /// every read is the one node's, with the requests it always made. With it, both nodes
    /// are asked and their answers reconciled (`quorum.rs`): a disagreement on existence, on
    /// the spending transaction or on the lock is `SwapError::Held` (the engine's bounded hold,
    /// with [`ChainBackend::primary_only`]), two confirmation counts or block times are the
    /// smaller one, and a second node that does not answer is `Held` (fail closed). Tips, sending, nonces, gas and balances stay on the one node.
    pub fn with_quorum_rpc(mut self, rpc_url: &str) -> Result<Self> {
        let url = rpc_url
            .parse()
            .map_err(|e| SwapError::Other(format!("bad quorum RPC URL: {e}")))?;
        // Read-only: nothing is ever signed or sent through the second node.
        self.quorum = Some(DynProvider::new(ProviderBuilder::new().connect_http(url)));
        Ok(self)
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

    /// The HTLC's `claim(id, preimage)` call, if this backend's key is its claim key.
    fn claim_call(
        &self,
        htlc: &HtlcParams,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<IErc20Htlc::claimCall> {
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
        Ok(IErc20Htlc::claimCall {
            id,
            preimage: B256::from(*preimage),
        })
    }

    /// Sign (but do not send) a call to the HTLC contract from this backend's key.
    async fn sign_htlc_call<C: alloy::sol_types::SolCall + Send + Sync>(
        &self,
        call: &C,
    ) -> Result<SignedTx> {
        self.sign_call(self.client.htlc_address(), call, None).await
    }

    /// Sign a call at the next free (`pending`) nonce. `max_fee`: `maxFeePerGas` in wei, with
    /// the tip no higher; `None` takes both from the node's current estimate.
    async fn sign_call<C: alloy::sol_types::SolCall + Send + Sync>(
        &self,
        to: Address,
        call: &C,
        max_fee: Option<u128>,
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
        let max_fee = max_fee.unwrap_or(fees.max_fee_per_gas);
        let tx = probe
            .with_gas_limit(gas + gas / 5) // 20% headroom over the current-state estimate
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas.min(max_fee));
        let envelope = tx
            .build(&self.wallet)
            .await
            .map_err(|e| SwapError::Other(format!("sign transaction: {e}")))?;
        let raw = envelope.encoded_2718();
        let txid = Txid((*envelope.tx_hash()).into());
        Ok(SignedTx { txid, raw })
    }

    // The reads a claim or refund rests on, made on one node `p`: the primary
    // (`self.client`) or the quorum's second node.

    async fn tip_height_on(p: &DynProvider) -> Result<u64> {
        p.get_block_number()
            .await
            .map_err(|e| SwapError::Transient(format!("get_block_number: {e}")))
    }

    /// The latest block's timestamp: the same quantity `Erc20Htlc`'s own
    /// `block.timestamp >= timelock` check compares against (see the design doc).
    async fn latest_timestamp_on(p: &DynProvider) -> Result<u32> {
        let block = p
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|e| SwapError::Transient(format!("get_block_by_number: {e}")))?
            .ok_or_else(|| SwapError::Transient("no latest block".into()))?;
        Ok(block.header.timestamp as u32)
    }

    async fn confirmations_on(p: &DynProvider, txid: &Txid) -> Result<Option<u32>> {
        let hash = B256::from(txid.0);
        if let Some(receipt) = p
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_receipt: {e}")))?
        {
            let Some(block_number) = receipt.block_number else {
                return Ok(Some(0));
            };
            let tip = Self::tip_height_on(p).await?;
            return Ok(Some((tip.saturating_sub(block_number) + 1) as u32));
        }
        let pending = p
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| SwapError::Transient(format!("get_transaction_by_hash: {e}")))?;
        Ok(pending.map(|_| 0))
    }

    async fn htlc_output_on(
        &self,
        p: &DynProvider,
        htlc: &HtlcParams,
        at: &Outpoint,
    ) -> Result<Option<LockedOutput>> {
        let hash = B256::from(at.txid.0);
        let Some(receipt) = p
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
        let tip = Self::tip_height_on(p).await?;
        let confirmations = (tip.saturating_sub(block_number) + 1) as u32;
        let amount = usdc_units_to_amount(locked.amount)?;
        Ok(Some(LockedOutput {
            amount,
            confirmations,
        }))
    }

    async fn find_spend_on(
        &self,
        p: &DynProvider,
        outpoint: &Outpoint,
        from_height: u64,
    ) -> Result<Option<SpendInfo>> {
        let hash = B256::from(outpoint.txid.0);
        let Some(receipt) = p
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
        for log in p
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
        for log in p
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

#[allow(clippy::double_must_use)]
#[async_trait]
impl ChainBackend for UsdcBackend {
    fn chain(&self) -> Chain {
        Chain::Usdc
    }

    fn pubkey(&self) -> [u8; 33] {
        self.compressed_pubkey
    }

    /// With the quorum, the same key on the one node alone: the engine reads and builds on it
    /// only where a hold ends at its deadline (`divi_swap` `hold.rs`). Without it, none.
    fn primary_only(&self) -> Option<std::sync::Arc<dyn ChainBackend>> {
        self.quorum.as_ref()?;
        Some(std::sync::Arc::new(UsdcBackend {
            quorum: None,
            ..self.clone()
        }))
    }

    async fn tip_height(&self) -> Result<u64> {
        Self::tip_height_on(self.client.provider()).await
    }

    async fn tip_hash(&self) -> Result<String> {
        let block = self
            .client
            .provider()
            .get_block_by_number(BlockNumberOrTag::Latest)
            .await
            .map_err(|e| SwapError::Transient(format!("get_block_by_number: {e}")))?
            .ok_or_else(|| SwapError::Transient("no latest block".into()))?;
        Ok(hex::encode(block.header.hash))
    }

    /// The latest block's timestamp: the same quantity `Erc20Htlc`'s own
    /// `block.timestamp >= timelock` check compares against (see the design doc). With a
    /// quorum, the smaller of the two nodes' (`quorum.rs`).
    async fn median_time_past(&self) -> Result<u32> {
        let a = Self::latest_timestamp_on(self.client.provider()).await?;
        let Some(q) = &self.quorum else {
            return Ok(a);
        };
        let b = quorum::second("median_time_past", Self::latest_timestamp_on(q).await)?;
        Ok(quorum::agree_mtp(a, b))
    }

    /// `Erc20Htlc.refund` checks `block.timestamp >= timelock` in the block that includes
    /// it, which comes after the latest block: a refund is good once the latest block's
    /// timestamp reaches the timelock, so EVM keeps `>=` where Bitcoin Core needs `>`.
    fn refund_final(&self, mtp: u32, locktime: u32) -> bool {
        mtp >= locktime
    }

    /// This key's `token` balance, with no allowance or gas taken off. Below the lock-gas
    /// floor ([`UsdcBackend::with_min_lock_gas_wei`]) the USDC cannot be locked at all, so
    /// that is refused outright rather than reported as a balance.
    async fn spendable(&self) -> Result<Option<Amount>> {
        let (eth_wei, units) = self.gas_and_token_balance().await?;
        if eth_wei < self.min_lock_gas_wei {
            return Err(SwapError::InsufficientFunds(format!(
                "maker has {eth_wei} wei for gas on usdc, a lock needs at least {}",
                self.min_lock_gas_wei
            )));
        }
        usdc_units_to_amount(units).map(Some)
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
        let call = self.claim_call(htlc, amount, preimage)?;
        self.sign_htlc_call(&call).await
    }

    fn fee_bump(&self) -> FeeBump {
        FeeBump::SameNonce
    }

    /// `maxFeePerGas` the node estimates now, wei per gas.
    async fn claim_feerate(&self) -> Result<Option<u64>> {
        let fees = self
            .client
            .provider()
            .estimate_eip1559_fees()
            .await
            .map_err(|e| SwapError::Transient(format!("estimate_eip1559_fees: {e}")))?;
        Ok(Some(
            u64::try_from(fees.max_fee_per_gas).unwrap_or(u64::MAX),
        ))
    }

    // `claim_sizes` stays `None`: the fee is paid in ETH and the leg is USDC, so a share of
    // the leg is no gas price; the fixed `FeeEscalation` cap bounds the claim instead.

    /// The claim with `maxFeePerGas` = `feerate` (wei per gas), at the next free nonce.
    async fn build_claim_at(
        &self,
        htlc: &HtlcParams,
        _at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
        feerate: u64,
    ) -> Result<SignedTx> {
        let call = self.claim_call(htlc, amount, preimage)?;
        self.sign_call(self.client.htlc_address(), &call, Some(u128::from(feerate)))
            .await
    }

    /// `prev` re-signed at its own nonce: same contract, calldata, value, gas limit, chain id
    /// and access list, with `maxFeePerGas` = `feerate` and the tip raised in proportion, both
    /// past the node's price bump, `price_bump_pct` ([`replacement_fees`]). Signed offline: no node call, so the
    /// gas limit is not re-estimated and the nonce is the stuck claim's, not `pending`.
    async fn build_claim_replacement(
        &self,
        prev: &SignedTx,
        feerate: u64,
        price_bump_pct: u64,
    ) -> Result<Option<SignedTx>> {
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::consensus::TxEnvelope;
        use alloy::eips::Decodable2718;
        use alloy::primitives::TxKind;
        let bad = |why: String| SwapError::InvalidParams(format!("claim {}: {why}", prev.txid));
        let envelope = TxEnvelope::decode_2718(&mut prev.raw.as_slice())
            .map_err(|e| bad(format!("decode: {e}")))?;
        let signer = envelope
            .recover_signer()
            .map_err(|e| bad(format!("recover signer: {e}")))?;
        if signer != self.address() {
            return Err(bad("not signed by this backend's key".into()));
        }
        let TxEnvelope::Eip1559(signed) = envelope else {
            return Err(bad("not an EIP-1559 transaction".into()));
        };
        let old = signed.tx();
        let TxKind::Call(to) = old.to else {
            return Err(bad("a contract creation".into()));
        };
        if to != self.client.htlc_address() {
            return Err(bad("not a call to this backend's HTLC contract".into()));
        }
        let Some((max_fee, tip)) = replacement_fees(
            old.max_fee_per_gas,
            old.max_priority_fee_per_gas,
            u128::from(feerate),
            price_bump_pct,
        ) else {
            return Ok(None);
        };
        let tx = TransactionRequest::default()
            .with_from(signer)
            .with_to(to)
            .with_input(old.input.clone())
            .with_value(old.value)
            .with_chain_id(old.chain_id)
            .with_nonce(old.nonce)
            .with_gas_limit(old.gas_limit)
            .with_access_list(old.access_list.clone())
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(tip);
        let envelope = tx
            .build(&self.wallet)
            .await
            .map_err(|e| SwapError::Other(format!("sign transaction: {e}")))?;
        let raw = envelope.encoded_2718();
        let txid = Txid((*envelope.tx_hash()).into());
        Ok(Some(SignedTx { txid, raw }))
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
                    // A pending transaction holds this nonce (an earlier version of this
                    // claim, say) and this one does not pay enough more to replace it.
                    None if e.to_string().to_ascii_lowercase().contains("underpriced") => {
                        Err(SwapError::Rejected(format!(
                            "{} not taken: the node holds another transaction at its nonce \
                             (an earlier version of it, or not ours) and this one does not \
                             clear the node's price bump: {e}",
                            tx.txid
                        )))
                    }
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
        let a = Self::confirmations_on(self.client.provider(), txid).await?;
        let Some(q) = &self.quorum else {
            return Ok(a);
        };
        let b = quorum::second("confirmations", Self::confirmations_on(q, txid).await)?;
        quorum::agree_confirmations(a, b)
    }

    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let a = self
            .htlc_output_on(self.client.provider(), htlc, at)
            .await?;
        let Some(q) = &self.quorum else {
            return Ok(a);
        };
        let b = quorum::second("htlc_output", self.htlc_output_on(q, htlc, at).await)?;
        quorum::agree_htlc_output(a, b)
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        let a = self
            .find_spend_on(self.client.provider(), outpoint, from_height)
            .await?;
        let Some(q) = &self.quorum else {
            return Ok(a);
        };
        let b = quorum::second(
            "find_spend",
            self.find_spend_on(q, outpoint, from_height).await,
        )?;
        quorum::agree_spend(a, b)
    }
}

/// Least fee geth takes in a replacement of a transaction paying `old` on a node whose
/// `PriceBump` is `price_bump_pct` (`--txpool.pricebump`, default 10 in
/// `core/txpool/legacypool/legacypool.go`, `DefaultConfig`; the chain's
/// `FeeEscalation::price_bump_pct`): `list.Add` in `core/txpool/legacypool/list.go` refuses
/// unless the new fee is strictly greater *and* at least `old * (100 + PriceBump) / 100`
/// (integer division), checked separately for `maxFeePerGas` and `maxPriorityFeePerGas`; it
/// answers `replacement transaction underpriced` (`ErrReplaceUnderpriced`,
/// `core/txpool/errors.go`).
fn geth_replacement_floor(old: u128, price_bump_pct: u64) -> u128 {
    (old.saturating_mul(100 + u128::from(price_bump_pct)) / 100).max(old.saturating_add(1))
}

/// `(maxFeePerGas, maxPriorityFeePerGas)` for a replacement of a transaction paying
/// `(old_max, old_tip)`, with the max fee at `target`: the tip rises in proportion to the max
/// fee, and at least to the node's floor at `price_bump_pct`. `None` when `target` is under
/// that floor for the max fee, or the tip's floor is over `target`: no replacement the node
/// takes fits.
fn replacement_fees(
    old_max: u128,
    old_tip: u128,
    target: u128,
    price_bump_pct: u64,
) -> Option<(u128, u128)> {
    if target < geth_replacement_floor(old_max, price_bump_pct) {
        return None;
    }
    let scaled = old_tip.saturating_mul(target).div_ceil(old_max.max(1));
    let tip = geth_replacement_floor(old_tip, price_bump_pct).max(scaled);
    (tip <= target).then_some((target, tip))
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

    /// The refund gate keeps the contract's own `block.timestamp >= timelock`: final at a
    /// latest-block timestamp equal to the timelock (the default, Core's `>`, would wait).
    #[test]
    fn refund_final_matches_contract_timelock_check() {
        let backend = UsdcBackend::new(
            "http://127.0.0.1:1",
            PrivateKeySigner::random(),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap();
        let l = 1_800_000_000;
        assert!(!backend.refund_final(l - 1, l));
        assert!(backend.refund_final(l, l));
        assert!(backend.refund_final(l + 1, l));
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

    /// A JSON-RPC node that has mined 5 transactions from the account (`latest` = 5) and
    /// holds `pending_txs` more in its mempool (`pending` = 5 + that). Records every block tag
    /// `eth_getTransactionCount` was asked about.
    #[derive(Clone, Default)]
    struct NonceNode {
        pending_txs: std::sync::Arc<std::sync::atomic::AtomicU64>,
        tags: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl wiremock::Respond for NonceNode {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            use serde_json::{json, Value};
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let result: Value = match body["method"].as_str().unwrap_or("") {
                "eth_getTransactionCount" => {
                    let tag = body["params"][1].as_str().unwrap_or("").to_string();
                    let pending = self.pending_txs.load(std::sync::atomic::Ordering::SeqCst);
                    let n = if tag == "latest" { 5 } else { 5 + pending };
                    self.tags.lock().unwrap().push(tag);
                    json!(format!("0x{n:x}"))
                }
                "eth_chainId" => json!("0x7a69"),
                "eth_estimateGas" => json!("0x30d40"),
                "eth_feeHistory" => {
                    let n = usize::from_str_radix(
                        body["params"][0]
                            .as_str()
                            .unwrap_or("0x1")
                            .trim_start_matches("0x"),
                        16,
                    )
                    .unwrap_or(1);
                    json!({
                        "oldestBlock": "0x1",
                        "baseFeePerGas": vec!["0x3b9aca00"; n + 1],
                        "gasUsedRatio": vec![0.5; n],
                        "reward": vec![vec!["0x3b9aca00"]; n],
                    })
                }
                "eth_maxPriorityFeePerGas" => json!("0x3b9aca00"),
                other => {
                    return wiremock::ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0", "id": body["id"],
                        "error": {"code": -32601, "message": format!("unmocked {other}")},
                    }))
                }
            };
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
        }
    }

    fn signed_nonce(tx: &SignedTx) -> u64 {
        use alloy::consensus::{Transaction as _, TxEnvelope};
        use alloy::eips::Decodable2718;
        TxEnvelope::decode_2718(&mut tx.raw.as_slice())
            .unwrap()
            .nonce()
    }

    /// The nonce source is the node's `pending` count, not `latest`: while one of our
    /// transactions sits unmined in the mempool, the next one is signed with the next nonce
    /// instead of replacing it ("replacement transaction underpriced"). Fails if the call is
    /// changed to `latest` (the second signature then reuses nonce 5).
    #[tokio::test]
    async fn two_pending_txs_get_distinct_nonces() {
        let server = wiremock::MockServer::start().await;
        let node = NonceNode::default();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(node.clone())
            .mount(&server)
            .await;
        let key = PrivateKeySigner::random();
        let backend = UsdcBackend::new(
            &server.uri(),
            key,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap();
        let call = IErc20Htlc::refundCall {
            id: B256::repeat_byte(7),
        };
        let first = backend.sign_htlc_call(&call).await.unwrap();
        // The first tx is now in the node's mempool, unmined.
        node.pending_txs
            .store(1, std::sync::atomic::Ordering::SeqCst);
        let second = backend.sign_htlc_call(&call).await.unwrap();
        assert_eq!(signed_nonce(&first), 5);
        assert_eq!(signed_nonce(&second), 6, "second tx reused a pending nonce");
        assert!(
            node.tags.lock().unwrap().iter().all(|t| t == "pending"),
            "{:?}",
            node.tags.lock().unwrap()
        );
    }

    /// A node whose `eth_getBalance` is `eth_wei` and whose every `eth_call` returns
    /// `usdc_units` (`spendable` makes one call, `balanceOf`).
    async fn balance_node(eth_wei: u128, usdc_units: u64) -> wiremock::MockServer {
        use serde_json::{json, Value};
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |req: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&req.body).unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "eth_getBalance" => json!(format!("0x{eth_wei:x}")),
                    "eth_call" => json!(format!("0x{usdc_units:064x}")),
                    "eth_chainId" => json!("0x7a69"),
                    other => {
                        return wiremock::ResponseTemplate::new(200).set_body_json(json!({
                            "jsonrpc": "2.0", "id": body["id"],
                            "error": {"code": -32601, "message": format!("unmocked {other}")},
                        }))
                    }
                };
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
            })
            .mount(&server)
            .await;
        server
    }

    fn balance_backend(server: &wiremock::MockServer, min_lock_gas_wei: u128) -> UsdcBackend {
        UsdcBackend::new(
            &server.uri(),
            PrivateKeySigner::random(),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap()
        .with_min_lock_gas_wei(min_lock_gas_wei)
    }

    /// `Maker::accept` checks `spendable` on the maker-leg chain, so on USDC it has to be the
    /// key's USDC in engine sats, and a refusal when there is no gas to lock it. Fails on the
    /// trait default (`None`, "cannot tell"), with which accept took any USDC swap.
    #[tokio::test]
    async fn spendable_is_the_usdc_balance_and_needs_lock_gas() {
        const FLOOR: u128 = 10_000_000_000_000_000; // 0.01 ETH
        let server = balance_node(FLOOR, 12_500_000).await; // 12.5 USDC
        assert_eq!(
            balance_backend(&server, FLOOR).spendable().await.unwrap(),
            Some(Amount::from_sat(1_250_000_000))
        );
        let server = balance_node(FLOOR - 1, 12_500_000).await;
        let err = balance_backend(&server, FLOOR)
            .spendable()
            .await
            .unwrap_err();
        assert!(matches!(err, SwapError::InsufficientFunds(_)), "{err:?}");
    }

    /// Property tests over the USDC unit conversions and the fundability floor: zero, one,
    /// the `u64` limits and random values, plus amounts beyond 64 bits.
    mod props {
        use super::*;
        use proptest::prelude::*;

        fn edge() -> impl Strategy<Value = u64> {
            prop_oneof![
                Just(0u64),
                Just(1),
                Just(99),
                Just(100),
                Just(u64::MAX / ENGINE_PER_USDC_UNIT),
                Just(u64::MAX / ENGINE_PER_USDC_UNIT + 1),
                Just(u64::MAX),
                0..=1_000_000_000u64,
                any::<u64>(),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1024))]

            /// Units become engine sats ×100 exactly, and round-trip; anything that would not
            /// fit in a `u64` of sats is refused, never wrapped or saturated.
            #[test]
            fn usdc_units_to_amount_is_exact_or_refused(units in edge(), high in any::<bool>()) {
                let u = if high {
                    U256::from(units) + (U256::from(1u8) << 64)
                } else {
                    U256::from(units)
                };
                let fits = !high && units <= u64::MAX / ENGINE_PER_USDC_UNIT;
                match usdc_units_to_amount(u) {
                    Ok(a) => {
                        prop_assert!(fits);
                        prop_assert_eq!(u128::from(a.to_sat()), u128::from(units) * 100);
                        prop_assert_eq!(amount_to_usdc_units(a).unwrap(), u);
                    }
                    Err(_) => prop_assert!(!fits),
                }
            }

            /// Only a whole number of base units converts, exactly, and it converts back.
            #[test]
            fn amount_to_usdc_units_refuses_only_fractions(sat in edge()) {
                match amount_to_usdc_units(Amount::from_sat(sat)) {
                    Ok(u) => {
                        prop_assert_eq!(sat % ENGINE_PER_USDC_UNIT, 0);
                        prop_assert_eq!(u, U256::from(sat / ENGINE_PER_USDC_UNIT));
                        prop_assert_eq!(usdc_units_to_amount(u).unwrap(), Amount::from_sat(sat));
                    }
                    Err(_) => prop_assert_ne!(sat % ENGINE_PER_USDC_UNIT, 0),
                }
            }

            /// More ETH or more USDC never makes a fundable offer unfundable.
            #[test]
            fn usdc_offer_fundability_is_monotone(
                pays_btc in any::<bool>(),
                eth in edge(),
                usdc in edge(),
                more_eth in edge(),
                more_usdc in edge(),
                min_eth in edge(),
                min_usdc in edge(),
            ) {
                let dir = if pays_btc { Direction::TakerPaysBtc } else { Direction::TakerPaysDivi };
                let ok = |eth: U256, usdc: U256| {
                    usdc_offer_is_fundable(dir, eth, usdc, u128::from(min_eth), min_usdc)
                };
                let (eth, usdc) = (U256::from(eth), U256::from(usdc));
                if ok(eth, usdc) {
                    prop_assert!(ok(eth + U256::from(more_eth), usdc));
                    prop_assert!(ok(eth, usdc + U256::from(more_usdc)));
                }
            }
        }
    }

    /// A [`NonceNode`] that also relays: `eth_sendRawTransaction` succeeds, or fails with
    /// `send_error`; `eth_getTransactionReceipt` reports a mined receipt for the hashes in
    /// `mined` only; nothing is pending by hash; the tip is block 0x10.
    #[derive(Clone, Default)]
    struct RelayNode {
        nonces: NonceNode,
        send_error: std::sync::Arc<std::sync::Mutex<Option<String>>>,
        mined: std::sync::Arc<std::sync::Mutex<Vec<B256>>>,
    }

    impl wiremock::Respond for RelayNode {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            use serde_json::{json, Value};
            let body: Value = serde_json::from_slice(&req.body).unwrap();
            let ok = |result: Value| {
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
            };
            match body["method"].as_str().unwrap_or("") {
                "eth_sendRawTransaction" => {
                    if let Some(msg) = self.send_error.lock().unwrap().clone() {
                        return wiremock::ResponseTemplate::new(200).set_body_json(json!({
                            "jsonrpc": "2.0", "id": body["id"],
                            "error": {"code": -32000, "message": msg},
                        }));
                    }
                    let raw =
                        hex::decode(body["params"][0].as_str().unwrap().trim_start_matches("0x"))
                            .unwrap();
                    ok(json!(keccak256(raw).to_string()))
                }
                "eth_getTransactionReceipt" => {
                    let hash: B256 = body["params"][0].as_str().unwrap().parse().unwrap();
                    if !self.mined.lock().unwrap().contains(&hash) {
                        return ok(Value::Null);
                    }
                    let addr = Address::repeat_byte(0x11).to_string();
                    ok(json!({
                        "transactionHash": hash.to_string(),
                        "transactionIndex": "0x0",
                        "blockHash": B256::repeat_byte(0x42).to_string(),
                        "blockNumber": "0xe",
                        "from": addr, "to": addr,
                        "cumulativeGasUsed": "0x5208", "gasUsed": "0x5208",
                        "effectiveGasPrice": "0x3b9aca00",
                        "contractAddress": null,
                        "logs": [],
                        "logsBloom": format!("0x{}", "00".repeat(256)),
                        "type": "0x2", "status": "0x1",
                    }))
                }
                "eth_getTransactionByHash" => ok(Value::Null),
                "eth_blockNumber" => ok(json!("0x10")),
                _ => self.nonces.respond(req),
            }
        }
    }

    async fn relay_backend() -> (wiremock::MockServer, RelayNode, UsdcBackend) {
        let server = wiremock::MockServer::start().await;
        let node = RelayNode::default();
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(node.clone())
            .mount(&server)
            .await;
        let backend = UsdcBackend::new(
            &server.uri(),
            PrivateKeySigner::random(),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap();
        (server, node, backend)
    }

    /// An HTLC `backend` may claim.
    fn claimable_by(backend: &UsdcBackend) -> HtlcParams {
        let other = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        HtlcParams {
            hash: [0xab; 32],
            claim_pubkey: backend.pubkey(),
            refund_pubkey: other.public_key(&secp256k1::Secp256k1::new()).serialize(),
            locktime: 1_800_000_000,
            script_version: Default::default(),
        }
    }

    fn decoded(tx: &SignedTx) -> alloy::consensus::TxEnvelope {
        use alloy::eips::Decodable2718;
        alloy::consensus::TxEnvelope::decode_2718(&mut tx.raw.as_slice()).unwrap()
    }

    /// Geth's replacement rule, transcribed from `core/txpool/legacypool/list.go`
    /// (`list.Add`) with the default `PriceBump` of 10 (`legacypool.go`, `DefaultConfig`).
    fn geth_accepts(old: (u128, u128), new: (u128, u128)) -> bool {
        geth_accepts_at(old, new, 10)
    }

    /// [`geth_accepts`] on a node run with `--txpool.pricebump=bump`.
    fn geth_accepts_at(old: (u128, u128), new: (u128, u128), bump: u64) -> bool {
        let (old_cap, old_tip) = old;
        let (new_cap, new_tip) = new;
        if old_cap >= new_cap || old_tip >= new_tip {
            return false;
        }
        let pct = 100 + u128::from(bump);
        new_cap >= old_cap * pct / 100 && new_tip >= old_tip * pct / 100
    }

    /// A node run with a stricter `--txpool.pricebump` (30 here) needs both fees that much
    /// higher: the bump is the caller's (the chain's configured one), not a constant, and
    /// every replacement it signs is one that node takes.
    #[test]
    fn replacement_fees_follow_the_configured_price_bump() {
        assert_eq!(replacement_fees(100, 10, 129, 30), None, "under 30%");
        assert_eq!(replacement_fees(100, 10, 130, 30), Some((130, 13)));
        assert_eq!(
            replacement_fees(100, 10, 101, 0),
            Some((101, 11)),
            "no bump: strictly more"
        );
        assert_eq!(replacement_fees(100, 10, 499, 400), None);
        assert_eq!(replacement_fees(100, 10, 500, 400), Some((500, 50)));
        for bump in [0u64, 1, 10, 25, 30, 100, 400] {
            for (old_cap, old_tip) in [
                (7u128, 1u128),
                (1_000_000_007, 300_000_000),
                (3_000_000_000, 3_000_000_000),
            ] {
                for target in [
                    old_cap,
                    old_cap * 11 / 10,
                    old_cap * 13 / 10,
                    old_cap * 2,
                    old_cap * 6,
                ] {
                    match replacement_fees(old_cap, old_tip, target, bump) {
                        Some((cap, tip)) => {
                            assert!(
                                geth_accepts_at((old_cap, old_tip), (cap, tip), bump),
                                "{bump} {old_cap} {old_tip} {target}"
                            );
                            assert!(cap <= target && tip <= cap);
                        }
                        None => assert!(
                            !geth_accepts_at((old_cap, old_tip), (target, target), bump),
                            "refused a target the node takes: {bump} {old_cap} {old_tip} {target}"
                        ),
                    }
                }
            }
        }
    }

    /// The backend signs a replacement only past the bump it is given: 3.8 gwei over 3 gwei
    /// clears geth's default 10% but not a 30% node's, and 3.9 gwei clears both.
    #[tokio::test]
    async fn claim_replacement_takes_the_price_bump_it_is_given() {
        let (_server, _node, backend) = relay_backend().await;
        let htlc = claimable_by(&backend);
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        assert!(backend
            .build_claim_replacement(&first, 3_800_000_000, 10)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            backend
                .build_claim_replacement(&first, 3_800_000_000, 30)
                .await
                .unwrap(),
            None
        );
        let next = backend
            .build_claim_replacement(&first, 3_900_000_000, 30)
            .await
            .unwrap()
            .expect("30% over");
        let (old, new) = (decoded(&first), decoded(&next));
        use alloy::consensus::Transaction as _;
        assert!(geth_accepts_at(
            (
                old.max_fee_per_gas(),
                old.max_priority_fee_per_gas().unwrap()
            ),
            (
                new.max_fee_per_gas(),
                new.max_priority_fee_per_gas().unwrap()
            ),
            30
        ));
    }

    /// Devnet check of the same-nonce replacement against a real txpool: foundry's `anvil`
    /// on 127.0.0.1 with its own dev accounts (no funds, no secrets, no public RPC), started
    /// with `--no-mining` so the claim and its replacement meet in the pool. A 10%
    /// replacement is taken at the same nonce and evicts the original; rebroadcasting the
    /// original (same nonce, lower fees) is then refused "replacement transaction
    /// underpriced" and the replacement is the one mined. Anvil 1.8.6 has no percentage
    /// bump (it takes any strictly higher fee, even +1%), so geth's 10% floor is covered by
    /// the unit tests above, not here. The "HTLC" is an empty address, so the call costs plain gas and needs
    /// no contract build. Ignored by default: needs `anvil` on `PATH` (foundry installs it
    /// under `~/.foundry/bin`); run with
    /// `PATH=$HOME/.foundry/bin:$PATH cargo test -p swap-chain-evm --lib anvil_ -- --ignored`.
    #[tokio::test]
    #[ignore = "needs foundry's anvil on PATH"]
    async fn anvil_txpool_takes_a_same_nonce_replacement_and_refuses_an_underpriced_one() {
        use alloy::consensus::Transaction as _;
        let anvil = alloy::node_bindings::Anvil::new()
            .arg("--no-mining")
            .spawn();
        let key = PrivateKeySigner::from(&anvil.keys()[0]);
        let backend = UsdcBackend::new(
            &anvil.endpoint(),
            key,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap();
        let htlc = claimable_by(&backend);
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        assert_eq!(backend.broadcast(&first).await.unwrap(), first.txid);
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), Some(0));

        let next = backend
            .build_claim_replacement(&first, 3_300_000_000, 10)
            .await
            .unwrap()
            .expect("10% over");
        assert_eq!(decoded(&next).nonce(), decoded(&first).nonce());
        assert_eq!(backend.broadcast(&next).await.unwrap(), next.txid);
        assert_eq!(backend.confirmations(&next.txid).await.unwrap(), Some(0));
        assert_eq!(
            backend.confirmations(&first.txid).await.unwrap(),
            None,
            "the replacement evicted the original"
        );

        // The taker's rebroadcast of an older version: same nonce, lower fees than the
        // pool's. Refused, and the pool keeps the replacement.
        let err = backend.broadcast(&first).await.unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("replacement transaction underpriced"),
            "{err}"
        );
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), None);
        assert_eq!(backend.confirmations(&next.txid).await.unwrap(), Some(0));

        backend
            .client
            .provider()
            .raw_request::<_, alloy::primitives::U256>("evm_mine".into(), ())
            .await
            .expect("evm_mine");
        assert_eq!(backend.confirmations(&next.txid).await.unwrap(), Some(1));
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), None);
    }

    /// `geth --dev` on 127.0.0.1 for the geth devnet check: no discovery, no peers, no IPC,
    /// HTTP on loopback only, the chain in `dir`. `period` 0 seals a block per transaction;
    /// a long period leaves sent transactions in the pool.
    fn spawn_geth_dev(dir: &std::path::Path, port: u16, period: u32) -> GethDev {
        let child = std::process::Command::new("geth")
            .args(["--dev", "--dev.period", &period.to_string(), "--datadir"])
            .arg(dir)
            .args([
                "--nodiscover",
                "--maxpeers",
                "0",
                "--ipcdisable",
                "--port",
                "0",
            ])
            .args([
                "--http",
                "--http.addr",
                "127.0.0.1",
                "--http.port",
                &port.to_string(),
            ])
            .args(["--http.api", "eth,net,web3,txpool"])
            .args(["--authrpc.addr", "127.0.0.1", "--authrpc.port", "0"])
            .args(["--verbosity", "1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("geth on PATH");
        GethDev(Some(child))
    }

    /// A running `geth --dev`, stopped with SIGTERM (so its chain is flushed to the datadir)
    /// and, if it lingers, killed, when dropped.
    struct GethDev(Option<std::process::Child>);

    impl Drop for GethDev {
        fn drop(&mut self) {
            let Some(mut child) = self.0.take() else {
                return;
            };
            let _ = std::process::Command::new("kill")
                .arg(child.id().to_string())
                .status();
            for _ in 0..100 {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Wait until the node at `backend` answers.
    async fn wait_for_rpc(backend: &UsdcBackend) {
        for _ in 0..100 {
            if backend.client.provider().get_chain_id().await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("geth --dev never answered");
    }

    /// Devnet check of geth's replacement rule itself (`list.Add`, `--txpool.pricebump`
    /// 10): an ephemeral `geth --dev` on 127.0.0.1 (no discovery, `--maxpeers 0`, no public
    /// network), its chain in a temp datadir removed with the test. First run: seal a
    /// block per transaction and fund dev key 0 from the dev account. Second run on the same
    /// datadir: a one-hour block period, so the claim and its replacements meet in the pool.
    /// A +1% same-nonce replacement is refused "replacement transaction underpriced" and the
    /// claim stays; a +10% one is taken and evicts it. Ignored by default: needs `geth` on
    /// `PATH`; run with
    /// `PATH=$HOME/.geth/bin:$PATH cargo test -p swap-chain-evm --lib geth_ -- --ignored`.
    #[tokio::test]
    #[ignore = "needs geth on PATH"]
    async fn geth_dev_txpool_refuses_a_one_percent_replacement_and_takes_ten_percent() {
        use alloy::consensus::Transaction as _;
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let endpoint = format!("http://127.0.0.1:{port}");
        let key: PrivateKeySigner =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
                .parse()
                .unwrap();
        let backend = UsdcBackend::new(
            &endpoint,
            key,
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
        )
        .unwrap();
        let provider = backend.client.provider();

        {
            let _geth = spawn_geth_dev(dir.path(), port, 0);
            wait_for_rpc(&backend).await;
            let dev: Vec<Address> = provider
                .raw_request("eth_accounts".into(), ())
                .await
                .expect("eth_accounts");
            let fund = TransactionRequest {
                from: Some(dev[0]),
                to: Some(backend.address().into()),
                value: Some(U256::from(10u128.pow(18))),
                ..Default::default()
            };
            let _: B256 = provider
                .raw_request("eth_sendTransaction".into(), (fund,))
                .await
                .expect("fund dev key 0");
            let mut funded = false;
            for _ in 0..100 {
                if provider.get_balance(backend.address()).await.unwrap() > U256::ZERO {
                    funded = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            assert!(funded, "dev key 0 never funded");
        }

        let _geth = spawn_geth_dev(dir.path(), port, 3600);
        wait_for_rpc(&backend).await;
        assert!(provider.get_balance(backend.address()).await.unwrap() > U256::ZERO);
        let htlc = claimable_by(&backend);
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        assert_eq!(backend.broadcast(&first).await.unwrap(), first.txid);
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), Some(0));

        let low = backend
            .build_claim_replacement(&first, 3_030_000_000, 1)
            .await
            .unwrap()
            .expect("1% clears a 1% bump");
        assert_eq!(decoded(&low).nonce(), decoded(&first).nonce());
        let err = backend.broadcast(&low).await.unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("replacement transaction underpriced"),
            "{err}"
        );
        assert_eq!(backend.confirmations(&low.txid).await.unwrap(), None);
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), Some(0));

        let next = backend
            .build_claim_replacement(&first, 3_300_000_000, 10)
            .await
            .unwrap()
            .expect("10% over");
        assert_eq!(decoded(&next).nonce(), decoded(&first).nonce());
        assert_eq!(backend.broadcast(&next).await.unwrap(), next.txid);
        assert_eq!(backend.confirmations(&next.txid).await.unwrap(), Some(0));
        assert_eq!(
            backend.confirmations(&first.txid).await.unwrap(),
            None,
            "the replacement evicted the original"
        );
    }

    /// The replacement's fees: the max fee is the target, the tip rises with it, and both
    /// clear geth's price bump; a target under the bump is refused (`None`), not raised past
    /// what the caller allowed. The tip never exceeds the max fee.
    #[test]
    fn replacement_fees_clear_geths_price_bump_within_the_target() {
        assert_eq!(replacement_fees(100, 10, 200, 10), Some((200, 20)));
        assert_eq!(replacement_fees(100, 10, 110, 10), Some((110, 11)));
        assert_eq!(
            replacement_fees(100, 10, 109, 10),
            None,
            "under 10% on the max fee"
        );
        assert_eq!(
            replacement_fees(100, 0, 200, 10),
            Some((200, 1)),
            "a zero tip still rises"
        );
        assert_eq!(replacement_fees(100, 9, 110, 10), Some((110, 10)));
        assert_eq!(replacement_fees(100, 100, 110, 10), Some((110, 110)));
        assert_eq!(
            replacement_fees(5, 1, 6, 10),
            Some((6, 2)),
            "wei-level: strictly more"
        );
        assert_eq!(replacement_fees(5, 5, 5, 10), None);
        for old_cap in [1u128, 7, 99, 1_000_000_007, 30_000_000_000] {
            for old_tip in [0, 1, old_cap / 3, old_cap] {
                for target in [
                    old_cap,
                    old_cap + 1,
                    old_cap * 11 / 10,
                    old_cap * 5 / 4,
                    old_cap * 3,
                ] {
                    match replacement_fees(old_cap, old_tip, target, 10) {
                        Some((cap, tip)) => {
                            assert!(
                                geth_accepts((old_cap, old_tip), (cap, tip)),
                                "{old_cap} {old_tip} {target}"
                            );
                            assert!(cap <= target && tip <= cap, "{old_cap} {old_tip} {target}");
                        }
                        None => assert!(
                            !geth_accepts((old_cap, old_tip), (target, target)),
                            "refused a target geth takes: {old_cap} {old_tip} {target}"
                        ),
                    }
                }
            }
        }
    }

    /// The same-nonce replacement of a claim re-signs the identical call (target, calldata,
    /// value, gas limit, chain id) at the claim's own nonce, though the node's pending count
    /// has moved past it, from the same key, with both fees raised. Before this, the only way
    /// to re-sign at a feerate was a fresh `pending` nonce: a second transaction behind the
    /// stuck one, not a replacement of it.
    #[tokio::test]
    async fn claim_replacement_keeps_the_call_and_nonce_and_raises_both_fees() {
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::consensus::Transaction as _;
        let (_server, node, backend) = relay_backend().await;
        assert_eq!(backend.fee_bump(), FeeBump::SameNonce);
        let htlc = claimable_by(&backend);
        assert_eq!(backend.claim_sizes(&htlc), None, "fee in ETH, leg in USDC");
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let estimate = backend.claim_feerate().await.unwrap().expect("a feerate");
        let plain = backend
            .build_claim(&htlc, &at, Amount(1_000_000), &[7; 32])
            .await
            .unwrap();
        assert_eq!(
            u64::try_from(decoded(&plain).max_fee_per_gas()).unwrap(),
            estimate
        );

        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        let old = decoded(&first);
        assert_eq!(old.max_fee_per_gas(), 3_000_000_000);
        assert!(old.max_priority_fee_per_gas().unwrap() <= 3_000_000_000);
        // The claim sits unmined: the pending count is past its nonce.
        node.nonces
            .pending_txs
            .store(1, std::sync::atomic::Ordering::SeqCst);

        let new = backend
            .build_claim_replacement(&first, 4_000_000_000, 10)
            .await
            .unwrap()
            .expect("25% over clears geth's 10%");
        let new = decoded(&new);
        assert_eq!(new.nonce(), old.nonce(), "same nonce");
        assert_eq!(new.nonce(), 5);
        assert_eq!(new.to(), old.to());
        assert_eq!(new.input(), old.input(), "identical call");
        assert_eq!(new.value(), old.value());
        assert_eq!(new.gas_limit(), old.gas_limit());
        assert_eq!(new.chain_id(), old.chain_id());
        assert_eq!(new.recover_signer().unwrap(), backend.address());
        assert_eq!(new.max_fee_per_gas(), 4_000_000_000);
        assert!(geth_accepts(
            (
                old.max_fee_per_gas(),
                old.max_priority_fee_per_gas().unwrap()
            ),
            (
                new.max_fee_per_gas(),
                new.max_priority_fee_per_gas().unwrap()
            ),
        ));
        assert_ne!(new.tx_hash(), old.tx_hash());

        // Under geth's bump within the target: nothing is signed.
        assert_eq!(
            backend
                .build_claim_replacement(&first, 3_200_000_000, 10)
                .await
                .unwrap(),
            None
        );
    }

    /// "replacement transaction underpriced" with the replacement unmined is a refusal of
    /// that transaction (the node holds another at its nonce), never success; the message
    /// says which refusal it was.
    #[tokio::test]
    async fn underpriced_replacement_is_rejected_not_success() {
        let (_server, node, backend) = relay_backend().await;
        let htlc = claimable_by(&backend);
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        let next = backend
            .build_claim_replacement(&first, 3_300_000_000, 10)
            .await
            .unwrap()
            .unwrap();
        *node.send_error.lock().unwrap() = Some("replacement transaction underpriced".into());
        let err = backend.broadcast(&next).await.unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
        assert!(err.to_string().contains("underpriced"), "{err}");
    }

    /// The original claim mined while its replacement was in flight: the replacement is
    /// refused ("nonce too low") and stays refused, while the original reads as confirmed,
    /// which is what the taker's check of replaced versions turns into success. And a nonce
    /// a different transaction took is a refusal; one this transaction took is success.
    #[tokio::test]
    async fn nonce_too_low_is_success_only_for_the_transaction_that_was_mined() {
        let (_server, node, backend) = relay_backend().await;
        let htlc = claimable_by(&backend);
        let at = Outpoint {
            txid: Txid([1; 32]),
            vout: 0,
        };
        let first = backend
            .build_claim_at(&htlc, &at, Amount(1_000_000), &[7; 32], 3_000_000_000)
            .await
            .unwrap();
        let next = backend
            .build_claim_replacement(&first, 4_000_000_000, 10)
            .await
            .unwrap()
            .unwrap();
        node.mined.lock().unwrap().push(B256::from(first.txid.0));
        *node.send_error.lock().unwrap() = Some("nonce too low: next nonce 6, tx nonce 5".into());

        let err = backend.broadcast(&next).await.unwrap_err();
        assert!(matches!(err, SwapError::Rejected(_)), "{err:?}");
        assert_eq!(backend.confirmations(&first.txid).await.unwrap(), Some(3));
        assert_eq!(backend.confirmations(&next.txid).await.unwrap(), None);
        assert_eq!(backend.broadcast(&first).await.unwrap(), first.txid);
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
