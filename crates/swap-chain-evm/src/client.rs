// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Thin alloy client over [`crate::contract::IErc20Htlc`]: deploy, lock (approve + lock),
//! claim, refund, read swap state, and recover the preimage from `Claimed` logs.

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;

use divi_swap::SwapError;

use crate::contract::{IErc20, IErc20Htlc};

type Result<T> = std::result::Result<T, SwapError>;

fn other<E: std::fmt::Display>(context: &str) -> impl FnOnce(E) -> SwapError + '_ {
    move |e| SwapError::Other(format!("{context}: {e}"))
}

/// On-chain state of one swap (the decoded `swaps(id)` getter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapState {
    /// Who locked the funds (refund destination).
    pub sender: Address,
    /// Who can claim with the preimage.
    pub receiver: Address,
    /// ERC-20 token address.
    pub token: Address,
    /// Amount in the token's smallest unit.
    pub amount: U256,
    /// SHA-256 of the swap preimage.
    pub hashlock: B256,
    /// Unix timestamp after which `sender` may refund.
    pub timelock: U256,
    /// Already paid to `receiver`.
    pub claimed: bool,
    /// Already returned to `sender`.
    pub refunded: bool,
}

impl SwapState {
    /// `true` when `sender` is the zero address, i.e. no swap was ever locked at this id.
    pub fn exists(&self) -> bool {
        self.sender != Address::ZERO
    }
}

/// `keccak256(abi.encode(sender, receiver, token, amount, hashlock, timelock))`, matching
/// `Erc20Htlc.swapId` exactly (`swap_id_matches_contract` cross-checks this against the
/// deployed contract).
pub fn swap_id(
    sender: Address,
    receiver: Address,
    token: Address,
    amount: U256,
    hashlock: B256,
    timelock: U256,
) -> B256 {
    let mut buf = Vec::with_capacity(6 * 32);
    for addr in [sender, receiver, token] {
        buf.extend_from_slice(&[0u8; 12]);
        buf.extend_from_slice(addr.as_slice());
    }
    buf.extend_from_slice(&amount.to_be_bytes::<32>());
    buf.extend_from_slice(hashlock.as_slice());
    buf.extend_from_slice(&timelock.to_be_bytes::<32>());
    keccak256(buf)
}

/// Build a provider that signs with `key` and sends to `rpc_url`.
///
/// Uses `SimpleNonceManager` (fetches the pending nonce fresh per send) rather than
/// alloy's default `CachedNonceManager`: a swap can legitimately send a transaction that
/// reverts (a stale `claim`/`refund` race, a wrong preimage), and the cached manager's
/// local nonce does not resynchronize after that, wedging every later send behind a gap
/// the chain never fills.
pub fn connect_provider(rpc_url: &str, key: PrivateKeySigner) -> Result<DynProvider> {
    let url = rpc_url
        .parse()
        .map_err(other::<_>(&format!("bad RPC URL {rpc_url:?}")))?;
    let wallet = EthereumWallet::from(key);
    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(wallet)
        .connect_http(url);
    Ok(DynProvider::new(provider))
}

/// Deploy raw `bytecode` (no constructor args) and return the new contract's address.
pub async fn deploy_contract(provider: &DynProvider, bytecode: Vec<u8>) -> Result<Address> {
    Ok(deploy_contract_with_tx(provider, bytecode).await?.0)
}

/// Same as [`deploy_contract`], also returning the deployment transaction's hash (e.g. to
/// print a block-explorer link for it).
pub async fn deploy_contract_with_tx(
    provider: &DynProvider,
    bytecode: Vec<u8>,
) -> Result<(Address, B256)> {
    let tx = TransactionRequest::default().with_deploy_code(Bytes::from(bytecode));
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(other::<_>("send deployment tx"))?;
    let receipt = pending
        .get_receipt()
        .await
        .map_err(other::<_>("await deployment receipt"))?;
    let address = receipt
        .contract_address
        .ok_or_else(|| SwapError::Other("deployment receipt lacks contract_address".into()))?;
    Ok((address, receipt.transaction_hash))
}

/// Client for one `Erc20Htlc` deployment, signing with one key.
#[derive(Debug, Clone)]
pub struct EvmHtlcClient {
    provider: DynProvider,
    address: Address,
    htlc: Address,
}

impl EvmHtlcClient {
    /// `htlc` is the deployed `Erc20Htlc` contract address.
    pub fn new(provider: DynProvider, address: Address, htlc: Address) -> Self {
        Self {
            provider,
            address,
            htlc,
        }
    }

    /// This client's own address (the key's address).
    pub fn address(&self) -> Address {
        self.address
    }

    /// The underlying provider, e.g. for `anvil_*` test-chain RPCs.
    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }

    /// The deployed `Erc20Htlc` contract address.
    pub fn htlc_address(&self) -> Address {
        self.htlc
    }

    fn htlc_contract(&self) -> IErc20Htlc::IErc20HtlcInstance<DynProvider> {
        IErc20Htlc::new(self.htlc, self.provider.clone())
    }

    fn erc20(&self, token: Address) -> IErc20::IErc20Instance<DynProvider> {
        IErc20::new(token, self.provider.clone())
    }

    /// `allowance(owner, spender)` on `token`.
    pub async fn token_allowance(
        &self,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<U256> {
        self.erc20(token)
            .allowance(owner, spender)
            .call()
            .await
            .map_err(other::<_>("call allowance"))
    }

    /// `approve(htlc, amount)` on `token`, then `lock(token, amount, receiver, hashlock,
    /// timelock)`. Returns the swap id from the `Locked` log.
    pub async fn lock(
        &self,
        token: Address,
        amount: U256,
        receiver: Address,
        hashlock: B256,
        timelock: U256,
    ) -> Result<B256> {
        self.erc20(token)
            .approve(self.htlc, amount)
            .send()
            .await
            .map_err(other::<_>("send approve"))?
            .get_receipt()
            .await
            .map_err(other::<_>("await approve receipt"))?;

        let receipt = self
            .htlc_contract()
            .lock(token, amount, receiver, hashlock, timelock)
            .send()
            .await
            .map_err(other::<_>("send lock"))?
            .get_receipt()
            .await
            .map_err(other::<_>("await lock receipt"))?;

        for log in receipt.inner.logs() {
            if let Ok(decoded) = log.log_decode::<IErc20Htlc::Locked>() {
                return Ok(decoded.inner.data.id);
            }
        }
        Err(SwapError::Other(
            "lock receipt did not contain a Locked event".into(),
        ))
    }

    /// `claim(id, preimage)`.
    pub async fn claim(&self, id: B256, preimage: B256) -> Result<()> {
        self.htlc_contract()
            .claim(id, preimage)
            .send()
            .await
            .map_err(other::<_>("send claim"))?
            .get_receipt()
            .await
            .map_err(other::<_>("await claim receipt"))?;
        Ok(())
    }

    /// `refund(id)`.
    pub async fn refund(&self, id: B256) -> Result<()> {
        self.htlc_contract()
            .refund(id)
            .send()
            .await
            .map_err(other::<_>("send refund"))?
            .get_receipt()
            .await
            .map_err(other::<_>("await refund receipt"))?;
        Ok(())
    }

    /// Read `swaps(id)`.
    pub async fn swap_state(&self, id: B256) -> Result<SwapState> {
        let r = self
            .htlc_contract()
            .swaps(id)
            .call()
            .await
            .map_err(other::<_>("call swaps"))?;
        Ok(SwapState {
            sender: r.sender,
            receiver: r.receiver,
            token: r.token,
            amount: r.amount,
            hashlock: r.hashlock,
            timelock: r.timelock,
            claimed: r.claimed,
            refunded: r.refunded,
        })
    }

    /// `balanceOf(account)` on `token`.
    pub async fn token_balance(&self, token: Address, account: Address) -> Result<U256> {
        self.erc20(token)
            .balanceOf(account)
            .call()
            .await
            .map_err(other::<_>("call balanceOf"))
    }

    /// Scan `Claimed` logs for `id` and return the preimage, if the swap has been claimed.
    pub async fn find_preimage(&self, id: B256) -> Result<Option<B256>> {
        let filter = Filter::new()
            .address(self.htlc)
            .event_signature(IErc20Htlc::Claimed::SIGNATURE_HASH)
            .from_block(0)
            .to_block(alloy::eips::BlockNumberOrTag::Latest);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(other::<_>("get_logs Claimed"))?;
        for log in logs {
            let decoded = log
                .log_decode::<IErc20Htlc::Claimed>()
                .map_err(other::<_>("decode Claimed"))?;
            if decoded.inner.data.id == id {
                return Ok(Some(decoded.inner.data.preimage));
            }
        }
        Ok(None)
    }
}
