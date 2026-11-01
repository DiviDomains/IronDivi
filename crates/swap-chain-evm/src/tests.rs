// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

#[cfg(feature = "live")]
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::TransactionBuilder;
use alloy::node_bindings::Anvil;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;

use divi_swap::{Amount, ChainBackend, HtlcParams, Outpoint, Txid};

use crate::artifact::{bytecode, foundry_available};
use crate::client::{connect_provider, deploy_contract, swap_id};
use crate::contract::IMockErc20;
use crate::{EvmHtlcClient, UsdcBackend};

/// Skip (rather than fail) a test that needs `forge`/`anvil` when neither is installed.
macro_rules! require_foundry {
    () => {
        if !foundry_available() {
            eprintln!("skipping: forge/anvil not found on PATH");
            return;
        }
    };
}

struct Fixture {
    _anvil: alloy::node_bindings::AnvilInstance,
    sender: EvmHtlcClient,
    receiver: EvmHtlcClient,
    token: Address,
}

async fn setup(initial_mint: U256) -> Fixture {
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();

    // Anvil's own dev accounts (genesis-funded with 10000 ETH each) — avoids hardcoding
    // the well-known default mnemonic's derived keys.
    let sender_key = PrivateKeySigner::from(&anvil.keys()[0]);
    let receiver_key = PrivateKeySigner::from(&anvil.keys()[1]);
    let sender_address = sender_key.address();
    let receiver_address = receiver_key.address();

    let deploy_provider = connect_provider(&endpoint, sender_key.clone()).expect("provider");
    let token_bytes = bytecode("MockErc20").expect("build MockErc20");
    let token = deploy_contract(&deploy_provider, token_bytes)
        .await
        .expect("deploy MockErc20");
    let htlc_bytes = bytecode("Erc20Htlc").expect("build Erc20Htlc");
    let htlc = deploy_contract(&deploy_provider, htlc_bytes)
        .await
        .expect("deploy Erc20Htlc");

    IMockErc20::new(token, deploy_provider.clone())
        .mint(sender_address, initial_mint)
        .send()
        .await
        .expect("send mint")
        .get_receipt()
        .await
        .expect("mint receipt");

    let sender_provider = connect_provider(&endpoint, sender_key).expect("sender provider");
    let receiver_provider = connect_provider(&endpoint, receiver_key).expect("receiver provider");
    let sender = EvmHtlcClient::new(sender_provider, sender_address, htlc);
    let receiver = EvmHtlcClient::new(receiver_provider, receiver_address, htlc);

    Fixture {
        _anvil: anvil,
        sender,
        receiver,
        token,
    }
}

fn future_timelock(secs_from_now: u64) -> U256 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    U256::from(now + secs_from_now)
}

/// Schedule `unix_ts` as the next block's timestamp; the next transaction's auto-mined
/// block carries it (no separate `evm_mine` — anvil's base-fee bookkeeping after an
/// explicit empty-block mine left follow-up transactions stuck pending in testing).
async fn mine_to(provider: &alloy::providers::DynProvider, unix_ts: U256) {
    provider
        .raw_request::<_, ()>("evm_setNextBlockTimestamp".into(), (unix_ts.to::<u64>(),))
        .await
        .expect("evm_setNextBlockTimestamp");
}

fn hashlock_for(preimage: B256) -> B256 {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(preimage.as_slice()).into();
    B256::from(digest)
}

/// `UsdcBackend::gas_and_token_balance` — divi-swapd's own funding gate reads this before
/// deciding whether to serve a usdc offer, so it has to report real numbers, not anvil's
/// own genesis balance for an account nobody touched.
#[tokio::test]
async fn gas_and_token_balance_reports_eth_and_minted_usdc() {
    require_foundry!();
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    let key = PrivateKeySigner::from(&anvil.keys()[0]);
    let address = key.address();
    let deploy_provider = connect_provider(&endpoint, key.clone()).expect("deploy provider");
    let htlc = deploy_contract(&deploy_provider, bytecode("Erc20Htlc").expect("build htlc"))
        .await
        .expect("deploy htlc");
    let token = deploy_contract(
        &deploy_provider,
        bytecode("MockErc20").expect("build token"),
    )
    .await
    .expect("deploy token");
    IMockErc20::new(token, deploy_provider.clone())
        .mint(address, U256::from(5_000_000u64))
        .send()
        .await
        .expect("send mint")
        .get_receipt()
        .await
        .expect("mint receipt");

    let backend = UsdcBackend::new(&endpoint, key, htlc, token).expect("backend");
    let (eth, usdc) = backend
        .gas_and_token_balance()
        .await
        .expect("gas_and_token_balance");
    assert!(eth > U256::ZERO, "anvil dev accounts start funded with ETH");
    assert_eq!(usdc, U256::from(5_000_000u64));
}

#[tokio::test]
async fn swap_id_matches_contract() {
    require_foundry!();
    let fx = setup(U256::from(1_000_000u64)).await;
    let amount = U256::from(100u64);
    let preimage = B256::from(keccak256(b"swap_id_matches_contract"));
    let hashlock = hashlock_for(preimage);
    let timelock = future_timelock(3600);

    let local = swap_id(
        fx.sender.address(),
        fx.receiver.address(),
        fx.token,
        amount,
        hashlock,
        timelock,
    );

    let on_chain = fx
        .sender
        .lock(fx.token, amount, fx.receiver.address(), hashlock, timelock)
        .await
        .expect("lock");

    assert_eq!(local, on_chain);
    let state = fx.sender.swap_state(on_chain).await.expect("swap_state");
    assert!(state.exists());
    assert_eq!(state.sender, fx.sender.address());
    assert_eq!(state.amount, amount);
}

#[tokio::test]
async fn anvil_lock_claim() {
    require_foundry!();
    let fx = setup(U256::from(1_000_000u64)).await;
    let amount = U256::from(250u64);
    let preimage = B256::from(keccak256(b"anvil_lock_claim"));
    let hashlock = hashlock_for(preimage);
    let timelock = future_timelock(3600);

    let id = fx
        .sender
        .lock(fx.token, amount, fx.receiver.address(), hashlock, timelock)
        .await
        .expect("lock");

    fx.receiver.claim(id, preimage).await.expect("claim");

    let state = fx.sender.swap_state(id).await.expect("swap_state");
    assert!(state.claimed);
    assert!(!state.refunded);
    let balance = fx
        .sender
        .token_balance(fx.token, fx.receiver.address())
        .await
        .expect("balanceOf receiver");
    assert_eq!(balance, amount);
}

#[tokio::test]
async fn anvil_lock_refund() {
    require_foundry!();
    let fx = setup(U256::from(1_000_000u64)).await;
    let amount = U256::from(400u64);
    let preimage = B256::from(keccak256(b"anvil_lock_refund"));
    let hashlock = hashlock_for(preimage);
    // Far enough out that locking (two real transactions) can't race past it before the
    // "refund too early" assertion below; `mine_to` then jumps the chain clock to it.
    let timelock = future_timelock(30);

    let id = fx
        .sender
        .lock(fx.token, amount, fx.receiver.address(), hashlock, timelock)
        .await
        .expect("lock");

    // Refund before maturity is rejected.
    let early = fx.sender.refund(id).await;
    assert!(early.is_err(), "refund before timelock must fail");

    mine_to(fx.sender.provider(), timelock).await;

    fx.sender.refund(id).await.expect("refund");

    let state = fx.sender.swap_state(id).await.expect("swap_state");
    assert!(state.refunded);
    assert!(!state.claimed);
}

#[tokio::test]
async fn anvil_find_preimage_from_logs() {
    require_foundry!();
    let fx = setup(U256::from(1_000_000u64)).await;
    let amount = U256::from(10u64);
    let preimage = B256::from(keccak256(b"anvil_find_preimage_from_logs"));
    let hashlock = hashlock_for(preimage);
    let timelock = future_timelock(3600);

    let id = fx
        .sender
        .lock(fx.token, amount, fx.receiver.address(), hashlock, timelock)
        .await
        .expect("lock");

    assert_eq!(fx.sender.find_preimage(id).await.expect("find"), None);

    fx.receiver.claim(id, preimage).await.expect("claim");

    let found = fx.sender.find_preimage(id).await.expect("find after claim");
    assert_eq!(found, Some(preimage));
}

/// Deploy, mint, lock (sender == receiver == `backend`'s own key, which is fine for a
/// refund: `build_funding`/`build_refund` only ever check `sender == self`) and jump the
/// chain clock past a short timelock — a real, refundable swap, so `build_refund`'s own
/// `estimate_gas` call does not itself revert ("no such swap") before these tests ever get
/// to exercise `broadcast`'s nonce handling.
async fn locked_and_refundable(
    deploy_provider: &alloy::providers::DynProvider,
    backend: &UsdcBackend,
    address: Address,
    token: Address,
) -> (HtlcParams, Outpoint, Amount) {
    let pk = backend.pubkey();
    let hash: [u8; 32] = B256::from(keccak256(b"nonce_conflict_test")).0;
    let locktime = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        + 30) as u32;
    let params = HtlcParams {
        hash,
        claim_pubkey: pk,
        refund_pubkey: pk,
        locktime,
    };
    let amount = Amount::from_sat(100); // 1 USDC base unit (100 engine sats / 100 per unit)

    IMockErc20::new(token, deploy_provider.clone())
        .mint(address, U256::from(1u64))
        .send()
        .await
        .expect("send mint")
        .get_receipt()
        .await
        .expect("mint receipt");

    let outpoint = Outpoint {
        txid: Txid([0u8; 32]),
        vout: 0,
    };
    let funding = backend
        .build_funding(&params, amount)
        .await
        .expect("build_funding");
    // `backend.broadcast` only submits; it does not wait for a receipt. Wait for one here
    // (via a plain provider, not `backend`'s own) so the lock is actually mined before the
    // tests that call this build a refund against it — `build_refund`'s own `estimate_gas`
    // would otherwise revert "no such swap" on a race.
    deploy_provider
        .send_raw_transaction(&funding.tx.raw)
        .await
        .expect("send lock")
        .get_receipt()
        .await
        .expect("lock receipt");

    mine_to(deploy_provider, U256::from(locktime)).await;
    (params, outpoint, amount)
}

/// `is_nonce_conflict`'s safe case: our own earlier broadcast already mined (same hash),
/// and we are asked to rebroadcast the identical bytes again — the write-ahead engine does
/// exactly this on every tick until it sees a confirmation. The node reports this as a
/// nonce conflict once the tx has left the mempool (it is no longer "already known" by
/// hash, just "nonce too low" against a nonce the chain has moved past) — `broadcast` must
/// still report success, by finding its own receipt.
#[tokio::test]
async fn broadcast_is_idempotent_once_its_own_tx_has_mined() {
    require_foundry!();
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    let key = PrivateKeySigner::from(&anvil.keys()[0]);
    let address = key.address();
    let deploy_provider = connect_provider(&endpoint, key.clone()).expect("deploy provider");
    let htlc = deploy_contract(&deploy_provider, bytecode("Erc20Htlc").expect("build htlc"))
        .await
        .expect("deploy htlc");
    let token = deploy_contract(
        &deploy_provider,
        bytecode("MockErc20").expect("build token"),
    )
    .await
    .expect("deploy token");

    let backend = UsdcBackend::new(&endpoint, key, htlc, token).expect("backend");
    let (params, outpoint, amount) =
        locked_and_refundable(&deploy_provider, &backend, address, token).await;
    let refund = backend
        .build_refund(&params, &outpoint, amount)
        .await
        .expect("build_refund");

    let first = backend.broadcast(&refund).await.expect("first broadcast");
    assert_eq!(first, refund.txid);
    // Resend the identical signed bytes now that they have already mined.
    let second = backend
        .broadcast(&refund)
        .await
        .expect("rebroadcast of an already-mined tx must still report success");
    assert_eq!(second, refund.txid);
}

/// `is_nonce_conflict`'s *unsafe* case: a different transaction — not ours — took the nonce
/// our signed-but-not-yet-sent transaction was built against (a stale read from a
/// load-balanced public RPC, or, against this lane's own rules, the same key in use by a
/// second process at once). Before the fix in this wave, `is_already_known` folded "nonce
/// too low" into unconditional success, so `broadcast` would have returned `Ok(refund.txid)`
/// here even though `refund.txid` can now never be mined — the engine would then poll
/// `confirmations(&refund.txid)` forever and the swap would never leave `MakerRefundable`/
/// `TakerClaimed`. `broadcast` must surface an error instead.
#[tokio::test]
async fn broadcast_errors_when_a_different_tx_stole_the_nonce() {
    require_foundry!();
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    let key = PrivateKeySigner::from(&anvil.keys()[0]);
    let address = key.address();
    let deploy_provider = connect_provider(&endpoint, key.clone()).expect("deploy provider");
    let htlc = deploy_contract(&deploy_provider, bytecode("Erc20Htlc").expect("build htlc"))
        .await
        .expect("deploy htlc");
    let token = deploy_contract(
        &deploy_provider,
        bytecode("MockErc20").expect("build token"),
    )
    .await
    .expect("deploy token");

    let backend = UsdcBackend::new(&endpoint, key.clone(), htlc, token).expect("backend");
    let (params, outpoint, amount) =
        locked_and_refundable(&deploy_provider, &backend, address, token).await;
    // Signed, but not yet sent: the mempool does not know about it yet, so the next query
    // for this account's pending nonce still returns the same value `refund` was signed
    // with.
    let refund = backend
        .build_refund(&params, &outpoint, amount)
        .await
        .expect("build_refund");

    // A second, unrelated transaction from the same key, sent (and auto-mined by anvil)
    // through the normal auto-filling path — it gets the same nonce `refund` was signed
    // with, and lands first.
    let stealer = connect_provider(&endpoint, key).expect("stealer provider");
    stealer
        .send_transaction(
            TransactionRequest::default()
                .with_to(address)
                .with_value(U256::ZERO),
        )
        .await
        .expect("send stealer tx")
        .get_receipt()
        .await
        .expect("stealer receipt");

    let err = backend
        .broadcast(&refund)
        .await
        .expect_err("a stolen nonce must not be reported as success");
    assert!(
        err.to_string().contains("never mined"),
        "wrong error: {err}"
    );
}

/// Live Sepolia run: deploys a fresh `Erc20Htlc`, locks a tiny amount of Circle test USDC
/// to itself, and claims it back. Needs Sepolia ETH for gas and test USDC in the key's
/// balance (`faucet.circle.com` / a Sepolia ETH faucet) — the orchestrator runs this from
/// the Mac with a funded throwaway key; never run with a key holding real funds.
#[cfg(feature = "live")]
#[tokio::test]
#[ignore]
async fn live_sepolia_lock_claim() {
    let key_hex = std::env::var("SWAP_EVM_TEST_KEY_HEX").expect("SWAP_EVM_TEST_KEY_HEX not set");
    let rpc_url = std::env::var("SWAP_EVM_SEPOLIA_RPC")
        .unwrap_or_else(|_| "https://ethereum-sepolia-rpc.publicnode.com".to_string());
    let key = PrivateKeySigner::from_str(key_hex.trim()).expect("bad SWAP_EVM_TEST_KEY_HEX");
    let address = key.address();

    let provider = connect_provider(&rpc_url, key).expect("connect");
    let htlc_bytes = bytecode("Erc20Htlc").expect("build Erc20Htlc");
    let htlc_address = deploy_contract(&provider, htlc_bytes)
        .await
        .expect("deploy Erc20Htlc");
    let client = EvmHtlcClient::new(provider, address, htlc_address);

    let token = Address::from_str(crate::SEPOLIA_USDC).expect("USDC address");
    let amount = U256::from(1u64); // 0.000001 USDC (6 decimals) — smallest practical probe.
    let preimage = B256::from(keccak256(b"live_sepolia_lock_claim"));
    let hashlock = hashlock_for(preimage);
    let timelock = future_timelock(3600);

    let id = client
        .lock(token, amount, address, hashlock, timelock)
        .await
        .expect("lock on Sepolia");
    client.claim(id, preimage).await.expect("claim on Sepolia");

    let state = client.swap_state(id).await.expect("swap_state");
    assert!(state.claimed);
}

/// Same as [`live_sepolia_lock_claim`], against Base Sepolia instead: needs Base Sepolia ETH
/// for gas and Circle test USDC in the key's balance. Not run by `usdc-live.sh` today (no
/// Base Sepolia funding exists yet, per `docs/plans/swap-poc/funding.md`); kept in sync with
/// the Sepolia version so turning on Base Sepolia live needs no new test, only funding.
#[cfg(feature = "live")]
#[tokio::test]
#[ignore]
async fn live_base_sepolia_lock_claim() {
    let key_hex = std::env::var("SWAP_EVM_TEST_KEY_HEX").expect("SWAP_EVM_TEST_KEY_HEX not set");
    let rpc_url = std::env::var("SWAP_EVM_BASE_SEPOLIA_RPC").unwrap_or_else(|_| {
        crate::UsdcNetwork::BaseSepolia
            .default_rpc_url()
            .to_string()
    });
    let key = PrivateKeySigner::from_str(key_hex.trim()).expect("bad SWAP_EVM_TEST_KEY_HEX");
    let address = key.address();

    let provider = connect_provider(&rpc_url, key).expect("connect");
    let htlc_bytes = bytecode("Erc20Htlc").expect("build Erc20Htlc");
    let htlc_address = deploy_contract(&provider, htlc_bytes)
        .await
        .expect("deploy Erc20Htlc");
    let client = EvmHtlcClient::new(provider, address, htlc_address);

    let token = Address::from_str(crate::BASE_SEPOLIA_USDC).expect("USDC address");
    let amount = U256::from(1u64); // 0.000001 USDC (6 decimals) — smallest practical probe.
    let preimage = B256::from(keccak256(b"live_base_sepolia_lock_claim"));
    let hashlock = hashlock_for(preimage);
    let timelock = future_timelock(3600);

    let id = client
        .lock(token, amount, address, hashlock, timelock)
        .await
        .expect("lock on Base Sepolia");
    client
        .claim(id, preimage)
        .await
        .expect("claim on Base Sepolia");

    let state = client.swap_state(id).await.expect("swap_state");
    assert!(state.claimed);
}
