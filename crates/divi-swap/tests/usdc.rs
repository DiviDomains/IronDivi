// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! DIVI against USDC, both directions, against a real [`UsdcBackend`] over a spawned
//! `anvil` instance (not `MockChain`) for the counter leg — exercises the account-chain
//! `ChainBackend` impl and the engine-sats ↔ USDC-base-units conversion end to end.
//! Skips with a message if `forge`/`anvil` are not on `PATH`.

use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider};

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::MockChain;
use divi_swap::{
    Amount, Chain, ChainBackend, Maker, Profile, Store, SwapConfig, SwapState, Taker, TakerState,
};
use swap_chain_evm::{
    bytecode, connect_provider, deploy_contract, foundry_available, IErc20, IMockErc20,
    PrivateKeySigner, UsdcBackend,
};

const T0: u32 = 1_800_000_000;
const DIVI_FUNDS: u64 = 20_000_000_000;
/// 0.1 "coin" in engine sats — a whole number of USDC base units (100_000, i.e. 0.1 USDC)
/// so the conversion in `UsdcBackend` never has to reject it.
const COUNTER_ENGINE_SATS: u64 = 10_000_000;
const USDC_MINT: u64 = 10_000_000; // 10 USDC base units' worth, well over what one swap needs

macro_rules! require_foundry {
    () => {
        if !foundry_available() {
            eprintln!("skipping: forge/anvil not found on PATH");
            return;
        }
    };
}

struct World {
    _anvil: alloy::node_bindings::AnvilInstance,
    chain_provider: DynProvider,
    divi: MockChain,
    maker_divi: divi_swap::mock::MockBackend,
    taker_divi: divi_swap::mock::MockBackend,
    maker_usdc: Arc<dyn ChainBackend>,
    taker_usdc: Arc<dyn ChainBackend>,
    token: Address,
    maker_usdc_addr: Address,
    taker_usdc_addr: Address,
}

async fn setup() -> World {
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();

    let deployer = PrivateKeySigner::from(&anvil.keys()[0]);
    let maker_key = PrivateKeySigner::from(&anvil.keys()[1]);
    let taker_key = PrivateKeySigner::from(&anvil.keys()[2]);
    let maker_usdc_addr = maker_key.address();
    let taker_usdc_addr = taker_key.address();

    let deploy_provider = connect_provider(&endpoint, deployer).expect("deploy provider");
    let token = deploy_contract(
        &deploy_provider,
        bytecode("MockErc20").expect("build token"),
    )
    .await
    .expect("deploy token");
    let htlc = deploy_contract(&deploy_provider, bytecode("Erc20Htlc").expect("build htlc"))
        .await
        .expect("deploy htlc");

    for addr in [maker_usdc_addr, taker_usdc_addr] {
        IMockErc20::new(token, deploy_provider.clone())
            .mint(addr, U256::from(USDC_MINT))
            .send()
            .await
            .expect("send mint")
            .get_receipt()
            .await
            .expect("mint receipt");
    }

    let maker_usdc = UsdcBackend::new(&endpoint, maker_key, htlc, token).expect("maker backend");
    let taker_usdc = UsdcBackend::new(&endpoint, taker_key, htlc, token).expect("taker backend");

    let divi = MockChain::new(Chain::Divi, T0, 60);
    World {
        maker_divi: divi.backend(1, Amount(DIVI_FUNDS)),
        taker_divi: divi.backend(2, Amount(DIVI_FUNDS)),
        divi,
        maker_usdc: Arc::new(maker_usdc),
        taker_usdc: Arc::new(taker_usdc),
        chain_provider: deploy_provider,
        token,
        maker_usdc_addr,
        taker_usdc_addr,
        _anvil: anvil,
    }
}

/// Mine one anvil block: nothing else drives block production, and the engine requires
/// `SwapConfig::chain_params(Chain::Usdc).confirmations` beyond the lock/claim/refund tx's
/// own auto-mined block.
async fn mine_usdc_block(provider: &DynProvider) {
    provider
        .raw_request::<_, String>("evm_mine".into(), ())
        .await
        .expect("evm_mine");
}

/// Jump anvil's clock `secs_forward` past its current latest block, so the next mined
/// block (and every one after) carries it. Cheap and instant — no real waiting.
async fn jump_usdc_time(provider: &DynProvider, secs_forward: u64) {
    let latest = provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await
        .expect("get latest block")
        .expect("latest block exists");
    let target = latest.header.timestamp + secs_forward;
    provider
        .raw_request::<_, ()>("evm_setNextBlockTimestamp".into(), (target,))
        .await
        .expect("evm_setNextBlockTimestamp");
}

async fn usdc_balance(provider: &DynProvider, token: Address, account: Address) -> U256 {
    IErc20::new(token, provider.clone())
        .balanceOf(account)
        .call()
        .await
        .expect("balanceOf")
}

fn offer(dir: Direction) -> Offer {
    Offer {
        id: "o".into(),
        direction: dir,
        counter_chain: Chain::Usdc,
        divi_sats_per_btc: 50_000_000_000,
        min_btc_sats: 1_000,
        max_btc_sats: 50_000_000,
    }
}

/// Quote → accept → lock → claim → claim, DIVI on `MockChain`, USDC on a real `UsdcBackend`
/// over anvil, until both sides are `Done`.
async fn full_swap(dir: Direction) {
    require_foundry!();
    let w = setup().await;
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.maker_divi.clone()),
        w.maker_usdc.clone(),
        store.clone(),
        vec![offer(dir)],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(w.taker_divi.clone()),
        w.taker_usdc.clone(),
        store.clone(),
    );

    let quote = maker.quote("o", COUNTER_ENGINE_SATS).await.unwrap();
    assert_eq!(quote.counter_chain, Chain::Usdc);
    let (tid, req) = taker.prepare(&quote).await.unwrap();
    let view = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &view).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&view.id, notice).await.unwrap().id;

    for _ in 0..120 {
        maker.tick().await.unwrap();
        let v = maker.view(&mid).unwrap();
        let _ = taker.step(&tid, v.as_ref()).await;
        w.divi.mine(1);
        mine_usdc_block(&w.chain_provider).await;
        let m = store.get_maker_swap(&mid).unwrap().unwrap().state;
        let t = store.get_taker_swap(&tid).unwrap().unwrap().state;
        if m == SwapState::Done && t == TakerState::Done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let m = store.get_maker_swap(&mid).unwrap().unwrap();
    let t = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!((m.state, t.state), (SwapState::Done, TakerState::Done));
    assert!(m.preimage.is_some());

    // The USDC leg actually moved on chain, by exactly the quoted amount (the engine-sats
    // <-> USDC-base-units conversion round-tripped exactly): the claimant's balance grew by
    // the counter amount's base units, net of nothing (the contract takes no fee).
    let counter_units = COUNTER_ENGINE_SATS / 100; // engine sats are 1e8/coin, USDC is 1e6/coin
    let (usdc_claimant, divi_claimant) = match dir {
        Direction::TakerPaysBtc => (w.maker_usdc_addr, &w.taker_divi),
        Direction::TakerPaysDivi => (w.taker_usdc_addr, &w.maker_divi),
    };
    let got_usdc = usdc_balance(&w.chain_provider, w.token, usdc_claimant).await;
    assert_eq!(got_usdc, U256::from(USDC_MINT + counter_units));
    let divi_amount = quote.divi_amount.to_sat();
    assert_eq!(
        w.divi.balance(&divi_claimant.pubkey()).0,
        DIVI_FUNDS + divi_amount - 1_000 // MockChain's flat claim fee
    );
}

#[tokio::test]
async fn usdc_swap_forward() {
    full_swap(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn usdc_swap_reverse() {
    full_swap(Direction::TakerPaysDivi).await;
}

/// Taker never claims: both legs time out and both sides refund, through the real
/// `UsdcBackend`'s `build_refund`/`broadcast` path (never exercised by the happy-path
/// tests above, which only reach `build_claim`).
async fn refund_swap(dir: Direction) {
    require_foundry!();
    let w = setup().await;
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(w.maker_divi.clone()),
        w.maker_usdc.clone(),
        store.clone(),
        vec![offer(dir)],
    )
    .unwrap();
    let taker = Taker::new(
        Arc::new(w.taker_divi.clone()),
        w.taker_usdc.clone(),
        store.clone(),
    );

    let quote = maker.quote("o", COUNTER_ENGINE_SATS).await.unwrap();
    let (tid, req) = taker.prepare(&quote).await.unwrap();
    let view = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &view).await.unwrap();
    // Broadcasts the taker's own funding directly; never call `taker.step` below until
    // after the time jump, so the taker never gets a chance to see the maker's leg
    // confirmed in time to claim it.
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&view.id, notice).await.unwrap().id;

    for _ in 0..60 {
        maker.tick().await.unwrap();
        w.divi.mine(1);
        mine_usdc_block(&w.chain_provider).await;
        if store.get_maker_swap(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        store.get_maker_swap(&mid).unwrap().unwrap().state,
        SwapState::MakerLockConfirmed,
        "maker leg never confirmed"
    );

    // Jump both chains' clocks past every timeout at once (taker's is the longer one), so
    // from here on neither side can claim safely — each independently decides to refund.
    let jump = SwapConfig::profile(Profile::Testnet).taker_timeout_secs as u64 + 3600;
    w.divi.advance_time(jump as u32);
    jump_usdc_time(&w.chain_provider, jump).await;

    for _ in 0..120 {
        maker.tick().await.unwrap();
        let v = maker.view(&mid).unwrap();
        let _ = taker.step(&tid, v.as_ref()).await;
        w.divi.mine(1);
        mine_usdc_block(&w.chain_provider).await;
        let m = store.get_maker_swap(&mid).unwrap().unwrap().state;
        let t = store.get_taker_swap(&tid).unwrap().unwrap().state;
        if m == SwapState::Done && t == TakerState::Done {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let m = store.get_maker_swap(&mid).unwrap().unwrap();
    let t = store.get_taker_swap(&tid).unwrap().unwrap();
    assert_eq!((m.state, t.state), (SwapState::Done, TakerState::Done));
    assert!(m.preimage.is_none(), "nobody ever claimed");

    // Everyone got their own lockup back: the USDC leg nets to zero (Erc20Htlc.refund pays
    // back the exact locked amount, no fee), whichever side's leg was DIVI pays MockChain's
    // flat fee twice (once funding, once refunding); the other side's DIVI backend was
    // never used and stays untouched.
    const MOCK_FEE: u64 = 1_000;
    assert_eq!(
        usdc_balance(&w.chain_provider, w.token, w.maker_usdc_addr).await,
        U256::from(USDC_MINT)
    );
    assert_eq!(
        usdc_balance(&w.chain_provider, w.token, w.taker_usdc_addr).await,
        U256::from(USDC_MINT)
    );
    let (divi_user, divi_untouched) = match dir {
        Direction::TakerPaysBtc => (&w.maker_divi, &w.taker_divi),
        Direction::TakerPaysDivi => (&w.taker_divi, &w.maker_divi),
    };
    assert_eq!(
        w.divi.balance(&divi_user.pubkey()).0,
        DIVI_FUNDS - 2 * MOCK_FEE
    );
    assert_eq!(w.divi.balance(&divi_untouched.pubkey()).0, DIVI_FUNDS);
}

#[tokio::test]
async fn usdc_swap_refund_forward() {
    refund_swap(Direction::TakerPaysBtc).await;
}

#[tokio::test]
async fn usdc_swap_refund_reverse() {
    refund_swap(Direction::TakerPaysDivi).await;
}
