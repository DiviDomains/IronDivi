// SPDX-License-Identifier: AGPL-3.0-only

use divi_swap::api::{Direction, Offer};
use divi_swap::mock::MockChain;
use divi_swap::{Amount, Chain, Maker, Profile, Store, SwapConfig, Taker};
use std::sync::Arc;

/// A restart with the CLI's default BTC counter must never select DIVI inputs
/// for a persisted USDC swap. Uses only APIs available on the baseline.
#[tokio::test]
async fn resumed_divi_payer_requires_its_accepted_usdc_counter() {
    let now = 1_800_000_000;
    let funds = Amount(2_000_000_000);
    let divi = MockChain::new(Chain::Divi, now, 60);
    let usdc = MockChain::new(Chain::Usdc, now, 60);
    let btc = MockChain::new(Chain::Btc, now, 600);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        Arc::new(divi.backend(1, funds)),
        Arc::new(usdc.backend(1, funds)),
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction: Direction::TakerPaysDivi,
            counter_chain: Chain::Usdc,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    let payer = Arc::new(divi.backend(3, funds));
    let taker = Taker::new(
        payer.clone(),
        Arc::new(usdc.backend(4, funds)),
        store.clone(),
    );
    let quote = maker.quote("o", 1_000_000).await.unwrap();
    let (id, req) = taker.prepare(&quote).await.unwrap();
    taker
        .accepted(&id, &maker.accept(req).await.unwrap())
        .await
        .unwrap();
    let accepted = store.get_taker_swap(&id).unwrap().unwrap();
    drop(taker);
    let resumed = Taker::new(
        payer.clone(),
        Arc::new(btc.backend(4, funds)),
        store.clone(),
    );
    let result = resumed.lock(&id).await;
    assert_eq!(
        payer.funding_calls(),
        0,
        "selected DIVI inputs with the wrong counter backend"
    );
    assert!(result.unwrap_err().to_string().contains("no usdc backend"));
    assert_eq!(store.get_taker_swap(&id).unwrap().unwrap(), accepted);
}
