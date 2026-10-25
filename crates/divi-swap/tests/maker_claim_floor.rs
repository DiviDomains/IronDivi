// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The maker's claim of a DIVI or ZEC taker leg is never bumped ([`FeeBump::None`]): it is
//! signed once and resent byte for byte, so its only margin is the floor the chain's spend
//! builder puts under every claim (DIVI: `CLAIM_FEE_FACTOR` x the relay minimum; ZEC:
//! `CLAIM_ZIP317_FACTOR` x the ZIP 317 conventional fee). These guard that the floor reaches
//! the maker's path. The maker's taker-leg backend prices each claim with the real chain's
//! spend builder, on a fee policy that alone pays less than the floor, and the mock chain
//! mines only spends that pay the floor: without it the claim never confirms and the
//! hostile taker's refund takes the taker leg.

use async_trait::async_trait;
use divi_primitives::serialize::deserialize;
use divi_primitives::transaction::Transaction;
use divi_swap::api::{Direction, Offer};
use divi_swap::backend::TipHeader;
use divi_swap::mock::{MockBackend, MockChain, TxKind, MOCK_VSIZE};
use divi_swap::{
    Amount, Chain, ChainBackend, ClaimDeadline, FeeBump, Funding, HtlcParams, LockedOutput, Maker,
    Outpoint, Profile, Result, SignedTx, SpendInfo, Store, SwapConfig, SwapState, Taker,
    TakerState, Txid,
};
use secp256k1::{All, Secp256k1};
use std::sync::{Arc, Mutex};
use swap_chain_divi::{DiviBackend, FeePolicy, CLAIM_FEE_FACTOR, RELAY_FEE_PER_KB};
use swap_chain_zec::tx::{build_spend_tx, OutPoint, Spend, CLAIM_ZIP317_FACTOR};

const T0: u32 = 1_800_000_000;
const FUNDS: u64 = 1_000_000_000_000;
const SATS: u64 = 1_000_000;
/// Rounds after the claim first shows up during which the taker-leg chain mines no spend.
const HOLD: u32 = 4;
/// NU6 consensus branch id; the ZEC claim's fee does not depend on it.
const ZEC_BRANCH_ID: u32 = 0xC8E7_1055;

/// ZIP 317 conventional fee of a transparent tx with inputs and outputs of these scriptSig /
/// scriptPubKey lengths: `5000 * max(2, ceil(vin bytes / 150), ceil(vout bytes / 34))`.
fn zip317_conventional(script_sigs: &[usize], script_pubkeys: &[usize]) -> u64 {
    let compact = |n: usize| if n < 0xfd { 1 } else { 3 } as u64;
    let vin: u64 = script_sigs
        .iter()
        .map(|&n| 36 + compact(n) + n as u64 + 4)
        .sum();
    let vout: u64 = script_pubkeys
        .iter()
        .map(|&n| 8 + compact(n) + n as u64)
        .sum();
    5000 * vin.div_ceil(150).max(vout.div_ceil(34)).max(2)
}

/// The real spend builder a claim is priced with.
enum Real {
    /// The DIVI backend at the relay minimum. Its `build_claim` makes no RPC call.
    Divi(DiviBackend),
    /// The ZEC builder `ZecBackend::build_claim` calls (after reading the branch id and tip
    /// height from lightwalletd, which this harness has none of), at 1 zatoshi per byte.
    Zec {
        secp: Secp256k1<All>,
        key: secp256k1::SecretKey,
        pubkey: [u8; 33],
    },
}

impl Real {
    fn divi() -> Self {
        let key = divi_crypto::keys::SecretKey::from_bytes(&[7; 32]).unwrap();
        let policy = FeePolicy {
            sat_per_kb: RELAY_FEE_PER_KB,
            min_fee: 0,
        };
        let b = DiviBackend::new(
            "http://127.0.0.1:1",
            key,
            divi_wallet::address::Network::Testnet,
            policy,
            None,
        )
        .unwrap();
        Real::Divi(b)
    }

    fn zec() -> Self {
        let secp = Secp256k1::new();
        let key = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let pubkey = key.public_key(&secp).serialize();
        Real::Zec { secp, key, pubkey }
    }

    fn pubkey(&self) -> [u8; 33] {
        match self {
            Real::Divi(b) => b.pubkey(),
            Real::Zec { pubkey, .. } => *pubkey,
        }
    }

    /// Build the claim of `htlc` (its claim key swapped for this builder's, which leaves the
    /// size unchanged): its fee, the floor it must pay, and what the fee policy alone pays.
    async fn claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<Priced> {
        let own = HtlcParams {
            claim_pubkey: self.pubkey(),
            ..*htlc
        };
        Ok(match self {
            Real::Divi(b) => {
                let tx = b.build_claim(&own, at, amount, preimage).await?;
                let parsed: Transaction = deserialize(&tx.raw).unwrap();
                let size = tx.raw.len() as u64;
                Priced {
                    fee: amount.0 - parsed.vout[0].value.as_sat() as u64,
                    floor: CLAIM_FEE_FACTOR * RELAY_FEE_PER_KB * size / 1000,
                    policy: (RELAY_FEE_PER_KB * size).div_ceil(1000),
                }
            }
            Real::Zec { secp, key, pubkey } => {
                let op = OutPoint {
                    txid: at.txid.0,
                    n: at.vout,
                };
                let tx = build_spend_tx(
                    secp,
                    key,
                    pubkey,
                    &own,
                    op,
                    amount.0,
                    Spend::Claim(preimage),
                    5,
                    ZEC_BRANCH_ID,
                    1,
                )?;
                let conventional = zip317_conventional(
                    &tx.vin
                        .iter()
                        .map(|i| i.script_sig.len())
                        .collect::<Vec<_>>(),
                    &tx.vout
                        .iter()
                        .map(|o| o.script_pubkey.len())
                        .collect::<Vec<_>>(),
                );
                Priced {
                    fee: amount.0 - tx.vout[0].value,
                    floor: CLAIM_ZIP317_FACTOR * conventional,
                    policy: conventional.max(tx.serialize().len() as u64),
                }
            }
        })
    }
}

/// One claim the maker's backend built.
#[derive(Debug, Clone)]
struct Priced {
    /// Fee the real builder paid.
    fee: u64,
    /// The chain's claim floor for that transaction.
    floor: u64,
    /// What the backend's fee policy alone would pay.
    policy: u64,
}

/// The maker's taker-leg backend: a [`MockBackend`] whose claims pay what the real chain's
/// builder pays.
#[derive(Clone)]
struct Floored {
    mock: MockBackend,
    real: Arc<Real>,
    built: Arc<Mutex<Vec<(Priced, SignedTx)>>>,
}

#[async_trait]
impl ChainBackend for Floored {
    fn chain(&self) -> Chain {
        self.mock.chain()
    }
    fn pubkey(&self) -> [u8; 33] {
        self.mock.pubkey()
    }
    async fn tip_height(&self) -> Result<u64> {
        self.mock.tip_height().await
    }
    async fn tip_hash(&self) -> Result<String> {
        self.mock.tip_hash().await
    }
    async fn median_time_past(&self) -> Result<u32> {
        self.mock.median_time_past().await
    }
    async fn tip_header(&self) -> Result<TipHeader> {
        self.mock.tip_header().await
    }
    async fn in_best_chain(&self, height: u64, hash: &str) -> Result<bool> {
        self.mock.in_best_chain(height, hash).await
    }
    fn target_block_secs(&self) -> Option<u32> {
        self.mock.target_block_secs()
    }
    async fn spendable(&self) -> Result<Option<Amount>> {
        self.mock.spendable().await
    }
    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.mock.build_funding(htlc, amount).await
    }
    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        let priced = self.real.claim(htlc, at, amount, preimage).await?;
        let feerate = priced.fee.div_ceil(MOCK_VSIZE);
        let tx = self
            .mock
            .build_claim_paying(htlc, at, amount, preimage, feerate)?;
        self.built.lock().unwrap().push((priced, tx.clone()));
        Ok(tx)
    }
    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.mock.build_refund(htlc, at, amount).await
    }
    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.mock.broadcast(tx).await
    }
    async fn release_dead_lock(&self, lock: &SignedTx) -> Result<bool> {
        self.mock.release_dead_lock(lock).await
    }
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        self.mock.confirmations(txid).await
    }
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        self.mock.htlc_output(htlc, at).await
    }
    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.mock.find_spend(outpoint, from_height).await
    }
}

fn block_secs(chain: Chain) -> u32 {
    ClaimDeadline::builtin(chain).block_secs
}

struct Outcome {
    /// The maker's final state.
    maker: SwapState,
    /// The maker's balance on the taker-leg chain gained the leg (less fees).
    maker_gained: bool,
    /// The hostile taker's refund of the taker leg confirmed.
    refunded: bool,
    /// Every claim the maker's backend built.
    built: Vec<(Priced, SignedTx)>,
    /// The claim the maker's record holds at the end.
    recorded: Option<SignedTx>,
    /// Feerate the taker-leg chain holds the recorded claim at.
    chain_feerate: Option<u64>,
    /// Distinct claim txids of the taker leg broadcast, and claim broadcasts in all.
    claim_txids: u32,
    claim_sends: usize,
    /// With `evict`: the claim was gone after the eviction and back after a later tick.
    evicted_then_resent: Option<bool>,
}

/// One swap whose taker leg is on `taker_leg` (DIVI against a BTC maker leg, or ZEC
/// against a DIVI one), revealed at the taker's claim deadline. The taker-leg chain then
/// mines no spend for [`HOLD`] rounds (with `evict`, the maker's claim is evicted in the
/// first) and from then on only spends paying the claim floor.
async fn race(taker_leg: Chain, evict: bool) -> Outcome {
    let (counter, direction, real) = match taker_leg {
        Chain::Divi => (Chain::Btc, Direction::TakerPaysDivi, Real::divi()),
        Chain::Zec => (Chain::Zec, Direction::TakerPaysBtc, Real::zec()),
        other => panic!("{other} claims are bumped"),
    };
    let maker_leg = if taker_leg == Chain::Divi {
        counter
    } else {
        Chain::Divi
    };
    let divi = MockChain::new(Chain::Divi, T0, block_secs(Chain::Divi));
    let ctr = MockChain::new(counter, T0, block_secs(counter));
    let (tl, ml) = if taker_leg == Chain::Divi {
        (&divi, &ctr)
    } else {
        (&ctr, &divi)
    };
    if let Real::Divi(b) = &real {
        assert_eq!(b.fee_bump(), FeeBump::None, "a DIVI claim is never bumped");
    }
    let floored = Floored {
        mock: tl.backend(2, Amount(FUNDS)),
        real: Arc::new(real),
        built: Arc::default(),
    };
    let maker_pk = floored.pubkey();
    let (mdivi, mctr): (Arc<dyn ChainBackend>, Arc<dyn ChainBackend>) = if taker_leg == Chain::Divi
    {
        (
            Arc::new(floored.clone()),
            Arc::new(ctr.backend(1, Amount(FUNDS))),
        )
    } else {
        (
            Arc::new(divi.backend(1, Amount(FUNDS))),
            Arc::new(floored.clone()),
        )
    };
    let (tdivi, tctr) = (
        divi.backend(3, Amount(FUNDS)),
        ctr.backend(4, Amount(FUNDS)),
    );
    let hostile = if taker_leg == Chain::Divi {
        tdivi.clone()
    } else {
        tctr.clone()
    };
    tl.set_refund_feerate(FUNDS);
    let store = Store::in_memory().unwrap();
    let maker = Maker::new(
        SwapConfig::profile(Profile::Testnet),
        mdivi,
        mctr,
        store.clone(),
        vec![Offer {
            id: "o".into(),
            direction,
            counter_chain: counter,
            divi_sats_per_btc: 50_000_000_000,
            min_btc_sats: 10_000,
            max_btc_sats: 5_000_000,
        }],
    )
    .unwrap();
    let taker = Taker::new(Arc::new(tdivi), Arc::new(tctr), store.clone());

    let q = maker.quote("o", SATS).await.unwrap();
    let (tid, req) = taker.prepare(&q).await.unwrap();
    let v = maker.accept(req).await.unwrap();
    taker.accepted(&tid, &v).await.unwrap();
    let notice = taker.lock(&tid).await.unwrap();
    let mid = maker.notify_lock(&v.id, notice).await.unwrap().id;
    for _ in 0..40 {
        divi.mine(1);
        ctr.mine(1);
        maker.tick().await.unwrap();
        if maker.view(&mid).unwrap().unwrap().state == SwapState::MakerLockConfirmed {
            break;
        }
    }
    let view = maker.view(&mid).unwrap().unwrap();
    assert_eq!(view.state, SwapState::MakerLockConfirmed);

    // The hostile taker claims the maker leg just inside its own claim deadline.
    let maker_locktime = view.maker_leg.as_ref().unwrap().htlc.locktime;
    let reveal_at = maker_locktime - ClaimDeadline::builtin(maker_leg).margin_secs() - 120;
    let wait = reveal_at.saturating_sub(ml.mtp());
    divi.advance_time(wait);
    ctr.advance_time(wait);
    let mut state = TakerState::Locked;
    for _ in 0..3 {
        state = taker.step(&tid, Some(&view)).await.unwrap();
        if state == TakerState::Claimed {
            break;
        }
    }
    assert_eq!(state, TakerState::Claimed);
    tl.set_block_floor(u64::MAX);

    let rec = store.get_maker_swap(&mid).unwrap().unwrap();
    let (taker_htlc, at, amount) = (
        rec.taker_leg_htlc,
        rec.taker_leg_outpoint.unwrap(),
        rec.taker_leg_locked.unwrap(),
    );
    let before = tl.balance(&maker_pk).0;
    let mut refund = None;
    let mut held = 0;
    let mut evicted = None;
    let mut evicted_then_resent = None;
    for _ in 0..200 {
        let _ = taker.step(&tid, Some(&view)).await;
        let _ = maker.tick().await;
        let claim = floored.built.lock().unwrap().first().cloned();
        if let Some((priced, tx)) = claim {
            if held == 0 && evict {
                assert!(
                    tl.drop_from_mempool(&tx.txid),
                    "the claim was in the mempool"
                );
                assert!(!tl.contains(&tx.txid));
                evicted = Some(tx.txid);
            } else if let Some(id) = evicted.take() {
                evicted_then_resent = Some(tl.contains(&id));
            }
            held += 1;
            if held == HOLD {
                tl.set_block_floor(priced.floor.div_ceil(MOCK_VSIZE));
            }
        }
        if refund.is_none() && tl.mtp() >= taker_htlc.locktime {
            if let Ok(tx) = hostile.build_refund(&taker_htlc, &at, amount).await {
                if hostile.broadcast(&tx).await.is_ok() {
                    refund = Some(tx.txid);
                }
            }
        }
        tl.advance_time(300u32.saturating_sub(block_secs(taker_leg)));
        tl.mine(1);
        ml.advance_time(240);
        ml.mine(1);
        let mk = maker.view(&mid).unwrap().unwrap().state;
        if mk.is_terminal() || tl.mtp() > taker_htlc.locktime + 7200 {
            break;
        }
    }
    let refunded = match refund {
        Some(id) => hostile
            .confirmations(&id)
            .await
            .unwrap()
            .is_some_and(|c| c >= 1),
        None => false,
    };
    let record = store.get_maker_swap(&mid).unwrap().unwrap();
    let counts = tl.tx_counts(&at);
    let built = floored.built.lock().unwrap().clone();
    Outcome {
        maker: maker.view(&mid).unwrap().unwrap().state,
        maker_gained: tl.balance(&maker_pk).0 > before,
        refunded,
        chain_feerate: record
            .taker_leg_claim
            .as_ref()
            .and_then(|c| tl.feerate_of(&c.txid)),
        recorded: record.taker_leg_claim,
        built,
        claim_txids: counts.claim_attempts,
        claim_sends: tl.attempts(TxKind::Claim),
        evicted_then_resent,
    }
}

/// The maker's claim paid the floor, was signed once and resent byte for byte, and won.
fn floor_held(chain: Chain, o: &Outcome) {
    assert_eq!(o.built.len(), 1, "{chain}: the claim was signed once");
    let (priced, tx) = &o.built[0];
    assert!(
        priced.policy < priced.floor,
        "{chain}: the fee policy alone pays the floor, the test proves nothing: {priced:?}"
    );
    assert!(
        priced.fee >= priced.floor,
        "{chain}: the maker's claim pays under the floor: {priced:?}"
    );
    let chain_fee = o.chain_feerate.expect("the claim is on chain") * MOCK_VSIZE;
    assert!(
        chain_fee >= priced.floor,
        "{chain}: {chain_fee} < {priced:?}"
    );
    assert_eq!(o.recorded.as_ref(), Some(tx), "{chain}: the recorded claim");
    assert_eq!(o.claim_txids, 1, "{chain}: one distinct claim txid");
    assert!(
        o.claim_sends > 1,
        "{chain}: the held claim was resent ({} sends)",
        o.claim_sends
    );
    assert!(!o.refunded, "{chain}: the taker refunded the taker leg");
    assert!(o.maker_gained, "{chain}: the maker's claim never paid out");
    assert_eq!(o.maker, SwapState::Done, "{chain}");
}

#[tokio::test]
async fn a_maker_claim_of_a_divi_taker_leg_pays_the_relay_floor_and_beats_the_taker_refund() {
    let o = race(Chain::Divi, false).await;
    floor_held(Chain::Divi, &o);
}

#[tokio::test]
async fn a_maker_claim_of_a_zec_taker_leg_pays_the_zip317_cap_and_beats_the_taker_refund() {
    let o = race(Chain::Zec, false).await;
    floor_held(Chain::Zec, &o);
}

#[tokio::test]
async fn an_evicted_zec_maker_claim_is_resent_byte_for_byte_and_wins() {
    let o = race(Chain::Zec, true).await;
    assert_eq!(
        o.evicted_then_resent,
        Some(true),
        "the same claim is back in the mempool after the eviction"
    );
    floor_held(Chain::Zec, &o);
}
