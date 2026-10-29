// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Two independent views of one chain, and a backend that acts only when they agree.
//!
//! The DIVI RPC proxy the taker uses is run by the same operator as the maker, so it could
//! report a maker lock that does not exist, or a claim that never confirmed. [`TwoSource`]
//! wraps a [`ChainBackend`] and answers the reads the taker trusts — `htlc_output`,
//! `confirmations` and `median_time_past` — from two [`Observer`]s, one of which must not
//! be run by that operator. Signing, broadcasting and spend-watching stay with the wrapped
//! backend. `ChainBackend` itself is unchanged.

use std::sync::Arc;

use async_trait::async_trait;

use crate::backend::ChainBackend;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::types::{Amount, Chain, Funding, LockedOutput, Outpoint, SignedTx, SpendInfo, Txid};

/// Where a transaction is, as one source sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedTx {
    /// 0 = in the mempool.
    pub confirmations: u32,
    /// Hash of the block holding it (hex as the chain's RPC prints it); `None` in the mempool.
    pub block_hash: Option<String>,
}

/// An HTLC output, as one source sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedLock {
    /// Value of the output.
    pub amount: Amount,
    /// The funding transaction.
    pub tx: ObservedTx,
}

/// A read-only view of one chain from one data source.
#[allow(clippy::double_must_use)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Observer: Send + Sync {
    /// Short name for logs and errors ("rpc", "cryptoid").
    fn name(&self) -> &str;

    /// Median time past of the tip.
    async fn median_time_past(&self) -> Result<u32>;

    /// The transaction's position, or `None` if this source does not know it.
    async fn tx(&self, txid: &Txid) -> Result<Option<ObservedTx>>;

    /// The output at `at`, or `None` if it is unknown or does not pay exactly `htlc`'s script.
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<ObservedLock>>;
}

/// A backend whose trusted reads need two observers to agree. See the module docs.
pub struct TwoSource<B> {
    inner: B,
    first: Arc<dyn Observer>,
    second: Arc<dyn Observer>,
}

impl<B: ChainBackend> TwoSource<B> {
    /// Wrap `inner`. `second` must be a source the counterparty does not control.
    pub fn new(inner: B, first: Arc<dyn Observer>, second: Arc<dyn Observer>) -> Self {
        TwoSource {
            inner,
            first,
            second,
        }
    }

    /// The wrapped backend.
    pub fn inner(&self) -> &B {
        &self.inner
    }

    fn disagree(&self, what: &str, a: impl std::fmt::Debug, b: impl std::fmt::Debug) -> String {
        let msg = format!(
            "{:?} sources disagree on {what}: {} says {a:?}, {} says {b:?}",
            self.inner.chain(),
            self.first.name(),
            self.second.name()
        );
        tracing::error!("{msg}");
        msg
    }

    /// Both views of one transaction, merged: the lower confirmation count. If both put it
    /// in a block but not the same block, one of them is on a fork or lying; that is
    /// `Transient` (a reorg settles, a liar stalls the swap toward its refund), never a count.
    fn merge(&self, a: ObservedTx, b: ObservedTx) -> Result<u32> {
        if let (Some(ha), Some(hb)) = (&a.block_hash, &b.block_hash) {
            if ha != hb {
                return Err(SwapError::Transient(self.disagree("the block", ha, hb)));
            }
        }
        Ok(a.confirmations.min(b.confirmations))
    }
}

#[allow(clippy::double_must_use)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<B: ChainBackend> ChainBackend for TwoSource<B> {
    fn chain(&self) -> Chain {
        self.inner.chain()
    }

    fn pubkey(&self) -> [u8; 33] {
        self.inner.pubkey()
    }

    async fn tip_height(&self) -> Result<u64> {
        self.inner.tip_height().await
    }

    /// The later of the two: every taker decision that reads MTP ("is it still safe to
    /// claim?") errs toward safety when time is assumed to have advanced further.
    async fn median_time_past(&self) -> Result<u32> {
        let a = self.first.median_time_past().await?;
        let b = self.second.median_time_past().await?;
        Ok(a.max(b))
    }

    async fn build_funding(&self, htlc: &HtlcParams, amount: Amount) -> Result<Funding> {
        self.inner.build_funding(htlc, amount).await
    }

    async fn build_claim(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
        preimage: &[u8; 32],
    ) -> Result<SignedTx> {
        self.inner.build_claim(htlc, at, amount, preimage).await
    }

    async fn build_refund(
        &self,
        htlc: &HtlcParams,
        at: &Outpoint,
        amount: Amount,
    ) -> Result<SignedTx> {
        self.inner.build_refund(htlc, at, amount).await
    }

    async fn broadcast(&self, tx: &SignedTx) -> Result<Txid> {
        self.inner.broadcast(tx).await
    }

    /// `None` until both sources know the transaction; then the lower count.
    async fn confirmations(&self, txid: &Txid) -> Result<Option<u32>> {
        let Some(a) = self.first.tx(txid).await? else {
            return Ok(None);
        };
        let Some(b) = self.second.tx(txid).await? else {
            return Ok(None);
        };
        self.merge(a, b).map(Some)
    }

    /// `None` until both sources see the output paying the HTLC's script. Different amounts
    /// for one outpoint cannot both be true (the txid commits to them): that is `Other`.
    async fn htlc_output(&self, htlc: &HtlcParams, at: &Outpoint) -> Result<Option<LockedOutput>> {
        let Some(a) = self.first.htlc_output(htlc, at).await? else {
            return Ok(None);
        };
        let Some(b) = self.second.htlc_output(htlc, at).await? else {
            return Ok(None);
        };
        if a.amount != b.amount {
            return Err(SwapError::Other(self.disagree(
                "the locked amount",
                a.amount,
                b.amount,
            )));
        }
        let confirmations = self.merge(a.tx, b.tx)?;
        Ok(Some(LockedOutput {
            amount: a.amount,
            confirmations,
        }))
    }

    async fn find_spend(&self, outpoint: &Outpoint, from_height: u64) -> Result<Option<SpendInfo>> {
        self.inner.find_spend(outpoint, from_height).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockBackend, MockChain};
    use parking_lot::Mutex;

    #[derive(Default)]
    struct Fixed {
        name: &'static str,
        mtp: u32,
        lock: Mutex<Option<ObservedLock>>,
        fail: bool,
    }

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl Observer for Fixed {
        fn name(&self) -> &str {
            self.name
        }
        async fn median_time_past(&self) -> Result<u32> {
            Ok(self.mtp)
        }
        async fn tx(&self, _: &Txid) -> Result<Option<ObservedTx>> {
            if self.fail {
                return Err(SwapError::Transient("down".into()));
            }
            Ok(self.lock.lock().as_ref().map(|l| l.tx.clone()))
        }
        async fn htlc_output(&self, _: &HtlcParams, _: &Outpoint) -> Result<Option<ObservedLock>> {
            if self.fail {
                return Err(SwapError::Transient("down".into()));
            }
            Ok(self.lock.lock().clone())
        }
    }

    fn seen(sat: u64, confs: u32, block: Option<&str>) -> Option<ObservedLock> {
        Some(ObservedLock {
            amount: Amount(sat),
            tx: ObservedTx {
                confirmations: confs,
                block_hash: block.map(String::from),
            },
        })
    }

    fn obs(name: &'static str, mtp: u32, lock: Option<ObservedLock>) -> Arc<Fixed> {
        Arc::new(Fixed {
            name,
            mtp,
            lock: Mutex::new(lock),
            fail: false,
        })
    }

    fn wrap(a: Arc<Fixed>, b: Arc<Fixed>) -> TwoSource<MockBackend> {
        let chain = MockChain::new(Chain::Divi, 0, 60);
        TwoSource::new(chain.backend(1, Amount(0)), a, b)
    }

    fn htlc() -> HtlcParams {
        HtlcParams {
            hash: [7; 32],
            claim_pubkey: [2; 33],
            refund_pubkey: [3; 33],
            locktime: 1_800_000_000,
        }
    }

    fn op() -> Outpoint {
        Outpoint {
            txid: Txid([9; 32]),
            vout: 0,
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn agreement_gives_the_lower_count() {
        let t = wrap(
            obs("rpc", 0, seen(5_000, 12, Some("aa"))),
            obs("cryptoid", 0, seen(5_000, 11, Some("aa"))),
        );
        let lo = block_on(t.htlc_output(&htlc(), &op())).unwrap().unwrap();
        assert_eq!((lo.amount, lo.confirmations), (Amount(5_000), 11));
        assert_eq!(block_on(t.confirmations(&op().txid)).unwrap(), Some(11));
    }

    #[test]
    fn mempool_on_one_side_counts_as_zero() {
        let t = wrap(
            obs("rpc", 0, seen(5_000, 10, Some("aa"))),
            obs("cryptoid", 0, seen(5_000, 0, None)),
        );
        let lo = block_on(t.htlc_output(&htlc(), &op())).unwrap().unwrap();
        assert_eq!(lo.confirmations, 0);
    }

    #[test]
    fn a_lock_only_the_operator_sees_is_not_a_lock() {
        let t = wrap(
            obs("rpc", 0, seen(5_000, 50, Some("aa"))),
            obs("cryptoid", 0, None),
        );
        assert_eq!(block_on(t.htlc_output(&htlc(), &op())).unwrap(), None);
        assert_eq!(block_on(t.confirmations(&op().txid)).unwrap(), None);
    }

    #[test]
    fn different_amounts_are_refused() {
        let t = wrap(
            obs("rpc", 0, seen(9_000, 12, Some("aa"))),
            obs("cryptoid", 0, seen(5_000, 12, Some("aa"))),
        );
        let e = block_on(t.htlc_output(&htlc(), &op())).unwrap_err();
        assert!(matches!(e, SwapError::Other(m) if m.contains("locked amount")));
    }

    #[test]
    fn different_blocks_are_refused() {
        let t = wrap(
            obs("rpc", 0, seen(5_000, 12, Some("aa"))),
            obs("cryptoid", 0, seen(5_000, 12, Some("bb"))),
        );
        let e = block_on(t.htlc_output(&htlc(), &op())).unwrap_err();
        assert!(matches!(e, SwapError::Transient(m) if m.contains("block")));
        let e = block_on(t.confirmations(&op().txid)).unwrap_err();
        assert!(matches!(e, SwapError::Transient(_)));
    }

    #[test]
    fn an_unreachable_second_source_is_transient() {
        let down = Arc::new(Fixed {
            name: "cryptoid",
            fail: true,
            ..Default::default()
        });
        let t = wrap(obs("rpc", 0, seen(5_000, 12, Some("aa"))), down);
        let e = block_on(t.htlc_output(&htlc(), &op())).unwrap_err();
        assert!(matches!(e, SwapError::Transient(_)));
    }

    #[test]
    fn mtp_is_the_later_of_the_two() {
        let t = wrap(obs("rpc", 1_000, None), obs("cryptoid", 1_600, None));
        assert_eq!(block_on(t.median_time_past()).unwrap(), 1_600);
        let t = wrap(obs("rpc", 2_000, None), obs("cryptoid", 1_600, None));
        assert_eq!(block_on(t.median_time_past()).unwrap(), 2_000);
    }
}
