// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Fee escalation of an HTLC claim sent after its preimage is out, shared by both roles:
//! the taker's claim of the maker leg and the maker's claim of the taker leg. Either one is
//! lost to the counterparty's refund unless it confirms before the leg's locktime, so both
//! climb the chain's [`FeeEscalation`] the same way: replaced by fee (RBF), at their nonce
//! (EVM) or bumped by CPFP children, every new transaction persisted before it is sent.

use crate::backend::{ChainBackend, FeeBump};
use crate::config::FeeEscalation;
use crate::error::{Result, SwapError};
use crate::htlc::HtlcParams;
use crate::store::{MakerRecord, Store, TakerRecord};
use crate::types::{Amount, Chain, Outpoint, SignedTx};

/// The claim of a persisted swap and its fee history, borrowed mutably.
pub(crate) struct ClaimMut<'a> {
    /// The newest claim version.
    pub claim: &'a mut Option<SignedTx>,
    /// Feerate the first version paid, where the backend can bump it.
    pub base_feerate: &'a mut Option<u64>,
    /// Feerate the claim (with its CPFP children) pays now.
    pub feerate: &'a mut Option<u64>,
    /// Versions a replacement superseded, oldest first, with the feerate each paid.
    pub replaced: &'a mut Vec<(SignedTx, u64)>,
    /// CPFP children, in spend order.
    pub children: &'a mut Vec<SignedTx>,
    /// The child the newest child replaces, with the feerate the package paid with it,
    /// until the node relays or refuses the replacement.
    pub child_replaced: &'a mut Option<(SignedTx, u64)>,
    /// Same-nonce replacements refused as underpriced since a version was last taken.
    pub underpriced: &'a mut u32,
}

/// A persisted swap that claims one leg after its preimage is out.
pub(crate) trait ClaimRecord: Send {
    /// The swap id, for logs.
    fn swap_id(&self) -> &str;
    /// The claim and its fee history.
    fn claim_mut(&mut self) -> ClaimMut<'_>;
    /// Write the whole record (write-ahead of every broadcast).
    fn persist(&self, store: &Store) -> Result<()>;
}

impl ClaimRecord for TakerRecord {
    fn swap_id(&self) -> &str {
        &self.id
    }
    fn claim_mut(&mut self) -> ClaimMut<'_> {
        ClaimMut {
            claim: &mut self.maker_leg_claim,
            base_feerate: &mut self.claim_base_feerate,
            feerate: &mut self.claim_feerate,
            replaced: &mut self.claim_replaced,
            children: &mut self.claim_children,
            child_replaced: &mut self.claim_child_replaced,
            underpriced: &mut self.claim_underpriced,
        }
    }
    fn persist(&self, store: &Store) -> Result<()> {
        store.put_taker_swap(self)
    }
}

impl ClaimRecord for MakerRecord {
    fn swap_id(&self) -> &str {
        &self.id
    }
    fn claim_mut(&mut self) -> ClaimMut<'_> {
        let f = &mut self.claim_fees;
        ClaimMut {
            claim: &mut self.taker_leg_claim,
            base_feerate: &mut f.claim_base_feerate,
            feerate: &mut f.claim_feerate,
            replaced: &mut f.claim_replaced,
            children: &mut f.claim_children,
            child_replaced: &mut f.claim_child_replaced,
            underpriced: &mut f.claim_underpriced,
        }
    }
    fn persist(&self, store: &Store) -> Result<()> {
        store.put_maker_swap(self)
    }
}

/// Everything about one claim that does not change while it escalates.
pub(crate) struct ClaimCtx<'a> {
    /// Chain of the claimed leg.
    pub chain: Chain,
    /// Backend of that chain.
    pub backend: &'a dyn ChainBackend,
    /// The schedule (`None`: never bump).
    pub escalation: Option<FeeEscalation>,
    /// The chain's claim-deadline margin, the window of [`FeeEscalation::ceiling_fee`].
    pub window: u32,
    /// The claimed HTLC.
    pub htlc: HtlcParams,
    /// Its lock output.
    pub op: Outpoint,
    /// Value locked in it.
    pub amount: Amount,
    /// The revealed preimage.
    pub preimage: [u8; 32],
    /// Where the record is written.
    pub store: &'a Store,
}

impl ClaimCtx<'_> {
    /// Sign the first claim. Where the backend can bump it and escalation is on, at the
    /// feerate it reports now, recorded as the base the escalation climbs from. A same-nonce
    /// claim whose estimate is within one price bump of the cap is signed at the cap
    /// ([`FeeEscalation::reach_cap`]): no replacement of it could stay within the cap, so it
    /// would stay at the estimate under a floor the cap clears.
    pub async fn sign_first<R: ClaimRecord>(&self, r: &mut R) -> Result<SignedTx> {
        let b = self.backend;
        let feerate = match (b.fee_bump(), self.escalation) {
            (FeeBump::None, _) | (_, None) => None,
            (FeeBump::SameNonce, Some(esc)) => b
                .claim_feerate()
                .await?
                .map(|f| esc.reach_cap(f, esc.cap(f))),
            _ => b.claim_feerate().await?,
        };
        let tx = match feerate {
            Some(f) => {
                b.build_claim_at(&self.htlc, &self.op, self.amount, &self.preimage, f)
                    .await?
            }
            None => {
                b.build_claim(&self.htlc, &self.op, self.amount, &self.preimage)
                    .await?
            }
        };
        let c = r.claim_mut();
        *c.claim = Some(tx.clone());
        *c.base_feerate = feerate;
        *c.feerate = feerate;
        c.replaced.clear();
        c.children.clear();
        *c.child_replaced = None;
        *c.underpriced = 0;
        Ok(tx)
    }

    /// Whether a version a replacement superseded is the one that got mined.
    pub async fn replaced_confirmed<R: ClaimRecord>(&self, r: &mut R) -> Result<bool> {
        let replaced = r.claim_mut().replaced.clone();
        for (old, _) in &replaced {
            if self
                .backend
                .confirmations(&old.txid)
                .await?
                .is_some_and(|c| c >= 1)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Resend every CPFP child. One refused for good is dropped with every child built on
    /// it (the next bump builds afresh); any failure is returned. A refused replacement of
    /// a child (e.g. written ahead and never sent before a restart, on a node that takes no
    /// child replacement) gives back the child it replaced, which the node still holds, for
    /// the next bump to chain on.
    pub async fn resend_children<R: ClaimRecord>(&self, r: &mut R) -> Result<()> {
        let children = r.claim_mut().children.clone();
        for (i, child) in children.iter().enumerate() {
            if let Err(e) = self.backend.broadcast(child).await {
                if matches!(e, SwapError::Rejected(_)) {
                    let c = r.claim_mut();
                    let replaced = c.child_replaced.take();
                    if let (Some((old, feerate)), true) = (replaced, i + 1 == children.len()) {
                        tracing::info!(swap = %r.swap_id(), refused = %child.txid,
                            back_to = %old.txid, error = %e,
                            "claim CPFP child replacement refused; back to the child it replaced");
                        let c = r.claim_mut();
                        c.children.pop();
                        c.children.push(old.clone());
                        *c.feerate = Some(feerate);
                        r.persist(self.store)?;
                        self.backend.broadcast(&old).await?;
                        return Ok(());
                    }
                    tracing::warn!(swap = %r.swap_id(), refused = %child.txid, error = %e,
                        "claim CPFP child refused; dropping it");
                    let c = r.claim_mut();
                    c.children.truncate(i);
                    *c.feerate = *c.base_feerate;
                    r.persist(self.store)?;
                }
                return Err(e);
            }
        }
        // Every child relayed: a pending replacement among them was taken.
        if r.claim_mut().child_replaced.take().is_some() {
            r.persist(self.store)?;
        }
        Ok(())
    }

    /// First half of handling a node's refusal `e` of `claim`, the newest claim version:
    /// `true` if the chain holds it after all, or holds a version it replaced. The newest
    /// version it holds is then kept (the refusal is not about the claim) and newer ones it
    /// never took are dropped: re-signing at the first claim's feerate would only conflict.
    pub async fn held_after_refusal<R: ClaimRecord>(
        &self,
        r: &mut R,
        claim: &SignedTx,
        e: &SwapError,
    ) -> Result<bool> {
        let b = self.backend;
        if b.confirmations(&claim.txid).await?.is_some() {
            tracing::warn!(swap = %r.swap_id(), txid = %claim.txid, error = %e,
                "claim rebroadcast refused but the chain holds it; keeping it");
            return Ok(true);
        }
        let replaced = r.claim_mut().replaced.clone();
        for i in (0..replaced.len()).rev() {
            let (prev, feerate) = replaced[i].clone();
            if b.confirmations(&prev.txid).await?.is_none() {
                continue;
            }
            tracing::warn!(swap = %r.swap_id(), refused = %claim.txid, back_to = %prev.txid,
                error = %e, "claim replacement refused; back to the claim the chain holds");
            let id = r.swap_id().to_owned();
            let c = r.claim_mut();
            // The node wants a bigger step than the configured price bump: counted, so the
            // next replacement outbids it (`FeeEscalation::underpriced_target`).
            if b.fee_bump() == FeeBump::SameNonce
                && e.to_string().to_ascii_lowercase().contains("underpriced")
            {
                *c.underpriced = c.underpriced.saturating_add(1);
                tracing::warn!(swap = %id, chain = %self.chain, refusals = *c.underpriced,
                    feerate = feerate, "claim replacement refused as underpriced");
            }
            c.replaced.truncate(i);
            *c.claim = Some(prev);
            *c.feerate = Some(feerate);
            c.children.clear();
            *c.child_replaced = None;
            r.persist(self.store)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Second half, once nothing of the claim is held and the leg is not lost: where the
    /// claim can be bumped, re-sign it at the escalation target, at least one unit per vbyte
    /// above what it paid and at least the current estimate, within the cap, and send it
    /// now (`true`). Otherwise forget it so the next step re-signs from the persisted
    /// preimage (e.g. signed by an older, buggy build), or, at the cap already, keep it
    /// (`false` either way). Under `SameNonce` nothing at the claim's nonce is held, so it
    /// is free (or a different transaction took it): `build_claim_at` signs at the next
    /// free nonce.
    pub async fn resign_after_refusal<R: ClaimRecord>(
        &self,
        r: &mut R,
        claim: &SignedTx,
        e: &SwapError,
    ) -> Result<bool> {
        let b = self.backend;
        let (base, current) = {
            let c = r.claim_mut();
            (*c.base_feerate, *c.feerate)
        };
        if let (
            Some(esc),
            Some(base),
            Some(current),
            FeeBump::Rbf | FeeBump::Cpfp | FeeBump::SameNonce,
        ) = (self.escalation, base, current, b.fee_bump())
        {
            let left = i64::from(self.htlc.locktime) - i64::from(b.median_time_past().await?);
            let estimate = b.claim_feerate().await?.unwrap_or(0);
            let (target, cap, fixed) = match self.ceiling(left, 0) {
                Some(ceiling) => (
                    esc.target_after_leak(base, left, ceiling),
                    ceiling,
                    esc.cap(base),
                ),
                None => {
                    let cap = esc.cap_after_leak(base, left);
                    (esc.same_nonce_target(base, left), cap, cap)
                }
            };
            // Refused at the fixed cap or above: the mempool wants more than the cap, so
            // step up by a bump's worth rather than one unit per vbyte.
            let step = if current >= fixed {
                (current / 4).max(1)
            } else {
                1
            };
            let feerate = target
                .max(estimate)
                .max(current.saturating_add(step))
                .min(cap);
            // A fresh same-nonce claim within one price bump of the cap could never be
            // replaced within it, as in `sign_first`.
            let feerate = match b.fee_bump() {
                FeeBump::SameNonce => esc.reach_cap(feerate, cap),
                _ => feerate,
            };
            if feerate <= current {
                tracing::warn!(swap = %r.swap_id(), txid = %claim.txid, feerate = current,
                    error = %e, "claim refused at the fee cap; resending it unchanged");
                return Ok(false);
            }
            let tx = b
                .build_claim_at(&self.htlc, &self.op, self.amount, &self.preimage, feerate)
                .await?;
            {
                let c = r.claim_mut();
                c.replaced.push((claim.clone(), current));
                *c.claim = Some(tx.clone());
                *c.feerate = Some(feerate);
                c.children.clear();
                *c.child_replaced = None;
                *c.underpriced = 0; // a fresh claim, not a replacement
            }
            r.persist(self.store)?; // write-ahead
            tracing::info!(swap = %r.swap_id(), chain = %self.chain, old_feerate = current,
                new_feerate = feerate, txid = %tx.txid, claim = %claim.txid, secs_left = left,
                error = %e, "claim refused and not held; re-signed at a higher feerate");
            b.broadcast(&tx).await?;
            return Ok(true);
        }
        {
            let c = r.claim_mut();
            *c.claim = None;
            c.children.clear();
            *c.child_replaced = None;
        }
        r.persist(self.store)?;
        Ok(false)
    }

    /// The post-leak fee ceiling ([`FeeEscalation::ceiling_fee`]) with `left` seconds
    /// before the locktime, as a feerate over the package the next version makes: the claim
    /// and `children` CPFP children (the new one included), so a CPFP ceiling covers the
    /// fee of parent and children together. `None` where the backend reports no sizes: the
    /// fixed cap then holds.
    fn ceiling(&self, left: i64, children: u64) -> Option<u64> {
        let sizes = self.backend.claim_sizes(&self.htlc)?;
        let vsize = sizes
            .claim_vsize
            .saturating_add(sizes.child_vsize.saturating_mul(children))
            .max(1);
        let fee = FeeEscalation::ceiling_fee(self.amount.0, sizes.dust, vsize, left, self.window);
        Some(fee / vsize)
    }

    /// Raise the fee of the unconfirmed `claim` along the schedule as the locktime nears:
    /// replace it (RBF, or at its nonce on EVM), or bump it through a CPFP child, persisting
    /// the new transaction before broadcasting it and logging every bump. A no-op where the
    /// backend cannot bump, escalation is off, or the target is not yet worth a new
    /// transaction.
    ///
    /// A CPFP bump replaces the newest child where [`FeeEscalation::replace_cpfp_child`]
    /// says so, so the package stays the claim and one child (the child signals BIP125). A
    /// node that refuses that (Litecoin Core's default, `-mempoolreplacement=0`) gets the
    /// old child back and a new one on top instead, which
    /// [`FeeEscalation::should_add_child`] keeps to about ten in all, inside the
    /// 25-transaction ancestor limit.
    pub async fn escalate<R: ClaimRecord>(&self, r: &mut R, claim: &SignedTx) -> Result<()> {
        let b = self.backend;
        let (base, current, underpriced) = {
            let c = r.claim_mut();
            (*c.base_feerate, *c.feerate, *c.underpriced)
        };
        let (Some(esc), Some(base), Some(current)) = (self.escalation, base, current) else {
            return Ok(());
        };
        let kind = b.fee_bump();
        if kind == FeeBump::None {
            return Ok(());
        }
        let left = i64::from(self.htlc.locktime) - i64::from(b.median_time_past().await?);
        if kind == FeeBump::Cpfp {
            return self.bump_child(r, claim, &esc, base, current, left).await;
        }
        // With no post-leak ceiling (EVM: the fee is not paid out of the leg), the fixed cap
        // gives way to `cap_feerate` past the cap point.
        let (target, cap) = match self.ceiling(left, 0) {
            Some(c) => (esc.target_after_leak(base, left, c), esc.cap(base)),
            None => (
                esc.same_nonce_target(base, left),
                esc.cap_after_leak(base, left),
            ),
        };
        if !FeeEscalation::should_bump_within(current, target, cap) {
            return Ok(());
        }
        // Refused as underpriced at least twice since the node last took a version: it holds
        // a stricter price bump than the chain's configured one. Double the step every second
        // refusal, within the cap.
        let target = match kind {
            FeeBump::SameNonce if underpriced >= 2 => {
                let raised = esc.reach_cap(
                    esc.underpriced_target_within(current, target, underpriced, cap),
                    cap,
                );
                tracing::warn!(
                    swap = %r.swap_id(),
                    chain = %self.chain,
                    refusals = underpriced,
                    price_bump_pct = esc.price_bump_pct,
                    old_feerate = current,
                    step_feerate = target,
                    new_feerate = raised,
                    cap,
                    "claim replacements refused as underpriced; doubling the step"
                );
                raised
            }
            _ => target,
        };
        let tx = match kind {
            FeeBump::Rbf => {
                b.build_claim_at(&self.htlc, &self.op, self.amount, &self.preimage, target)
                    .await?
            }
            FeeBump::SameNonce => {
                // `None`: the node's replacement minimum is above the target; keep the claim.
                let Some(tx) = b
                    .build_claim_replacement(claim, target, esc.price_bump_pct)
                    .await?
                else {
                    return Ok(());
                };
                tx
            }
            FeeBump::Cpfp | FeeBump::None => unreachable!("returned above"),
        };
        {
            let c = r.claim_mut();
            c.replaced.push((claim.clone(), current));
            *c.claim = Some(tx.clone());
            *c.feerate = Some(target);
        }
        r.persist(self.store)?; // write-ahead
        tracing::info!(
            swap = %r.swap_id(),
            chain = %self.chain,
            bump = ?kind,
            old_feerate = current,
            new_feerate = target,
            txid = %tx.txid,
            claim = %claim.txid,
            secs_left = left,
            "claim fee bumped"
        );
        match b.broadcast(&tx).await {
            Ok(_) if underpriced > 0 => {
                // The node took a version: the next step starts from the configured bump.
                *r.claim_mut().underpriced = 0;
                r.persist(self.store)?;
            }
            Ok(_) => {}
            // Kept: the next step resends it and, if refused for good, falls back.
            Err(e) => {
                tracing::warn!(swap = %r.swap_id(), txid = %tx.txid, error = %e,
                    "fee bump broadcast failed");
            }
        }
        Ok(())
    }

    /// The CPFP target for the package of the claim and `children` CPFP children (the new
    /// one included), with `left` seconds before the locktime, and whether it is worth a
    /// bump from `current`. Past the cap point the ceiling is the one at the start of the
    /// current step ([`FeeEscalation::cpfp_step`]), so the step's target holds through it.
    fn cpfp_target(
        &self,
        esc: &FeeEscalation,
        base: u64,
        current: u64,
        left: i64,
        children: u64,
    ) -> (u64, bool) {
        let at = esc.cpfp_step(left).map_or(left, |(_, start)| start);
        let target = match self.ceiling(at, children) {
            Some(c) => esc.cpfp_target_after_leak(base, left, c),
            None => esc.target(base, left),
        };
        (target, esc.should_add_child(base, left, current, target))
    }

    /// [`ClaimCtx::escalate`] for a CPFP claim: add a child on top of the newest child of
    /// `claim` (or the first). With [`FeeEscalation::replace_cpfp_child`], replace the
    /// newest child instead, and where the node refuses the replacement, keep the old child
    /// and add one on top of it.
    async fn bump_child<R: ClaimRecord>(
        &self,
        r: &mut R,
        claim: &SignedTx,
        esc: &FeeEscalation,
        base: u64,
        current: u64,
        left: i64,
    ) -> Result<()> {
        let b = self.backend;
        let held = r.claim_mut().children.len() as u64;
        let replace = esc.replace_cpfp_child && held > 0;
        let children = if replace { held } else { held + 1 };
        let (target, bump) = self.cpfp_target(esc, base, current, left, children);
        if !bump {
            return Ok(());
        }
        let old = if replace {
            r.claim_mut().children.pop()
        } else {
            None
        };
        let mut package = vec![claim.clone()];
        package.extend(r.claim_mut().children.iter().cloned());
        let tx = match b.build_cpfp(&package, self.amount, target).await {
            Ok(tx) => tx,
            Err(e) => {
                r.claim_mut().children.extend(old);
                return Err(e);
            }
        };
        {
            let c = r.claim_mut();
            c.children.push(tx.clone());
            *c.feerate = Some(target);
            // Kept until the node relays or refuses the replacement: one that refuses it
            // still holds the old child, also after a crash before the broadcast.
            *c.child_replaced = old.clone().map(|o| (o, current));
        }
        r.persist(self.store)?; // write-ahead
        self.log_child_bump(r, claim, &tx, current, target, left, old.is_some());
        let refused = match b.broadcast(&tx).await {
            Ok(_) => {
                if r.claim_mut().child_replaced.take().is_some() {
                    r.persist(self.store)?;
                }
                return Ok(());
            }
            Err(SwapError::Rejected(e)) if old.is_some() => e,
            Err(e) => {
                // Kept: the next step resends it and, if refused for good, drops it.
                tracing::warn!(swap = %r.swap_id(), txid = %tx.txid, error = %e,
                    "fee bump broadcast failed");
                return Ok(());
            }
        };
        // The node keeps the old child (no child replacement): put it back, then chain a
        // new child onto the whole package, which is one child bigger.
        tracing::info!(swap = %r.swap_id(), refused = %tx.txid, error = %refused,
            "claim CPFP child replacement refused; adding a child instead");
        {
            let c = r.claim_mut();
            c.children.pop();
            c.children.extend(old);
            *c.feerate = Some(current);
            *c.child_replaced = None;
        }
        let (target, bump) = self.cpfp_target(esc, base, current, left, held + 1);
        if !bump {
            r.persist(self.store)?;
            return Ok(());
        }
        let mut package = vec![claim.clone()];
        package.extend(r.claim_mut().children.iter().cloned());
        let tx = match b.build_cpfp(&package, self.amount, target).await {
            Ok(tx) => tx,
            Err(e) => {
                r.persist(self.store)?;
                return Err(e);
            }
        };
        {
            let c = r.claim_mut();
            c.children.push(tx.clone());
            *c.feerate = Some(target);
        }
        r.persist(self.store)?; // write-ahead
        self.log_child_bump(r, claim, &tx, current, target, left, false);
        if let Err(e) = b.broadcast(&tx).await {
            tracing::warn!(swap = %r.swap_id(), txid = %tx.txid, error = %e,
                "fee bump broadcast failed");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn log_child_bump<R: ClaimRecord>(
        &self,
        r: &mut R,
        claim: &SignedTx,
        tx: &SignedTx,
        current: u64,
        target: u64,
        left: i64,
        replaces: bool,
    ) {
        let children = r.claim_mut().children.len();
        tracing::info!(
            swap = %r.swap_id(),
            chain = %self.chain,
            bump = ?FeeBump::Cpfp,
            replaces,
            children,
            old_feerate = current,
            new_feerate = target,
            txid = %tx.txid,
            claim = %claim.txid,
            secs_left = left,
            "claim fee bumped"
        );
    }
}
