// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! The whole taker flow, shared by `divi-swap run` and the end-to-end tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use divi_swap::api::Offer;
use divi_swap::taker::TAKER_SAFETY_MARGIN_SECS;
use divi_swap::{rt, Chain, ChainBackend, QuoteIntent, Store, SwapError, Taker, TakerState};

use crate::client::MakerClient;
use crate::session::{Session, Sessions};

pub struct RunOpts {
    /// Give up (without refunding) after this long.
    pub timeout: Duration,
    /// Pause between polls of the maker.
    pub poll: Duration,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts {
            timeout: Duration::from_secs(8 * 3600),
            poll: Duration::from_secs(10),
        }
    }
}

/// When the taker may claim the maker's DIVI lock (end-to-end scenarios).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPolicy {
    /// As soon as the lock is verified and confirmed (the normal flow).
    Asap,
    /// Hold the claim until the DIVI median time is within this many seconds of the maker's
    /// refund locktime (case D, "late claim"). Must exceed the maker-leg chain's claim margin
    /// ([`Taker::claim_deadline`]), or the engine declines the claim when it is released.
    NotBefore { secs_before_timeout: u32 },
    /// Never claim; wait out the BTC timelock and refund (case C).
    Never,
}

impl ClaimPolicy {
    /// Reject a late-claim lead the engine would refuse to claim with on any chain (the
    /// least margin, [`TAKER_SAFETY_MARGIN_SECS`]). Checked before the quote, when the
    /// maker-leg chain is not known yet; [`ClaimPolicy::validate_for`] then checks that chain.
    pub fn validate(&self) -> Result<()> {
        self.check(TAKER_SAFETY_MARGIN_SECS, "the taker safety margin")
    }

    /// Reject a late-claim lead the engine would refuse to claim with on `maker_chain`,
    /// reading the margin from `taker` itself so the two cannot drift.
    pub fn validate_for(&self, taker: &Taker, maker_chain: Chain) -> Result<()> {
        let margin = taker.claim_deadline(maker_chain).margin_secs();
        self.check(margin, &format!("the {maker_chain} maker-leg claim margin"))
    }

    fn check(&self, margin: u32, what: &str) -> Result<()> {
        if let ClaimPolicy::NotBefore {
            secs_before_timeout,
        } = self
        {
            if *secs_before_timeout <= margin {
                bail!(
                    "--claim-not-before must exceed {what} ({margin}s), or the engine refuses to claim"
                );
            }
        }
        Ok(())
    }
}

/// What a gated run needs to read from: the taker's own store (the maker lock's locktime)
/// and the backend of the maker-leg chain (its median time): DIVI going forward, the counter
/// chain in reverse.
pub struct ClaimGate {
    pub policy: ClaimPolicy,
    pub store: Store,
    pub divi: Arc<dyn ChainBackend>,
    /// The counter-chain backend (BTC, LTC, …).
    pub btc: Arc<dyn ChainBackend>,
}

/// Quote, accept, lock, then step the taker until `Done`, held to the selected `offer`'s
/// terms ([`QuoteIntent::for_offer`]). `pump` is called once per poll (the CLI passes a
/// no-op; tests use it to mine blocks on simulated chains).
/// Returns the local swap id and the final taker state.
pub async fn run_swap(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer: &Offer,
    btc_sats: u64,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
) -> Result<(String, TakerState)> {
    run_swap_gated(taker, client, sessions, offer, btc_sats, opts, pump, None).await
}

/// [`run_swap`] with an optional [`ClaimGate`]. Under a non-`Asap` policy the taker is
/// halted on entering `MakerLockConfirmed` (verified, persisted, not claimed) and released
/// when the policy allows. Prints `claim_secs_before_timeout=<n>` when it releases.
#[allow(clippy::too_many_arguments)]
pub async fn run_swap_gated(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer: &Offer,
    btc_sats: u64,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
    gate: Option<&ClaimGate>,
) -> Result<(String, TakerState)> {
    let intent = QuoteIntent::for_offer(offer, btc_sats)?;
    run_swap_intent(taker, client, sessions, &intent, opts, pump, gate).await
}

/// [`run_swap_gated`] for any [`QuoteIntent`] (selected terms or explicit limits): the quote
/// must match it ([`QuoteIntent::check_quote`]), and under a profile floor its HTLC timing
/// must too ([`QuoteIntent::check_htlc_terms`]), before anything is accepted or locked.
pub async fn run_swap_intent(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    intent: &QuoteIntent,
    opts: &RunOpts,
    pump: &mut dyn FnMut(),
    gate: Option<&ClaimGate>,
) -> Result<(String, TakerState)> {
    let mut gate = gate.filter(|g| g.policy != ClaimPolicy::Asap);
    if let Some(g) = gate {
        g.policy.validate()?;
        taker.halt_after(Some(TakerState::MakerLockConfirmed));
    }
    let local = begin_checked(taker, client, sessions, intent, gate.map(|g| g.policy)).await?;
    lock(taker, client, sessions, &local).await?;
    let started = Instant::now();
    let mut held = false;
    let mut backoff = opts.poll;
    loop {
        pump();
        // A transient backend error (a network hiccup on either chain, e.g. a failed
        // Esplora request) must never end the run: retry this poll after a backoff
        // instead of propagating it. Orchestrator bug report: a live case-c run died on
        // one "error sending request" mid-poll, after both sides had already locked.
        // Chain-agnostic — this is the one step loop shared by every counter chain.
        let outcome = match (gate, held) {
            // Verified and persisted but not claimed: do not step (a step would claim).
            (Some(g), true) => match release(g, &local).await {
                Ok(false) => Ok(TakerState::MakerLockConfirmed),
                Ok(true) => {
                    taker.halt_after(None);
                    gate = None;
                    step(taker, client, sessions, &local).await
                }
                Err(e) => Err(e),
            },
            _ => step(taker, client, sessions, &local).await,
        };
        let state = match outcome {
            Ok(s) => {
                backoff = opts.poll;
                s
            }
            Err(e) if is_retryable_backend_error(&e) => {
                tracing::warn!(error = %e, backoff_secs = backoff.as_secs(), "transient backend error; retrying after backoff");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(300));
                continue;
            }
            Err(e) => return Err(e),
        };
        if state == TakerState::Done {
            return Ok((local, state));
        }
        lost_is_an_error(&local, state)?;
        held = gate.is_some() && state == TakerState::MakerLockConfirmed;
        if started.elapsed() > opts.timeout {
            bail!("timed out in taker state {state:?}; swap {local} left in place — rerun `status`/`refund`");
        }
        tokio::time::sleep(opts.poll).await;
    }
}

/// Whether `e` is a retryable [`SwapError`] (`Transient` or `Premature`,
/// [`SwapError::is_retryable`]) that reached here through `?` into an `anyhow::Error` —
/// the concrete type survives the conversion, so this still works.
fn is_retryable_backend_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<SwapError>()
        .is_some_and(SwapError::is_retryable)
}

/// Fresh quote → prepare → `POST /swaps` → record the maker's reply. Returns the local id.
/// The quote must be for exactly the selected `offer`'s id, chain and direction, `btc_sats`,
/// and the DIVI amount the offer promised for it ([`QuoteIntent::for_offer`]). `offer` is the
/// copy the user selected, not one re-fetched to quote against.
pub async fn begin(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    offer: &Offer,
    btc_sats: u64,
) -> Result<String> {
    begin_with_intent(
        taker,
        client,
        sessions,
        &QuoteIntent::for_offer(offer, btc_sats)?,
    )
    .await
}

/// [`begin`] for any [`QuoteIntent`] (selected terms, or explicit limits).
pub async fn begin_with_intent(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    intent: &QuoteIntent,
) -> Result<String> {
    begin_checked(taker, client, sessions, intent, None).await
}

/// [`begin_with_intent`], refusing a `policy` whose late-claim lead the maker-leg chain's
/// claim margin would turn into a declined claim. Every check runs once the quote names the
/// chains, before anything is accepted or locked; the quote's remaining validity is checked
/// again right before `POST /swaps`.
async fn begin_checked(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    intent: &QuoteIntent,
    policy: Option<ClaimPolicy>,
) -> Result<String> {
    intent.validate()?;
    let offer_id = intent.offer_id.as_str();
    let c = intent.counter_chain;
    if !taker.counter_chains().contains(&c) {
        bail!(
            "offer {offer_id} swaps DIVI against {c}; rerun with --counter-chain {c} \
             (and --{c}-key for the live backend)"
        );
    }
    let quote = client.quote(offer_id, intent.btc_sats).await?;
    intent.check_quote(&quote, rt::unix_now())?;
    if let Some(p) = taker.profile_floor() {
        intent.check_htlc_terms(&quote, p, &|chain| taker.claim_deadline(chain))?;
    }
    if let Some(p) = policy {
        p.validate_for(taker, quote.maker_chain())?;
    }
    let (local, req) = taker.prepare(&quote).await?;
    intent.check_deadline(&quote, rt::unix_now())?;
    let view = client.accept(&req).await?;
    sessions.put(
        &local,
        Session {
            maker_url: client.base().to_string(),
            maker_swap_id: view.id.clone(),
            swap_token: client.swap_token(&view.id).unwrap_or_default(),
        },
    )?;
    taker.accepted(&local, &view).await?;
    Ok(local)
}

/// Fund the taker-leg HTLC and tell the maker.
pub async fn lock(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    local: &str,
) -> Result<()> {
    let session = sessions.get(local)?;
    let notice = taker.lock(local).await?;
    let client = client
        .clone()
        .with_swap_token(&session.maker_swap_id, &session.swap_token);
    client.lock(&session.maker_swap_id, &notice).await?;
    Ok(())
}

/// One taker step against the maker's latest view (`None` if the maker is unreachable).
pub async fn step(
    taker: &Taker,
    client: &MakerClient,
    sessions: &Sessions,
    local: &str,
) -> Result<TakerState> {
    let session = sessions.get(local)?;
    let client = client
        .clone()
        .with_swap_token(&session.maker_swap_id, &session.swap_token);
    let view = match client.swap(&session.maker_swap_id).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "maker unreachable; stepping without its view");
            None
        }
    };
    lost_is_an_error(local, taker.step(local, view.as_ref()).await?)
}

/// Refund `local`'s taker leg without ever claiming the maker leg (see [`Taker::refund`]) —
/// never needs the maker's view, so no `client`/`sessions` lookup either.
pub async fn refund(taker: &Taker, local: &str) -> Result<TakerState> {
    lost_is_an_error(local, taker.refund(local).await?)
}

/// `Lost` is terminal but not a success: both legs went to the maker (see
/// [`TakerState::Lost`]), so `claim`, `refund` and `run` exit non-zero instead of printing it
/// as an ordinary state or polling it until the timeout.
fn lost_is_an_error(local: &str, state: TakerState) -> Result<TakerState> {
    if state == TakerState::Lost {
        tracing::error!(swap = %local, "swap lost: the maker refunded its leg and claimed ours with our leaked preimage");
        bail!(
            "swap {local} is lost: our maker-leg claim never confirmed and the maker claimed the \
             taker leg with its preimage; nothing is left to claim or refund"
        );
    }
    Ok(state)
}

/// Whether the gate's policy now allows the claim (or, for `Never`, the claim window
/// has closed so the next step takes the refund path).
async fn release(g: &ClaimGate, local: &str) -> Result<bool> {
    let rec = g
        .store
        .get_taker_swap(local)?
        .ok_or_else(|| anyhow::anyhow!("no taker record {local}"))?;
    let chain = match rec.quote.maker_chain() {
        Chain::Divi => &g.divi,
        _ => &g.btc,
    };
    let locktime = rec
        .maker_leg_htlc
        .ok_or_else(|| anyhow::anyhow!("MakerLockConfirmed without a maker-leg lock"))?
        .locktime;
    let mtp = chain.median_time_past().await?;
    let open_at = match g.policy {
        ClaimPolicy::Asap => 0,
        ClaimPolicy::NotBefore {
            secs_before_timeout,
        } => locktime.saturating_sub(secs_before_timeout),
        ClaimPolicy::Never => locktime,
    };
    if mtp < open_at {
        return Ok(false);
    }
    println!(
        "claim_secs_before_timeout={} policy={:?}",
        locktime.saturating_sub(mtp),
        g.policy
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use divi_swap::api::{Direction, Quote};
    use divi_swap::mock::MockChain;
    use divi_swap::Amount;

    use super::*;

    #[derive(Clone)]
    struct FakeMaker {
        quote: Quote,
        accepts: Arc<AtomicUsize>,
    }

    async fn serve_quote(State(m): State<FakeMaker>) -> Json<Quote> {
        Json(m.quote)
    }

    /// Counts the commitment and refuses it: reaching here is all a test needs to know.
    async fn serve_accept(State(m): State<FakeMaker>) -> (StatusCode, &'static str) {
        m.accepts.fetch_add(1, Ordering::SeqCst);
        (StatusCode::IM_A_TEAPOT, r#"{"error":"accept reached"}"#)
    }

    /// A local maker answering every quote request with `quote`. Returns its client and
    /// the `POST /swaps` counter.
    async fn maker(quote: Quote) -> (MakerClient, Arc<AtomicUsize>) {
        let accepts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/offers/:id/quote", get(serve_quote))
            .route("/swaps", post(serve_accept))
            .with_state(FakeMaker {
                quote,
                accepts: accepts.clone(),
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (MakerClient::new(&format!("http://{addr}")), accepts)
    }

    fn honest_quote() -> Quote {
        Quote {
            id: "q-1".into(),
            offer_id: "divi-btc-testnet".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Btc,
            btc_amount: Amount(10_000),
            divi_amount: Amount(1_000_000_000),
            expires_at: rt::unix_now() + 60,
            maker_btc_pubkey: [2; 33],
            maker_divi_pubkey: [3; 33],
            taker_timeout_secs: 6 * 3600,
            maker_timeout_secs: 3 * 3600,
            btc_confirmations: 1,
            divi_confirmations: 3,
        }
    }

    /// The offer the user selected: 10_000 sats of BTC buys 1e9 DIVI sats.
    fn selected_offer() -> Offer {
        Offer {
            id: "divi-btc-testnet".into(),
            direction: Direction::TakerPaysBtc,
            counter_chain: Chain::Btc,
            divi_sats_per_btc: 10_000_000_000_000,
            min_btc_sats: 1_000,
            max_btc_sats: 1_000_000,
        }
    }

    fn selected() -> QuoteIntent {
        QuoteIntent::for_offer(&selected_offer(), 10_000).unwrap()
    }

    /// A taker as the CLI builds it (`floor`: `--profile`), its store and a session dir.
    fn taker(floor: Option<divi_swap::Profile>) -> (Taker, Store, tempfile::TempDir) {
        let divi = MockChain::new(Chain::Divi, 1_700_000_000, 60);
        let btc = MockChain::new(Chain::Btc, 1_700_000_000, 600);
        let store = Store::in_memory().unwrap();
        let taker = Taker::new(
            Arc::new(divi.backend(1, Amount(0))),
            Arc::new(btc.backend(2, Amount(1_000_000))),
            store.clone(),
        );
        let taker = match floor {
            Some(p) => taker.with_profile_floor(p),
            None => taker,
        };
        (taker, store, tempfile::tempdir().unwrap())
    }

    /// `begin_with_intent` against a maker serving `quote`: the error (if any), how many
    /// times it reached `POST /swaps`, and how many taker records it left.
    async fn try_begin_on(
        floor: Option<divi_swap::Profile>,
        quote: Quote,
        intent: &QuoteIntent,
    ) -> (String, usize, usize) {
        let (taker, store, dir) = taker(floor);
        let sessions = Sessions::beside(&dir.path().join("taker.db"));
        let (client, accepts) = maker(quote).await;
        let err = begin_with_intent(&taker, &client, &sessions, intent)
            .await
            .unwrap_err()
            .to_string();
        let records = store.list_taker_swaps().unwrap().len();
        (err, accepts.load(Ordering::SeqCst), records)
    }

    async fn try_begin(quote: Quote, intent: &QuoteIntent) -> (String, usize, usize) {
        try_begin_on(None, quote, intent).await
    }

    #[tokio::test]
    async fn a_quote_off_the_intent_is_refused_before_anything_is_committed() {
        let mut wrong_amount = honest_quote();
        wrong_amount.btc_amount = Amount(20_000);
        let mut flipped = honest_quote();
        flipped.direction = Direction::TakerPaysDivi;
        let mut ltc = honest_quote();
        ltc.counter_chain = Chain::Ltc;
        let mut cheap = honest_quote();
        cheap.divi_amount = Amount(999_999_999);
        let mut stale = honest_quote();
        stale.expires_at = rt::unix_now() + 5;
        for (q, want) in [
            (wrong_amount, "not the 10000 asked for"),
            (flipped, "direction"),
            (ltc, "on ltc, not btc"),
            (cheap, "below the 1000000000 agreed"),
            (stale, "margin required to commit"),
        ] {
            let (err, accepts, records) = try_begin(q, &selected()).await;
            assert!(err.contains(want), "{want}: {err}");
            assert_eq!(accepts, 0, "{want}: nothing may reach POST /swaps");
            assert_eq!(records, 0, "{want}: no preimage may be generated");
        }
    }

    #[tokio::test]
    async fn the_default_begin_is_bound_to_the_selected_offer() {
        // The maker changed its price after the user selected the offer.
        let mut repriced = honest_quote();
        repriced.divi_amount = Amount(900_000_000);
        for (q, want) in [
            (repriced, Some("below the 1000000000 agreed")),
            (honest_quote(), None),
        ] {
            let (taker, store, dir) = taker(Some(divi_swap::Profile::Testnet));
            let sessions = Sessions::beside(&dir.path().join("taker.db"));
            let (client, accepts) = maker(q).await;
            let err = begin(&taker, &client, &sessions, &selected_offer(), 10_000)
                .await
                .unwrap_err()
                .to_string();
            let records = store.list_taker_swaps().unwrap().len();
            match want {
                Some(w) => {
                    assert!(err.contains(w), "{err}");
                    assert_eq!((accepts.load(Ordering::SeqCst), records), (0, 0));
                }
                None => {
                    assert!(err.contains("accept reached"), "{err}");
                    assert_eq!((accepts.load(Ordering::SeqCst), records), (1, 1));
                }
            }
        }
        // An amount outside the selected offer never reaches the maker.
        let (taker, _, dir) = taker(Some(divi_swap::Profile::Testnet));
        let sessions = Sessions::beside(&dir.path().join("taker.db"));
        let (client, accepts) = maker(honest_quote()).await;
        let err = begin(&taker, &client, &sessions, &selected_offer(), 999)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside offer"), "{err}");
        assert_eq!(accepts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_default_run_refuses_an_unselected_amount_before_any_request() {
        let (taker, store, dir) = taker(Some(divi_swap::Profile::Testnet));
        let sessions = Sessions::beside(&dir.path().join("taker.db"));
        let (client, accepts) = maker(honest_quote()).await;
        let opts = RunOpts {
            timeout: Duration::from_secs(1),
            poll: Duration::from_millis(1),
        };
        let err = run_swap(
            &taker,
            &client,
            &sessions,
            &selected_offer(),
            0,
            &opts,
            &mut || {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("outside offer"), "{err}");
        assert_eq!(accepts.load(Ordering::SeqCst), 0);
        assert!(store.list_taker_swaps().unwrap().is_empty());
    }

    #[tokio::test]
    async fn under_a_profile_floor_the_htlc_timing_is_checked_before_prepare() {
        use divi_swap::Profile;
        // Testnet floor: 12 BTC confirmations still fit a 6 h / 3 h quote, 13 do not.
        let mut deep = honest_quote();
        deep.btc_confirmations = 13;
        let mut long = honest_quote();
        long.taker_timeout_secs = 12 * 3600 + 1;
        for (floor, q, want) in [
            (Profile::Testnet, deep, "maker would refuse to lock"),
            (Profile::Testnet, long, "ceiling"),
            (Profile::Mainnet, honest_quote(), "floor"),
        ] {
            let (err, accepts, records) = try_begin_on(Some(floor), q, &selected()).await;
            assert!(err.contains(want), "{floor} {want}: {err}");
            assert_eq!((accepts, records), (0, 0), "{floor} {want}");
        }
        let mut twelve = honest_quote();
        twelve.btc_confirmations = 12;
        let (err, accepts, records) =
            try_begin_on(Some(Profile::Testnet), twelve, &selected()).await;
        assert!(err.contains("accept reached"), "{err}");
        assert_eq!((accepts, records), (1, 1));
    }

    #[tokio::test]
    async fn explicit_limits_go_on_to_accept_and_only_tighten() {
        let limits = QuoteIntent::with_limit(
            "divi-btc-testnet",
            10_000,
            Chain::Btc,
            Direction::TakerPaysBtc,
            10_000_000_000_000,
        )
        .unwrap();
        let (err, accepts, records) = try_begin(honest_quote(), &limits).await;
        assert!(err.contains("accept reached"), "{err}");
        assert_eq!((accepts, records), (1, 1));

        let stricter = selected().stricter_price(10_000_100_000_000).unwrap();
        let (err, accepts, records) = try_begin(honest_quote(), &stricter).await;
        assert!(err.contains("below the 1000010000 agreed"), "{err}");
        assert_eq!((accepts, records), (0, 0));
    }

    #[tokio::test]
    async fn a_malformed_intent_makes_no_request() {
        let bad = QuoteIntent {
            offer_id: "../swaps".into(),
            ..selected()
        };
        let (err, accepts, records) = try_begin(honest_quote(), &bad).await;
        assert!(err.contains("bad offer id"), "{err}");
        assert_eq!((accepts, records), (0, 0));
    }

    #[test]
    fn lost_is_an_error_and_every_other_state_passes_through() {
        let err = lost_is_an_error("l1", TakerState::Lost).unwrap_err();
        assert!(err.to_string().contains("swap l1 is lost"), "{err}");
        for s in [TakerState::Done, TakerState::Refunded, TakerState::Claimed] {
            assert_eq!(lost_is_an_error("l1", s).unwrap(), s);
        }
    }
}
